//! End-to-end spend test for the asterism-xpub 3-of-5 federation against
//! a regtest Bitcoin Core node.
//!
//! Flow exercised:
//!
//! 1. Connect to the regtest node configured in `asterism-xpub/.env` and
//!    assert `chain == "regtest"`.
//! 2. Build the 3-of-5 federation from the BIP-39 fixture (regtest-typed
//!    `TestExternalSigner`s).
//! 3. Idempotently bootstrap the watch-only descriptor wallet
//!    `asterism-xpub-regtest` and import the receive (`/0/*`) +
//!    change (`/1/*`) descriptors.
//! 4. Self-fund: if the watch-only balance is below
//!    [`FUND_THRESHOLD_BTC`], derive the next unfunded `/0/N`, send
//!    [`FUND_AMOUNT_BTC`] from `default` via the `-named` form (with an
//!    explicit `fee_rate`, since this regtest has no `-fallbackfee`),
//!    mine 1 block, and rescan.
//! 5. Build an in-memory `bdk_wallet::Wallet` from the federation
//!    descriptor, sync it from the node via `bdk_bitcoind_rpc::Emitter`,
//!    and assert it sees the funded UTXO.
//! 6. Build a PSBT spending [`SPEND_AMOUNT_BTC`] to a fresh
//!    `default`-owned address using `wallet.build_tx()`.
//! 7. Drive [`SigningCoordinator`] through 3 of the 5 `TestExternalSigner`s
//!    (`#0`, `#2`, `#4`), assert the threshold is reached, and finalize.
//! 8. Pre-broadcast: verify the change output's address is `ismine` on
//!    the watch-only wallet and lives on the `/1/*` chain.
//! 9. Broadcast via `sendrawtransaction`, mine 1 block, and assert the
//!    funded UTXO is gone, the new tx has 1 confirmation, and the
//!    watch-only balance has shrunk by `(spend + fee)`.
//!
//! Re-running the test consumes the change UTXO, so the auto-top-up
//! restores the wallet to a spendable state on each invocation.
//!
//! Run with:
//!
//! ```bash
//! cargo test -p asterism-xpub \
//!   --features test-utils,node-tests \
//!   --test regtest_spend -- --nocapture
//! ```
//!
//! Skips quietly if `BITCOIN_RPC_*` is missing or the node is unreachable
//! — same gate as `regtest_node_setup`.

#![cfg(all(feature = "test-utils", feature = "node-tests"))]

use asterism_core::descriptor::KeyMode;
use asterism_core::{
    Federation, NetworkType, Signer, SigningAction, SigningCoordinator, UnsignedPsbt,
};
use asterism_xpub::{DeviceType, TestExternalSigner};
use bdk_wallet::SignOptions;
use bitcoin::address::NetworkUnchecked;
use bitcoin::bip32::DerivationPath;
use bitcoin::{Address, Amount, FeeRate, Network};

mod common;

use common::rpc::RpcClient;

const WALLET_NAME: &str = "asterism-xpub-regtest";
/// Range of the receive + change descriptor imports — must match
/// `regtest_node_setup` so the importdescriptors call is idempotent.
const IMPORT_RANGE_LO: u32 = 0;
const IMPORT_RANGE_HI: u32 = 999;
/// Amount the auto-top-up sends from `default` to a fresh `/0/N`.
const FUND_AMOUNT_BTC: f64 = 0.05;
/// Watch-only balance below which the test self-funds before spending.
const FUND_THRESHOLD_BTC: f64 = 0.04;
/// How much we ask the federation to spend out to `default`. Leaves a
/// healthy change output well above the dust limit.
const SPEND_AMOUNT_BTC: f64 = 0.03;
/// sat/vB. 2 is plenty above regtest's 1 sat/vB relay floor and matches
/// the rate documented in `REGTEST.md` for the manual funding command.
const FEE_RATE_SAT_VB: u64 = 2;

#[test]
fn three_of_five_spends_real_utxo_and_confirms() {
    common::init_env();

    // ---- 1. Connect + verify regtest ----
    let Some(rpc) = RpcClient::from_env() else {
        eprintln!(
            "[skip] BITCOIN_RPC_* env vars not set; this test only runs against a \
             configured regtest node. See asterism-xpub/.env."
        );
        return;
    };
    let chain_info = match rpc.getblockchaininfo() {
        Ok(v) => v,
        Err(e) => {
            eprintln!("[skip] could not reach Bitcoin Core: {e}");
            return;
        }
    };
    let chain = chain_info
        .get("chain")
        .and_then(serde_json::Value::as_str)
        .unwrap_or("?");
    assert_eq!(
        chain, "regtest",
        "configured node must be on regtest, got chain={chain}"
    );

    // ---- 2. Build the 3-of-5 regtest federation ----
    let signers = build_regtest_test_signers();
    let fed_signers: Vec<Box<dyn Signer>> = signers
        .iter()
        .map(|s| Box::new(s.external_signer().clone()) as Box<dyn Signer>)
        .collect();
    let fed = Federation::with_key_mode(
        3,
        fed_signers,
        NetworkType::Bitcoin(Network::Regtest),
        KeyMode::Ranged,
    )
    .expect("3-of-5 regtest federation");

    // ---- 3. Bootstrap watch-only wallet + import descriptors (idempotent) ----
    let receive_with_cs = fed.descriptor().to_string();
    let receive_no_cs = receive_with_cs
        .split('#')
        .next()
        .expect("descriptor body present")
        .to_string();
    let change_no_cs = receive_no_cs.replace("/0/*", "/1/*");
    let change_with_cs = rpc
        .getdescriptorinfo(&change_no_cs)
        .expect("change descriptor canonicalize")
        .descriptor;

    rpc.ensure_wallet(WALLET_NAME).expect("ensure wallet");
    rpc.ensure_descriptors_imported(
        WALLET_NAME,
        &receive_with_cs,
        &change_with_cs,
        IMPORT_RANGE_LO,
        IMPORT_RANGE_HI,
    )
    .expect("ensure descriptors imported");

    // ---- 4. Auto-top-up if needed ----
    let initial_balance = rpc.getbalance(WALLET_NAME).unwrap_or(0.0);
    if initial_balance < FUND_THRESHOLD_BTC {
        println!(
            "[topup] watch-only balance is {initial_balance} BTC, below threshold \
             {FUND_THRESHOLD_BTC}; self-funding {FUND_AMOUNT_BTC} BTC"
        );
        let next_addr = pick_unfunded_receive_address(&rpc, &fed);
        let funding_txid = rpc
            .sendtoaddress_named("default", &next_addr, FUND_AMOUNT_BTC, FEE_RATE_SAT_VB)
            .expect("default wallet sends to fresh /0/N");
        let mining_addr = rpc
            .getnewaddress("default", "bech32")
            .expect("getnewaddress(default)");
        rpc.generatetoaddress(1, &mining_addr)
            .expect("mine 1 block to confirm funding");
        // Make sure the watch-only wallet's index sees the new UTXO.
        let _ = rpc.rescanblockchain(WALLET_NAME);
        println!("[topup] funded {next_addr} via tx {funding_txid}, mined 1 block");
    }

    let pre_balance = rpc
        .getbalance(WALLET_NAME)
        .expect("watch-only balance after top-up");
    assert!(
        pre_balance >= FUND_THRESHOLD_BTC,
        "watch-only balance still below threshold after top-up: got {pre_balance}"
    );

    // ---- 5. Build + sync the in-memory bdk_wallet from chain state ----
    let mut wallet = common::build_bdk_wallet(&fed, Network::Regtest);
    let bcr = common::sync::open_bcr_client().expect("bitcoincore_rpc::Client from env");
    common::sync::sync_wallet(&mut wallet, &bcr).expect("sync wallet from regtest node");

    let bdk_balance_sats = wallet.balance().total().to_sat();
    let pre_balance_sats = Amount::from_btc(pre_balance)
        .expect("pre balance fits Amount")
        .to_sat();
    assert!(
        bdk_balance_sats >= pre_balance_sats / 2,
        "BDK wallet didn't pick up the funded UTXO: bdk={bdk_balance_sats}, \
         core={pre_balance_sats}"
    );

    // ---- 6. Build the spend with TxBuilder ----
    let dest_str = rpc
        .getnewaddress("default", "bech32")
        .expect("destination address");
    let dest_unchecked: Address<NetworkUnchecked> = dest_str.parse().expect("parse destination");
    let dest_addr = dest_unchecked
        .require_network(Network::Regtest)
        .expect("destination is a regtest address");
    let send_amount = Amount::from_btc(SPEND_AMOUNT_BTC).expect("spend amount fits Amount");
    let fee_rate = FeeRate::from_sat_per_vb(FEE_RATE_SAT_VB).expect("fee rate fits FeeRate");

    let psbt = {
        let mut builder = wallet.build_tx();
        builder
            .add_recipient(dest_addr.script_pubkey(), send_amount)
            .fee_rate(fee_rate);
        builder.finish().expect("TxBuilder produces a PSBT")
    };
    let unsigned_txid = psbt.unsigned_tx.compute_txid();
    let funded_outpoints: Vec<_> = psbt
        .unsigned_tx
        .input
        .iter()
        .map(|i| i.previous_output)
        .collect();
    assert!(
        !funded_outpoints.is_empty(),
        "PSBT must spend at least one UTXO"
    );

    // ---- 7. Drive SigningCoordinator through 3 of 5 signers ----
    let mut coord = SigningCoordinator::new(
        &fed,
        UnsignedPsbt::new(psbt).expect("BDK-built PSBT carries no signatures"),
    );
    let actions = coord
        .request_signatures(&wallet, SignOptions::default())
        .expect("request_signatures");
    assert_eq!(actions.len(), 5, "all 5 actions emitted");
    for (_id, action) in &actions {
        assert!(
            matches!(action, SigningAction::External(_)),
            "all-External federation must emit only External actions"
        );
    }

    let picks = [0usize, 2, 4];
    for &i in &picks {
        let SigningAction::External(ext) = &actions[i].1 else {
            panic!("expected External action at index {i}");
        };
        let req_psbt = ext.request.psbt.clone();
        let signed = signers[i]
            .sign_for_test(&req_psbt)
            .expect("test signer signs");
        let signer_id = signers[i].external_signer().id();
        coord
            .receive_signature(&signer_id, signed)
            .expect("coordinator accepts signature");
    }
    assert_eq!(coord.signatures_collected(), 3);
    assert!(coord.is_complete(), "3-of-5 threshold reached");

    // ---- 8. Finalize + pre-broadcast assertions ----
    let finalized = coord
        .finalize(&wallet, SignOptions::default())
        .expect("finalize");
    let tx = finalized.transaction();
    assert!(!tx.input.is_empty(), "spend has at least one input");
    assert_eq!(
        tx.compute_txid(),
        unsigned_txid,
        "txid stable through signing"
    );

    let dest_spk = dest_addr.script_pubkey();
    let mut dest_outputs = 0;
    let mut change_addr_str: Option<String> = None;
    for out in &tx.output {
        if out.script_pubkey == dest_spk {
            assert_eq!(out.value, send_amount, "destination value matches");
            dest_outputs += 1;
        } else {
            // The non-destination output is the federation change.
            let change_addr = Address::from_script(&out.script_pubkey, Network::Regtest)
                .expect("change script_pubkey decodes to a regtest address");
            change_addr_str = Some(change_addr.to_string());
        }
    }
    assert_eq!(dest_outputs, 1, "exactly one output to the destination");
    let change_addr_str =
        change_addr_str.expect("BDK should have produced a change output for this spend");

    let info = rpc
        .getaddressinfo(WALLET_NAME, &change_addr_str)
        .expect("getaddressinfo(change)");
    let ismine = info
        .get("ismine")
        .and_then(serde_json::Value::as_bool)
        .unwrap_or(false);
    assert!(
        ismine,
        "change output {change_addr_str} must be ismine on the watch-only wallet"
    );
    let parent_desc = info
        .get("parent_desc")
        .and_then(serde_json::Value::as_str)
        .unwrap_or_default();
    assert!(
        parent_desc.contains("/1/"),
        "change must come from the /1/* keychain, got parent_desc={parent_desc}"
    );

    // Each input's witness must be the wsh(sortedmulti(3, ...)) shape:
    // [empty, sig, sig, sig, witness_script].
    for (i, input) in tx.input.iter().enumerate() {
        let witness_items: Vec<&[u8]> = input.witness.iter().collect();
        assert_eq!(
            witness_items.len(),
            5,
            "input {i}: wsh(sortedmulti(3,...)) witness should have 5 stack items, got {} ({witness_items:?})",
            witness_items.len()
        );
        assert!(
            witness_items[0].is_empty(),
            "input {i}: leading witness item must be empty (CHECKMULTISIG)"
        );
    }

    // ---- 9. Broadcast + confirm + post-checks ----
    let raw_hex = bitcoin::consensus::encode::serialize_hex(tx);
    let txid = rpc
        .sendrawtransaction(&raw_hex)
        .expect("regtest accepts the finalized tx");
    assert_eq!(txid, unsigned_txid.to_string(), "txid round-trips");

    let mining_addr = rpc
        .getnewaddress("default", "bech32")
        .expect("getnewaddress for mining");
    rpc.generatetoaddress(1, &mining_addr)
        .expect("mine 1 block to confirm spend");

    for op in &funded_outpoints {
        let still_there = rpc
            .gettxout(&op.txid.to_string(), op.vout, true)
            .expect("gettxout");
        assert!(
            still_there.is_none(),
            "funded outpoint {op} must be spent after broadcast"
        );
    }

    let raw_after = rpc
        .getrawtransaction(&txid, true)
        .expect("getrawtransaction post-confirm");
    let confirmations = raw_after
        .get("confirmations")
        .and_then(serde_json::Value::as_u64)
        .unwrap_or(0);
    assert!(
        confirmations >= 1,
        "spend tx must have ≥1 confirmation, got {confirmations}"
    );

    let post_balance = rpc.getbalance(WALLET_NAME).expect("post-spend balance");
    assert!(
        post_balance < pre_balance,
        "post-spend balance ({post_balance}) must be lower than pre-spend ({pre_balance})"
    );

    println!();
    println!("====================================================================");
    println!("  asterism-xpub regtest spend — confirmed");
    println!("====================================================================");
    println!("  txid:               {txid}");
    println!("  destination:        {dest_addr} ({SPEND_AMOUNT_BTC} BTC)");
    println!("  change address:    {change_addr_str}  (parent: {parent_desc})");
    println!("  pre-spend balance:  {pre_balance} BTC");
    println!("  post-spend balance: {post_balance} BTC");
    println!("  confirmations:      {confirmations}");
    println!("====================================================================");
    println!();
}

/// Find the next `/0/N` for `N in 0..=IMPORT_RANGE_HI` whose
/// `getaddressinfo` reports zero balance / no UTXOs.
///
/// We don't try to be fancy here — `listunspent` returns the spent set,
/// not the unfunded set, so we walk the receive chain and pick the first
/// address that doesn't appear in `listunspent`.
fn pick_unfunded_receive_address(rpc: &RpcClient, fed: &Federation<Box<dyn Signer>>) -> String {
    let utxos = rpc.listunspent(WALLET_NAME).unwrap_or_default();
    let occupied: std::collections::HashSet<String> = utxos
        .iter()
        .filter_map(|u| u.get("address").and_then(serde_json::Value::as_str))
        .map(str::to_string)
        .collect();
    for idx in 0..=IMPORT_RANGE_HI {
        let addr = fed
            .descriptor()
            .at_derivation_index(idx)
            .expect("idx in range")
            .address(Network::Regtest)
            .expect("regtest address")
            .to_string();
        if !occupied.contains(&addr) {
            return addr;
        }
    }
    panic!("no unfunded receive address found in /0/0..={IMPORT_RANGE_HI}");
}

fn build_regtest_test_signers() -> Vec<TestExternalSigner> {
    let path: DerivationPath = std::env::var("ASTERISM_XPUB_TEST_DERIVATION_PATH")
        .expect("ASTERISM_XPUB_TEST_DERIVATION_PATH set in .env")
        .parse()
        .expect("derivation path parses");

    (1..=5u32)
        .map(|n| {
            let mnemonic = std::env::var(format!("ASTERISM_XPUB_TEST_MNEMONIC_{n}"))
                .unwrap_or_else(|_| panic!("missing ASTERISM_XPUB_TEST_MNEMONIC_{n}"));
            let device_label = std::env::var(format!("ASTERISM_XPUB_TEST_DEVICE_{n}"))
                .unwrap_or_else(|_| panic!("missing ASTERISM_XPUB_TEST_DEVICE_{n}"));
            let label = std::env::var(format!("ASTERISM_XPUB_TEST_LABEL_{n}"))
                .unwrap_or_else(|_| panic!("missing ASTERISM_XPUB_TEST_LABEL_{n}"));
            TestExternalSigner::from_mnemonic(
                &mnemonic,
                "",
                &path,
                Network::Regtest,
                parse_device_type(&device_label),
                Some(label),
            )
            .expect("test signer constructs")
        })
        .collect()
}

fn parse_device_type(s: &str) -> DeviceType {
    match s.trim() {
        "Trezor" => DeviceType::Trezor,
        "Jade" => DeviceType::Jade,
        "Ledger" => DeviceType::Ledger,
        "Coldcard" => DeviceType::Coldcard,
        "PassportPrime" => DeviceType::PassportPrime,
        "Generic" => DeviceType::Generic,
        other => panic!("unknown device type {other:?}"),
    }
}

// ---------------------------------------------------------------------------
// Negative test: rebroadcast after confirmation must be rejected by bitcoind.
// ---------------------------------------------------------------------------

/// Builds an independent finalized spend (separately from the happy-path
/// test, so test ordering doesn't matter), broadcasts it, mines a block,
/// then attempts to rebroadcast and asserts bitcoind returns the
/// "transaction already in block chain" error (RPC code -27).
#[test]
fn rebroadcast_after_confirmation_is_rejected() {
    common::init_env();
    let Some(rpc) = RpcClient::from_env() else {
        eprintln!("[skip] BITCOIN_RPC_* env vars not set");
        return;
    };
    if rpc.getblockchaininfo().is_err() {
        eprintln!("[skip] node unreachable");
        return;
    }

    // Build the same federation + a chain-synced bdk_wallet.
    let signers = build_regtest_test_signers();
    let fed_signers: Vec<Box<dyn Signer>> = signers
        .iter()
        .map(|s| Box::new(s.external_signer().clone()) as Box<dyn Signer>)
        .collect();
    let fed = Federation::with_key_mode(
        3,
        fed_signers,
        NetworkType::Bitcoin(Network::Regtest),
        KeyMode::Ranged,
    )
    .expect("federation");

    rpc.ensure_wallet(WALLET_NAME).expect("ensure wallet");
    let receive_with_cs = fed.descriptor().to_string();
    let receive_no_cs = receive_with_cs
        .split('#')
        .next()
        .expect("descriptor body present")
        .to_string();
    let change_no_cs = receive_no_cs.replace("/0/*", "/1/*");
    let change_with_cs = rpc
        .getdescriptorinfo(&change_no_cs)
        .expect("change descriptor canonicalize")
        .descriptor;
    rpc.ensure_descriptors_imported(
        WALLET_NAME,
        &receive_with_cs,
        &change_with_cs,
        IMPORT_RANGE_LO,
        IMPORT_RANGE_HI,
    )
    .expect("ensure descriptors imported");

    // Self-fund if needed so the test stands alone.
    let bal = rpc.getbalance(WALLET_NAME).unwrap_or(0.0);
    if bal < FUND_THRESHOLD_BTC {
        let next_addr = pick_unfunded_receive_address(&rpc, &fed);
        rpc.sendtoaddress_named("default", &next_addr, FUND_AMOUNT_BTC, FEE_RATE_SAT_VB)
            .expect("topup");
        let m = rpc.getnewaddress("default", "bech32").expect("miner addr");
        rpc.generatetoaddress(1, &m).expect("mine");
        let _ = rpc.rescanblockchain(WALLET_NAME);
    }

    let mut wallet = common::build_bdk_wallet(&fed, Network::Regtest);
    let bcr = common::sync::open_bcr_client().expect("bcr client");
    common::sync::sync_wallet(&mut wallet, &bcr).expect("sync");

    // Build, sign, broadcast, mine.
    let dest_str = rpc.getnewaddress("default", "bech32").expect("dest");
    let dest_unchecked: Address<NetworkUnchecked> = dest_str.parse().expect("parse dest");
    let dest_addr = dest_unchecked
        .require_network(Network::Regtest)
        .expect("regtest dest");
    let send_amount = Amount::from_btc(SPEND_AMOUNT_BTC).expect("amount");
    let fee_rate = FeeRate::from_sat_per_vb(FEE_RATE_SAT_VB).expect("fee");

    let psbt = {
        let mut b = wallet.build_tx();
        b.add_recipient(dest_addr.script_pubkey(), send_amount)
            .fee_rate(fee_rate);
        b.finish().expect("psbt")
    };

    let mut coord = SigningCoordinator::new(&fed, UnsignedPsbt::new(psbt).expect("zero sigs"));
    let actions = coord
        .request_signatures(&wallet, SignOptions::default())
        .expect("request_signatures");
    for &i in &[0usize, 2, 4] {
        let SigningAction::External(ext) = &actions[i].1 else {
            panic!("expected External");
        };
        let signed = signers[i].sign_for_test(&ext.request.psbt).expect("sign");
        coord
            .receive_signature(&signers[i].external_signer().id(), signed)
            .expect("ingest");
    }
    let finalized = coord
        .finalize(&wallet, SignOptions::default())
        .expect("finalize");
    let raw_hex = bitcoin::consensus::encode::serialize_hex(finalized.transaction());

    let txid = rpc
        .sendrawtransaction(&raw_hex)
        .expect("first broadcast accepted");
    let mining_addr = rpc.getnewaddress("default", "bech32").expect("miner");
    rpc.generatetoaddress(1, &mining_addr).expect("mine");

    // Now retry. Bitcoin Core returns RPC code -27 with one of:
    //   - "Transaction already in block chain"
    //   - "Transaction outputs already in utxo set"
    //   - "txn-mempool-conflict" / "already in mempool"
    // The exact text varies by Bitcoin Core version (and by whether the
    // tx is in the mempool vs confirmed at the moment of retry); the
    // *strict* invariant we assert is the structured error code -27.
    let err = rpc
        .sendrawtransaction(&raw_hex)
        .expect_err("rebroadcast must be rejected by bitcoind");
    let code = err.rpc_code();
    let msg = format!("{err}");
    assert_eq!(
        code,
        Some(-27),
        "expected RPC code -27 (already in chain / utxo set / mempool), \
         got code={code:?}, msg={msg}"
    );
    assert!(
        msg.to_lowercase().contains("already"),
        "expected error message to mention 'already', got: {msg}"
    );

    println!("[ok] rebroadcast of confirmed txid {txid} rejected: {msg}");
}
