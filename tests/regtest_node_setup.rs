//! Regtest end-to-end setup test for the 3-of-5 emvault-xpub federation.
//!
//! What it does:
//!
//! 1. Loads `emvault-xpub/.env` and verifies the node is running on
//!    `regtest`.
//! 2. Builds five `TestExternalSigner`s from the BIP-39 fixtures, networked
//!    for `Network::Regtest`.
//! 3. Constructs a 3-of-5 `Federation` in `KeyMode::Ranged`.
//! 4. Cross-validates the descriptor: the addresses miniscript derives
//!    locally for `/0/0`...`/0/9` must match what Bitcoin Core's
//!    `deriveaddresses` produces from the same descriptor.
//! 5. Bootstraps a watch-only descriptor wallet `emvault-xpub-regtest` and
//!    imports the receive (`/0/*`) and change (`/1/*`) descriptors. Both
//!    are computed with their `#checksum` via `getdescriptorinfo`.
//! 6. Prints the first 10 receive addresses to stdout (run with
//!    `--nocapture` to see them) so the user can fund one and progress to
//!    the spending tests.
//!
//! Run with:
//!
//! ```bash
//! cargo test -p emvault-xpub \
//!   --features test-utils,node-tests \
//!   --test regtest_node_setup -- --nocapture
//! ```
//!
//! If `BITCOIN_RPC_*` is missing from `.env` or the node is unreachable,
//! the test prints a skip banner and returns successfully — this matches
//! the gating pattern emvault-core uses for its own node-tests.

#![cfg(all(feature = "test-utils", feature = "node-tests"))]

use bitcoin::Network;
use bitcoin::bip32::DerivationPath;
use emvault_core::descriptor::KeyMode;
use emvault_core::{Federation, NetworkType, Signer};
use emvault_xpub::{DeviceType, TestExternalSigner};

mod common;

use common::rpc::RpcClient;

const WALLET_NAME: &str = "emvault-xpub-regtest";
/// Index range covered by the descriptor import in Bitcoin Core. Once a
/// descriptor has been imported with this range, future imports must
/// include it (per `importdescriptors` semantics) — so we bind to the
/// default `[0, 999]` Bitcoin Core uses, which is plenty for development.
const IMPORT_RANGE_LO: u32 = 0;
const IMPORT_RANGE_HI: u32 = 999;
/// Addresses we cross-check + print at the end of the test (idx 0..=9).
const PRINT_LO: u32 = 0;
const PRINT_HI: u32 = 9;

#[test]
fn regtest_setup_prints_funding_addresses() {
    common::init_env();
    let Some(rpc) = RpcClient::from_env() else {
        eprintln!(
            "[skip] BITCOIN_RPC_* env vars not set; this test only runs against a \
             configured regtest node. See emvault-xpub/.env."
        );
        return;
    };

    // ---- 1. Verify node is alive and on regtest ----
    let chain_info = match rpc.getblockchaininfo() {
        Ok(v) => v,
        Err(e) => {
            eprintln!("[skip] could not reach Bitcoin Core at the configured RPC endpoint: {e}");
            return;
        }
    };
    let chain = chain_info
        .get("chain")
        .and_then(serde_json::Value::as_str)
        .unwrap_or("?");
    let height = chain_info
        .get("blocks")
        .and_then(serde_json::Value::as_u64)
        .unwrap_or(0);
    assert_eq!(
        chain, "regtest",
        "configured node must be on regtest, got chain={chain}"
    );
    println!("[ok] connected to bitcoin-core on chain={chain} height={height}");

    // ---- 2. Build the 3-of-5 federation in regtest mode ----
    let signers = build_regtest_test_signers();
    let signer_summary: Vec<(String, String)> = signers
        .iter()
        .map(|s| {
            let xs = s.external_signer();
            (
                xs.label().unwrap_or("<unlabelled>").to_string(),
                format!("{}", xs.fingerprint()),
            )
        })
        .collect();

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

    // ---- 3. Compute receive + change descriptors with checksums ----
    let receive_with_cs = fed.descriptor().to_string(); // miniscript emits #checksum
    let receive_no_cs = receive_with_cs
        .split('#')
        .next()
        .expect("descriptor body present")
        .to_string();
    let change_no_cs = receive_no_cs.replace("/0/*", "/1/*");
    let change_info = rpc
        .getdescriptorinfo(&change_no_cs)
        .expect("change descriptor canonicalize");
    let change_with_cs = change_info.descriptor;

    // Sanity: bitcoin core can canonicalize our receive descriptor too.
    let receive_info = rpc
        .getdescriptorinfo(&receive_no_cs)
        .expect("receive descriptor canonicalize");
    assert!(
        receive_info.isrange,
        "Ranged-mode descriptor must report isrange=true"
    );
    assert!(
        receive_info.issolvable,
        "Bitcoin Core says the descriptor isn't solvable: {receive_with_cs}"
    );

    // ---- 4. Cross-validate addresses against bitcoind ----
    let core_addrs = rpc
        .deriveaddresses(&receive_with_cs, Some([PRINT_LO, PRINT_HI]))
        .expect("deriveaddresses receive");
    assert_eq!(core_addrs.len(), (PRINT_HI - PRINT_LO + 1) as usize);
    for (idx, core_addr) in core_addrs.iter().enumerate() {
        #[allow(clippy::cast_possible_truncation)]
        let i = idx as u32 + PRINT_LO;
        let local = fed
            .descriptor()
            .at_derivation_index(i)
            .expect("descriptor index in range")
            .address(Network::Regtest)
            .expect("regtest address");
        assert_eq!(
            local.to_string(),
            *core_addr,
            "address mismatch between miniscript-local and bitcoin-core at idx {i}"
        );
        assert!(
            core_addr.starts_with("bcrt1q"),
            "expected bcrt1q prefix on regtest, got {core_addr}"
        );
    }
    println!(
        "[ok] cross-validated {n} addresses (idx {PRINT_LO}..={PRINT_HI}) against bitcoin-core",
        n = core_addrs.len()
    );

    // ---- 5. Bootstrap watch-only wallet + import descriptors (idempotent) ----
    rpc.ensure_wallet(WALLET_NAME).expect("ensure wallet");
    rpc.ensure_descriptors_imported(
        WALLET_NAME,
        &receive_with_cs,
        &change_with_cs,
        IMPORT_RANGE_LO,
        IMPORT_RANGE_HI,
    )
    .expect("ensure descriptors imported (never shrinking the existing range)");

    // ---- 6. Pretty-print the funding addresses ----
    let balance = rpc.getbalance(WALLET_NAME).unwrap_or(0.0);
    println!();
    println!("====================================================================");
    println!("  emvault-xpub regtest 3-of-5 federation — ready for funding");
    println!("====================================================================");
    println!("  wallet:       {WALLET_NAME}  (watch-only, descriptor)");
    println!("  threshold:    3 of {}", signer_summary.len());
    println!("  signers:");
    for (label, fp) in &signer_summary {
        println!("    - [{fp}] {label}");
    }
    println!("  descriptor:   {receive_with_cs}");
    println!("  change desc:  {change_with_cs}");
    println!("  current bal:  {balance} BTC");
    println!();
    println!("  Funding addresses (m/.../0/idx):");
    for (idx, addr) in core_addrs.iter().enumerate() {
        #[allow(clippy::cast_possible_truncation)]
        let i = idx as u32 + PRINT_LO;
        println!("    /0/{i:<3}  {addr}");
    }
    println!("====================================================================");
    println!();
}

fn build_regtest_test_signers() -> Vec<TestExternalSigner> {
    // Pull the same 5 mnemonics emvault-xpub's testnet fixture uses, but
    // re-derive each with `Network::Regtest` so the federation typing
    // matches what Bitcoin Core expects.
    let path: DerivationPath = std::env::var("EMVAULT_XPUB_TEST_DERIVATION_PATH")
        .expect("EMVAULT_XPUB_TEST_DERIVATION_PATH set in .env")
        .parse()
        .expect("derivation path parses");

    (1..=5u32)
        .map(|n| {
            let mnemonic = std::env::var(format!("EMVAULT_XPUB_TEST_MNEMONIC_{n}"))
                .unwrap_or_else(|_| panic!("missing EMVAULT_XPUB_TEST_MNEMONIC_{n}"));
            let device_label = std::env::var(format!("EMVAULT_XPUB_TEST_DEVICE_{n}"))
                .unwrap_or_else(|_| panic!("missing EMVAULT_XPUB_TEST_DEVICE_{n}"));
            let label = std::env::var(format!("EMVAULT_XPUB_TEST_LABEL_{n}"))
                .unwrap_or_else(|_| panic!("missing EMVAULT_XPUB_TEST_LABEL_{n}"));
            let device_type = parse_device_type(&device_label);
            TestExternalSigner::from_mnemonic(
                &mnemonic,
                "",
                &path,
                Network::Regtest,
                device_type,
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
