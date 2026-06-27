//! Shared helpers for the `test-utils`-gated test suite.
//!
//! Lives in a `common/` folder rather than a `_helpers.rs` to avoid
//! cargo's "unused module" warnings when only a subset of integration
//! tests includes it.

#![cfg(feature = "test-utils")]
#![allow(dead_code)] // helpers are referenced by some integration tests but not all

#[cfg(feature = "node-tests")]
pub mod rpc;

#[cfg(feature = "node-tests")]
pub mod sync;

use std::collections::BTreeMap;
use std::sync::OnceLock;

use emvault_core::{Federation, Signer, UnsignedPsbt};
use bdk_wallet::Wallet;
use bitcoin::bip32::{ChildNumber, DerivationPath};
use bitcoin::hashes::Hash as _;
use bitcoin::secp256k1::Secp256k1;
use bitcoin::{
    Amount, Network, OutPoint, Psbt, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Txid, Witness,
    absolute::LockTime, transaction::Version,
};

/// Load `emvault-xpub/.env` exactly once for the whole test process.
///
/// `cargo test` runs from the crate manifest directory (`emvault-xpub/`),
/// so `.env` resolves at that root. We resolve it via `CARGO_MANIFEST_DIR`
/// to be robust against a different CWD if the test binary is invoked
/// directly.
pub fn init_env() {
    static ONCE: OnceLock<()> = OnceLock::new();
    ONCE.get_or_init(|| {
        let manifest = env!("CARGO_MANIFEST_DIR");
        let path = std::path::Path::new(manifest).join(".env");
        if let Err(e) = dotenvy::from_path(&path) {
            // If the file is already loaded by another caller we'll still
            // resolve env vars correctly; only flag truly missing files.
            assert!(
                std::env::var("EMVAULT_XPUB_TEST_MNEMONIC_1").is_ok(),
                "could not load emvault-xpub/.env at {}: {e}",
                path.display(),
            );
        }
    });
}

/// Result of [`build_synthetic_psbt`]: the unsigned PSBT plus the per-signer
/// metadata the round-trip test needs to verify partial signatures.
pub struct SyntheticPsbt {
    /// The unsigned, zero-signature PSBT wrapped in the safety newtype.
    pub psbt: UnsignedPsbt,
    /// Witness script (the redeem) used in input 0.
    pub witness_script: ScriptBuf,
    /// Value (sats) at input 0's `witness_utxo`.
    pub input_value: u64,
    /// For each signer in the federation: their derived child pubkey at
    /// `/0/derivation_index` and the full BIP-32 path that was written into
    /// `bip32_derivation`. Same order as `fed.signers()`.
    pub per_signer: Vec<PerSignerMeta>,
}

/// Metadata for one federation signer at a particular derivation index.
pub struct PerSignerMeta {
    /// Master fingerprint of the signer.
    pub fingerprint: bitcoin::bip32::Fingerprint,
    /// Derived child pubkey at `signer.xpub()/0/idx`.
    pub child_pubkey: bitcoin::secp256k1::PublicKey,
    /// Full path from master, e.g. `m/48'/1'/0'/2'/0/idx`.
    pub full_path: DerivationPath,
}

/// Build a synthetic unsigned PSBT spending a fake UTXO that pays the
/// federation's address at `derivation_index`.
///
/// The PSBT has exactly one input and one output (the burn address). It is
/// **not** broadcastable — the previous outpoint is fabricated — but it has
/// every field a `TestExternalSigner` and `bdk_wallet::Wallet::finalize_psbt`
/// need to produce a valid witness.
pub fn build_synthetic_psbt<S: Signer>(
    fed: &Federation<S>,
    derivation_index: u32,
    input_value: u64,
    output_value: u64,
) -> SyntheticPsbt {
    let secp = Secp256k1::new();

    // 1) Get the descriptor at this index → derived pubkeys + scripts.
    let definite = fed
        .descriptor()
        .at_derivation_index(derivation_index)
        .expect("derivation index in range");
    let script_pubkey = definite.script_pubkey();
    let witness_script = definite
        .explicit_script()
        .expect("wsh descriptor exposes its underlying redeem script");

    // 2) Compute per-signer derived pubkey + full path.
    let zero = ChildNumber::from_normal_idx(0).unwrap();
    let idx = ChildNumber::from_normal_idx(derivation_index).unwrap();
    let mut per_signer = Vec::with_capacity(fed.signers().len());
    for s in fed.signers() {
        let child_xpub = s
            .xpub()
            .derive_pub(&secp, &[zero, idx])
            .expect("derive_pub /0/idx");
        let full_path: DerivationPath = s
            .derivation_path()
            .into_iter()
            .copied()
            .chain([zero, idx])
            .collect::<Vec<ChildNumber>>()
            .into();
        per_signer.push(PerSignerMeta {
            fingerprint: s.fingerprint(),
            child_pubkey: child_xpub.public_key,
            full_path,
        });
    }

    // 3) Build the unsigned tx with one synthetic input + one output.
    let prev_outpoint = OutPoint {
        txid: Txid::from_byte_array([0xab_u8; 32]),
        vout: 0,
    };
    let tx_in = TxIn {
        previous_output: prev_outpoint,
        script_sig: ScriptBuf::new(),
        sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
        witness: Witness::new(),
    };

    // Burn output: standard OP_RETURN-ish? Use a deterministic P2WPKH-shaped
    // script_pubkey to make finalize_psbt happy. We use the descriptor's
    // own change-side derivation just for a valid Bitcoin script.
    let burn_script = definite.script_pubkey();
    let tx_out = TxOut {
        value: Amount::from_sat(output_value),
        script_pubkey: burn_script,
    };

    let unsigned_tx = Transaction {
        version: Version::TWO,
        lock_time: LockTime::ZERO,
        input: vec![tx_in],
        output: vec![tx_out],
    };

    let mut psbt = Psbt::from_unsigned_tx(unsigned_tx).expect("valid unsigned tx");
    let input = &mut psbt.inputs[0];

    input.witness_utxo = Some(TxOut {
        value: Amount::from_sat(input_value),
        script_pubkey,
    });
    input.witness_script = Some(witness_script.clone());

    let mut bip32: BTreeMap<
        bitcoin::secp256k1::PublicKey,
        (bitcoin::bip32::Fingerprint, DerivationPath),
    > = BTreeMap::new();
    for meta in &per_signer {
        bip32.insert(
            meta.child_pubkey,
            (meta.fingerprint, meta.full_path.clone()),
        );
    }
    input.bip32_derivation = bip32;

    SyntheticPsbt {
        psbt: UnsignedPsbt::new(psbt).expect("freshly constructed PSBT carries no signatures"),
        witness_script,
        input_value,
        per_signer,
    }
}

/// Build an in-memory `bdk_wallet::Wallet` from a federation's descriptor.
///
/// Mechanics:
///
/// 1. Take the descriptor's `Display` form, which is `wsh(...)#checksum`.
/// 2. Strip the `#checksum` — string-substituting `/0/*` -> `/1/*` for the
///    change descriptor would invalidate it anyway.
/// 3. Build the change descriptor by swapping `/0/*` for `/1/*`.
/// 4. Hand both to `Wallet::create(...)`, which recomputes its own
///    checksums and constructs a fresh in-memory wallet on `network`.
///
/// Used both by the synthetic round-trip test (testnet, no chain state)
/// and the regtest spend test (regtest, chain-synced via
/// [`sync::sync_wallet`]).
pub fn build_bdk_wallet<S: Signer>(fed: &Federation<S>, network: Network) -> Wallet {
    let receive_full = fed.descriptor().to_string();
    let receive = receive_full
        .split('#')
        .next()
        .expect("descriptor body present")
        .to_string();
    let change = receive.replace("/0/*", "/1/*");
    Wallet::create(receive, change)
        .network(network)
        .create_wallet_no_persist()
        .expect("create in-memory wallet")
}
