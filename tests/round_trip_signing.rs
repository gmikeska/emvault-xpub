//! Full `request_signatures` -> `sign_for_test` -> `receive_signature` -> `finalize`
//! round trip against a synthetic in-memory PSBT.
//!
//! This test runs entirely in process — there is no chain interaction, no
//! broadcast, no real UTXO. The PSBT carries a fabricated previous outpoint
//! plus all the metadata (`witness_utxo`, `witness_script`,
//! `bip32_derivation`) that a real BDK-built PSBT would contain. The
//! finalized transaction's witness is asserted to be valid for the
//! `wsh(sortedmulti(3, ...))` script.

#![cfg(feature = "test-utils")]

use emvault_core::descriptor::KeyMode;
use emvault_core::{Federation, NetworkType, Signer, SigningAction, SigningCoordinator};
use emvault_xpub::{TestExternalSigner, TestFederationFixture};
use bdk_wallet::SignOptions;

/// `SignOptions` tuned for synthetic-PSBT round-trip tests.
///
/// `trust_witness_utxo: true` — our PSBT carries no `non_witness_utxo`
/// because the previous transaction is fabricated. BDK normally requires
/// the prev tx as a defence against the `SegWit` fee-malleation attack;
/// flipping this flag tells BDK we accept the `witness_utxo` as-is.
fn synthetic_sign_options() -> SignOptions {
    SignOptions {
        trust_witness_utxo: true,
        ..Default::default()
    }
}
use bitcoin::Network;
use bitcoin::hashes::Hash;
use bitcoin::secp256k1::{Message, Secp256k1};
use bitcoin::sighash::{EcdsaSighashType, SighashCache};

mod common;

fn build_3_of_5() -> (Federation<Box<dyn Signer>>, Vec<TestExternalSigner>) {
    common::init_env();
    let fix = TestFederationFixture::from_env().expect("fixture loads");
    let test_signers = fix.build_test_signers().expect("signers build");

    let signers: Vec<Box<dyn Signer>> = test_signers
        .iter()
        .map(|t| Box::new(t.external_signer().clone()) as Box<dyn Signer>)
        .collect();

    let fed = Federation::with_key_mode(
        3,
        signers,
        NetworkType::Bitcoin(Network::Testnet),
        KeyMode::Ranged,
    )
    .expect("3-of-5 Ranged");
    (fed, test_signers)
}

#[test]
fn three_of_five_round_trip_finalizes() {
    let (fed, test_signers) = build_3_of_5();
    let wallet = common::build_bdk_wallet(&fed, Network::Testnet);

    let synth = common::build_synthetic_psbt(&fed, 5, 100_000, 99_000);
    let mut coord = SigningCoordinator::new(&fed, synth.psbt);

    // 1) Request signatures. With an all-External federation, BDK's
    //    `Wallet::sign` is a no-op (no TransactionSigners registered) and
    //    the coordinator emits 5 SigningAction::External payloads.
    let actions = coord
        .request_signatures(&wallet, synthetic_sign_options())
        .expect("request_signatures");
    assert_eq!(actions.len(), 5);
    let mut external_count = 0;
    for (_id, action) in &actions {
        if matches!(action, SigningAction::External(_)) {
            external_count += 1;
        }
    }
    assert_eq!(external_count, 5, "all 5 actions should be External");

    // 2) Pick 3 of the 5 signers (#0, #2, #4) and route their PSBTs
    //    through TestExternalSigner::sign_for_test, then back through
    //    receive_signature.
    let picks = [0usize, 2, 4];
    for &i in &picks {
        let action = &actions[i].1;
        let req_psbt = match action {
            SigningAction::External(ext) => ext.request.psbt.clone(),
            SigningAction::Direct => panic!("expected External action at index {i}"),
        };
        let signed = test_signers[i]
            .sign_for_test(&req_psbt)
            .expect("test signer signs");
        let signer_id = test_signers[i].external_signer().id();
        coord
            .receive_signature(&signer_id, signed)
            .expect("coordinator accepts the signed PSBT");
    }

    assert_eq!(
        coord.signatures_collected(),
        3,
        "coordinator should have recorded 3 contributing signers"
    );
    assert!(coord.is_complete(), "3-of-5 threshold reached");

    // 3) Finalize. The descriptor is re-registered on the wallet via
    //    create_wallet_no_persist, so finalize_psbt knows how to satisfy
    //    `wsh(sortedmulti(3, ...))`.
    let finalized = coord
        .finalize(&wallet, synthetic_sign_options())
        .expect("finalize");

    // Witness shape for wsh(sortedmulti(m, ...)) is:
    //   [empty, sig_1, sig_2, sig_3, witness_script]
    // i.e. m + 2 stack items.
    let tx = finalized.transaction();
    assert_eq!(tx.input.len(), 1);
    let witness = &tx.input[0].witness;
    let witness_items: Vec<&[u8]> = witness.iter().collect();
    assert_eq!(
        witness_items.len(),
        5,
        "wsh(sortedmulti(3,...)) witness should be 5 items, got {} items: {witness_items:?}",
        witness_items.len()
    );
    assert!(
        witness_items[0].is_empty(),
        "leading witness item must be empty (CHECKMULTISIG bug compensator)"
    );
    // Last stack item is the witness_script (the sortedmulti redeem).
    assert_eq!(
        witness_items.last().copied(),
        Some(synth.witness_script.as_bytes()),
        "trailing witness item must be the redeem script"
    );

    // 4) Verify each contributing signer's ECDSA signature against its
    //    derived child pubkey + the recomputed sighash.
    let secp = Secp256k1::new();
    let sighash = SighashCache::new(&tx.clone())
        .p2wsh_signature_hash(
            0,
            &synth.witness_script,
            bitcoin::Amount::from_sat(synth.input_value),
            EcdsaSighashType::All,
        )
        .expect("recompute sighash");
    let msg = Message::from_digest(sighash.to_byte_array());

    let mut verified = 0;
    for sig_bytes in &witness_items[1..witness_items.len() - 1] {
        // Each is a DER-encoded ECDSA signature with sighash byte appended.
        let der_len = sig_bytes.len() - 1;
        let sig = bitcoin::secp256k1::ecdsa::Signature::from_der(&sig_bytes[..der_len])
            .expect("DER decode partial sig");
        for meta in &synth.per_signer {
            if secp.verify_ecdsa(&msg, &sig, &meta.child_pubkey).is_ok() {
                verified += 1;
                break;
            }
        }
    }
    assert_eq!(
        verified, 3,
        "3 partial sigs should each verify against one fed pubkey"
    );
}

#[test]
fn wrong_fingerprint_signature_is_rejected() {
    let (fed, test_signers) = build_3_of_5();
    let wallet = common::build_bdk_wallet(&fed, Network::Testnet);

    let synth = common::build_synthetic_psbt(&fed, 11, 50_000, 49_000);
    let mut coord = SigningCoordinator::new(&fed, synth.psbt);
    let actions = coord
        .request_signatures(&wallet, synthetic_sign_options())
        .expect("request_signatures");

    // Get signer #1's request, but sign with signer #2's key, then claim
    // we're returning signer #1's signature. The coordinator must detect
    // that no new partial sig attributable to signer #1's fingerprint is
    // present and reject.
    let req_psbt_for_1 = match &actions[1].1 {
        SigningAction::External(ext) => ext.request.psbt.clone(),
        SigningAction::Direct => unreachable!(),
    };
    let signed_by_2 = test_signers[2]
        .sign_for_test(&req_psbt_for_1)
        .expect("test signer signs (with wrong key)");
    let signer_id_for_1 = test_signers[1].external_signer().id();
    let err = coord
        .receive_signature(&signer_id_for_1, signed_by_2)
        .expect_err("coordinator must reject mismatched signer/signature");
    let msg = format!("{err}");
    assert!(
        msg.contains("no new partial signature attributable to this signer"),
        "expected attribution error, got: {msg}"
    );
}
