//! Unit tests for [`TestExternalSigner`] and the BIP-39 fixture loader.

#![cfg(feature = "test-utils")]

use std::collections::HashSet;

use asterism_core::{DeviceType, Signer};
use asterism_xpub::{TestExternalSigner, TestFederationFixture};
use bitcoin::Network;
use bitcoin::bip32::{DerivationPath, Xpub};
use bitcoin::secp256k1::Secp256k1;

mod common;

fn fixture() -> TestFederationFixture {
    common::init_env();
    TestFederationFixture::from_env().expect("load fixture from .env")
}

#[test]
fn from_mnemonic_is_deterministic() {
    let path: DerivationPath = "m/48'/1'/0'/2'".parse().unwrap();
    let phrase = "abandon abandon abandon abandon abandon abandon abandon \
                  abandon abandon abandon abandon about";

    let a = TestExternalSigner::from_mnemonic(
        phrase,
        "",
        &path,
        Network::Testnet,
        DeviceType::Trezor,
        None,
    )
    .unwrap();
    let b = TestExternalSigner::from_mnemonic(
        phrase,
        "",
        &path,
        Network::Testnet,
        DeviceType::Trezor,
        None,
    )
    .unwrap();
    assert_eq!(
        a.external_signer().fingerprint(),
        b.external_signer().fingerprint()
    );
    assert_eq!(a.external_signer().xpub(), b.external_signer().xpub());
}

#[test]
fn fixture_yields_five_distinct_fingerprints() {
    let fix = fixture();
    let signers = fix.build_test_signers().expect("build signers");
    assert_eq!(signers.len(), 5);
    let mut seen = HashSet::new();
    for s in &signers {
        let inserted = seen.insert(s.external_signer().fingerprint());
        assert!(
            inserted,
            "duplicate fingerprint {:?} — federation construction would reject",
            s.external_signer().fingerprint()
        );
    }
}

#[test]
fn fixture_assigns_each_distinct_device_type() {
    let fix = fixture();
    let signers = fix.build_test_signers().unwrap();
    let labels: Vec<&str> = signers
        .iter()
        .map(|s| s.external_signer().label().unwrap_or(""))
        .collect();
    assert!(labels.contains(&"alice-trezor"));
    assert!(labels.contains(&"bob-jade"));
    assert!(labels.contains(&"carol-ledger"));
    assert!(labels.contains(&"dave-passport"));
    assert!(labels.contains(&"eve-coldcard"));

    let device_kinds: HashSet<_> = signers
        .iter()
        .map(|s| s.external_signer().device_type().clone())
        .collect();
    assert!(device_kinds.contains(&DeviceType::Trezor));
    assert!(device_kinds.contains(&DeviceType::Jade));
    assert!(device_kinds.contains(&DeviceType::Ledger));
    assert!(device_kinds.contains(&DeviceType::PassportPrime));
    assert!(device_kinds.contains(&DeviceType::Coldcard));
}

#[test]
fn external_signer_xpub_matches_master_xpriv_at_path() {
    let fix = fixture();
    let signers = fix.build_test_signers().unwrap();
    let secp = Secp256k1::new();
    for s in &signers {
        let derived_xpriv = s
            .master_xpriv()
            .derive_priv(&secp, &fix.derivation_path)
            .unwrap();
        let xpub_recomputed = Xpub::from_priv(&secp, &derived_xpriv);
        assert_eq!(
            s.external_signer().xpub(),
            &xpub_recomputed,
            "xpub embedded in TestExternalSigner ({:?}) must equal the xpub derived directly \
             from its master xpriv at the federation path",
            s.external_signer().label()
        );
    }
}

#[test]
fn fixture_network_is_testnet_class() {
    let fix = fixture();
    assert_eq!(fix.network, Network::Testnet);
}
