//! 3-of-5 federation construction + Ranged-mode address derivation tests.
//!
//! These verify that XPUBs aggregated from heterogeneous test signers
//! produce a coherent `wsh(sortedmulti(...))` descriptor, that addresses
//! derived at arbitrary indices match expectations, and that BDK's wallet
//! reveals the same first address as a direct miniscript derivation.

#![cfg(feature = "test-utils")]

use asterism_core::descriptor::{KeyMode, to_multipath_string};
use asterism_core::{Federation, NetworkType, Signer};
use asterism_xpub::TestFederationFixture;
use bdk_wallet::KeychainKind;
use bitcoin::{AddressType, Network};

mod common;

fn build_federation() -> (Federation<Box<dyn Signer>>, TestFederationFixture) {
    common::init_env();
    let fix = TestFederationFixture::from_env().expect("fixture loads");
    let test_signers = fix.build_test_signers().expect("signers build");
    assert_eq!(test_signers.len(), 5);

    let signers: Vec<Box<dyn Signer>> = test_signers
        .into_iter()
        .map(|t| Box::new(t.external_signer().clone()) as Box<dyn Signer>)
        .collect();

    let fed = Federation::with_key_mode(
        3,
        signers,
        NetworkType::Bitcoin(Network::Testnet),
        KeyMode::Ranged,
    )
    .expect("3-of-5 Ranged federation");
    (fed, fix)
}

#[test]
fn descriptor_is_ranged_3_of_5_wsh_sortedmulti() {
    let (fed, _) = build_federation();
    let s = fed.descriptor().to_string();
    assert!(s.starts_with("wsh(sortedmulti(3,"), "got: {s}");
    assert!(
        s.contains("/0/*"),
        "Ranged mode must emit /0/* wildcard, got: {s}"
    );
    // Five `xpub` origin metadata entries → five `[fp/...]xpub` substrings.
    let origin_count = s.matches('[').count();
    assert_eq!(
        origin_count, 5,
        "expected 5 `[fp/...]xpub` origins, got {origin_count} in: {s}"
    );
}

#[test]
fn addresses_at_multiple_indices_are_p2wsh_testnet() {
    let (fed, _) = build_federation();
    let desc = fed.descriptor();
    for idx in [0u32, 1, 7, 50] {
        let definite = desc.at_derivation_index(idx).expect("index in range");
        let addr = definite
            .address(Network::Testnet)
            .expect("descriptor produces an address at this index");
        assert_eq!(addr.address_type(), Some(AddressType::P2wsh), "index {idx}");
        assert!(
            addr.to_string().starts_with("tb1q"),
            "expected tb1q at idx {idx}, got {addr}"
        );
        assert_eq!(addr.script_pubkey(), definite.script_pubkey());
    }
}

#[test]
fn addresses_differ_across_indices() {
    let (fed, _) = build_federation();
    let desc = fed.descriptor();
    let a = desc
        .at_derivation_index(0)
        .unwrap()
        .address(Network::Testnet)
        .unwrap();
    let b = desc
        .at_derivation_index(1)
        .unwrap()
        .address(Network::Testnet)
        .unwrap();
    let c = desc
        .at_derivation_index(7)
        .unwrap()
        .address(Network::Testnet)
        .unwrap();
    assert_ne!(a, b);
    assert_ne!(a, c);
    assert_ne!(b, c);
}

#[test]
fn multipath_string_swaps_only_external_chain() {
    let (fed, _) = build_federation();
    let mp = to_multipath_string(fed.descriptor());
    assert!(mp.contains("/<0;1>/*"));
    assert!(
        !mp.contains("/0/*"),
        "single-chain wildcard should have been swapped"
    );
}

#[test]
fn bdk_wallet_first_address_matches_direct_descriptor_derivation() {
    let (fed, _) = build_federation();
    let mut wallet = common::build_bdk_wallet(&fed, Network::Testnet);

    let direct = fed
        .descriptor()
        .at_derivation_index(0)
        .unwrap()
        .address(Network::Testnet)
        .unwrap();

    let revealed = wallet.reveal_next_address(KeychainKind::External);
    assert_eq!(
        revealed.address.to_string(),
        direct.to_string(),
        "BDK's first revealed address must match the descriptor's index-0 address"
    );
    assert_eq!(revealed.index, 0);
}

#[test]
fn descriptor_carries_all_5_fingerprints() {
    let (fed, fix) = build_federation();
    let signers = fix.build_test_signers().unwrap();
    let s = fed.descriptor().to_string();
    for ts in &signers {
        let fp_hex = ts.external_signer().fingerprint().to_string();
        assert!(
            s.contains(&fp_hex),
            "descriptor missing fingerprint {fp_hex} for {:?}",
            ts.external_signer().label()
        );
    }
}
