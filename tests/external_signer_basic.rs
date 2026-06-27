//! Production-side `ExternalSigner` tests.
//!
//! These exercise the public surface (`new`, `from_descriptor_key`, the
//! `Signer` trait impl) and do not require the `test-utils` feature.

use std::fmt::Write as _;

use emvault_core::{DeviceType, Signer, SignerType, TransportType};
use emvault_xpub::{ExternalSigner, XpubError};
use bitcoin::Network;
use bitcoin::bip32::{DerivationPath, Fingerprint, Xpriv, Xpub};
use bitcoin::secp256k1::Secp256k1;

/// Build a deterministic descriptor key string `[fp/m/48'/1'/0'/2']xpub...`
/// suitable for end-to-end tests.
fn fixture(seed: u8) -> (Fingerprint, DerivationPath, Xpub, String) {
    let secp = Secp256k1::new();
    let xpriv = Xpriv::new_master(Network::Testnet, &[seed; 32]).unwrap();
    let path: DerivationPath = "m/48'/1'/0'/2'".parse().unwrap();
    let derived = xpriv.derive_priv(&secp, &path).unwrap();
    let xpub = Xpub::from_priv(&secp, &derived);
    let fp = xpriv.fingerprint(&secp);
    let s = format!("[{fp}/48h/1h/0h/2h]{xpub}");
    (fp, path, xpub, s)
}

#[test]
fn from_descriptor_key_round_trip() {
    let (fp, path, xpub, key) = fixture(0xa1);
    let signer = ExternalSigner::from_descriptor_key(
        &key,
        Network::Testnet,
        DeviceType::Trezor,
        Some("alice".into()),
    )
    .expect("valid descriptor key");
    assert_eq!(signer.fingerprint(), fp);
    assert_eq!(signer.derivation_path(), &path);
    assert_eq!(signer.xpub(), &xpub);
    assert_eq!(signer.label(), Some("alice"));
    assert_eq!(signer.signer_type(), SignerType::External);
    assert_eq!(signer.id().as_str(), fp.to_string());
}

#[test]
fn rejects_missing_origin() {
    let (_, _, xpub, _) = fixture(0xa2);
    let key = xpub.to_string();
    let err = ExternalSigner::from_descriptor_key(&key, Network::Testnet, DeviceType::Trezor, None)
        .unwrap_err();
    assert!(matches!(err, XpubError::MissingKeyOrigin), "got {err:?}");
}

#[test]
fn rejects_malformed_string() {
    let err = ExternalSigner::from_descriptor_key(
        "not-a-key",
        Network::Testnet,
        DeviceType::Generic,
        None,
    )
    .unwrap_err();
    assert!(
        matches!(err, XpubError::ParseDescriptorKey(_)),
        "got {err:?}"
    );
}

#[test]
fn rejects_network_mismatch() {
    // Generate a mainnet xpub but ask for Testnet.
    let secp = Secp256k1::new();
    let xpriv = Xpriv::new_master(Network::Bitcoin, &[0xa3; 32]).unwrap();
    let path: DerivationPath = "m/48'/0'/0'/2'".parse().unwrap();
    let derived = xpriv.derive_priv(&secp, &path).unwrap();
    let xpub = Xpub::from_priv(&secp, &derived);
    let fp = xpriv.fingerprint(&secp);
    let key = format!("[{fp}/48h/0h/0h/2h]{xpub}");

    let err = ExternalSigner::from_descriptor_key(&key, Network::Testnet, DeviceType::Ledger, None)
        .unwrap_err();
    assert!(
        matches!(err, XpubError::NetworkMismatch { .. }),
        "got {err:?}"
    );
}

#[test]
fn rejects_single_pubkey_form() {
    // Construct a SinglePub descriptor key by serializing a raw compressed
    // pubkey with origin metadata. The miniscript `DescriptorPublicKey`
    // FromStr accepts `[fp/path]<hex pubkey>` as `Single`.
    let secp = Secp256k1::new();
    let xpriv = Xpriv::new_master(Network::Testnet, &[0xa4; 32]).unwrap();
    let path: DerivationPath = "m/48'/1'/0'/2'".parse().unwrap();
    let derived = xpriv.derive_priv(&secp, &path).unwrap();
    let raw = derived.private_key.public_key(&secp).serialize();
    let pk_hex = raw
        .iter()
        .fold(String::with_capacity(raw.len() * 2), |mut acc, b| {
            write!(acc, "{b:02x}").unwrap();
            acc
        });
    let fp = xpriv.fingerprint(&secp);
    let key = format!("[{fp}/48h/1h/0h/2h]{pk_hex}");

    let err =
        ExternalSigner::from_descriptor_key(&key, Network::Testnet, DeviceType::Generic, None)
            .unwrap_err();
    assert!(
        matches!(err, XpubError::ExpectedXpubGotSingle),
        "got {err:?}"
    );
}

#[test]
fn capabilities_match_device_family() {
    let mk = |dev: DeviceType| {
        let (_, _, _, key) = fixture(0xb1);
        ExternalSigner::from_descriptor_key(&key, Network::Testnet, dev, None).unwrap()
    };
    assert!(mk(DeviceType::Jade).capabilities().blind_signing);
    assert!(mk(DeviceType::Jade).capabilities().taproot);
    assert!(mk(DeviceType::Trezor).capabilities().taproot);
    assert!(!mk(DeviceType::Coldcard).capabilities().taproot);
    assert!(
        mk(DeviceType::PassportPrime)
            .capabilities()
            .transports
            .contains(&TransportType::Qr)
    );
}

#[test]
fn upcasts_to_box_dyn_signer() {
    let (_, _, _, key) = fixture(0xb2);
    let signer =
        ExternalSigner::from_descriptor_key(&key, Network::Testnet, DeviceType::Trezor, None)
            .unwrap();
    let boxed: Box<dyn Signer> = Box::new(signer);
    assert_eq!(boxed.signer_type(), SignerType::External);
}

#[test]
fn health_check_reports_unreachable() {
    let (_, _, _, key) = fixture(0xb3);
    let signer =
        ExternalSigner::from_descriptor_key(&key, Network::Testnet, DeviceType::Generic, None)
            .unwrap();
    let health = signer.health_check().unwrap();
    assert!(!health.reachable);
    assert!(health.last_seen.is_none());
    assert!(health.firmware_version.is_none());
}
