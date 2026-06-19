//! [`ExternalSigner`] — XPUB-based identity for consumer hardware wallets.
//!
//! `ExternalSigner` holds public-key material plus enough metadata for the
//! [`asterism_core::SigningCoordinator`] to route signing requests to the
//! correct browser-side device. It implements
//! [`asterism_core::Signer`] but not any signing trait — that work happens in
//! the trustee's browser, not in this library.

use asterism_core::{
    DeviceType, Signer, SignerCapabilities, SignerHealth, SignerId, SignerType, TransportType,
    error::SignerError, network::NetworkType,
};
use bitcoin::Network;
use bitcoin::bip32::{DerivationPath, Fingerprint, Xpub};

use crate::error::XpubError;
use crate::parsing::parse_origin;

/// XPUB-based [`Signer`] for consumer hardware wallets (Trezor, Jade, Ledger,
/// Coldcard, Foundation Passport Prime, etc.).
///
/// `ExternalSigner` is **structurally incapable** of signing server-side:
/// [`Self::signer_type`] always returns [`SignerType::External`], so the
/// [`asterism_core::SigningCoordinator`] emits a
/// [`SigningAction::External`](asterism_core::SigningAction::External)
/// whenever this signer is asked to participate, leaving the actual signing
/// to the browser-side device SDK.
#[derive(Clone, Debug)]
pub struct ExternalSigner {
    id: SignerId,
    label: Option<String>,
    xpub: Xpub,
    fingerprint: Fingerprint,
    derivation_path: DerivationPath,
    network: Network,
    device_type: DeviceType,
}

impl ExternalSigner {
    /// Construct an `ExternalSigner` from already-parsed key material.
    ///
    /// # Errors
    ///
    /// - [`XpubError::NetworkMismatch`] if the xpub's
    ///   [`network`](bitcoin::bip32::Xpub::network) disagrees with `network`.
    /// - [`XpubError::MasterPathTooDeep`] if `derivation_path` has more than
    ///   255 levels (BIP-32 caps depth at one byte).
    pub fn new(
        xpub: Xpub,
        fingerprint: Fingerprint,
        derivation_path: DerivationPath,
        network: Network,
        device_type: DeviceType,
        label: Option<String>,
    ) -> Result<Self, XpubError> {
        let expected_kind = bitcoin::NetworkKind::from(network);
        if xpub.network != expected_kind {
            return Err(XpubError::NetworkMismatch {
                expected: network,
                actual: xpub.network,
            });
        }
        if derivation_path.len() > 255 {
            return Err(XpubError::MasterPathTooDeep {
                depth: derivation_path.len(),
            });
        }
        let id = SignerId::from_fingerprint(fingerprint);
        Ok(Self {
            id,
            label,
            xpub,
            fingerprint,
            derivation_path,
            network,
            device_type,
        })
    }

    /// Construct an `ExternalSigner` from a descriptor key string in the
    /// format real device exports use:
    ///
    /// ```text
    /// [d34db33f/48'/1'/0'/2']tpubD6NzVbkrYhZ4...
    /// ```
    ///
    /// # Errors
    ///
    /// - [`XpubError::ParseDescriptorKey`] if the string is not a valid
    ///   miniscript descriptor key.
    /// - [`XpubError::MissingKeyOrigin`] if the parsed key has no
    ///   `[fingerprint/path]` origin.
    /// - [`XpubError::ExpectedXpubGotSingle`] /
    ///   [`XpubError::MultiXpubNotSupported`] for non-xpub inputs.
    /// - Plus any error returned by [`Self::new`].
    pub fn from_descriptor_key(
        key: &str,
        network: Network,
        device_type: DeviceType,
        label: Option<String>,
    ) -> Result<Self, XpubError> {
        let (fingerprint, derivation_path, xpub) = parse_origin(key)?;
        Self::new(
            xpub,
            fingerprint,
            derivation_path,
            network,
            device_type,
            label,
        )
    }

    /// The device family this signer represents.
    pub fn device_type(&self) -> &DeviceType {
        &self.device_type
    }

    /// The Bitcoin network this signer is bound to.
    pub fn network(&self) -> Network {
        self.network
    }

    /// Set or replace the human-readable label.
    pub fn set_label(&mut self, label: Option<String>) {
        self.label = label;
    }
}

impl Signer for ExternalSigner {
    fn id(&self) -> SignerId {
        self.id.clone()
    }

    fn label(&self) -> Option<&str> {
        self.label.as_deref()
    }

    fn xpub(&self) -> &Xpub {
        &self.xpub
    }

    fn fingerprint(&self) -> Fingerprint {
        self.fingerprint
    }

    fn derivation_path(&self) -> &DerivationPath {
        &self.derivation_path
    }

    fn signer_type(&self) -> SignerType {
        SignerType::External
    }

    fn supported_networks(&self) -> Vec<NetworkType> {
        vec![NetworkType::Bitcoin(self.network)]
    }

    fn capabilities(&self) -> SignerCapabilities {
        capabilities_for(&self.device_type)
    }

    fn health_check(&self) -> Result<SignerHealth, SignerError> {
        // The server has no path to the device — only the browser does.
        // Web apps that want browser-reported liveness should track it at
        // the session layer, not via this trait.
        Ok(SignerHealth {
            reachable: false,
            firmware_version: None,
            last_seen: None,
        })
    }
}

/// Capability matrix derived from
/// `design_docs/asterism_multisignature_library.md` (XPUB Backend section)
/// and the per-device tables that follow it.
fn capabilities_for(device: &DeviceType) -> SignerCapabilities {
    match device {
        // Jade speaks both Bitcoin and Liquid; its USB and BLE transports are
        // first-class and it supports Taproot key/script-path spends. Blind
        // signing is a Jade hallmark for confidential Liquid transactions.
        DeviceType::Jade => SignerCapabilities {
            blind_signing: true,
            taproot: true,
            musig2: false,
            transports: vec![TransportType::Usb, TransportType::Ble, TransportType::Qr],
        },
        // Trezor (Model T / Safe family) supports Taproot via Trezor Connect.
        DeviceType::Trezor => SignerCapabilities {
            blind_signing: false,
            taproot: true,
            musig2: false,
            transports: vec![TransportType::Usb],
        },
        // Ledger supports Taproot for SegWit v1 paths.
        DeviceType::Ledger => SignerCapabilities {
            blind_signing: false,
            taproot: true,
            musig2: false,
            transports: vec![TransportType::Usb, TransportType::Ble],
        },
        // Foundation Passport Prime: USB, QR (camera), microSD; Taproot
        // supported in current firmware.
        DeviceType::PassportPrime => SignerCapabilities {
            blind_signing: false,
            taproot: true,
            musig2: false,
            transports: vec![TransportType::Usb, TransportType::Qr, TransportType::SdCard],
        },
        // Coldcard: SD card air-gap, NFC, USB. Taproot landed in recent
        // firmware but we keep it conservative until certified for asterism
        // federations.
        DeviceType::Coldcard => SignerCapabilities {
            blind_signing: false,
            taproot: false,
            musig2: false,
            transports: vec![
                TransportType::SdCard,
                TransportType::Nfc,
                TransportType::Usb,
            ],
        },
        // PKCS#11 HSM is not a consumer-hardware-wallet path; if someone wires
        // it through `ExternalSigner` (e.g. for a network-attached signing
        // service that proxies an HSM), report PKCS#11 transport with a
        // conservative capability set.
        DeviceType::Hsm { .. } => SignerCapabilities {
            blind_signing: false,
            taproot: true,
            musig2: false,
            transports: vec![TransportType::Pkcs11],
        },
        // Generic / unknown — the conservative default.
        DeviceType::Generic => {
            SignerCapabilities::p2wsh_only(vec![TransportType::Usb, TransportType::Qr])
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::bip32::Xpriv;
    use bitcoin::secp256k1::Secp256k1;

    fn deterministic_testnet_xpub(seed_byte: u8) -> Xpub {
        let secp = Secp256k1::new();
        let xpriv = Xpriv::new_master(Network::Testnet, &[seed_byte; 32]).unwrap();
        Xpub::from_priv(&secp, &xpriv)
    }

    #[test]
    fn new_validates_network_kind() {
        let xpub = deterministic_testnet_xpub(0x11);
        let err = ExternalSigner::new(
            xpub,
            Fingerprint::default(),
            DerivationPath::master(),
            Network::Bitcoin,
            DeviceType::Generic,
            None,
        )
        .unwrap_err();
        assert!(matches!(err, XpubError::NetworkMismatch { .. }));
    }

    #[test]
    fn capabilities_jade_blind_signing_taproot() {
        let caps = capabilities_for(&DeviceType::Jade);
        assert!(caps.blind_signing);
        assert!(caps.taproot);
    }

    #[test]
    fn capabilities_coldcard_no_taproot() {
        let caps = capabilities_for(&DeviceType::Coldcard);
        assert!(!caps.taproot);
        assert!(caps.transports.contains(&TransportType::SdCard));
    }

    #[test]
    fn signer_type_is_always_external() {
        let xpub = deterministic_testnet_xpub(0x22);
        let signer = ExternalSigner::new(
            xpub,
            Fingerprint::default(),
            DerivationPath::master(),
            Network::Testnet,
            DeviceType::Trezor,
            Some("Alice's Trezor".into()),
        )
        .unwrap();
        assert_eq!(signer.signer_type(), SignerType::External);
        assert_eq!(signer.label(), Some("Alice's Trezor"));
    }
}
