//! Helpers for parsing descriptor-key strings exported by hardware wallets.
//!
//! Real device exports come back from the browser-side SDK as strings of the
//! form `[fingerprint/derivation/path]xpub...`. This module normalizes them
//! into the trio of values an [`ExternalSigner`](crate::ExternalSigner) needs.

use bitcoin::bip32::{DerivationPath, Fingerprint, Xpub};
use miniscript::DescriptorPublicKey;

use crate::error::XpubError;

/// Parse a descriptor-key string into `(fingerprint, derivation_path, xpub)`.
///
/// Accepts the descriptor-key syntax from BIP-380 / miniscript, e.g.
///
/// ```text
/// [d34db33f/48'/1'/0'/2']tpubD6NzVbkrYhZ4...
/// ```
///
/// # Errors
///
/// - [`XpubError::ParseDescriptorKey`] if the string is not a valid descriptor
///   public key.
/// - [`XpubError::MissingKeyOrigin`] if the parsed key carries no
///   `[fingerprint/path]` origin (real device exports always include it; raw
///   xpubs without origin metadata leave the federation unable to populate
///   `bip32_derivation` in PSBTs).
/// - [`XpubError::ExpectedXpubGotSingle`] if the input was a `SinglePub` (raw
///   public key rather than an xpub).
/// - [`XpubError::MultiXpubNotSupported`] if the input was a BIP-389
///   multipath xpub (`/<0;1>/*`); pass the single-path receive form instead.
pub fn parse_origin(key: &str) -> Result<(Fingerprint, DerivationPath, Xpub), XpubError> {
    let dpk: DescriptorPublicKey = key.parse()?;
    match dpk {
        DescriptorPublicKey::XPub(xkey) => {
            let (fp, path) = xkey.origin.ok_or(XpubError::MissingKeyOrigin)?;
            Ok((fp, path, xkey.xkey))
        }
        DescriptorPublicKey::Single(_) => Err(XpubError::ExpectedXpubGotSingle),
        DescriptorPublicKey::MultiXPub(_) => Err(XpubError::MultiXpubNotSupported),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::Network;
    use bitcoin::bip32::Xpriv;
    use bitcoin::secp256k1::Secp256k1;

    /// Build a deterministic descriptor-key string `[fp/m/48'/1'/0'/2']xpub...`
    /// suitable for parser round-trip tests.
    fn deterministic_descriptor_key(seed: u8) -> (Fingerprint, DerivationPath, Xpub, String) {
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
    fn parse_round_trip() {
        let (fp, path, xpub, s) = deterministic_descriptor_key(0x33);
        let (got_fp, got_path, got_xpub) = parse_origin(&s).unwrap();
        assert_eq!(got_fp, fp);
        assert_eq!(got_path, path);
        assert_eq!(got_xpub, xpub);
    }

    #[test]
    fn missing_origin_rejected() {
        // Pure xpub without `[origin]` prefix.
        let (_, _, xpub, _) = deterministic_descriptor_key(0x44);
        let s = xpub.to_string();
        let err = parse_origin(&s).unwrap_err();
        assert!(matches!(err, XpubError::MissingKeyOrigin));
    }

    #[test]
    fn malformed_string_rejected() {
        let err = parse_origin("not-a-key").unwrap_err();
        assert!(matches!(err, XpubError::ParseDescriptorKey(_)));
    }
}
