//! Error type for [`emvault-xpub`](crate).
//!
//! Each variant points at a specific failure mode with enough context for the
//! caller to act on it (per the project's error-style guidance in
//! `.cursorrules`). Cross-crate errors convert via `From` at the boundary.

use bitcoin::Network;

/// Errors produced by [`emvault-xpub`](crate).
#[derive(Debug, thiserror::Error)]
pub enum XpubError {
    /// The string did not parse as a [`miniscript::DescriptorPublicKey`].
    #[error("could not parse descriptor key: {0}")]
    ParseDescriptorKey(#[from] miniscript::descriptor::DescriptorKeyParseError),

    /// The descriptor key parsed cleanly but had no `[fingerprint/path]`
    /// origin metadata. Hardware wallet exports must include this.
    #[error(
        "descriptor key has no `[fingerprint/path]` origin metadata; \
         the device export must include it"
    )]
    MissingKeyOrigin,

    /// The descriptor key was a `SinglePub` (raw public key); we require an
    /// xpub so the federation can derive multiple addresses.
    #[error(
        "descriptor key is a single raw public key; an xpub with key origin \
         is required (e.g. \"[fp/48'/1'/0'/2']tpubD...\")"
    )]
    ExpectedXpubGotSingle,

    /// The descriptor key was a BIP-389 multipath xpub (`/<0;1>/*`); callers
    /// should pass the single-path receive form.
    #[error("multipath xpubs (`/<0;1>/*`) are not supported here; pass the single-path xpub")]
    MultiXpubNotSupported,

    /// The xpub's network kind disagrees with the requested network.
    #[error(
        "network mismatch: signer was constructed for {expected:?} but xpub \
         declares {actual:?}"
    )]
    NetworkMismatch {
        /// Network the caller asked for.
        expected: Network,
        /// Network kind the xpub itself reports.
        actual: bitcoin::NetworkKind,
    },

    /// The provided derivation path is too deep to encode in a BIP-32 depth
    /// byte (max 255).
    #[error("derivation path is {depth} levels deep; BIP-32 caps depth at 255")]
    MasterPathTooDeep {
        /// Length of the offending path.
        depth: usize,
    },

    /// A BIP-32 derivation operation failed (usually only happens with
    /// malformed paths).
    #[error("BIP-32 derivation failed: {0}")]
    Bip32(#[from] bitcoin::bip32::Error),

    /// A signing-side failure surfaced from the test harness
    /// (`TestExternalSigner::sign_for_test`). Production
    /// [`ExternalSigner`](crate::ExternalSigner) instances never produce this
    /// because they cannot sign.
    #[error("test signer failure: {0}")]
    Sign(String),

    /// A BIP-39 mnemonic could not be decoded. Only constructible with the
    /// `test-utils` feature.
    #[cfg(feature = "test-utils")]
    #[error("BIP-39 mnemonic decode failed: {0}")]
    Mnemonic(#[from] bip39::Error),
}
