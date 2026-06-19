//! [`TestExternalSigner`] — hardware-wallet simulator for round-trip tests.
//!
//! Holds an [`Xpriv`] derived from a BIP-39 mnemonic plus the matching
//! [`ExternalSigner`]. [`Self::sign_for_test`] mimics what a real device does
//! when the browser hands it a PSBT: it walks the inputs, finds the ones
//! whose `bip32_derivation` references this signer's fingerprint, derives
//! the matching child private key, and inserts an ECDSA partial signature.
//!
//! This struct is **never** linked into a production build — it lives behind
//! the `test-utils` feature and exists solely so the round-trip test can
//! exercise [`asterism_core::SigningCoordinator`] without a real device.

use asterism_core::{DeviceType, Signer};
use bitcoin::Network;
use bitcoin::Psbt;
use bitcoin::bip32::{DerivationPath, Xpriv, Xpub};
use bitcoin::hashes::Hash;
use bitcoin::secp256k1::{All, Message, Secp256k1};
use bitcoin::sighash::{EcdsaSighashType, SighashCache};

use crate::error::XpubError;
use crate::signer::ExternalSigner;

/// In-process hardware-wallet simulator backed by a BIP-39 mnemonic.
///
/// Pairs an [`ExternalSigner`] (the public-side identity) with the [`Xpriv`]
/// needed to actually produce signatures during tests.
#[derive(Debug)]
pub struct TestExternalSigner {
    master_xpriv: Xpriv,
    external_signer: ExternalSigner,
    secp: Secp256k1<All>,
}

impl TestExternalSigner {
    /// Build a `TestExternalSigner` from a BIP-39 mnemonic.
    ///
    /// The mnemonic + passphrase are converted to a 64-byte seed via
    /// PBKDF2-HMAC-SHA512 (the standard BIP-39 derivation), then to a
    /// master [`Xpriv`]. The derivation path is the federation path
    /// (e.g. `m/48'/1'/0'/2'`); the embedded [`ExternalSigner`] holds the
    /// xpub at that path with the master fingerprint as origin metadata —
    /// matching what a real hardware wallet exports.
    ///
    /// # Errors
    ///
    /// - [`XpubError::Mnemonic`] if `mnemonic` is not a valid BIP-39 phrase.
    /// - [`XpubError::Bip32`] if BIP-32 derivation along `derivation_path`
    ///   fails.
    /// - Anything [`ExternalSigner::new`] returns.
    pub fn from_mnemonic(
        mnemonic: &str,
        passphrase: &str,
        derivation_path: &DerivationPath,
        network: Network,
        device_type: DeviceType,
        label: Option<String>,
    ) -> Result<Self, XpubError> {
        let secp = Secp256k1::new();
        let parsed = bip39::Mnemonic::parse(mnemonic)?;
        let seed = parsed.to_seed_normalized(passphrase);

        let master_xpriv = Xpriv::new_master(network, &seed)?;
        let fingerprint = master_xpriv.fingerprint(&secp);

        let derived_xpriv = master_xpriv.derive_priv(&secp, derivation_path)?;
        let xpub: Xpub = Xpub::from_priv(&secp, &derived_xpriv);

        let external_signer = ExternalSigner::new(
            xpub,
            fingerprint,
            derivation_path.clone(),
            network,
            device_type,
            label,
        )?;

        Ok(Self {
            master_xpriv,
            external_signer,
            secp,
        })
    }

    /// The public-side identity. Use this to build the
    /// [`Federation`](asterism_core::Federation).
    pub fn external_signer(&self) -> &ExternalSigner {
        &self.external_signer
    }

    /// The underlying master [`Xpriv`]. Useful for tests that want to verify
    /// signatures against the derived child pubkey.
    pub fn master_xpriv(&self) -> &Xpriv {
        &self.master_xpriv
    }

    /// Simulate a hardware wallet receiving an unsigned PSBT and returning a
    /// copy with this signer's partial signatures inserted on every input
    /// whose `bip32_derivation` references this signer's fingerprint.
    ///
    /// Inputs are assumed to be P2WSH (matching `wsh(sortedmulti(...))`
    /// federations). Inputs missing `witness_script` or `witness_utxo`, or
    /// inputs with no `bip32_derivation` entry for this fingerprint, are
    /// silently skipped — exactly how a real device behaves when it has no
    /// key for the input.
    ///
    /// # Errors
    ///
    /// Returns [`XpubError::Sign`] if a sighash computation or BIP-32
    /// derivation fails for an input that *does* claim this signer's
    /// fingerprint, [`XpubError::Bip32`] if child derivation hits a malformed
    /// path.
    pub fn sign_for_test(&self, psbt: &Psbt) -> Result<Psbt, XpubError> {
        let mut out = psbt.clone();
        let our_fp = self.external_signer.fingerprint();

        for input_idx in 0..out.inputs.len() {
            let our_origin = out.inputs[input_idx]
                .bip32_derivation
                .iter()
                .find(|(_, (fp, _))| *fp == our_fp)
                .map(|(pk, (_, path))| (*pk, path.clone()));
            let Some((our_pk, full_path)) = our_origin else {
                continue;
            };

            let child_xpriv = self.master_xpriv.derive_priv(&self.secp, &full_path)?;

            // Defensive sanity check: make sure the descriptor's bip32_derivation
            // metadata actually maps to this child key. Mismatches would
            // produce a partial sig that fails finalize_psbt.
            debug_assert_eq!(
                bitcoin::secp256k1::PublicKey::from_secret_key(
                    &self.secp,
                    &child_xpriv.private_key
                ),
                our_pk,
                "TestExternalSigner: bip32_derivation pubkey does not match derived child pubkey \
                 (path={full_path}, fingerprint={our_fp})"
            );

            let witness_script = out.inputs[input_idx]
                .witness_script
                .clone()
                .ok_or_else(|| {
                    XpubError::Sign(format!("input {input_idx} missing witness_script"))
                })?;
            let value = out.inputs[input_idx]
                .witness_utxo
                .as_ref()
                .ok_or_else(|| XpubError::Sign(format!("input {input_idx} missing witness_utxo")))?
                .value;
            let sighash_type = out.inputs[input_idx]
                .sighash_type
                .map(bitcoin::psbt::PsbtSighashType::ecdsa_hash_ty)
                .transpose()
                .map_err(|e| XpubError::Sign(format!("invalid sighash type: {e}")))?
                .unwrap_or(EcdsaSighashType::All);

            let sighash = SighashCache::new(&out.unsigned_tx)
                .p2wsh_signature_hash(input_idx, &witness_script, value, sighash_type)
                .map_err(|e| XpubError::Sign(format!("sighash failure: {e}")))?;
            let sighash_msg = Message::from_digest(sighash.to_byte_array());

            let mut sig = self.secp.sign_ecdsa(&sighash_msg, &child_xpriv.private_key);
            sig.normalize_s();

            out.inputs[input_idx].partial_sigs.insert(
                bitcoin::PublicKey::new(our_pk),
                bitcoin::ecdsa::Signature {
                    signature: sig,
                    sighash_type,
                },
            );
        }
        Ok(out)
    }
}
