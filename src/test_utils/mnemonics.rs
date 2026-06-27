//! BIP-39 fixture loader for the 5-signer test federation.
//!
//! The fixture is read from the process environment (callers should
//! `dotenvy::from_path("emvault-xpub/.env").ok()` before invoking
//! [`TestFederationFixture::from_env`]). See [`emvault-xpub/.env`] for the
//! canonical mnemonics; they are publicly-known test vectors with no value.

use emvault_core::DeviceType;
use bitcoin::Network;
use bitcoin::bip32::DerivationPath;

use crate::error::XpubError;
use crate::test_utils::signer::TestExternalSigner;

/// One slot in the 5-signer fixture.
#[derive(Clone, Debug)]
pub struct TestSignerSpec {
    /// 12 / 24 word BIP-39 mnemonic.
    pub mnemonic: String,
    /// Device the signer simulates (drives `capabilities()`).
    pub device_type: DeviceType,
    /// Stable label used in tests / UI.
    pub label: String,
}

/// A loaded fixture describing the 5-signer federation.
#[derive(Clone, Debug)]
pub struct TestFederationFixture {
    /// Bitcoin network the federation is bound to.
    pub network: Network,
    /// Federation derivation path (e.g. `m/48'/1'/0'/2'`).
    pub derivation_path: DerivationPath,
    /// One [`TestSignerSpec`] per signer (always length 5 from `.env`).
    pub specs: Vec<TestSignerSpec>,
}

impl TestFederationFixture {
    /// Load the fixture from process environment variables. The caller is
    /// expected to have already loaded `emvault-xpub/.env` via
    /// [`dotenvy::from_path`].
    ///
    /// # Errors
    ///
    /// Returns [`XpubError::Sign`] if any required environment variable is
    /// missing or unparseable. (We use [`XpubError::Sign`] rather than a
    /// dedicated `Env` variant because the fixture loader is itself a
    /// test-side concern; production callers never invoke this.)
    pub fn from_env() -> Result<Self, XpubError> {
        let network = parse_network(&env_required("EMVAULT_XPUB_TEST_NETWORK")?)?;
        let derivation_path = env_required("EMVAULT_XPUB_TEST_DERIVATION_PATH")?
            .parse::<DerivationPath>()
            .map_err(|e| XpubError::Sign(format!("derivation path: {e}")))?;

        let mut specs = Vec::with_capacity(5);
        for n in 1..=5u32 {
            let mnemonic = env_required(&format!("EMVAULT_XPUB_TEST_MNEMONIC_{n}"))?;
            let device_type =
                parse_device_type(&env_required(&format!("EMVAULT_XPUB_TEST_DEVICE_{n}"))?)?;
            let label = env_required(&format!("EMVAULT_XPUB_TEST_LABEL_{n}"))?;
            specs.push(TestSignerSpec {
                mnemonic,
                device_type,
                label,
            });
        }

        Ok(Self {
            network,
            derivation_path,
            specs,
        })
    }

    /// Materialize all 5 specs into [`TestExternalSigner`]s.
    ///
    /// # Errors
    ///
    /// Returns the first error encountered while parsing a mnemonic or
    /// deriving its xpriv at the fixture's derivation path.
    pub fn build_test_signers(&self) -> Result<Vec<TestExternalSigner>, XpubError> {
        self.specs
            .iter()
            .map(|spec| {
                TestExternalSigner::from_mnemonic(
                    &spec.mnemonic,
                    "",
                    &self.derivation_path,
                    self.network,
                    spec.device_type.clone(),
                    Some(spec.label.clone()),
                )
            })
            .collect()
    }
}

fn env_required(name: &str) -> Result<String, XpubError> {
    std::env::var(name).map_err(|_| {
        XpubError::Sign(format!(
            "missing required env var `{name}`; did you load emvault-xpub/.env?"
        ))
    })
}

fn parse_network(s: &str) -> Result<Network, XpubError> {
    match s.trim() {
        "bitcoin" | "mainnet" | "main" => Ok(Network::Bitcoin),
        // testnet4 ships in current bitcoin/bdk releases as `Network::Testnet4`,
        // but we keep the fixture flexible: it always represents non-mainnet.
        "testnet" | "testnet3" => Ok(Network::Testnet),
        "testnet4" => Ok(Network::Testnet4),
        "signet" => Ok(Network::Signet),
        "regtest" => Ok(Network::Regtest),
        other => Err(XpubError::Sign(format!(
            "unrecognized EMVAULT_XPUB_TEST_NETWORK: {other:?}"
        ))),
    }
}

fn parse_device_type(s: &str) -> Result<DeviceType, XpubError> {
    match s.trim() {
        "Trezor" => Ok(DeviceType::Trezor),
        "Jade" => Ok(DeviceType::Jade),
        "PassportPrime" => Ok(DeviceType::PassportPrime),
        "Ledger" => Ok(DeviceType::Ledger),
        "Coldcard" => Ok(DeviceType::Coldcard),
        "Generic" => Ok(DeviceType::Generic),
        other => Err(XpubError::Sign(format!(
            "unrecognized DeviceType {other:?}; expected one of \
             Trezor / Jade / Ledger / Coldcard / PassportPrime / Generic"
        ))),
    }
}
