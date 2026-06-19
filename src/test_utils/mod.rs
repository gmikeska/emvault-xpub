//! Test scaffolding (gated behind the `test-utils` feature).
//!
//! Nothing in this module is for production use. The keys are derived from
//! publicly-known BIP-39 test vectors and provide no security. The module
//! exists to let downstream crates and the asterism-xpub round-trip test
//! exercise the [`SigningCoordinator`](asterism_core::SigningCoordinator)
//! flow end-to-end without touching real hardware.

pub mod mnemonics;
pub mod signer;

pub use mnemonics::{TestFederationFixture, TestSignerSpec};
pub use signer::TestExternalSigner;
