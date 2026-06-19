//! # asterism-xpub
//!
//! XPUB-based [`Signer`](asterism_core::Signer) backend for consumer hardware
//! wallets (Trezor, Blockstream Jade, Ledger, Coldcard, Foundation Passport
//! Prime, etc.).
//!
//! ## What this crate provides
//!
//! - [`ExternalSigner`] — a [`Signer`](asterism_core::Signer) implementation
//!   that holds an XPUB plus key-origin metadata. It declares
//!   [`SignerType::External`](asterism_core::SignerType::External) so the
//!   [`SigningCoordinator`](asterism_core::SigningCoordinator) routes signing
//!   requests through the browser, never attempting to sign server-side.
//! - [`ExternalSigner::from_descriptor_key`] — parse a `[fp/origin]xpub...`
//!   descriptor key (the format real hardware wallets export) into a fully
//!   populated signer.
//! - [`XpubError`] — specific, actionable errors per the project's error-style
//!   guidance.
//! - Behind the `test-utils` feature: [`test_utils::TestExternalSigner`] —
//!   a deterministic in-process simulator that mimics a hardware wallet's
//!   signing behaviour for round-trip tests of the
//!   [`SigningCoordinator`](asterism_core::SigningCoordinator) flow.
//!
//! ## Why "External"?
//!
//! Consumer hardware wallets are **structurally incapable** of signing
//! server-side: the device is in the trustee's pocket, connected to the
//! trustee's browser, communicating over USB-HID / BLE / QR. The Asterism
//! library never sees the device. `ExternalSigner` therefore holds public-key
//! material only and routes every signing request through
//! [`SigningCoordinator::request_signatures`](asterism_core::SigningCoordinator::request_signatures),
//! which produces a
//! [`SigningAction::External`](asterism_core::SigningAction::External)
//! payload for the web layer to forward to the browser. The browser invokes
//! the device-specific SDK (Trezor Connect, Jade serial, Ledger hwapp, etc.),
//! collects the signed PSBT, and feeds it back via
//! [`SigningCoordinator::receive_signature`](asterism_core::SigningCoordinator::receive_signature).
//!
//! This crate intentionally contains **no USB/HID/BLE drivers and no signing
//! code** — that work lives in the browser layer of the consuming web app.
//!
//! ## A short example
//!
//! ```ignore
//! use asterism_core::{Federation, NetworkType};
//! use asterism_xpub::{ExternalSigner, DeviceType};
//! use bitcoin::Network;
//!
//! // Real device exports come back from the browser as descriptor keys:
//! //   "[d34db33f/48'/1'/0'/2']tpubD6NzVbkrYhZ4..."
//! let alice = ExternalSigner::from_descriptor_key(
//!     alice_descriptor_key,
//!     Network::Testnet,
//!     DeviceType::Trezor,
//!     Some("Alice's Trezor".into()),
//! )?;
//! let bob   = ExternalSigner::from_descriptor_key(bob_key,   Network::Testnet, DeviceType::Jade,   None)?;
//! let carol = ExternalSigner::from_descriptor_key(carol_key, Network::Testnet, DeviceType::Ledger, None)?;
//!
//! let federation = Federation::new(
//!     2,
//!     vec![Box::new(alice) as _, Box::new(bob) as _, Box::new(carol) as _],
//!     NetworkType::Bitcoin(Network::Testnet),
//! )?;
//!
//! let descriptor = federation.descriptor();
//! let address = descriptor.at_derivation_index(0)?.address(Network::Testnet)?;
//! println!("Receive at: {address}");
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```
//!
//! ## Reference
//!
//! See `design_docs/asterism_multisignature_library.md` (the **XPUB Backend**
//! section) for the full design rationale.

#![warn(missing_docs)]
#![forbid(unsafe_code)]
#![allow(
    // chatty on every getter/builder; not a footgun in this codebase
    clippy::must_use_candidate,
    // const-fn surface area is still evolving in stable Rust
    clippy::missing_const_for_fn,
)]

pub mod error;
pub mod parsing;
pub mod signer;

#[cfg(feature = "test-utils")]
pub mod test_utils;

pub use error::XpubError;
pub use parsing::parse_origin;
pub use signer::ExternalSigner;

#[cfg(feature = "test-utils")]
pub use test_utils::{TestExternalSigner, TestFederationFixture, TestSignerSpec};

/// Re-export of `asterism-core`'s [`DeviceType`](asterism_core::DeviceType)
/// so callers don't need a direct dependency on the core crate.
pub use asterism_core::DeviceType;
