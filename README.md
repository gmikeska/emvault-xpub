# asterism-xpub

XPUB-based external [`Signer`] backend for the Emerald multi-signature custody
platform. Consumer hardware wallets (Trezor, Blockstream Jade, Ledger,
Coldcard, Foundation Passport Prime, etc.) export an XPUB at a BIP-48
derivation path; this crate ingests that XPUB plus its key-origin metadata
and exposes it as an `ExternalSigner` ready to drop into an
`asterism_core::Federation`.

## Quick start

```rust,ignore
use asterism_core::{Federation, NetworkType};
use asterism_xpub::{ExternalSigner, DeviceType};
use bitcoin::Network;

let alice = ExternalSigner::from_descriptor_key(
    "[d34db33f/48'/1'/0'/2']tpubD6NzVbkrYhZ4...",
    Network::Testnet,
    DeviceType::Trezor,
    Some("Alice's Trezor".into()),
)?;
// ... bob, carol from their respective device exports ...

let fed = Federation::new(
    2,
    vec![Box::new(alice) as _, Box::new(bob) as _, Box::new(carol) as _],
    NetworkType::Bitcoin(Network::Testnet),
)?;

let address = fed.descriptor().at_derivation_index(0)?.address(Network::Testnet)?;
```

## What this crate is **not**

It is **not** a USB driver, an HID driver, a BLE stack, or a signing
backend. Consumer hardware wallets are physically with the trustee, attached
to the trustee's browser. The browser is responsible for:

1. Extracting the XPUB at the federation's derivation path.
2. Forwarding unsigned PSBTs to the device for signing (via Trezor Connect,
   Jade serial API, Ledger `hwapp`, etc.).
3. Returning the signed PSBT to the web app.

The `SigningCoordinator` in `asterism-core` orchestrates this by emitting a
`SigningAction::External` payload for every external signer in the
federation; `asterism-xpub` provides the server-side identity that makes
that payload meaningful.

## The `test-utils` feature

When you enable `test-utils`, this crate also exposes `TestExternalSigner` —
a deterministic in-process simulator that derives an `Xpriv` from a BIP-39
mnemonic and signs PSBTs the same way a real hardware wallet would. Combined
with the dev mnemonics in [`./.env`](./.env), this lets you exercise the
full `request_signatures -> receive_signature -> finalize` round trip
without any device or browser involvement.

```bash
cargo test -p asterism-xpub --features test-utils
```

The mnemonics in `.env` are **dev-only test vectors with no real value**.
Do not fund any address derived from them — anyone reading this file can
spend those funds.

### What's deferred

- **Real-fund spending tests.** The round-trip test uses a synthetic in-memory
  PSBT (fake outpoint + fake `witness_utxo`). When the test-app accumulates
  testnet4 funds, we can add a `bdk_wallet::TxBuilder`-driven test that
  actually constructs a spend from real UTXOs and broadcasts it.
- **Taproot signing in `TestExternalSigner`.** The 3-of-5 fixture builds
  `wsh(sortedmulti(...))` only. A `tap_key_origins` / Schnorr signing branch
  can be added when `TaprootFederationBuilder` becomes the test focus.

## Strict-mode lints

This crate is held to the same strict-clippy bar as `asterism-core` and
`asterism-pkcs11`:

```bash
cargo clippy -p asterism-xpub --all-features -- \
  -D warnings -W clippy::pedantic -W clippy::nursery -W rust-2018-idioms
```
