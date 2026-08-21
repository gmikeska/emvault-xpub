# Changelog

All notable changes to `emvault-xpub` are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

> Entries for 0.5.0 and earlier were reconstructed from git history.

## [0.9.0] - 2026-08-21

### Changed
- Released in lockstep with the suite-wide v0.9.0 (driven by `emvault-elements`'
  asset-aware federation migration). No functional changes to `emvault-xpub` this
  round; adds GitHub CI workflows and switches inter-crate dependencies to
  version-only requirements so isolated CI resolves against crates.io.

## [0.8.0] - 2026-08-16

### Added
- Doctest example on `ExternalSigner::from_descriptor_key` showing how a
  `[fingerprint/derivation]xpub` device export is parsed into a signer and its
  inherent (`network`, `device_type`) and `Signer`-trait (`fingerprint`,
  `derivation_path`, `label`) accessors read back — pure parsing, no device or
  network contacted.

### Changed
- Released in lockstep with the suite-wide v0.8.0 update.
- Expanded the `elements`-gated test suite with HSM Liquid network-advertisement
  coverage: testnet HSM signers advertise Liquid Testnet + Elements Regtest, and
  mainnet HSM signers advertise Liquid (and not Liquid Testnet).

## [0.7.0] - 2026-08-03

### Added
- `elements` feature: advertise Liquid networks on Liquid-capable signers
  (Jade / HSM), forwarding to `emvault-core/elements` so `NetworkType::Elements`
  is offered on signers that can sign for it.

### Changed
- Released in lockstep with the suite-wide v0.7.0 update.

## [0.6.0] - 2026-07-29

### Changed
- Released in lockstep with the suite-wide reorg-reconciliation update (v0.6.0).
- Documentation updates.

## [0.5.0] - 2026-07-27

### Changed
- Dependency and lockfile refresh; version realigned across the emvault suite.

## [0.4.0] - 2026-07-22

### Changed
- Release-metadata bump only (no functional changes).

## [0.3.0] - 2026-07-13

### Changed
- Documentation and release-metadata updates only.
