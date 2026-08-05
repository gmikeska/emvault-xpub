# Changelog

All notable changes to `emvault-xpub` are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

> Entries for 0.5.0 and earlier were reconstructed from git history.

## [0.8.0] - Unreleased

### Changed
- Released in lockstep with the suite-wide v0.8.0; no functional changes to
  `emvault-xpub` yet. Taproot support for the xpub signing path (and hardware
  cosigners such as Passport Prime) is in progress ahead of the v0.8.0 cut.

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
