//! BDK chain-sync helper for the regtest spend test.
//!
//! Wraps [`bdk_bitcoind_rpc::Emitter`] — the canonical BDK pattern for
//! pulling block + mempool data from a Bitcoin Core node — behind a
//! single [`sync_wallet`] entry point so the test body stays focused on
//! spend-flow assertions rather than chain plumbing.
//!
//! Per [`.cursorrules`](../../../../.cursorrules) chain sync is a
//! consumer-app responsibility, so this lives strictly under `tests/` and
//! depends only on dev-deps (`bdk_bitcoind_rpc`, `bitcoincore-rpc`).
//!
//! Connection parameters are read from the same `.env` file the rest of
//! the node-tests use:
//!
//! - `BITCOIN_RPC_HOST`
//! - `BITCOIN_RPC_PORT`
//! - `BITCOIN_RPC_USER`
//! - `BITCOIN_RPC_PASSWORD`

#![cfg(all(feature = "test-utils", feature = "node-tests"))]
#![allow(dead_code)] // helpers are referenced from a single test today

use bdk_wallet::Wallet;
use bitcoincore_rpc::{Auth, Client};

/// Connect a fresh `bitcoincore_rpc::Client` to the node configured in
/// `asterism-xpub/.env`.
///
/// Returns `None` if any of the required env vars are missing — callers
/// should treat that as a "skip the test" signal, matching the behaviour
/// of [`super::rpc::RpcClient::from_env`].
pub fn open_bcr_client() -> Option<Client> {
    super::rpc::load_env();
    let user = std::env::var("BITCOIN_RPC_USER").ok()?;
    let password = std::env::var("BITCOIN_RPC_PASSWORD").ok()?;
    let host = std::env::var("BITCOIN_RPC_HOST").ok()?;
    let port = std::env::var("BITCOIN_RPC_PORT").ok()?;
    let url = format!("http://{host}:{port}");
    Client::new(&url, Auth::UserPass(user, password)).ok()
}

/// Drive a [`bdk_bitcoind_rpc::Emitter`] over `wallet`'s current checkpoint
/// until it reaches the node's tip, then ingest the mempool.
///
/// This populates the wallet's [`TxGraph`](bdk_chain::TxGraph), revealed
/// addresses, and balance from on-chain data sourced over JSON-RPC. After
/// this returns, calls to `wallet.balance()` / `wallet.list_unspent()` /
/// `wallet.build_tx()` reflect whatever Bitcoin Core sees.
///
/// # Errors
///
/// Returns whatever `bdk_bitcoind_rpc::Emitter` or
/// `Wallet::apply_block_connected_to` raises. Both are surfaced as a
/// boxed error — tests just `.expect()` the result and rely on the panic
/// message for diagnostics.
pub fn sync_wallet(wallet: &mut Wallet, rpc: &Client) -> Result<(), Box<dyn std::error::Error>> {
    let mut emitter = bdk_bitcoind_rpc::Emitter::new(
        rpc,
        wallet.latest_checkpoint(),
        0,
        bdk_bitcoind_rpc::NO_EXPECTED_MEMPOOL_TXS,
    );
    while let Some(event) = emitter.next_block()? {
        wallet.apply_block_connected_to(
            &event.block,
            event.block_height(),
            event.connected_to(),
        )?;
    }
    let mempool = emitter.mempool()?;
    wallet.apply_unconfirmed_txs(mempool.update);
    if !mempool.evicted.is_empty() {
        wallet.apply_evicted_txs(mempool.evicted);
    }
    Ok(())
}
