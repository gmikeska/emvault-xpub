# Regtest dev workflow

This file is the operational cheat-sheet for the local regtest node Greg
runs at `bitcoin-regtest` (Docker, host port `127.0.0.1:18443`). It is
read-by-Claude when funding test addresses or debugging the node-tests
flow. Connection details mirror `emvault-xpub/.env`:

- RPC: `regtestbtc:regtestbtcpass@127.0.0.1:18443`
- Network: `regtest`
- Miner wallet: `default` (mined funds land here, balances grow every 60s)
- EmVault watch-only wallet: `emvault-xpub-regtest` (created and
  populated by `tests/regtest_node_setup.rs`)

## Starting / inspecting the chain

```bash
# Check whether the miner is running already.
ps aux | grep mine.sh | grep -v grep

# If not, start it (mines one block every 60s).
/home/greg/Projects/btc_regtest/mine.sh
```

## Fund an emvault-xpub address from the miner's wallet

The canonical command (positional form):

```bash
docker exec bitcoin-regtest \
  bitcoin-cli -regtest \
    -rpcuser=regtestbtc -rpcpassword=regtestbtcpass \
    -rpcwallet=default \
  sendtoaddress <DESTINATION_ADDRESS> <AMOUNT_IN_BTC>
```

**Important on this regtest node:** `bitcoind` is configured without
`fallbackfee`, and regtest has no fee history, so the plain form fails
with:

```
error code: -6
error message:
Fee estimation failed. Fallbackfee is disabled. Wait a few blocks or enable -fallbackfee.
```

Use the `-named` form with an explicit `fee_rate` (sat/vB) instead:

```bash
docker exec bitcoin-regtest \
  bitcoin-cli -regtest \
    -rpcuser=regtestbtc -rpcpassword=regtestbtcpass \
    -rpcwallet=default \
  -named sendtoaddress \
    address=<DESTINATION_ADDRESS> \
    amount=<AMOUNT_IN_BTC> \
    fee_rate=2
```

The command returns a txid. Wait one mined block (~60s — `mine.sh`
mines on a 60s loop) for it to confirm, then `getbalance` on
`emvault-xpub-regtest` will show the new balance. To accelerate
confirmation manually, mine one block to any address — the miner
script's address is fine:

```bash
docker exec bitcoin-regtest \
  bitcoin-cli -regtest \
    -rpcuser=regtestbtc -rpcpassword=regtestbtcpass \
    -rpcwallet=default \
  -generate 1
```

## Bootstrap / refresh the watch-only wallet

```bash
cargo test -p emvault-xpub \
  --features test-utils,node-tests \
  --test regtest_node_setup -- --nocapture
```

This creates `emvault-xpub-regtest` (idempotent), imports the
3-of-5 receive + change descriptors with `range=[0, 999]`, and prints the
first 10 receive addresses.

## Inspect the watch-only wallet

```bash
WALLET=emvault-xpub-regtest
RPC="docker exec bitcoin-regtest bitcoin-cli -regtest -rpcuser=regtestbtc -rpcpassword=regtestbtcpass -rpcwallet=$WALLET"

$RPC getbalance
$RPC listunspent 0
$RPC listdescriptors | jq '.descriptors[] | {desc, internal, active, range}'
$RPC getaddressinfo <ADDRESS>
```

## Spend test (end-to-end)

Once the watch-only wallet has been bootstrapped, the full spend
pipeline can be exercised against the regtest node:

```bash
cargo test -p emvault-xpub \
  --features test-utils,node-tests \
  --test regtest_spend -- --nocapture --test-threads=1
```

What it does:

1. Cross-validates federation descriptors against the node and
   re-imports them only if the wallet's range needs widening (no-op
   on a fresh run).
2. **Self-funds** when the watch-only balance falls below `0.04 BTC` —
   the test sends `0.05 BTC` from the miner's `default` wallet to the
   next unfunded `/0/N` and mines one block. So the test is
   re-runnable indefinitely as long as `mine.sh` is keeping
   `default` solvent.
3. Builds an in-memory `bdk_wallet::Wallet` from the federation
   descriptor and syncs it from the node via
   `bdk_bitcoind_rpc::Emitter`.
4. Builds a PSBT spending `0.03 BTC` to a fresh `default`-owned
   address using `wallet.build_tx()` (BDK picks coins, computes
   fee, places change on `/1/*`).
5. Drives `SigningCoordinator` with three of the five
   `TestExternalSigner`s (#0, #2, #4) — full `request_signatures` →
   `sign_for_test` → `receive_signature` round-trip.
6. Finalizes via `Wallet::finalize_psbt`, asserts the change output
   is on the federation's internal `/1/*` chain, broadcasts via
   `sendrawtransaction`, mines one block, and asserts the funded
   outpoint is gone and the spend tx has 1 confirmation.

A negative test (`rebroadcast_after_confirmation_is_rejected`)
reproduces the same flow once more, then attempts to rebroadcast the
mined transaction and asserts bitcoind returns RPC code `-27`
(`Transaction outputs already in utxo set` /
`Transaction already in block chain`).

Run sequentially (`--test-threads=1`) to avoid two concurrent spends
racing for the same UTXO. Both tests self-fund independently.

## Reset the watch-only wallet (rarely needed)

```bash
WALLET=emvault-xpub-regtest
RPC_NODE="docker exec bitcoin-regtest bitcoin-cli -regtest -rpcuser=regtestbtc -rpcpassword=regtestbtcpass"

$RPC_NODE unloadwallet $WALLET
$RPC_NODE -rpcwallet=$WALLET dumpwallet /tmp/emvault-xpub-regtest.dump   # optional backup
docker exec bitcoin-regtest rm -rf /home/bitcoin/.bitcoin/regtest/wallets/$WALLET
# Re-run the setup test to recreate.
```
