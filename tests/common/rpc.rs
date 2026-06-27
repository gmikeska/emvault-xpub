//! Minimal Bitcoin Core JSON-RPC client for `node-tests`-gated tests.
//!
//! Mirrors `emvault-core/tests/common/rpc.rs` but with the additional
//! wallet-management methods the regtest workflow needs:
//! `createwallet`, `loadwallet`, `listwallets`, `importdescriptors`,
//! `getbalance`, `listunspent`. All wallet-scoped methods route through
//! the `/wallet/<name>` URL form so we can talk to a specific watch-only
//! wallet alongside the miner's `default` wallet.
//!
//! Connection parameters are read from `.env`:
//!
//! - `BITCOIN_RPC_HOST`
//! - `BITCOIN_RPC_PORT`
//! - `BITCOIN_RPC_USER`
//! - `BITCOIN_RPC_PASSWORD`
//! - `BITCOIN_NETWORK` (informational only)
//!
//! Tests calling [`RpcClient::from_env`] should treat `None` as a graceful
//! skip — the helper does not panic when env vars are missing.

#![allow(dead_code)] // some helpers are reserved for the spending tests we'll add later

use std::path::PathBuf;
use std::time::Duration;

use serde_json::{Value, json};

const TIMEOUT: Duration = Duration::from_secs(10);

/// Best-effort load of `emvault-xpub/.env`.
pub fn load_env() {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(".env");
    let _ = dotenvy::from_path(&path);
}

/// Minimal JSON-RPC client targeting Bitcoin Core.
#[derive(Clone)]
pub struct RpcClient {
    base_url: String,
    auth_header: String,
    /// `BITCOIN_NETWORK` value from `.env` — informational only.
    pub network_label: String,
}

#[derive(Debug)]
pub enum RpcError {
    Transport(String),
    Status { code: u16, body: String },
    Json(String),
    Rpc { code: i64, message: String },
}

impl std::fmt::Display for RpcError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Transport(e) => write!(f, "transport error: {e}"),
            Self::Status { code, body } => write!(f, "HTTP {code}: {body}"),
            Self::Json(e) => write!(f, "JSON error: {e}"),
            Self::Rpc { code, message } => write!(f, "RPC error {code}: {message}"),
        }
    }
}

impl std::error::Error for RpcError {}

impl RpcError {
    /// True if this error came from Bitcoin Core (i.e. we *did* reach the
    /// node and got a structured RPC error, including 4xx response bodies).
    pub const fn is_rpc_error(&self) -> bool {
        matches!(self, Self::Rpc { .. } | Self::Status { .. })
    }

    /// Returns the RPC error code if any (matches [the Bitcoin Core RPC
    /// error codes](https://github.com/bitcoin/bitcoin/blob/master/src/rpc/protocol.h)).
    pub const fn rpc_code(&self) -> Option<i64> {
        if let Self::Rpc { code, .. } = self {
            Some(*code)
        } else {
            None
        }
    }
}

impl RpcClient {
    /// Build a client from environment variables. Returns `None` if any of
    /// the required variables are missing — callers should treat this as a
    /// skip-the-test signal rather than a failure.
    pub fn from_env() -> Option<Self> {
        load_env();
        let user = std::env::var("BITCOIN_RPC_USER").ok()?;
        let password = std::env::var("BITCOIN_RPC_PASSWORD").ok()?;
        let host = std::env::var("BITCOIN_RPC_HOST").ok()?;
        let port = std::env::var("BITCOIN_RPC_PORT").ok()?;
        let network_label = std::env::var("BITCOIN_NETWORK").unwrap_or_else(|_| "unknown".into());
        let base_url = format!("http://{host}:{port}");
        let auth = format!("{user}:{password}");
        let auth_header = format!("Basic {}", base64_encode(auth.as_bytes()));
        Some(Self {
            base_url,
            auth_header,
            network_label,
        })
    }

    fn call(&self, url: &str, method: &str, params: &Value) -> Result<Value, RpcError> {
        let body = json!({
            "jsonrpc": "1.0",
            "id": "emvault-xpub-test",
            "method": method,
            "params": params.clone(),
        });
        let req = ureq::AgentBuilder::new()
            .timeout(TIMEOUT)
            .build()
            .post(url)
            .set("Authorization", &self.auth_header)
            .set("Content-Type", "application/json");
        let resp = match req.send_json(body) {
            Ok(r) => r,
            Err(ureq::Error::Status(code, r)) => {
                let raw = r.into_string().unwrap_or_default();
                // Bitcoin Core returns structured RPC errors with non-2xx
                // status codes; try to surface the inner code/message.
                if let Ok(v) = serde_json::from_str::<Value>(&raw)
                    && let Some(err) = v.get("error").filter(|e| !e.is_null())
                {
                    let code = err.get("code").and_then(Value::as_i64).unwrap_or(0);
                    let message = err
                        .get("message")
                        .and_then(Value::as_str)
                        .unwrap_or("")
                        .to_string();
                    return Err(RpcError::Rpc { code, message });
                }
                return Err(RpcError::Status { code, body: raw });
            }
            Err(e) => return Err(RpcError::Transport(e.to_string())),
        };
        let v: Value = resp
            .into_json()
            .map_err(|e| RpcError::Json(e.to_string()))?;
        if let Some(err) = v.get("error").filter(|e| !e.is_null()) {
            let code = err.get("code").and_then(Value::as_i64).unwrap_or(0);
            let message = err
                .get("message")
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_string();
            return Err(RpcError::Rpc { code, message });
        }
        v.get("result")
            .cloned()
            .ok_or_else(|| RpcError::Json("missing 'result' field".into()))
    }

    fn call_default(&self, method: &str, params: &Value) -> Result<Value, RpcError> {
        let url = format!("{}/", self.base_url);
        self.call(&url, method, params)
    }

    fn call_wallet(&self, wallet: &str, method: &str, params: &Value) -> Result<Value, RpcError> {
        let url = format!("{}/wallet/{wallet}", self.base_url);
        self.call(&url, method, params)
    }

    // --------------------------- node-scoped methods ---------------------------

    /// `getblockchaininfo`.
    pub fn getblockchaininfo(&self) -> Result<Value, RpcError> {
        self.call_default("getblockchaininfo", &json!([]))
    }

    /// `getdescriptorinfo(descriptor)` — canonicalize and compute checksum.
    pub fn getdescriptorinfo(&self, descriptor: &str) -> Result<DescriptorInfo, RpcError> {
        let v = self.call_default("getdescriptorinfo", &json!([descriptor]))?;
        Ok(DescriptorInfo {
            descriptor: v
                .get("descriptor")
                .and_then(Value::as_str)
                .ok_or_else(|| RpcError::Json("missing 'descriptor'".into()))?
                .to_string(),
            checksum: v
                .get("checksum")
                .and_then(Value::as_str)
                .ok_or_else(|| RpcError::Json("missing 'checksum'".into()))?
                .to_string(),
            isrange: v.get("isrange").and_then(Value::as_bool).unwrap_or(false),
            issolvable: v
                .get("issolvable")
                .and_then(Value::as_bool)
                .unwrap_or(false),
        })
    }

    /// `deriveaddresses(descriptor[, range])`.
    pub fn deriveaddresses(
        &self,
        descriptor: &str,
        range: Option<[u32; 2]>,
    ) -> Result<Vec<String>, RpcError> {
        let params = match range {
            Some([lo, hi]) => json!([descriptor, [lo, hi]]),
            None => json!([descriptor]),
        };
        let v = self.call_default("deriveaddresses", &params)?;
        let arr = v
            .as_array()
            .ok_or_else(|| RpcError::Json("expected array of addresses".into()))?;
        Ok(arr
            .iter()
            .filter_map(Value::as_str)
            .map(str::to_string)
            .collect())
    }

    /// `listwallets`. Returns the names of currently-loaded wallets.
    pub fn listwallets(&self) -> Result<Vec<String>, RpcError> {
        let v = self.call_default("listwallets", &json!([]))?;
        let arr = v
            .as_array()
            .ok_or_else(|| RpcError::Json("expected array".into()))?;
        Ok(arr
            .iter()
            .filter_map(Value::as_str)
            .map(str::to_string)
            .collect())
    }

    /// `createwallet` with options for a watch-only descriptor wallet.
    /// Returns the wallet name on success.
    ///
    /// `disable_private_keys=true` and `blank=true` produce a wallet that
    /// can only hold imported descriptors (no key generation).
    pub fn createwallet(
        &self,
        name: &str,
        disable_private_keys: bool,
        blank: bool,
        descriptors: bool,
    ) -> Result<String, RpcError> {
        // Bitcoin Core 25+: `createwallet` takes named or positional args.
        // Use the positional form for compatibility.
        let params = json!([
            name,
            disable_private_keys,
            blank,
            "",    // passphrase
            false, // avoid_reuse
            descriptors,
            false, // load_on_startup (false = don't auto-load on restart)
            false, // external_signer
        ]);
        let v = self.call_default("createwallet", &params)?;
        Ok(v.get("name")
            .and_then(Value::as_str)
            .unwrap_or(name)
            .to_string())
    }

    /// `loadwallet`. Returns the wallet name on success.
    pub fn loadwallet(&self, name: &str) -> Result<String, RpcError> {
        let v = self.call_default("loadwallet", &json!([name]))?;
        Ok(v.get("name")
            .and_then(Value::as_str)
            .unwrap_or(name)
            .to_string())
    }

    /// Idempotent wallet bootstrap: load the wallet if it exists, otherwise
    /// create it as a watch-only descriptor wallet.
    ///
    /// Tolerates the common error codes:
    /// - `-4` (wallet already loaded)
    /// - `-18` (wallet does not exist) → triggers create
    /// - `-35` (wallet path already exists / wallet already loaded)
    pub fn ensure_wallet(&self, name: &str) -> Result<(), RpcError> {
        if self.listwallets()?.iter().any(|w| w == name) {
            return Ok(());
        }
        match self.loadwallet(name) {
            Ok(_) => Ok(()),
            Err(e) if e.rpc_code() == Some(-18) => {
                self.createwallet(name, true, true, true).map(|_| ())
            }
            // -4 / -35 → already loaded; either fine.
            Err(e) if e.rpc_code() == Some(-4) || e.rpc_code() == Some(-35) => Ok(()),
            Err(e) => Err(e),
        }
    }

    // --------------------------- wallet-scoped methods ---------------------------

    /// `importdescriptors` against the named wallet.
    ///
    /// `descriptors` should already include their checksum suffix
    /// (`#xxxxxxxx`); call [`Self::getdescriptorinfo`] first to compute one
    /// for any descriptor whose source string lacks it.
    pub fn importdescriptors(
        &self,
        wallet: &str,
        descriptors: &[ImportDescriptor<'_>],
    ) -> Result<Value, RpcError> {
        let request: Vec<Value> = descriptors
            .iter()
            .map(|d| {
                let mut obj = serde_json::Map::new();
                obj.insert("desc".into(), Value::String(d.desc.to_string()));
                obj.insert("active".into(), Value::Bool(d.active));
                obj.insert("internal".into(), Value::Bool(d.internal));
                obj.insert(
                    "timestamp".into(),
                    d.timestamp
                        .map_or_else(|| Value::String("now".into()), Value::from),
                );
                if let Some([lo, hi]) = d.range {
                    obj.insert("range".into(), json!([lo, hi]));
                }
                if let Some(label) = d.label {
                    obj.insert("label".into(), Value::String(label.to_string()));
                }
                Value::Object(obj)
            })
            .collect();
        self.call_wallet(wallet, "importdescriptors", &json!([request]))
    }

    /// `getbalance` for the named wallet.
    pub fn getbalance(&self, wallet: &str) -> Result<f64, RpcError> {
        let v = self.call_wallet(wallet, "getbalance", &json!([]))?;
        v.as_f64()
            .ok_or_else(|| RpcError::Json("balance was not a number".into()))
    }

    /// `listunspent` for the named wallet (default args: 0 confs minimum).
    pub fn listunspent(&self, wallet: &str) -> Result<Vec<Value>, RpcError> {
        let v = self.call_wallet(wallet, "listunspent", &json!([0]))?;
        v.as_array()
            .cloned()
            .ok_or_else(|| RpcError::Json("expected array".into()))
    }

    /// `rescanblockchain` (slow on a full chain, fast on regtest).
    pub fn rescanblockchain(&self, wallet: &str) -> Result<Value, RpcError> {
        self.call_wallet(wallet, "rescanblockchain", &json!([]))
    }

    /// `listdescriptors` against the named wallet. Returns the raw `descriptors`
    /// array (each entry has `desc`, `internal`, `active`, `range`, etc.).
    ///
    /// Bitcoin Core auto-extends a descriptor's range whenever a derived
    /// address at the new tip is observed, which means a literal "import
    /// with range=[0,999]" can become "current range=[0,1000]" after the
    /// wallet sees /0/1 funded. Future imports are then rejected with
    /// `-4: new range must include current range` — so call this first to
    /// decide whether you can skip the import or need to widen the range.
    pub fn listdescriptors(&self, wallet: &str) -> Result<Vec<Value>, RpcError> {
        let v = self.call_wallet(wallet, "listdescriptors", &json!([]))?;
        let arr = v
            .get("descriptors")
            .and_then(Value::as_array)
            .cloned()
            .ok_or_else(|| RpcError::Json("listdescriptors missing 'descriptors'".into()))?;
        Ok(arr)
    }

    /// Idempotently import a receive + change descriptor pair, never
    /// shrinking the wallet's existing range.
    ///
    /// Bitcoin Core auto-extends a descriptor's range as new derived
    /// addresses are observed, so a literal re-import with the original
    /// `[lo, hi]` range is rejected with RPC code -4 (`new range must
    /// include current range`). This helper handles three cases:
    ///
    /// 1. Descriptor is absent → import with the requested range.
    /// 2. Descriptor is present and its current range already covers
    ///    `[range_lo, range_hi]` → skip (no-op).
    /// 3. Descriptor is present but the request would widen the lower
    ///    bound *or* the requested upper bound exceeds the current →
    ///    re-import with `range = [min(cur_lo, range_lo),
    ///    max(cur_hi, range_hi)]` so the call always strictly widens.
    ///
    /// Use this from any test that imports a federation's receive +
    /// change pair so re-running the test suite never breaks once the
    /// wallet has seen funded indexes beyond the original range.
    ///
    /// # Errors
    ///
    /// Bubbles up any RPC failure from `listdescriptors` or
    /// `importdescriptors`. Returns `Ok(())` if the import was skipped
    /// or completed successfully.
    pub fn ensure_descriptors_imported(
        &self,
        wallet: &str,
        receive_with_cs: &str,
        change_with_cs: &str,
        range_lo: u32,
        range_hi: u32,
    ) -> Result<(), RpcError> {
        let existing = self.listdescriptors(wallet)?;
        let decide = |label: &'static str, want: &str| -> Option<[u32; 2]> {
            let cur = existing
                .iter()
                .find(|e| e.get("desc").and_then(Value::as_str) == Some(want));
            let Some(entry) = cur else {
                return Some([range_lo, range_hi]);
            };
            let (cur_lo, cur_hi) = entry
                .get("range")
                .and_then(Value::as_array)
                .and_then(|r| {
                    Some((
                        u32::try_from(r.first()?.as_u64()?).ok()?,
                        u32::try_from(r.get(1)?.as_u64()?).ok()?,
                    ))
                })
                .unwrap_or((range_lo, range_hi));
            if cur_lo <= range_lo && cur_hi >= range_hi {
                eprintln!(
                    "[import] {label} already covers [{range_lo},{range_hi}] \
                     (current=[{cur_lo},{cur_hi}]); skipping"
                );
                None
            } else {
                let new_lo = cur_lo.min(range_lo);
                let new_hi = cur_hi.max(range_hi);
                eprintln!(
                    "[import] widening {label} from [{cur_lo},{cur_hi}] to \
                     [{new_lo},{new_hi}]"
                );
                Some([new_lo, new_hi])
            }
        };

        let mut to_import: Vec<ImportDescriptor<'_>> = Vec::new();
        if let Some(range) = decide("receive", receive_with_cs) {
            to_import.push(ImportDescriptor {
                desc: receive_with_cs,
                active: true,
                internal: false,
                range: Some(range),
                timestamp: Some(0),
                label: None,
            });
        }
        if let Some(range) = decide("change", change_with_cs) {
            to_import.push(ImportDescriptor {
                desc: change_with_cs,
                active: true,
                internal: true,
                range: Some(range),
                timestamp: Some(0),
                label: None,
            });
        }
        if to_import.is_empty() {
            return Ok(());
        }
        let result = self.importdescriptors(wallet, &to_import)?;
        let arr = result
            .as_array()
            .ok_or_else(|| RpcError::Json("importdescriptors did not return an array".into()))?;
        for entry in arr {
            let success = entry
                .get("success")
                .and_then(Value::as_bool)
                .unwrap_or(false);
            if !success {
                return Err(RpcError::Json(format!(
                    "importdescriptors entry failed: {entry}"
                )));
            }
        }
        Ok(())
    }

    // --------------------------- spend-flow methods ---------------------------

    /// `getnewaddress(label, address_type)` against the named wallet.
    ///
    /// `address_type` is one of `legacy`, `p2sh-segwit`, `bech32`, `bech32m`.
    /// Mirrors the `bitcoin-cli getnewaddress` form so test scaffolding can
    /// generate fresh `default`-owned destinations and miner addresses.
    pub fn getnewaddress(&self, wallet: &str, address_type: &str) -> Result<String, RpcError> {
        let v = self.call_wallet(wallet, "getnewaddress", &json!(["", address_type]))?;
        v.as_str()
            .map(str::to_string)
            .ok_or_else(|| RpcError::Json("getnewaddress did not return a string".into()))
    }

    /// `sendtoaddress` via the named-arg form, so we can pass an explicit
    /// `fee_rate` (sat/vB). The plain positional form fails on this regtest
    /// node because `bitcoind` runs without `-fallbackfee`. See
    /// `emvault-xpub/REGTEST.md` for the full background.
    ///
    /// Returns the txid as a hex string.
    pub fn sendtoaddress_named(
        &self,
        wallet: &str,
        address: &str,
        amount_btc: f64,
        fee_rate_sat_vb: u64,
    ) -> Result<String, RpcError> {
        // Bitcoin Core also accepts named params at the JSON-RPC layer (not
        // just on the CLI) by passing an *object* in `params` instead of an
        // array. This is the analogue of `bitcoin-cli -named sendtoaddress
        // address=... amount=... fee_rate=...`.
        let params = json!({
            "address": address,
            "amount": amount_btc,
            "fee_rate": fee_rate_sat_vb,
        });
        let v = self.call_wallet(wallet, "sendtoaddress", &params)?;
        v.as_str()
            .map(str::to_string)
            .ok_or_else(|| RpcError::Json("sendtoaddress did not return a txid string".into()))
    }

    /// `sendrawtransaction(hex)` against the node (not wallet-scoped). Returns
    /// the broadcasted txid.
    pub fn sendrawtransaction(&self, raw_tx_hex: &str) -> Result<String, RpcError> {
        let v = self.call_default("sendrawtransaction", &json!([raw_tx_hex]))?;
        v.as_str()
            .map(str::to_string)
            .ok_or_else(|| RpcError::Json("sendrawtransaction did not return a txid string".into()))
    }

    /// `generatetoaddress(nblocks, address)` — confirm a freshly broadcast
    /// transaction. Returns the list of generated block hashes.
    pub fn generatetoaddress(&self, nblocks: u32, address: &str) -> Result<Vec<String>, RpcError> {
        let v = self.call_default("generatetoaddress", &json!([nblocks, address]))?;
        let arr = v
            .as_array()
            .ok_or_else(|| RpcError::Json("expected array of block hashes".into()))?;
        Ok(arr
            .iter()
            .filter_map(Value::as_str)
            .map(str::to_string)
            .collect())
    }

    /// `gettxout(txid, vout, include_mempool)`. Returns `None` when the
    /// outpoint has been spent (or never existed). The node-scoped form is
    /// suitable for asserting that the funded UTXO is gone after confirmation.
    pub fn gettxout(
        &self,
        txid: &str,
        vout: u32,
        include_mempool: bool,
    ) -> Result<Option<Value>, RpcError> {
        let v = self.call_default("gettxout", &json!([txid, vout, include_mempool]))?;
        Ok(if v.is_null() { None } else { Some(v) })
    }

    /// `getrawtransaction(txid, verbose)` against the node. With
    /// `verbose=true`, returns the JSON-decoded transaction (which includes
    /// `confirmations` once the tx has been mined).
    pub fn getrawtransaction(&self, txid: &str, verbose: bool) -> Result<Value, RpcError> {
        self.call_default("getrawtransaction", &json!([txid, verbose]))
    }

    /// `getaddressinfo(address)` against the named wallet. Used to assert
    /// that change outputs come back to a watched `/1/*` address (i.e.
    /// `ismine == true` and the descriptor source contains `/1/`).
    pub fn getaddressinfo(&self, wallet: &str, address: &str) -> Result<Value, RpcError> {
        self.call_wallet(wallet, "getaddressinfo", &json!([address]))
    }
}

/// Argument bag for [`RpcClient::importdescriptors`].
#[derive(Clone, Debug)]
pub struct ImportDescriptor<'a> {
    /// Descriptor including `#checksum`.
    pub desc: &'a str,
    /// Treat this descriptor as the active receive (or change) chain.
    pub active: bool,
    /// `true` means this is the internal/change chain; `false` means
    /// receive.
    pub internal: bool,
    /// Optional `[start, end]` derivation range. If `None`, Bitcoin Core
    /// uses the default of `[0, 999]` for ranged descriptors.
    pub range: Option<[u32; 2]>,
    /// Per-RPC docs: integer Unix time, or `None` for `"now"`.
    pub timestamp: Option<u64>,
    /// Optional human-readable label applied to derived addresses.
    pub label: Option<&'a str>,
}

/// Parsed `getdescriptorinfo` response.
#[derive(Clone, Debug)]
pub struct DescriptorInfo {
    /// Bitcoin Core's canonical form of the descriptor (always with `#checksum`).
    pub descriptor: String,
    /// Just the checksum portion (8 lowercase chars).
    pub checksum: String,
    /// True if the descriptor contains a wildcard `*`.
    pub isrange: bool,
    /// True if Bitcoin Core's wallet would consider the descriptor solvable.
    pub issolvable: bool,
}

// ---------------------------------------------------------------------------
// Tiny base64 encoder (avoids pulling base64 as a dev dep).
// RFC-4648 standard alphabet, padding-only on partial chunks.
// ---------------------------------------------------------------------------

fn base64_encode(input: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(input.len().div_ceil(3) * 4);
    for chunk in input.chunks(3) {
        let b0 = chunk[0];
        let b1 = chunk.get(1).copied().unwrap_or(0);
        let b2 = chunk.get(2).copied().unwrap_or(0);
        let n = (u32::from(b0) << 16) | (u32::from(b1) << 8) | u32::from(b2);
        out.push(ALPHABET[((n >> 18) & 0x3F) as usize] as char);
        out.push(ALPHABET[((n >> 12) & 0x3F) as usize] as char);
        if chunk.len() > 1 {
            out.push(ALPHABET[((n >> 6) & 0x3F) as usize] as char);
        } else {
            out.push('=');
        }
        if chunk.len() > 2 {
            out.push(ALPHABET[(n & 0x3F) as usize] as char);
        } else {
            out.push('=');
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::base64_encode;

    #[test]
    fn base64_known_vectors() {
        assert_eq!(base64_encode(b""), "");
        assert_eq!(base64_encode(b"f"), "Zg==");
        assert_eq!(base64_encode(b"fo"), "Zm8=");
        assert_eq!(base64_encode(b"foo"), "Zm9v");
        assert_eq!(base64_encode(b"user:pass"), "dXNlcjpwYXNz");
    }
}
