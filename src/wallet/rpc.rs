//! Minimal `monero-wallet-rpc` JSON-RPC client (spec §31 research notes).
//! Only the methods xmrts actually needs are implemented.

use reqwest::redirect::Policy;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::time::Duration;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum RpcError {
    #[error("connection failed to {endpoint}: {message}")]
    Connection { endpoint: String, message: String },
    #[error("wallet RPC rejected authentication at {endpoint}")]
    Auth { endpoint: String },
    #[error("wallet RPC error {code}: {message}")]
    Server { code: i64, message: String },
    #[error("malformed RPC response: {0}")]
    Malformed(String),
    #[error("cannot build HTTP client for wallet RPC: {0}")]
    ClientBuild(String),
    #[error(transparent)]
    Http(#[from] reqwest::Error),
}

impl RpcError {
    /// True when the server answered but rejected auth (HTTP 401).
    /// Something listens on the port with a different login than ours.
    pub fn is_auth_failure(&self) -> bool {
        matches!(self, RpcError::Auth { .. })
    }
}

#[derive(Debug, Clone)]
pub struct WalletRpc {
    endpoint: String,
    client: Client,
    username: Option<String>,
    password: Option<String>,
}

impl WalletRpc {
    pub fn new(
        endpoint: impl Into<String>,
        username: Option<String>,
        password: Option<String>,
        proxy: Option<String>,
    ) -> Result<Self, RpcError> {
        let endpoint_str: String = endpoint.into();
        let mut builder = Client::builder().timeout(Duration::from_secs(30));
        builder = builder.redirect(Policy::none());
        if let Some(p) = super::connection::effective_proxy(Some(&endpoint_str), proxy.as_deref()) {
            match reqwest::Proxy::all(&p) {
                Ok(proxy) => builder = builder.proxy(proxy),
                Err(e) => tracing::warn!(
                    proxy = %super::connection::display_url(&p),
                    error = %e,
                    "saved proxy could not be applied to wallet RPC; traffic goes direct"
                ),
            }
        }
        let client = builder
            .build()
            .map_err(|e| RpcError::ClientBuild(e.to_string()))?;
        Ok(Self {
            endpoint: endpoint_str,
            client,
            username,
            password,
        })
    }

    pub fn endpoint(&self) -> &str {
        &self.endpoint
    }

    async fn call(&self, method: &str, params: Value) -> Result<Value, RpcError> {
        let url = format!("{}/json_rpc", self.endpoint.trim_end_matches('/'));
        let body = json!({"jsonrpc": "2.0", "id": "0", "method": method, "params": params});
        let conn_err = |e: reqwest::Error| RpcError::Connection {
            endpoint: super::connection::display_url(&self.endpoint),
            message: e.to_string(),
        };
        // First attempt: no auth header. monero-wallet-rpc answers with
        // `401 + WWW-Authenticate: Digest ...` when --rpc-login is set.
        let mut resp = self
            .client
            .post(&url)
            .json(&body)
            .send()
            .await
            .map_err(conn_err)?;
        // Second attempt: answer a Digest challenge (RFC 2617). Monero does
        // not accept Basic auth, so there is no point pre-empting with it.
        if resp.status() == reqwest::StatusCode::UNAUTHORIZED {
            let (Some(u), Some(p)) = (self.username.as_deref(), self.password.as_deref()) else {
                return Err(RpcError::Auth {
                    endpoint: super::connection::display_url(&self.endpoint),
                });
            };
            let challenges: Vec<String> = resp
                .headers()
                .get_all(reqwest::header::WWW_AUTHENTICATE)
                .iter()
                .filter_map(|v| v.to_str().ok().map(String::from))
                .collect();
            let auth_header = digest_auth_header("POST", "/json_rpc", &challenges, u, p)
                .ok_or_else(|| RpcError::Connection {
                    endpoint: super::connection::display_url(&self.endpoint),
                    message: "could not answer the wallet RPC auth challenge (expected Digest); if the wallet uses --rpc-login from a custom build, run it without --rpc-login on localhost instead".to_string(),
                })?;
            resp = self
                .client
                .post(&url)
                .json(&body)
                .header(reqwest::header::AUTHORIZATION, auth_header)
                .send()
                .await
                .map_err(conn_err)?;
            if resp.status() == reqwest::StatusCode::UNAUTHORIZED {
                return Err(RpcError::Auth {
                    endpoint: super::connection::display_url(&self.endpoint),
                });
            }
        }
        // Read the body as text first: `.json()` alone can only say "not
        // JSON", losing all evidence at exactly the wrong moment. A reverse
        // proxy error page or a plain web server on the endpoint answers
        // HTTP with a status + body that identify the real problem; a bare
        // "connection" error would send the user checking network/wallet
        // state for a configuration issue instead.
        let status = resp.status();
        let text = resp.text().await.map_err(conn_err)?;
        let v: Value = serde_json::from_str(&text).map_err(|e| {
            let snippet: String = text
                .trim()
                .chars()
                .filter(|c| !c.is_control())
                .take(200)
                .collect();
            RpcError::Connection {
                endpoint: super::connection::display_url(&self.endpoint),
                message: format!(
                    "wallet RPC endpoint answered HTTP {status} with non-JSON data (is this really a monero-wallet-rpc?): {e}; body starts: {snippet:?}"
                ),
            }
        })?;
        if let Some(err) = v.get("error") {
            return Err(RpcError::Server {
                code: err.get("code").and_then(Value::as_i64).unwrap_or(-1),
                message: err
                    .get("message")
                    .and_then(Value::as_str)
                    .unwrap_or("unknown error")
                    .to_string(),
            });
        }
        v.get("result")
            .cloned()
            .ok_or_else(|| RpcError::Malformed("missing result field".into()))
    }

    /// `get_version` - connectivity check, no wallet required.
    pub async fn get_version(&self) -> Result<(u32, u32), RpcError> {
        let r = self.call("get_version", json!({})).await?;
        let v = r
            .get("version")
            .and_then(Value::as_u64)
            .ok_or_else(|| RpcError::Malformed("missing version".into()))?;
        Ok((((v >> 16) & 0xFFFF) as u32, (v & 0xFFFF) as u32))
    }

    /// `get_height` - requires an open wallet.
    pub async fn get_height(&self) -> Result<u64, RpcError> {
        let r = self.call("get_height", json!({})).await?;
        r.get("height")
            .and_then(Value::as_u64)
            .ok_or_else(|| RpcError::Malformed("missing height".into()))
    }

    /// `get_address` - primary address (account 0).
    pub async fn get_address(&self) -> Result<String, RpcError> {
        let r = self.address_info(0).await?;
        r.get("address")
            .and_then(Value::as_str)
            .map(String::from)
            .ok_or_else(|| RpcError::Malformed("missing address".into()))
    }

    /// Full `get_address` response for an account: primary `address` plus
    /// the `addresses` array (all subaddresses). Used to prove a
    /// destination belongs to this wallet before relaying.
    pub async fn address_info(&self, account_index: u32) -> Result<Value, RpcError> {
        self.call("get_address", json!({"account_index": account_index}))
            .await
    }

    /// True when `address` is one of this wallet's own addresses
    /// (primary or any subaddress of account 0).
    pub async fn owns_address(&self, address: &str) -> Result<bool, RpcError> {
        let info = self.address_info(0).await?;
        if info.get("address").and_then(Value::as_str) == Some(address) {
            return Ok(true);
        }
        let found = info
            .get("addresses")
            .and_then(Value::as_array)
            .map(|arr| {
                arr.iter()
                    .any(|a| a.get("address").and_then(Value::as_str) == Some(address))
            })
            .unwrap_or(false);
        Ok(found)
    }

    /// `get_balance` - returns (balance, unlocked_balance) in atomic units.
    pub async fn get_balance(&self) -> Result<(u64, u64), RpcError> {
        let r = self
            .call("get_balance", json!({"account_index": 0}))
            .await?;
        let b = r
            .get("balance")
            .and_then(Value::as_u64)
            .ok_or_else(|| RpcError::Malformed("missing balance".into()))?;
        let u = r
            .get("unlocked_balance")
            .and_then(Value::as_u64)
            .unwrap_or(b);
        Ok((b, u))
    }

    /// `validate_address` - also reports the nettype when the daemon
    /// answers; used to cross-check proof network vs wallet network.
    pub async fn validate_address(&self, address: &str) -> Result<Value, RpcError> {
        self.call(
            "validate_address",
            json!({"address": address, "any_net_type": true}),
        )
        .await
    }
}

/// A single transfer destination.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Destination {
    pub address: String,
    pub amount: u64,
}

/// Outcome of a `transfer` call.
#[derive(Debug, Clone)]
pub struct TransferResult {
    pub tx_hash: String,
    pub fee: u64,
    pub amount: u64,
}

/// `transfer` with an arbitrary `extra` hex payload (spec §4.2).
/// `priority` is the Monero tx priority (0 = wallet default, 1-4 slow to
/// fast). `ring_size` stays 0 (wallet default, consensus-enforced).
pub async fn transfer_with_extra(
    rpc: &WalletRpc,
    destinations: Vec<Destination>,
    extra_hex: &str,
    do_not_relay: bool,
    get_tx_hex: bool,
    priority: u32,
) -> Result<(TransferResult, Value), RpcError> {
    let params = json!({
        "destinations": destinations,
        "priority": priority,
        "ring_size": 0,
        "unlock_time": 0,
        "get_tx_key": false,
        "do_not_relay": do_not_relay,
        "get_tx_hex": get_tx_hex,
        "get_tx_metadata": true,
        "extra": extra_hex,
    });
    let r = rpc.call("transfer", params).await?;
    let tx_hash = r
        .get("tx_hash")
        .and_then(Value::as_str)
        .ok_or_else(|| RpcError::Malformed("missing tx_hash".into()))?
        .to_string();
    let fee = r.get("fee").and_then(Value::as_u64).unwrap_or(0);
    let amount = r.get("amount").and_then(Value::as_u64).unwrap_or(0);
    Ok((
        TransferResult {
            tx_hash,
            fee,
            amount,
        },
        r,
    ))
}

/// `open_wallet` - opens a wallet file on the server. The password is
/// passed straight through and must never be logged or persisted by
/// callers (use an interactive hidden prompt + zeroizing memory).
pub async fn open_wallet(
    rpc: &WalletRpc,
    filename: &str,
    password: &str,
) -> Result<Value, RpcError> {
    rpc.call(
        "open_wallet",
        json!({"filename": filename, "password": password}),
    )
    .await
}

/// `close_wallet` - closes the currently open wallet, releasing the
/// wallet files so other apps (e.g. the Monero GUI) can open them.
/// Errors when no wallet is open; callers treat that as already-closed.
pub async fn close_wallet(rpc: &WalletRpc) -> Result<Value, RpcError> {
    rpc.call("close_wallet", json!({})).await
}

/// `get_transfer_by_txid` - used to poll confirmation status.
pub async fn get_transfer_by_txid(rpc: &WalletRpc, txid: &str) -> Result<Value, RpcError> {
    rpc.call("get_transfer_by_txid", json!({"txid": txid}))
        .await
}

/// `relay_tx` - broadcast a transaction previously created with
/// `do_not_relay`. Returns the relayed transaction hash.
pub async fn relay_tx(rpc: &WalletRpc, tx_hex: &str) -> Result<String, RpcError> {
    let r = rpc.call("relay_tx", json!({"hex": tx_hex})).await?;
    r.get("tx_hash")
        .and_then(Value::as_str)
        .map(String::from)
        .ok_or_else(|| RpcError::Malformed("missing tx_hash".into()))
}

/// Build an `Authorization: Digest ...` header answering one of the
/// `WWW-Authenticate: Digest ...` challenges (RFC 2617 + RFC 7616).
/// Newer wallet builds offer several algorithms across multiple headers;
/// the strongest understood one wins (SHA-256, then MD5, `-sess` variants
/// included). Returns `None` when nothing answerable was offered.
fn digest_auth_header(
    http_method: &str,
    uri: &str,
    challenges: &[String],
    username: &str,
    password: &str,
) -> Option<String> {
    // cnonce only needs to be unique per request; time-nanos hex is plenty.
    let cnonce = format!(
        "{:x}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(1)
    );
    // Preference order: strongest first.
    for prefer in ["SHA-256", "SHA-256-sess", "MD5", "MD5-sess"] {
        for challenge in challenges {
            if let Some(h) = digest_auth_header_with_cnonce(
                http_method,
                uri,
                challenge,
                username,
                password,
                &cnonce,
                Some(prefer),
            ) {
                return Some(h);
            }
        }
    }
    None
}

fn digest_auth_header_with_cnonce(
    http_method: &str,
    uri: &str,
    challenge: &str,
    username: &str,
    password: &str,
    cnonce: &str,
    require_algorithm: Option<&str>,
) -> Option<String> {
    let challenge = challenge.strip_prefix("Digest ")?;
    let fields = parse_challenge_fields(challenge);
    let get = |k: &str| {
        fields
            .iter()
            .find(|(key, _)| key.as_str() == k)
            .map(|(_, v)| v.as_str())
    };
    let realm = get("realm")?;
    let nonce = get("nonce")?;
    // These values are copied into a quoted header. A `"`, `\`, or control
    // character lets a hostile challenge (or a hostile username) break out
    // of the quotes or inject a new header line. Reject instead of echoing.
    if !quoted_digest_field_ok(username)
        || !quoted_digest_field_ok(realm)
        || !quoted_digest_field_ok(nonce)
        || !quoted_digest_field_ok(uri)
        || !quoted_digest_field_ok(cnonce)
    {
        return None;
    }
    let qop: Option<&str> = get("qop").and_then(|q| {
        q.split(',')
            .map(str::trim)
            .find(|s| s.trim_matches('"') == "auth")
            .map(|_| "auth")
    });
    let opaque = get("opaque");
    let algorithm = get("algorithm").unwrap_or("MD5");
    if let Some(want) = require_algorithm {
        if !algorithm.eq_ignore_ascii_case(want) {
            return None;
        }
    }
    let sess = algorithm.eq_ignore_ascii_case("MD5-sess")
        || algorithm.eq_ignore_ascii_case("SHA-256-sess");
    // Hash helper per the negotiated algorithm (hex in, hex out).
    let hash_hex = |s: &str| -> Option<String> {
        if algorithm.eq_ignore_ascii_case("MD5") || algorithm.eq_ignore_ascii_case("MD5-sess") {
            Some(format!("{:x}", md5::compute(s.as_bytes())))
        } else if algorithm.eq_ignore_ascii_case("SHA-256")
            || algorithm.eq_ignore_ascii_case("SHA-256-sess")
        {
            use sha2::{Digest, Sha256};
            let mut h = Sha256::new();
            h.update(s.as_bytes());
            Some(hex::encode(h.finalize()))
        } else {
            None
        }
    };
    // Echo the algorithm back without the `-sess` suffix, per RFC 7616.
    let algorithm_name = if sess {
        algorithm
            .strip_suffix("-sess")
            .or_else(|| algorithm.strip_suffix("-SESS"))
            .unwrap_or(algorithm)
    } else {
        algorithm
    };
    let inner = hash_hex(&format!("{username}:{realm}:{password}"))?;
    let ha1 = if sess {
        hash_hex(&format!("{inner}:{nonce}:{cnonce}"))?
    } else {
        inner
    };
    let ha2 = hash_hex(&format!("{http_method}:{uri}"))?;
    let response = if qop.is_some() {
        hash_hex(&format!("{ha1}:{nonce}:00000001:{cnonce}:auth:{ha2}"))?
    } else {
        hash_hex(&format!("{ha1}:{nonce}:{ha2}"))?
    };
    let mut h = format!(
        "Digest username=\"{username}\", realm=\"{realm}\", nonce=\"{nonce}\", uri=\"{uri}\", response=\"{response}\", algorithm={algorithm_name}"
    );
    if qop.is_some() {
        h.push_str(", qop=auth, nc=00000001, cnonce=\"");
        h.push_str(cnonce);
        h.push('"');
    }
    if let Some(o) = opaque {
        if !quoted_digest_field_ok(o) {
            return None;
        }
        h.push_str(&format!(", opaque=\"{o}\""));
    }
    Some(h)
}

/// True when `value` can sit inside a Digest quoted-string with no escaping.
/// Commas are allowed (they stay inside the quotes). Quotes, backslashes,
/// and control characters are not: those are how a challenge smuggles a
/// second directive or a new header line.
fn quoted_digest_field_ok(value: &str) -> bool {
    !value.is_empty()
        && !value
            .chars()
            .any(|c| c == '"' || c == '\\' || c.is_control())
}

/// Parse `key="value", key=value, ...` pairs; commas inside quotes do not
/// split. Keys are lowercased for case-insensitive lookup.
fn parse_challenge_fields(challenge: &str) -> Vec<(String, String)> {
    let mut out = Vec::new();
    let bytes = challenge.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        while i < bytes.len() && (bytes[i] == b' ' || bytes[i] == b',' || bytes[i] == b'\t') {
            i += 1;
        }
        let key_start = i;
        while i < bytes.len() && bytes[i] != b'=' && bytes[i] != b',' {
            i += 1;
        }
        if i >= bytes.len() || bytes[i] != b'=' {
            break;
        }
        let key = challenge[key_start..i].trim().to_ascii_lowercase();
        i += 1; // '='
        let value;
        if i < bytes.len() && bytes[i] == b'"' {
            i += 1;
            let val_start = i;
            while i < bytes.len() && bytes[i] != b'"' {
                if bytes[i] == b'\\' {
                    i += 1;
                }
                i += 1;
            }
            value = challenge[val_start..i.min(bytes.len())].to_string();
            i += 1; // closing quote
        } else {
            let val_start = i;
            while i < bytes.len() && bytes[i] != b',' {
                i += 1;
            }
            value = challenge[val_start..i].trim().to_string();
        }
        out.push((key, value));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn answers_rfc2617_example_challenge() {
        // RFC 2617 §3.5 example values (fixed cnonce from the RFC).
        let challenge = "Digest realm=\"testrealm@host.com\", qop=\"auth\", nonce=\"dcd98b7102dd2f0e8b11d0f600bfb0c093\", opaque=\"5ccc069c403ebaf9f0171e9517f40e41\"";
        let h = digest_auth_header_with_cnonce(
            "GET",
            "/dir/index.html",
            challenge,
            "Mufasa",
            "Circle Of Life",
            "0a4f113b",
            None,
        )
        .expect("must answer");
        assert!(h.contains("response=\"6629fae49393a05397450978507c4ef1\""));
        assert!(h.contains("username=\"Mufasa\""));
    }

    #[test]
    fn answers_sha256_challenge() {
        // Same RFC values, SHA-256 algorithm; expected response computed
        // independently (see commit history / python hashlib reference).
        let challenge = "Digest realm=\"testrealm@host.com\", qop=\"auth\", algorithm=SHA-256, nonce=\"dcd98b7102dd2f0e8b11d0f600bfb0c093\", opaque=\"5ccc069c403ebaf9f0171e9517f40e41\"";
        let h = digest_auth_header_with_cnonce(
            "GET",
            "/dir/index.html",
            challenge,
            "Mufasa",
            "Circle Of Life",
            "0a4f113b",
            None,
        )
        .expect("must answer");
        assert!(h.contains(
            "response=\"5abdd07184ba512a22c53f41470e5eea7dcaa3a93a59b630c13dfe0a5dc6e38b\""
        ));
        assert!(h.contains("algorithm=SHA-256"));
    }

    #[test]
    fn negotiates_strongest_of_several_challenges() {
        let challenges = vec![
            "Digest qop=\"auth\",algorithm=MD5,realm=\"r\",nonce=\"n\",stale=false".to_string(),
            "Digest qop=\"auth\",algorithm=SHA-256,realm=\"r\",nonce=\"n\",stale=false".to_string(),
        ];
        let h =
            digest_auth_header("POST", "/json_rpc", &challenges, "u", "p").expect("must answer");
        assert!(h.contains("algorithm=SHA-256"));
    }

    #[test]
    fn flags_auth_failures() {
        let auth = super::RpcError::Auth {
            endpoint: "http://127.0.0.1:18082".to_string(),
        };
        assert!(auth.is_auth_failure());
        let down = super::RpcError::Connection {
            endpoint: "http://127.0.0.1:18082".to_string(),
            message: "connection refused".to_string(),
        };
        assert!(!down.is_auth_failure());
    }

    #[test]
    fn rejects_header_breaking_challenge_fields() {
        let answer = |challenge: &str, username: &str| {
            digest_auth_header_with_cnonce(
                "POST",
                "/json_rpc",
                challenge,
                username,
                // codeql[rust/hardcoded-credentials]: test fixture, not a real secret
                // lgtm[rust/hardcoded-credentials]
                "p",
                "abc",
                None,
            )
        };
        // A comma inside a quoted realm is one field, not a new directive.
        let comma = answer("Digest realm=\"a,b\", nonce=\"n\", qop=\"auth\"", "user")
            .expect("comma inside quotes is one field");
        assert!(comma.contains("realm=\"a,b\""));
        assert!(!comma.contains("evil="));

        // Quote breakout, backslash, and a smuggled header line are refused.
        assert!(answer("Digest realm=\"a\\\", evil=\\\"x\", nonce=\"n\"", "user",).is_none());
        assert!(answer("Digest realm=\"a\\b\", nonce=\"n\"", "user").is_none());
        assert!(answer("Digest realm=ab\r\nX-Evil: 1, nonce=\"n\"", "user").is_none());
        assert!(answer("Digest realm=\"r\", nonce=\"n\"", "user\", evil=\"x",).is_none());
        assert!(answer("Digest realm=\"r\", nonce=\"n\", opaque=\"o\\\"k\"", "user").is_none());
    }

    #[test]
    fn rejects_non_digest_challenge() {
        assert!(digest_auth_header(
            "POST",
            "/json_rpc",
            &["Basic realm=\"x\"".to_string()],
            "u",
            "p"
        )
        .is_none());
    }
}
