//! Minimal `monero-wallet-rpc` JSON-RPC client (spec §31 research notes).
//! Only the methods xmrts actually needs are implemented.

use reqwest::Client;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::time::Duration;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum RpcError {
    #[error("connection failed to {endpoint}: {message}")]
    Connection { endpoint: String, message: String },
    #[error("wallet RPC error {code}: {message}")]
    Server { code: i64, message: String },
    #[error("malformed RPC response: {0}")]
    Malformed(String),
    #[error(transparent)]
    Http(#[from] reqwest::Error),
}

impl RpcError {
    /// True when the server answered but rejected auth (HTTP 401).
    /// Something listens on the port with a different login than ours.
    pub fn is_auth_failure(&self) -> bool {
        match self {
            RpcError::Connection { message, .. } => message.contains("401"),
            _ => false,
        }
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
    ) -> Self {
        let client = Client::builder()
            .timeout(Duration::from_secs(30))
            .build()
            .expect("reqwest client");
        Self {
            endpoint: endpoint.into(),
            client,
            username,
            password,
        }
    }

    pub fn endpoint(&self) -> &str {
        &self.endpoint
    }

    async fn call(&self, method: &str, params: Value) -> Result<Value, RpcError> {
        let url = format!("{}/json_rpc", self.endpoint.trim_end_matches('/'));
        let body = json!({"jsonrpc": "2.0", "id": "0", "method": method, "params": params});
        let conn_err = |e: reqwest::Error| RpcError::Connection {
            endpoint: self.endpoint.clone(),
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
                return Err(RpcError::Connection {
                    endpoint: self.endpoint.clone(),
                    message: "wallet RPC requires login (HTTP 401) but no username/password is configured; run `xmrts connect --username USER --password PASS --save-auth`".to_string(),
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
                    endpoint: self.endpoint.clone(),
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
                return Err(RpcError::Connection {
                    endpoint: self.endpoint.clone(),
                    message: "wallet RPC rejected the username/password (HTTP 401 even with Digest response)".to_string(),
                });
            }
        }
        let v: Value = resp.json().await.map_err(conn_err)?;
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
pub async fn transfer_with_extra(
    rpc: &WalletRpc,
    destinations: Vec<Destination>,
    extra_hex: &str,
    do_not_relay: bool,
    get_tx_hex: bool,
) -> Result<(TransferResult, Value), RpcError> {
    let params = json!({
        "destinations": destinations,
        "priority": 0,
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
        h.push_str(&format!(", opaque=\"{o}\""));
    }
    Some(h)
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
        let auth = super::RpcError::Connection {
            endpoint: "http://127.0.0.1:18082".to_string(),
            message:
                "wallet RPC rejected the username/password (HTTP 401 even with Digest response)"
                    .to_string(),
        };
        assert!(auth.is_auth_failure());
        let down = super::RpcError::Connection {
            endpoint: "http://127.0.0.1:18082".to_string(),
            message: "connection refused".to_string(),
        };
        assert!(!down.is_auth_failure());
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
