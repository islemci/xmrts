//! Read-only Monero daemon access (spec §13: blockchain data retrieval).
//! Used to fetch a transaction's `tx_extra` and confirm the XMRTS
//! commitment bytes are really on chain. Works against local or remote
//! (restricted-RPC) daemons: `get_transactions` is unrestricted.

use thiserror::Error;

#[derive(Debug, Error)]
pub enum DaemonError {
    #[error("daemon unreachable at {endpoint}: {message}")]
    Unreachable { endpoint: String, message: String },
    #[error("transaction {txid} not found on daemon")]
    NotFound { txid: String },
    #[error("bad daemon response: {0}")]
    Malformed(String),
    #[error("no XMRST commitment for this root in transaction {txid}")]
    CommitmentAbsent { txid: String },
    #[error("transaction {txid} is not yet confirmed (still in mempool)")]
    Unconfirmed { txid: String },
}

#[derive(Debug, Clone)]
pub struct DaemonClient {
    endpoint: String,
    client: reqwest::Client,
}

impl DaemonClient {
    pub fn new(endpoint: impl Into<String>) -> Self {
        // Daemon calls happen mid-flow (stamp/verify/finalize): a
        // black-holing endpoint must time out, never hang the command.
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(30))
            .build()
            .unwrap_or_else(|_| reqwest::Client::new());
        Self {
            endpoint: endpoint.into(),
            client,
        }
    }

    /// Fetch (`tx_extra` hex, block height) for a confirmed transaction.
    pub async fn tx_extra(&self, txid_hex: &str) -> Result<(String, u64), DaemonError> {
        let url = format!("{}/get_transactions", self.endpoint.trim_end_matches('/'));
        let resp: serde_json::Value = self
            .client
            .post(&url)
            .json(&serde_json::json!({"txs_hashes": [txid_hex], "decode_as_json": true}))
            .send()
            .await
            .map_err(|e| DaemonError::Unreachable {
                endpoint: self.endpoint.clone(),
                message: e.to_string(),
            })?
            .json()
            .await
            .map_err(|e| DaemonError::Malformed(e.to_string()))?;
        let tx = resp
            .get("txs")
            .and_then(|t| t.as_array())
            .and_then(|a| a.first())
            .ok_or_else(|| DaemonError::NotFound {
                txid: txid_hex.to_string(),
            })?;
        // Prefer decoded JSON `extra`, fall back to parsing `as_json`.
        let mut extra: Option<String> = tx.get("extra").and_then(|e| e.as_str()).map(String::from);
        if extra.is_none() {
            if let Some(as_json) = tx.get("as_json").and_then(|j| j.as_str()) {
                let v: serde_json::Value = serde_json::from_str(as_json)
                    .map_err(|e| DaemonError::Malformed(e.to_string()))?;
                // In decoded tx JSON, `extra` is an array of byte ints.
                if let Some(arr) = v.get("extra").and_then(|e| e.as_array()) {
                    let bytes: Option<Vec<u8>> = arr
                        .iter()
                        .map(|n| n.as_u64().and_then(|b| u8::try_from(b).ok()))
                        .collect();
                    extra = bytes.map(hex::encode);
                } else if let Some(s) = v.get("extra").and_then(|e| e.as_str()) {
                    extra = Some(s.to_string());
                }
            }
        }
        let extra = extra.ok_or_else(|| DaemonError::NotFound {
            txid: txid_hex.to_string(),
        })?;
        let height = tx.get("block_height").and_then(|h| h.as_u64()).unwrap_or(0);
        Ok((extra, height))
    }
}

/// Fetch the block hash for a height (for proof anchoring; warns to
/// zeros when unavailable - height is the load-bearing field).
pub async fn block_hash(daemon_endpoint: &str, height: u64) -> Result<[u8; 32], DaemonError> {
    let url = format!("{}/json_rpc", daemon_endpoint.trim_end_matches('/'));
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .build()
        .unwrap_or_else(|_| reqwest::Client::new());
    let resp: serde_json::Value = client
        .post(&url)
        .json(&serde_json::json!({
            "jsonrpc": "2.0", "id": "0",
            "method": "get_block_header_by_height",
            "params": {"height": height},
        }))
        .send()
        .await
        .map_err(|e| DaemonError::Unreachable {
            endpoint: daemon_endpoint.to_string(),
            message: e.to_string(),
        })?
        .json()
        .await
        .map_err(|e| DaemonError::Malformed(e.to_string()))?;
    let hash_hex = resp
        .get("result")
        .and_then(|r| r.get("block_header"))
        .and_then(|h| h.get("hash"))
        .and_then(|h| h.as_str())
        .ok_or_else(|| DaemonError::Malformed("missing block hash".to_string()))?;
    hex::decode(hash_hex)
        .map_err(|e| DaemonError::Malformed(format!("bad block hash: {e}")))?
        .try_into()
        .map_err(|_| DaemonError::Malformed("bad block hash length".to_string()))
}
/// Confirm the commitment for `root` is present in the transaction's
/// `tx_extra` **and** the transaction is confirmed. Returns the
/// chain-reported block height. Mempool transactions fail with
/// [`DaemonError::Unconfirmed`] even when the bytes match: presence
/// without burial proves nothing about time.
pub async fn confirm_commitment(
    daemon_endpoint: &str,
    txid_hex: &str,
    root: &[u8; 32],
) -> Result<u64, DaemonError> {
    let client = DaemonClient::new(daemon_endpoint);
    let (extra_hex, height) = client.tx_extra(txid_hex).await?;
    if height == 0 {
        return Err(DaemonError::Unconfirmed {
            txid: txid_hex.to_string(),
        });
    }
    let found = crate::protocol::commitment::find_commitments_hex(&extra_hex)
        .map_err(|e| DaemonError::Malformed(format!("commitment parse: {e}")))?;
    if found.iter().any(|c| c.root == *root) {
        Ok(height)
    } else {
        Err(DaemonError::CommitmentAbsent {
            txid: txid_hex.to_string(),
        })
    }
}
