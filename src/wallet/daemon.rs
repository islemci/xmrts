//! Read-only Monero daemon access (spec §13: blockchain data retrieval).
//! Used to fetch a transaction's `tx_extra` and confirm the XMRTS
//! commitment bytes are really on chain. Works against local or remote
//! (restricted-RPC) daemons: `get_transactions` is unrestricted.

use thiserror::Error;

/// Minimum confirmations before a proof counts as anchored.
///
/// Ten confirmations, matching Monero's own 10-block output lock. On
/// 2025-09-14 mainnet saw an 18-block reorg (heights 3_499_659..3_499_676)
/// that orphaned ~115-118 transactions and overwhelmed the 10-block lock;
/// post-incident guidance treats 10 as a *minimum* and recommends 20+ for
/// high-value settlement (Kraken moved to 720 for deposits). Timestamps
/// are long-lived, so 10 is the floor here: `verify --json` reports
/// `"final": false` below it, and callers needing stronger finality
/// should wait for 20+ before relying on a proof.
/// Depth 1 is never final.
///
/// Note on arithmetic: daemon `get_info.height` is the chain *length*
/// (top block height + 1), so `confirmations = tip - tx_height`. A tx in
/// the current top block has exactly 1 confirmation.
pub const MIN_CONFIRMATIONS: u64 = 10;

/// Confirmations for a tx at `tx_height` given daemon `get_info.height`
/// (`tip`, the chain length = top height + 1). A tx in the top block has
/// exactly 1 confirmation. Floor is 1 for any confirmed tx: a `tip <=
/// tx_height` reading means the daemon lags or raced, not zero burial.
pub fn confirmations(tip: u64, tx_height: u64) -> u64 {
    tip.saturating_sub(tx_height).max(1)
}

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
    #[error("block hash mismatch at height {height}: proof says {expected}, chain says {actual}")]
    BlockHashMismatch {
        height: u64,
        expected: String,
        actual: String,
    },
    #[error("height split: proof says block {proof_height} but chain puts tx {txid} in block {chain_height}")]
    HeightMismatch {
        txid: String,
        proof_height: u64,
        chain_height: u64,
    },
    #[error("anchored proof carries an all-zero block_hash; re-stamp or run `xmrts finalize` to fetch the real hash")]
    ZeroBlockHash,
    #[error("network split: proof is {proof_net} but daemon is {daemon_net}")]
    NetworkMismatch {
        proof_net: String,
        daemon_net: String,
    },
}

/// A fully checked anchor (H1+H3+M1): commitment present, height exact,
/// block hash matched, network matched, confirmations computed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AnchorCheck {
    pub height: u64,
    pub block_hash: [u8; 32],
    pub confirmations: u64,
    pub chain_height: u64,
    /// Block timestamp from the daemon (`block_timestamp`; 0 when unknown).
    pub block_timestamp: u64,
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
        // Loopback daemons bypass the proxy; remote daemons use it.
        let endpoint_str: String = endpoint.into();
        let client = super::connection::http_client_builder_for(Some(&endpoint_str))
            .timeout(std::time::Duration::from_secs(30))
            .build()
            .unwrap_or_else(|_| reqwest::Client::new());
        Self {
            endpoint: endpoint_str,
            client,
        }
    }

    /// Fetch (`tx_extra` hex, block height, block timestamp) for a
    /// confirmed transaction.
    pub async fn tx_extra(&self, txid_hex: &str) -> Result<(String, u64, u64), DaemonError> {
        let url = format!("{}/get_transactions", self.endpoint.trim_end_matches('/'));
        let resp: serde_json::Value = self
            .client
            .post(&url)
            .json(&serde_json::json!({"txs_hashes": [txid_hex], "decode_as_json": true}))
            .send()
            .await
            .map_err(|e| DaemonError::Unreachable {
                endpoint: super::connection::display_url(&self.endpoint),
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
        let timestamp = tx
            .get("block_timestamp")
            .and_then(|t| t.as_u64())
            .unwrap_or(0);
        Ok((extra, height, timestamp))
    }
}

/// Format a chain block timestamp as `YYYY-MM-DD HH:MM UTC` (UX).
pub fn format_block_time(timestamp: u64) -> String {
    match chrono::DateTime::from_timestamp(timestamp as i64, 0) {
        Some(dt) => dt.format("%Y-%m-%d %H:%M UTC").to_string(),
        None => format!("{timestamp} (raw Unix time)"),
    }
}

/// Fetch the block hash for a height (for proof anchoring; warns to
/// zeros when unavailable - height is the load-bearing field).
pub async fn block_hash(daemon_endpoint: &str, height: u64) -> Result<[u8; 32], DaemonError> {
    let url = format!("{}/json_rpc", daemon_endpoint.trim_end_matches('/'));
    let client = super::connection::http_client_builder_for(Some(daemon_endpoint))
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
            endpoint: super::connection::display_url(daemon_endpoint),
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

/// Fetch the block header (hash, timestamp) for a height.
/// Timestamp is 0 when the daemon omits it (tolerated: callers treat 0
/// as unknown rather than failing the whole check).
pub async fn block_header(
    daemon_endpoint: &str,
    height: u64,
) -> Result<([u8; 32], u64), DaemonError> {
    let url = format!("{}/json_rpc", daemon_endpoint.trim_end_matches('/'));
    let client = super::connection::http_client_builder_for(Some(daemon_endpoint))
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
            endpoint: super::connection::display_url(daemon_endpoint),
            message: e.to_string(),
        })?
        .json()
        .await
        .map_err(|e| DaemonError::Malformed(e.to_string()))?;
    let header = resp
        .get("result")
        .and_then(|r| r.get("block_header"))
        .ok_or_else(|| DaemonError::Malformed("missing block header".to_string()))?;
    let hash_hex = header
        .get("hash")
        .and_then(|h| h.as_str())
        .ok_or_else(|| DaemonError::Malformed("missing block hash".to_string()))?;
    let hash: [u8; 32] = hex::decode(hash_hex)
        .map_err(|e| DaemonError::Malformed(format!("bad block hash: {e}")))?
        .try_into()
        .map_err(|_| DaemonError::Malformed("bad block hash length".to_string()))?;
    let timestamp = header
        .get("timestamp")
        .and_then(|t| t.as_u64())
        .unwrap_or(0);
    Ok((hash, timestamp))
}

/// Describe how stale a tip timestamp is, if known. Returns `None` for
/// fresh tips (< 30 min) and unknown timestamps (0); otherwise a
/// human age like "3h 12m".
pub fn tip_staleness(tip_timestamp: u64, now_secs: u64) -> Option<String> {
    const STALE_AFTER_SECS: u64 = 30 * 60;
    if tip_timestamp == 0 || now_secs <= tip_timestamp {
        return None;
    }
    let age = now_secs - tip_timestamp;
    if age < STALE_AFTER_SECS {
        return None;
    }
    let desc = if age < 3600 {
        format!("{}m", age / 60)
    } else if age < 86400 {
        format!("{}h {}m", age / 3600, age % 3600 / 60)
    } else {
        format!("{}d {}h", age / 86400, age % 86400 / 3600)
    };
    Some(desc)
}
/// Confirm the commitment for `expected_commitment` is present in the
/// transaction's `tx_extra` **and** the transaction is confirmed. Returns
/// the chain-reported block height. Mempool transactions fail with
/// [`DaemonError::Unconfirmed`] even when the bytes match: presence
/// without burial proves nothing about time.
///
/// `expected_commitment` is the size-bound root for V2 proofs
/// (`commit_root`) and the raw root for legacy V1 proofs. When
/// `expected_merkle_ver` is `Some`, the matching chain commitment must
/// also carry that version byte.
pub async fn confirm_commitment(
    daemon_endpoint: &str,
    txid_hex: &str,
    expected_commitment: &[u8; 32],
) -> Result<u64, DaemonError> {
    confirm_commitment_for_version(daemon_endpoint, txid_hex, expected_commitment, None).await
}

pub async fn confirm_commitment_for_version(
    daemon_endpoint: &str,
    txid_hex: &str,
    expected_commitment: &[u8; 32],
    expected_merkle_ver: Option<u8>,
) -> Result<u64, DaemonError> {
    let client = DaemonClient::new(daemon_endpoint);
    let (extra_hex, height, _) = client.tx_extra(txid_hex).await?;
    if height == 0 {
        return Err(DaemonError::Unconfirmed {
            txid: txid_hex.to_string(),
        });
    }
    let found = crate::protocol::commitment::find_commitments_hex(&extra_hex)
        .map_err(|e| DaemonError::Malformed(format!("commitment parse: {e}")))?;
    let ok = found.iter().any(|c| {
        c.root == *expected_commitment
            && expected_merkle_ver
                .map(|v| c.merkle_ver == v)
                .unwrap_or(true)
    });
    if ok {
        Ok(height)
    } else {
        Err(DaemonError::CommitmentAbsent {
            txid: txid_hex.to_string(),
        })
    }
}

/// Daemon `get_info`: returns (nettype, chain height).
pub async fn get_info(daemon_endpoint: &str) -> Result<(String, u64), DaemonError> {
    let url = format!("{}/json_rpc", daemon_endpoint.trim_end_matches('/'));
    let client = super::connection::http_client_builder_for(Some(daemon_endpoint))
        .timeout(std::time::Duration::from_secs(30))
        .build()
        .unwrap_or_else(|_| reqwest::Client::new());
    let resp: serde_json::Value = client
        .post(&url)
        .json(&serde_json::json!({
            "jsonrpc": "2.0", "id": "0",
            "method": "get_info",
        }))
        .send()
        .await
        .map_err(|e| DaemonError::Unreachable {
            endpoint: super::connection::display_url(daemon_endpoint),
            message: e.to_string(),
        })?
        .json()
        .await
        .map_err(|e| DaemonError::Malformed(e.to_string()))?;
    let result = resp
        .get("result")
        .ok_or_else(|| DaemonError::Malformed("get_info: missing result".to_string()))?;
    let nettype = result
        .get("nettype")
        .and_then(|v| v.as_str())
        .ok_or_else(|| DaemonError::Malformed("get_info: missing nettype".to_string()))?
        .to_string();
    let height = result
        .get("height")
        .and_then(|v| v.as_u64())
        .ok_or_else(|| DaemonError::Malformed("get_info: missing height".to_string()))?;
    Ok((nettype, height))
}

/// Fully verify a proof's anchor against the daemon (H1+H3+M1):
/// commitment present, tx confirmed, `proof_height` equals the chain tx
/// height (never `max`), `proof_block_hash` equals the header hash at
/// that height, and daemon nettype equals the proof network.
/// Returns the anchor with confirmation depth for H3 enforcement.
///
/// `expected_commitment` is the size-bound root for V2 proofs and the raw
/// root for legacy V1; `proof_merkle_ver` (when `Some`) must match the
/// chain commitment's version byte.
pub async fn verify_anchor(
    daemon_endpoint: &str,
    txid_hex: &str,
    expected_commitment: &[u8; 32],
    proof_height: u64,
    proof_block_hash: &[u8; 32],
    proof_network: &str,
) -> Result<AnchorCheck, DaemonError> {
    verify_anchor_for_version(
        daemon_endpoint,
        txid_hex,
        expected_commitment,
        None,
        proof_height,
        proof_block_hash,
        proof_network,
    )
    .await
}

pub async fn verify_anchor_for_version(
    daemon_endpoint: &str,
    txid_hex: &str,
    expected_commitment: &[u8; 32],
    proof_merkle_ver: Option<u8>,
    proof_height: u64,
    proof_block_hash: &[u8; 32],
    proof_network: &str,
) -> Result<AnchorCheck, DaemonError> {
    if proof_block_hash == &[0u8; 32] {
        return Err(DaemonError::ZeroBlockHash);
    }
    let client = DaemonClient::new(daemon_endpoint);
    let (extra_hex, chain_height, block_timestamp) = client.tx_extra(txid_hex).await?;
    if chain_height == 0 {
        return Err(DaemonError::Unconfirmed {
            txid: txid_hex.to_string(),
        });
    }
    let found = crate::protocol::commitment::find_commitments_hex(&extra_hex)
        .map_err(|e| DaemonError::Malformed(format!("commitment parse: {e}")))?;
    let ok = found.iter().any(|c| {
        c.root == *expected_commitment
            && proof_merkle_ver.map(|v| c.merkle_ver == v).unwrap_or(true)
    });
    if !ok {
        return Err(DaemonError::CommitmentAbsent {
            txid: txid_hex.to_string(),
        });
    }
    if chain_height != proof_height {
        return Err(DaemonError::HeightMismatch {
            txid: txid_hex.to_string(),
            proof_height,
            chain_height,
        });
    }
    let header_hash = block_hash(daemon_endpoint, proof_height).await?;
    if &header_hash != proof_block_hash {
        return Err(DaemonError::BlockHashMismatch {
            height: proof_height,
            expected: hex::encode(proof_block_hash),
            actual: hex::encode(header_hash),
        });
    }
    let (daemon_net, tip) = get_info(daemon_endpoint).await?;
    if !daemon_net.eq_ignore_ascii_case(proof_network) {
        return Err(DaemonError::NetworkMismatch {
            proof_net: proof_network.to_string(),
            daemon_net,
        });
    }
    let confirmations = confirmations(tip, chain_height);
    Ok(AnchorCheck {
        height: chain_height,
        block_hash: header_hash,
        confirmations,
        chain_height: tip,
        block_timestamp,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tip_staleness_flags_old_tips_only() {
        let now = 1_760_000_000u64;
        // Fresh (< 30 min) and unknown (0) pass silently.
        assert_eq!(tip_staleness(now - 60, now), None);
        assert_eq!(tip_staleness(now - 29 * 60, now), None);
        assert_eq!(tip_staleness(0, now), None);
        // Future timestamps (clock skew) are not "stale".
        assert_eq!(tip_staleness(now + 60, now), None);
        // Stale tips name their age.
        assert_eq!(tip_staleness(now - 3600, now).as_deref(), Some("1h 0m"));
        assert_eq!(
            tip_staleness(now - 3 * 3600 - 12 * 60, now).as_deref(),
            Some("3h 12m")
        );
        assert_eq!(
            tip_staleness(now - 2 * 86400, now).as_deref(),
            Some("2d 0h")
        );
    }
}
