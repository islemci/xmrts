//! Read-only Monero daemon access (spec §13: blockchain data retrieval).
//! Used to fetch a transaction's `tx_extra` and confirm the XMRTS
//! commitment bytes are really on chain. Works against local or remote
//! (restricted-RPC) daemons: `get_transactions` is unrestricted.

use thiserror::Error;

/// Minimum confirmations before a proof counts as anchored (H3).
/// Matches Monero's ~10-block spendable window; reorgs of 1-2 blocks are
/// routine, so depth 1 is never final.
pub const MIN_CONFIRMATIONS: u64 = 10;

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
    let (extra_hex, height) = client.tx_extra(txid_hex).await?;
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
    let client = reqwest::Client::builder()
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
            endpoint: daemon_endpoint.to_string(),
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
    let (extra_hex, chain_height) = client.tx_extra(txid_hex).await?;
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
    let confirmations = tip.saturating_sub(chain_height).saturating_add(1).max(1);
    Ok(AnchorCheck {
        height: chain_height,
        block_hash: header_hash,
        confirmations,
        chain_height: tip,
    })
}
