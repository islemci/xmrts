//! Interrupted-operation recovery state (spec §23 / Phase 7).
//!
//! A pending file records the minimum needed to finish a stamp later:
//! input files, sorted hashes + root, commitment, and transaction state
//! (preview hex always, relayed txid once known). Never file contents.

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

use crate::wallet::connection;

fn default_merkle_ver() -> u8 {
    crate::protocol::merkle::MERKLE_V1
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PendingOp {
    pub files: Vec<String>,
    pub file_hashes: Vec<String>,
    pub sorted_hashes: Vec<String>,
    pub root: String,
    pub extra_hex: String,
    pub txid: String,
    /// Preview hex (doubles as the relay payload): enough to re-relay
    /// after a crash between preview and relay.
    pub tx_hex: String,
    #[serde(default)]
    pub out_dir: Option<String>,
    pub network: String,
    /// Merkle version used for the chain commitment (M6). Old pendings
    /// predate the field and default to V1.
    #[serde(default = "default_merkle_ver")]
    pub merkle_ver: u8,
}

pub fn path_for_root(root_hex: &str) -> Option<PathBuf> {
    connection::pending_dir().map(|d| {
        d.join(format!(
            "pending-{}.json",
            &root_hex[..16.min(root_hex.len())]
        ))
    })
}

/// All pending files, sorted for deterministic selection.
pub fn list() -> Vec<PathBuf> {
    let Some(dir) = connection::pending_dir() else {
        return Vec::new();
    };
    let mut out: Vec<PathBuf> = std::fs::read_dir(dir)
        .into_iter()
        .flatten()
        .flatten()
        .map(|e| e.path())
        .filter(|p| {
            p.file_name()
                .and_then(|n| n.to_str())
                .map(|n| n.starts_with("pending-") && n.ends_with(".json"))
                .unwrap_or(false)
        })
        .collect();
    out.sort();
    out
}

pub fn load(path: &Path) -> Result<PendingOp> {
    let text =
        std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
    serde_json::from_str(&text).with_context(|| format!("parsing {}", path.display()))
}

pub fn save(op: &PendingOp) -> Result<PathBuf> {
    let Some(dir) = connection::pending_dir() else {
        anyhow::bail!("no config dir");
    };
    std::fs::create_dir_all(&dir)?;
    let path = path_for_root(&op.root).ok_or_else(|| anyhow::anyhow!("no config dir"))?;
    std::fs::write(&path, serde_json::to_string_pretty(op)?)?;
    Ok(path)
}

/// Record the relayed txid in the pending file, so a crash between relay
/// and proof-writing still leaves the files→root→transaction link behind.
pub fn update_txid(path: &Path, txid: &str) {
    let Ok(text) = std::fs::read_to_string(path) else {
        return;
    };
    let Ok(mut v) = serde_json::from_str::<serde_json::Value>(&text) else {
        return;
    };
    v["txid"] = serde_json::Value::String(txid.to_string());
    if let Ok(out) = serde_json::to_string_pretty(&v) {
        let _ = std::fs::write(path, out);
    }
}
