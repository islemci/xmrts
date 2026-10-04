//! `xmrts finalize` — finish a pending stamp into anchored proofs.
//!
//! Used when the transaction confirmed after `stamp` gave up waiting
//! (slow blocks, remote-daemon lag): re-checks confirmation, re-checks
//! the on-chain commitment bytes, re-hashes the files, and writes the
//! anchored `.xmrts` proofs. No new transaction, no new fee.

use anyhow::{Context, Result};
use clap::Args;
use std::path::{Path, PathBuf};

use super::pending;
use super::stamp;
use crate::protocol::hash;
use crate::protocol::merkle::MerkleTree;
use crate::protocol::proof::Network;
use crate::wallet::connection;

#[derive(Debug, Args)]
pub struct FinalizeArgs {
    /// Pending file to finalize (default: auto-select when exactly one exists).
    pub pending: Option<PathBuf>,
    /// Daemon endpoint override for the on-chain checks.
    #[arg(long)]
    pub daemon: Option<String>,
}

pub async fn run(args: &FinalizeArgs, verbose: bool, stagenet: bool) -> Result<()> {
    let _ = verbose;
    let pending_path = match &args.pending {
        Some(p) => p.clone(),
        None => match pending::list().as_slice() {
            [] => anyhow::bail!("nothing pending (no files in the pending directory)"),
            [only] => only.clone(),
            many => {
                anyhow::bail!(
                    "several pending operations; specify one:\n{}",
                    many.iter()
                        .map(|p| format!("  {}", p.display()))
                        .collect::<Vec<_>>()
                        .join("\n")
                );
            }
        },
    };
    let op = pending::load(&pending_path)?;
    if op.txid.is_empty() {
        anyhow::bail!(
            "pending operation was never relayed (no txid); re-run `xmrts stamp` instead"
        );
    }
    let root: [u8; 32] = hex::decode(&op.root)
        .context("bad root in pending file")?
        .try_into()
        .map_err(|_| anyhow::anyhow!("bad root length in pending file"))?;
    let network =
        Network::from_str(&op.network).map_err(|e| anyhow::anyhow!("bad network: {e}"))?;
    if stagenet && network != Network::Stagenet {
        anyhow::bail!("pending operation is for {}, not stagenet", op.network);
    }

    let cfg = connection::load_config();
    let daemon = args
        .daemon
        .clone()
        .or(cfg.daemon_endpoint.clone())
        .ok_or_else(|| {
            anyhow::anyhow!(
                "no daemon endpoint configured; set one with `xmrts connect --daemon <url>`"
            )
        })?;
    // 1. Chain confirmation + commitment bytes (same honesty rule as stamp).
    let bar = super::ui::spinner("Checking on-chain commitment…");
    let height = crate::wallet::daemon::confirm_commitment(&daemon, &op.txid, &root).await;
    super::ui::abandon(&bar);
    let height = height.map_err(|e| anyhow::anyhow!("not yet finalizable: {e}"))?;
    super::ui::ok(&format!(
        "Transaction {} confirmed in block {height}",
        op.txid
    ));
    super::ui::ok("Commitment confirmed on chain");
    let block_hash = match crate::wallet::daemon::block_hash(&daemon, height).await {
        Ok(h) => h,
        Err(e) => {
            super::ui::warn(&format!(
                "block hash lookup failed ({e}); proofs carry zeroed block hash"
            ));
            [0u8; 32]
        }
    };

    // 2. Re-hash the files; the set must be unchanged since stamp.
    let mut pairs: Vec<([u8; 32], PathBuf)> = Vec::new();
    for f in &op.files {
        let path = Path::new(f);
        let h = hash::hash_file(path)
            .with_context(|| format!("hashing {f} (file changed or unreadable?)"))?;
        pairs.push((h, path.to_path_buf()));
    }
    pairs.sort_by_key(|(h, _)| *h);
    let recomputed: Vec<String> = pairs.iter().map(|(h, _)| hex::encode(h)).collect();
    let mut stored = op.sorted_hashes.clone();
    stored.sort();
    let mut recomputed_sorted = recomputed.clone();
    recomputed_sorted.sort();
    if recomputed_sorted != stored {
        anyhow::bail!("files changed since stamp (hash set differs); cannot finalize safely");
    }
    let file_hashes: Vec<[u8; 32]> = pairs.iter().map(|(h, _)| *h).collect();
    let (sorted, tree) =
        MerkleTree::build_from_unsorted(file_hashes).map_err(|e| anyhow::anyhow!("merkle: {e}"))?;
    if tree.root() != root {
        anyhow::bail!("recomputed root differs from pending record; cannot finalize safely");
    }
    let txid_bytes: [u8; 32] = hex::decode(&op.txid)
        .context("bad txid in pending file")?
        .try_into()
        .map_err(|_| anyhow::anyhow!("bad txid length in pending file"))?;
    let out_dir = op.out_dir.as_ref().map(PathBuf::from);

    // 3. Write anchored proofs (reuse stamp's writer).
    stamp::write_proofs(
        &pairs,
        &sorted,
        &tree,
        &network,
        &txid_bytes,
        height,
        &block_hash,
        out_dir.as_deref(),
    )?;
    let _ = std::fs::remove_file(&pending_path);
    println!();
    super::ui::ok(&format!(
        "Finalized {} proof(s) at block {height}",
        pairs.len()
    ));
    println!("Meaning: the files existed no later than block {height}.");
    Ok(())
}
