//! `xmrts finalize`. Turns pending stamps into anchored proofs.
//! Use after slow blocks. No new tx. No new fee.

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
    /// Pending file to finish (picks the only one when empty).
    pub pending: Option<PathBuf>,
    /// Daemon address for chain checks.
    #[arg(long)]
    pub daemon: Option<String>,
}

pub async fn run(args: &FinalizeArgs, verbose: bool, stagenet: bool) -> Result<()> {
    let _ = verbose;
    let _ = connection::ensure_dirs();
    super::ui::header("◆", "Finalize");
    let pending_path = match &args.pending {
        Some(p) => p.clone(),
        None => match pending::list().as_slice() {
            [] => anyhow::bail!("Nothing pending. No files wait."),
            [only] => only.clone(),
            many => {
                anyhow::bail!(
                    "Many pendings. Name one:\n{}",
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
        anyhow::bail!("This pending never sent (no txid). Run `xmrts stamp` again");
    }
    let root: [u8; 32] = hex::decode(&op.root)
        .context("Pending file holds a bad root")?
        .try_into()
        .map_err(|_| anyhow::anyhow!("Pending file holds a short root"))?;
    let network =
        Network::from_str(&op.network).map_err(|e| anyhow::anyhow!("Bad network: {e}"))?;
    if stagenet && network != Network::Stagenet {
        anyhow::bail!("This pending is for {}, not stagenet", op.network);
    }

    let cfg = connection::load_config();
    let daemon = args
        .daemon
        .clone()
        .or(cfg.daemon_endpoint.clone())
        .ok_or_else(|| anyhow::anyhow!("No daemon set. Run `xmrts connect --daemon <url>`"))?;
    let bar = super::ui::spinner("Checking chain...");
    let height = crate::wallet::daemon::confirm_commitment(&daemon, &op.txid, &root).await;
    super::ui::abandon(&bar);
    let height = height.map_err(|e| anyhow::anyhow!("Not ready yet: {e}"))?;
    super::ui::ok(&format!("Tx {} sits in block {height}.", op.txid));
    super::ui::ok("Chain holds your mark.");
    let block_hash = match crate::wallet::daemon::block_hash(&daemon, height).await {
        Ok(h) => h,
        Err(e) => {
            super::ui::warn(&format!("Block hash missed ({e}). Proofs carry zeros"));
            [0u8; 32]
        }
    };

    let mut pairs: Vec<([u8; 32], PathBuf)> = Vec::new();
    for f in &op.files {
        let path = Path::new(f);
        let h =
            hash::hash_file(path).with_context(|| format!("Reading {f} (moved or changed?)"))?;
        pairs.push((h, path.to_path_buf()));
    }
    pairs.sort_by_key(|(h, _)| *h);
    let recomputed: Vec<String> = pairs.iter().map(|(h, _)| hex::encode(h)).collect();
    let mut stored = op.sorted_hashes.clone();
    stored.sort();
    let mut recomputed_sorted = recomputed.clone();
    recomputed_sorted.sort();
    if recomputed_sorted != stored {
        anyhow::bail!("Files changed since stamp. Cannot finish safely");
    }
    let file_hashes: Vec<[u8; 32]> = pairs.iter().map(|(h, _)| *h).collect();
    let (sorted, tree) = MerkleTree::build_from_unsorted(file_hashes)
        .map_err(|e| anyhow::anyhow!("Tree failed: {e}"))?;
    if tree.root() != root {
        anyhow::bail!("Root changed. Cannot finish safely");
    }
    let txid_bytes: [u8; 32] = hex::decode(&op.txid)
        .context("Pending file holds a bad txid")?
        .try_into()
        .map_err(|_| anyhow::anyhow!("Pending file holds a short txid"))?;
    let out_dir = op.out_dir.as_ref().map(PathBuf::from);

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
        "Done. {} proof(s) at block {height}.",
        pairs.len()
    ));
    println!("Files lived no later than block {height}.");
    Ok(())
}
