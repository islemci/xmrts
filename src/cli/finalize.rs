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
    /// Finish every pending stamp, one after another.
    #[arg(long)]
    pub all: bool,
}

pub async fn run(args: &FinalizeArgs, verbose: bool, stagenet: bool) -> Result<()> {
    let _ = verbose;
    let _ = connection::ensure_dirs();
    super::ui::header("◆", "Finalize");
    if args.all && args.pending.is_some() {
        anyhow::bail!("Use --all or name one pending. Not both.");
    }
    if args.all {
        let all = pending::list();
        if all.is_empty() {
            anyhow::bail!("Nothing pending. No files wait.");
        }
        let mut failures: Vec<String> = Vec::new();
        for p in &all {
            match finalize_one(p, args.daemon.as_deref(), stagenet).await {
                Ok(()) => {}
                Err(e) => failures.push(format!("{}: {e:#}", p.display())),
            }
        }
        if !failures.is_empty() {
            anyhow::bail!(
                "{} of {} pending(s) still wait:\n{}",
                failures.len(),
                all.len(),
                failures.join("\n")
            );
        }
        super::ui::ok(&format!("Done. {} pending(s) finished.", all.len()));
        return Ok(());
    }
    let pending_path = match &args.pending {
        Some(p) => p.clone(),
        None => match pending::list().as_slice() {
            [] => anyhow::bail!("Nothing pending. No files wait."),
            [only] => only.clone(),
            many => {
                anyhow::bail!(
                    "Many pendings. Name one or pass --all:\n{}",
                    many.iter()
                        .map(|p| format!("  {}", p.display()))
                        .collect::<Vec<_>>()
                        .join("\n")
                );
            }
        },
    };
    finalize_one(&pending_path, args.daemon.as_deref(), stagenet).await
}

async fn finalize_one(
    pending_path: &std::path::Path,
    daemon_opt: Option<&str>,
    stagenet: bool,
) -> Result<()> {
    super::ui::field("Pending", &pending_path.display().to_string());
    let op = pending::load(pending_path)?;
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
    let daemon = daemon_opt
        .map(String::from)
        .or(cfg.daemon_endpoint.clone())
        .ok_or_else(|| anyhow::anyhow!("No daemon set. Run `xmrts connect --daemon <url>`"))?;
    // M6: commitment is version-aware (V1 raw root, V2 size-bound).
    // Old pendings default to V1 via serde.
    let merkle_ver = op.merkle_ver;
    crate::protocol::merkle::check_version(merkle_ver)
        .map_err(|e| anyhow::anyhow!("Pending file holds a bad merkle version: {e}"))?;
    let tree_size = op.sorted_hashes.len() as u64;
    let commitment = crate::protocol::merkle::commitment_for_version(&root, tree_size, merkle_ver);
    let bar = super::ui::spinner("Checking chain...");
    let height = crate::wallet::daemon::confirm_commitment_for_version(
        &daemon,
        &op.txid,
        &commitment,
        Some(merkle_ver),
    )
    .await;
    super::ui::abandon(&bar);
    let height = height.map_err(|e| anyhow::anyhow!("Not ready yet: {e}"))?;
    super::ui::ok(&format!("Tx {} sits in block {height}.", op.txid));
    super::ui::ok("Chain holds your mark.");
    // H2: never write zeros. If the hash cannot be fetched, stay pending.
    let block_hash = crate::wallet::daemon::block_hash(&daemon, height)
        .await
        .map_err(|e| anyhow::anyhow!("Block hash missed ({e}). Staying pending; retry later"))?;
    // H3: depth gate — only anchor when buried deep enough.
    let (_, tip) = crate::wallet::daemon::get_info(&daemon)
        .await
        .map_err(|e| anyhow::anyhow!("Chain tip unknown ({e}). Staying pending; retry later"))?;
    let confirmations = tip.saturating_sub(height).saturating_add(1);
    if confirmations < crate::wallet::daemon::MIN_CONFIRMATIONS {
        anyhow::bail!(
            "Only {confirmations} confirmation(s); want {}+. Staying pending; run `xmrts finalize` later",
            crate::wallet::daemon::MIN_CONFIRMATIONS
        );
    }

    let mut pairs: Vec<([u8; 32], PathBuf)> = Vec::new();
    for f in &op.files {
        let path = Path::new(f);
        let h =
            hash::hash_file(path).with_context(|| format!("Reading {f} (moved or changed?)"))?;
        pairs.push((h, path.to_path_buf()));
    }
    pairs.sort_by_key(|(h, _)| *h);
    // M6: compare deduped sets (identical content shares one leaf).
    let mut recomputed_unique: Vec<[u8; 32]> = Vec::new();
    for (h, _) in &pairs {
        if !recomputed_unique.contains(h) {
            recomputed_unique.push(*h);
        }
    }
    let mut recomputed_sorted: Vec<String> = recomputed_unique.iter().map(hex::encode).collect();
    recomputed_sorted.sort();
    let mut stored = op.sorted_hashes.clone();
    stored.sort();
    if recomputed_sorted != stored {
        anyhow::bail!("Files changed since stamp. Cannot finish safely");
    }
    let (sorted, tree) = MerkleTree::build_from_unsorted(recomputed_unique)
        .map_err(|e| anyhow::anyhow!("Tree failed: {e}"))?;
    if tree.root() != root {
        anyhow::bail!("Root changed. Cannot finish safely");
    }
    let txid_bytes: [u8; 32] = hex::decode(&op.txid)
        .context("Pending file holds a bad txid")?
        .try_into()
        .map_err(|_| anyhow::anyhow!("Pending file holds a short txid"))?;
    let out_dir = op.out_dir.as_ref().map(PathBuf::from);

    let _ = stamp::write_proofs(
        &pairs,
        &sorted,
        &tree,
        &network,
        &txid_bytes,
        height,
        &block_hash,
        out_dir.as_deref(),
    )?;
    let _ = std::fs::remove_file(pending_path);
    println!();
    super::ui::ok(&format!(
        "Done. {} proof(s) at block {height}.",
        pairs.len()
    ));
    println!("Files lived no later than block {height}.");
    Ok(())
}
