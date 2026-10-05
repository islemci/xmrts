//! `xmrts stamp` — hash, Merkle-tree, commitment, wallet tx, proofs.
//!
//! One invocation = one Monero transaction (subject to weight limits).
//! `--offline` creates pending proofs without touching a wallet (Phase 2
//! dev mode); otherwise the wallet flow runs with explicit confirmation.

use anyhow::{Context, Result};
use clap::Args;
use std::collections::HashMap;
use std::path::{Path, PathBuf};

use super::pending::{self, PendingOp};

use crate::protocol::commitment;
use crate::protocol::hash;
use crate::protocol::merkle::MerkleTree;
use crate::protocol::proof::{Network, Proof};
use crate::wallet::connection::{self, WalletConfig};
use crate::wallet::transaction;

#[derive(Debug, Args)]
pub struct StampArgs {
    /// Files to timestamp.
    #[arg(required = true)]
    pub files: Vec<PathBuf>,
    /// Skip wallet: write pending (.xmrts, unanchored) proofs only.
    #[arg(long)]
    pub offline: bool,
    /// Do not broadcast (create tx but don't relay).
    #[arg(long)]
    pub do_not_relay: bool,
    /// Do not wait for confirmation; write pending proofs immediately.
    #[arg(long)]
    pub no_wait: bool,
    /// Skip the interactive confirmation prompt.
    #[arg(long)]
    pub yes: bool,
    /// Self-send address override (default: wallet primary address).
    #[arg(long)]
    pub address: Option<String>,
    /// Self-send amount in atomic units (default 10000).
    #[arg(long, default_value_t = 10_000)]
    pub amount: u64,
    /// Output directory for .xmrts proofs (default: alongside each file).
    #[arg(long)]
    pub out_dir: Option<PathBuf>,
    /// Daemon endpoint override for the on-chain commitment check,
    /// e.g. http://127.0.0.1:18081 (else the saved config value is used).
    #[arg(long)]
    pub daemon: Option<String>,
}

pub async fn run(args: &StampArgs, verbose: bool, stagenet: bool) -> Result<()> {
    // Step 1 — validate.
    if args.files.is_empty() {
        anyhow::bail!("no files given");
    }
    let mut seen: HashMap<String, usize> = HashMap::new();
    for f in &args.files {
        if !f.is_file() {
            anyhow::bail!("not a readable file: {}", f.display());
        }
        let canon = canonical_key(f)?;
        if seen.insert(canon, 1).is_some() {
            // Duplicates occupy distinct leaves (deterministic under the
            // same sorted order); keep validating the remaining inputs.
            eprintln!("Note: duplicate input — it gets its own leaf, the batch root covers it once per occurrence.");
            continue;
        }
    }

    // Step 2 — hash (streaming, with progress for large files).
    let mut hashes: Vec<([u8; 32], PathBuf)> = Vec::new();
    for f in &args.files {
        let total = std::fs::metadata(f).map(|m| m.len()).unwrap_or(0);
        let bar = super::ui::bytes_bar(&format!("Hashing {}", f.display()), total.max(1));
        let h = hash::hash_file_with_progress(f, |n| bar.inc(n))
            .with_context(|| format!("hashing {}", f.display()))?;
        super::ui::done(&bar, &format!("Hashed {}", f.display()));
        hashes.push((h, f.clone()));
    }

    // Step 3 — deterministic order: sort by file hash.
    hashes.sort_by_key(|(h, _)| *h);
    let file_hashes: Vec<[u8; 32]> = hashes.iter().map(|(h, _)| *h).collect();
    let (sorted, tree) = MerkleTree::build_from_unsorted(file_hashes.clone())
        .map_err(|e| anyhow::anyhow!("merkle: {e}"))?;
    let root = tree.root();
    super::ui::ok("Merkle tree built");
    println!();
    super::ui::field("Files", &format!("{}", hashes.len()));
    super::ui::field("Root", &hex::encode(root));

    // Step 4 — commitment.
    let extra_hex = commitment::build_tx_extra_hex(&root);
    if verbose {
        println!("Commitment (tx_extra): {extra_hex}");
    }

    let mut cfg: WalletConfig = connection::load_config();
    // Default is mainnet; stagenet only when explicitly requested via
    // `--stagenet` on this invocation. The flag never persists — but it
    // must reach the sidecar too, or the wallet would run on the wrong net.
    if stagenet {
        cfg.network = "stagenet".to_string();
    }
    let network = Network::from_str(&cfg.network).unwrap_or(Network::Mainnet);
    let network_name = network.as_str().to_string();

    if args.offline {
        write_proofs(
            &hashes,
            &sorted,
            &tree,
            &network,
            &[0u8; 32],
            0,
            &[0u8; 32],
            args.out_dir.as_deref(),
        )?;
        println!();
        println!("Offline mode: wrote pending proofs (unanchored, block 0).");
        return Ok(());
    }

    // Step 5 — wallet tx.
    let mut client = cfg.client();
    // Auto-start a managed sidecar so the preview below has something to
    // talk to. Unmanaged configs skip silently (legacy error path).
    // start() may provision credentials, so rebuild the client after it.
    match crate::wallet::process::status(&cfg, &client).await {
        crate::wallet::process::SidecarStatus::Stopped => {
            println!("Starting managed monero-wallet-rpc…");
            crate::wallet::process::start(&mut cfg)
                .await
                .map_err(|e| anyhow::anyhow!("managed sidecar unavailable: {e}"))?;
            client = cfg.client();
        }
        crate::wallet::process::SidecarStatus::Unhealthy(pid) => {
            anyhow::bail!(
                "managed sidecar (pid {pid}) is not answering RPC; inspect it with `xmrts wallet status`"
            );
        }
        _ => {}
    }
    let version = client.get_version().await.with_context(|| {
        format!(
            "could not connect to monero-wallet-rpc.\n\nEndpoint:\n{}\n\nRun:\n\n    xmrts doctor",
            cfg.endpoint
        )
    })?;
    if verbose {
        println!("wallet RPC v{}.{}", version.0, version.1);
    }
    let (address, address_checked) = match &args.address {
        Some(a) => (a.clone(), false),
        None => client
            .get_address()
            .await
            .context("wallet has no open wallet; open one in monero-wallet-rpc first")
            .map(|a| (a, true))?,
    };
    // Safety: never timestamp to an address outside this wallet. The
    // default (primary address, just fetched from the wallet) is trusted;
    // a manual --address override is verified against the wallet's own
    // address list before anything is built.
    if !address_checked && !client.owns_address(&address).await.unwrap_or(false) {
        anyhow::bail!(
            "refusing to timestamp to an address outside this wallet:\n{address}\nOmit --address to use the wallet's own primary address."
        );
    }
    let (balance, _unlocked) = client.get_balance().await.unwrap_or((0, 0));
    super::ui::field("Network", &network_name);
    super::ui::field("Destination (self)", &super::ui::short_address(&address));
    super::ui::field("Balance", &transaction::format_xmr(balance));

    // Step 5b — preview (no relay) so the wallet quotes the fee up front.
    // The pending record is written only after the preview succeeds: a
    // failed preview leaves no wallet-side state worth recovering.
    let fee_bar = super::ui::spinner("Estimating fee…");
    let previewed =
        transaction::preview_timestamp(&client, &address, args.amount, &extra_hex).await;
    super::ui::abandon(&fee_bar);
    let (preview, tx_hex) =
        previewed.map_err(|e| anyhow::anyhow!("transaction preview failed: {e}"))?;
    super::ui::field(
        "Estimated fee",
        &super::ui::with_fiat(
            &transaction::format_xmr(preview.fee),
            super::ui::fiat_for(preview.fee, &cfg).await,
        ),
    );
    let pending_path = pending::save(&PendingOp {
        files: args
            .files
            .iter()
            .map(|f| f.to_string_lossy().into_owned())
            .collect(),
        file_hashes: vec![],
        sorted_hashes: sorted.iter().map(hex::encode).collect(),
        root: hex::encode(root),
        extra_hex: extra_hex.clone(),
        txid: preview.tx_hash.clone(),
        tx_hex: tx_hex.clone(),
        out_dir: args
            .out_dir
            .as_ref()
            .map(|d| d.to_string_lossy().into_owned()),
        network: network_name.clone(),
    })?;

    // Step 6 — confirm (single keypress, no Enter needed).
    if !args.yes && !super::ui::confirm("Broadcast transaction? [y/N] ")? {
        let _ = std::fs::remove_file(&pending_path);
        println!("Aborted; no funds spent. Commitment was NOT published.");
        return Ok(());
    }

    // Step 7 — relay (unless --do-not-relay).
    let tx_hash = if args.do_not_relay {
        println!("Not relaying (--do-not-relay). Nothing was broadcast.");
        preview.tx_hash
    } else {
        let h = transaction::relay(&client, &tx_hex)
            .await
            .map_err(|e| anyhow::anyhow!("transaction relay failed: {e}"))?;
        pending::update_txid(&pending_path, &h);
        h
    };
    println!();
    super::ui::field("Transaction", &tx_hash);
    super::ui::field(
        "Fee",
        &super::ui::with_fiat(
            &transaction::format_xmr(preview.fee),
            super::ui::fiat_for(preview.fee, &cfg).await,
        ),
    );
    let txid_bytes: [u8; 32] = hex::decode(&tx_hash)
        .context("wallet returned non-hex tx hash")?
        .try_into()
        .map_err(|_| anyhow::anyhow!("wallet returned bad-length tx hash"))?;

    // Step 8 — confirmation (poll wallet; best-effort).
    let (height, block_hash) = if args.no_wait || args.do_not_relay {
        super::ui::note("Skipping confirmation wait (--no-wait). Proofs will be pending.");
        (0u64, [0u8; 32])
    } else {
        let bar = super::ui::spinner("Waiting for confirmation…");
        let found = wait_for_confirmation(&client, &tx_hash).await;
        super::ui::abandon(&bar);
        match found {
            Some((h, bh)) => {
                super::ui::ok(&format!("Confirmed in block {h}"));
                (h, bh)
            }
            None => {
                super::ui::note("Not yet confirmed; writing pending proofs.");
                println!("Once it confirms, run `xmrts finalize` to write anchored proofs.");
                (0u64, [0u8; 32])
            }
        }
    };

    // Step 8b — commitment byte check. Anchored proofs are written ONLY
    // after the commitment is confirmed present in the transaction's
    // tx_extra (stock wallet RPCs are known to silently drop unknown
    // fields such as our `extra`). Without a daemon to check against,
    // proofs stay pending rather than asserting an unverified anchor.
    let height = if height > 0 {
        let daemon = args.daemon.clone().or(cfg.daemon_endpoint.clone());
        match daemon {
            Some(d) => {
                let bar = super::ui::spinner("Checking commitment on chain…");
                let checked = crate::wallet::daemon::confirm_commitment(&d, &tx_hash, &root).await;
                super::ui::abandon(&bar);
                match checked {
                    Ok(chain_height) => {
                        super::ui::ok("Commitment confirmed on chain");
                        chain_height.max(height)
                    }
                    Err(e) => {
                        super::ui::warn(&format!(
                            "transaction confirmed but commitment NOT found on chain: {e}"
                        ));
                        println!("Proofs left pending; no anchored proof was written.");
                        0u64
                    }
                }
            }
            None => {
                super::ui::warn(
                    "no daemon endpoint configured, so the on-chain commitment bytes were not re-checked.",
                );
                println!(
                    "Set one with `xmrts connect --daemon <url>`; proofs left pending meanwhile."
                );
                0u64
            }
        }
    } else {
        0u64
    };

    // Step 9 — proofs (anchored only when height survived the byte check;
    // write_proofs treats height 0 as pending).
    write_proofs(
        &hashes,
        &sorted,
        &tree,
        &network,
        &txid_bytes,
        height,
        &block_hash,
        args.out_dir.as_deref(),
    )?;
    // Finalize pending state (only reached with anchored proofs; pending
    // proofs keep their file for `xmrts finalize`).
    if height > 0 {
        let _ = std::fs::remove_file(&pending_path);
    }
    Ok(())
}

fn canonical_key(p: &Path) -> Result<String> {
    match p.canonicalize() {
        Ok(c) => Ok(c.to_string_lossy().into_owned()),
        Err(_) => Ok(p.to_string_lossy().into_owned()),
    }
}

async fn wait_for_confirmation(
    client: &crate::wallet::rpc::WalletRpc,
    txid: &str,
) -> Option<(u64, [u8; 32])> {
    // Poll get_transfer_by_txid up to ~2 minutes for a height > 0.
    for _ in 0..24 {
        tokio::time::sleep(std::time::Duration::from_secs(5)).await;
        if let Ok(v) = crate::wallet::rpc::get_transfer_by_txid(client, txid).await {
            let h = v
                .get("transfer")
                .and_then(|t| t.get("height"))
                .or_else(|| v.get("height"))
                .and_then(|h| h.as_u64())
                .unwrap_or(0);
            if h > 0 {
                return Some((h, [0u8; 32]));
            }
        }
    }
    None
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn write_proofs(
    sorted_inputs: &[([u8; 32], PathBuf)],
    sorted: &[[u8; 32]],
    tree: &MerkleTree,
    network: &Network,
    txid: &[u8; 32],
    height: u64,
    block_hash: &[u8; 32],
    out_dir: Option<&Path>,
) -> Result<()> {
    // Map hash -> queue of leaf indexes (handles duplicate file hashes).
    let mut index_of: HashMap<[u8; 32], Vec<u64>> = HashMap::new();
    for (i, h) in sorted.iter().enumerate() {
        index_of.entry(*h).or_default().push(i as u64);
    }
    let mut used: HashMap<[u8; 32], usize> = HashMap::new();
    // NOTE: sorted_inputs is already sorted by hash, so leaves align.
    for (h, path) in sorted_inputs {
        let n = used.entry(*h).or_insert(0);
        let leaf_index = index_of[h][*n];
        *n += 1;
        let _ = sorted; // (kept for signature clarity)
        let siblings = tree
            .proof_for(leaf_index)
            .map_err(|e| anyhow::anyhow!("merkle: {e}"))?;
        let proof = if height == 0 {
            Proof::new_pending(
                *network,
                *h,
                leaf_index,
                tree.tree_size(),
                tree.root(),
                siblings,
            )
        } else {
            Proof::new(
                *network,
                *h,
                leaf_index,
                tree.tree_size(),
                tree.root(),
                *txid,
                height,
                *block_hash,
                siblings,
            )
        }
        .map_err(|e| anyhow::anyhow!("proof: {e}"))?;
        let out = proof_path_for(path, out_dir)?;
        std::fs::write(&out, proof.to_bytes())
            .with_context(|| format!("writing {}", out.display()))?;
        println!("Proof: {}", out.display());
    }
    Ok(())
}

pub(crate) fn proof_path_for(input: &Path, out_dir: Option<&Path>) -> Result<PathBuf> {
    let file_name = input
        .file_name()
        .map(|s| format!("{}.xmrts", s.to_string_lossy()))
        .ok_or_else(|| anyhow::anyhow!("bad filename: {}", input.display()))?;
    match out_dir {
        Some(d) => {
            std::fs::create_dir_all(d)?;
            Ok(d.join(file_name))
        }
        None => Ok(PathBuf::from(format!("{}.xmrts", input.display()))),
    }
}
