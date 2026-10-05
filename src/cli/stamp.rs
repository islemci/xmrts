//! `xmrts stamp`. Hashes files, builds one Monero tx, writes proofs.
//! One run means one tx. `--offline` writes pending proofs with no wallet.

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
    /// Skip wallet: write pending proofs only.
    #[arg(long)]
    pub offline: bool,
    /// Build tx but do not send it.
    #[arg(long)]
    pub do_not_relay: bool,
    /// Do not wait for confirmation. Write pending proofs right away.
    #[arg(long)]
    pub no_wait: bool,
    /// Skip the confirmation prompt.
    #[arg(long)]
    pub yes: bool,
    /// Send to this address (default: your wallet address).
    #[arg(long)]
    pub address: Option<String>,
    /// Send amount in atomic units (default 10000). This is a self-send
    /// to carry the commitment: the amount returns to your wallet and only
    /// the fee is lost.
    #[arg(long, default_value_t = 10_000)]
    pub amount: u64,
    /// Folder for .xmrts proofs (default: next to each file).
    #[arg(long)]
    pub out_dir: Option<PathBuf>,
    /// Daemon address for chain checks, like http://127.0.0.1:18081
    #[arg(long)]
    pub daemon: Option<String>,
}

pub async fn run(args: &StampArgs, verbose: bool, stagenet: bool) -> Result<()> {
    let _ = connection::ensure_dirs();
    if args.files.is_empty() {
        anyhow::bail!("No files given.");
    }
    let mut seen: HashMap<String, usize> = HashMap::new();
    for f in &args.files {
        if !f.is_file() {
            anyhow::bail!("Cannot read file: {}", f.display());
        }
        let canon = canonical_key(f)?;
        if seen.insert(canon.clone(), 1).is_some() {
            anyhow::bail!("Same file twice: {}. List each file once.", f.display());
        }
    }

    let mut hashes: Vec<([u8; 32], PathBuf)> = Vec::new();
    for f in &args.files {
        let total = std::fs::metadata(f).map(|m| m.len()).unwrap_or(0);
        let bar = super::ui::bytes_bar(&format!("Hashing {}", f.display()), total.max(1));
        let h = hash::hash_file_with_progress(f, |n| bar.inc(n))
            .with_context(|| format!("Hashing {}", f.display()))?;
        super::ui::done(&bar, &format!("Hashed {}", f.display()));
        hashes.push((h, f.clone()));
    }

    hashes.sort_by_key(|(h, _)| *h);
    // M6: dedupe identical content to one leaf. Files with the same bytes
    // share a leaf; each still gets its own proof file.
    let mut unique_hashes: Vec<[u8; 32]> = Vec::new();
    for (h, _) in &hashes {
        if !unique_hashes.contains(h) {
            unique_hashes.push(*h);
        }
    }
    if unique_hashes.len() != hashes.len() {
        super::ui::note(&format!(
            "{} file(s) share content; deduped to {} leaf/leaves.",
            hashes.len(),
            unique_hashes.len()
        ));
    }
    let (sorted, tree) = MerkleTree::build_from_unsorted(unique_hashes.clone())
        .map_err(|e| anyhow::anyhow!("Tree failed: {e}"))?;
    let root = tree.root();
    let commitment = crate::protocol::merkle::commitment_for_version(
        &root,
        tree.tree_size(),
        crate::protocol::merkle::MERKLE_V2,
    );
    super::ui::header("◆", "Stamp");
    super::ui::ok("Tree built.");
    super::ui::field("Files", &format!("{}", hashes.len()));
    super::ui::field("Root", &hex::encode(root));

    let extra_hex =
        commitment::build_tx_extra_hex_for(&commitment, crate::protocol::merkle::MERKLE_V2);
    if verbose {
        println!("Commitment: {extra_hex}");
    }

    let mut cfg: WalletConfig = connection::load_config();
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
        super::ui::note("Offline run. Proofs are pending. No block yet.");
        return Ok(());
    }

    let mut client = cfg.client();
    if cfg.wallet_dir.is_none() {
        let found = crate::wallet::discover::discover();
        if found.len() == 1 {
            let d = found[0].dir.display().to_string();
            cfg.wallet_dir = Some(d.clone());
            let _ = connection::save_config(&cfg);
            super::ui::ok(&format!("Found wallets in {d}. Using it."));
            client = cfg.client();
        }
    }
    match crate::wallet::process::status(&cfg, &client).await {
        crate::wallet::process::SidecarStatus::Stopped => {
            super::ui::info("Helper is stopped. Starting it...");
            crate::wallet::process::start(&mut cfg)
                .await
                .map_err(|e| anyhow::anyhow!("Helper did not start: {e}"))?;
            client = cfg.client();
            super::ui::ok("Helper is up.");
        }
        crate::wallet::process::SidecarStatus::Unhealthy(pid) => {
            anyhow::bail!("Helper (pid {pid}) stays quiet. Check `xmrts wallet status`");
        }
        crate::wallet::process::SidecarStatus::NotManaged(reason)
            if cfg.wallet_dir.is_none() && !crate::wallet::discover::discover().is_empty() =>
        {
            super::ui::note(&format!("Helper is off. {reason}"));
            super::ui::hint("Run `xmrts init` and pick a wallet folder.");
        }
        _ => {}
    }
    let version = client.get_version().await.with_context(|| {
        format!(
            "Wallet is quiet.\n\nEndpoint:\n{}\n\nTry:\n\n    xmrts doctor",
            cfg.endpoint
        )
    })?;
    if verbose {
        super::ui::field("Wallet RPC", &format!("v{}.{}", version.0, version.1));
    }
    let (address, address_checked) = match &args.address {
        Some(a) => (a.clone(), false),
        None => client
            .get_address()
            .await
            .context("No open wallet. Open one with `xmrts wallet open` first")
            .map(|a| (a, true))?,
    };
    if !address_checked && !client.owns_address(&address).await.unwrap_or(false) {
        anyhow::bail!(
            "That address is outside this wallet:\n{address}\nSkip --address to use your own."
        );
    }
    let (balance, _unlocked) = client.get_balance().await.unwrap_or((0, 0));
    super::ui::field("Network", &network_name);
    super::ui::field("To (self)", &super::ui::short_address(&address));
    super::ui::field("Balance", &transaction::format_xmr(balance));

    let fee_bar = super::ui::spinner("Checking fee...");
    let previewed =
        transaction::preview_timestamp(&client, &address, args.amount, &extra_hex).await;
    super::ui::abandon(&fee_bar);
    let (preview, tx_hex) = previewed.map_err(|e| anyhow::anyhow!("Wallet said no: {e}"))?;
    super::ui::field(
        "Fee",
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
        merkle_ver: crate::protocol::merkle::MERKLE_V2,
    })?;

    if !args.yes && !super::ui::confirm("Send now? [y/N] ")? {
        let _ = std::fs::remove_file(&pending_path);
        super::ui::note("Stopped. No funds spent. Nothing published.");
        return Ok(());
    }

    let tx_hash = if args.do_not_relay {
        super::ui::note("Kept local (--do-not-relay). Nothing sent.");
        preview.tx_hash
    } else {
        let h = transaction::relay(&client, &tx_hex)
            .await
            .map_err(|e| anyhow::anyhow!("Send failed: {e}"))?;
        if let Err(e) = pending::update_txid(&pending_path, &h) {
            super::ui::warn(&format!("Relayed but pending record update failed: {e}"));
        }
        h
    };
    println!();
    super::ui::field("Transaction", &tx_hash);
    super::ui::field(
        "Fee paid",
        &super::ui::with_fiat(
            &transaction::format_xmr(preview.fee),
            super::ui::fiat_for(preview.fee, &cfg).await,
        ),
    );
    let txid_bytes: [u8; 32] = hex::decode(&tx_hash)
        .context("Wallet gave a bad tx hash")?
        .try_into()
        .map_err(|_| anyhow::anyhow!("Wallet gave a short tx hash"))?;

    let (height, block_hash) = if args.no_wait || args.do_not_relay {
        super::ui::note("Skipping wait. Proofs stay pending.");
        (0u64, [0u8; 32])
    } else {
        super::ui::note("Blocks average ~2 min; waiting up to ~10 min. Pending is normal.");
        super::ui::hint("Safe to Ctrl-C any time: `xmrts finalize` finishes later.");
        let bar = super::ui::spinner("Waiting for block...");
        let found = wait_for_confirmation(&client, &tx_hash, &bar).await;
        super::ui::abandon(&bar);
        match found {
            Some((h, bh)) => {
                super::ui::ok(&format!("Locked in block {h}."));
                (h, bh)
            }
            None => {
                super::ui::note("No block yet (normal for slow blocks). Proofs stay pending.");
                super::ui::hint("Run `xmrts finalize` once it confirms.");
                (0u64, [0u8; 32])
            }
        }
    };

    // H1+H2+H3: the wallet's word is not enough. Re-check the mark on the
    // daemon, fetch the REAL block hash (never zeros), require exact height
    // match and MIN_CONFIRMATIONS depth. Anything short stays pending.
    let (height, block_hash) = if height > 0 {
        // M5: never go pending just because no daemon was configured. Fall
        // back to the default local daemon for this read-only recheck.
        let (daemon, is_default) = match args.daemon.clone().or(cfg.daemon_endpoint.clone()) {
            Some(d) => (d, false),
            None => {
                super::ui::note(
                    "No daemon configured. Trying the default local node http://127.0.0.1:18081.",
                );
                ("http://127.0.0.1:18081".to_string(), true)
            }
        };
        {
            let d = daemon;
            let bar = super::ui::spinner("Checking chain...");
            let chain_height = crate::wallet::daemon::confirm_commitment_for_version(
                &d,
                &tx_hash,
                &commitment,
                Some(crate::protocol::merkle::MERKLE_V2),
            )
            .await;
            super::ui::abandon(&bar);
            match chain_height {
                Ok(chain_height) => {
                    if chain_height != height {
                        super::ui::warn(&format!(
                            "Wallet says block {height} but chain says {chain_height}. Proofs stay pending."
                        ));
                        (0u64, [0u8; 32])
                    } else {
                        match crate::wallet::daemon::block_hash(&d, chain_height).await {
                            Ok(bh) => {
                                // H3: depth gate.
                                let depth = match crate::wallet::daemon::get_info(&d).await {
                                    Ok((_, tip)) => {
                                        tip.saturating_sub(chain_height).saturating_add(1)
                                    }
                                    Err(_) => 1,
                                };
                                if depth < crate::wallet::daemon::MIN_CONFIRMATIONS {
                                    super::ui::note(&format!(
                                        "Only {depth} confirmation(s); want {}+. Proofs stay pending until deep enough.",
                                        crate::wallet::daemon::MIN_CONFIRMATIONS
                                    ));
                                    super::ui::hint("Run `xmrts finalize` once it buries deeper.");
                                    (0u64, [0u8; 32])
                                } else {
                                    super::ui::ok("Chain holds your mark.");
                                    (chain_height, bh)
                                }
                            }
                            Err(e) => {
                                super::ui::warn(&format!(
                                    "Block hash missed ({e}). Proofs stay pending."
                                ));
                                super::ui::hint("Run `xmrts finalize` once the daemon answers.");
                                (0u64, [0u8; 32])
                            }
                        }
                    }
                }
                Err(e) => {
                    if is_default {
                        super::ui::warn(&format!(
                            "Default local daemon did not confirm ({e}). Proofs stay pending."
                        ));
                    } else {
                        super::ui::warn(&format!("Tx is in but mark is missing: {e}"));
                    }
                    super::ui::hint(
                        "Set one with `xmrts connect --daemon <url>` or run `xmrts finalize` later.",
                    );
                    (0u64, [0u8; 32])
                }
            }
        }
    } else {
        (0u64, block_hash)
    };

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
    if height > 0 {
        let _ = std::fs::remove_file(&pending_path);
        super::ui::ok(&format!("Done. Files prove no later than block {height}."));
    }
    Ok(())
}

fn canonical_key(p: &Path) -> Result<String> {
    match p.canonicalize() {
        Ok(c) => Ok(c.to_string_lossy().into_owned()),
        Err(_) => Ok(p.to_string_lossy().into_owned()),
    }
}

/// Poll the wallet for confirmation (M4). Monero averages a block every
/// ~2 minutes with Poisson arrivals, so ~37% of stamps need more than 2
/// minutes. We wait ~10 minutes (120 x 5s) with a visible countdown; the
/// pending record is already on disk, so Ctrl-C is safe at any point and
/// `xmrts finalize` finishes the job later.
async fn wait_for_confirmation(
    client: &crate::wallet::rpc::WalletRpc,
    txid: &str,
    progress: &indicatif::ProgressBar,
) -> Option<(u64, [u8; 32])> {
    const ROUNDS: u64 = 120;
    const STEP_SECS: u64 = 5;
    for i in 0..ROUNDS {
        tokio::time::sleep(std::time::Duration::from_secs(STEP_SECS)).await;
        let elapsed = (i + 1) * STEP_SECS;
        let remain = (ROUNDS - i - 1) * STEP_SECS;
        progress.set_message(format!(
            "Waiting for block... {elapsed}s in, ~{remain}s left (blocks average ~2 min; safe to Ctrl-C, then `xmrts finalize`)"
        ));
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
    // M6: one leaf per distinct hash; files with identical content share
    // the same leaf_index.
    let mut index_of: HashMap<[u8; 32], u64> = HashMap::new();
    for (i, h) in sorted.iter().enumerate() {
        index_of.insert(*h, i as u64);
    }
    for (h, path) in sorted_inputs {
        let leaf_index = *index_of
            .get(h)
            .ok_or_else(|| anyhow::anyhow!("Tree failed: file hash missing from deduped tree"))?;
        let _ = sorted;
        let siblings = tree
            .proof_for(leaf_index)
            .map_err(|e| anyhow::anyhow!("Tree failed: {e}"))?;
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
        .map_err(|e| anyhow::anyhow!("Proof failed: {e}"))?;
        let out = proof_path_for(path, out_dir)?;
        std::fs::write(&out, proof.to_bytes())
            .with_context(|| format!("Writing {}", out.display()))?;
        super::ui::ok(&format!("Proof: {}", out.display()));
    }
    Ok(())
}

pub(crate) fn proof_path_for(input: &Path, out_dir: Option<&Path>) -> Result<PathBuf> {
    let file_name = input
        .file_name()
        .map(|s| format!("{}.xmrts", s.to_string_lossy()))
        .ok_or_else(|| anyhow::anyhow!("Bad file name: {}", input.display()))?;
    match out_dir {
        Some(d) => {
            std::fs::create_dir_all(d)?;
            Ok(d.join(file_name))
        }
        None => Ok(PathBuf::from(format!("{}.xmrts", input.display()))),
    }
}
