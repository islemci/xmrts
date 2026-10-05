//! `xmrts verify`. Checks a file against its proof.
//! Crypto first. Chain second. No wallet needed.

use anyhow::{Context, Result};
use clap::Args;
use std::path::PathBuf;

use crate::protocol::hash;
use crate::protocol::proof::Proof;
use crate::wallet::connection;

#[derive(Debug, Args)]
pub struct VerifyArgs {
    /// File to check.
    pub file: PathBuf,
    /// Proof file (.xmrts).
    pub proof: PathBuf,
    /// Crypto only. Skip chain lookup.
    #[arg(long)]
    pub offline: bool,
    /// Daemon address for tx lookup.
    #[arg(long)]
    pub daemon: Option<String>,
}

pub async fn run(args: &VerifyArgs, verbose: bool, stagenet: bool) -> Result<()> {
    let ok = true;
    let raw =
        std::fs::read(&args.proof).with_context(|| format!("Reading {}", args.proof.display()))?;
    let proof = match Proof::from_bytes(&raw) {
        Ok(p) => {
            super::ui::header("◆", "Verify");
            super::ui::ok("Proof file looks good.");
            p
        }
        Err(e) => {
            super::ui::fail("Check failed.");
            println!();
            println!("Why:\nProof file is broken: {e}");
            fail_exit();
        }
    };
    if verbose {
        println!();
        print!("{}", proof.describe());
        println!();
    }

    let file_hash =
        hash::hash_file(&args.file).with_context(|| format!("Reading {}", args.file.display()))?;
    if file_hash == proof.file_hash {
        super::ui::ok("File hash matches.");
    } else {
        super::ui::fail("Check failed.");
        println!();
        println!("Why:\nFile differs from what the proof holds.");
        println!("got:  {}", hex::encode(file_hash));
        println!("proof: {}", hex::encode(proof.file_hash));
        fail_exit();
    }

    match proof.verify_merkle_path() {
        Ok(()) => super::ui::ok("Tree path is valid."),
        Err(e) => {
            super::ui::fail("Check failed.");
            println!();
            println!("Why:\nTree path misses the root: {e}");
            fail_exit();
        }
    }

    if proof.is_pending() {
        if args.offline {
            super::ui::note("Proof is pending. Crypto passed. No block yet.");
            println!();
            println!("Not anchored yet. Run `xmrts stamp` without --offline.");
            return Ok(());
        }
        super::ui::note("Proof is pending. No block or tx saved.");
        println!();
        println!("Not verified. Run `xmrts stamp` without --offline.");
        fail_exit();
    }

    if args.offline {
        super::ui::note("Skipped chain lookup (--offline).");
        println!();
        println!("Crypto passed. Chain not checked.");
        return Ok(());
    }

    let bar = super::ui::spinner("Checking chain...");
    let checked = blockchain_check(&proof, args.daemon.as_deref(), stagenet).await;
    super::ui::abandon(&bar);
    match checked {
        Ok((height, txid_hex)) => {
            super::ui::ok("Mark found on chain.");
            super::ui::ok("Tx is confirmed.");
            super::ui::ok("Time is proven.");
            println!();
            super::ui::field("Block", &height.to_string());
            super::ui::field("Transaction", &txid_hex);
            println!();
            println!("This file lived no later than block {height}.");
        }
        Err(e) => {
            let _ = ok;
            super::ui::fail("Check failed.");
            println!();
            println!("Why:\n{e}");
            fail_exit();
        }
    }
    Ok(())
}

fn fail_exit() -> ! {
    use std::io::Write;
    let _ = std::io::stdout().flush();
    std::process::exit(1);
}

async fn blockchain_check(
    proof: &Proof,
    daemon_override: Option<&str>,
    stagenet: bool,
) -> Result<(u64, String)> {
    let cfg = connection::load_config();
    let effective_net = if stagenet {
        "stagenet".to_string()
    } else {
        cfg.network.to_ascii_lowercase()
    };
    if effective_net != proof.network.as_str() {
        anyhow::bail!(
            "Network split: proof is {} but you ask {effective_net}. One network per check.",
            proof.network.as_str()
        );
    }

    let txid_hex = hex::encode(proof.txid);
    let daemon = daemon_override
        .map(String::from)
        .or(cfg.daemon_endpoint.clone());
    let Some(daemon) = daemon else {
        anyhow::bail!(
            "No daemon set so chain bytes stay unchecked.\nSet one with `xmrts connect --daemon http://127.0.0.1:18081`. Any local or remote node fits. Or pass --offline for crypto only."
        );
    };
    let height = crate::wallet::daemon::confirm_commitment(&daemon, &txid_hex, &proof.root)
        .await
        .map_err(|e| match e {
            crate::wallet::daemon::DaemonError::CommitmentAbsent { .. } => anyhow::anyhow!(
                "Tx {txid_hex} holds no mark for this file.\nIt lives but it does not anchor you. The wallet may have dropped the mark."
            ),
            other => anyhow::anyhow!("{other}"),
        })?;
    let client = cfg.client();
    if let Ok(v) = crate::wallet::rpc::get_transfer_by_txid(&client, &txid_hex).await {
        let wh = v
            .get("transfer")
            .and_then(|t| t.get("height"))
            .or_else(|| v.get("height"))
            .and_then(|h| h.as_u64())
            .unwrap_or(0);
        if wh > 0 && proof.block_height != 0 && wh != proof.block_height {
            anyhow::bail!(
                "Wallet says block {wh} but proof says {}. Stopping on split anchors.",
                proof.block_height
            );
        }
    }
    Ok((height.max(proof.block_height), txid_hex))
}
