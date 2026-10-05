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
        Ok(anchor) => {
            super::ui::ok("Mark found on chain.");
            super::ui::ok("Tx is confirmed.");
            if anchor.confirmations < crate::wallet::daemon::MIN_CONFIRMATIONS {
                super::ui::warn(&format!(
                    "Only {} confirmation(s); want {}+. Reorg risk: wait before relying on this.",
                    anchor.confirmations,
                    crate::wallet::daemon::MIN_CONFIRMATIONS
                ));
            }
            if proof.network != crate::protocol::proof::Network::Mainnet {
                super::ui::warn(
                    "NON-MAINNET proof: testnet/stagenet marks have no security value.",
                );
            }
            super::ui::ok("Time is proven.");
            println!();
            super::ui::field("Block", &anchor.height.to_string());
            super::ui::field("Transaction", &hex::encode(proof.txid));
            super::ui::field("Confirmations", &anchor.confirmations.to_string());
            println!();
            println!("This file lived no later than block {}.", anchor.height);
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
) -> Result<crate::wallet::daemon::AnchorCheck> {
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
    // Anchored proofs must carry the real block hash (H1). Zeros mean the
    // proof was written before the hash was fetched: fail, do not verify.
    if proof.block_hash == [0u8; 32] {
        anyhow::bail!(
            "Proof has no block hash (all zeros). It was never properly anchored.\nRun `xmrts finalize` to fetch the real hash."
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
    // Full anchor check: commitment + exact height + block-hash match +
    // daemon nettype match (H1+M1). No wallet involved (M2): verification
    // depends only on the proof file, the original file, and daemon(s).
    // M6: the chain holds the size-bound commitment for V2 proofs.
    crate::wallet::daemon::verify_anchor_for_version(
        &daemon,
        &txid_hex,
        &proof.expected_commitment(),
        Some(proof.merkle_ver),
        proof.block_height,
        &proof.block_hash,
        proof.network.as_str(),
    )
    .await
    .map_err(|e| match e {
        crate::wallet::daemon::DaemonError::CommitmentAbsent { .. } => anyhow::anyhow!(
            "Tx {txid_hex} holds no mark for this file.\nIt lives but it does not anchor you. The wallet may have dropped the mark."
        ),
        other => anyhow::anyhow!("{other}"),
    })
}
