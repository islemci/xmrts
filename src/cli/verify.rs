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
    /// Machine-readable JSON on stdout (human lines suppressed).
    #[arg(long)]
    pub json: bool,
}

pub async fn run(args: &VerifyArgs, verbose: bool, stagenet: bool) -> Result<()> {
    let ok = true;
    if args.json {
        super::ui::set_quiet(true);
    }
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
            if !args.json {
                println!();
                println!("Why:\nProof file is broken: {e}");
            }
            fail_exit_json(args.json, &format!("proof file is broken: {e}"));
        }
    };
    if verbose && !args.json {
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
        if !args.json {
            println!();
            println!("Why:\nFile differs from what the proof holds.");
            println!("got:  {}", hex::encode(file_hash));
            println!("proof: {}", hex::encode(proof.file_hash));
        }
        fail_exit_json(args.json, "file differs from what the proof holds");
    }

    match proof.verify_merkle_path() {
        Ok(()) => super::ui::ok("Tree path is valid."),
        Err(e) => {
            super::ui::fail("Check failed.");
            if !args.json {
                println!();
                println!("Why:\nTree path misses the root: {e}");
            }
            fail_exit_json(args.json, &format!("tree path misses the root: {e}"));
        }
    }

    if proof.is_pending() {
        if args.offline {
            super::ui::note("Proof is pending. Crypto passed. No block yet.");
            if !args.json {
                println!();
                println!("Not anchored yet. Run `xmrts stamp` without --offline.");
            }
            if args.json {
                print_json(&serde_json::json!({
                    "ok": true, "anchored": false,
                    "file_hash": hex::encode(file_hash),
                    "root": hex::encode(proof.root),
                    "network": proof.network.as_str(),
                }));
            }
            return Ok(());
        }
        super::ui::note("Proof is pending. No block or tx saved.");
        if !args.json {
            println!();
            println!("Not verified. Run `xmrts stamp` without --offline.");
        }
        fail_exit_json(args.json, "proof is pending: no block yet");
    }

    if args.offline {
        super::ui::note("Skipped chain lookup (--offline).");
        if !args.json {
            println!();
            println!("Crypto passed. Chain not checked.");
        }
        if args.json {
            print_json(&serde_json::json!({
                "ok": true, "anchored": false, "chain_checked": false,
                "file_hash": hex::encode(file_hash),
                "root": hex::encode(proof.root),
                "txid": hex::encode(proof.txid),
                "block_height": proof.block_height,
                "network": proof.network.as_str(),
            }));
        }
        return Ok(());
    }

    let bar = super::ui::spinner("Checking chain...");
    let checked = blockchain_check(&proof, args.daemon.as_deref(), stagenet).await;
    super::ui::abandon(&bar);
    match checked {
        Ok((anchor, daemon_used)) => {
            // L2+UX1: lead with time, then list what was trusted.
            if !args.json {
                println!();
                if anchor.block_timestamp > 0 {
                    println!(
                        "No later than {} (block {}, {} confirmations).",
                        crate::wallet::daemon::format_block_time(anchor.block_timestamp),
                        anchor.height,
                        anchor.confirmations
                    );
                } else {
                    println!(
                        "No later than block {} ({} confirmations).",
                        anchor.height, anchor.confirmations
                    );
                }
                println!();
                super::ui::field("Transaction", &hex::encode(proof.txid));
                super::ui::field("Block hash", &hex::encode(proof.block_hash));
                super::ui::field("Network", proof.network.as_str());
                super::ui::field("Confirmations", &anchor.confirmations.to_string());
                println!();
                println!("Trusted: daemon {daemon_used} (single source), block hash matched,");
                println!(
                    "height exact, {}+ confirmations recommended.",
                    crate::wallet::daemon::MIN_CONFIRMATIONS
                );
            }
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
            if args.json {
                print_json(&serde_json::json!({
                    "ok": true, "anchored": true, "chain_checked": true,
                    "file_hash": hex::encode(file_hash),
                    "root": hex::encode(proof.root),
                    "txid": hex::encode(proof.txid),
                    "block_height": anchor.height,
                    "block_hash": hex::encode(proof.block_hash),
                    "block_time": crate::wallet::daemon::format_block_time(anchor.block_timestamp),
                    "confirmations": anchor.confirmations,
                    "network": proof.network.as_str(),
                    "daemon": daemon_used,
                }));
            }
        }
        Err(e) => {
            let _ = ok;
            super::ui::fail("Check failed.");
            if !args.json {
                println!();
                println!("Why:\n{e}");
            }
            fail_exit_json(args.json, &format!("{e}"));
        }
    }
    Ok(())
}

fn print_json(v: &serde_json::Value) {
    println!("{}", serde_json::to_string(v).unwrap());
}

fn fail_exit_json(json: bool, err: &str) -> ! {
    use std::io::Write;
    if json {
        print_json(&serde_json::json!({"ok": false, "error": err}));
    }
    let _ = std::io::stdout().flush();
    std::process::exit(1);
}

async fn blockchain_check(
    proof: &Proof,
    daemon_override: Option<&str>,
    stagenet: bool,
) -> Result<(crate::wallet::daemon::AnchorCheck, String)> {
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
    // M1: one remote daemon decides the result. Warn on plain-HTTP
    // non-loopback transport (response could be tampered in flight).
    if daemon.to_ascii_lowercase().starts_with("http://")
        && !connection::endpoint_is_loopback(&daemon)
    {
        super::ui::warn(&format!(
            "Daemon {daemon} is remote without TLS. A network attacker could lie about the chain."
        ));
    }
    // Full anchor check: commitment + exact height + block-hash match +
    // daemon nettype match (H1+M1). No wallet involved (M2): verification
    // depends only on the proof file, the original file, and daemon(s).
    // M6: the chain holds the size-bound commitment for V2 proofs.
    let anchor = crate::wallet::daemon::verify_anchor_for_version(
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
    })?;
    Ok((anchor, daemon))
}
