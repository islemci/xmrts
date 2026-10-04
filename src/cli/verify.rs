//! `xmrts verify` — no wallet required. Crypto checks first, then
//! blockchain commitment lookup via daemon/wallet RPC where available.
//!
//! Stages (each reported, failure names the stage):
//! 1 parse proof, 2 hash file, 3 compare file hash, 4/5 reconstruct +
//! compare root, 6 find tx, 7 extract commitment, 8 compare root,
//! 9 inclusion, 10 report.

use anyhow::{Context, Result};
use clap::Args;
use std::path::PathBuf;

use crate::protocol::hash;
use crate::protocol::proof::Proof;
use crate::wallet::connection;

#[derive(Debug, Args)]
pub struct VerifyArgs {
    /// File to verify.
    pub file: PathBuf,
    /// Proof file (.xmrts).
    pub proof: PathBuf,
    /// Crypto-only: skip blockchain lookup.
    #[arg(long)]
    pub offline: bool,
    /// Daemon endpoint override for tx lookup.
    #[arg(long)]
    pub daemon: Option<String>,
}

pub async fn run(args: &VerifyArgs, verbose: bool, stagenet: bool) -> Result<()> {
    let mut ok = true; // 1. Parse proof (untrusted input).
    let raw =
        std::fs::read(&args.proof).with_context(|| format!("reading {}", args.proof.display()))?;
    let proof = match Proof::from_bytes(&raw) {
        Ok(p) => {
            super::ui::ok("Proof parses");
            p
        }
        Err(e) => {
            super::ui::fail("Verification failed");
            println!();
            println!("Reason:\nThe proof file is malformed: {e}");
            fail_exit();
        }
    };
    if verbose {
        println!();
        print!("{}", proof.describe());
        println!();
    }

    // 2+3. Hash + compare.
    let file_hash =
        hash::hash_file(&args.file).with_context(|| format!("reading {}", args.file.display()))?;
    if file_hash == proof.file_hash {
        super::ui::ok("File hash matches");
    } else {
        super::ui::fail("Verification failed");
        println!();
        println!("Reason:\nThe supplied file hash does not match the hash stored in the proof.");
        println!("got:  {}", hex::encode(file_hash));
        println!("proof: {}", hex::encode(proof.file_hash));
        fail_exit();
    }

    // 4+5. Merkle path.
    match proof.verify_merkle_path() {
        Ok(()) => super::ui::ok("Merkle proof valid"),
        Err(e) => {
            super::ui::fail("Verification failed");
            println!();
            println!("Reason:\nMerkle path does not recompute to the proof root: {e}");
            fail_exit();
        }
    }

    if proof.is_pending() {
        if args.offline {
            super::ui::note(
                "Unanchored (pending) proof: crypto checks passed, no block/tx recorded.",
            );
            println!();
            println!(
                "Timestamp NOT anchored: create an anchored proof with `xmrts stamp` (no --offline)."
            );
            return Ok(());
        }
        super::ui::note("Unanchored (pending) proof: no block/tx recorded.");
        println!();
        println!(
            "Timestamp NOT verified: create an anchored proof with `xmrts stamp` (no --offline)."
        );
        fail_exit();
    }

    if args.offline {
        super::ui::note("Blockchain lookup skipped (--offline).");
        println!();
        println!("Cryptographic checks passed; blockchain anchoring NOT checked.");
        return Ok(());
    }

    // 6-9. Blockchain lookup.
    let bar = super::ui::spinner("Checking on-chain commitment…");
    let checked = blockchain_check(&proof, args.daemon.as_deref(), stagenet).await;
    super::ui::abandon(&bar);
    match checked {
        Ok((height, txid_hex)) => {
            super::ui::ok("xmrts commitment found");
            super::ui::ok("Transaction confirmed");
            super::ui::ok("Timestamp verified");
            println!();
            println!("Block: {height}");
            println!("Transaction: {txid_hex}");
            println!();
            println!("Meaning: the file existed no later than block {height}.");
        }
        Err(e) => {
            ok = false;
            super::ui::fail("Verification failed");
            println!();
            println!("Reason:\n{e}");
        }
    }
    if !ok {
        fail_exit();
    }
    Ok(())
}

/// Exit 1 after flushing stdout: `process::exit` does not flush
/// block-buffered stdout, so piped failure output could be lost.
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
    // Network guard: default is mainnet; `--stagenet` on this invocation
    // selects stagenet instead. A proof from one network must not verify
    // against another.
    let effective_net = if stagenet {
        "stagenet".to_string()
    } else {
        cfg.network.to_ascii_lowercase()
    };
    if effective_net != proof.network.as_str() {
        anyhow::bail!(
            "network mismatch: proof is for {} but this invocation targets {effective_net}. A proof from one network must not verify against another.",
            proof.network.as_str()
        );
    }

    let txid_hex = hex::encode(proof.txid);
    // The commitment bytes can only be checked against a daemon: the wallet
    // RPC confirms inclusion but never returns tx_extra. Fail closed here —
    // inclusion without the byte check proves nothing about anchoring.
    let daemon = daemon_override
        .map(String::from)
        .or(cfg.daemon_endpoint.clone());
    let Some(daemon) = daemon else {
        anyhow::bail!(
            "no daemon endpoint configured, so the on-chain commitment bytes cannot be checked.\nSet one with `xmrts connect --daemon http://127.0.0.1:18081` (any local or remote node works; get_transactions is unrestricted), or re-run with --offline for crypto-only checks."
        );
    };
    let height = crate::wallet::daemon::confirm_commitment(&daemon, &txid_hex, &proof.root)
        .await
        .map_err(|e| match e {
            crate::wallet::daemon::DaemonError::CommitmentAbsent { .. } => anyhow::anyhow!(
                "no xmrts commitment in transaction {txid_hex} matches the proof root.\nThe transaction exists but does NOT anchor this file (the wallet may have dropped the commitment when building it)."
            ),
            other => anyhow::anyhow!("{other}"),
        })?;
    // Cross-check the wallet's view when reachable (best effort only).
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
                "wallet reports block {wh} but the proof claims {}; refusing to verify across conflicting anchors.",
                proof.block_height
            );
        }
    }
    Ok((height.max(proof.block_height), txid_hex))
}
