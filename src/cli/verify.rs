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
    /// Daemon address for tx lookup. Repeat for a quorum: every daemon
    /// must agree on the anchor or verification fails.
    #[arg(long)]
    pub daemon: Vec<String>,
    /// Required confirmations before a proof counts as final (default 10).
    /// Higher (e.g. 20+) is safer for high-value timestamps.
    #[arg(long)]
    pub min_confirmations: Option<u64>,
    /// Machine-readable JSON on stdout (human lines suppressed).
    #[arg(long)]
    pub json: bool,
    /// Detached GPG signature to check as well (from `stamp --sign-with`).
    /// The signature itself is verified by GPG; its own proof
    /// (`<sig>.xmrts`) must anchor in the SAME transaction as the file
    /// proof, binding authorship to the timestamp. The signer's fingerprint
    /// is printed on success.
    #[arg(long)]
    pub sig: Option<PathBuf>,
    /// Location of the `.sig` proof when proofs live away from the files
    /// (e.g. `stamp --out-dir`). Defaults to `<sig>.xmrts` next to the
    /// signature, falling back to the main proof's directory.
    #[arg(long)]
    pub sig_proof: Option<PathBuf>,
}

pub async fn run(args: &VerifyArgs, verbose: bool, stagenet: bool) -> Result<()> {
    if args.json {
        super::ui::set_quiet(true);
    }
    let min_conf = super::stamp::resolve_min_confirmations(args.min_confirmations)?;
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

    // Detached signature binding: gpg proves authorship NOW, the sig proof
    // binds that signature to the SAME timestamp transaction as the file.
    // Without this, a signature made years later would still `gpg --verify`.
    let signer: Option<String> = if let Some(sig) = &args.sig {
        let fingerprint = match run_gpg_verify(sig, &args.file) {
            Ok(fp) => fp,
            Err(e) => {
                super::ui::fail("Check failed.");
                if !args.json {
                    println!();
                    println!("Why:\n{e}");
                }
                fail_exit_json(args.json, &format!("{e}"));
            }
        };
        match check_sig_binding(&proof, sig, args.sig_proof.as_deref(), &args.proof) {
            Ok(()) => {}
            Err(e) => {
                super::ui::fail("Check failed.");
                if !args.json {
                    println!();
                    println!("Why:\n{e}");
                }
                fail_exit_json(args.json, &format!("{e}"));
            }
        }
        if !args.json {
            super::ui::field("Signer", &fingerprint);
        }
        super::ui::ok("GPG signature is valid and anchored with the file.");
        Some(fingerprint)
    } else {
        if args.sig_proof.is_some() {
            super::ui::fail("Check failed.");
            let e = "--sig-proof needs --sig: pass both or neither.";
            if !args.json {
                println!();
                println!("Why:\n{e}");
            }
            fail_exit_json(args.json, e);
        }
        None
    };

    if proof.is_pending() {
        if args.offline {
            super::ui::note("Proof is pending. Crypto passed. No block yet.");
            if !args.json {
                println!();
                println!("Not anchored yet. Run `xmrts stamp` without --offline.");
            }
            if args.json {
                let mut v = serde_json::json!({
                    "ok": true, "anchored": false, "final": false,
                    "warnings": ["pending proof: no block yet; crypto only"],
                    "file_hash": hex::encode(file_hash),
                    "root": hex::encode(proof.root),
                    "network": proof.network.as_str(),
                });
                if let Some(s) = &signer {
                    v["signer"] = serde_json::Value::String(s.clone());
                }
                print_json(&v);
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
            let mut v = serde_json::json!({
                "ok": true, "anchored": false, "chain_checked": false, "final": false,
                "warnings": ["chain not checked (--offline); crypto only"],
                "file_hash": hex::encode(file_hash),
                "root": hex::encode(proof.root),
                "txid": hex::encode(proof.txid),
                "block_height": proof.block_height,
                "network": proof.network.as_str(),
            });
            if let Some(s) = &signer {
                v["signer"] = serde_json::Value::String(s.clone());
            }
            print_json(&v);
        }
        return Ok(());
    }

    let bar = super::ui::spinner("Checking chain...");
    let checked = blockchain_check(&proof, &args.daemon, stagenet).await;
    super::ui::abandon(&bar);
    match checked {
        Ok((anchor, daemons_used, transport_warnings)) => {
            // Collect machine-visible warnings. `ui::warn` prints to
            // stderr in human mode but is suppressed in `--json` mode,
            // so JSON must carry them or automation sees a clean success.
            let mut warnings: Vec<String> = transport_warnings;
            if anchor.confirmations < min_conf {
                let w = format!(
                    "Only {} confirmation(s); want {min_conf}+. Reorg risk: wait before relying on this. (Sep 2025 saw an 18-block reorg; consider 20+ for high value.)",
                    anchor.confirmations,
                );
                super::ui::warn(&w);
                warnings.push(w);
            }
            if proof.network != crate::protocol::proof::Network::Mainnet {
                let w =
                    "NON-MAINNET proof: testnet/stagenet marks have no security value.".to_string();
                super::ui::warn(&w);
                warnings.push(w);
            }
            // `final` means buried deep enough on mainnet over a trusted
            // transport. Anything else is anchored but not final.
            let insecure = warnings.iter().any(|w| w.contains("without TLS"));
            let is_final = anchor.confirmations >= min_conf
                && proof.network == crate::protocol::proof::Network::Mainnet
                && !insecure;
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
                if daemons_used.len() > 1 {
                    super::ui::field("Daemons", &format!("{} agree", daemons_used.len()));
                }
                if !is_final {
                    super::ui::field("Final", "no (see warnings above)");
                }
            }
            if args.json {
                print_json(&anchored_json(
                    &file_hash,
                    &proof,
                    &anchor,
                    &warnings,
                    min_conf,
                    is_final,
                    &daemons_used,
                    signer.as_deref(),
                ));
            }
        }
        Err(e) => {
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

/// Merge per-daemon anchors into one quorum verdict. Height and block
/// hash must match exactly across all daemons; a mismatch means a
/// reorged, lying, or stale node — fail closed, naming the outlier.
/// Tips may honestly differ by a block, so confirmations take the
/// minimum (conservative) instead of requiring equality.
fn merge_quorum(
    daemons: &[String],
    anchors: Vec<crate::wallet::daemon::AnchorCheck>,
    txid_hex: &str,
) -> Result<crate::wallet::daemon::AnchorCheck> {
    let mut it = anchors.into_iter();
    let mut anchor = it
        .next()
        .ok_or_else(|| anyhow::anyhow!("No daemon answered the chain check."))?;
    for (daemon, other) in daemons.iter().skip(1).zip(it) {
        if other.height != anchor.height || other.block_hash != anchor.block_hash {
            // List every daemon's view so the outlier is identifiable with
            // 3+ daemons, not just the first two.
            let mut views = vec![format!(
                "{}: block {} ({})",
                daemons[0],
                anchor.height,
                hex::encode(anchor.block_hash)
            )];
            views.push(format!(
                "{daemon}: block {} ({})",
                other.height,
                hex::encode(other.block_hash)
            ));
            anyhow::bail!(
                "Daemons disagree on tx {txid_hex}. Refusing to verify against a split chain:\n{}",
                views.join("\n"),
            );
        }
        anchor.confirmations = anchor.confirmations.min(other.confirmations);
    }
    Ok(anchor)
}

/// Machine-readable anchored-verdict document. Built by a pure function
/// so the field contract (types included) is pinned by unit tests:
/// automation parses stdout, so fields must never silently change shape.
#[allow(clippy::too_many_arguments)]
fn anchored_json(
    file_hash: &[u8; 32],
    proof: &Proof,
    anchor: &crate::wallet::daemon::AnchorCheck,
    warnings: &[String],
    min_conf: u64,
    is_final: bool,
    daemons: &[String],
    signer: Option<&str>,
) -> serde_json::Value {
    let mut v = serde_json::json!({
        "ok": true, "anchored": true, "chain_checked": true,
        "final": is_final,
        "warnings": warnings,
        "min_confirmations": min_conf,
        "file_hash": hex::encode(file_hash),
        "root": hex::encode(proof.root),
        "txid": hex::encode(proof.txid),
        "block_height": anchor.height,
        "block_hash": hex::encode(proof.block_hash),
        "block_time": crate::wallet::daemon::format_block_time(anchor.block_timestamp),
        "confirmations": anchor.confirmations,
        "network": proof.network.as_str(),
        "daemon": daemons.first().cloned().unwrap_or_default(),
        "daemons": daemons,
    });
    if let Some(s) = signer {
        v["signer"] = serde_json::Value::String(s.to_string());
    }
    v
}

/// Verify a detached GPG signature and return the signer's fingerprint.
/// Uses `--status-fd 1` so the fingerprint is machine-readable (`VALIDSIG`)
/// instead of parsing human text. A signature made at any time verifies
/// here — the timestamp binding is checked separately by
/// [`check_sig_binding`].
fn run_gpg_verify(sig: &std::path::Path, file: &std::path::Path) -> anyhow::Result<String> {
    let out = std::process::Command::new("gpg")
        .args([
            "--status-fd",
            "1",
            "--verify",
            &sig.to_string_lossy(),
            &file.to_string_lossy(),
        ])
        .output()
        .map_err(|e| anyhow::anyhow!("Could not run gpg ({e}). Is GnuPG installed?"))?;
    if !out.status.success() {
        anyhow::bail!("GPG signature does not verify for this file.");
    }
    let status =
        String::from_utf8_lossy(&out.stderr).into_owned() + &String::from_utf8_lossy(&out.stdout);
    Ok(parse_gpg_fingerprint(&status))
}

/// Extract the `VALIDSIG <fingerprint>` field from `gpg --status-fd`
/// output, falling back to `GOODSIG <keyid>` when only that is present.
fn parse_gpg_fingerprint(status: &str) -> String {
    for line in status.lines() {
        let line = line.trim_start_matches("[GNUPG:]").trim();
        if let Some(rest) = line.strip_prefix("VALIDSIG") {
            if let Some(fp) = rest.split_whitespace().next() {
                return fp.to_string();
            }
        }
    }
    for line in status.lines() {
        let line = line.trim_start_matches("[GNUPG:]").trim();
        if let Some(rest) = line.strip_prefix("GOODSIG") {
            if let Some(id) = rest.split_whitespace().next() {
                return id.to_string();
            }
        }
    }
    "unknown (gpg said valid, fingerprint not parsed)".to_string()
}

/// Require the signature's own proof (`file.sig.xmrts`) to anchor in the
/// same transaction as the file proof. `stamp --sign-with` stamps the `.sig`
/// files in the same batch, so both proofs share `root` and `txid`.
/// Returns an error explaining which side is missing or split.
fn check_sig_binding(
    proof: &Proof,
    sig: &std::path::Path,
    sig_proof_opt: Option<&std::path::Path>,
    main_proof_path: &std::path::Path,
) -> anyhow::Result<()> {
    let sig_proof_path = resolve_sig_proof_path(sig, sig_proof_opt, main_proof_path)?;
    let raw = std::fs::read(&sig_proof_path).map_err(|_| {
        anyhow::anyhow!(
            "Signature proof missing: {} holds no anchored proof for the .sig.\nStamp with `xmrts stamp --sign-with <key>` so the signature joins the same batch, or pass --sig-proof <path> when proofs live elsewhere (e.g. --out-dir).",
            sig_proof_path.display()
        )
    })?;
    let sig_proof = Proof::from_bytes(&raw).map_err(|e| {
        anyhow::anyhow!(
            "Signature proof {} is broken: {e}",
            sig_proof_path.display()
        )
    })?;
    let sig_hash = crate::protocol::hash::hash_file(sig)
        .map_err(|e| anyhow::anyhow!("Reading {}: {e:#}", sig.display()))?;
    if sig_hash != sig_proof.file_hash {
        anyhow::bail!(
            "Signature file {} differs from what {} holds. It was replaced after stamping.",
            sig.display(),
            sig_proof_path.display()
        );
    }
    sig_proof.verify_merkle_path().map_err(|e| {
        anyhow::anyhow!(
            "Signature proof {} tree path misses the root: {e}",
            sig_proof_path.display()
        )
    })?;
    if sig_proof.is_pending() {
        anyhow::bail!(
            "Signature proof {} is pending (no block yet). Run `xmrts finalize` first.",
            sig_proof_path.display()
        );
    }
    if sig_proof.root != proof.root || sig_proof.txid != proof.txid {
        anyhow::bail!(
            "Signature is valid but NOT bound to this timestamp: file tx {} vs sig tx {}.\nA signature made later still verifies with gpg; only the same-transaction proof binds authorship to this block.",
            hex::encode(proof.txid),
            hex::encode(sig_proof.txid)
        );
    }
    Ok(())
}

/// Locate the `.sig` proof: explicit `--sig-proof`, else `<sig>.xmrts` next
/// to the signature, else the same file name inside the main proof's
/// directory (covers `stamp --out-dir`).
fn resolve_sig_proof_path(
    sig: &std::path::Path,
    explicit: Option<&std::path::Path>,
    main_proof: &std::path::Path,
) -> anyhow::Result<std::path::PathBuf> {
    use std::path::PathBuf;
    if let Some(p) = explicit {
        return Ok(p.to_path_buf());
    }
    let next_to_sig = PathBuf::from(format!("{}.xmrts", sig.display()));
    if next_to_sig.exists() {
        return Ok(next_to_sig);
    }
    if let (Some(parent), Some(name)) = (main_proof.parent(), sig.file_name()) {
        let cand = parent.join(format!("{}.xmrts", name.to_string_lossy()));
        if cand.exists() {
            return Ok(cand);
        }
        // Return the next-to-sig candidate for a clear "missing" error that
        // names where the user should look first.
        let _ = cand;
    }
    Ok(next_to_sig)
}

/// Normalize a daemon URL to `host[:port]` for quorum distinctness.
/// Lowercased, scheme/userinfo/path stripped. Two spellings of the same
/// host (`http://node:18081` vs `http://node:18081/json_rpc`) compare equal.
fn daemon_identity(daemon: &str) -> String {
    let rest = daemon
        .strip_prefix("https://")
        .or_else(|| daemon.strip_prefix("http://"))
        .unwrap_or(daemon);
    let authority = rest.split(['/', '?', '#']).next().unwrap_or(rest);
    let host_port = authority.rsplit('@').next().unwrap_or(authority);
    host_port.to_ascii_lowercase()
}

/// Refuse a quorum whose entries resolve to the same host:port twice.
/// Pass `--daemon` once, or point at genuinely independent nodes.
fn check_daemons_distinct(daemons: &[String]) -> anyhow::Result<()> {
    let mut seen = std::collections::HashSet::new();
    for d in daemons {
        let id = daemon_identity(d);
        if !seen.insert(id.clone()) {
            anyhow::bail!(
                "Quorum needs distinct daemons: '{d}' repeats '{id}'. One --daemon, or independent nodes."
            );
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

pub(crate) async fn blockchain_check(
    proof: &Proof,
    daemon_overrides: &[String],
    stagenet: bool,
) -> Result<(crate::wallet::daemon::AnchorCheck, Vec<String>, Vec<String>)> {
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
    let daemons: Vec<String> = if daemon_overrides.is_empty() {
        match cfg.daemon_endpoint.clone() {
            Some(d) => vec![d],
            None => anyhow::bail!(
                "No daemon set so chain bytes stay unchecked.\nSet one with `xmrts connect --daemon http://127.0.0.1:18081`. Any local or remote node fits. Or pass --offline for crypto only."
            ),
        }
    } else {
        daemon_overrides.to_vec()
    };
    // A quorum of one host is no quorum: the same daemon twice (or the same
    // host under two spellings) would always "agree" with itself.
    check_daemons_distinct(&daemons)?;
    // Quorum: every daemon is checked independently and all must agree
    // on (height, block hash). Tips may legitimately differ by a block
    // between honest daemons, so confirmations are NOT compared: the
    // minimum across daemons is reported (conservative).
    let mut warnings = Vec::new();
    let mut anchors: Vec<crate::wallet::daemon::AnchorCheck> = Vec::new();
    for daemon in &daemons {
        // Warn on plain-HTTP non-loopback transport (response could be
        // tampered in flight). Returned in the warnings vec too so
        // `--json` automation sees it.
        if let Some(w) = connection::insecure_daemon_warning(daemon) {
            super::ui::warn(&w);
            warnings.push(w);
        }
        // Full anchor check: commitment + exact height + block-hash match +
        // daemon nettype match (H1+M1). No wallet involved (M2): verification
        // depends only on the proof file, the original file, and daemon(s).
        // M6: the chain holds the size-bound commitment for V2 proofs.
        let anchor = crate::wallet::daemon::verify_anchor_for_version(
            daemon,
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
            other => anyhow::anyhow!("Daemon {daemon} says: {other}"),
        })?;
        anchors.push(anchor);
    }
    let anchor = merge_quorum(&daemons, anchors, &txid_hex)?;
    Ok((anchor, daemons, warnings))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wallet::daemon::AnchorCheck;

    fn anchor_at(height: u64, hash_byte: u8, confirmations: u64) -> AnchorCheck {
        AnchorCheck {
            height,
            block_hash: [hash_byte; 32],
            confirmations,
            chain_height: height + confirmations,
            block_timestamp: 1760000000,
        }
    }

    fn daemons() -> Vec<String> {
        vec!["http://a:18081".to_string(), "http://b:18081".to_string()]
    }

    #[test]
    fn quorum_agrees_takes_minimum_confirmations() {
        let a = anchor_at(100, 0xab, 12);
        let b = anchor_at(100, 0xab, 10);
        let merged = merge_quorum(&daemons(), vec![a, b], "txid").unwrap();
        assert_eq!(merged.height, 100);
        assert_eq!(merged.confirmations, 10);
    }

    #[test]
    fn quorum_single_daemon_passes_through() {
        let a = anchor_at(100, 0xab, 12);
        let merged = merge_quorum(&daemons()[..1], vec![a], "txid").unwrap();
        assert_eq!(merged.confirmations, 12);
    }

    #[test]
    fn quorum_hash_split_fails_naming_outlier() {
        let a = anchor_at(100, 0xab, 12);
        let b = anchor_at(100, 0xcd, 12);
        let err = merge_quorum(&daemons(), vec![a, b], "txid").unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("Daemons disagree"), "{msg}");
        assert!(msg.contains("http://b:18081"), "{msg}");
    }

    #[test]
    fn quorum_height_split_fails() {
        let a = anchor_at(100, 0xab, 12);
        let b = anchor_at(101, 0xab, 11);
        let err = merge_quorum(&daemons(), vec![a, b], "txid").unwrap_err();
        assert!(format!("{err:#}").contains("Daemons disagree"));
    }

    fn anchored_proof() -> Proof {
        Proof::new(
            crate::protocol::proof::Network::Mainnet,
            [0x11u8; 32],
            0,
            1,
            [0x22u8; 32],
            [0x33u8; 32],
            3_000_090,
            [0xabu8; 32],
            vec![],
        )
        .unwrap()
    }

    #[test]
    fn quorum_rejects_repeated_daemons() {
        let same = vec![
            "http://node:18081".to_string(),
            "http://node:18081/json_rpc".to_string(),
        ];
        assert!(check_daemons_distinct(&same).is_err());
        let case = vec![
            "http://node:18081".to_string(),
            "http://NODE:18081".to_string(),
        ];
        assert!(check_daemons_distinct(&case).is_err());
        assert!(check_daemons_distinct(&daemons()).is_ok());
        assert!(check_daemons_distinct(&daemons()[..1]).is_ok());
    }

    #[test]
    fn gpg_fingerprint_parses_status_fd() {
        let s = "[GNUPG:] VALIDSIG ABCDEF1234567890 2024-01-01 1234\n[GNUPG:] GOODSIG 1234 user <u@x>\n";
        assert_eq!(parse_gpg_fingerprint(s), "ABCDEF1234567890");
        let s = "[GNUPG:] GOODSIG DEADBEEF some user\n";
        assert_eq!(parse_gpg_fingerprint(s), "DEADBEEF");
        assert!(parse_gpg_fingerprint("nothing here").contains("unknown"));
    }

    #[test]
    fn anchored_json_shape_is_stable() {
        let proof = anchored_proof();
        let anchor = anchor_at(3_000_090, 0xab, 12);
        let warnings = vec!["w1".to_string()];
        let v = anchored_json(
            &[0x11u8; 32],
            &proof,
            &anchor,
            &warnings,
            10,
            true,
            &daemons(),
            None,
        );
        // Booleans.
        assert_eq!(v["ok"], true);
        assert_eq!(v["anchored"], true);
        assert_eq!(v["chain_checked"], true);
        assert_eq!(v["final"], true);
        // Numbers.
        assert_eq!(v["min_confirmations"], 10);
        assert_eq!(v["block_height"], 3_000_090);
        assert_eq!(v["confirmations"], 12);
        // Strings.
        assert_eq!(v["network"], "mainnet");
        assert_eq!(v["daemon"], "http://a:18081");
        assert!(v["file_hash"].is_string());
        assert!(v["root"].is_string());
        assert!(v["txid"].is_string());
        assert!(v["block_hash"].is_string());
        assert!(v["block_time"].is_string());
        // Arrays.
        assert_eq!(v["warnings"], serde_json::json!(["w1"]));
        assert_eq!(
            v["daemons"],
            serde_json::json!(["http://a:18081", "http://b:18081"])
        );
    }

    #[test]
    fn anchored_json_marks_weak_proofs_not_final() {
        let proof = anchored_proof();
        let shallow = anchor_at(3_000_090, 0xab, 2);
        let v = anchored_json(
            &[0x11u8; 32],
            &proof,
            &shallow,
            &["Only 2 confirmation(s)".to_string()],
            10,
            false,
            &daemons()[..1],
            None,
        );
        assert_eq!(v["ok"], true);
        assert_eq!(v["anchored"], true);
        assert_eq!(v["final"], false);
        assert_eq!(v["confirmations"], 2);
        assert!(!v["warnings"].as_array().unwrap().is_empty());
    }
}
