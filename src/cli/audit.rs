//! `xmrts audit`. Re-verify saved proofs against the chain tip.
//!
//! Timestamps are long-lived: a proof anchored months ago should still
//! anchor today. `audit` re-runs the full check (file hash, Merkle path,
//! chain commitment, height, block hash, confirmations) for every
//! `.xmrts` proof found, and fails loudly naming any proof whose anchor
//! orphaned in a reorg. Read-only: no wallet needed.
//!
//! ```text
//! xmrts audit proofs/                      # every .xmrts under proofs/
//! xmrts audit a.pdf.xmrts b.pdf.xmrts      # named proofs
//! xmrts audit --daemon http://127.0.0.1:18081 proofs/
//! xmrts audit --proof-only proofs/         # anchors only, no originals
//! ```

use anyhow::{Context, Result};
use clap::Args;
use std::path::{Path, PathBuf};

use crate::protocol::hash;
use crate::protocol::proof::Proof;

#[derive(Debug, Args)]
pub struct AuditArgs {
    /// Proof files or folders to audit (folders are walked for *.xmrts).
    #[arg(required = true)]
    pub paths: Vec<PathBuf>,
    /// Daemon address for tx lookup. Repeat for a quorum.
    #[arg(long)]
    pub daemon: Vec<String>,
    /// Required confirmations before a proof counts as final (default 10).
    #[arg(long)]
    pub min_confirmations: Option<u64>,
    /// Machine-readable JSON on stdout (human lines suppressed).
    #[arg(long)]
    pub json: bool,
    /// Skip the original-file check: verify the Merkle path and chain
    /// anchor from the proof alone. Fixes `--out-dir` layouts (originals
    /// not next to proofs) and avoids re-hashing large files just to
    /// re-check the chain anchor.
    #[arg(long)]
    pub proof_only: bool,
}

struct AuditResult {
    proof: PathBuf,
    ok: bool,
    detail: String,
    confirmations: Option<u64>,
}

pub async fn run(args: &AuditArgs, verbose: bool, stagenet: bool) -> Result<()> {
    if args.json {
        super::ui::set_quiet(true);
    }
    let _ = verbose;
    let min_conf = super::stamp::resolve_min_confirmations(args.min_confirmations)?;
    let proofs = expand_proofs(&args.paths)?;
    if proofs.is_empty() {
        anyhow::bail!("No .xmrts proofs found in the given paths.");
    }
    super::ui::header("◆", "Audit");
    if args.proof_only {
        super::ui::note("Proof-only: original files unchecked, anchors only.");
    }
    let mut results: Vec<AuditResult> = Vec::new();
    for proof_path in &proofs {
        results.push(
            audit_one(
                proof_path,
                &args.daemon,
                stagenet,
                min_conf,
                args.proof_only,
            )
            .await,
        );
    }
    let failed = results.iter().filter(|r| !r.ok).count();
    if args.json {
        println!(
            "{}",
            serde_json::to_string(&serde_json::json!({
                "ok": failed == 0,
                "audited": results.len(),
                "failed": failed,
                "proof_only": args.proof_only,
                "results": results.iter().map(|r| serde_json::json!({
                    "proof": r.proof.display().to_string(),
                    "ok": r.ok,
                    "detail": r.detail,
                    "confirmations": r.confirmations,
                })).collect::<Vec<_>>(),
            }))
            .unwrap()
        );
    } else {
        for r in &results {
            if r.ok {
                super::ui::ok(&format!(
                    "{} ({})",
                    r.proof.display(),
                    r.confirmations
                        .map(|c| format!("{c} confirmations"))
                        .unwrap_or_else(|| "checked".to_string())
                ));
            } else {
                super::ui::fail(&format!("{}: {}", r.proof.display(), r.detail));
            }
        }
        super::ui::field(
            "Result",
            &format!("{}/{} proofs hold", results.len() - failed, results.len()),
        );
    }
    if failed > 0 {
        // Single JSON document on stdout (automation parses it); the
        // human message already went to stderr per proof above.
        if args.json {
            std::process::exit(1);
        }
        anyhow::bail!("{failed} of {} proof(s) no longer anchor.", results.len());
    }
    Ok(())
}

async fn audit_one(
    proof_path: &Path,
    daemons: &[String],
    stagenet: bool,
    min_conf: u64,
    proof_only: bool,
) -> AuditResult {
    let fail = |detail: String| AuditResult {
        proof: proof_path.to_path_buf(),
        ok: false,
        detail,
        confirmations: None,
    };
    let raw = match std::fs::read(proof_path) {
        Ok(b) => b,
        Err(e) => return fail(format!("cannot read proof: {e}")),
    };
    let proof = match Proof::from_bytes(&raw) {
        Ok(p) => p,
        Err(e) => return fail(format!("proof file is broken: {e}")),
    };
    if proof.is_pending() {
        return fail("proof is pending: no block yet".to_string());
    }
    // Full mode: the sibling original (`file.pdf` for `file.pdf.xmrts`)
    // must still hash to the proof's file_hash. Proof-only mode skips this
    // (originals may live elsewhere with `--out-dir`, or re-hashing
    // multi-gigabyte files just to re-check the anchor is wasteful): the
    // Merkle path is still checked for internal consistency and the chain
    // anchor is fully verified.
    if !proof_only {
        let file_path = match proof_path
            .to_string_lossy()
            .strip_suffix(".xmrts")
            .map(PathBuf::from)
        {
            Some(p) => p,
            None => return fail("proof file name must end in .xmrts".to_string()),
        };
        let file_hash = match hash::hash_file(&file_path) {
            Ok(h) => h,
            Err(e) => {
                return fail(format!(
                    "cannot read original file {}: {e:#}",
                    file_path.display()
                ));
            }
        };
        if file_hash != proof.file_hash {
            return fail("file differs from what the proof holds".to_string());
        }
    }
    if let Err(e) = proof.verify_merkle_path() {
        return fail(format!("tree path misses the root: {e}"));
    }
    let bar = super::ui::spinner(&format!("Checking {}...", proof_path.display()));
    let checked = super::verify::blockchain_check(&proof, daemons, stagenet).await;
    super::ui::abandon(&bar);
    match checked {
        Ok((anchor, _, _)) => {
            if anchor.confirmations < min_conf {
                AuditResult {
                    proof: proof_path.to_path_buf(),
                    ok: false,
                    detail: format!(
                        "only {} confirmation(s); want {min_conf}+ (reorg risk)",
                        anchor.confirmations
                    ),
                    confirmations: Some(anchor.confirmations),
                }
            } else {
                AuditResult {
                    proof: proof_path.to_path_buf(),
                    ok: true,
                    detail: "holds".to_string(),
                    confirmations: Some(anchor.confirmations),
                }
            }
        }
        Err(e) => fail(format!("{e:#}")),
    }
}

/// Expand audit inputs: `.xmrts` files pass through, directories walk for
/// `*.xmrts` (top level unless `--recursive`... audit always walks
/// depth-first: proof folders are small). Sorted for determinism.
fn expand_proofs(paths: &[PathBuf]) -> Result<Vec<PathBuf>> {
    let mut out: Vec<PathBuf> = Vec::new();
    for p in paths {
        if p.is_file() {
            if !p
                .extension()
                .is_some_and(|e| e.eq_ignore_ascii_case("xmrts"))
            {
                anyhow::bail!(
                    "Not a proof file: {}. Pass .xmrts files or folders holding them.",
                    p.display()
                );
            }
            out.push(p.clone());
        } else if p.is_dir() {
            collect_proofs(p, &mut out).with_context(|| format!("Reading dir {}", p.display()))?;
        } else {
            anyhow::bail!("Cannot read path: {}", p.display());
        }
    }
    out.sort();
    out.dedup();
    Ok(out)
}

fn collect_proofs(dir: &Path, out: &mut Vec<PathBuf>) -> Result<()> {
    let mut entries: Vec<PathBuf> = std::fs::read_dir(dir)?
        .filter_map(|e| e.ok().map(|e| e.path()))
        .collect();
    entries.sort();
    for e in entries {
        if e.is_file() {
            if e.extension()
                .is_some_and(|x| x.eq_ignore_ascii_case("xmrts"))
            {
                out.push(e);
            }
        } else if e.is_dir() {
            collect_proofs(&e, out)?;
        }
    }
    Ok(())
}
