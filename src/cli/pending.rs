//! Interrupted-operation recovery state (spec §23 / Phase 7).
//!
//! A pending file records the minimum needed to finish a stamp later:
//! input files, sorted hashes + root, commitment, and transaction state
//! (preview hex always, relayed txid once known). Never file contents.

use anyhow::{Context, Result};
use clap::{Args, Subcommand};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

use crate::wallet::connection;

fn default_merkle_ver() -> u8 {
    crate::protocol::merkle::MERKLE_V1
}

fn default_relayed() -> bool {
    true
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PendingOp {
    pub files: Vec<String>,
    pub file_hashes: Vec<String>,
    pub sorted_hashes: Vec<String>,
    pub root: String,
    pub extra_hex: String,
    pub txid: String,
    /// Preview hex (doubles as the relay payload): enough to re-relay
    /// after a crash between preview and relay.
    pub tx_hex: String,
    /// Quoted fee in atomic units (for `stats`). Old pendings default to 0.
    #[serde(default)]
    pub fee: u64,
    #[serde(default)]
    pub out_dir: Option<String>,
    pub network: String,
    /// Merkle version used for the chain commitment (M6). Old pendings
    /// predate the field and default to V1.
    #[serde(default = "default_merkle_ver")]
    pub merkle_ver: u8,
    /// Whether the transaction was actually relayed. Saved as false and
    /// only flipped true in the same atomic write as the final txid
    /// (`pending::update_txid`), right after `relay` succeeds: a crash
    /// between save and relay must not leave a broadcast that never
    /// happened. Old pendings predate the field and default to true.
    #[serde(default = "default_relayed")]
    pub relayed: bool,
}

pub fn path_for_root(root_hex: &str) -> Option<PathBuf> {
    connection::pending_dir().map(|d| {
        d.join(format!(
            "pending-{}.json",
            &root_hex[..16.min(root_hex.len())]
        ))
    })
}

/// All pending files, sorted for deterministic selection.
pub fn list() -> Vec<PathBuf> {
    let Some(dir) = connection::pending_dir() else {
        return Vec::new();
    };
    let mut out: Vec<PathBuf> = std::fs::read_dir(dir)
        .into_iter()
        .flatten()
        .flatten()
        .map(|e| e.path())
        .filter(|p| {
            p.file_name()
                .and_then(|n| n.to_str())
                .map(|n| n.starts_with("pending-") && n.ends_with(".json"))
                .unwrap_or(false)
        })
        .collect();
    out.sort();
    out
}

pub fn load(path: &Path) -> Result<PendingOp> {
    let text =
        std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
    serde_json::from_str(&text).with_context(|| format!("parsing {}", path.display()))
}

pub fn save(op: &PendingOp) -> Result<PathBuf> {
    let Some(dir) = connection::pending_dir() else {
        anyhow::bail!("no config dir");
    };
    let _ = connection::ensure_dirs();
    let _ = &dir;
    let mut path = path_for_root(&op.root).ok_or_else(|| anyhow::anyhow!("no config dir"))?;
    // Same file set re-stamped must not clobber the earlier pending (its
    // txid is the only link to the broadcast tx). Resume of the same txid
    // reuses the path; a different txid gets a suffixed path.
    if path.exists() {
        let same_txid = load(&path)
            .map(|prev| prev.txid == op.txid)
            .unwrap_or(false);
        if !same_txid {
            let stem = path
                .file_stem()
                .map(|s| s.to_string_lossy().into_owned())
                .unwrap_or_else(|| "pending".to_string());
            let mut n = 2u32;
            loop {
                let cand = dir.join(format!("{stem}-{n}.json"));
                if !cand.exists() {
                    path = cand;
                    break;
                }
                n += 1;
            }
        }
    }
    // Atomic + owner-only: crash-safe recovery record (M3). Holds tx
    // metadata and the list of stamped file paths.
    connection::atomic_write_0600(&path, serde_json::to_string_pretty(op)?.as_bytes())?;
    Ok(path)
}

/// `xmrts pending`: inspect and tidy recovery records.
/// Bare `pending` lists; `pending clean` removes records that can never
/// finalize (input files gone or record unreadable). Records with all
/// files present are never touched: they may still confirm.
#[derive(Debug, Args)]
pub struct PendingArgs {
    #[command(subcommand)]
    pub command: Option<PendingCommand>,
    /// Machine-readable JSON list on stdout (human lines suppressed).
    /// Pass before the subcommand: `xmrts pending --json list`.
    #[arg(long)]
    pub json: bool,
}

#[derive(Debug, Subcommand)]
pub enum PendingCommand {
    /// List pending stamps (default): age, network, files, tx state.
    List,
    /// Remove records whose input files are gone (asks first).
    Clean {
        /// Skip the confirmation prompt.
        #[arg(long)]
        yes: bool,
    },
}

struct PendingView {
    path: PathBuf,
    age_secs: Option<u64>,
    op: Result<PendingOp, String>,
}

fn view_all() -> Vec<PendingView> {
    list()
        .into_iter()
        .map(|path| {
            let age_secs = std::fs::metadata(&path)
                .and_then(|m| m.modified())
                .ok()
                .and_then(|t| {
                    std::time::SystemTime::now()
                        .duration_since(t)
                        .map(|d| d.as_secs())
                        .ok()
                });
            let op = load(&path).map_err(|e| format!("{e:#}"));
            PendingView { path, age_secs, op }
        })
        .collect()
}

fn format_age(secs: Option<u64>) -> String {
    match secs {
        None => "age unknown".to_string(),
        Some(s) if s < 60 => format!("{s}s old"),
        Some(s) if s < 3600 => format!("{}m old", s / 60),
        Some(s) if s < 86400 => format!("{}h {}m old", s / 3600, s % 3600 / 60),
        Some(s) => format!("{}d {}h old", s / 86400, s % 86400 / 3600),
    }
}

pub fn run(args: &PendingArgs) -> Result<()> {
    if args.json {
        super::ui::set_quiet(true);
    }
    let _ = connection::ensure_dirs();
    match args.command.as_ref().unwrap_or(&PendingCommand::List) {
        PendingCommand::List => run_list(args.json),
        PendingCommand::Clean { yes } => run_clean(*yes, args.json),
    }
}

fn run_list(json: bool) -> Result<()> {
    let views = view_all();
    if views.is_empty() {
        super::ui::note("Nothing pending. No files wait.");
        if json {
            println!(
                "{}",
                serde_json::to_string(&serde_json::json!({"ok": true, "pending": []})).unwrap()
            );
        }
        return Ok(());
    }
    if json {
        let items: Vec<serde_json::Value> = views
            .iter()
            .map(|v| match &v.op {
                Ok(op) => {
                    let missing: Vec<&String> = op
                        .files
                        .iter()
                        .filter(|f| !Path::new(f).is_file())
                        .collect();
                    serde_json::json!({
                        "path": v.path.display().to_string(),
                        "age_secs": v.age_secs,
                        "network": op.network,
                        "files": op.files,
                        "missing_files": missing,
                        "txid": op.txid,
                        // Honest states, matching the human list: a record
                        // with a preview txid but relayed=false was built,
                        // not broadcast (--do-not-relay or an interrupted
                        // run). sent flips only when the record says the
                        // relay happened; relayed is exposed for automations
                        // that want both bits.
                        "relayed": op.relayed,
                        "sent": op.relayed && !op.txid.is_empty(),
                    })
                }
                Err(e) => serde_json::json!({
                    "path": v.path.display().to_string(),
                    "age_secs": v.age_secs,
                    "error": e,
                }),
            })
            .collect();
        println!(
            "{}",
            serde_json::to_string(&serde_json::json!({"ok": true, "pending": items})).unwrap()
        );
        return Ok(());
    }
    super::ui::header("◆", "Pending");
    for v in &views {
        let name = v
            .path
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_else(|| v.path.display().to_string());
        match &v.op {
            Ok(op) => {
                let missing = op.files.iter().filter(|f| !Path::new(f).is_file()).count();
                let tx = if !op.relayed {
                    "never relayed (--do-not-relay or interrupted run)"
                } else if op.txid.is_empty() {
                    "never sent"
                } else {
                    "sent, awaiting confirmations"
                };
                super::ui::field(&name, &format!("{}, {}", format_age(v.age_secs), tx));
                println!(
                    "  {} file(s), {} ({}), txid: {}",
                    op.files.len(),
                    op.network,
                    if missing == 0 {
                        "all files present".to_string()
                    } else {
                        format!("{missing} file(s) missing")
                    },
                    if op.txid.is_empty() {
                        "—".to_string()
                    } else {
                        op.txid.clone()
                    }
                );
            }
            Err(e) => {
                super::ui::field(
                    &name,
                    &format!("{}, unreadable: {e}", format_age(v.age_secs)),
                );
            }
        }
    }
    super::ui::hint("Finish one with `xmrts finalize`; drop dead ones with `xmrts pending clean`.");
    Ok(())
}

fn run_clean(yes: bool, json: bool) -> Result<()> {
    // Machine mode cannot answer the removal prompt: without --yes the
    // "Remove N dead record(s)?" bytes would land on the JSON stream.
    super::stamp::ensure_json_consent(json, yes)?;
    let views = view_all();
    // Cleanable = unreadable, or at least one input file gone (finalize
    // needs every file to recompute the root, so these can never finish).
    let dead: Vec<&PendingView> = views
        .iter()
        .filter(|v| match &v.op {
            Err(_) => true,
            Ok(op) => op.files.iter().any(|f| !Path::new(f).is_file()),
        })
        .collect();
    if dead.is_empty() {
        if views.is_empty() {
            super::ui::note("Nothing pending. No files wait.");
        } else {
            super::ui::ok(&format!(
                "All {} pending(s) have their files. Nothing to clean.",
                views.len()
            ));
        }
        if json {
            println!(
                "{}",
                serde_json::to_string(&serde_json::json!({"ok": true, "removed": 0})).unwrap()
            );
        }
        return Ok(());
    }
    if json {
        // One JSON doc per run: the removal summary prints after the work.
    } else {
        super::ui::header("◆", "Pending clean");
        for v in &dead {
            println!("  {}", v.path.display());
        }
    }
    if !yes && !super::ui::confirm(&format!("Remove {} dead record(s)? [y/N] ", dead.len()))? {
        super::ui::note("Stopped. Nothing removed.");
        return Ok(());
    }
    let mut removed = 0;
    for v in &dead {
        match std::fs::remove_file(&v.path) {
            Ok(()) => removed += 1,
            Err(e) => super::ui::warn(&format!("Could not remove {}: {e}", v.path.display())),
        }
    }
    super::ui::ok(&format!("Removed {removed} dead record(s)."));
    if json {
        println!(
            "{}",
            serde_json::to_string(
                &serde_json::json!({"ok": removed == dead.len(), "removed": removed})
            )
            .unwrap()
        );
    }
    Ok(())
}

/// Record the relayed txid and mark the record as relayed in ONE atomic
/// write, so a crash in between cannot leave a final txid behind a
/// `relayed: false` claim (or an honest-looking `relayed: true` for a
/// tx that was never broadcast - only this function sets true, and it
/// only runs after `relay` succeeded). Returns an error instead of
/// swallowing it (M3): callers surface it as a warning.
pub fn update_txid(path: &Path, txid: &str) -> Result<()> {
    let text =
        std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
    let mut v: serde_json::Value =
        serde_json::from_str(&text).with_context(|| format!("parsing {}", path.display()))?;
    v["txid"] = serde_json::Value::String(txid.to_string());
    v["relayed"] = serde_json::Value::Bool(true);
    let out = serde_json::to_string_pretty(&v)?;
    connection::atomic_write_0600(path, out.as_bytes())?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn temp_pending(relayed: bool) -> (tempfile::TempDir, PathBuf) {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("pending-abc.json");
        let op = PendingOp {
            files: vec!["/a.doc".to_string()],
            file_hashes: vec![],
            sorted_hashes: vec!["aa".repeat(32)],
            root: "bb".repeat(32),
            extra_hex: String::new(),
            txid: String::new(),
            tx_hex: "dead".to_string(),
            fee: 12_345,
            out_dir: None,
            network: "mainnet".to_string(),
            merkle_ver: 2,
            relayed,
        };
        std::fs::write(&path, serde_json::to_string_pretty(&op).unwrap()).unwrap();
        (dir, path)
    }

    /// save starts with relayed: false; only update_txid may flip it, and
    /// it must do so in the same atomic write as the final txid.
    #[test]
    fn update_txid_sets_relayed_and_txid_together() {
        let (_dir, path) = temp_pending(false);
        update_txid(&path, "abc123hex").unwrap();
        let op = load(&path).unwrap();
        assert_eq!(op.txid, "abc123hex");
        assert!(op.relayed, "relay success must mark the record relayed");
        // Everything else survives the rewrite.
        assert_eq!(op.files, vec!["/a.doc"]);
        assert_eq!(op.root, "bb".repeat(32));
        assert_eq!(op.fee, 12_345);
    }

    /// An already-true record stays true (old pendings predate the flag
    /// and default to true); unknown/extra fields survive the rewrite.
    #[test]
    fn update_txid_keeps_record_true_and_extra_fields() {
        let (_dir, path) = temp_pending(true);
        update_txid(&path, "zzz").unwrap();
        let text = std::fs::read_to_string(&path).unwrap();
        let v: serde_json::Value = serde_json::from_str(&text).unwrap();
        assert_eq!(v["relayed"], serde_json::Value::Bool(true));
        assert_eq!(v["txid"], "zzz");
        assert_eq!(v["network"], "mainnet");
    }
}
