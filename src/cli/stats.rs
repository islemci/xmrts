//! `xmrts stats`. What timestamping cost and what waits.
//!
//! Read-only: sums lifetime fees from `history.jsonl` (appended at every
//! anchoring), counts pending records with their quoted fees, and shows
//! the queue depth. No wallet or daemon needed.

use anyhow::Result;
use clap::Args;
use serde::{Deserialize, Serialize};

use crate::wallet::connection;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct HistoryEntry {
    pub txid: String,
    pub fee: u64,
    pub files: usize,
    pub height: u64,
    pub network: String,
    pub time_unix: u64,
}

fn history_path() -> Result<std::path::PathBuf> {
    connection::config_dir()
        .map(|d| d.join("history.jsonl"))
        .ok_or_else(|| anyhow::anyhow!("no config dir"))
}

/// Append one anchoring to the lifetime history (best-effort: a failure
/// here must never fail the stamp itself).
pub fn record(entry: &HistoryEntry) {
    let Ok(path) = history_path() else { return };
    record_at(&path, entry);
}

/// Write one history line to an explicit path. Kept separate from
/// [`record`] so tests can pin the permission behavior without touching
/// the user's real config dir.
pub(crate) fn record_at(path: &std::path::Path, entry: &HistoryEntry) {
    let Ok(line) = serde_json::to_string(entry) else {
        return;
    };
    let mut opts = std::fs::OpenOptions::new();
    opts.create(true).append(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let Ok(mut f) = opts.open(path) else { return };
    // A pre-existing history may have been created by an older release
    // (or by other tooling) with looser bits: harden it in place.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600));
    }
    use std::io::Write;
    let _ = writeln!(f, "{line}");
}

pub fn load_history() -> Vec<HistoryEntry> {
    let Ok(path) = history_path() else {
        return Vec::new();
    };
    let Ok(text) = std::fs::read_to_string(&path) else {
        return Vec::new();
    };
    text.lines()
        .filter_map(|l| serde_json::from_str(l).ok())
        .collect()
}

pub fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[derive(Debug, Args)]
pub struct StatsArgs {
    /// Machine-readable JSON on stdout (human lines suppressed).
    #[arg(long)]
    pub json: bool,
}

pub fn run(args: &StatsArgs) -> Result<()> {
    if args.json {
        super::ui::set_quiet(true);
    }
    let _ = connection::ensure_dirs();
    let history = load_history();
    let stamps: usize = history.iter().map(|e| e.files).sum();
    let fees: u64 = history.iter().map(|e| e.fee).sum();

    let pendings = super::pending::list();
    let mut pending_fees = 0u64;
    let mut oldest_age: Option<u64> = None;
    for p in &pendings {
        if let Ok(op) = super::pending::load(p) {
            pending_fees += op.fee;
        }
        if let Ok(md) = std::fs::metadata(p) {
            if let Ok(t) = md.modified() {
                if let Ok(d) = std::time::SystemTime::now().duration_since(t) {
                    oldest_age = Some(oldest_age.map_or(d.as_secs(), |a| a.max(d.as_secs())));
                }
            }
        }
    }
    let queue_depth = super::queue::load_queue().map(|q| q.len()).unwrap_or(0);

    if args.json {
        println!(
            "{}",
            serde_json::to_string(&serde_json::json!({
                "ok": true,
                "anchored_txs": history.len(),
                "anchored_files": stamps,
                "lifetime_fees_atomic": fees,
                "pending": pendings.len(),
                "pending_fees_atomic": pending_fees,
                "oldest_pending_age_secs": oldest_age,
                "queued": queue_depth,
            }))
            .unwrap()
        );
        return Ok(());
    }
    super::ui::header("◆", "Stats");
    super::ui::field("Anchored txs", &history.len().to_string());
    super::ui::field("Anchored files", &stamps.to_string());
    super::ui::field(
        "Lifetime fees",
        &crate::wallet::transaction::format_xmr(fees),
    );
    super::ui::field("Pending", &pendings.len().to_string());
    if !pendings.is_empty() {
        super::ui::field(
            "Pending fees (quoted)",
            &crate::wallet::transaction::format_xmr(pending_fees),
        );
        if let Some(age) = oldest_age {
            super::ui::field("Oldest pending", &format!("{age}s old"));
        }
        super::ui::hint("Finish them with `xmrts finalize` or `xmrts watch`.");
    }
    super::ui::field("Queued", &queue_depth.to_string());
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(unix)]
    #[test]
    fn record_hardens_loose_history_mode_and_appends() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("history.jsonl");
        // Pre-create the file with world/group-readable bits, as an old
        // release or other tooling might have left it.
        std::fs::write(&path, b"").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        record_at(
            &path,
            &HistoryEntry {
                txid: "ab".to_string(),
                fee: 15000,
                files: 1,
                height: 3_000_090,
                network: "mainnet".to_string(),
                time_unix: 1_760_000_000,
            },
        );
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "history line must harden the file to 0600");
        let text = std::fs::read_to_string(&path).unwrap();
        assert_eq!(text.lines().count(), 1);
        assert!(serde_json::from_str::<HistoryEntry>(text.trim()).is_ok());
    }

    #[test]
    fn history_entry_round_trip() {
        let e = HistoryEntry {
            txid: "ab".to_string(),
            fee: 15000,
            files: 3,
            height: 3_000_090,
            network: "mainnet".to_string(),
            time_unix: 1_760_000_000,
        };
        let line = serde_json::to_string(&e).unwrap();
        assert_eq!(serde_json::from_str::<HistoryEntry>(&line).unwrap(), e);
    }
}
