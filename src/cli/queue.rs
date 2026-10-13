//! `xmrts queue`. Collect files over days, anchor them in one transaction.
//!
//! ```text
//! xmrts queue add a.pdf b.pdf      # hash + remember, no wallet needed
//! xmrts queue list                 # what waits, with ages
//! xmrts queue flush --yes          # one stamp for the whole queue
//! xmrts queue clear --yes          # drop the queue without stamping
//! ```
//!
//! Queue entries store paths + hashes (never contents). `flush` re-hashes
//! and refuses when a file changed since it was queued. On success the
//! flushed entries are removed; `stamp`'s own pending machinery takes over
//! from there (`finalize`, `watch`).

use anyhow::{Context, Result};
use clap::{Args, Subcommand};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

use crate::wallet::connection;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct QueueEntry {
    pub path: String,
    pub hash: String,
    pub added_unix: u64,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct QueueFile {
    #[serde(default)]
    entries: Vec<QueueEntry>,
}

fn queue_path() -> Result<PathBuf> {
    connection::config_dir()
        .map(|d| d.join("queue.json"))
        .ok_or_else(|| anyhow::anyhow!("no config dir"))
}

pub fn load_queue() -> Result<Vec<QueueEntry>> {
    let path = queue_path()?;
    if !path.exists() {
        return Ok(Vec::new());
    }
    let text =
        std::fs::read_to_string(&path).with_context(|| format!("reading {}", path.display()))?;
    let qf: QueueFile =
        serde_json::from_str(&text).with_context(|| format!("parsing {}", path.display()))?;
    Ok(qf.entries)
}

fn save_queue(entries: &[QueueEntry]) -> Result<()> {
    let path = queue_path()?;
    let _ = connection::ensure_dirs();
    connection::atomic_write_0600(
        &path,
        serde_json::to_string_pretty(&QueueFile {
            entries: entries.to_vec(),
        })?
        .as_bytes(),
    )
    .map_err(|e| anyhow::anyhow!("writing {}: {e}", path.display()))?;
    Ok(())
}

fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[derive(Debug, Args)]
pub struct QueueArgs {
    #[command(subcommand)]
    pub command: QueueCommand,
}

#[derive(Debug, Subcommand)]
pub enum QueueCommand {
    /// Hash files and remember them for a later `queue flush`.
    Add {
        /// Files to queue.
        #[arg(required = true)]
        files: Vec<PathBuf>,
        /// Machine-readable JSON on stdout (human lines suppressed).
        #[arg(long)]
        json: bool,
    },
    /// Show queued files with ages.
    List {
        /// Machine-readable JSON on stdout (human lines suppressed).
        #[arg(long)]
        json: bool,
    },
    /// Drop queued files without stamping.
    Clear {
        /// Skip the confirmation prompt.
        #[arg(long)]
        yes: bool,
    },
    /// Stamp the whole queue in one transaction.
    Flush {
        /// Skip the confirmation prompt.
        #[arg(long)]
        yes: bool,
        /// Do not wait for confirmation. Write pending proofs right away.
        #[arg(long)]
        no_wait: bool,
        /// Send amount in atomic units (default 10000).
        #[arg(long, default_value_t = 10_000)]
        amount: u64,
        /// Transaction priority 0-4 (default 0).
        #[arg(long, default_value_t = 0)]
        priority: u32,
        /// Refuse to send when the quoted fee exceeds this (atomic units).
        #[arg(long)]
        max_fee: Option<u64>,
        /// Folder for .xmrts proofs (default: next to each file).
        #[arg(long)]
        out_dir: Option<PathBuf>,
        /// Daemon address for chain checks.
        #[arg(long)]
        daemon: Option<String>,
        /// Required confirmations before proofs count as anchored.
        #[arg(long)]
        min_confirmations: Option<u64>,
        /// Machine-readable JSON summary on stdout (human lines suppressed).
        #[arg(long)]
        json: bool,
    },
}

pub async fn run(args: &QueueArgs, verbose: bool, stagenet: bool) -> Result<()> {
    let _ = connection::ensure_dirs();
    match &args.command {
        QueueCommand::Add { files, json } => run_add(files, *json),
        QueueCommand::List { json } => run_list(*json),
        QueueCommand::Clear { yes } => run_clear(*yes),
        QueueCommand::Flush {
            yes,
            no_wait,
            amount,
            priority,
            max_fee,
            out_dir,
            daemon,
            min_confirmations,
            json,
        } => {
            run_flush(
                *yes,
                *no_wait,
                *amount,
                *priority,
                *max_fee,
                out_dir.clone(),
                daemon.clone(),
                *min_confirmations,
                *json,
                verbose,
                stagenet,
            )
            .await
        }
    }
}

fn run_add(files: &[PathBuf], json: bool) -> Result<()> {
    if json {
        super::ui::set_quiet(true);
    }
    if files.is_empty() {
        anyhow::bail!("No files given.");
    }
    let mut entries = load_queue()?;
    let mut added = 0usize;
    for f in files {
        if !f.is_file() {
            anyhow::bail!("Cannot read file: {}", f.display());
        }
        if f.extension()
            .is_some_and(|e| e.eq_ignore_ascii_case("xmrts"))
        {
            anyhow::bail!(
                "Refusing to queue proof file itself: {}. Queue the original file instead.",
                f.display()
            );
        }
        let h = crate::protocol::hash::hash_file(f)
            .with_context(|| format!("Hashing {}", f.display()))?;
        let key = f.to_string_lossy().into_owned();
        if entries.iter().any(|e| e.path == key) {
            super::ui::note(&format!("Already queued: {}", f.display()));
            continue;
        }
        entries.push(QueueEntry {
            path: key,
            hash: hex::encode(h),
            added_unix: now_unix(),
        });
        added += 1;
    }
    save_queue(&entries)?;
    super::ui::ok(&format!(
        "Queued {added} file(s); {} total wait.",
        entries.len()
    ));
    if json {
        println!(
            "{}",
            serde_json::to_string(&serde_json::json!({
                "ok": true, "added": added, "queued": entries.len(),
            }))
            .unwrap()
        );
    }
    Ok(())
}

fn run_list(json: bool) -> Result<()> {
    if json {
        super::ui::set_quiet(true);
    }
    let entries = load_queue()?;
    if entries.is_empty() {
        super::ui::note("Queue is empty. Add files with `xmrts queue add`.");
        if json {
            println!(
                "{}",
                serde_json::to_string(&serde_json::json!({"ok": true, "queued": []})).unwrap()
            );
        }
        return Ok(());
    }
    if json {
        println!(
            "{}",
            serde_json::to_string(&serde_json::json!({"ok": true, "queued": entries})).unwrap()
        );
        return Ok(());
    }
    super::ui::header("◆", "Queue");
    let now = now_unix();
    for e in &entries {
        let age = now.saturating_sub(e.added_unix);
        let missing = if PathBuf::from(&e.path).is_file() {
            ""
        } else {
            " (missing!)"
        };
        super::ui::field(&e.path, &format!("{} old{}", age_desc(age), missing));
    }
    super::ui::hint("Stamp them all with `xmrts queue flush --yes`.");
    Ok(())
}

fn age_desc(secs: u64) -> String {
    if secs < 60 {
        format!("{secs}s")
    } else if secs < 3600 {
        format!("{}m", secs / 60)
    } else if secs < 86400 {
        format!("{}h", secs / 3600)
    } else {
        format!("{}d", secs / 86400)
    }
}

fn run_clear(yes: bool) -> Result<()> {
    let entries = load_queue()?;
    if entries.is_empty() {
        super::ui::note("Queue is already empty.");
        return Ok(());
    }
    if !yes && !super::ui::confirm(&format!("Drop {} queued file(s)? [y/N] ", entries.len()))? {
        super::ui::note("Stopped. Queue kept.");
        return Ok(());
    }
    save_queue(&[])?;
    super::ui::ok(&format!("Dropped {} queued file(s).", entries.len()));
    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn run_flush(
    yes: bool,
    no_wait: bool,
    amount: u64,
    priority: u32,
    max_fee: Option<u64>,
    out_dir: Option<PathBuf>,
    daemon: Option<String>,
    min_confirmations: Option<u64>,
    json: bool,
    verbose: bool,
    stagenet: bool,
) -> Result<()> {
    let entries = load_queue()?;
    if entries.is_empty() {
        anyhow::bail!("Queue is empty. Add files with `xmrts queue add`.");
    }
    // Re-hash: refuse files that changed or vanished since they were queued.
    let mut files: Vec<PathBuf> = Vec::new();
    for e in &entries {
        let p = PathBuf::from(&e.path);
        let h = crate::protocol::hash::hash_file(&p)
            .with_context(|| format!("Reading queued file {} (moved or changed?)", e.path))?;
        if hex::encode(h) != e.hash {
            anyhow::bail!(
                "Queued file changed since `queue add`: {}. Re-add it or drop it with `queue clear`.",
                e.path
            );
        }
        files.push(p);
    }
    let stamp_args = super::stamp::StampArgs {
        files,
        offline: false,
        do_not_relay: false,
        no_wait,
        yes,
        address: None,
        amount,
        recursive: false,
        out_dir,
        daemon,
        min_confirmations,
        max_fee,
        priority,
        json,
        sign_with: None,
    };
    super::stamp::run(&stamp_args, verbose, stagenet).await?;
    // The stamp pipeline owns recovery from here (pending records,
    // `finalize`, `watch`): the queue's job is done.
    save_queue(&[])?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn queue_entry_round_trip() {
        let e = QueueEntry {
            path: "a.pdf".to_string(),
            hash: "ab".repeat(32),
            added_unix: 1_760_000_000,
        };
        let qf = QueueFile {
            entries: vec![e.clone()],
        };
        let text = serde_json::to_string(&qf).unwrap();
        let back: QueueFile = serde_json::from_str(&text).unwrap();
        assert_eq!(back.entries, vec![e]);
        // Old queue files without new fields still parse.
        let back: QueueFile = serde_json::from_str(r#"{"entries":[]}"#).unwrap();
        assert!(back.entries.is_empty());
    }
}
