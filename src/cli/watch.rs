//! `xmrts watch`. Finish pending stamps in the background.
//!
//! Polls `finalize --all` until nothing waits, then exits. Ctrl-C is
//! always safe: pending records persist and the next run resumes.
//!
//! ```text
//! xmrts stamp big.iso --yes --no-wait && xmrts watch
//! xmrts watch --interval 300 --daemon http://127.0.0.1:18081
//! ```

use anyhow::Result;
use clap::Args;

use crate::wallet::connection;

#[derive(Debug, Args)]
pub struct WatchArgs {
    /// Seconds between rounds (default 120, minimum 15).
    #[arg(long, default_value_t = 120)]
    pub interval: u64,
    /// Stop after this many rounds (default: run until nothing waits).
    #[arg(long)]
    pub max_rounds: Option<u64>,
    /// Daemon address for chain checks.
    #[arg(long)]
    pub daemon: Option<String>,
    /// Required confirmations before proofs count as anchored (default 10).
    #[arg(long)]
    pub min_confirmations: Option<u64>,
}

pub async fn run(args: &WatchArgs, verbose: bool, stagenet: bool) -> Result<()> {
    let _ = verbose;
    let _ = connection::ensure_dirs();
    let interval = args.interval.max(15);
    let min_conf = super::stamp::resolve_min_confirmations(args.min_confirmations)?;
    super::ui::header("◆", "Watch");
    super::ui::hint("Ctrl-C is safe anytime: pendings persist, the next run resumes.");
    let mut round = 0u64;
    let mut quiet_rounds = 0u32;
    loop {
        round += 1;
        let all = super::pending::list();
        if all.is_empty() {
            super::ui::ok("Nothing pending. Done.");
            return Ok(());
        }
        if let Some(max) = args.max_rounds {
            if round > max {
                anyhow::bail!(
                    "{} pending(s) still wait after {max} round(s). Run `xmrts watch` again later.",
                    all.len()
                );
            }
        }
        super::ui::field("Round", &format!("{round} ({} pending)", all.len()));
        let mut failures = 0usize;
        for p in &all {
            match super::finalize::finalize_one(p, args.daemon.as_deref(), stagenet, min_conf).await
            {
                Ok(()) => {}
                Err(e) => {
                    failures += 1;
                    super::ui::note(&format!("{}: {e:#}", p.display()));
                }
            }
        }
        let remaining = super::pending::list().len();
        if remaining == 0 {
            super::ui::ok("Done. All pendings finished.");
            return Ok(());
        }
        if failures > 0 {
            // Back off a little when nothing is confirming (slow blocks or
            // a down daemon): jitter avoids hammering on a fixed phase.
            quiet_rounds += 1;
            let extra = (quiet_rounds.min(5) as u64) * 15;
            super::ui::note(&format!(
                "{remaining} pending(s) still wait. Sleeping {}s (+{extra}s backoff)...",
                interval
            ));
            tokio::time::sleep(std::time::Duration::from_secs(interval + extra)).await;
        } else {
            quiet_rounds = 0;
            super::ui::note(&format!(
                "{remaining} pending(s) still wait. Sleeping {interval}s..."
            ));
            tokio::time::sleep(std::time::Duration::from_secs(interval)).await;
        }
    }
}
