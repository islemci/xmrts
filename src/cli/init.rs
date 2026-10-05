//! `xmrts init`. Creates config folders and sane defaults.
//! Finds wallet folders for you. Never touches seeds or passwords.

use anyhow::{Context, Result};
use clap::Args;

use crate::wallet::connection::{self, WalletConfig};
use crate::wallet::discover;
use crate::wallet::process;

#[derive(Debug, Args)]
pub struct InitArgs {
    /// Overwrite saved settings with defaults.
    #[arg(long)]
    pub force: bool,
    /// Path to the monero-wallet-rpc binary.
    /// Unset means autodetect next to xmrts, in /opt/monero, or on PATH.
    #[arg(long)]
    pub wallet_rpc_path: Option<String>,
    /// Wallet folder passed as --wallet-dir to the sidecar.
    /// Setting this turns on sidecar control.
    #[arg(long)]
    pub wallet_dir: Option<String>,
}

pub fn run(args: &InitArgs) -> Result<()> {
    let dir = connection::ensure_dirs().context("creating config folders")?;

    let path = connection::config_file().ok_or_else(|| anyhow::anyhow!("no config folder"))?;
    let mut cfg = connection::load_config();
    if !path.exists() || args.force {
        let keep_wallet = cfg.wallet_dir.clone();
        let keep_rpc = cfg.wallet_rpc_path.clone();
        cfg = WalletConfig::default();
        if !args.force {
            cfg.wallet_dir = keep_wallet;
            cfg.wallet_rpc_path = keep_rpc;
        }
    }
    if let Some(p) = &args.wallet_rpc_path {
        cfg.wallet_rpc_path = Some(p.clone());
    }
    if let Some(d) = &args.wallet_dir {
        cfg.wallet_dir = Some(d.clone());
    }

    if cfg.wallet_dir.is_none() {
        if let Some(found) = pick_wallet_dir() {
            cfg.wallet_dir = Some(found);
        }
    }

    if path.exists() && !args.force && args.wallet_rpc_path.is_none() && args.wallet_dir.is_none() {
        let saved = connection::save_config(&cfg)?;
        super::ui::ok(&format!("Config ready at {}", saved.display()));
        print_next(&cfg);
        return Ok(());
    }
    let saved = connection::save_config(&cfg)?;
    let _ = dir;
    super::ui::header("◆", "Setup done");
    super::ui::ok(&format!("Saved settings to {}", saved.display()));
    match process::find_binary(cfg.wallet_rpc_path.as_deref()) {
        Ok(p) => super::ui::field("Wallet RPC", &p.display().to_string()),
        Err(_) => {
            super::ui::note("Wallet RPC binary not found yet.");
            super::ui::hint("Install Monero and point xmrts at it:");
            super::ui::hint("  xmrts init --wallet-rpc-path /path/to/monero-wallet-rpc");
        }
    }
    if let Some(d) = &cfg.wallet_dir {
        super::ui::field("Wallet folder", d);
        super::ui::ok("Sidecar control is on. Try `xmrts wallet start`.");
    } else {
        super::ui::note("Sidecar control is off. No wallet folder set.");
        super::ui::hint("Set one with `xmrts init --wallet-dir <folder>`.");
    }
    println!();
    print_next(&cfg);
    Ok(())
}

fn print_next(cfg: &WalletConfig) {
    if cfg.wallet_dir.is_some() {
        super::ui::hint("Next: `xmrts wallet start`, then `xmrts wallet open`.");
    } else {
        super::ui::hint("Next: `xmrts connect` to point at your wallet.");
    }
}

/// Look in known folders. One hit means use it. Many hits means ask.
/// Returns None when nothing fits or the user skips.
fn pick_wallet_dir() -> Option<String> {
    let found = discover::discover();
    if found.is_empty() {
        super::ui::note("No wallet folders found in the usual places.");
        super::ui::hint("Monero GUI uses ~/Monero/wallets on Mac and Linux.");
        super::ui::hint("On Windows it uses Documents\\Monero\\wallets.");
        super::ui::hint("Set yours with `xmrts init --wallet-dir <folder>`.");
        return None;
    }
    if found.len() == 1 && !found[0].wallets.is_empty() {
        let d = found[0].dir.display().to_string();
        super::ui::ok(&format!(
            "Found {} wallet(s) in {}",
            found[0].wallets.len(),
            d
        ));
        super::ui::hint(&format!("Using {d} as your wallet folder."));
        return Some(d);
    }
    if !super::ui::is_interactive() {
        super::ui::info("Found these wallet folders:");
        for f in &found {
            super::ui::field(
                &f.dir.display().to_string(),
                &format!("{} wallet(s)", f.wallets.len()),
            );
        }
        super::ui::hint("Pick one with `xmrts init --wallet-dir <folder>`.");
        return None;
    }
    super::ui::header("◆", "Wallet folders found");
    for (i, f) in found.iter().enumerate() {
        let preview: Vec<String> = f.wallets.iter().take(3).cloned().collect();
        let more = if f.wallets.len() > 3 {
            format!(" and {} more", f.wallets.len() - 3)
        } else {
            String::new()
        };
        println!(
            "  [{}] {} ({}: {}{more})",
            i + 1,
            f.dir.display(),
            f.wallets.len(),
            preview.join(", ")
        );
    }
    println!("  [Enter] Skip for now");
    match super::ui::choose_number("Pick a folder [Enter to skip]: ", found.len(), found.len()) {
        Ok(idx) if idx < found.len() => Some(found[idx].dir.display().to_string()),
        _ => {
            super::ui::note("Skipped. Sidecar control stays off.");
            None
        }
    }
}
