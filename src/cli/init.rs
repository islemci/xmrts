//! `xmrts init` — create config dirs and sane defaults. Never touches seeds.
//! Optionally records sidecar settings (binary path + wallet directory)
//! so `xmrts wallet start` can manage the process. Wallet passwords are
//! never requested or stored here.

use anyhow::{Context, Result};
use clap::Args;

use crate::wallet::connection::{self, WalletConfig};
use crate::wallet::process;

#[derive(Debug, Args)]
pub struct InitArgs {
    /// Overwrite existing config with defaults.
    #[arg(long)]
    pub force: bool,
    /// Path to the monero-wallet-rpc binary for sidecar management.
    /// Unset = autodetect (beside xmrts, /opt/monero, PATH).
    #[arg(long)]
    pub wallet_rpc_path: Option<String>,
    /// Wallet directory passed as --wallet-dir to the sidecar.
    /// Setting this enables sidecar management.
    #[arg(long)]
    pub wallet_dir: Option<String>,
}

pub fn run(args: &InitArgs) -> Result<()> {
    let Some(dir) = connection::config_dir() else {
        anyhow::bail!("could not determine platform config directory");
    };
    std::fs::create_dir_all(&dir).with_context(|| format!("creating {}", dir.display()))?;
    if let Some(pending) = connection::pending_dir() {
        std::fs::create_dir_all(&pending)
            .with_context(|| format!("creating {}", pending.display()))?;
    }

    let path = connection::config_file().ok_or_else(|| anyhow::anyhow!("no config dir"))?;
    // Merge into existing config when present (init must not wipe the
    // endpoint/auth the user configured via `connect`).
    let mut cfg = connection::load_config();
    let fresh = !path.exists() || args.force;
    if fresh {
        cfg = WalletConfig::default();
    }
    if let Some(p) = &args.wallet_rpc_path {
        cfg.wallet_rpc_path = Some(p.clone());
    }
    if let Some(d) = &args.wallet_dir {
        cfg.wallet_dir = Some(d.clone());
    }
    if path.exists() && !args.force && args.wallet_rpc_path.is_none() && args.wallet_dir.is_none() {
        println!("Config exists: {}", path.display());
        println!("Next: run `xmrts connect` to point at your monero-wallet-rpc.");
        return Ok(());
    }
    let saved = connection::save_config(&cfg)?;
    println!("Initialized {}", saved.display());
    match process::find_binary(cfg.wallet_rpc_path.as_deref()) {
        Ok(p) => println!("monero-wallet-rpc: {}", p.display()),
        Err(e) => println!("monero-wallet-rpc: {e}"),
    }
    if cfg.wallet_dir.is_some() {
        println!("wallet dir: {}", cfg.wallet_dir.as_deref().unwrap_or(""));
        println!("Sidecar management enabled: `xmrts wallet start`.");
    }
    println!();
    println!("No seeds, keys, or wallet passwords were created or stored. xmrts never holds them,");
    println!("and it never opens wallets by itself — that step stays manual via `open_wallet`.");
    println!("Next: run `xmrts connect`.");
    Ok(())
}
