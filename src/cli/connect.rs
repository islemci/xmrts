//! `xmrts connect` — configure and verify wallet RPC connectivity.
//! Never prints secrets.

use anyhow::{Context, Result};
use clap::Args;

use crate::wallet::connection::{self, WalletConfig};

#[derive(Debug, Args)]
pub struct ConnectArgs {
    /// Wallet RPC endpoint, e.g. http://127.0.0.1:18082
    #[arg(long)]
    pub endpoint: Option<String>,
    /// RPC username (for --rpc-login protected wallets)
    #[arg(long)]
    pub username: Option<String>,
    /// RPC password. Only stored when combined with --save-auth; otherwise
    /// rejected (xmrts never stores a password without explicit consent).
    #[arg(long)]
    pub password: Option<String>,
    /// Persist username/password in local config (plaintext, mode 0600).
    /// Required together with --password.
    #[arg(long)]
    pub save_auth: bool,
    /// Remove any stored username/password from local config.
    #[arg(long)]
    pub clear_auth: bool,
    /// Monero network: mainnet|testnet|stagenet
    #[arg(long)]
    pub network: Option<String>,
    /// Daemon endpoint for read-only verification, e.g. http://127.0.0.1:18081
    #[arg(long)]
    pub daemon: Option<String>,
}

pub async fn run(args: &ConnectArgs, verbose: bool, stagenet: bool) -> Result<()> {
    let mut cfg: WalletConfig = connection::load_config();
    if let Some(e) = &args.endpoint {
        cfg.endpoint = e.clone();
    }
    if let Some(u) = &args.username {
        cfg.username = Some(u.clone());
    }
    if args.clear_auth {
        cfg.username = None;
        cfg.password = None;
        println!("Cleared stored RPC credentials.");
    }
    match (&args.password, args.save_auth) {
        (Some(p), true) => {
            if cfg.username.is_none() {
                anyhow::bail!(
                    "--password needs a username: pass --username or already have one stored"
                );
            }
            cfg.password = Some(p.clone());
            eprintln!(
                "Note: password will be stored in plaintext in the config file (mode 0600). Anyone with read access to your user account can read it."
            );
        }
        (Some(_), false) => {
            anyhow::bail!("--password requires --save-auth: re-run adding --save-auth to store it (plaintext, mode 0600), or omit --password to leave stored credentials untouched");
        }
        (None, true) => {
            eprintln!("Note: --save-auth without --password changes nothing.");
        }
        (None, false) => {}
    }
    if stagenet && args.network.is_some() {
        anyhow::bail!("use either --stagenet or --network, not both");
    }
    if let Some(n) = &args.network {
        cfg.network = n.clone();
    } else if stagenet {
        cfg.network = "stagenet".to_string();
    }
    if let Some(d) = &args.daemon {
        cfg.daemon_endpoint = Some(d.clone());
    }
    cfg.validate()
        .map_err(|e| anyhow::anyhow!("bad config: {e}"))?;

    // Warn when a username is set but requests would go out unauthenticated.
    if cfg.username.is_some() && cfg.password.is_none() {
        eprintln!(
            "Note: RPC username set but no password stored; requests will be unauthenticated."
        );
        eprintln!("Set one with: xmrts connect --username USER --password PASS --save-auth");
    }

    if cfg.is_remote() && !cfg.is_tls() {
        eprintln!("WARNING: remote wallet RPC without TLS. Credentials and tx data are sent in cleartext.");
    }

    // Save first so endpoint/credentials persist even when the wallet is
    // unreachable — the user can fix the wallet side and retry.
    let saved = connection::save_config(&cfg)?;
    println!("Saved {}", saved.display());
    println!("Network: {}", cfg.network);

    let client = cfg.client();
    let sidecar_hint = match crate::wallet::process::status(&cfg, &client).await {
        crate::wallet::process::SidecarStatus::Stopped => {
            "\nSidecar is configured but stopped; start it with:\n\n    xmrts wallet start"
        }
        crate::wallet::process::SidecarStatus::NotManaged(_) => "",
        _ => "",
    };
    let version = client.get_version().await.with_context(|| {
        format!(
            "could not connect to monero-wallet-rpc.\n\nEndpoint:\n{}\n\nRun:\n\n    xmrts doctor{}",
            cfg.endpoint, sidecar_hint
        )
    })?;
    if verbose {
        println!("wallet RPC version: {}.{}", version.0, version.1);
    }
    match client.get_height().await {
        Ok(h) => println!("Wallet height: {h}"),
        Err(e) => {
            super::ui::note(&format!("Wallet not open or unreachable: {e}"));
            println!("Open a wallet in monero-wallet-rpc first.");
        }
    }
    match client.get_address().await {
        Ok(a) => println!("Primary address: {a}"),
        Err(_) => super::ui::note("No address available (is a wallet open?)"),
    }

    Ok(())
}
