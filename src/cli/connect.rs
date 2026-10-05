//! `xmrts connect`. Points xmrts at your wallet. Checks it answers.
//! Never prints secrets.

use anyhow::{Context, Result};
use clap::Args;

use crate::wallet::connection::{self, WalletConfig};

#[derive(Debug, Args)]
pub struct ConnectArgs {
    /// Wallet RPC address, like http://127.0.0.1:18082
    #[arg(long)]
    pub endpoint: Option<String>,
    /// RPC user name (for wallets started with a login)
    #[arg(long)]
    pub username: Option<String>,
    /// RPC password. Needs --save-auth too. Never saved without consent.
    #[arg(long)]
    pub password: Option<String>,
    /// Save user name and password locally (plain text, locked to you).
    /// Needs --password together.
    #[arg(long)]
    pub save_auth: bool,
    /// Forget saved user name and password.
    #[arg(long)]
    pub clear_auth: bool,
    /// Monero network: mainnet, testnet, stagenet
    #[arg(long)]
    pub network: Option<String>,
    /// Daemon address for checks, like http://127.0.0.1:18081
    #[arg(long)]
    pub daemon: Option<String>,
}

pub async fn run(args: &ConnectArgs, verbose: bool, stagenet: bool) -> Result<()> {
    let _ = connection::ensure_dirs();
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
        super::ui::ok("Forgot saved login.");
    }
    match (&args.password, args.save_auth) {
        (Some(p), true) => {
            if cfg.username.is_none() {
                anyhow::bail!("Need a user name too. Pass --username or keep one saved.");
            }
            cfg.password = Some(p.clone());
            super::ui::note("Password is saved as plain text. Only your user can read it.");
        }
        (Some(_), false) => {
            anyhow::bail!("Add --save-auth to save the password. Or skip --password.");
        }
        (None, true) => {
            super::ui::note("--save-auth alone changes nothing.");
        }
        (None, false) => {}
    }
    if stagenet && args.network.is_some() {
        anyhow::bail!("Use --stagenet or --network. Not both.");
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
        .map_err(|e| anyhow::anyhow!("Settings look wrong: {e}"))?;

    if cfg.username.is_some() && cfg.password.is_none() {
        super::ui::note("User name is set but no password is saved. Calls go out bare.");
        super::ui::hint("Set one with: xmrts connect --username YOU --password PASS --save-auth");
    }

    if cfg.is_remote() && !cfg.is_tls() {
        super::ui::warn("Remote wallet without TLS. Login and tx data travel openly.");
    }

    // Save first so settings stick even when the wallet is down.
    // The user can fix the wallet side and retry.
    let saved = connection::save_config(&cfg)?;
    super::ui::header("◆", "Connect");
    super::ui::ok(&format!("Saved to {}", saved.display()));
    super::ui::field("Network", &cfg.network);

    let client = cfg.client();
    let sidecar_hint = match crate::wallet::process::status(&cfg, &client).await {
        crate::wallet::process::SidecarStatus::Stopped => {
            "\nHelper is set but stopped. Start it:\n\n    xmrts wallet start"
        }
        crate::wallet::process::SidecarStatus::NotManaged(_) => "",
        _ => "",
    };
    let version = client.get_version().await.with_context(|| {
        format!(
            "Wallet is quiet.\n\nEndpoint:\n{}\n\nTry:\n\n    xmrts doctor{}",
            cfg.endpoint, sidecar_hint
        )
    })?;
    if verbose {
        super::ui::field("Wallet RPC", &format!("v{}.{}", version.0, version.1));
    } else {
        super::ui::ok("Wallet answers.");
    }
    match client.get_height().await {
        Ok(h) => super::ui::field("Wallet height", &h.to_string()),
        Err(e) => {
            super::ui::note(&format!("Wallet gives no height: {e}"));
            super::ui::hint("Open a wallet in monero-wallet-rpc first.");
        }
    }
    match client.get_address().await {
        Ok(a) => super::ui::field("Address", &a),
        Err(_) => super::ui::note("No address yet. Is a wallet open?"),
    }

    Ok(())
}
