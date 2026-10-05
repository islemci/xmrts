//! `xmrts doctor`. Checks setup. Guides fixes. Never prints secrets.

use anyhow::Result;
use clap::Args;

use crate::wallet::connection;

#[derive(Debug, Args)]
pub struct DoctorArgs {}

pub async fn run(_args: &DoctorArgs, verbose: bool, stagenet: bool) -> Result<()> {
    let _ = verbose;
    super::ui::header("◆", &format!("xmrts {}", env!("CARGO_PKG_VERSION")));
    super::ui::field(
        "System",
        &format!("{} / {}", std::env::consts::OS, std::env::consts::ARCH),
    );
    println!();

    match connection::config_dir() {
        Some(d) => {
            if d.exists() {
                super::ui::ok(&format!("Config folder: {}", d.display()));
            } else {
                super::ui::note("Config folder is missing.");
                super::ui::hint("Make it with `xmrts init`.");
            }
            check_writable(&d);
        }
        None => super::ui::note("Config folder: unknown on this system."),
    }
    if let Some(p) = connection::pending_dir() {
        if p.exists() {
            let n = std::fs::read_dir(&p).map(|r| r.count()).unwrap_or(0);
            if n > 0 {
                super::ui::note(&format!("{n} stamp(s) wait in {}", p.display()));
                super::ui::hint("Finish them with `xmrts finalize`.");
            }
        }
    }
    println!();

    let cfg = connection::load_config();
    super::ui::header("◆", "Settings");
    super::ui::field("Endpoint", &cfg.endpoint);
    if stagenet {
        super::ui::field("Network", "stagenet (flag; saved: {})");
        println!("  saved: {}", cfg.network);
    } else {
        super::ui::field(
            "Network",
            &format!("{} (add --stagenet for stagenet)", cfg.network),
        );
    }
    if cfg.username.is_some() {
        super::ui::field("Login", "user name saved, password hidden");
    } else {
        super::ui::field("Login", "none");
    }
    if cfg.is_remote() {
        if cfg.is_tls() {
            super::ui::ok("Remote uses TLS.");
        } else {
            super::ui::warn("Remote without TLS. Traffic travels openly.");
        }
    }
    match &cfg.daemon_endpoint {
        Some(d) => super::ui::field("Daemon", d),
        None => {
            super::ui::note("No daemon set. Chain checks will wait.");
            super::ui::hint("Set one with `xmrts connect --daemon http://127.0.0.1:18081`.");
        }
    }
    match &cfg.wallet_dir {
        Some(wd) => {
            super::ui::field("Wallet folder", wd);
            let found = crate::cli::wallet::list_wallets(wd);
            if found.is_empty() {
                super::ui::note("Folder holds no wallets.");
            } else {
                let preview: Vec<String> = found.iter().take(3).cloned().collect();
                let more = if found.len() > 3 {
                    format!(" and {} more", found.len() - 3)
                } else {
                    String::new()
                };
                super::ui::field("Wallets", &format!("{}{more}", preview.join(", ")));
            }
        }
        None => {
            let found = crate::wallet::discover::discover();
            if found.is_empty() {
                super::ui::note("No wallet folder set.");
                super::ui::hint("Set one with `xmrts init --wallet-dir <folder>`.");
            } else {
                super::ui::info("No wallet folder set. Found these:");
                for f in &found {
                    println!("  {} ({} wallets)", f.dir.display(), f.wallets.len());
                }
                super::ui::hint("Pick one with `xmrts init --wallet-dir <folder>`.");
            }
        }
    }
    let client = cfg.client();
    match crate::wallet::process::resolve(&cfg) {
        Ok(sc) => super::ui::field("Helper binary", &sc.binary.display().to_string()),
        Err(crate::wallet::process::ProcessError::NotConfigured(_)) => {}
        Err(e) => super::ui::note(&format!("Helper binary: {e}")),
    }
    crate::cli::wallet::print_status(&crate::wallet::process::status(&cfg, &client).await, false);
    println!();

    super::ui::header("◆", "Live checks");
    match client.get_version().await {
        Ok((maj, min)) => super::ui::ok(&format!("Wallet answers (v{maj}.{min}).")),
        Err(e) => {
            super::ui::fail(&format!("Wallet is quiet ({e})."));
            super::ui::hint("Try `xmrts wallet start`, then `xmrts wallet open`.");
        }
    }
    match client.get_height().await {
        Ok(h) => super::ui::field("Wallet height", &h.to_string()),
        Err(_) => super::ui::note("No open wallet or wallet is quiet."),
    }
    match client.get_balance().await {
        Ok((b, _)) => {
            let line = super::ui::with_fiat(
                &crate::wallet::transaction::format_xmr(b),
                super::ui::fiat_for(b, &cfg).await,
            );
            super::ui::field("Balance", &line);
        }
        Err(_) => super::ui::note("Balance unknown."),
    }
    Ok(())
}

fn check_writable(dir: &std::path::Path) {
    if !dir.exists() {
        return;
    }
    let probe = dir.join(".writetest");
    match std::fs::write(&probe, b"ok") {
        Ok(()) => {
            let _ = std::fs::remove_file(&probe);
        }
        Err(_) => super::ui::warn(&format!("Config folder is locked: {}", dir.display())),
    }
}
