//! `xmrts doctor` — diagnose installation. Never prints secrets.

use anyhow::Result;
use clap::Args;

use crate::wallet::connection;

#[derive(Debug, Args)]
pub struct DoctorArgs {}

pub async fn run(_args: &DoctorArgs, verbose: bool, stagenet: bool) -> Result<()> {
    println!("xmrts {}", env!("CARGO_PKG_VERSION"));
    println!(
        "OS/arch: {} / {}",
        std::env::consts::OS,
        std::env::consts::ARCH
    );
    println!();

    match connection::config_dir() {
        Some(d) => {
            println!(
                "config dir: {} ({})",
                d.display(),
                if d.exists() {
                    "exists"
                } else {
                    "missing — run `xmrts init`"
                }
            );
            check_writable(&d);
        }
        None => println!("config dir: unknown"),
    }
    if let Some(p) = connection::pending_dir() {
        if p.exists() {
            let n = std::fs::read_dir(&p).map(|r| r.count()).unwrap_or(0);
            if n > 0 {
                println!(
                    "pending ops: {n} interrupted timestamp(s) in {}",
                    p.display()
                );
            }
        }
    }

    let cfg = connection::load_config();
    println!("endpoint: {}", cfg.endpoint);
    if stagenet {
        println!("network:  stagenet (--stagenet; config: {})", cfg.network);
    } else {
        println!(
            "network:  {} (default; pass --stagenet to target stagenet)",
            cfg.network
        );
    }
    if cfg.username.is_some() {
        println!("auth:     username set (password hidden)");
    } else {
        println!("auth:     none");
    }
    if cfg.is_remote() {
        if cfg.is_tls() {
            println!("remote:   TLS");
        } else {
            println!("remote:   WARNING non-TLS remote");
        }
    }
    if let Some(d) = &cfg.daemon_endpoint {
        println!("daemon:   {d}");
    }
    let client = cfg.client();
    if let Some(wd) = &cfg.wallet_dir {
        println!("wallet dir: {wd}");
    }
    match crate::wallet::process::resolve(&cfg) {
        Ok(sc) => println!("sidecar binary: {}", sc.binary.display()),
        Err(crate::wallet::process::ProcessError::NotConfigured(_)) => {}
        Err(e) => println!("sidecar binary: {e}"),
    }
    crate::cli::wallet::print_status(
        &crate::wallet::process::status(&cfg, &client).await,
        verbose,
    );

    match client.get_version().await {
        Ok((maj, min)) => super::ui::ok(&format!("wallet RPC reachable (v{maj}.{min})")),
        Err(e) => super::ui::fail(&format!("wallet RPC UNREACHABLE ({e})")),
    }
    match client.get_height().await {
        Ok(h) => println!("wallet height: {h}"),
        Err(_) => super::ui::note("wallet: no open wallet or unreachable"),
    }
    match client.get_balance().await {
        Ok((b, _)) => {
            let line = super::ui::with_fiat(
                &crate::wallet::transaction::format_xmr(b),
                super::ui::fiat_for(b, &cfg).await,
            );
            println!("balance: {line}");
        }
        Err(_) => super::ui::note("balance: unknown"),
    }
    let _ = verbose;
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
        Err(_) => println!("WARNING: config dir not writable: {}", dir.display()),
    }
}
