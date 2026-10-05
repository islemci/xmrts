//! `xmrts wallet start|stop|status|open`. Controls the sidecar process.
//!
//! The password you type for `open` goes straight to the wallet.
//! It lives in wiped memory for one call only. Never saved or logged.

use anyhow::Result;
use clap::{Args, Subcommand};
use std::io::Write;

use crate::wallet::connection;
use crate::wallet::discover;
use crate::wallet::process::{self, SidecarStatus};

#[derive(Debug, Args)]
pub struct WalletArgs {
    #[command(subcommand)]
    pub command: WalletCommand,
}

#[derive(Debug, Subcommand)]
pub enum WalletCommand {
    /// Start the wallet helper (does nothing if already running).
    Start,
    /// Stop the wallet helper.
    Stop,
    /// Show if the helper runs and if the wallet answers.
    Status,
    /// Open a wallet on the running helper (asks for password safely).
    Open,
}

pub async fn run(args: &WalletArgs, verbose: bool) -> Result<()> {
    let _ = connection::ensure_dirs();
    let mut cfg = connection::load_config();
    let client = cfg.client();
    match &args.command {
        WalletCommand::Start => {
            if cfg.wallet_dir.is_none() {
                auto_pick_wallet_dir(&mut cfg)?;
            }
            match process::start(&mut cfg).await {
                Ok(pid) => {
                    super::ui::ok(&format!("Wallet helper runs (pid {pid})."));
                    super::ui::hint("Next: `xmrts wallet open`, then `xmrts doctor`.");
                }
                Err(e) => anyhow::bail!("Could not start helper: {e}"),
            }
            let _ = verbose;
        }
        WalletCommand::Stop => match process::stop(&cfg) {
            Ok(msg) => super::ui::ok(&msg),
            Err(e) => anyhow::bail!("Could not stop helper: {e}"),
        },
        WalletCommand::Status => print_status(&process::status(&cfg, &client).await, verbose),
        WalletCommand::Open => open_flow(&cfg, &client).await?,
    }
    Ok(())
}

pub fn print_status(status: &SidecarStatus, verbose: bool) {
    let _ = verbose;
    super::ui::header("◆", "Wallet helper");
    match status {
        SidecarStatus::NotManaged(reason) => {
            super::ui::note(&format!("Helper is off. {reason}"));
            super::ui::hint("Run `xmrts init` to set it up.");
        }
        SidecarStatus::Stopped => {
            super::ui::note("Helper is stopped.");
            super::ui::hint("Start it with `xmrts wallet start`.");
        }
        SidecarStatus::Unhealthy(pid) => {
            super::ui::fail(&format!("Helper runs (pid {pid}) but stays quiet."));
            super::ui::hint("Check it with `xmrts wallet status`. Logs live in the config folder.");
        }
        SidecarStatus::Running {
            pid,
            rpc_major,
            rpc_minor,
        } => {
            super::ui::ok(&format!(
                "Helper runs (pid {pid}, RPC v{rpc_major}.{rpc_minor})."
            ));
        }
    }
}

/// Strip a `.keys` suffix to get the wallet name for `open_wallet`.
pub fn wallet_name_from_path(path: &std::path::Path) -> Option<String> {
    let name = path.file_name()?.to_string_lossy().into_owned();
    Some(name.strip_suffix(".keys").unwrap_or(&name).to_string())
}

/// List wallets (names without `.keys`) in a folder.
pub fn list_wallets(dir: &str) -> Vec<String> {
    discover::scan_dir(std::path::Path::new(dir))
}

/// Fill in a missing wallet folder from known places.
/// One hit means use it and save. Many hits means ask.
/// Returns Ok(true) when a folder was picked.
pub fn auto_pick_wallet_dir(cfg: &mut connection::WalletConfig) -> Result<bool> {
    let found = discover::discover();
    if found.is_empty() {
        anyhow::bail!(
            "No wallet folder set and none found. Run `xmrts init --wallet-dir <folder>`"
        );
    }
    if found.len() == 1 {
        let d = found[0].dir.display().to_string();
        cfg.wallet_dir = Some(d.clone());
        connection::save_config(cfg)?;
        super::ui::ok(&format!("Found wallets in {d}. Using it."));
        return Ok(true);
    }
    if !super::ui::is_interactive() {
        let mut msg = String::from("Many wallet folders found. Pick one:\n");
        for f in &found {
            msg.push_str(&format!("  {}\n", f.dir.display()));
        }
        msg.push_str("Run `xmrts init --wallet-dir <folder>`");
        anyhow::bail!("{msg}");
    }
    super::ui::info("Many wallet folders found. Pick one:");
    for (i, f) in found.iter().enumerate() {
        println!(
            "  [{}] {} ({} wallets)",
            i + 1,
            f.dir.display(),
            f.wallets.len()
        );
    }
    let idx = super::ui::choose_number("Pick a folder: ", found.len(), 0)?;
    let d = found[idx].dir.display().to_string();
    cfg.wallet_dir = Some(d.clone());
    connection::save_config(cfg)?;
    super::ui::ok(&format!("Using {d}."));
    Ok(true)
}

fn prompt_line(prompt: &str) -> Result<String> {
    print!("{prompt}");
    std::io::stdout().flush()?;
    let mut line = String::new();
    std::io::stdin().read_line(&mut line)?;
    Ok(line.trim().to_string())
}

/// Interactive `open_wallet`. Password comes from a hidden prompt.
/// It lives in wiped memory for one call only. Never saved or logged.
async fn open_flow(
    cfg: &connection::WalletConfig,
    client: &crate::wallet::rpc::WalletRpc,
) -> Result<()> {
    client.get_version().await.map_err(|e| {
        anyhow::anyhow!("Wallet helper is quiet: {e}\nStart it with `xmrts wallet start`.")
    })?;
    if let Ok(addr) = client.get_address().await {
        super::ui::ok("A wallet is already open.");
        super::ui::field("Address", &addr);
        return Ok(());
    }
    let wallets: Vec<String> = match &cfg.wallet_dir {
        Some(d) => list_wallets(d),
        None => {
            let found = discover::discover_with_extra(None);
            if found.is_empty() {
                super::ui::note("No wallet folder set and none found.");
                super::ui::hint("Set one with `xmrts init --wallet-dir <folder>`.");
                Vec::new()
            } else if found.len() == 1 {
                super::ui::info(&format!("Found wallets in {}.", found[0].dir.display()));
                found[0].wallets.clone()
            } else {
                super::ui::info("Found wallets in many folders:");
                for f in &found {
                    println!("  {} ({} wallets)", f.dir.display(), f.wallets.len());
                }
                super::ui::hint("Set one with `xmrts init --wallet-dir <folder>`.");
                found.first().map(|f| f.wallets.clone()).unwrap_or_default()
            }
        }
    };
    let filename = if wallets.len() == 1 {
        super::ui::info(&format!("Wallet file: {}", wallets[0]));
        wallets[0].clone()
    } else if wallets.len() > 1 {
        super::ui::header("◆", "Wallets found");
        for (i, w) in wallets.iter().enumerate() {
            println!("  [{}] {w}", i + 1);
        }
        let idx = super::ui::choose_number("Pick a wallet [1]: ", wallets.len(), 0)?;
        wallets[idx].clone()
    } else {
        if cfg.wallet_dir.is_none() {
            anyhow::bail!("No wallets found. Set a folder with `xmrts init --wallet-dir <folder>`");
        }
        prompt_line("Wallet file name: ")?
    };
    if filename.is_empty() {
        anyhow::bail!("No wallet name given.");
    }
    for attempt in 1..=3 {
        let password = zeroize::Zeroizing::new(
            rpassword::prompt_password("Wallet password: ")
                .map_err(|e| anyhow::anyhow!("Password prompt failed: {e}"))?,
        );
        let open_bar = super::ui::spinner("Opening wallet...");
        let opened = crate::wallet::rpc::open_wallet(client, &filename, &password).await;
        super::ui::abandon(&open_bar);
        match opened {
            Ok(_) => {
                let addr = client
                    .get_address()
                    .await
                    .map_err(|e| anyhow::anyhow!("Wallet opened but address is unreadable: {e}"))?;
                super::ui::ok("Wallet is open.");
                super::ui::field("Address", &addr);
                return Ok(());
            }
            Err(e) => {
                if attempt == 3 {
                    anyhow::bail!("Could not open wallet after 3 tries: {e}");
                }
                eprintln!("That did not work ({e}). Try again.");
            }
        }
    }
    unreachable!("retry loop always returns")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strips_keys_suffix() {
        assert_eq!(
            wallet_name_from_path(std::path::Path::new("/w/musti.keys")),
            Some("musti".to_string())
        );
        assert_eq!(
            wallet_name_from_path(std::path::Path::new("/w/plain")),
            Some("plain".to_string())
        );
    }

    #[test]
    fn lists_only_key_files_sorted() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("b.keys"), b"x").unwrap();
        std::fs::write(dir.path().join("a.keys"), b"x").unwrap();
        std::fs::write(dir.path().join("notes.txt"), b"x").unwrap();
        assert_eq!(
            list_wallets(dir.path().to_str().unwrap()),
            vec!["a".to_string(), "b".to_string()]
        );
    }
}
