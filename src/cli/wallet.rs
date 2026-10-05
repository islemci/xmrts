//! `xmrts wallet start|stop|status|open` — manage the sidecar process.
//!
//! Management is process-lifecycle only, with one deliberate exception:
//! `wallet open` forwards a wallet password you type at an interactive
//! hidden prompt straight to `open_wallet`. The password lives only in
//! zeroized memory for the duration of that call — never in args, config,
//! logs, or history — and is wiped immediately after.

use anyhow::Result;
use clap::{Args, Subcommand};
use std::io::Write;

use crate::wallet::connection;
use crate::wallet::process::{self, SidecarStatus};

#[derive(Debug, Args)]
pub struct WalletArgs {
    #[command(subcommand)]
    pub command: WalletCommand,
}

#[derive(Debug, Subcommand)]
pub enum WalletCommand {
    /// Start the managed monero-wallet-rpc sidecar (no-op if running).
    Start,
    /// Stop the managed sidecar (refuses foreign pids).
    Stop,
    /// Show sidecar status (process + RPC health).
    Status,
    /// Open a wallet on the running sidecar (interactive password prompt).
    Open,
}

pub async fn run(args: &WalletArgs, verbose: bool) -> Result<()> {
    let mut cfg = connection::load_config();
    let client = cfg.client();
    match &args.command {
        WalletCommand::Start => {
            match process::start(&mut cfg).await {
                Ok(pid) => {
                    super::ui::ok(&format!("Sidecar running (pid {pid})"));
                    println!("Next: `xmrts wallet open`, then `xmrts doctor`.");
                }
                Err(e) => anyhow::bail!("could not start sidecar: {e}"),
            }
            let _ = verbose;
        }
        WalletCommand::Stop => match process::stop(&cfg) {
            Ok(msg) => println!("{msg}"),
            Err(e) => anyhow::bail!("could not stop sidecar: {e}"),
        },
        WalletCommand::Status => print_status(&process::status(&cfg, &client).await, verbose),
        WalletCommand::Open => open_flow(&cfg, &client).await?,
    }
    Ok(())
}

pub fn print_status(status: &SidecarStatus, verbose: bool) {
    match status {
        SidecarStatus::NotManaged(reason) => println!("sidecar: unmanaged ({reason})"),
        SidecarStatus::Stopped => println!("sidecar: stopped"),
        SidecarStatus::Unhealthy(pid) => {
            println!("sidecar: process alive (pid {pid}) but RPC unhealthy");
        }
        SidecarStatus::Running {
            pid,
            rpc_major,
            rpc_minor,
        } => {
            println!("sidecar: running (pid {pid}, wallet RPC v{rpc_major}.{rpc_minor})");
        }
    }
    let _ = verbose;
}

/// Strip a `.keys` suffix to get the wallet filename for `open_wallet`.
pub fn wallet_name_from_path(path: &std::path::Path) -> Option<String> {
    let name = path.file_name()?.to_string_lossy().into_owned();
    Some(name.strip_suffix(".keys").unwrap_or(&name).to_string())
}

/// List openable wallets (filenames without `.keys`) in a directory.
pub fn list_wallets(dir: &str) -> Vec<String> {
    let mut out: Vec<String> = std::fs::read_dir(dir)
        .into_iter()
        .flatten()
        .flatten()
        .filter_map(|e| {
            let name = e.file_name().to_string_lossy().into_owned();
            name.ends_with(".keys")
                .then(|| wallet_name_from_path(&e.path()))
                .flatten()
        })
        .collect();
    out.sort();
    out.dedup();
    out
}

fn prompt_line(prompt: &str) -> Result<String> {
    print!("{prompt}");
    std::io::stdout().flush()?;
    let mut line = String::new();
    std::io::stdin().read_line(&mut line)?;
    Ok(line.trim().to_string())
}

/// Interactive `open_wallet`: password comes from a hidden TTY prompt,
/// lives in zeroized memory only for the call, and is wiped on drop.
/// Never args, never config, never logs.
async fn open_flow(
    cfg: &connection::WalletConfig,
    client: &crate::wallet::rpc::WalletRpc,
) -> Result<()> {
    // The sidecar (or any wallet RPC) must answer first.
    client.get_version().await.map_err(|e| {
        anyhow::anyhow!("wallet RPC unreachable: {e}\nStart it with `xmrts wallet start`.")
    })?;
    if let Ok(addr) = client.get_address().await {
        super::ui::ok("A wallet is already open.");
        println!("Primary address: {addr}");
        return Ok(());
    }
    // Pick the file: offer directory listing, fall back to manual entry.
    let wallets: Vec<String> = cfg
        .wallet_dir
        .as_deref()
        .map(list_wallets)
        .unwrap_or_default();
    let filename = if wallets.len() == 1 {
        println!("Wallet file: {}", wallets[0]);
        wallets[0].clone()
    } else if wallets.len() > 1 {
        println!("Wallets found:");
        for (i, w) in wallets.iter().enumerate() {
            println!("  [{}] {w}", i + 1);
        }
        let idx = super::ui::choose_number("Select wallet [1]: ", wallets.len(), 0)?;
        wallets[idx].clone()
    } else {
        prompt_line("Wallet filename: ")?
    };
    if filename.is_empty() {
        anyhow::bail!("no wallet filename given");
    }
    for attempt in 1..=3 {
        // Hidden input (no echo) + zeroizing memory on drop.
        let password = zeroize::Zeroizing::new(
            rpassword::prompt_password("Wallet password: ")
                .map_err(|e| anyhow::anyhow!("password prompt failed: {e}"))?,
        );
        let open_bar = super::ui::spinner("Opening wallet…");
        let opened = crate::wallet::rpc::open_wallet(client, &filename, &password).await;
        super::ui::abandon(&open_bar);
        match opened {
            Ok(_) => {
                let addr = client
                    .get_address()
                    .await
                    .map_err(|e| anyhow::anyhow!("wallet opened but address unreadable: {e}"))?;
                println!("Wallet open.");
                println!("Primary address: {addr}");
                return Ok(());
            }
            Err(e) => {
                if attempt == 3 {
                    anyhow::bail!("could not open wallet after 3 attempts: {e}");
                }
                eprintln!("Could not open wallet ({e}); try again.");
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
