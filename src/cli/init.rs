//! `xmrts init`. Creates config folders and sane defaults.
//! On a terminal it walks the setup with short questions: the
//! `monero-wallet-rpc` path and the wallet folder, each with a pick
//! list and a typed option. Flags answer the matching question, and
//! piped runs keep the plain, prompt-free steps from before.
//! Never touches seeds or passwords.

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

    // The wizard asks only on a real terminal, and only about the parts
    // no flag pinned this run. Every question accepts Enter, so the
    // saved or default value always wins when the user just skips.
    let mut wizard_took_dir = false;
    if super::ui::is_interactive() && !super::ui::is_quiet() {
        super::ui::header("◆", "Setup");
        super::ui::hint("Press Enter to keep things as they are.");
        if args.wallet_rpc_path.is_none() {
            ask_rpc(&mut cfg)?;
        }
        if args.wallet_dir.is_none() {
            wizard_took_dir = true;
            cfg.wallet_dir = ask_wallet_dir(cfg.wallet_dir.clone())?;
        }
    }

    // Piped runs (and flag-pinned runs never asked about the folder)
    // fall back to quiet discovery: one hit means use it, no prompts.
    if cfg.wallet_dir.is_none() && !wizard_took_dir {
        if let Some(found) = pick_wallet_dir() {
            cfg.wallet_dir = Some(found);
        }
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

/// Ask about the `monero-wallet-rpc` binary. Only runs on a terminal.
/// A working saved path gets a keep question. An autodetected binary
/// gets a save question. Skipping leaves autodetect at use time.
fn ask_rpc(cfg: &mut WalletConfig) -> Result<()> {
    let mut declined: Option<String> = None;
    if let Some(p) = cfg.wallet_rpc_path.clone() {
        if std::path::Path::new(&p).is_file() {
            super::ui::field("Wallet RPC", &p);
            if super::ui::confirm_y("Keep it? [Y/n] ")? {
                return Ok(());
            }
            declined = Some(p);
        } else {
            super::ui::note(&format!("Saved wallet RPC path is gone: {p}"));
        }
        cfg.wallet_rpc_path = None;
    }
    match process::find_binary(None) {
        // A binary exists next to xmrts, in /opt/monero, or on PATH.
        // Saving it here pins the choice in `setting list` too. A path
        // the user just declined stays declined: typed entry is next.
        Ok(found) if declined.as_deref() != Some(&found.display().to_string()) => {
            let d = found.display().to_string();
            super::ui::field("Found wallet RPC", &d);
            if super::ui::confirm_y("Save it? [Y/n] ")? {
                cfg.wallet_rpc_path = Some(d);
                return Ok(());
            }
        }
        Ok(_) => {}
        Err(_) => {
            super::ui::note("monero-wallet-rpc not found in the usual places.");
            super::ui::hint(
                "xmrts needs the patched build from `scripts/build-wallet-rpc.sh` for tx_extra.",
            );
        }
    }
    loop {
        let t = expand_home(&super::ui::ask_line(
            "Path to monero-wallet-rpc (Enter to skip): ",
        )?);
        if t.is_empty() {
            return Ok(());
        }
        if std::path::Path::new(&t).is_file() {
            cfg.wallet_rpc_path = Some(t);
            return Ok(());
        }
        super::ui::note(&format!("{t} is not a file."));
    }
}

/// Ask which wallet folder the sidecar should use. Only runs on a
/// terminal. A saved folder gets a keep question, then every route
/// lists discovered folders plus a typed option. Enter always skips,
/// which leaves sidecar control off.
fn ask_wallet_dir(saved: Option<String>) -> Result<Option<String>> {
    if let Some(d) = saved {
        super::ui::field("Wallet folder", &d);
        if super::ui::confirm_y("Keep it? [Y/n] ")? {
            return Ok(Some(d));
        }
        super::ui::note(&format!("Dropped wallet folder {d}"));
    }
    let found = discover::discover();
    if found.is_empty() {
        super::ui::note("No wallet folders found in the usual places.");
        super::ui::hint("Monero GUI uses ~/Monero/wallets on Mac and Linux.");
        super::ui::hint("On Windows it uses Documents\\Monero\\wallets.");
        return ask_typed_dir();
    }
    super::ui::header("◆", "Wallet folders found");
    for (i, f) in found.iter().enumerate() {
        let preview: Vec<String> = f.wallets.iter().take(3).cloned().collect();
        let more = if f.wallets.len() > 3 {
            format!(" and {} more", f.wallets.len() - 3)
        } else {
            String::new()
        };
        let noun = if f.wallets.len() == 1 {
            "wallet"
        } else {
            "wallets"
        };
        println!(
            "  [{}] {} ({} {}: {}{more})",
            i + 1,
            f.dir.display(),
            f.wallets.len(),
            noun,
            preview.join(", ")
        );
    }
    println!("  [t] Type a folder path");
    loop {
        let answer =
            super::ui::ask_line(&format!("Pick 1 to {}, t, or Enter to skip: ", found.len()))?;
        if answer.is_empty() {
            return Ok(None);
        }
        let t = answer.to_ascii_lowercase();
        if t == "t" {
            return ask_typed_dir();
        }
        if let Ok(n) = t.parse::<usize>() {
            if (1..=found.len()).contains(&n) {
                return Ok(Some(found[n - 1].dir.display().to_string()));
            }
        }
        super::ui::note(&format!("Answer with 1 to {}, t, or Enter.", found.len()));
    }
}

/// Ask for a folder by path. The folder must exist. It may hold no
/// wallets yet (nothing to open until one is created), so it counts.
fn ask_typed_dir() -> Result<Option<String>> {
    loop {
        let t = expand_home(&super::ui::ask_line("Wallet folder (Enter to skip): ")?);
        if t.is_empty() {
            return Ok(None);
        }
        if !std::path::Path::new(&t).is_dir() {
            super::ui::note(&format!("{t} is not a folder."));
            continue;
        }
        let wallets = discover::scan_dir(std::path::Path::new(&t));
        if wallets.is_empty() {
            super::ui::note("No .keys files in it yet. Wallets you create land there.");
        } else {
            super::ui::ok(&format!("Found {} wallet(s) in {t}", wallets.len()));
        }
        return Ok(Some(t));
    }
}

/// Expand a leading `~` or `~/` to the home folder. Typed answers do
/// not run through a shell, so the CLI does the expansion here.
fn expand_home(p: &str) -> String {
    if p == "~" || p.starts_with("~/") {
        if let Some(user) = directories::UserDirs::new() {
            let home = user.home_dir().display().to_string();
            return format!("{home}{}", &p[1..]);
        }
    }
    p.to_string()
}

/// Quiet discovery for piped runs. One hit means use it. Many hits
/// means a plain list and a hint, no prompts.
fn pick_wallet_dir() -> Option<String> {
    let found = discover::discover();
    if found.is_empty() {
        super::ui::note("No wallet folders found in the usual places.");
        super::ui::hint("Monero GUI uses ~/Monero/wallets on Mac and Linux.");
        super::ui::hint("On Windows it uses Documents\\Monero\\wallets.");
        super::ui::hint("Set yours with `xmrts init --wallet-dir <folder>`.");
        return None;
    }
    if found.len() == 1 {
        let d = found[0].dir.display().to_string();
        super::ui::ok(&format!(
            "Found {} wallet(s) in {}",
            found[0].wallets.len(),
            d
        ));
        super::ui::hint(&format!("Using {d} as your wallet folder."));
        return Some(d);
    }
    super::ui::info("Found these wallet folders:");
    for f in &found {
        super::ui::field(
            &f.dir.display().to_string(),
            &format!("{} wallet(s)", f.wallets.len()),
        );
    }
    super::ui::hint("Pick one with `xmrts init --wallet-dir <folder>`.");
    None
}

#[cfg(test)]
mod tests {
    use super::expand_home;

    #[test]
    fn expand_home_only_touches_tilde_leading_paths() {
        // No home in test envs is fine: untouched input falls through.
        if let Some(user) = directories::UserDirs::new() {
            let home = user.home_dir().display().to_string();
            assert_eq!(expand_home("~"), home);
            assert_eq!(expand_home("~/wallets"), format!("{home}/wallets"));
        }
        assert_eq!(expand_home("/opt/monero"), "/opt/monero");
        assert_eq!(expand_home("wallets"), "wallets");
        // A tilde mid-path is a normal path fragment, not a home alias.
        assert_eq!(expand_home("a/~b"), "a/~b");
    }
}
