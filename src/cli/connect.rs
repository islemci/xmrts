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
    /// RPC password. Prefer omitting this and typing the password when
    /// asked: passing `--password` on the command line exposes it in shell
    /// history and the process list. Needs --save-auth too. Never saved
    /// without consent.
    #[arg(long)]
    pub password: Option<String>,
    /// Read the RPC password from stdin (e.g. `printf '%s' "$SECRET" |
    /// xmrts connect ... --password-stdin --save-auth`, or
    /// `cat secret.txt |`). Keeps the password out of argv so `ps`
    /// cannot see it — CI runners and shared machines are exactly where
    /// `--password` is unacceptable. Only one trailing newline is
    /// stripped, so everything else reaches the config verbatim.
    /// Needs --save-auth together.
    #[arg(long, conflicts_with = "password")]
    pub password_stdin: bool,
    /// Save user name and password locally (plain text, locked to you).
    /// Needs --password or --password-stdin (or an interactive prompt)
    /// to carry one.
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
    /// Proxy for daemon and price-feed traffic, e.g. socks5h://127.0.0.1:9050
    /// for Tor. Loopback endpoints (local wallet/daemon) always bypass it.
    #[arg(long)]
    pub proxy: Option<String>,
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
    let from_stdin = if args.password_stdin {
        Some(zeroize::Zeroizing::new(password_from_reader(
            std::io::stdin(),
        )?))
    } else {
        None
    };
    match (&args.password, from_stdin.as_deref(), args.save_auth) {
        (Some(p), _, true) => {
            if cfg.username.is_none() {
                anyhow::bail!("Need a user name too. Pass --username or keep one saved.");
            }
            super::ui::warn(
                "Password passed on the command line stays in shell history and is visible in `ps`. Prefer `xmrts connect --username YOU --save-auth` and type it when asked, or pipe it with --password-stdin.",
            );
            cfg.password = Some(p.clone());
            super::ui::note("Password is saved as plain text. Only your user can read it.");
        }
        (Some(_), _, false) => {
            anyhow::bail!("Add --save-auth to save the password. Or skip --password.");
        }
        (None, Some(p), true) => {
            if cfg.username.is_none() {
                anyhow::bail!("Need a user name too. Pass --username or keep one saved.");
            }
            cfg.password = Some(p.to_string());
            super::ui::note("Password is saved as plain text. Only your user can read it.");
        }
        (None, Some(_), false) => {
            anyhow::bail!("Add --save-auth to save the password. Or skip --password-stdin.");
        }
        (None, None, true) => {
            if cfg.username.is_none() {
                anyhow::bail!("Need a user name too. Pass --username or keep one saved.");
            }
            let password = zeroize::Zeroizing::new(
                rpassword::prompt_password("RPC password: ")
                    .map_err(|e| anyhow::anyhow!("Password prompt failed: {e}"))?,
            );
            if password.is_empty() {
                anyhow::bail!("No password typed. Nothing saved.");
            }
            cfg.password = Some(password.to_string());
            super::ui::note("Password is saved as plain text. Only your user can read it.");
        }
        (None, None, false) => {}
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
    if let Some(p) = &args.proxy {
        cfg.proxy = Some(p.clone());
    }
    cfg.validate()
        .map_err(|e| anyhow::anyhow!("Settings look wrong: {e}"))?;

    if cfg.username.is_some() && cfg.password.is_none() {
        super::ui::note("User name is set but no password is saved. Calls go out bare.");
        super::ui::hint("Set one with: xmrts connect --username YOU --save-auth");
    }

    if cfg.is_remote() && !cfg.is_tls() {
        super::ui::warn("Remote wallet without TLS. Login and tx data travel openly.");
    }

    if let Some(d) = &cfg.daemon_endpoint {
        if let Some(w) = connection::insecure_daemon_warning(d) {
            super::ui::warn(&w);
        }
    }

    // Save first so settings stick even when the wallet is down.
    // The user can fix the wallet side and retry.
    let saved = connection::save_config(&cfg)?;
    super::ui::header("◆", "Connect");
    super::ui::ok(&format!("Saved to {}", saved.display()));
    super::ui::field("Network", &cfg.network);

    let client = cfg.client().map_err(|e| anyhow::anyhow!("{e}"))?;
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
            connection::display_url(&cfg.endpoint),
            sidecar_hint
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
        Ok(a) => super::ui::field("Address", &super::ui::short_address(&a)),
        Err(_) => super::ui::note("No address yet. Is a wallet open?"),
    }

    Ok(())
}

/// Password bytes from `--password-stdin`.
///
/// Strips one trailing newline (`\n`, or the `\r` in front of it) so a
/// piped secret and the same secret passed with `--password` land in the
/// config as the same string. Interior newlines stay. Empty input errors.
pub(crate) fn password_from_reader(mut reader: impl std::io::Read) -> Result<String> {
    let mut buf = Vec::new();
    reader
        .read_to_end(&mut buf)
        .context("Could not read the password from stdin")?;
    if buf.last() == Some(&b'\n') {
        buf.pop();
        if buf.last() == Some(&b'\r') {
            buf.pop();
        }
    }
    let password = String::from_utf8(buf).context("Password from stdin is not UTF-8")?;
    if password.is_empty() {
        anyhow::bail!("No password on stdin. Nothing saved.");
    }
    Ok(password)
}

#[cfg(test)]
mod tests {
    use super::password_from_reader;

    #[test]
    fn stdin_password_matches_flag_password() {
        let flag = "s3cret";
        assert_eq!(password_from_reader(flag.as_bytes()).unwrap(), flag);
        assert_eq!(password_from_reader(b"s3cret\n".as_slice()).unwrap(), flag);
        assert_eq!(
            password_from_reader(b"s3cret\r\n".as_slice()).unwrap(),
            flag
        );
    }

    #[test]
    fn stdin_password_keeps_interior_newlines_and_rejects_empty() {
        assert_eq!(password_from_reader(b"a\nb\n".as_slice()).unwrap(), "a\nb");
        assert!(password_from_reader(b"\n".as_slice()).is_err());
        assert!(password_from_reader(b"".as_slice()).is_err());
        assert!(password_from_reader(b"\xFFsecret".as_slice()).is_err());
    }
}
