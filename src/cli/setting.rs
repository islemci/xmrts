//! `xmrts setting`. View and change settings.
//!
//! ```text
//! xmrts setting list
//! xmrts setting get currency
//! xmrts setting set price true
//! xmrts setting set currency eur
//! xmrts setting unset daemon
//! ```
//!
//! Wallet login password stays out of here.
//! Setting it here would leak it to shell history. Use
//! `xmrts connect --username YOU --password PASS --save-auth`.
//! Passwords show as hidden. Never printed.

use anyhow::Result;
use clap::{Args, Subcommand};

use crate::wallet::connection::{self, WalletConfig};

#[derive(Debug, Args)]
pub struct SettingArgs {
    #[command(subcommand)]
    pub command: SettingCommand,
}

#[derive(Debug, Subcommand)]
pub enum SettingCommand {
    /// Show all settings (password stays hidden).
    List,
    /// Show one setting.
    Get {
        /// Name: price, currency, endpoint, daemon, network,
        /// wallet-dir, wallet-rpc-path, username
        key: String,
    },
    /// Change one setting.
    Set {
        /// Name (see get).
        key: String,
        /// New value.
        value: String,
    },
    /// Clear an optional setting.
    Unset {
        /// Name: currency, daemon, wallet-dir, wallet-rpc-path, username
        key: String,
    },
}

fn describe(cfg: &WalletConfig, key: &str) -> Result<String> {
    Ok(match key {
        "price" => cfg.price.to_string(),
        "currency" => cfg.currency.clone().unwrap_or_else(|| "usd".to_string()),
        "endpoint" => cfg.endpoint.clone(),
        "daemon" => cfg
            .daemon_endpoint
            .clone()
            .unwrap_or_else(|| "(empty)".to_string()),
        "network" => cfg.network.clone(),
        "wallet-dir" => cfg
            .wallet_dir
            .clone()
            .unwrap_or_else(|| "(empty)".to_string()),
        "wallet-rpc-path" => cfg
            .wallet_rpc_path
            .clone()
            .unwrap_or_else(|| "(auto)".to_string()),
        "username" => cfg
            .username
            .clone()
            .unwrap_or_else(|| "(empty)".to_string()),
        "password" => "(hidden)".to_string(),
        _ => anyhow::bail!("Unknown setting '{key}'. Try `xmrts setting list`"),
    })
}

fn apply_set(cfg: &mut WalletConfig, key: &str, value: &str) -> Result<()> {
    match key {
        "price" => {
            cfg.price = value.parse().map_err(|_| {
                anyhow::anyhow!("Price wants true or false. Got '{value}'")
            })?;
        }
        "currency" => {
            if !crate::wallet::price::is_valid_currency(value) {
                anyhow::bail!("Currency wants 3 letters like usd. Got '{value}'");
            }
            cfg.currency = Some(value.to_ascii_lowercase());
        }
        "endpoint" => {
            cfg.endpoint = value.to_string();
            cfg.validate()
                .map_err(|e| anyhow::anyhow!("Not using that: {e}"))?;
        }
        "daemon" => {
            cfg.daemon_endpoint = Some(value.to_string());
        }
        "network" => {
            crate::protocol::proof::Network::from_str(value)
                .map_err(|e| anyhow::anyhow!("Not using that: {e}"))?;
            cfg.network = value.to_ascii_lowercase();
        }
        "wallet-dir" => cfg.wallet_dir = Some(value.to_string()),
        "wallet-rpc-path" => cfg.wallet_rpc_path = Some(value.to_string()),
        "username" => cfg.username = Some(value.to_string()),
        "password" => anyhow::bail!(
            "Use connect for passwords.\nRun `xmrts connect --username YOU --password PASS --save-auth`"
        ),
        _ => anyhow::bail!("Unknown setting '{key}'. Try `xmrts setting list`"),
    }
    Ok(())
}

fn apply_unset(cfg: &mut WalletConfig, key: &str) -> Result<()> {
    match key {
        "currency" => cfg.currency = None,
        "daemon" => cfg.daemon_endpoint = None,
        "wallet-dir" => cfg.wallet_dir = None,
        "wallet-rpc-path" => cfg.wallet_rpc_path = None,
        "username" => {
            cfg.username = None;
            cfg.password = None;
        }
        "price" | "endpoint" | "network" => {
            anyhow::bail!("'{key}' must stay set. Cannot clear it")
        }
        _ => anyhow::bail!("Unknown setting '{key}'. Try `xmrts setting list`"),
    }
    Ok(())
}

pub fn run(args: &SettingArgs) -> Result<()> {
    let _ = connection::ensure_dirs();
    let mut cfg = connection::load_config();
    match &args.command {
        SettingCommand::List => {
            super::ui::header("◆", "Settings");
            for key in [
                "price",
                "currency",
                "endpoint",
                "daemon",
                "network",
                "wallet-dir",
                "wallet-rpc-path",
                "username",
                "password",
            ] {
                super::ui::field(key, &describe(&cfg, key)?);
            }
        }
        SettingCommand::Get { key } => {
            println!("{}", describe(&cfg, key)?);
        }
        SettingCommand::Set { key, value } => {
            apply_set(&mut cfg, key, value)?;
            let saved = connection::save_config(&cfg)?;
            super::ui::ok(&format!("{key} is now {}", describe(&cfg, key)?));
            super::ui::hint(&format!("Saved to {}", saved.display()));
        }
        SettingCommand::Unset { key } => {
            apply_unset(&mut cfg, key)?;
            let saved = connection::save_config(&cfg)?;
            super::ui::ok(&format!("{key} cleared."));
            super::ui::hint(&format!("Saved to {}", saved.display()));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validates_values() {
        let mut cfg = WalletConfig::default();
        assert!(apply_set(&mut cfg, "price", "yes").is_err());
        apply_set(&mut cfg, "price", "true").unwrap();
        assert!(cfg.price);
        assert!(apply_set(&mut cfg, "currency", "usdd").is_err());
        apply_set(&mut cfg, "currency", "EUR").unwrap();
        assert_eq!(cfg.currency.as_deref(), Some("eur"));
        assert!(apply_set(&mut cfg, "password", "x").is_err());
        assert!(apply_set(&mut cfg, "bogus", "x").is_err());
        assert!(apply_set(&mut cfg, "network", "bogus").is_err());
    }
}
