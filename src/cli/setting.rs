//! `xmrts setting` — read and modify config from the CLI.
//!
//! ```text
//! xmrts setting list
//! xmrts setting get currency
//! xmrts setting set price true
//! xmrts setting set currency eur
//! xmrts setting unset daemon
//! ```
//!
//! The wallet RPC *login* password is deliberately not settable here:
//! `setting set` would leak it into shell history. Use
//! `xmrts connect --username USER --password PASS --save-auth`.
//! Passwords are never printed (shown as `<hidden>`).

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
    /// Show all settings (password never printed).
    List,
    /// Show one setting.
    Get {
        /// Setting name: price, currency, endpoint, daemon, network,
        /// wallet-dir, wallet-rpc-path, username
        key: String,
    },
    /// Change one setting.
    Set {
        /// Setting name (see get).
        key: String,
        /// New value.
        value: String,
    },
    /// Clear an optional setting back to unset.
    Unset {
        /// Setting name: currency, daemon, wallet-dir, wallet-rpc-path, username
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
            .unwrap_or_else(|| "(unset)".to_string()),
        "network" => cfg.network.clone(),
        "wallet-dir" => cfg
            .wallet_dir
            .clone()
            .unwrap_or_else(|| "(unset)".to_string()),
        "wallet-rpc-path" => cfg
            .wallet_rpc_path
            .clone()
            .unwrap_or_else(|| "(autodetect)".to_string()),
        "username" => cfg
            .username
            .clone()
            .unwrap_or_else(|| "(unset)".to_string()),
        "password" => "(hidden)".to_string(),
        _ => anyhow::bail!("unknown setting '{key}'"),
    })
}

fn apply_set(cfg: &mut WalletConfig, key: &str, value: &str) -> Result<()> {
    match key {
        "price" => {
            cfg.price = value.parse().map_err(|_| {
                anyhow::anyhow!("price wants true/false, got '{value}'")
            })?;
        }
        "currency" => {
            if !crate::wallet::price::is_valid_currency(value) {
                anyhow::bail!("currency wants 3 letters (e.g. usd), got '{value}'");
            }
            cfg.currency = Some(value.to_ascii_lowercase());
        }
        "endpoint" => {
            cfg.endpoint = value.to_string();
            cfg.validate()
                .map_err(|e| anyhow::anyhow!("rejected: {e}"))?;
        }
        "daemon" => {
            cfg.daemon_endpoint = Some(value.to_string());
        }
        "network" => {
            crate::protocol::proof::Network::from_str(value)
                .map_err(|e| anyhow::anyhow!("rejected: {e}"))?;
            cfg.network = value.to_ascii_lowercase();
        }
        "wallet-dir" => cfg.wallet_dir = Some(value.to_string()),
        "wallet-rpc-path" => cfg.wallet_rpc_path = Some(value.to_string()),
        "username" => cfg.username = Some(value.to_string()),
        "password" => anyhow::bail!(
            "refusing: `setting set` would leak the password into shell history.\nUse `xmrts connect --username USER --password PASS --save-auth` instead."
        ),
        _ => anyhow::bail!("unknown setting '{key}'"),
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
            anyhow::bail!("'{key}' is required and cannot be unset")
        }
        _ => anyhow::bail!("unknown setting '{key}'"),
    }
    Ok(())
}

pub fn run(args: &SettingArgs) -> Result<()> {
    let mut cfg = connection::load_config();
    match &args.command {
        SettingCommand::List => {
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
                println!("{key} = {}", describe(&cfg, key)?);
            }
        }
        SettingCommand::Get { key } => {
            println!("{}", describe(&cfg, key)?);
        }
        SettingCommand::Set { key, value } => {
            apply_set(&mut cfg, key, value)?;
            let saved = connection::save_config(&cfg)?;
            println!("{key} = {}", describe(&cfg, key)?);
            println!("Saved {}", saved.display());
        }
        SettingCommand::Unset { key } => {
            apply_unset(&mut cfg, key)?;
            let saved = connection::save_config(&cfg)?;
            println!("{key} = {}", describe(&cfg, key)?);
            println!("Saved {}", saved.display());
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
