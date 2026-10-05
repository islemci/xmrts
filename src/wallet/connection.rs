//! Wallet RPC connection configuration (spec: `connect`, `doctor`).
//! Default endpoint is loopback only; remote connections must be explicit
//! and trigger an insecure-transport warning when not TLS.

use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use thiserror::Error;

use crate::protocol::proof::Network;

pub const DEFAULT_ENDPOINT: &str = "http://127.0.0.1:18082";

#[derive(Debug, Error)]
pub enum ConnectionError {
    #[error("invalid endpoint '{0}': must be http(s)://host:port")]
    BadEndpoint(String),
    #[error(transparent)]
    Rpc(#[from] super::rpc::RpcError),
    #[error("I/O: {0}")]
    Io(#[from] std::io::Error),
    #[error("config: {0}")]
    Config(String),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WalletConfig {
    pub endpoint: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,
    /// Password is stored only if the user opts in; `connect --save-auth`
    /// is required. Never printed by any command.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub password: Option<String>,
    #[serde(default = "default_network")]
    pub network: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub daemon_endpoint: Option<String>,
    /// Explicit path to the `monero-wallet-rpc` binary for sidecar
    /// management (`xmrts wallet start`). Unset = autodetect at use time.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub wallet_rpc_path: Option<String>,
    /// Wallet directory passed as `--wallet-dir` when xmrts starts the
    /// sidecar. Unset = sidecar management disabled. This is a directory
    /// of wallet files, never a seed or key.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub wallet_dir: Option<String>,
    /// Show fiat estimates next to XMR amounts (`setting set price true`).
    #[serde(default)]
    pub price: bool,
    /// 3-letter fiat currency for estimates (`setting set currency eur`).
    /// Defaults to USD when unset.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub currency: Option<String>,
}

fn default_network() -> String {
    "mainnet".to_string()
}

impl Default for WalletConfig {
    fn default() -> Self {
        Self {
            endpoint: DEFAULT_ENDPOINT.to_string(),
            username: None,
            password: None,
            network: default_network(),
            daemon_endpoint: None,
            wallet_rpc_path: None,
            wallet_dir: None,
            price: false,
            currency: None,
        }
    }
}

impl WalletConfig {
    pub fn network_id(&self) -> Result<Network, ConnectionError> {
        Network::from_str(&self.network).map_err(|e| ConnectionError::Config(e.to_string()))
    }

    /// True when the endpoint is not loopback - caller must warn about
    /// non-TLS transport.
    pub fn is_remote(&self) -> bool {
        !endpoint_is_loopback(&self.endpoint)
    }

    pub fn is_tls(&self) -> bool {
        self.endpoint.to_ascii_lowercase().starts_with("https")
    }

    pub fn validate(&self) -> Result<(), ConnectionError> {
        if !(self.endpoint.starts_with("http://") || self.endpoint.starts_with("https://")) {
            return Err(ConnectionError::BadEndpoint(self.endpoint.clone()));
        }
        Network::from_str(&self.network).map_err(|e| ConnectionError::Config(e.to_string()))?;
        Ok(())
    }

    pub fn client(&self) -> super::rpc::WalletRpc {
        super::rpc::WalletRpc::new(
            self.endpoint.clone(),
            self.username.clone(),
            self.password.clone(),
        )
    }
}

/// True when a daemon/wallet endpoint URL points at loopback.
/// Parses the host exactly (L1 fix): `http://127.0.0.1.evil.com` is NOT
/// loopback. Handles `localhost`, `127.0.0.1`, `::1` (bracketed or not).
pub fn endpoint_is_loopback(endpoint: &str) -> bool {
    let rest = endpoint
        .strip_prefix("https://")
        .or_else(|| endpoint.strip_prefix("http://"))
        .unwrap_or(endpoint);
    // Strip userinfo, then cut at first '/', '?', '#'.
    let rest = rest.rsplit('@').next().unwrap_or(rest);
    let host_port = rest.split(['/', '?', '#']).next().unwrap_or(rest);
    // Strip port (but not for bracketed IPv6 without port... handle below).
    let host = if let Some(stripped) = host_port.strip_prefix('[') {
        stripped.split(']').next().unwrap_or(stripped)
    } else if host_port.matches(':').count() == 1 {
        host_port.split(':').next().unwrap_or(host_port)
    } else {
        host_port
    };
    let h = host.to_ascii_lowercase();
    h == "127.0.0.1" || h == "localhost" || h == "::1"
}

/// Platform config directory: `~/.config/xmrts` (Linux),
/// `~/Library/Application Support/xmrts` (macOS), `%APPDATA%\xmrts`
/// (Windows) - via the `directories` crate.
pub fn config_dir() -> Option<PathBuf> {
    directories::ProjectDirs::from("", "", "xmrts").map(|d| d.config_dir().to_path_buf())
}

pub fn config_file() -> Option<PathBuf> {
    config_dir().map(|d| d.join("config.toml"))
}

pub fn pending_dir() -> Option<PathBuf> {
    config_dir().map(|d| d.join("pending"))
}

/// Create config and pending dirs when missing. Safe to call often.
/// Returns the config dir.
pub fn ensure_dirs() -> anyhow::Result<PathBuf> {
    let Some(dir) = config_dir() else {
        anyhow::bail!("could not find a config folder on this system");
    };
    std::fs::create_dir_all(&dir)?;
    if let Some(pending) = pending_dir() {
        std::fs::create_dir_all(&pending)?;
    }
    Ok(dir)
}

pub fn load_config() -> WalletConfig {
    let Some(path) = config_file() else {
        return WalletConfig::default();
    };
    let Ok(text) = std::fs::read_to_string(&path) else {
        return WalletConfig::default();
    };
    toml::from_str(&text).unwrap_or_default()
}

pub fn save_config(cfg: &WalletConfig) -> Result<PathBuf, ConnectionError> {
    cfg.validate()?;
    let Some(dir) = config_dir() else {
        return Err(ConnectionError::Config("no config dir".into()));
    };
    std::fs::create_dir_all(&dir)?;
    let path = dir.join("config.toml");
    let text = toml::to_string_pretty(cfg).map_err(|e| ConnectionError::Config(e.to_string()))?;
    std::fs::write(&path, text)?;
    // The file may hold an RPC password: restrict to owner-only on Unix.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600));
    }
    Ok(path)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn loopback_detection_is_exact() {
        assert!(endpoint_is_loopback("http://127.0.0.1:18081"));
        assert!(endpoint_is_loopback("http://localhost:18081"));
        assert!(endpoint_is_loopback("https://localhost:18081/"));
        assert!(endpoint_is_loopback("http://[::1]:18081"));
        assert!(endpoint_is_loopback("http://127.0.0.1:18081/"));
        // L1: suffix tricks must NOT count as loopback.
        assert!(!endpoint_is_loopback("http://127.0.0.1.evil.com:18081"));
        assert!(!endpoint_is_loopback("http://localhost.evil.com:18081"));
        assert!(!endpoint_is_loopback("http://evil.com:18081"));
        assert!(!endpoint_is_loopback("http://192.168.1.1:18081"));
        // is_remote agrees.
        let cfg = WalletConfig {
            endpoint: "http://127.0.0.1.evil.com:18082".to_string(),
            ..WalletConfig::default()
        };
        assert!(cfg.is_remote());
        let cfg = WalletConfig {
            endpoint: "http://127.0.0.1:18082".to_string(),
            ..WalletConfig::default()
        };
        assert!(!cfg.is_remote());
    }
}
