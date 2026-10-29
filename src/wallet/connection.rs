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
    /// HTTP/SOCKS proxy for daemon and price-feed traffic, e.g.
    /// `socks5h://127.0.0.1:9050` for Tor. Loopback endpoints (wallet RPC
    /// on 127.0.0.1/localhost/::1, local daemons) always bypass the proxy:
    /// wallet `open_wallet` carries the wallet password and must never go
    /// through a (possibly remote) proxy, and Tor cannot reach loopback.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub proxy: Option<String>,
    /// Close the wallet in the sidecar when `stamp` finishes, releasing
    /// the wallet files so the Monero GUI (or anything else) can open
    /// them. `finalize`/`watch`/`verify` never need an open wallet.
    /// Old configs predate the field and default to true.
    #[serde(default = "default_autoclose")]
    pub autoclose: bool,
    /// On-chain commitment encoding: `bare` (default, random-looking
    /// 32-byte nonce) or `magic` (legacy XMRTS-tagged payload for
    /// tooling that scans for it). Readers accept both either way.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub commitment: Option<String>,
    /// 3-letter fiat currency for estimates (`setting set currency eur`).
    /// Defaults to USD when unset.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub currency: Option<String>,
    /// Send a developer donation equal to the transaction fee with each
    /// stamp (`setting set donate true`, or `y` at `xmrts init`). Off by
    /// default. The donation rides in the same transaction as the
    /// timestamp self-send; mainnet only.
    #[serde(default)]
    pub donate: bool,
}

fn default_network() -> String {
    "mainnet".to_string()
}

fn default_autoclose() -> bool {
    true
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
            proxy: None,
            autoclose: default_autoclose(),
            commitment: None,
            donate: false,
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
            // Error text can end up in terminals/logs; endpoints may carry
            // embedded credentials (see `parse_endpoint`).
            return Err(ConnectionError::BadEndpoint(display_url(&self.endpoint)));
        }
        if let Some(d) = &self.daemon_endpoint {
            if !(d.starts_with("http://") || d.starts_with("https://")) {
                return Err(ConnectionError::BadEndpoint(display_url(d)));
            }
        }
        if let Some(p) = &self.proxy {
            if !is_valid_proxy(p) {
                return Err(ConnectionError::Config(format!(
                    "bad proxy '{p}': want socks5h://, socks5://, http:// or https:// URL"
                )));
            }
        }
        if let Some(c) = &self.commitment {
            if c != "bare" && c != "magic" {
                return Err(ConnectionError::Config(format!(
                    "bad commitment '{c}': want bare or magic"
                )));
            }
        }
        Network::from_str(&self.network).map_err(|e| ConnectionError::Config(e.to_string()))?;
        Ok(())
    }

    pub fn client(&self) -> Result<super::rpc::WalletRpc, ConnectionError> {
        super::rpc::WalletRpc::new(
            self.endpoint.clone(),
            self.username.clone(),
            self.password.clone(),
            self.proxy.clone(),
        )
        .map_err(ConnectionError::Rpc)
    }
}

/// True for proxy URLs reqwest can use: socks5h (remote DNS, prefer for
/// Tor), socks5, http, https.
pub fn is_valid_proxy(url: &str) -> bool {
    ["socks5h://", "socks5://", "http://", "https://"]
        .iter()
        .any(|s| url.to_ascii_lowercase().starts_with(s))
}

/// Effective proxy for an endpoint: `None` for loopback endpoints (never
/// proxy local wallet/daemon traffic), otherwise the configured proxy when
/// valid. Testable without building a reqwest client.
pub fn effective_proxy(endpoint: Option<&str>, proxy: Option<&str>) -> Option<String> {
    if let Some(ep) = endpoint {
        if endpoint_is_loopback(ep) {
            return None;
        }
    }
    proxy.filter(|p| is_valid_proxy(p)).map(String::from)
}

/// Base HTTP client builder honoring the *saved* proxy setting, if any.
/// The proxy applies to daemon and price-feed traffic only. When `endpoint`
/// is a loopback URL the proxy is skipped: local wallet RPC (which can
/// carry the `open_wallet` password) must never go through a proxy, and a
/// proxy (local Tor or remote) cannot or should not carry loopback traffic.
/// Callers set their own timeout on top.
pub fn http_client_builder_for(endpoint: Option<&str>) -> reqwest::ClientBuilder {
    let mut b = reqwest::Client::builder();
    let cfg = load_config();
    if let Some(proxy) = effective_proxy(endpoint, cfg.proxy.as_deref()) {
        match reqwest::Proxy::all(&proxy) {
            Ok(p) => b = b.proxy(p),
            Err(e) => tracing::warn!(
                proxy = %proxy,
                error = %e,
                "saved proxy could not be applied; traffic will go direct"
            ),
        }
    }
    // Daemon, wallet-side HTTP and price clients never follow redirects.
    // A 30x from the daemon would carry the POST body — tx hashes at
    // least, and with decode_as_json the marked-commitment queries — to
    // whatever the Location header says, and reqwest's default follows
    // up to ten hops. Monero RPC APIs answer in place; fail closed.
    // (Verified: api.coingecko.com answers 200 with zero redirects, so
    // the price feed needs no redirect tolerance either.)
    b = b.redirect(reqwest::redirect::Policy::none());
    b
}

/// Backwards-compatible builder without endpoint context: applies the proxy
/// (used for remote-only traffic such as the price feed).
pub fn http_client_builder() -> reqwest::ClientBuilder {
    http_client_builder_for(None)
}

/// True when a daemon/wallet endpoint URL points at loopback.
/// Parses the host exactly (L1 fix): `http://127.0.0.1.evil.com` is NOT
/// loopback. Handles `localhost`, `127.0.0.1`, `::1` (bracketed or not).
pub fn endpoint_is_loopback(endpoint: &str) -> bool {
    let rest = endpoint
        .strip_prefix("https://")
        .or_else(|| endpoint.strip_prefix("http://"))
        .unwrap_or(endpoint);
    // Cut the authority at the first '/', '?', or '#' BEFORE stripping
    // userinfo: `@` in the path/query/fragment is not a userinfo
    // separator. The old `rsplit('@')`-over-everything order let
    // `http://evil.com/x@127.0.0.1` and `http://evil.com/?a=@localhost`
    // count as loopback.
    let authority = rest.split(['/', '?', '#']).next().unwrap_or(rest);
    let host_port = authority.rsplit('@').next().unwrap_or(authority);
    // Strip port. Bracketed IPv6 (`[::1]` / `[::1]:port`) needs care:
    // only treat `[...]` as brackets when the remainder is empty or a
    // `:port`; `[::1].evil.com` is a hostname, not loopback.
    let host = if let Some(after_bracket) = host_port.strip_prefix('[') {
        match after_bracket.find(']') {
            Some(end) => {
                let inside = &after_bracket[..end];
                let rest = &after_bracket[end + 1..];
                if rest.is_empty() || rest.starts_with(':') {
                    inside
                } else {
                    host_port
                }
            }
            None => host_port,
        }
    } else if host_port.matches(':').count() == 1 {
        host_port.split(':').next().unwrap_or(host_port)
    } else {
        host_port
    };
    let h = host.to_ascii_lowercase();
    h == "127.0.0.1" || h == "localhost" || h == "::1"
}

/// Redact `user:pass@` userinfo from a URL for display.
///
/// Endpoints may carry embedded RPC credentials (saved config, pasted
/// `--daemon` values), and URL text gets echoed into error messages,
/// `doctor`, `setting list` and JSON documents that end up in CI logs
/// and paste-backs. Keeps the scheme, host, port and any path/query/
/// fragment; hides everything up to the last `@` in the authority.
/// URLs without userinfo pass through unchanged.
///
/// Also scrubs userinfo hidden inside the string, like a query value
/// carrying a redirect target (`?next=http://u:p@node`) — those would
/// otherwise print verbatim through the same echo paths. A real
/// authority never contains '&', '=', ';', ',', ' ', '(' or ')', so the
/// scan ends the authority on them without ever splitting a host:port.
pub fn display_url(url: &str) -> String {
    let mut out = String::with_capacity(url.len());
    let mut i = 0;
    while i < url.len() {
        let Some(offset) = url[i..].find("://") else {
            // No scheme at all (common user typo, e.g. pasting a bare
            // `user:pass@host:port`). The text is still effectively an
            // authority, so redact userinfo exactly like the scheme case
            // instead of echoing the tail verbatim.
            let tail = &url[i..];
            let authority_end = tail
                .find(['/', '?', '#', ' ', '&', '=', '+', ',', ';', '(', ')'])
                .unwrap_or(tail.len());
            let authority = &tail[..authority_end];
            match authority.rfind('@') {
                // Keep the trailing '@' and host tail: the endpoint stays
                // identifiable, matching the scheme case below.
                Some(at) => {
                    out.push_str("<hidden>");
                    out.push_str(&authority[at..]);
                }
                None => out.push_str(authority),
            }
            out.push_str(&tail[authority_end..]);
            return out;
        };
        let scheme_end = i + offset + 3;
        out.push_str(&url[i..scheme_end]);
        let rest = &url[scheme_end..];
        let authority_end = rest
            .find(['/', '?', '#', ' ', '&', '=', '+', ',', ';', '(', ')'])
            .unwrap_or(rest.len());
        let authority = &rest[..authority_end];
        match authority.rfind('@') {
            Some(at) => {
                // Keep the trailing '@' and the host tail: quorum errors
                // and daemon identity must stay identifiable.
                out.push_str("<hidden>");
                out.push_str(&authority[at..]);
            }
            None => out.push_str(authority),
        }
        i = scheme_end + authority_end;
    }
    out
}

/// Warning text when a daemon endpoint is remote without TLS, or `None`
/// when the transport is loopback or TLS. Callers print it via `ui::warn`
/// and (for `--json` modes) include it in their warnings array so
/// automation sees it too. The daemon URL is redacted: callers echo this
/// text straight into logs and warnings.
pub fn insecure_daemon_warning(daemon: &str) -> Option<String> {
    if daemon.to_ascii_lowercase().starts_with("http://") && !endpoint_is_loopback(daemon) {
        Some(format!(
            "Daemon {} is remote without TLS. A network attacker could lie about the chain.",
            display_url(daemon)
        ))
    } else {
        None
    }
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

/// Create config and pending dirs when missing (mode 0700 on Unix).
/// Safe to call often. Returns the config dir.
pub fn ensure_dirs() -> anyhow::Result<PathBuf> {
    let Some(dir) = config_dir() else {
        anyhow::bail!("could not find a config folder on this system");
    };
    create_dir_0700(&dir)?;
    if let Some(pending) = pending_dir() {
        create_dir_0700(&pending)?;
    }
    Ok(dir)
}

#[cfg(unix)]
fn create_dir_0700(dir: &std::path::Path) -> std::io::Result<()> {
    use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
    let mut b = std::fs::DirBuilder::new();
    b.recursive(true).mode(0o700);
    // Propagate errors: a config dir that cannot be created (read-only
    // $HOME, permission denied) must fail loudly, not silently run with
    // no config.
    b.create(dir)?;
    // Harden pre-existing dirs too (cheap, idempotent).
    std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))?;
    Ok(())
}

#[cfg(not(unix))]
fn create_dir_0700(dir: &std::path::Path) -> std::io::Result<()> {
    std::fs::create_dir_all(dir)
}

/// Atomic owner-only file write (M3): temp file with mode 0600 at creation
/// (no umask race), `fsync`, then `rename`. The temp file lives in the same
/// directory so the rename is atomic on one filesystem.
pub fn atomic_write_0600(path: &std::path::Path, bytes: &[u8]) -> std::io::Result<()> {
    use std::io::Write;
    let Some(parent) = path.parent() else {
        return Err(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            "no parent dir",
        ));
    };
    std::fs::create_dir_all(parent)?;
    // Retry a few times on a create_new collision (pid+nanos name): a
    // hostile or stuck directory could otherwise make every write fail.
    // Anything other than AlreadyExists propagates immediately.
    let mut last_err = None;
    for _ in 0..5 {
        let tmp = parent.join(format!(
            ".tmp-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        ));
        let write_result = (|| -> std::io::Result<()> {
            #[cfg(unix)]
            {
                use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
                let mut f = std::fs::OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .mode(0o600)
                    .open(&tmp)?;
                f.write_all(bytes)?;
                f.sync_all()?;
                drop(f);
                let _ = std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o600));
            }
            #[cfg(not(unix))]
            {
                let mut f = std::fs::OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .open(&tmp)?;
                f.write_all(bytes)?;
                f.sync_all()?;
                drop(f);
            }
            if let Err(e) = std::fs::rename(&tmp, path) {
                let _ = std::fs::remove_file(&tmp);
                return Err(e);
            }
            Ok(())
        })();
        match write_result {
            Ok(()) => {
                // Best-effort dir fsync so the rename survives a crash.
                if let Ok(d) = std::fs::File::open(parent) {
                    let _ = d.sync_all();
                }
                return Ok(());
            }
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                last_err = Some(e);
                continue;
            }
            Err(e) => return Err(e),
        }
    }
    Err(last_err.unwrap_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::AlreadyExists,
            "temp file name collision",
        )
    }))
}

pub fn load_config() -> WalletConfig {
    let Some(path) = config_file() else {
        return WalletConfig::default();
    };
    load_config_from(&path)
}

/// Read one config file. A missing file is a normal "not configured yet"
/// state and is silent; a file that exists but cannot be read or parsed
/// must NOT silently look like a fresh default (a wiped 0600 config
/// would otherwise reset `network` to mainnet and `stamp` would run on
/// the wrong chain). Warn, name the file, and fall back to defaults so
/// the CLI still works; the operator sees why in the log output.
fn load_config_from(path: &std::path::Path) -> WalletConfig {
    let text = match std::fs::read_to_string(path) {
        Ok(text) => text,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            // Not configured yet: normal state, stay silent.
            return WalletConfig::default();
        }
        Err(e) => {
            tracing::warn!(
                file = %path.display(),
                error = %e,
                "existing config file is unreadable; using defaults"
            );
            return WalletConfig::default();
        }
    };
    match toml::from_str(&text) {
        Ok(cfg) => cfg,
        Err(e) => {
            tracing::warn!(
                file = %path.display(),
                error = %e,
                "config file is not valid TOML; using defaults"
            );
            WalletConfig::default()
        }
    }
}

pub fn save_config(cfg: &WalletConfig) -> Result<PathBuf, ConnectionError> {
    cfg.validate()?;
    let Some(dir) = config_dir() else {
        return Err(ConnectionError::Config("no config dir".into()));
    };
    create_dir_0700(&dir).map_err(ConnectionError::Io)?;
    let path = dir.join("config.toml");
    let text = toml::to_string_pretty(cfg).map_err(|e| ConnectionError::Config(e.to_string()))?;
    // Owner-only from creation: no umask race window (M3).
    atomic_write_0600(&path, text.as_bytes()).map_err(ConnectionError::Io)?;
    Ok(path)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};

    /// Buffer collecting everything tracing writes during a capture run.
    #[derive(Clone)]
    struct Capture(Arc<Mutex<Vec<u8>>>);
    impl tracing_subscriber::fmt::MakeWriter<'_> for Capture {
        type Writer = CaptureWriter;
        fn make_writer(&self) -> CaptureWriter {
            CaptureWriter(self.0.clone())
        }
    }
    struct CaptureWriter(Arc<Mutex<Vec<u8>>>);
    impl std::io::Write for CaptureWriter {
        fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(b);
            Ok(b.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    /// Run `f` with tracing warnings captured into a string, so tests can
    /// assert that a warning actually fired and what it said.
    fn capture_warnings(f: impl FnOnce()) -> String {
        let inner = Arc::new(Mutex::new(Vec::new()));
        let subscriber = tracing_subscriber::fmt()
            .with_max_level(tracing::Level::WARN)
            .with_writer(Capture(inner.clone()))
            .without_time()
            .finish();
        tracing::subscriber::with_default(subscriber, f);
        let bytes = inner.lock().unwrap().clone();
        String::from_utf8_lossy(&bytes).into_owned()
    }

    fn config_identity(cfg: &WalletConfig) -> (String, String) {
        (cfg.endpoint.clone(), cfg.network.clone())
    }

    #[test]
    fn corrupt_config_warns_and_falls_back_to_defaults() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        std::fs::write(&path, b"endp[oint = certainly not toml\n").unwrap();
        let log = capture_warnings(|| {
            let cfg = load_config_from(&path);
            assert_eq!(
                config_identity(&cfg),
                config_identity(&WalletConfig::default())
            );
        });
        assert!(log.contains("not valid TOML"), "log was: {log}");
        assert!(log.contains("config.toml"), "log must name the file: {log}");
    }

    #[test]
    fn missing_config_is_still_silent() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("does-not-exist.toml");
        let log = capture_warnings(|| {
            let cfg = load_config_from(&path);
            assert_eq!(
                config_identity(&cfg),
                config_identity(&WalletConfig::default())
            );
        });
        assert!(log.is_empty(), "a missing config must not warn: {log}");
    }

    #[test]
    fn unreadable_config_warns_and_defaults() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        std::fs::write(&path, b"endpoint = \"http://127.0.0.1:18082\"\n").unwrap();
        // Strip every permission bit to force a read failure on Unix.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o000)).unwrap();
        }
        let log = capture_warnings(|| {
            let cfg = load_config_from(&path);
            assert_eq!(
                config_identity(&cfg),
                config_identity(&WalletConfig::default())
            );
        });
        assert!(log.contains("unreadable"), "log was: {log}");
    }

    #[test]
    fn valid_config_loads_without_warning() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        std::fs::write(&path, b"endpoint = \"http://127.0.0.1:18082\"\n").unwrap();
        let log = capture_warnings(|| {
            let cfg = load_config_from(&path);
            assert_eq!(cfg.endpoint, "http://127.0.0.1:18082");
        });
        assert!(log.is_empty(), "a valid config must not warn: {log}");
    }

    #[test]
    fn loopback_detection_is_exact() {
        assert!(endpoint_is_loopback("http://127.0.0.1:18081"));
        assert!(endpoint_is_loopback("http://localhost:18081"));
        assert!(endpoint_is_loopback("https://localhost:18081/"));
        assert!(endpoint_is_loopback("http://[::1]:18081"));
        assert!(endpoint_is_loopback("http://127.0.0.1:18081/"));
        // Genuine userinfo still counts as loopback.
        assert!(endpoint_is_loopback("http://user:pass@127.0.0.1:18081"));
        assert!(endpoint_is_loopback("http://user@localhost:18081/json_rpc"));
        // L1: suffix tricks must NOT count as loopback.
        assert!(!endpoint_is_loopback("http://127.0.0.1.evil.com:18081"));
        assert!(!endpoint_is_loopback("http://localhost.evil.com:18081"));
        assert!(!endpoint_is_loopback("http://evil.com:18081"));
        assert!(!endpoint_is_loopback("http://192.168.1.1:18081"));
        // `@` in path/query/fragment is NOT userinfo: all remote.
        assert!(!endpoint_is_loopback("http://evil.com/x@127.0.0.1"));
        assert!(!endpoint_is_loopback("http://evil.com/?a=@localhost"));
        assert!(!endpoint_is_loopback("https://evil.example/@[::1]"));
        assert!(!endpoint_is_loopback("http://evil.com/#@127.0.0.1"));
        assert!(!endpoint_is_loopback(
            "http://evil.com:18081/path@127.0.0.1"
        ));
        // Host itself is still exact.
        assert!(!endpoint_is_loopback("http://evil.com:18081"));
        assert!(!endpoint_is_loopback("http://[::1].evil.com:18081"));
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

    #[test]
    fn loopback_endpoints_bypass_proxy() {
        let proxy = Some("socks5h://127.0.0.1:9050");
        assert_eq!(effective_proxy(Some("http://127.0.0.1:18082"), proxy), None);
        assert_eq!(effective_proxy(Some("http://localhost:18082"), proxy), None);
        assert_eq!(effective_proxy(Some("http://[::1]:18082"), proxy), None);
        assert_eq!(effective_proxy(Some("http://127.0.0.1:18081"), proxy), None);
        // Remote endpoints keep the proxy; invalid proxies are dropped.
        assert_eq!(
            effective_proxy(Some("http://node.example:18081"), proxy),
            Some("socks5h://127.0.0.1:9050".to_string())
        );
        assert_eq!(
            effective_proxy(Some("http://node.example:18081"), Some("bogus")),
            None
        );
        assert_eq!(effective_proxy(None, proxy), proxy.map(String::from));
    }

    #[test]
    fn validates_proxy_urls() {
        assert!(is_valid_proxy("socks5h://127.0.0.1:9050"));
        assert!(is_valid_proxy("socks5://127.0.0.1:9050"));
        assert!(is_valid_proxy("http://proxy:8080"));
        assert!(is_valid_proxy("https://proxy:8080"));
        assert!(!is_valid_proxy("proxy:8080"));
        assert!(!is_valid_proxy("ftp://proxy:21"));
        assert!(!is_valid_proxy(""));
        let mut cfg = WalletConfig {
            proxy: Some("bogus".to_string()),
            ..WalletConfig::default()
        };
        assert!(cfg.validate().is_err());
        cfg.proxy = Some("socks5h://127.0.0.1:9050".to_string());
        assert!(cfg.validate().is_ok());
    }

    #[test]
    fn autoclose_defaults_to_true() {
        assert!(WalletConfig::default().autoclose);
        // Old configs without the field still parse, defaulting to true.
        let cfg: WalletConfig = toml::from_str("endpoint = \"http://127.0.0.1:18082\"").unwrap();
        assert!(cfg.autoclose);
    }

    #[test]
    fn endpoint_validation_error_redacts_credentials() {
        let err = WalletConfig {
            endpoint: "stamp:topsecretpw@host:18081".to_string(),
            ..WalletConfig::default()
        }
        .validate()
        .expect_err("missing scheme must fail");
        assert!(!err.to_string().contains("topsecretpw"));
        assert!(!err.to_string().contains("stamp:"));
        let err = WalletConfig {
            endpoint: "http://127.0.0.1:18082".to_string(),
            daemon_endpoint: Some("node:hunter2@example:18081".to_string()),
            ..WalletConfig::default()
        }
        .validate()
        .expect_err("daemon must fail");
        assert!(!err.to_string().contains("hunter2"));
        assert!(!err.to_string().contains("node:"));
    }

    #[test]
    #[cfg(unix)]
    fn atomic_write_is_owner_only() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("secret.toml");
        atomic_write_0600(&path, b"password = 1").unwrap();
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(
            mode, 0o600,
            "config/pending files must be 0600, got {mode:o}"
        );
        assert_eq!(std::fs::read(&path).unwrap(), b"password = 1");
        // Overwrite stays atomic + 0600.
        atomic_write_0600(&path, b"password = 2").unwrap();
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
        assert_eq!(std::fs::read(&path).unwrap(), b"password = 2");
    }

    #[test]
    fn display_url_hides_embedded_credentials() {
        assert_eq!(
            display_url("http://stamp:topsecretpw@127.0.0.1:18082"),
            "http://<hidden>@127.0.0.1:18082"
        );
        // Path, query and fragment survive the redaction.
        assert_eq!(
            display_url("https://u:p@node.example/x?y=1#frag"),
            "https://<hidden>@node.example/x?y=1#frag"
        );
        // Last '@' in the authority wins, so weird userinfo still hides it all.
        assert_eq!(
            display_url("https://u@p@node.example"),
            "https://<hidden>@node.example"
        );
        // Portless hosts and userinfo-only credentials.
        assert_eq!(display_url("http://bob@monerod"), "http://<hidden>@monerod");
        // Non-http URLs (proxies) get the same treatment.
        assert_eq!(
            display_url("socks5h://tor:hunter2@127.0.0.1:9050"),
            "socks5h://<hidden>@127.0.0.1:9050"
        );
    }

    #[test]
    fn display_url_scrubs_credentials_inside_query_values() {
        // A redirect target or callback URL carrying its own credentials
        // would print verbatim: the echo paths must scrub the inner
        // userinfo too, not just the outermost authority.
        assert_eq!(
            display_url("http://h.example/?next=http://secret:o@x.example"),
            "http://h.example/?next=http://<hidden>@x.example"
        );
        assert_eq!(
            display_url("http://h.example/?cb=https://a:b@c.example&x=1"),
            "http://h.example/?cb=https://<hidden>@c.example&x=1"
        );
        // Plain query values with no userinfo shape stay readable; an
        // '@' in a path or query value is not credentials.
        assert_eq!(
            display_url("http://h.example/?token=abc123&u=x@y"),
            "http://h.example/?token=abc123&u=x@y"
        );
    }

    #[test]
    fn display_url_leaves_plain_urls_untouched() {
        assert_eq!(
            display_url("http://127.0.0.1:18082"),
            "http://127.0.0.1:18082"
        );
        assert_eq!(
            display_url("https://node.example:18081"),
            "https://node.example:18081"
        );
        // '@' in the path is not userinfo: nothing to hide.
        assert_eq!(
            display_url("http://node.example/x@y"),
            "http://node.example/x@y"
        );
        // No scheme, no userinfo shape: pass through as-is.
        assert_eq!(display_url("127.0.0.1:18082"), "127.0.0.1:18082");
        // No scheme but credential-shaped (common paste typo): the
        // bare `user:pass@host` must redact exactly like scheme'd URLs,
        // because validate()/parse_endpoint errors echo these strings.
        assert_eq!(
            display_url("stamp:topsecretpw@host:18081"),
            "<hidden>@host:18081"
        );
        // Multi-'@' authority matches the URL parser's split: everything
        // before the last '@' is userinfo, so all of it is hidden while
        // the effective host stays visible for quorum identification.
        assert_eq!(
            display_url("http://a@evil.example:80@real.example"),
            "http://<hidden>@real.example"
        );
    }

    #[test]
    fn insecure_daemon_warning_redacts_credentials() {
        let w = insecure_daemon_warning("http://u:secret@node.example:18081")
            .expect("remote plain http must warn");
        assert!(w.contains("<hidden>"), "{w}");
        assert!(!w.contains("secret"), "{w}");
        // Loopback plain http stays quiet.
        assert!(insecure_daemon_warning("http://u:secret@127.0.0.1:18081").is_none());
    }
}
