//! Managed `monero-wallet-rpc` sidecar (process lifecycle).
//!
//! xmrts can start/stop/health-check the wallet RPC as a child process,
//! configured via `init` (`wallet_rpc_path`, `wallet_dir`). Management
//! covers the *process only*: xmrts never opens wallets (that needs the
//! wallet password, which xmrts must never hold), so after `wallet start`
//! the user still opens a wallet themselves via `open_wallet`.
//!
//! Safety rules:
//! - Only loopback endpoints are managed. A sidecar binds locally; if the
//!   configured endpoint is remote, management is disabled (`NotManaged`).
//! - Status checks verify the pid really is our sidecar (binary name +
//!   our `--rpc-bind-port` in its command line) to survive pid reuse.
//! - Passwords never appear in logs, status output, or errors: display
//!   paths use [`SidecarConfig::redacted_args`].

use std::path::{Path, PathBuf};
use thiserror::Error;

use super::connection::WalletConfig;

#[derive(Debug, Error)]
pub enum ProcessError {
    #[error("sidecar not configured: {0}")]
    NotConfigured(String),
    #[error("binary not found: {0}")]
    BinaryNotFound(String),
    #[error("I/O: {0}")]
    Io(#[from] std::io::Error),
    #[error("config: {0}")]
    Config(String),
    #[error("wallet RPC did not become healthy in time")]
    Unhealthy,
}

/// Everything needed to run the sidecar, resolved from [`WalletConfig`].
#[derive(Debug, Clone)]
pub struct SidecarConfig {
    pub binary: PathBuf,
    pub wallet_dir: String,
    pub bind_port: u16,
    pub daemon_address: Option<String>,
    pub username: Option<String>,
    pub password: Option<String>,
    pub network_flag: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SidecarStatus {
    /// Management disabled (no wallet dir, remote endpoint, or no binary).
    NotManaged(String),
    /// No live sidecar behind our pidfile.
    Stopped,
    /// A live sidecar, but it does not answer RPC.
    Unhealthy(u32),
    /// A live sidecar answering RPC: pid + reported RPC version.
    Running {
        pid: u32,
        rpc_major: u32,
        rpc_minor: u32,
    },
}

/// Candidate binary locations, in priority order.
pub fn candidate_binaries() -> Vec<PathBuf> {
    let mut out = Vec::new();
    // Alongside the xmrts executable (release-archive layout).
    if let Ok(exe) = std::env::current_exe() {
        if let Some(dir) = exe.parent() {
            out.push(dir.join("monero-wallet-rpc"));
            #[cfg(windows)]
            out.push(dir.join("monero-wallet-rpc.exe"));
        }
    }
    // Previous manual-install location.
    out.push(PathBuf::from("/opt/monero/monero-wallet-rpc"));
    // PATH lookup entries (resolved by `find_on_path`).
    out.push(PathBuf::from("monero-wallet-rpc"));
    out
}

/// Resolve `monero-wallet-rpc` to an executable path: explicit config
/// first, then [`candidate_binaries`].
pub fn find_binary(explicit: Option<&str>) -> Result<PathBuf, ProcessError> {
    if let Some(p) = explicit {
        let path = PathBuf::from(p);
        if path.is_file() {
            return Ok(path);
        }
        return Err(ProcessError::BinaryNotFound(p.to_string()));
    }
    for cand in candidate_binaries() {
        if cand.components().count() > 1 && cand.is_file() {
            return Ok(cand);
        }
        if cand.components().count() == 1 {
            if let Some(found) = find_on_path(&cand) {
                return Ok(found);
            }
        }
    }
    Err(ProcessError::BinaryNotFound(
        "monero-wallet-rpc not found. Set it with `xmrts init --wallet-rpc-path <path>`"
            .to_string(),
    ))
}

fn find_on_path(name: &Path) -> Option<PathBuf> {
    let file = name.to_str()?;
    for dir in std::env::split_paths(&std::env::var_os("PATH")?) {
        let p = dir.join(file);
        if p.is_file() {
            return Some(p);
        }
        #[cfg(windows)]
        {
            let exe = dir.join(format!("{file}.exe"));
            if exe.is_file() {
                return Some(exe);
            }
        }
    }
    None
}

/// Ensure RPC credentials exist, generating them on first use.
///
/// Like Bitcoin Core's cookie auth: the username is stable (`xmrts`) and
/// the password is 48 random alphanumerics (no shell-special characters,
/// so it never needs quoting). Stored in the config file
/// (mode 0600, see `save_config`) and passed to the sidecar *and* used
/// for our own requests, so the user never needs to know, type, or
/// remember anything. Explicitly configured credentials are never
/// overwritten - only missing pieces are filled in.
/// Returns true when anything was generated.
pub fn ensure_credentials(cfg: &mut WalletConfig) -> bool {
    let mut generated = false;
    if cfg.username.is_none() {
        cfg.username = Some("xmrts".to_string());
        generated = true;
    }
    if cfg.password.is_none() {
        use rand::{distr::Alphanumeric, Rng};
        let password: String = rand::rng()
            .sample_iter(&Alphanumeric)
            .take(48)
            .map(char::from)
            .collect();
        cfg.password = Some(password);
        generated = true;
    }
    generated
}

/// Split `http(s)://host:port` into (host, port).
pub fn parse_endpoint(endpoint: &str) -> Result<(String, u16), ProcessError> {
    let rest = endpoint
        .strip_prefix("http://")
        .or_else(|| endpoint.strip_prefix("https://"))
        .ok_or_else(|| ProcessError::Config(format!("bad endpoint '{endpoint}'")))?;
    let rest = rest.trim_end_matches('/');
    let (host, port) = rest
        .rsplit_once(':')
        .ok_or_else(|| ProcessError::Config(format!("endpoint '{endpoint}' has no port")))?;
    if host.is_empty() {
        return Err(ProcessError::Config(format!("bad endpoint '{endpoint}'")));
    }
    // Strip brackets for IPv6 literals (bind uses the same form).
    let host = host.strip_prefix('[').unwrap_or(host);
    let host = host.strip_suffix(']').unwrap_or(host);
    let port: u16 = port
        .parse()
        .map_err(|_| ProcessError::Config(format!("bad port in '{endpoint}'")))?;
    Ok((host.to_string(), port))
}

fn is_loopback(host: &str) -> bool {
    let h = host.to_ascii_lowercase();
    h == "127.0.0.1" || h == "localhost" || h == "::1"
}

/// Strip `http(s)://` for `--daemon-address host:port`.
pub fn strip_scheme(url: &str) -> String {
    url.strip_prefix("https://")
        .or_else(|| url.strip_prefix("http://"))
        .unwrap_or(url)
        .trim_end_matches('/')
        .to_string()
}

/// Resolve a runnable sidecar from config, or report why management is
/// disabled. Never touches wallet passwords beyond carrying them.
pub fn resolve(cfg: &WalletConfig) -> Result<SidecarConfig, ProcessError> {
    let wallet_dir = cfg.wallet_dir.clone().ok_or_else(|| {
        ProcessError::NotConfigured(
            "No wallet folder set. Run `xmrts init --wallet-dir <folder>`".to_string(),
        )
    })?;
    let (host, port) = parse_endpoint(&cfg.endpoint)?;
    if !is_loopback(&host) {
        return Err(ProcessError::NotConfigured(format!(
            "Sidecar needs a local endpoint. {} is remote so control stays off",
            cfg.endpoint
        )));
    }
    let binary = find_binary(cfg.wallet_rpc_path.as_deref())?;
    let network_flag = match cfg.network.to_ascii_lowercase().as_str() {
        "stagenet" => Some("--stagenet".to_string()),
        "testnet" => Some("--testnet".to_string()),
        _ => None,
    };
    Ok(SidecarConfig {
        binary,
        wallet_dir,
        bind_port: port,
        daemon_address: cfg.daemon_endpoint.clone().map(|d| strip_scheme(&d)),
        username: cfg.username.clone(),
        password: cfg.password.clone(),
        network_flag,
    })
}

impl SidecarConfig {
    /// Real argv for spawning (contains the RPC password when configured).
    ///
    /// Known exposure (M3): the password travels as `--rpc-login=user:pass`
    /// on the child command line, readable by other local users via `ps` /
    /// `/proc/<pid>/cmdline` while the sidecar lives. The pinned
    /// monero-wallet-rpc build has no `--config-file` path for `rpc-login`,
    /// so argv is currently the only transport. Mitigations in place:
    /// loopback-only bind, 0600 config file, redacted display argv. Treat
    /// any local user as able to call the wallet RPC while it runs.
    pub fn spawn_args(&self) -> Vec<String> {
        let mut args = vec![
            format!("--wallet-dir={}", self.wallet_dir),
            format!("--rpc-bind-port={}", self.bind_port),
            "--rpc-bind-ip=127.0.0.1".to_string(),
        ];
        if let Some(d) = &self.daemon_address {
            args.push(format!("--daemon-address={d}"));
        }
        if let Some(flag) = &self.network_flag {
            args.push(flag.clone());
        }
        if let (Some(u), Some(p)) = (&self.username, &self.password) {
            args.push(format!("--rpc-login={u}:{p}"));
        }
        args
    }

    /// Display argv with the password redacted. Use this for all output.
    pub fn redacted_args(&self) -> Vec<String> {
        self.spawn_args()
            .into_iter()
            .map(|a| {
                if a.starts_with("--rpc-login=") {
                    "--rpc-login=<hidden>".to_string()
                } else {
                    a
                }
            })
            .collect()
    }

    pub fn pidfile() -> Option<PathBuf> {
        super::connection::config_dir().map(|d| d.join("monero-wallet-rpc.pid"))
    }

    pub fn logfile() -> Option<PathBuf> {
        super::connection::config_dir().map(|d| d.join("monero-wallet-rpc.log"))
    }
}

/// True when the command line looks like our sidecar: the wallet binary
/// plus our `--rpc-bind-port`. Guards against pid reuse.
pub fn cmdline_matches(cmd: &[String], port: u16) -> bool {
    let joined = cmd.join(" ");
    joined.contains("monero-wallet-rpc") && joined.contains(&format!("--rpc-bind-port={port}"))
}

fn read_pid() -> Option<u32> {
    let path = SidecarConfig::pidfile()?;
    std::fs::read_to_string(path).ok()?.trim().parse().ok()
}

fn refresh_all(sys: &mut sysinfo::System) {
    // Plain refresh_processes() leaves cmd/exe empty on some platforms
    // (notably macOS); request everything - identity checks need argv.
    sys.refresh_processes_specifics(
        sysinfo::ProcessesToUpdate::All,
        true,
        sysinfo::ProcessRefreshKind::everything(),
    );
}

fn process_cmdline(pid: u32) -> Option<Vec<String>> {
    use sysinfo::{Pid, System};
    let mut sys = System::new();
    refresh_all(&mut sys);
    let p = sys.process(Pid::from_u32(pid))?;
    Some(
        p.cmd()
            .iter()
            .map(|s| s.to_string_lossy().into_owned())
            .collect(),
    )
}

/// Any live wallet process bound to `port`, ours or not.
fn find_listener_pid(port: u16) -> Option<u32> {
    use sysinfo::{get_current_pid, System};
    let mut sys = System::new();
    refresh_all(&mut sys);
    let me = get_current_pid().ok();
    for (pid, proc) in sys.processes() {
        if me.is_some_and(|m| m == *pid) {
            continue;
        }
        let cmd: Vec<String> = proc
            .cmd()
            .iter()
            .map(|s| s.to_string_lossy().into_owned())
            .collect();
        if cmdline_matches(&cmd, port) {
            return Some(pid.as_u32());
        }
    }
    None
}

/// Check status without changing anything. `endpoint` is the configured
/// wallet RPC URL (for health checks); `port` selects our sidecar.
pub async fn status(cfg: &WalletConfig, client: &super::rpc::WalletRpc) -> SidecarStatus {
    let sidecar = match resolve(cfg) {
        Ok(s) => s,
        Err(ProcessError::NotConfigured(reason)) => return SidecarStatus::NotManaged(reason),
        Err(_) => return SidecarStatus::NotManaged("sidecar unresolvable".to_string()),
    };
    let Some(pid) = read_pid() else {
        // No pidfile, but something foreign may still hold the port.
        if let Some(foreign) = find_listener_pid(sidecar.bind_port) {
            return SidecarStatus::Unhealthy(foreign);
        }
        return SidecarStatus::Stopped;
    };
    match process_cmdline(pid) {
        Some(cmd) if cmdline_matches(&cmd, sidecar.bind_port) => {}
        // Stale pidfile. Check for a foreign holder before saying stopped.
        _ => {
            if let Some(foreign) = find_listener_pid(sidecar.bind_port) {
                return SidecarStatus::Unhealthy(foreign);
            }
            return SidecarStatus::Stopped;
        }
    }
    match client.get_version().await {
        Ok((maj, min)) => SidecarStatus::Running {
            pid,
            rpc_major: maj,
            rpc_minor: min,
        },
        Err(e) if e.is_auth_failure() => {
            // Our pid answers but rejects our login. It kept an old login
            // (monero stores it next to the binary) or someone changed it.
            SidecarStatus::Unhealthy(pid)
        }
        Err(_) => SidecarStatus::Unhealthy(pid),
    }
}

/// Start the sidecar (no-op when already running). Returns the pid.
/// Provisions RPC credentials first (see [`ensure_credentials`]) so the
/// spawned process and our own health checks share them; the user never
/// needs to know them. Never opens a wallet: opening needs the wallet
/// password, which xmrts must not hold.
pub async fn start(cfg: &mut WalletConfig) -> Result<u32, ProcessError> {
    // Check before touching config. A live holder stays live, so never
    // regen creds or spawn into an occupied port.
    let _ = resolve(cfg)?;
    let probe = cfg.client();
    match status(cfg, &probe).await {
        SidecarStatus::Running { pid, .. } => return Ok(pid),
        SidecarStatus::Unhealthy(pid) => {
            return Err(ProcessError::Config(format!(
                "Port holds a wallet (pid {pid}) that does not answer us. Stop it first, then retry"
            )));
        }
        _ => {}
    }
    // Backstop: something answers that status could not attribute
    // (e.g. a non wallet process on the port). A 401 means it uses a
    // different login. Only a refused connection means the port is free.
    match probe.get_version().await {
        Ok(_) => {
            return Err(ProcessError::Config(format!(
                "Something else already answers at {}. Stop it first or keep using it",
                cfg.endpoint
            )));
        }
        Err(e) if e.is_auth_failure() => {
            return Err(ProcessError::Config(format!(
                "Something else answers at {} with a different login. Stop it first, then retry",
                cfg.endpoint
            )));
        }
        Err(_) => {}
    }
    if ensure_credentials(cfg) {
        super::connection::save_config(cfg).map_err(|e| ProcessError::Config(e.to_string()))?;
        println!("Made fresh RPC login for the sidecar. Saved locally.");
    }
    let client = cfg.client();
    let sidecar = resolve(cfg)?;
    let log_path = SidecarConfig::logfile()
        .ok_or_else(|| ProcessError::Config("no config dir".to_string()))?;
    if let Some(parent) = log_path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let log = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&log_path)?;
    let mut cmd = std::process::Command::new(&sidecar.binary);
    cmd.args(sidecar.spawn_args())
        .stdin(std::process::Stdio::null())
        .stdout(log.try_clone()?)
        .stderr(log);
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        cmd.creation_flags(0x00000008); // DETACHED_PROCESS
    }
    let child = cmd.spawn()?;
    let pid = child.id();
    // Intentionally do not wait: the sidecar outlives xmrts. (Unix note:
    // it shares xmrts's session, so closing the terminal may stop it;
    // run under tmux/a service for permanence.)
    std::mem::forget(child);
    if let Some(pf) = SidecarConfig::pidfile() {
        std::fs::write(pf, pid.to_string())?;
    }
    // Wait for health (generous: first start loads the binary cold).
    // Keep the last error so the timeout does not hide the real cause.
    let mut last_err = String::from("no attempts made");
    for _ in 0..30 {
        tokio::time::sleep(std::time::Duration::from_millis(500)).await;
        match client.get_version().await {
            Ok(_) => return Ok(pid),
            Err(e) => last_err = e.to_string(),
        }
    }
    // The spawn failed to come up. Drop a stale pidfile pointing at the
    // dead child so later runs see the true state.
    if !process_cmdline(pid).is_some_and(|cmd| cmdline_matches(&cmd, sidecar.bind_port)) {
        if let Some(pf) = SidecarConfig::pidfile() {
            let ours = std::fs::read_to_string(&pf)
                .ok()
                .is_some_and(|s| s.trim() == pid.to_string());
            if ours {
                let _ = std::fs::remove_file(pf);
            }
        }
    }
    let log_hint = SidecarConfig::logfile()
        .map(|p| format!(" See {}", p.display()))
        .unwrap_or_default();
    Err(ProcessError::Config(format!(
        "Wallet RPC stayed quiet. Last error: {last_err}.{log_hint}"
    )))
}

/// Stop our sidecar (SIGTERM, then SIGKILL after a grace period).
/// Refuses to touch foreign pids.
pub fn stop(cfg: &WalletConfig) -> Result<String, ProcessError> {
    let sidecar = resolve(cfg)?;
    let Some(pid) = read_pid() else {
        return Ok("Sidecar is not running.".to_string());
    };
    use sysinfo::{Pid, Signal, System};
    let mut sys = System::new();
    refresh_all(&mut sys);
    let sys_pid = Pid::from_u32(pid);
    match sys.process(sys_pid) {
        Some(p)
            if cmdline_matches(
                &p.cmd()
                    .iter()
                    .map(|s| s.to_string_lossy().into_owned())
                    .collect::<Vec<_>>(),
                sidecar.bind_port,
            ) => {}
        _ => {
            // Stale pidfile or foreign process: clear the file, touch nothing.
            if let Some(pf) = SidecarConfig::pidfile() {
                let _ = std::fs::remove_file(pf);
            }
            return Ok("Found a stale pid file. Cleared it.".to_string());
        }
    }
    let proc = match sys.process(sys_pid) {
        // Vanished between the check above and now: already stopped.
        None => {
            if let Some(pf) = SidecarConfig::pidfile() {
                let _ = std::fs::remove_file(pf);
            }
            return Ok(format!("Sidecar (pid {pid}) already stopped."));
        }
        Some(p) => p,
    };
    let _ = proc.kill_with(Signal::Term);
    for _ in 0..20 {
        std::thread::sleep(std::time::Duration::from_millis(500));
        refresh_all(&mut sys);
        if sys.process(sys_pid).is_none() {
            break;
        }
    }
    if let Some(p) = sys.process(sys_pid) {
        let _ = p.kill();
    }
    if let Some(pf) = SidecarConfig::pidfile() {
        let _ = std::fs::remove_file(pf);
    }
    Ok(format!("Sidecar (pid {pid}) stopped."))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generates_credentials_without_clobbering() {
        let mut cfg = WalletConfig::default();
        assert!(ensure_credentials(&mut cfg));
        assert_eq!(cfg.username.as_deref(), Some("xmrts"));
        let first = cfg.password.clone().unwrap();
        assert_eq!(first.len(), 48); // 48 random alphanumerics
        assert!(first.chars().all(|c| c.is_ascii_alphanumeric()));
        // Second call: nothing changes.
        assert!(!ensure_credentials(&mut cfg));
        assert_eq!(cfg.password.as_deref(), Some(first.as_str()));
        // Explicit credentials are never overwritten.
        let mut cfg2 = WalletConfig {
            username: Some("mine".to_string()),
            password: Some("mine-pass".to_string()),
            ..WalletConfig::default()
        };
        assert!(!ensure_credentials(&mut cfg2));
        assert_eq!(cfg2.username.as_deref(), Some("mine"));
        // Randomness: two fresh generations differ.
        let mut a = WalletConfig::default();
        let mut b = WalletConfig::default();
        ensure_credentials(&mut a);
        ensure_credentials(&mut b);
        assert_ne!(a.password, b.password);
    }

    #[test]
    fn parses_endpoints() {
        assert_eq!(
            parse_endpoint("http://127.0.0.1:18082").unwrap(),
            ("127.0.0.1".to_string(), 18082)
        );
        assert_eq!(
            parse_endpoint("https://localhost:38082/").unwrap(),
            ("localhost".to_string(), 38082)
        );
        assert!(parse_endpoint("notaurl").is_err());
        assert!(parse_endpoint("http://127.0.0.1").is_err());
    }

    #[test]
    fn redacts_password_everywhere() {
        let sc = SidecarConfig {
            binary: PathBuf::from("/x/monero-wallet-rpc"),
            wallet_dir: "/w".to_string(),
            bind_port: 18082,
            daemon_address: None,
            username: Some("u".to_string()),
            password: Some("SUPERSECRET".to_string()),
            network_flag: None,
        };
        let shown = sc.redacted_args().join(" ");
        assert!(!shown.contains("SUPERSECRET"));
        assert!(shown.contains("--rpc-login=<hidden>"));
        // The real argv still carries it (needed to start the process).
        assert!(sc.spawn_args().join(" ").contains("SUPERSECRET"));
    }

    #[test]
    fn matches_own_cmdline_only() {
        let good = vec![
            "/opt/monero/monero-wallet-rpc".to_string(),
            "--wallet-dir=/w".to_string(),
            "--rpc-bind-port=18082".to_string(),
        ];
        assert!(cmdline_matches(&good, 18082));
        assert!(!cmdline_matches(&good, 18083));
        assert!(!cmdline_matches(&["/usr/bin/other".to_string()], 18082));
    }

    #[test]
    fn resolve_needs_wallet_dir() {
        let cfg = WalletConfig::default();
        assert!(matches!(resolve(&cfg), Err(ProcessError::NotConfigured(_))));
    }
}
