//! CLI orchestration: `init/connect/stamp/verify/doctor`.
//! Depends on protocol + wallet; neither depends back on CLI.

pub mod connect;
pub mod doctor;
pub mod finalize;
pub mod init;
pub mod pending;
pub mod setting;
pub mod stamp;
pub mod ui;
pub mod verify;
pub mod wallet;

use clap::{Parser, Subcommand};

#[derive(Debug, Parser)]
#[command(
    name = "xmrts",
    version,
    about = "Self-sovereign file timestamping on Monero"
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Command,
    /// Verbose output (also shows proof contents for verify).
    #[arg(long, global = true)]
    pub verbose: bool,
    /// Use stagenet for this invocation (overrides saved config; default is mainnet).
    /// Must be passed explicitly on every command that should touch stagenet.
    #[arg(long, global = true)]
    pub stagenet: bool,
}

#[derive(Debug, Subcommand)]
pub enum Command {
    /// Initialize local configuration.
    Init(init::InitArgs),
    /// Connect to monero-wallet-rpc.
    Connect(connect::ConnectArgs),
    /// Timestamp files (one transaction per invocation).
    Stamp(stamp::StampArgs),
    /// Verify a file against a .xmrts proof.
    Verify(verify::VerifyArgs),
    /// Diagnose the installation.
    Doctor(doctor::DoctorArgs),
    /// Finish a pending stamp into anchored proofs (no new transaction).
    Finalize(finalize::FinalizeArgs),
    /// Manage the monero-wallet-rpc sidecar (start/stop/status).
    Wallet(wallet::WalletArgs),
    /// Read and modify settings (price, currency, endpoint, ...).
    Setting(setting::SettingArgs),
}
