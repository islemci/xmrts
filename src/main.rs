use anyhow::Result;
use clap::Parser;
use tracing_subscriber::EnvFilter;

use xmrts::cli::{Cli, Command};

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .init();
    let cli = Cli::parse();
    match &cli.command {
        Command::Init(args) => xmrts::cli::init::run(args),
        Command::Connect(args) => xmrts::cli::connect::run(args, cli.verbose, cli.stagenet).await,
        Command::Stamp(args) => xmrts::cli::stamp::run(args, cli.verbose, cli.stagenet).await,
        Command::Verify(args) => xmrts::cli::verify::run(args, cli.verbose, cli.stagenet).await,
        Command::Doctor(args) => xmrts::cli::doctor::run(args, cli.verbose, cli.stagenet).await,
        Command::Finalize(args) => xmrts::cli::finalize::run(args, cli.verbose, cli.stagenet).await,
        Command::Wallet(args) => xmrts::cli::wallet::run(args, cli.verbose).await,
        Command::Setting(args) => xmrts::cli::setting::run(args),
    }
}
