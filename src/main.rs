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
    let result = match &cli.command {
        Command::Init(args) => xmrts::cli::init::run(args),
        Command::Connect(args) => xmrts::cli::connect::run(args, cli.verbose, cli.stagenet).await,
        Command::Stamp(args) => xmrts::cli::stamp::run(args, cli.verbose, cli.stagenet)
            .await
            .map(|_stamped| ()),
        Command::Verify(args) => xmrts::cli::verify::run(args, cli.verbose, cli.stagenet).await,
        Command::Audit(args) => xmrts::cli::audit::run(args, cli.verbose, cli.stagenet).await,
        Command::Doctor(args) => xmrts::cli::doctor::run(args, cli.verbose, cli.stagenet).await,
        Command::Finalize(args) => xmrts::cli::finalize::run(args, cli.verbose, cli.stagenet).await,
        Command::Queue(args) => xmrts::cli::queue::run(args, cli.verbose, cli.stagenet).await,
        Command::Watch(args) => xmrts::cli::watch::run(args, cli.verbose, cli.stagenet).await,
        Command::Pending(args) => xmrts::cli::pending::run(args),
        Command::Generate(args) => xmrts::cli::generate::run(args),
        Command::Wallet(args) => xmrts::cli::wallet::run(args, cli.verbose).await,
        Command::Setting(args) => xmrts::cli::setting::run(args),
        Command::Stats(args) => xmrts::cli::stats::run(args),
    };
    // Every failure ends with the red cross on stderr. In `--json` mode
    // stdout must also carry a JSON error document (automation parses
    // stdout; humans read stderr). Commands that already printed their
    // own JSON error exit directly via `fail_exit_json`, so this covers
    // the `anyhow::bail!` paths like `stamp --json` with a missing file.
    if let Err(e) = result {
        let msg = format!("{e:#}");
        xmrts::cli::ui::fail(&msg);
        if xmrts::cli::ui::is_quiet() {
            println!(
                "{}",
                serde_json::to_string(&serde_json::json!({"ok": false, "error": msg}))
                    .unwrap_or_else(|_| "{}".into())
            );
        }
        std::process::exit(1);
    }
    Ok(())
}
