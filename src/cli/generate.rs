//! `xmrts generate`. Emit shell completions or a man page to stdout.
//!
//! ```bash
//! xmrts generate --completions bash > ~/.bash_completion.d/xmrts
//! xmrts generate --completions zsh > ~/.zsh/completions/_xmrts
//! xmrts generate --completions fish > ~/.config/fish/completions/xmrts.fish
//! xmrts generate --man > xmrts.1 && man ./xmrts.1
//! ```

use anyhow::Result;
use clap::{Args, CommandFactory};
use std::io::Write;

use super::Cli;

#[derive(Debug, Args)]
pub struct GenerateArgs {
    /// Shell completion script: bash, zsh, fish, powershell, elvish.
    #[arg(long, conflicts_with = "man")]
    pub completions: Option<String>,
    /// Render the man page (section 1).
    #[arg(long, conflicts_with = "completions")]
    pub man: bool,
}

pub fn run(args: &GenerateArgs) -> Result<()> {
    match (args.completions.as_deref(), args.man) {
        (Some(name), false) => {
            let shell: clap_complete::Shell = name.parse().map_err(|_| {
                anyhow::anyhow!(
                    "Unknown shell '{name}'. Pick bash, zsh, fish, powershell or elvish."
                )
            })?;
            let mut cmd = Cli::command();
            let mut buf = Vec::new();
            clap_complete::generate(shell, &mut cmd, "xmrts", &mut buf);
            std::io::stdout().write_all(&buf)?;
        }
        (None, true) => {
            let cmd = Cli::command();
            let man = clap_mangen::Man::new(cmd);
            let mut buf = Vec::new();
            man.render(&mut buf)?;
            std::io::stdout().write_all(&buf)?;
        }
        _ => {
            anyhow::bail!("Pass exactly one of --completions <shell> or --man.");
        }
    }
    Ok(())
}
