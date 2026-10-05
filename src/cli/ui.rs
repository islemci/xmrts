//! Small terminal UI: color with meaning, progress with restraint.
//!
//! Rules:
//! - Color means something only. Green is good. Red is bad.
//!   Yellow is pending or a warning. Blue is info. Nothing decorative.
//! - Short lines. Plain words. No em dashes.
//! - Motion only for slow work like hashing or waiting for a block.
//!   Fast work prints plain lines.
//! - Piped output stays clean. Spinners hide off TTY. NO_COLOR strips color.

use console::style;
use indicatif::{ProgressBar, ProgressStyle};
use std::sync::atomic::{AtomicBool, Ordering};

/// Global quiet flag for `--json` mode: human lines are suppressed and only
/// the JSON document reaches stdout. Set once per invocation.
static QUIET: AtomicBool = AtomicBool::new(false);

pub fn set_quiet(q: bool) {
    QUIET.store(q, Ordering::Relaxed);
}

fn quiet() -> bool {
    QUIET.load(Ordering::Relaxed)
}

/// Green check line. Use for done steps.
pub fn ok(message: &str) {
    if quiet() {
        return;
    }
    println!("{} {message}", style("✓").green().bold());
}

/// Red cross line. Use for failures.
pub fn fail(message: &str) {
    if quiet() {
        return;
    }
    println!("{} {message}", style("✗").red().bold());
}

/// Yellow circle line. Use for pending or skipped steps.
pub fn note(message: &str) {
    if quiet() {
        return;
    }
    println!("{} {message}", style("○").yellow());
}

/// Blue info line. Use for helpful facts.
pub fn info(message: &str) {
    if quiet() {
        return;
    }
    println!("{} {message}", style("ℹ").blue().bold());
}

/// Dim arrow line. Use for next steps.
/// Example: hint("Next: run `xmrts wallet open`.")
pub fn hint(message: &str) {
    if quiet() {
        return;
    }
    println!("{} {message}", style("→").dim());
}

/// Bold section title with a small icon.
/// Example: header("◆", "Wallet")
pub fn header(icon: &str, title: &str) {
    if quiet() {
        return;
    }
    println!();
    println!("{} {}", style(icon).cyan().bold(), style(title).bold());
}

/// Yellow warning to stderr.
pub fn warn(message: &str) {
    if quiet() {
        return;
    }
    eprintln!("{} {message}", style("!").yellow().bold());
}

/// Bold `label: value` line for summaries.
pub fn field(label: &str, value: &str) {
    if quiet() {
        return;
    }
    println!("{} {value}", style(format!("{label}:")).bold());
}

/// Shorten a long address for display: first 5 plus last 5.
/// Short inputs pass through untouched.
pub fn short_address(addr: &str) -> String {
    if addr.len() > 14 {
        format!("{}....{}", &addr[..5], &addr[addr.len() - 5..])
    } else {
        addr.to_string()
    }
}

/// Fetch the fiat suffix for an amount when estimates are on
/// (`setting set price true`). Returns `None` when off. Prints a short
/// note when the price feed is down. Never fails the command.
pub async fn fiat_for(
    atomic: u64,
    cfg: &crate::wallet::connection::WalletConfig,
) -> Option<String> {
    if !cfg.price {
        return None;
    }
    let currency = cfg.currency.as_deref().unwrap_or("usd");
    match crate::wallet::price::fiat_suffix(atomic, currency).await {
        Some(f) => Some(f),
        None => {
            note("Price feed is down. Showing XMR only.");
            None
        }
    }
}

/// Append a fiat suffix inline: `0.00003150 XMR (about 0.0153 EUR)`.
pub fn with_fiat(xmr: &str, fiat: Option<String>) -> String {
    match fiat {
        Some(f) => format!("{xmr} ({f})"),
        None => xmr.to_string(),
    }
}

/// Ping pong spinner frames. Loops back cleanly with no stutter.
fn tick_frames() -> &'static [&'static str] {
    &["·", "✢", "✳", "✶", "✻", "✽", "✻", "✶", "✳", "✢"]
}

fn styled_spinner() -> ProgressStyle {
    ProgressStyle::with_template("{spinner:.green} {msg}")
        .unwrap_or_else(|_| ProgressStyle::default_spinner())
        .tick_strings(tick_frames())
}

fn styled_bytes() -> ProgressStyle {
    ProgressStyle::with_template("{spinner:.green} {msg} [{bar:30.cyan/dim}] {bytes}/{total_bytes}")
        .unwrap_or_else(|_| ProgressStyle::default_bar())
        .tick_strings(tick_frames())
        .progress_chars("##-")
}

/// A spinner for slow work. Hidden off TTY so pipes stay clean.
/// Finish with [`done`] or [`abandon`].
pub fn spinner(message: &str) -> ProgressBar {
    if !console::Term::stderr().is_term() {
        return ProgressBar::hidden();
    }
    let bar = ProgressBar::new_spinner();
    bar.set_style(styled_spinner());
    bar.set_message(message.to_string());
    bar.enable_steady_tick(std::time::Duration::from_millis(80));
    bar
}

/// A byte progress bar of known total. Hidden off TTY.
pub fn bytes_bar(message: &str, total_bytes: u64) -> ProgressBar {
    if !console::Term::stderr().is_term() {
        return ProgressBar::hidden();
    }
    let bar = ProgressBar::new(total_bytes);
    bar.set_style(styled_bytes());
    bar.set_message(message.to_string());
    bar
}

/// Finish a spinner or bar with a green check line.
pub fn done(bar: &ProgressBar, message: &str) {
    bar.finish_and_clear();
    ok(message);
}

/// Stop a spinner or bar with no verdict. Caller prints its own line.
pub fn abandon(bar: &ProgressBar) {
    bar.finish_and_clear();
}

/// True when both stdin and stderr are terminals. Use to decide if a
/// prompt makes sense or if we should print plain steps instead.
pub fn is_interactive() -> bool {
    console::Term::stderr().is_term()
}

/// Read one keypress without needing Enter. Returns the key, or `None`
/// for Enter or Escape. Reads one line when input is piped.
fn read_key() -> Option<char> {
    let term = console::Term::stderr();
    if !term.is_term() {
        let mut line = String::new();
        if std::io::stdin().read_line(&mut line).is_err() {
            return None;
        }
        return line.trim().chars().next();
    }
    match term.read_key() {
        Ok(console::Key::Char(c)) => {
            println!("{c}");
            Some(c)
        }
        Ok(console::Key::Enter) => {
            println!();
            None
        }
        _ => {
            println!();
            None
        }
    }
}

/// Yes or no prompt with one keypress. `y` means yes. Enter means no.
/// Print the prompt as is, like `"Send now? [y/N] "`.
pub fn confirm(prompt: &str) -> anyhow::Result<bool> {
    use std::io::Write;
    print!("{prompt}");
    std::io::stdout().flush()?;
    match read_key() {
        Some('y') | Some('Y') => Ok(true),
        _ => Ok(false),
    }
}

/// Numbered choice with one keypress (`1` to `9`). Enter picks `default`.
/// Keeps asking until the key is valid.
pub fn choose_number(prompt: &str, count: usize, default: usize) -> anyhow::Result<usize> {
    use std::io::Write;
    loop {
        print!("{prompt}");
        std::io::stdout().flush()?;
        match read_key() {
            None => return Ok(default),
            Some(c) if c.is_ascii_digit() => {
                let n = (c as u8 - b'0') as usize;
                if n >= 1 && n <= count {
                    return Ok(n - 1);
                }
                println!("Pick 1 to {count}.");
            }
            _ => println!("Pick 1 to {count}."),
        }
    }
}
