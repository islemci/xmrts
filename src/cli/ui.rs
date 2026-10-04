//! Minimal terminal UI: semantic color + progress, restraint by default.
//!
//! Rules:
//! - Color carries meaning only: green ok, red failure, yellow pending /
//!   warning. No decorative color.
//! - Motion only for unknown durations (hashing, confirmation waits,
//!   network fetches). Instant operations print plain lines.
//! - Piped output and `NO_COLOR=1` degrade to today's plain text: spinners
//!   are hidden off-TTY, and `console` strips color codes automatically.

use console::style;
use indicatif::{ProgressBar, ProgressStyle};

/// Green `✓ message`.
pub fn ok(message: &str) {
    println!("{} {message}", style("✓").green().bold());
}

/// Red `✗ message`.
pub fn fail(message: &str) {
    println!("{} {message}", style("✗").red().bold());
}

/// Yellow `○ message` (pending / skipped / informational-negative).
pub fn note(message: &str) {
    println!("{} {message}", style("○").yellow());
}

/// Yellow `WARNING: message`.
pub fn warn(message: &str) {
    eprintln!("{} {message}", style("WARNING:").yellow().bold());
}

/// Bold `label: value` line for summaries.
pub fn field(label: &str, value: &str) {
    println!("{} {value}", style(format!("{label}:")).bold());
}

/// Shorten a long address for display: first 5 + `....` + last 5.
/// Short inputs pass through untouched.
pub fn short_address(addr: &str) -> String {
    if addr.len() > 14 {
        format!("{}....{}", &addr[..5], &addr[addr.len() - 5..])
    } else {
        addr.to_string()
    }
}

/// Fetch the fiat suffix for an amount when estimates are enabled
/// (`setting set price true`). Returns `None` when disabled, and prints
/// a one-line note (not an error) when the feed is unreachable.
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
            note("fiat estimate unavailable (price feed unreachable)");
            None
        }
    }
}

/// Append a fiat suffix inline: `0.00003150 XMR (≈ 0.0153 EUR)`.
pub fn with_fiat(xmr: &str, fiat: Option<String>) -> String {
    match fiat {
        Some(f) => format!("{xmr} ({f})"),
        None => xmr.to_string(),
    }
}

/// Ping-pong asterisk frames: interpunct out through the teardrop
/// asterisks and back. The loop seam restarts at `·`, so endpoints are
/// listed once (no double-frame stutter).
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

/// A spinner for an unknown-duration task. Hidden (no-op) off-TTY so
/// piped output stays clean. Finish with [`done`] or [`abandon`].
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

/// A byte progress bar of known total. Hidden off-TTY.
pub fn bytes_bar(message: &str, total_bytes: u64) -> ProgressBar {
    if !console::Term::stderr().is_term() {
        return ProgressBar::hidden();
    }
    let bar = ProgressBar::new(total_bytes);
    bar.set_style(styled_bytes());
    bar.set_message(message.to_string());
    bar
}

/// Finish a spinner/bar with a green check line.
pub fn done(bar: &ProgressBar, message: &str) {
    bar.finish_and_clear();
    ok(message);
}

/// Abandon a spinner/bar without a verdict (caller prints its own).
pub fn abandon(bar: &ProgressBar) {
    bar.finish_and_clear();
}

/// Read one keypress without requiring Enter. Returns the character, or
/// `None` for Enter / Escape / anything non-character. Falls back to a
/// line read when stdin is not a terminal (piped input, tests).
fn read_key() -> Option<char> {
    // NB: read_key always reads stdin; the Term only decides echo/output.
    // stderr keeps the prompt line intact when stdout is piped.
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
            // read_key doesn't echo: show what was pressed.
            println!("{c}");
            Some(c)
        }
        Ok(console::Key::Enter) => {
            println!();
            None
        }
        // Escape, arrows, unknown keys: treat as "no choice".
        _ => {
            println!();
            None
        }
    }
}

/// Yes/no prompt answered by a single keypress (`y` = yes, Enter = default
/// no). `prompt` is printed as-is, e.g. `"Broadcast transaction? [y/N] "`.
pub fn confirm(prompt: &str) -> anyhow::Result<bool> {
    use std::io::Write;
    print!("{prompt}");
    std::io::stdout().flush()?;
    match read_key() {
        Some('y') | Some('Y') => Ok(true),
        _ => Ok(false),
    }
}

/// Numbered choice answered by a single digit keypress (`1`-`9`), Enter
/// for `default` (0-based index). Retries invalid keys.
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
                println!("Enter 1–{count}.");
            }
            _ => println!("Enter 1–{count}."),
        }
    }
}
