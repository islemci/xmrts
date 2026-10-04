//! Fiat estimates for XMR amounts via CoinGecko (optional, off by default).
//!
//! Enable with `xmrts setting set price true`, pick any 3-letter fiat
//! with `xmrts setting set currency eur` (default USD). A failed price
//! fetch degrades to XMR-only display — it never fails the operation.

use thiserror::Error;

#[derive(Debug, Error)]
pub enum PriceError {
    #[error("price feed unreachable: {0}")]
    Unreachable(String),
    #[error("bad currency code '{0}': want 3 letters, e.g. usd")]
    BadCurrency(String),
    #[error("price feed returned no {0} price for monero")]
    MissingPrice(String),
}

/// True for 3-letter alphabetic codes (`usd`, `EUR`, ...).
pub fn is_valid_currency(code: &str) -> bool {
    code.len() == 3 && code.chars().all(|c| c.is_ascii_alphabetic())
}

/// Normalize for display + API (`Eur` -> `eur`).
pub fn normalize_currency(code: &str) -> String {
    code.to_ascii_lowercase()
}

/// Current XMR price in `currency` units (per 1 XMR).
pub async fn xmr_price(currency: &str) -> Result<f64, PriceError> {
    let cur = normalize_currency(currency);
    if !is_valid_currency(&cur) {
        return Err(PriceError::BadCurrency(currency.to_string()));
    }
    let url =
        format!("https://api.coingecko.com/api/v3/simple/price?ids=monero&vs_currencies={cur}");
    // CoinGecko's firewall rejects requests without a descriptive
    // User-Agent (HTTP 403), so identify honestly.
    let resp: serde_json::Value = reqwest::Client::new()
        .get(&url)
        .header(
            reqwest::header::USER_AGENT,
            format!(
                "xmrts/{} (monero file timestamping CLI)",
                env!("CARGO_PKG_VERSION")
            ),
        )
        .timeout(std::time::Duration::from_secs(10))
        .send()
        .await
        .map_err(|e| PriceError::Unreachable(e.to_string()))?
        .json()
        .await
        .map_err(|e| PriceError::Unreachable(e.to_string()))?;
    resp.get("monero")
        .and_then(|m| m.get(&cur))
        .and_then(|p| p.as_f64())
        .ok_or(PriceError::MissingPrice(cur))
}

/// Render `≈ <fiat> <CODE>` for an atomic-unit amount, or `None` when the
/// feed is unreachable (callers fall back to XMR-only).
pub async fn fiat_suffix(atomic: u64, currency: &str) -> Option<String> {
    let price = xmr_price(currency).await.ok()?;
    Some(format_fiat(atomic as f64 / 1e12 * price, currency))
}

/// Format a fiat value with precision that survives dust amounts:
/// 2 decimals at/above 1 unit, 4 below, 6 for anything smaller (a fee
/// worth €0.015 must not render as zero). Trailing zeros trimmed, keeping
/// at least 2 decimals.
pub fn format_fiat(value: f64, currency: &str) -> String {
    let code = currency.to_ascii_uppercase();
    let decimals = if value >= 1.0 {
        2
    } else if value >= 0.01 {
        4
    } else {
        6
    };
    let mut s = format!("{value:.decimals$}");
    if decimals > 2 {
        while s.ends_with('0') && s.split('.').nth(1).is_some_and(|f| f.len() > 2) {
            s.pop();
        }
    }
    format!("≈ {s} {code}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validates_currency_codes() {
        assert!(is_valid_currency("usd"));
        assert!(is_valid_currency("EUR"));
        assert!(!is_valid_currency("us"));
        assert!(!is_valid_currency("usdd"));
        assert!(!is_valid_currency("u5d"));
        assert!(!is_valid_currency(""));
    }

    #[test]
    fn formats_small_values_without_rounding_to_zero() {
        assert_eq!(format_fiat(123.456, "usd"), "≈ 123.46 USD");
        assert_eq!(format_fiat(0.0153, "usd"), "≈ 0.0153 USD");
        assert_eq!(format_fiat(0.0042, "usd"), "≈ 0.0042 USD");
        assert_eq!(format_fiat(0.0000153, "usd"), "≈ 0.000015 USD");
    }
}
