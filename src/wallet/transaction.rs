//! Timestamp transaction preparation/broadcast/status (spec §10 steps 5-8).
//! All signing happens inside `monero-wallet-rpc`. xmrts only supplies the
//! `extra` commitment hex and a self-send destination.

use serde_json::Value;
use thiserror::Error;

use super::rpc::{self, Destination, TransferResult, WalletRpc};

/// Address that receives the optional developer donation. The donation
/// rides in the same transaction as the timestamp self-send, sized to
/// the fee. Mainnet only: the address is a mainnet one, so stagenet and
/// testnet stamps skip donations (monero-wallet-rpc rejects
/// cross-network destinations).
pub const DONATION_ADDRESS: &str = "851YMCyZXDKiJu7ckZdREfg5WmGGJgG37CjVvDT4Ds6W8joEXzV2DgSRpjX6cVKKKeMnsAYieKPRCN9wHC93Dj7SNbqJPxc";

#[derive(Debug, Error)]
pub enum TxError {
    #[error(transparent)]
    Rpc(#[from] rpc::RpcError),
    #[error("wallet has no usable address (open a wallet first)")]
    NoAddress,
    #[error("transaction rejected: {0}")]
    Rejected(String),
}

pub struct PreparedTx {
    pub extra_hex: String,
    pub destination: Destination,
}

/// Build a self-send destination for the timestamp tx. Amount is the
/// smallest non-dust self-payment; the wallet deducts the fee on top.
pub fn prepare_self_send(address: String, amount_atomic: u64) -> PreparedTx {
    PreparedTx {
        extra_hex: String::new(), // filled by caller via commitment
        destination: Destination {
            address,
            amount: amount_atomic,
        },
    }
}

/// True when the signed tx blob hex contains our commitment bytes.
/// The commitment (`extra_hex`) is appended verbatim to `tx_extra` inside
/// the serialized transaction, so a substring check on the blob is enough
/// to prove the wallet honored `extra`. Case-insensitive (wallets return
/// lowercase hex, but be liberal).
pub fn tx_blob_contains_extra(tx_blob_hex: &str, extra_hex: &str) -> bool {
    // Fail closed: an empty `extra_hex` would make `contains` vacuously
    // true for every blob, turning this mark gate into a no-op. Callers
    // derive the hex from a 32-byte commitment today; future callers
    // must get the same fail-closed behavior, not a silent pass.
    if extra_hex.is_empty() {
        return false;
    }
    tx_blob_hex
        .to_ascii_lowercase()
        .contains(&extra_hex.to_ascii_lowercase())
}

/// Build the timestamp tx once (`do_not_relay`) and run the mark gates.
/// Returns the wallet result and the relay payload. Used by both the
/// plain flow and the donation flow's rebuild passes, so the mark
/// checks are never skipped on either path.
///
/// Robust patched-build gate: besides the RPC-version hint checked by
/// callers, the signed tx *blob* (`tx_hex`) is inspected for our
/// commitment bytes before anything is relayed. A stock wallet silently
/// ignores the `extra` key and would otherwise spend a fee with no mark;
/// a future stock release that bumps the RPC minor past 31 would also
/// pass a version-only check. The blob check fails closed in both cases.
///
/// NOTE: `relay_tx` parses its `hex` argument as serialized transaction
/// *metadata* (`tx_metadata`), not the raw transaction blob. Passing the
/// blob fails with `-27: Failed to parse txmetadata`.
async fn build_marked(
    rpc_client: &WalletRpc,
    destinations: Vec<Destination>,
    extra_hex: &str,
    priority: u32,
) -> Result<(TransferResult, String), TxError> {
    let (res, raw) =
        rpc::transfer_with_extra(rpc_client, destinations, extra_hex, true, true, priority).await?;
    // Definitive mark check on the blob (not the opaque metadata): the
    // wallet must have embedded our commitment in the signed tx. Stock
    // Monero names the field `tx_blob`; accept `tx_hex` too (some builds).
    let blob = raw
        .get("tx_hex")
        .or_else(|| raw.get("tx_blob"))
        .and_then(Value::as_str);
    if let Some(blob) = blob {
        if !tx_blob_contains_extra(blob, extra_hex) {
            return Err(TxError::Rejected(
                "Wallet built the tx without our mark (`extra` missing from tx blob). \
                Stock monero-wallet-rpc ignores `extra`; install the patched build (see README: Managed sidecar). \
                Nothing was relayed and no fee was spent."
                    .to_string(),
            ));
        }
    } else {
        // `get_tx_hex=true` was requested: no blob means we cannot prove
        // the mark. Fail closed rather than risk a mark-less relay. The
        // response keys are included so a wallet returning a new shape is
        // diagnosable instead of a dead end.
        let keys = response_keys(&raw);
        return Err(TxError::Rejected(format!(
            "Wallet did not return the signed tx blob (`tx_hex`/`tx_blob`; response keys: {keys}); cannot verify the mark. \
            Nothing was relayed."
        )));
    }
    // relay_tx consumes tx_metadata (not the blob), and both come from the
    // same constructed tx in one `transfer` call — but they are different
    // encodings, so verify the mark in the metadata too. A wallet that
    // embeds the mark in the blob yet drops it from the relay payload
    // would otherwise spend a fee with no anchor. Fail closed: nothing
    // has been relayed at this point.
    if let Some(meta) = raw.get("tx_metadata").and_then(Value::as_str) {
        if !tx_blob_contains_extra(meta, extra_hex) {
            return Err(TxError::Rejected(
                "Wallet built the tx without our mark (`extra` missing from tx metadata). \
                Nothing was relayed and no fee was spent."
                    .to_string(),
            ));
        }
    }
    // relay_tx consumes tx_metadata (not the blob); fall back to tx_hex.
    let tx_hex = raw
        .get("tx_metadata")
        .or_else(|| raw.get("tx_hex"))
        .and_then(Value::as_str)
        .ok_or_else(|| {
            let keys = response_keys(&raw);
            TxError::Rejected(format!(
                "wallet did not return tx metadata (response keys: {keys})"
            ))
        })?
        .to_string();
    Ok((res, tx_hex))
}

/// Compact `response keys: ...` text for diagnostics.
fn response_keys(raw: &Value) -> String {
    raw.as_object()
        .map(|o| o.keys().map(String::as_str).collect::<Vec<_>>().join(", "))
        .unwrap_or_else(|| "<non-object>".to_string())
}

/// Preview the timestamp transaction without relaying it
/// (`do_not_relay` + metadata). Returns the wallet's fee quote and the
/// transaction metadata hex, so the CLI can show the fee *before*
/// asking for confirmation and relaying afterwards with [`relay`].
pub async fn preview_timestamp(
    rpc_client: &WalletRpc,
    address: &str,
    amount_atomic: u64,
    extra_hex: &str,
    priority: u32,
) -> Result<(TransferResult, String), TxError> {
    if address.is_empty() {
        return Err(TxError::NoAddress);
    }
    let dest = Destination {
        address: address.to_string(),
        amount: amount_atomic,
    };
    build_marked(rpc_client, vec![dest], extra_hex, priority).await
}

/// Destinations for a donation stamp: the self-send first, then the
/// fee-sized donation to the developers. Order matters only for
/// clarity; the commitment mark is bound to tx_extra, not to outputs.
fn dests_with_donation(
    self_address: &str,
    amount_atomic: u64,
    donation_address: &str,
    donation_atomic: u64,
) -> Vec<Destination> {
    vec![
        Destination {
            address: self_address.to_string(),
            amount: amount_atomic,
        },
        Destination {
            address: donation_address.to_string(),
            amount: donation_atomic,
        },
    ]
}

/// Donation-aware preview. Pass 1 quotes the fee on a plain self-send.
/// Rebuilds then carry `[self, donation]` with the donation set to the
/// last quoted fee. The tx size does not change between rebuilds
/// (amounts serialize at fixed width), so the quoted fee settles on a
/// value and the next build pays exactly that fee: donation == fee.
/// Every build is `do_not_relay`, so discarded passes cost nothing and
/// nothing is relayed here.
/// Returns (result, donated amount, relay payload).
pub async fn preview_timestamp_with_donation(
    rpc_client: &WalletRpc,
    address: &str,
    amount_atomic: u64,
    extra_hex: &str,
    priority: u32,
    donation_address: &str,
) -> Result<(TransferResult, u64, String), TxError> {
    if address.is_empty() {
        return Err(TxError::NoAddress);
    }
    let (quote, _) =
        preview_timestamp(rpc_client, address, amount_atomic, extra_hex, priority).await?;
    let mut donation = quote.fee;
    for _ in 0..4 {
        let dests = dests_with_donation(address, amount_atomic, donation_address, donation);
        let (res, tx_hex) = build_marked(rpc_client, dests, extra_hex, priority).await?;
        if res.fee == donation {
            return Ok((res, donation, tx_hex));
        }
        donation = res.fee;
    }
    Err(TxError::Rejected(format!(
        "Donation could not settle on the tx fee after 4 builds (last quote {} atomic units). \
        Nothing was relayed and no fee was spent.",
        donation
    )))
}

/// Relay a transaction previously built with [`preview_timestamp`].
/// Returns the relayed transaction hash.
pub async fn relay(rpc_client: &WalletRpc, tx_hex: &str) -> Result<String, TxError> {
    Ok(rpc::relay_tx(rpc_client, tx_hex).await?)
}

/// Format atomic units as XMR for display.
pub fn format_xmr(atomic: u64) -> String {
    // 1 XMR = 1e12 atomic units.
    let whole = atomic / 1_000_000_000_000;
    let frac = atomic % 1_000_000_000_000;
    format!("{whole}.{frac:012} XMR")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn blob_check_finds_commitment_case_insensitively() {
        let extra = "0228584D525453010102AAAA";
        let blob = format!("deadbeef{extra}cafef00d").to_lowercase();
        assert!(tx_blob_contains_extra(&blob, extra));
        assert!(tx_blob_contains_extra(
            &blob.to_uppercase(),
            &extra.to_lowercase()
        ));
        assert!(!tx_blob_contains_extra("deadbeefcafef00d", extra));
        assert!(!tx_blob_contains_extra("", extra));
    }

    #[test]
    fn blob_check_fails_closed_on_empty_extra() {
        // `"anything".contains("")` is vacuously true; the gate must
        // never turn that into a pass.
        assert!(!tx_blob_contains_extra("deadbeef", ""));
        assert!(!tx_blob_contains_extra("", ""));
        assert!(!tx_blob_contains_extra("0228584d525453010102aaaa", ""));
    }

    #[test]
    fn donation_destinations_come_second() {
        let dests = dests_with_donation("self_address", 10_000, DONATION_ADDRESS, 25_000_000_000);
        assert_eq!(dests.len(), 2);
        assert_eq!(dests[0].address, "self_address");
        assert_eq!(dests[0].amount, 10_000);
        assert_eq!(dests[1].address, DONATION_ADDRESS);
        assert_eq!(dests[1].amount, 25_000_000_000);
    }

    #[test]
    fn donation_address_looks_like_monero() {
        // 95 mainnet chars, subaddress shape (starts with 8), as provided.
        assert_eq!(DONATION_ADDRESS.chars().count(), 95);
        assert!(DONATION_ADDRESS.starts_with('8'));
        assert!(DONATION_ADDRESS.chars().all(|c| c.is_ascii_alphanumeric()));
    }
}
