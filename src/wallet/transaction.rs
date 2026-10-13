//! Timestamp transaction preparation/broadcast/status (spec §10 steps 5-8).
//! All signing happens inside `monero-wallet-rpc`. xmrts only supplies the
//! `extra` commitment hex and a self-send destination.

use serde_json::Value;
use thiserror::Error;

use super::rpc::{self, Destination, TransferResult, WalletRpc};

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
    tx_blob_hex
        .to_ascii_lowercase()
        .contains(&extra_hex.to_ascii_lowercase())
}

/// Preview the timestamp transaction without relaying it
/// (`do_not_relay` + metadata). Returns the wallet's fee quote and the
/// transaction metadata hex, so the CLI can show the fee *before* asking
/// for confirmation and relay afterwards with [`relay`].
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
    let (res, raw) =
        rpc::transfer_with_extra(rpc_client, vec![dest], extra_hex, true, true, priority).await?;
    // Definitive mark check on the blob (not the opaque metadata): the
    // wallet must have embedded our commitment in the signed tx.
    if let Some(blob) = raw.get("tx_hex").and_then(Value::as_str) {
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
        // the mark. Fail closed rather than risk a mark-less relay.
        return Err(TxError::Rejected(
            "Wallet did not return the signed tx blob (`tx_hex`); cannot verify the mark. \
            Nothing was relayed."
                .to_string(),
        ));
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
            let keys = raw
                .as_object()
                .map(|o| o.keys().map(String::as_str).collect::<Vec<_>>().join(", "))
                .unwrap_or_else(|| "<non-object>".to_string());
            TxError::Rejected(format!(
                "wallet did not return tx metadata (response keys: {keys})"
            ))
        })?
        .to_string();
    Ok((res, tx_hex))
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
}
