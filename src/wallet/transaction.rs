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

/// Preview the timestamp transaction without relaying it
/// (`do_not_relay` + metadata). Returns the wallet's fee quote and the
/// transaction metadata hex, so the CLI can show the fee *before* asking
/// for confirmation and relay afterwards with [`relay`].
///
/// NOTE: `relay_tx` parses its `hex` argument as serialized transaction
/// *metadata* (`tx_metadata`), not the raw transaction blob. Passing the
/// blob fails with `-27: Failed to parse txmetadata`.
pub async fn preview_timestamp(
    rpc_client: &WalletRpc,
    address: &str,
    amount_atomic: u64,
    extra_hex: &str,
) -> Result<(TransferResult, String), TxError> {
    if address.is_empty() {
        return Err(TxError::NoAddress);
    }
    let dest = Destination {
        address: address.to_string(),
        amount: amount_atomic,
    };
    let (res, raw) =
        rpc::transfer_with_extra(rpc_client, vec![dest], extra_hex, true, true).await?;
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
