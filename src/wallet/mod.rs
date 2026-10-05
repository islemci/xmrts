//! Wallet: interaction with the user's `monero-wallet-rpc` over JSON-RPC.
//! Wallet must never depend on CLI. Transaction signing stays inside the
//! wallet; xmrts only passes the commitment via the `extra` hex parameter.

pub mod connection;
pub mod daemon;
pub mod discover;
pub mod price;
pub mod process;
pub mod rpc;
pub mod transaction;
