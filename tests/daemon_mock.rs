//! Chain-verification tests against a mock daemon (brief §5, Step 1).
//!
//! Spins up a minimal HTTP mock on 127.0.0.1 implementing the two daemon
//! endpoints xmrts uses:
//! - `POST /get_transactions` → `{"txs": [{"extra": <hex>, "block_height": H}]}`
//! - `POST /json_rpc` with `method` = `get_block_header_by_height` or `get_info`
//!
//! These tests target the *desired* post-H1/H3/M1 API:
//! `verify_anchor(endpoint, txid, root, proof_height, proof_block_hash,
//! proof_network)` which must:
//! - fail when `proof.block_hash` differs from the chain header (H1),
//! - fail when daemon tx height differs from `proof.block_height` (H1),
//! - fail on anchored proofs with an all-zero `block_hash` (H1),
//! - report confirmations so callers can enforce depth (H3),
//! - fail when daemon nettype differs from proof network (M1),
//! - fail mempool txs (height 0) as unconfirmed.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt};

/// Configurable mock daemon state.
#[derive(Debug, Clone)]
pub struct MockState {
    /// txid_hex -> (extra_hex, block_height)
    pub txs: HashMap<String, (String, u64)>,
    /// height -> block hash hex
    pub headers: HashMap<u64, String>,
    /// chain tip height (for confirmations) + nettype
    pub tip_height: u64,
    pub nettype: String,
}

impl MockState {
    pub fn new(nettype: &str, tip_height: u64) -> Self {
        Self {
            txs: HashMap::new(),
            headers: HashMap::new(),
            tip_height,
            nettype: nettype.to_string(),
        }
    }
}

/// Start the mock; returns the base URL (e.g. `http://127.0.0.1:PORT`).
pub async fn start_mock(state: Arc<Mutex<MockState>>) -> String {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let Ok((mut sock, _)) = listener.accept().await else {
                break;
            };
            let state = state.clone();
            tokio::spawn(async move {
                handle_conn(&mut sock, &state).await;
            });
        }
    });
    format!("http://127.0.0.1:{}", addr.port())
}

async fn handle_conn(sock: &mut tokio::net::TcpStream, state: &Arc<Mutex<MockState>>) {
    let mut reader = tokio::io::BufReader::new(&mut *sock);
    let mut head = Vec::new();
    // Read HTTP headers.
    let mut content_length = 0usize;
    let mut path = String::new();
    loop {
        let mut line = String::new();
        if reader.read_line(&mut line).await.is_err() {
            return;
        }
        if line == "\r\n" || line == "\n" || line.is_empty() {
            break;
        }
        if line.starts_with("POST") || line.starts_with("GET") {
            path = line.split_whitespace().nth(1).unwrap_or("").to_string();
        }
        if let Some(v) = line.to_ascii_lowercase().strip_prefix("content-length:") {
            content_length = v.trim().parse().unwrap_or(0);
        }
        head.push(line);
        if head.len() > 64 {
            break;
        }
    }
    let mut body = vec![0u8; content_length];
    if content_length > 0 {
        let _ = reader.read_exact(&mut body).await;
    }
    let body_json: serde_json::Value =
        serde_json::from_slice(&body).unwrap_or(serde_json::Value::Null);

    let resp_json = route(&path, &body_json, state);
    let resp_body = serde_json::to_string(&resp_json).unwrap();
    let resp = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        resp_body.len(),
        resp_body
    );
    let _ = reader.into_inner().write_all(resp.as_bytes()).await;
}

fn route(path: &str, body: &serde_json::Value, state: &Arc<Mutex<MockState>>) -> serde_json::Value {
    let st = state.lock().unwrap().clone();
    if path == "/get_transactions" {
        let txid = body
            .get("txs_hashes")
            .and_then(|v| v.as_array())
            .and_then(|a| a.first())
            .and_then(|v| v.as_str())
            .unwrap_or("");
        match st.txs.get(txid) {
            Some((extra, h)) => serde_json::json!({
                "txs": [{"extra": extra, "block_height": h, "block_timestamp": 1760000000u64}],
            }),
            None => serde_json::json!({ "txs": [] }),
        }
    } else if path == "/json_rpc" {
        let method = body.get("method").and_then(|v| v.as_str()).unwrap_or("");
        match method {
            "get_block_header_by_height" => {
                let h = body
                    .get("params")
                    .and_then(|p| p.get("height"))
                    .and_then(|v| v.as_u64())
                    .unwrap_or(0);
                match st.headers.get(&h) {
                    Some(hash) => serde_json::json!({
                        "result": {"block_header": {"hash": hash, "height": h}}
                    }),
                    None => serde_json::json!({"error": {"code": -1, "message": "no such block"}}),
                }
            }
            "get_info" => serde_json::json!({
                "result": {"nettype": st.nettype, "height": st.tip_height}
            }),
            _ => serde_json::json!({"error": {"code": -1, "message": "unknown method"}}),
        }
    } else {
        serde_json::json!({"error": "unknown path"})
    }
}

fn rx(root_hex: &str) -> String {
    let root: [u8; 32] = hex::decode(root_hex).unwrap().try_into().unwrap();
    xmrts::protocol::commitment::build_tx_extra_hex(&root)
        .chars()
        .collect::<String>()
        .to_lowercase()
}

async fn setup() -> (String, String, [u8; 32], [u8; 32]) {
    // Returns (endpoint, txid_hex, root, block_hash).
    let root = [0x42u8; 32];
    let block_hash = [0xabu8; 32];
    let txid = [0x11u8; 32];
    let txid_hex = hex::encode(txid);
    let extra = xmrts::protocol::commitment::build_tx_extra_hex(&root);
    let state = Arc::new(Mutex::new({
        let mut s = MockState::new("mainnet", 3_000_100);
        s.txs.insert(txid_hex.clone(), (extra, 3_000_090));
        s.headers.insert(3_000_090, hex::encode(block_hash));
        s
    }));
    let endpoint = start_mock(state).await;
    (endpoint, txid_hex, root, block_hash)
}

#[tokio::test]
async fn correct_tx_and_block_verifies() {
    let (endpoint, txid_hex, root, block_hash) = setup().await;
    let anchor = xmrts::wallet::daemon::verify_anchor(
        &endpoint,
        &txid_hex,
        &root,
        3_000_090,
        &block_hash,
        "mainnet",
    )
    .await
    .expect("correct anchor must verify");
    assert_eq!(anchor.height, 3_000_090);
    assert_eq!(anchor.block_hash, block_hash);
    assert_eq!(anchor.block_timestamp, 1760000000u64);
    assert_eq!(
        xmrts::wallet::daemon::format_block_time(1760000000),
        "2025-10-09 08:53 UTC"
    );
}

#[tokio::test]
async fn wrong_block_hash_fails() {
    let (endpoint, txid_hex, root, _) = setup().await;
    let wrong = [0xffu8; 32];
    let r = xmrts::wallet::daemon::verify_anchor(
        &endpoint, &txid_hex, &root, 3_000_090, &wrong, "mainnet",
    )
    .await;
    assert!(r.is_err(), "forged block_hash must fail, got {r:?}");
}

#[tokio::test]
async fn height_mismatch_fails() {
    let (endpoint, txid_hex, root, block_hash) = setup().await;
    let r = xmrts::wallet::daemon::verify_anchor(
        &endpoint,
        &txid_hex,
        &root,
        3_000_091, // proof claims a different height
        &block_hash,
        "mainnet",
    )
    .await;
    assert!(r.is_err(), "height split must fail, got {r:?}");
}

#[tokio::test]
async fn zero_block_hash_fails() {
    let (endpoint, txid_hex, root, _) = setup().await;
    let r = xmrts::wallet::daemon::verify_anchor(
        &endpoint, &txid_hex, &root, 3_000_090, &[0u8; 32], "mainnet",
    )
    .await;
    assert!(r.is_err(), "zero block_hash must fail, got {r:?}");
}

#[tokio::test]
async fn nettype_mismatch_fails() {
    let (endpoint, txid_hex, root, block_hash) = setup().await;
    let r = xmrts::wallet::daemon::verify_anchor(
        &endpoint,
        &txid_hex,
        &root,
        3_000_090,
        &block_hash,
        "stagenet", // proof says stagenet, daemon is mainnet
    )
    .await;
    assert!(r.is_err(), "nettype split must fail, got {r:?}");
}

#[tokio::test]
async fn mempool_tx_is_unconfirmed() {
    let root = [0x42u8; 32];
    let txid_hex = hex::encode([0x22u8; 32]);
    let extra = rx(&hex::encode(root));
    let state = Arc::new(Mutex::new({
        let mut s = MockState::new("mainnet", 3_000_100);
        s.txs.insert(txid_hex.clone(), (extra, 0)); // mempool
        s
    }));
    let endpoint = start_mock(state).await;
    let r =
        xmrts::wallet::daemon::verify_anchor(&endpoint, &txid_hex, &root, 0, &[0u8; 32], "mainnet")
            .await;
    assert!(r.is_err(), "mempool tx must be unconfirmed, got {r:?}");
}

#[tokio::test]
async fn shallow_confirmation_reports_low_depth() {
    // Tip only 2 blocks above the anchor → confirmations = 3 < 10.
    let root = [0x42u8; 32];
    let block_hash = [0xabu8; 32];
    let txid_hex = hex::encode([0x33u8; 32]);
    let extra = xmrts::protocol::commitment::build_tx_extra_hex(&root);
    let state = Arc::new(Mutex::new({
        let mut s = MockState::new("mainnet", 1_000_102);
        s.txs.insert(txid_hex.clone(), (extra, 1_000_100));
        s.headers.insert(1_000_100, hex::encode(block_hash));
        s
    }));
    let endpoint = start_mock(state).await;
    let anchor = xmrts::wallet::daemon::verify_anchor(
        &endpoint,
        &txid_hex,
        &root,
        1_000_100,
        &block_hash,
        "mainnet",
    )
    .await
    .expect("shallow anchor still resolves");
    assert_eq!(anchor.confirmations, 3);
    assert!(
        anchor.confirmations < xmrts::wallet::daemon::MIN_CONFIRMATIONS,
        "test setup must be below threshold"
    );
}
