//! `preview_timestamp` against a mock `monero-wallet-rpc`.
//!
//! The blob/metadata mark checks were previously only unit-tested as string
//! predicates. These tests drive the real `preview_timestamp` flow
//! (JSON-RPC `transfer` with `do_not_relay` + `get_tx_hex`) against a mock
//! patched wallet: one that embeds the commitment in both `tx_hex` and
//! `tx_metadata` (must pass), one that drops it from the metadata, and one
//! that drops it from the blob (both must fail closed with nothing relayed).

use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt};

/// Start a mock wallet RPC that answers every `transfer` with `result`.
async fn start_wallet_mock(result: serde_json::Value) -> String {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let Ok((mut sock, _)) = listener.accept().await else {
                break;
            };
            let result = result.clone();
            tokio::spawn(async move {
                let mut reader = tokio::io::BufReader::new(&mut sock);
                let mut content_length = 0usize;
                loop {
                    let mut line = String::new();
                    if reader.read_line(&mut line).await.is_err() {
                        return;
                    }
                    if line == "\r\n" || line == "\n" || line.is_empty() {
                        break;
                    }
                    if let Some(v) = line.to_ascii_lowercase().strip_prefix("content-length:") {
                        content_length = v.trim().parse().unwrap_or(0);
                    }
                }
                let mut body = vec![0u8; content_length];
                if content_length > 0 {
                    let _ = reader.read_exact(&mut body).await;
                }
                let resp_json = serde_json::json!({"result": result});
                let resp_body = serde_json::to_string(&resp_json).unwrap();
                let resp = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    resp_body.len(),
                    resp_body
                );
                let _ = reader.into_inner().write_all(resp.as_bytes()).await;
            });
        }
    });
    format!("http://127.0.0.1:{}", addr.port())
}

fn tx_result(tx_hex: &str, tx_metadata: &str) -> serde_json::Value {
    serde_json::json!({
        "tx_hash": "11".repeat(32),
        "fee": 1234u64,
        "amount": 10000u64,
        "tx_hex": tx_hex,
        "tx_metadata": tx_metadata,
    })
}

#[tokio::test]
async fn preview_accepts_mark_in_blob_and_metadata() {
    let extra = xmrts::protocol::commitment::build_bare_tx_extra_hex(&[0x42u8; 32]);
    let blob = format!("aabbcc{}ddeeff", extra.to_lowercase());
    let endpoint = start_wallet_mock(tx_result(&blob, &blob)).await;
    let rpc = xmrts::wallet::rpc::WalletRpc::new(endpoint, None, None, None);
    let (res, meta) =
        xmrts::wallet::transaction::preview_timestamp(&rpc, "4Adummy", 10_000, &extra, 0)
            .await
            .expect("patched wallet embedding the mark must pass");
    assert_eq!(res.fee, 1234);
    assert!(
        meta.to_ascii_lowercase()
            .contains(&extra.to_ascii_lowercase()),
        "relay payload must carry the mark"
    );
}

#[tokio::test]
async fn preview_rejects_metadata_without_mark() {
    // A wallet that embeds the mark in the blob yet drops it from the relay
    // payload (`tx_metadata`) would spend a fee with no anchor: fail closed.
    let extra = xmrts::protocol::commitment::build_bare_tx_extra_hex(&[0x42u8; 32]);
    let blob = format!("aabbcc{}ddeeff", extra.to_lowercase());
    let bare_meta = "aabbccddeeff00112233";
    let endpoint = start_wallet_mock(tx_result(&blob, bare_meta)).await;
    let rpc = xmrts::wallet::rpc::WalletRpc::new(endpoint, None, None, None);
    let err = xmrts::wallet::transaction::preview_timestamp(&rpc, "4Adummy", 10_000, &extra, 0)
        .await
        .expect_err("metadata without the mark must fail");
    assert!(
        err.to_string().contains("metadata"),
        "unexpected error: {err}"
    );
}

#[tokio::test]
async fn preview_rejects_blob_without_mark() {
    // Stock wallets silently ignore `extra`: the blob carries no mark.
    let extra = xmrts::protocol::commitment::build_bare_tx_extra_hex(&[0x42u8; 32]);
    let bare_blob = "aabbccddeeff00112233";
    let endpoint = start_wallet_mock(tx_result(bare_blob, bare_blob)).await;
    let rpc = xmrts::wallet::rpc::WalletRpc::new(endpoint, None, None, None);
    let err = xmrts::wallet::transaction::preview_timestamp(&rpc, "4Adummy", 10_000, &extra, 0)
        .await
        .expect_err("blob without the mark must fail");
    assert!(
        err.to_string().contains("mark") || err.to_string().contains("blob"),
        "unexpected error: {err}"
    );
}

/// Mock that answers everything with a non-JSON HTTP error page, the way
/// a reverse proxy does when the real wallet RPC is down (or the endpoint
/// points at a plain web server).
async fn start_proxy_error_mock() -> String {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let Ok((mut sock, _)) = listener.accept().await else {
                break;
            };
            tokio::spawn(async move {
                let mut reader = tokio::io::BufReader::new(&mut sock);
                let mut content_length = 0usize;
                loop {
                    let mut line = String::new();
                    if reader.read_line(&mut line).await.is_err() {
                        return;
                    }
                    if line == "\r\n" || line == "\n" || line.is_empty() {
                        break;
                    }
                    if let Some(v) = line.to_ascii_lowercase().strip_prefix("content-length:") {
                        content_length = v.trim().parse().unwrap_or(0);
                    }
                }
                let mut body = vec![0u8; content_length];
                if content_length > 0 {
                    let _ = reader.read_exact(&mut body).await;
                }
                let page = r#"<!DOCTYPE html><html><body>502 Bad Gateway</body></html>"#;
                let resp = format!(
                    "HTTP/1.1 502 Bad Gateway\r\nContent-Type: text/html\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    page.len(),
                    page
                );
                let _ = reader.into_inner().write_all(resp.as_bytes()).await;
            });
        }
    });
    format!("http://127.0.0.1:{}", addr.port())
}

#[tokio::test]
async fn non_json_rpc_answer_reports_status_and_body() {
    // A reverse-proxy error page must not masquerade as a "connection"
    // failure: the error should keep the HTTP status and a body snippet
    // so the user sees the endpoint is not (a healthy) wallet RPC.
    let endpoint = start_proxy_error_mock().await;
    let rpc = xmrts::wallet::rpc::WalletRpc::new(endpoint, None, None, None);
    let err = rpc
        .get_version()
        .await
        .expect_err("502 HTML page cannot be a JSON-RPC answer");
    let text = err.to_string();
    assert!(text.contains("502"), "status must be kept: {text}");
    assert!(
        text.contains("DOCTYPE") || text.contains("Bad Gateway"),
        "body snippet must be kept: {text}"
    );
    assert!(
        text.contains("monero-wallet-rpc"),
        "error should hint the right endpoint type: {text}"
    );
}
