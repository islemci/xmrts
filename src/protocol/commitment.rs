//! xmrts commitment in Monero `tx_extra` (spec §4).
//!
//! Nonce payload (40 bytes):
//! `XMRTS || version || hash_algo || merkle_ver || root`.
//! Full field: `0x02 || 0x28 || payload` (42 bytes), passed to
//! `monero-wallet-rpc transfer` via its `extra` hex parameter.

use crate::protocol::hash::HASH_SHA256;
use crate::protocol::merkle::{MERKLE_V1, MERKLE_V2};
use thiserror::Error;

/// ASCII "XMRTS".
pub const MAGIC: [u8; 5] = [0x58, 0x4D, 0x52, 0x54, 0x53];
/// xmrts protocol version.
pub const PROTOCOL_VERSION: u8 = 0x01;
/// Length of the nonce payload (magic + 3 version bytes + 32-byte root).
pub const NONCE_PAYLOAD_LEN: usize = 40;
/// Length of the full tx_extra field (tag + len varint + payload).
pub const TX_EXTRA_FIELD_LEN: usize = 42;

const TAG_NONCE: u8 = 0x02;

#[derive(Debug, Error)]
pub enum CommitmentError {
    #[error("commitment not found in tx_extra")]
    NotFound,
    #[error("malformed tx_extra: {0}")]
    Malformed(String),
    #[error("unsupported commitment version {0:#04x}")]
    UnsupportedVersion(u8),
}

/// A parsed v1 commitment.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Commitment {
    pub version: u8,
    pub hash_algo: u8,
    pub merkle_ver: u8,
    pub root: [u8; 32],
}

/// Build the 40-byte nonce payload for a Merkle root (V1).
pub fn build_nonce_payload(root: &[u8; 32]) -> [u8; NONCE_PAYLOAD_LEN] {
    build_nonce_payload_for(root, MERKLE_V1)
}

/// Build the 40-byte nonce payload for a commitment root + merkle version.
pub fn build_nonce_payload_for(root: &[u8; 32], merkle_ver: u8) -> [u8; NONCE_PAYLOAD_LEN] {
    let mut out = [0u8; NONCE_PAYLOAD_LEN];
    out[0..5].copy_from_slice(&MAGIC);
    out[5] = PROTOCOL_VERSION;
    out[6] = HASH_SHA256;
    out[7] = merkle_ver;
    out[8..40].copy_from_slice(root);
    out
}

/// Build the full 42-byte tx_extra field, hex-encoded for the wallet RPC
/// `extra` parameter (V1).
pub fn build_tx_extra_hex(root: &[u8; 32]) -> String {
    build_tx_extra_hex_for(root, MERKLE_V1)
}

/// Version-parameterized variant (V2 stamps use `MERKLE_V2`).
pub fn build_tx_extra_hex_for(root: &[u8; 32], merkle_ver: u8) -> String {
    let payload = build_nonce_payload_for(root, merkle_ver);
    let mut field = Vec::with_capacity(TX_EXTRA_FIELD_LEN);
    field.push(TAG_NONCE);
    field.push(NONCE_PAYLOAD_LEN as u8); // 40 < 128: single-byte varint
    field.extend_from_slice(&payload);
    hex::encode(field)
}

/// Parse one nonce payload (exactly 40 bytes).
pub fn parse_nonce_payload(bytes: &[u8]) -> Result<Commitment, CommitmentError> {
    if bytes.len() != NONCE_PAYLOAD_LEN {
        return Err(CommitmentError::Malformed(format!(
            "nonce payload len {}, expected {NONCE_PAYLOAD_LEN}",
            bytes.len()
        )));
    }
    if bytes[0..5] != MAGIC {
        return Err(CommitmentError::NotFound);
    }
    let (version, hash_algo, merkle_ver) = (bytes[5], bytes[6], bytes[7]);
    if version != PROTOCOL_VERSION {
        return Err(CommitmentError::UnsupportedVersion(version));
    }
    if hash_algo != HASH_SHA256 {
        return Err(CommitmentError::Malformed(format!(
            "unknown hash algo {hash_algo:#04x}"
        )));
    }
    if merkle_ver != MERKLE_V1 && merkle_ver != MERKLE_V2 {
        return Err(CommitmentError::Malformed(format!(
            "unknown merkle version {merkle_ver:#04x}"
        )));
    }
    let mut root = [0u8; 32];
    root.copy_from_slice(&bytes[8..40]);
    Ok(Commitment {
        version,
        hash_algo,
        merkle_ver,
        root,
    })
}

fn read_varint(buf: &[u8], pos: &mut usize) -> Result<u64, CommitmentError> {
    let mut value: u64 = 0;
    let mut shift = 0;
    loop {
        if *pos >= buf.len() {
            return Err(CommitmentError::Malformed("truncated varint".into()));
        }
        let b = buf[*pos];
        *pos += 1;
        value |= ((b & 0x7F) as u64) << shift;
        if b & 0x80 == 0 {
            return Ok(value);
        }
        shift += 7;
        if shift >= 64 {
            return Err(CommitmentError::Malformed("varint overflow".into()));
        }
    }
}

/// Scan raw `tx_extra` bytes; return every valid v1 commitment found.
/// Unknown tags are skipped. Malformed framing aborts with an error, while
/// a well-framed non-XMRTS nonce is simply ignored.
pub fn find_commitments(tx_extra: &[u8]) -> Result<Vec<Commitment>, CommitmentError> {
    let mut out = Vec::new();
    let mut pos = 0;
    // Tag 0x00 is padding: a run of zeroes where the tag byte itself is
    // part of the count. Tag 0x01 (pubkey) is a fixed 32-byte field
    // without a size varint. Everything else is varint tag/varint size.
    while pos < tx_extra.len() {
        let tag = tx_extra[pos];
        pos += 1;
        match tag {
            0x00 => {
                // Padding: consume following zero bytes.
                while pos < tx_extra.len() && tx_extra[pos] == 0x00 {
                    pos += 1;
                }
            }
            0x01 => {
                if pos + 32 > tx_extra.len() {
                    return Err(CommitmentError::Malformed("truncated pubkey field".into()));
                }
                pos += 32;
            }
            _ => {
                let size = read_varint(tx_extra, &mut pos)? as usize;
                if pos + size > tx_extra.len() {
                    return Err(CommitmentError::Malformed("truncated extra field".into()));
                }
                let body = &tx_extra[pos..pos + size];
                pos += size;
                if tag == TAG_NONCE && body.len() == NONCE_PAYLOAD_LEN && body[0..5] == MAGIC {
                    out.push(parse_nonce_payload(body)?);
                }
            }
        }
    }
    Ok(out)
}

/// Hex-string variant used with RPC responses (`extra` is hex).
pub fn find_commitments_hex(extra_hex: &str) -> Result<Vec<Commitment>, CommitmentError> {
    let raw = hex::decode(extra_hex.trim())
        .map_err(|e| CommitmentError::Malformed(format!("extra hex: {e}")))?;
    find_commitments(&raw)
}

/// Find the commitment matching `expected_root`, if any.
pub fn find_commitment_for_root(
    tx_extra: &[u8],
    expected_root: &[u8; 32],
) -> Result<Commitment, CommitmentError> {
    for c in find_commitments(tx_extra)? {
        if &c.root == expected_root {
            return Ok(c);
        }
    }
    Err(CommitmentError::NotFound)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_fixed_root() {
        let root = [0xABu8; 32];
        let hex_extra = build_tx_extra_hex(&root);
        assert_eq!(hex_extra.len(), 84);
        assert!(hex_extra.starts_with("0228"));
        let raw = hex::decode(&hex_extra).unwrap();
        let found = find_commitments(&raw).unwrap();
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].root, root);
    }

    #[test]
    fn skips_pubkey_and_padding() {
        let root = [0x11u8; 32];
        let mut extra = vec![0x00, 0x00]; // padding
        extra.push(0x01);
        extra.extend_from_slice(&[0x99u8; 32]); // fake pubkey
        let field = hex::decode(build_tx_extra_hex(&root)).unwrap();
        extra.extend_from_slice(&field);
        let found = find_commitments(&extra).unwrap();
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].root, root);
    }

    #[test]
    fn ignores_payment_id_nonce() {
        // 8-byte unencrypted payment id style nonce: tag 0x02, size 9,
        // body 0x00 || 8 bytes. Must not be reported as a commitment.
        let mut extra = vec![0x02, 0x09, 0x00, 1, 2, 3, 4, 5, 6, 7, 8];
        let root = [0x22u8; 32];
        extra.extend_from_slice(&hex::decode(build_tx_extra_hex(&root)).unwrap());
        let found = find_commitments(&extra).unwrap();
        assert_eq!(found.len(), 1);
    }
}
