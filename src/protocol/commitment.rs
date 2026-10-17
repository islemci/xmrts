//! xmrts commitment in Monero `tx_extra` (spec §4).
//!
//! Two encodings, both accepted when reading:
//!
//! - Legacy (magic): 40-byte nonce payload
//!   `XMRTS || version || hash_algo || merkle_ver || root`.
//!   Full field: `0x02 || 0x28 || payload` (42 bytes).
//! - Bare (V3, default since 0.3.0): the 32-byte size-bound commitment
//!   alone as a standard nonce field, `0x02 || 0x20 || root` (34 bytes).
//!   The bytes look like a random 32-byte nonce (much better than the
//!   `XMRTS` magic, which is trivially enumerable), but a 32-byte nonce
//!   body is unusual on chain — normal nonces are 9 or 33 bytes — so it is
//!   fingerprintable by size. Do not rely on it for anonymity.
//!   The version is implicit (SHA-256, size-bound root, Merkle-V2 semantics).
//!
//! Readers start from a known txid (from the proof) and compare against
//! an expected 32-byte value, so no magic is needed for discovery.
//! Both forms are passed to `monero-wallet-rpc transfer` via its `extra`
//! hex parameter.

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
/// Length of the bare V3 nonce body: the commitment alone, no magic.
pub const BARE_PAYLOAD_LEN: usize = 32;
/// Length of the full bare tx_extra field (tag + len varint + 32 bytes).
pub const BARE_FIELD_LEN: usize = 34;

const TAG_NONCE: u8 = 0x02;
const TAG_ADDITIONAL_PUBKEYS: u8 = 0x04;
/// Sanity cap for additional pubkeys (one per output minus one;
/// Monero txs never approach this many outputs).
const MAX_ADDITIONAL_PUBKEYS: u64 = 32;

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

/// Build the bare 34-byte tx_extra field for a commitment: `0x02 || 0x20`
/// plus the 32-byte value, hex-encoded for the wallet RPC `extra`
/// parameter. No magic, no version bytes: the bytes look like a random
/// 32-byte nonce, but the 32-byte size itself is unusual on chain (normal
/// nonces are 9 or 33 bytes), so it is not anonymous, only unlabelled.
pub fn build_bare_tx_extra_hex(commitment: &[u8; 32]) -> String {
    let mut field = Vec::with_capacity(BARE_FIELD_LEN);
    field.push(TAG_NONCE);
    field.push(BARE_PAYLOAD_LEN as u8); // 32 < 128: single-byte varint
    field.extend_from_slice(commitment);
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
/// Unknown tags are skipped. A well-framed non-XMRTS nonce is ignored.
/// Tag 0x04 (additional pubkeys) is `varint count + 32*count` bytes, not
/// `varint size + bytes`, and is handled explicitly: without this a
/// subaddress/self-send-with-change tx desyncs the parser and a valid
/// commitment later in `extra` is missed.
/// If trailing bytes are malformed after at least one commitment was
/// already found, the commitments found so far are returned instead of
/// aborting with an error.
pub fn find_commitments(tx_extra: &[u8]) -> Result<Vec<Commitment>, CommitmentError> {
    let mut out = Vec::new();
    let mut pos = 0;
    // Tag 0x00 is padding: a run of zeroes where the tag byte itself is
    // part of the count. Tag 0x01 (pubkey) is a fixed 32-byte field
    // without a size varint. Tag 0x04 (additional pubkeys) is a varint
    // count followed by 32 bytes per key. Everything else (0x02 nonce,
    // 0x03 merge-mining, …) is varint size + bytes.
    // On trailing malformation return what was found so far instead of
    // discarding it: a commitment already parsed is still valid evidence.
    let partial_ok =
        |out: &Vec<Commitment>, msg: &str| -> Result<Vec<Commitment>, CommitmentError> {
            if out.is_empty() {
                Err(CommitmentError::Malformed(msg.into()))
            } else {
                Ok(out.clone())
            }
        };
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
                    return partial_ok(&out, "truncated pubkey field");
                }
                pos += 32;
            }
            TAG_ADDITIONAL_PUBKEYS => {
                let count = match read_varint(tx_extra, &mut pos) {
                    Ok(c) => c,
                    Err(_) => return partial_ok(&out, "truncated additional-pubkeys count"),
                };
                if count > MAX_ADDITIONAL_PUBKEYS {
                    return partial_ok(&out, "additional-pubkeys count too large");
                }
                let need = (count as usize).saturating_mul(32);
                if pos + need > tx_extra.len() {
                    return partial_ok(&out, "truncated additional-pubkeys field");
                }
                pos += need;
            }
            _ => {
                let size = match read_varint(tx_extra, &mut pos) {
                    Ok(s) => s as usize,
                    Err(_) => return partial_ok(&out, "truncated varint"),
                };
                let end = match pos.checked_add(size) {
                    Some(e) => e,
                    None => return partial_ok(&out, "extra field size overflow"),
                };
                if end > tx_extra.len() {
                    return partial_ok(&out, "truncated extra field");
                }
                let body = &tx_extra[pos..end];
                pos = end;
                if tag == TAG_NONCE && body.len() == NONCE_PAYLOAD_LEN && body[0..5] == MAGIC {
                    out.push(parse_nonce_payload(body)?);
                } else if tag == TAG_NONCE && body.len() == BARE_PAYLOAD_LEN {
                    // Bare V3 commitment: the 32-byte size-bound root with
                    // no magic. Implicitly SHA-256 + Merkle-V2 semantics,
                    // so it carries that version for downstream gates.
                    // Only meaningful matched against an expected value
                    // (callers compare `root`); a random 32-byte nonce
                    // matching a real root needs a hash preimage.
                    let mut root = [0u8; 32];
                    root.copy_from_slice(body);
                    out.push(Commitment {
                        version: PROTOCOL_VERSION,
                        hash_algo: HASH_SHA256,
                        merkle_ver: MERKLE_V2,
                        root,
                    });
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

    #[test]
    fn skips_additional_pubkeys_before_commitment() {
        // Subaddress / change tx layout: pubkey, additional pubkeys
        // (tag 0x04, count, 32 bytes each), then our nonce. The old
        // varint-size fallback read the count as a byte size and desynced.
        let root = [0x33u8; 32];
        let mut extra = vec![0x01];
        extra.extend_from_slice(&[0xAAu8; 32]); // tx pubkey
        extra.push(0x04);
        extra.push(0x02); // count = 2
        extra.extend_from_slice(&[0xBBu8; 32]);
        extra.extend_from_slice(&[0xCCu8; 32]);
        extra.extend_from_slice(&hex::decode(build_tx_extra_hex(&root)).unwrap());
        let found = find_commitments(&extra).unwrap();
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].root, root);
    }

    #[test]
    fn trailing_garbage_preserves_found_commitment() {
        let root = [0x44u8; 32];
        let mut extra = hex::decode(build_tx_extra_hex(&root)).unwrap();
        extra.extend_from_slice(&[0x01, 0x02]); // truncated pubkey
        let found = find_commitments(&extra).unwrap();
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].root, root);
        // With nothing found, the same garbage must still error.
        assert!(find_commitments(&[0x01, 0x02]).is_err());
    }

    #[test]
    fn bare_commitment_has_no_magic() {
        let commitment = [0xABu8; 32];
        let hex_extra = build_bare_tx_extra_hex(&commitment);
        assert_eq!(hex_extra.len(), 68); // 34 bytes
        assert!(hex_extra.starts_with("0220"));
        assert!(!hex_extra.contains("584d525453")); // no "XMRTS"
    }

    #[test]
    fn bare_commitment_round_trip_as_v2() {
        let commitment = [0x55u8; 32];
        let mut extra = vec![0x01];
        extra.extend_from_slice(&[0x99u8; 32]); // tx pubkey
                                                // Wallet-added payment-id nonce must not confuse the scan.
        extra.extend_from_slice(&[0x02, 0x09, 0x00, 1, 2, 3, 4, 5, 6, 7, 8]);
        extra.extend_from_slice(&hex::decode(build_bare_tx_extra_hex(&commitment)).unwrap());
        let found = find_commitments(&extra).unwrap();
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].root, commitment);
        // Bare carries implicit V2 semantics for downstream version gates.
        assert_eq!(found[0].merkle_ver, MERKLE_V2);
    }

    #[test]
    fn random_32byte_nonce_matches_only_itself() {
        // A bare nonce is only meaningful compared against an expected
        // value: unrelated 32-byte nonces parse but never equal another root.
        let extra = hex::decode(build_bare_tx_extra_hex(&[0x11u8; 32])).unwrap();
        assert!(find_commitment_for_root(&extra, &[0x22u8; 32]).is_err());
        assert!(find_commitment_for_root(&extra, &[0x11u8; 32]).is_ok());
    }
}
