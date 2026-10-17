#![no_main]

//! Fuzz `commitment::find_commitments` with arbitrary tx_extra bytes.
//!
//! The parser runs on bytes that come straight from a daemon's
//! `get_transactions` answer, so a hostile or broken daemon must never
//! be able to panic it in a loop: malformed varints, truncated nonce
//! bodies, absurd field sizes, tag soup, empty input. Invariants:
//! - no panic on any input,
//! - parsing either errors or commits,
//! - any parsed commitment round trips: the 40-byte nonce payload
//!   encodes version/hash_algo/merkle_ver verbatim, the parser pins the
//!   first two and admits known merkle versions only, so
//!   re-parsing the rebuilt field (plus standard leading PADDING)
//!   must reproduce the parsed commitment exactly.

use libfuzzer_sys::fuzz_target;
use xmrts::protocol::commitment;

fuzz_target!(|data: &[u8]| {
    if let Ok(found) = commitment::find_commitments(data) {
        for c in found {
            let raw = hex::decode(commitment::build_tx_extra_hex_for(&c.root, c.merkle_ver))
                .expect("built hex must decode");
            let mut padded = Vec::with_capacity(raw.len() + 2);
            padded.extend_from_slice(&[0x00u8, 0x00]);
            padded.extend_from_slice(&raw);
            let back = commitment::find_commitments(&padded).expect("built payload must parse");
            assert!(back.contains(&c), "built and parsed commitment must round trip");
        }
    }
});
