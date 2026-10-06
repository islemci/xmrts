#![no_main]

//! Fuzz `Proof::from_bytes` with arbitrary untrusted input.
//!
//! Invariants: parsing must never panic, and any proof that parses must
//! survive a serialize -> parse round trip unchanged. Merkle verification
//! is NOT asserted: the fuzzer may craft well-shaped proofs whose path
//! misses the root, and rejecting those is correct behavior.
//!
//! Run with nightly cargo-fuzz (libFuzzer):
//! ```bash
//! cargo install cargo-fuzz
//! cargo +nightly fuzz run proof_from_bytes -- -max_total_time=300
//! ```

use libfuzzer_sys::fuzz_target;
use xmrts::protocol::proof::Proof;

fuzz_target!(|data: &[u8]| {
    if let Ok(p) = Proof::from_bytes(data) {
        let bytes = p.to_bytes();
        let back = Proof::from_bytes(&bytes).expect("re-serialized proof must parse");
        assert_eq!(p, back);
    }
});
