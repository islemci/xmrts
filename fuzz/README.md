# Fuzzing xmrts

## Targets

`fuzz_targets/proof_from_bytes.rs` feeds arbitrary bytes to
`Proof::from_bytes` and asserts no-panic plus serialize/parse
round-trip stability.

`fuzz_targets/commitment_from_bytes.rs` feeds arbitrary bytes to
`commitment::find_commitments` (the tx_extra parser, driven by hostile
daemon responses at runtime) and asserts no-panic plus this round
trip: any parsed commitment re-encoded through
`build_tx_extra_hex_for` (with standard leading PADDING) must parse
back to the same commitment.

## Running

Needs nightly Rust (libFuzzer):

```bash
cargo install cargo-fuzz
cargo +nightly fuzz run proof_from_bytes -- -max_total_time=300
cargo +nightly fuzz run commitment_from_bytes -- -max_total_time=300
```

Corpus and crash artifacts live here (`corpus/`, `artifacts/`) and are
git-ignored. CI does not run the fuzzer; the deterministic version of
the same invariant (every single-bit flip + every truncation of valid
proofs) runs as `proof_parser_total_mutation_sweep` in
`src/protocol/proof.rs` unit tests, and a byte-level tx_extra
mutation sweep runs as `commitment_parser_tolerates_hostile_bytes` in
`src/protocol/commitment.rs` unit tests.
