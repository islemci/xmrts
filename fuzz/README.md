# Fuzzing xmrts

`fuzz_targets/proof_from_bytes.rs` feeds arbitrary bytes to
`Proof::from_bytes` and asserts no-panic plus serialize/parse
round-trip stability. Needs nightly Rust (libFuzzer):

```bash
cargo install cargo-fuzz
cargo +nightly fuzz run proof_from_bytes -- -max_total_time=300
```

Corpus and crash artifacts live here (`corpus/`, `artifacts/`) and are
git-ignored. CI does not run the fuzzer; the deterministic version of
the same invariant (every single-bit flip + every truncation of valid
proofs) runs as `proof_parser_total_mutation_sweep` in
`src/protocol/proof.rs` unit tests.
