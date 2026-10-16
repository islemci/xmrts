# Timestamp release artifacts from CI

Use the [`action.yml`](https://github.com/islemci/xmrts/blob/main/action.yml)
GitHub Action (see
[`examples/ci-stamp.yml`](https://github.com/islemci/xmrts/blob/main/examples/ci-stamp.yml)).
Use a dedicated low-value timestamping wallet. **Never use savings**.

```yaml
- uses: islemci/xmrts@v1
  with:
    files: "dist/SHA256SUMS"
    daemon: ${{ secrets.XMRTS_DAEMON }}
    max-fee: "100000"
```

## Inputs

- `files` (required), `version`, `network`
- `daemon`, `wallet-endpoint`, `wallet-username` / `wallet-password`
- `max-fee`, `no-wait` (default `true`), `out-dir`

## Outputs

- `txid`: timestamp tx hash (empty for offline runs)
- `proofs`: space-separated `.xmrts` files
- `pending`: `true` when proofs aren't anchored yet

## Safety

- Tarball attestation verified before executing anything.
- `SHA256SUMS` integrity check on extracted files.
- Pair with a `--max-fee` cap against congestion spikes.
