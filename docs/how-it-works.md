# How it works

Hash → Merkle root → Monero `tx_extra` → block → proof.

1. **Hash**: each file is hashed (SHA-256).
2. **Merkle root**: batch hashes form one Merkle tree; the root is the commitment.
3. **Commit**: the root is embedded in `tx_extra` of a self-send. The amount
   returns to your wallet; only the fee is lost.
4. **Anchor**: after ≥10 confirmations, anchored `.xmrts` proofs are written
   (block height + hash + timestamp).
5. **Verify**: re-hash, check the Merkle path, then confirm the transaction
   on-chain. Crypto first, chain second.

## What's in a proof?

A `.xmrts` file binds your file to a chain position:

- File hash + Merkle path to the batch root
- Transaction ID carrying the commitment
- Block height, block hash, block timestamp
- Network (mainnet / stagenet)

Sharing a proof only reveals the txid: already public on-chain.

## Confirmations & reorgs

Monero averages a block every ~2 minutes. `stamp` defaults to **10 confirmations**
(~20 minutes), matching Monero's own 10-block output lock.

!!! warning "Treat 10 as a minimum"

    On 2025-09-14 mainnet saw an **18-block reorg** that overwhelmed 10
    confirmations. Wait for **20+** before relying on high-value timestamps:

    ```bash
    xmrts stamp --min-confirmations 20 contract.pdf
    xmrts verify contract.pdf contract.pdf.xmrts --min-confirmations 20
    ```

## Authorship: sign first, then stamp

Timestamping proves *existence*, not authorship. For authorship, sign first:
`stamp --sign-with` anchors a detached GPG signature in the same batch:

```bash
xmrts stamp --sign-with <gpg-key> file
xmrts verify file file.xmrts --sig file.sig
```

GPG verifies the signature (fingerprint printed), and `file.sig.xmrts` must anchor
in the **same transaction** as the file proof: a later signature still passes GPG
but fails the binding. Proofs living away from the files (e.g. `--out-dir`) pass
`--sig-proof`.
