# Trust model

A proof shows a file hash existed **no later than** the Monero block in its
proof (height + hash + timestamp). It does **not** prove authorship, creation
time, or anything before that block. For authorship, sign first; see
[How it works](how-it-works.md#authorship-sign-first-then-stamp).

## Verifying releases

Each release tarball ships with `SHA256SUMS` inside the archive plus a GitHub
build-provenance attestation on the release page:

```bash
tar -xzf xmrts-linux-x86_64.tar.gz
cd xmrts-linux-x86_64 && shasum -a 256 -c SHA256SUMS
gh attestation verify xmrts-linux-x86_64.tar.gz --owner <org>
```

Signed checksums via minisign/cosign are planned; provenance attestations are
the current signing story.

## Good practice

- Stamp with a **dedicated low-value wallet**, never savings.
- Set `--max-fee` in scripts and CI against congestion spikes.
- Wait **20+ confirmations** for high-value timestamps.
- Prefer IP-allowlisted wallets without RPC login over passwords in argv/env.
- Batch related files in **one** `stamp` call: one tx, one fee.
