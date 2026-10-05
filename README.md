# xmrts

Self-sovereign, decentralized file timestamping on Monero.

Prove a file existed **no later than** the Monero block containing its
timestamp commitment: without a secondary server or provider and with cheap
fees.

## Status

```bash
xmrts init
xmrts connect
xmrts stamp file.png
xmrts stamp a.pdf b.pdf c.pdf   # one tx for the whole batch
xmrts finalize                  # finish a pending stamp (no new tx/fee)
xmrts verify file.png file.png.xmrts
xmrts setting set price true    # fiat estimates; list/get/set/unset
xmrts doctor
xmrts --help
```

Your transaction will be completed in around 3 minutes: `stamp` waits for
the transaction to confirm and bury 2 deep, then writes anchored proofs.
If confirmation isn't seen in time, `stamp` leaves pending proofs plus a
recovery record, and `xmrts finalize` upgrades them to anchored proofs
once the transaction confirms.

## Managed sidecar

xmrts runs a modified version of `monero-wallet-rpc` due to the limits
of the stock software. This modification only adds the functionality to
add data to `tx_extra`, which the original software can't and [won't](https://github.com/monero-project/monero/pull/11480).    

```bash
xmrts init --wallet-dir ~/Monero/wallets/personal   # enables management
xmrts wallet start    # spawn (no-op if running; refuses foreign processes on the port)
xmrts wallet open     # open a wallet: lists .keys files, hidden password prompt
xmrts wallet status   # process + RPC health
xmrts wallet stop     # SIGTERM, then SIGKILL; never touches foreign pids
```

`stamp` auto-starts a configured-but-stopped sidecar. Management is
process-lifecycle only and local-only (loopback endpoints): xmrts never
requests or stores wallet passwords and never opens wallets by itself,
open yours via `open_wallet` after `wallet start`.

`stamp --offline` writes pending (unanchored) proofs without a wallet.
Useful for testing the protocol plumbing. `verify --offline` checks
cryptography only and clearly reports that anchoring was NOT checked.
## Install

xmrts can be installed via [Homebrew](https://brew.sh) on both MacOS and Linux devices.

```bash
brew tap islemci/xmrts
brew install xmrts
```

## Build

```bash
cargo fmt && cargo clippy -- -D warnings && cargo test
```

## Trust model

A proof shows a file hash existed **no later than** the Monero block in
its proof (block height + hash + timestamp). It does **not** prove
authorship, creation time, or anything before that block.

What you trust:

- **The daemon you verify against.** One (possibly remote) daemon decides
  the result. `verify` checks the mark bytes, the exact height, the block
  hash, and the daemon's network, and warns below 10 confirmations — but a
  lying daemon can still lie. Prefer your own node; treat plain-HTTP remote
  nodes as untrusted transport.
- **Confirmation depth.** Proofs anchor at 2 confirmations, and `verify`
  warns below that.
- **Mainnet.** Testnet/stagenet marks verify the same way but carry no
  security value; `verify` says so loudly.
- **The patched `monero-wallet-rpc`.** Stock wallet RPC cannot attach
  `tx_extra`, so xmrts ships a minimally patched build (see below). It is
  part of your trust base, like the Monero software itself.

What you do not need to trust: any xmrts server (there is none), the
wallet after stamping (verification needs no wallet), or anyone's
permission.

## Formats (v1 + v2)

- **Commitment (`tx_extra`, 42 bytes):**
  `0x02 || 0x28 || "XMRTS" || ver(0x01) || hash_algo(0x01) || merkle_ver || root[32]`.
  `merkle_ver` is `0x01` (v1: `root` is the raw Merkle root) or `0x02`
  (v2: `root` is the size-bound commitment
  `SHA256(0x02 || tree_size_le_u64 || top_root)`).
- **Proof (`.xmrts`, 165 + 32·N bytes, little-endian):**
  `"XMRTS" || ver || hash_algo || merkle_ver || network || file_hash[32] ||
  leaf_index u64 || tree_size u64 || root[32] || txid[32] || block_height u64
  || block_hash[32] || path_len u32 || siblings[32·N]`.
  V2 proofs carry the top root; verifiers recompute the size-bound
  commitment before comparing with the chain.
- **Merkle tree:** `leaf = SHA256(0x00 || file_hash)`,
  `node = SHA256(0x01 || L || R)`, leaves sorted by file hash, odd node
  duplicated, single leaf means `root = leaf`. V1 and V2 share the tree
  shape; v1 proofs (raw root on chain) still verify.

## Patched wallet

Stock `monero-wallet-rpc` cannot attach arbitrary `tx_extra` (upstream
declined: monero-project/monero#11480). xmrts builds monero v0.18.5.0 with
[patches/monero-wallet-rpc-extra-v0.18.5.0.patch](patches/monero-wallet-rpc-extra-v0.18.5.0.patch),
which adds one opt-in `extra` hex parameter to `transfer`: hex bytes are
appended to `tx_extra` under the same relay-size ceiling the txpool
enforces, and the wallet RPC version minor is bumped 30 → 31 so xmrts
(and `xmrts doctor`) can detect patched builds. `stamp` refuses stock
wallets before any fee is spent. Build it with
`MODE=static ./scripts/build-wallet-rpc.sh`; the script aborts if the
patch does not apply cleanly and verifies the Monero tag commit first.

## Supported platforms

Release archives: Linux x86_64 and macOS Apple Silicon. Windows and
macOS Intel are not built yet. Homebrew: macOS + Linux (see Install).

## Verifying releases

Each release tarball ships with `SHA256SUMS` inside the archive plus a
GitHub build-provenance attestation on the release page:

```bash
tar -xzf xmrts-linux-x86_64.tar.gz
cd xmrts-linux-x86_64 && shasum -a 256 -c SHA256SUMS
gh attestation verify xmrts-linux-x86_64.tar.gz --owner <org>
```

(Signed checksums via minisign/cosign are planned; provenance
attestations are the current signing story.)