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

Monero averages a block every ~2 minutes and `stamp` waits for 10
confirmations (~20 minutes) before writing anchored proofs, matching
Monero's own 10-block output lock. (On 2025-09-14 mainnet saw an 18-block
reorg that overwhelmed 10 confirmations, so treat 10 as a minimum and wait
for 20+ before relying on high-value timestamps.)
If confirmation isn't seen in time, `stamp` leaves pending proofs plus a
recovery record, and `xmrts finalize` upgrades them to anchored proofs
once the transaction confirms and buries deep enough.

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