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

Pending is normal: Monero averages a block every ~2 minutes, so `stamp`
waits up to ~10 minutes for confirmation and often leaves pending proofs
plus a recovery record. `xmrts finalize` upgrades them to anchored proofs
once the transaction is buried deep enough (10+ confirmations). Safe to
Ctrl-C the wait at any time.

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