---
title: xmrts
hide:
  - navigation
---
# xmrts

**xmrts** is a self-sovereign, decentralized file timestamping tool built on Monero.
It anchors file hashes in Monero `tx_extra`: no secondary server, no provider,
cheap fees. Pick a starting point below, or browse the tabs above for the full guide.

<div class="grid cards features" markdown>

-   :material-cash-fast:{ .lg .middle } **Cheap**

    ---

    Stamp one file or a hundred, the price is always a single small fee.

    [:octicons-arrow-right-24: What it costs](cli.md#useful-extras)

-   :material-lightning-bolt:{ .lg .middle } **Fast**

    ---

    Stamping takes seconds, and checking a stamp takes even less than that.

    [:octicons-arrow-right-24: Quickstart](#quickstart)

-   :material-shield-check:{ .lg .middle } **Secure**

    ---

    Your file fingerprint is buried deep in real Monero proof-of-work.

    [:octicons-arrow-right-24: How it works](how-it-works.md)

-   :material-eye-off:{ .lg .middle } **Private**

    ---

    No accounts and no tracking. Just you, your files, and the Monero chain.

    [:octicons-arrow-right-24: Trust model](trust.md)

</div>

## Install

=== "Homebrew (macOS & Linux)"

    ```bash
    brew tap islemci/xmrts
    brew install xmrts
    ```

=== "From source"

    ```bash
    cargo fmt && cargo clippy -- -D warnings && cargo test
    cargo install --path .
    ```

## Quickstart

**1. Initialize**: creates local config. On a terminal it asks for the wallet
RPC path and your wallet folder (Enter keeps the found or saved value),
about live fiat prices and which currency, and whether you want to support
the protocol with per-tx donations (that one off by default). Flags answer
the matching question; pass `--wallet-dir` to enable sidecar management:

```bash
xmrts init
xmrts init --wallet-dir ~/Monero/wallets/personal   # enables management
```

**2. Connect & open your wallet:**

```bash
xmrts wallet start    # spawn sidecar (no-op if running)
xmrts wallet open     # lists .keys files, hidden password prompt
xmrts connect         # check the connection
```

**3. Stamp**: one transaction for the whole batch:

```bash
xmrts stamp file.png
xmrts stamp a.pdf b.pdf c.pdf   # one tx for the whole batch
xmrts finalize                  # finish a pending stamp (no new tx/fee)
```

`stamp` waits for 10 confirmations (~20 minutes) before writing anchored proofs.
If confirmation isn't seen in time, it leaves pending proofs plus a recovery
record. `xmrts finalize` upgrades them to anchored proofs once the transaction
confirms and buries deep enough.

**4. Verify anywhere**: no wallet needed:

```bash
xmrts verify file.png file.png.xmrts
```

Next: [How it works](how-it-works.md) · [CLI reference](cli.md)
