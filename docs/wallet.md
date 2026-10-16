# Wallet sidecar

xmrts runs a modified `monero-wallet-rpc`: the only change adds the ability to
put data in `tx_extra`, which stock software can't and
[won't](https://github.com/monero-project/monero/pull/11480).

```bash
xmrts wallet start    # spawn (no-op if running; refuses foreign processes on the port)
xmrts wallet open     # open a wallet: lists .keys files, hidden password prompt
xmrts wallet status   # process + RPC health
xmrts wallet close    # close the wallet so the Monero GUI can open it
xmrts wallet stop     # SIGTERM, then SIGKILL; never touches foreign pids
```

- `stamp` closes the wallet when it finishes (success or failure) so the Monero
  GUI can open it afterwards. Disable with
  `xmrts setting set autoclose false` for back-to-back stamping.
- When no wallet is open, `stamp` offers to open one right away (hidden prompt,
  never stored); scripts and pipes fail with a clear message instead.
- `stamp` auto-starts a configured-but-stopped sidecar.
- Management is process-lifecycle only and local-only (loopback endpoints):
  xmrts never requests or stores wallet passwords and never opens wallets by
  itself.
