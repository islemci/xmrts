# Troubleshooting

Common problems and how to fix them.

## "Wallet is quiet" / connection refused

- The wallet RPC is not running or no wallet is open. Run `xmrts wallet status`, then `xmrts wallet start` and `xmrts wallet open`.
- Check the endpoint saved by `xmrts connect --endpoint ...`. `xmrts doctor` reports the saved endpoint and whether it answers.
- If you use `--rpc-login`, the sidecar keeps its own login in a 0600 file; a mismatch surfaces as `SidecarStatus::Unhealthy` (pid answers but rejects the login). Stop the sidecar and start it again.

## Stale pending proofs

- `xmrts stamp` leaves pending proofs when confirmation is not seen in time. Run `xmrts finalize` once the transaction confirms and is buried deep enough.
- `xmrts pending` lists pending records; `xmrts pending clean` removes orphaned ones. Pending files are owner-only (mode 0600).

## Permission errors on config or pending files

- Config lives in `~/.config/xmrts` (Linux), `~/Library/Application Support/xmrts` (macOS). On Unix these are created mode 0700/0600. On Windows the mode bits are not applied (known limitation).
- Do not share these files; they may contain an RPC password if you used `--save-auth`.

## Sidecar killed when the terminal closes

- The detached sidecar shares xmrts's session on Unix, so closing the terminal may stop it. Run under `tmux`/a service for permanence, or use `xmrts wallet stop` / `start` per session.

## Slow or failing price feed

- `xmrts setting set price true` enables CoinGecko estimates. A failed fetch degrades to XMR-only display and never fails the operation. Set a proxy with `xmrts connect --proxy socks5h://...` for Tor.

## Non-JSON daemon or wallet answers

- If an endpoint is behind a reverse proxy, xmrts keeps the HTTP status and a body snippet in the error so you can see it is not (a healthy) wallet RPC. Point `--endpoint`/`--daemon` at the real service.