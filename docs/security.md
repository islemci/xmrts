# Security model

xmrts is a CLI that talks to your Monero wallet RPC and, optionally, a
daemon. This page states what it protects and what it does not.

## Secrets

- Wallet passwords are never requested or stored by xmrts unless you opt
  in with `xmrts connect --save-auth` (plain text, mode 0600, your user
  only).
- Prefer `--password-stdin` (pipe) over `--password` (argv) in CI: argv
  is visible in `ps` and shell history. The GitHub Action pipes the
  secret.
- The sidecar receives its RPC login through a 0600 config file, never
  through argv.
- Embedded credentials in daemon endpoints are redacted in all error
  messages, status output, and logs.

## Transport

- Wallet, daemon, and price clients disable redirects (`Policy::none()`):
  a 30x cannot replay a POST body to a redirect target.
- Loopback endpoints bypass any configured proxy; remote endpoints use
  it (Tor-friendly). Invalid proxy strings are warned about, not
  silently dropped.
- Remote plain-HTTP daemons trigger an insecure-transport warning.

## Files

- Config and pending files are created mode 0600 on Unix; directories
  0700. On Windows the mode bits are not applied (known limitation).
- Pending records are never overwritten silently; name collisions are
  bounded.
- Directory walks never follow nested symlinks; an explicitly named
  symlink proof file is dereferenced.

## What a proof does and does not prove

See the trust model in `trust.md`. A proof shows a file hash existed
no later than the Monero block in the proof. It does not prove
authorship or creation time.