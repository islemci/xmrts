# CLI reference

Global flags (work on every command): `--verbose` for extra detail (also shows
proof contents for `verify`), and `--stagenet` to touch stagenet instead of
mainnet for one invocation. Pass `--stagenet` explicitly every time you mean it.

## `init`

Create local config and point xmrts at your tools. On a terminal it walks the
setup in four short steps: the `monero-wallet-rpc` path, the wallet folder,
live fiat prices (plus currency), and per-transaction donations. Every
question takes Enter, and Enter keeps the saved or found value, so pressing
Enter through it changes nothing. A flag answers its matching question
instead. Scripts and pipes keep the prompt-free steps.

```bash
xmrts init
xmrts init --wallet-dir ~/Monero/wallets/personal
xmrts init --wallet-rpc-path /opt/monero/monero-wallet-rpc
xmrts init --force    # overwrite saved settings with defaults
```

Flags:

- `--wallet-dir DIR`: wallet folder passed to the sidecar. Setting this turns on sidecar control.
- `--wallet-rpc-path PATH`: path to the `monero-wallet-rpc` binary. Unset means autodetect next to xmrts, in `/opt/monero`, or on `PATH`.
- `--force`: overwrite saved settings with defaults.

The folder question lists discovered folders (`1` to `N`) plus typed entry
(`t`), and typed paths expand a leading `~` to your home folder. Declining
all answers leaves sidecar control off: `xmrts connect` covers that case.

Every wizard run then asks about live prices. `y` turns fiat estimates on
and asks which currency (a pick list plus any 3-letter fiat code); Enter
keeps them off. Enabling means one third-party request per estimate:
prices come from CoinGecko, and a feed outage degrades cleanly to
XMR-only amounts.

Last, it asks whether you want to support the development of the protocol.
`y` turns donations on (`setting donate true`), Enter keeps them off.
Donations are off by default.

## `connect`

Point xmrts at your wallet RPC and daemon, and check the connection.

```bash
xmrts connect
xmrts connect --endpoint http://127.0.0.1:18082
xmrts connect --daemon http://127.0.0.1:18081
xmrts connect --network stagenet --daemon http://127.0.0.1:38081
xmrts connect --username alice --password          # prompts safely
xmrts connect --username alice --password s3cret --save-auth
xmrts connect --clear-auth                          # forget saved login
```

Flags:

- `--endpoint URL`: wallet RPC address, like `http://127.0.0.1:18082`.
- `--username NAME`: RPC user name (for wallets started with a login).
- `--password PASS`: RPC password. Prefer omitting it and typing the password when asked. Passing it on the command line exposes it in shell history and the process list.
- `--save-auth`: save user name and password locally (plain text, locked to you). Needs `--password` together.
- `--clear-auth`: forget the saved user name and password.
- `--network NAME`: Monero network: `mainnet`, `testnet`, or `stagenet`.
- `--daemon URL`: daemon address for checks, like `http://127.0.0.1:18081`.
- `--proxy URL`: proxy for daemon and price-feed traffic, e.g. `socks5h://127.0.0.1:9050` for Tor. Local loopback endpoints always bypass it.

## `stamp`

Timestamp files. One invocation means one transaction, no matter how many files
you pass.

```bash
xmrts stamp report.pdf
xmrts stamp a.pdf b.pdf c.pdf            # one tx for the whole batch
xmrts stamp ./dist --recursive --yes
xmrts stamp report.pdf --out-dir ./proofs
xmrts stamp report.pdf --no-wait         # pending now, finalize later
xmrts stamp report.pdf --max-fee 100000 --yes
xmrts stamp report.pdf --min-confirmations 20   # high-value patience
xmrts stamp report.pdf --sign-with alice@example.com
xmrts stamp report.pdf --offline         # no wallet, pending proofs only
xmrts stamp report.pdf --json            # machine-readable summary
```

Flags:

- `--offline`: skip the wallet and write pending proofs only.
- `--no-wait`: do not wait for confirmation. Write pending proofs right away.
- `--do-not-relay`: build the transaction but do not send it.
- `--yes`: skip the confirmation prompt.
- `--json`: machine-readable JSON summary on stdout (human lines suppressed).
- `--address ADDR`: send to this address (default: your wallet address).
- `--amount N`: send amount in atomic units (default 10000). This is a self-send to carry the commitment: the amount returns to your wallet and only the fee is lost.
- `--max-fee N`: refuse to send when the quoted fee is above this many atomic units. Guards `--yes` and `--json` runs against congestion fee spikes.
- `--priority 0-4`: transaction priority. 0 is the wallet default, 1 to 4 go from slow to fast. Higher priorities confirm sooner but cost more.
- `--recursive`: walk directories depth-first (default: top level only).
- `--out-dir DIR`: folder for `.xmrts` proofs (default: next to each file).
- `--daemon URL`: daemon address for chain checks, like `http://127.0.0.1:18081`.
- `--min-confirmations N`: required confirmations before proofs count as anchored (default 10). Lower (e.g. 2) anchors in minutes but dies on shallow reorgs. Higher (e.g. 20+) is safer for high-value timestamps.
- `--sign-with KEY`: GPG-sign each file first (detached `.sig` next to it) and stamp the signatures in the same batch, binding authorship to the timestamp. Takes a GPG key id.

When `donate` is on (`xmrts init` or `setting set donate true`), the
transaction carries an extra output to the xmrts developers, sized exactly
to the fee you pay. It rides in the same transaction, so nothing changes
for verification. Mainnet only.

## `verify`

Check a file against its proof. Crypto first, chain second. Needs no wallet.

```bash
xmrts verify report.pdf report.pdf.xmrts
xmrts verify report.pdf report.pdf.xmrts --verbose   # also show proof contents
xmrts verify report.pdf report.pdf.xmrts --offline   # crypto only
xmrts verify report.pdf report.pdf.xmrts \
  --daemon http://127.0.0.1:18081 \
  --daemon http://node2.example:18081                # quorum: all must agree
xmrts verify report.pdf report.pdf.xmrts --min-confirmations 20
xmrts verify report.pdf report.pdf.xmrts --sig report.pdf.sig
xmrts verify report.pdf report.pdf.xmrts --json
```

Flags:

- `--offline`: crypto only, skip the chain lookup. Clearly reports that anchoring was not checked.
- `--daemon URL`: daemon address for tx lookup. Repeat for a quorum: every daemon must agree on the anchor or verification fails.
- `--min-confirmations N`: required confirmations before a proof counts as final (default 10). Higher (e.g. 20+) is safer for high-value timestamps.
- `--json`: machine-readable JSON on stdout (human lines suppressed).
- `--sig FILE.sig`: also check the detached GPG signature from `stamp --sign-with`. GPG verifies the signature itself, and its own proof (`<sig>.xmrts`) must anchor in the same transaction as the file proof.
- `--sig-proof PATH`: location of the `.sig` proof when proofs live away from the files (e.g. `stamp --out-dir`). Defaults to `<sig>.xmrts` next to the signature, falling back to the main proof's directory.

## `finalize`

Finish a pending stamp into anchored proofs. Sends no new transaction and pays
no new fee.

```bash
xmrts finalize                    # finishes the only pending record
xmrts finalize --all              # finish every pending stamp, one by one
xmrts finalize --pending path/to/pending-<root>.json
xmrts finalize report.pdf.xmrts   # upgrade this proof file itself
```

Flags:

- `--pending PATH`: pending record (`.json`) or pending proof (`.xmrts`) to finish. Picks the only pending record when empty.
- `--all`: finish every pending stamp, one after another.
- `--daemon URL`: daemon address for chain checks.
- `--min-confirmations N`: required confirmations before proofs count as anchored (default 10).

## `audit`

Re-verify saved proofs against the chain tip. Good for scheduled checks of
proofs you rely on.

```bash
xmrts audit ./proofs
xmrts audit report.pdf.xmrts
xmrts audit ./archive --daemon http://127.0.0.1:18081 --json
```

Flags:

- Paths (one or more): proof files or folders to audit. Folders are walked for `*.xmrts`.
- `--daemon URL`: daemon address for tx lookup. Repeat for a quorum.
- `--min-confirmations N`: required confirmations before a proof counts as final (default 10).
- `--json`: machine-readable JSON on stdout (human lines suppressed).
- `--proof-only`: skip the original-file check. Verifies the Merkle path and chain anchor from the proof alone. Fixes `--out-dir` layouts where originals are not next to proofs.

## `queue`

Collect files over days or weeks, then stamp them all in one transaction.

```bash
xmrts queue add monday.pdf tuesday.pdf
xmrts queue list
xmrts queue flush --yes
xmrts queue clear --yes
```

Subcommands:

- `queue add FILES... [--json]`: hash files and remember them for a later `queue flush`.
- `queue list [--json]`: show queued files with ages.
- `queue flush [--yes] [--no-wait] [--amount N] [--priority 0-4] [--max-fee N] [--out-dir DIR] [--daemon URL] [--min-confirmations N] [--json]`: stamp the whole queue in one transaction. Same fee and confirmation flags as `stamp`.
- `queue clear [--yes]`: drop queued files without stamping.

## `watch`

Finish pending stamps in the background until nothing waits. Ideal for a
terminal you leave running, or a small systemd unit.

```bash
xmrts watch
xmrts watch --interval 60 --max-rounds 30
xmrts watch --daemon http://127.0.0.1:18081 --min-confirmations 20
```

Flags:

- `--interval SECS`: seconds between rounds (default 120, minimum 15).
- `--max-rounds N`: stop after this many rounds (default: run until nothing waits).
- `--daemon URL`: daemon address for chain checks.
- `--min-confirmations N`: required confirmations before proofs count as anchored (default 10).

## `pending`

Inspect and tidy recovery records. Bare `pending` lists. `pending clean`
removes records that can never finalize (input files gone or record
unreadable). Records with all files present are never touched: they may still
confirm.

```bash
xmrts pending
xmrts pending --json list
xmrts pending clean
xmrts pending clean --yes
```

Subcommands and flags:

- `pending list`: list pending stamps with age, network, files, and tx state. This is the default when no subcommand is given.
- `pending clean [--yes]`: remove records whose input files are gone (asks first).
- `--json`: machine-readable JSON list on stdout (human lines suppressed). Pass before the subcommand: `xmrts pending --json list`.

## `wallet`

Manage the `monero-wallet-rpc` sidecar (process lifecycle only, local only).

```bash
xmrts wallet start
xmrts wallet open       # hidden password prompt, never stored
xmrts wallet status
xmrts wallet close      # free the files so the Monero GUI can open them
xmrts wallet stop
```

Subcommands:

- `wallet start`: start the wallet helper (does nothing if already running).
- `wallet open`: open a wallet on the running helper (asks for the password safely).
- `wallet status`: show if the helper runs and if the wallet answers.
- `wallet close`: close the open wallet, releasing its files for other apps (e.g. the Monero GUI).
- `wallet stop`: stop the wallet helper.

## `setting`

Read and change settings. Passwords stay hidden in output.

```bash
xmrts setting list
xmrts setting get price
xmrts setting set price true
xmrts setting set currency eur
xmrts setting set autoclose false
xmrts setting unset daemon
```

Subcommands:

- `setting list`: show all settings (password stays hidden).
- `setting get NAME`: show one setting. Names: `price`, `autoclose`, `donate`, `currency`, `endpoint`, `daemon`, `network`, `wallet-dir`, `wallet-rpc-path`, `username`, `proxy`, `commitment`.
- `setting set NAME VALUE`: change one setting.
- `setting unset NAME`: clear an optional setting. Names: `currency`, `daemon`, `wallet-dir`, `wallet-rpc-path`, `username`, `proxy`, `commitment`.

## `stats`

Show what timestamping cost over time and what is still waiting.

```bash
xmrts stats
xmrts stats --json
```

Flags:

- `--json`: machine-readable JSON on stdout (human lines suppressed).

## `doctor`

Diagnose the installation: config, sidecar, RPC reachability, daemon health,
and `tx_extra` support.

```bash
xmrts doctor
xmrts doctor --verbose
xmrts doctor --stagenet
```

Takes no flags of its own. Honors the global `--verbose` and `--stagenet`.

## `generate`

Shell completions and man pages for your setup.

```bash
xmrts generate --completions zsh >> ~/.zshrc
xmrts generate --completions bash >> ~/.bashrc
xmrts generate --man | man -l -
```

Flags:

- `--completions SHELL`: print a completion script for `bash`, `zsh`, `fish`, `powershell`, or `elvish`.
- `--man`: render the man page (section 1).
