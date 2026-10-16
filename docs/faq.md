# FAQ

## What does timestamping actually prove?

It proves a file hash existed no later than the Monero block recorded in its
proof. That is all. It does not prove who made the file, when it was created,
or that it existed before that block. If authorship matters, GPG-sign first
with `stamp --sign-with` and verify with `--sig`, which binds the signature
to the same transaction as the file proof.

## How long does stamping take?

Submitting the transaction takes seconds. The default wait for 10
confirmations is about 20 minutes, since Monero averages a block every 2
minutes. If you do not want to wait, pass `--no-wait` to write pending proofs
immediately, then run `xmrts finalize` later. Finalizing sends no new
transaction and pays no new fee.

## How much does it cost?

One Monero transaction fee per `stamp` invocation, regardless of batch size.
Stamping a hundred files in one call costs the same as stamping one, so batch
related files together. The send amount (default 10000 atomic units) is a
self-send back to your own wallet, so only the network fee is spent. Run
`xmrts stats` to see what you have paid over time. In scripts and CI, always
set `--max-fee` so a congestion spike cannot surprise you.

## Do verifiers need a wallet?

No. Verification needs three things: the file, its `.xmrts` proof, and a
daemon to check the anchor against. Anyone can verify anywhere with:

```bash
xmrts verify report.pdf report.pdf.xmrts --daemon http://127.0.0.1:18081
```

Pass `--offline` for a cryptography-only check that skips the chain lookup.
It clearly reports that anchoring was not checked, so nobody mistakes it for
a full verification.

## Can I try it without spending XMR?

Yes, two ways. `stamp --offline` writes pending proofs without touching a
wallet, which exercises the hashing and proof plumbing for free. Or pass
`--stagenet` to any command to work with worthless test coins on Monero
stagenet instead of mainnet. You must pass `--stagenet` explicitly on every
command that should use it.

## What is the difference between pending and anchored proofs?

A pending proof says "a transaction carrying this commitment was submitted".
An anchored proof says "that transaction is buried under enough
proof-of-work". `stamp` writes pending proofs first, waits for the configured
confirmations (default 10), then upgrades them to anchored proofs. If the wait
is interrupted or confirmation is slow, the pending proofs and a recovery
record stay on disk, and `xmrts finalize` completes the upgrade later for
free. Never rely on a pending proof as evidence; wait for anchored.

## How many confirmations are enough?

The default of 10 matches Monero's own 10-block output lock and is fine for
everyday use. It is a minimum, not a guarantee. In September 2025 mainnet saw
an 18-block reorg that overwhelmed 10 confirmations, so for anything
high-value (contracts, evidence, releases) use 20 or more on both ends:

```bash
xmrts stamp --min-confirmations 20 contract.pdf
xmrts verify contract.pdf contract.pdf.xmrts --min-confirmations 20
```

Lower values like 2 anchor in minutes but die on shallow reorgs. Pick the
depth that matches what the timestamp is worth to you.

## What if I stamp now and verify years later?

That is the normal case. Proofs are self-contained files: file hash, Merkle
path, transaction id, block height, block hash, and timestamp. Keep the
`.xmrts` next to the file (or somewhere safe with `--out-dir`), and anyone
can verify it against any synced daemon, years from now, without your wallet
or your involvement. Consider running `xmrts audit` periodically over proof
archives to catch chain-side surprises early.

## What happens if the file changes after stamping?

Verification fails, loudly. Even one changed byte produces a different hash,
and the hash will not match the proof. To timestamp a new revision, stamp the
new file; it gets its own proof and its own block. Old proofs keep working
for old revisions, so keep both.

## Can I timestamp a whole folder or release?

Yes. Pass many files, or a directory with `--recursive`, in a single `stamp`
call. One transaction covers the whole batch through one Merkle root. For
slow trickles of files, `queue add` them over time and `queue flush` once to
pay a single fee:

```bash
xmrts stamp ./dist --recursive --yes
xmrts queue add draft-v1.pdf draft-v2.pdf
xmrts queue flush --yes
```

## How do I prove authorship, not just existence?

Sign first, then stamp in the same batch:

```bash
xmrts stamp --sign-with alice@example.com report.pdf
xmrts verify report.pdf report.pdf.xmrts --sig report.pdf.sig
```

GPG checks the signature and prints the signer fingerprint, while xmrts
checks that `report.pdf.sig.xmrts` anchors in the same transaction as the
file proof. A signature made later still passes GPG but fails the binding, so
a verifier knows the authorship claim and the timestamp truly go together.
If proofs live away from the files (`--out-dir`), point at the detached
proof with `--sig-proof`.

## Which daemon should I trust for verification?

Any daemon can lie by omission, so for serious checks use more than one.
Repeat `--daemon` and xmrts builds a quorum: every daemon must agree on the
anchor or verification fails. Prefer daemons you run yourself; a remote node
over plain HTTP sees your txid and timing. The same caution applies when
stamping: chain checks go to the configured daemon in the clear.

## Is my stamping activity private?

Mostly, with one honest caveat. There are no accounts, no servers, and no
telemetry. Monero hides amounts and addresses behind ring signatures, stealth
addresses, and confidential transactions. The caveat: the `XMRTS` marker in
`tx_extra` is visible on-chain, so anyone scanning the chain can enumerate
timestamp transactions and their fees. Assume the fact that you stamped, and
when, is public. The contents of your files never touch the chain, only their
hashes.

## Why does stamp close my wallet? The GUI complains.

Only one program can hold a wallet open at a time. `stamp` closes the wallet
when it finishes (success or failure) precisely so the Monero GUI can open it
afterward without lock errors. If you stamp back-to-back and would rather
close manually, opt out once:

```bash
xmrts setting set autoclose false
xmrts wallet close   # when you are done stamping
```

`finalize`, `watch`, and `verify` never need an open wallet at all.

## The wallet RPC asks for a username and password. Is that safe?

Those belong to `monero-wallet-rpc --rpc-login`, not to xmrts. Prefer wallets
without RPC login on an IP-allowlisted loopback interface. If you must use a
login, type the password at the prompt instead of passing `--password` on the
command line, where it lands in shell history and the process list. Saved
logins (`--save-auth`) are stored as plain text locked to your user, and
`xmrts connect --clear-auth` forgets them.

## What does the price setting do? Does it phone home?

`xmrts setting set price true` enables fiat fee estimates via a CoinGecko
lookup. It is off by default, and each stamp makes up to two requests that
reveal only that an xmrts user asked for a price at that time. No txid or
file data is sent. Turn it off with `xmrts setting set price false` if you
want zero network calls beyond Monero itself.

## How do I stamp release artifacts from CI?

Use the GitHub Action with a dedicated low-value timestamping wallet (never
savings) and a fee cap. See [CI Action](ci.md) for inputs, outputs, and the
attestation and checksum checks the Action performs before executing
anything.

## How do I verify an xmrts release itself?

Each release tarball ships `SHA256SUMS` inside the archive, plus a GitHub
build-provenance attestation on the release page:

```bash
tar -xzf xmrts-linux-x86_64.tar.gz
cd xmrts-linux-x86_64 && shasum -a 256 -c SHA256SUMS
gh attestation verify xmrts-linux-x86_64.tar.gz --owner <org>
```

Signed checksums via minisign or cosign are planned. Provenance attestations
are the current signing story.
