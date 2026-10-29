//! `xmrts stamp`. Hashes files, builds one Monero tx, writes proofs.
//! One run means one tx. `--offline` writes pending proofs with no wallet.

use anyhow::{Context, Result};
use clap::Args;
use std::collections::HashMap;
use std::path::{Path, PathBuf};

use super::pending::{self, PendingOp};

use crate::protocol::commitment;
use crate::protocol::hash;
use crate::protocol::merkle::MerkleTree;
use crate::protocol::proof::{Network, Proof};
use crate::wallet::connection::{self, WalletConfig};
use crate::wallet::transaction;

#[derive(Debug, Args)]
pub struct StampArgs {
    /// Files to timestamp.
    #[arg(required = true)]
    pub files: Vec<PathBuf>,
    /// Skip wallet: write pending proofs only.
    #[arg(long)]
    pub offline: bool,
    /// Build tx but do not send it.
    #[arg(long)]
    pub do_not_relay: bool,
    /// Do not wait for confirmation. Write pending proofs right away.
    #[arg(long)]
    pub no_wait: bool,
    /// Skip the confirmation prompt.
    #[arg(long)]
    pub yes: bool,
    /// Send to this address (default: your wallet address).
    #[arg(long)]
    pub address: Option<String>,
    /// Send amount in atomic units (default 10000). This is a self-send
    /// to carry the commitment: the amount returns to your wallet and only
    /// the fee is lost.
    #[arg(long, default_value_t = 10_000)]
    pub amount: u64,
    /// Refuse to send when the quoted fee is above this many atomic units.
    /// Guards `--yes` / `--json` runs against congestion fee spikes.
    #[arg(long)]
    pub max_fee: Option<u64>,
    /// Transaction priority: 0 = wallet default, 1-4 slow to fast.
    /// Higher priorities confirm sooner but cost more.
    #[arg(long, default_value_t = 0)]
    pub priority: u32,
    /// Walk directories depth-first (default: top level only).
    #[arg(long)]
    pub recursive: bool,
    /// Folder for .xmrts proofs (default: next to each file).
    #[arg(long)]
    pub out_dir: Option<PathBuf>,
    /// Daemon address for chain checks, like http://127.0.0.1:18081
    #[arg(long)]
    pub daemon: Option<String>,
    /// Required confirmations before proofs count as anchored (default 10).
    /// Lower (e.g. 2) anchors in minutes but dies on shallow reorgs;
    /// higher (e.g. 20+) is safer for high-value timestamps.
    #[arg(long)]
    pub min_confirmations: Option<u64>,
    /// Machine-readable JSON summary on stdout (human lines suppressed).
    #[arg(long)]
    pub json: bool,
    /// GPG-sign each file first (detached .sig next to it) and stamp the
    /// signatures in the same batch, binding authorship to the timestamp.
    /// Takes a GPG key id. Proofs stay plain file hashes (no protocol change).
    #[arg(long)]
    pub sign_with: Option<String>,
}

/// Effective depth gate: `--min-confirmations` or MIN_CONFIRMATIONS.
/// Rejects 0: a proof buried zero deep proves nothing about time.
/// Average minutes a Monero block takes; display-only estimate, so the
/// multiplication saturates rather than wrapping at extreme values.
const EST_MINUTES_PER_BLOCK: u64 = 2;

pub(crate) fn resolve_min_confirmations(opt: Option<u64>) -> Result<u64> {
    match opt {
        Some(0) => anyhow::bail!("--min-confirmations must be at least 1."),
        Some(n) => Ok(n),
        None => Ok(crate::wallet::daemon::MIN_CONFIRMATIONS),
    }
}

/// `--json` stdout must stay a single parseable document, and no prompt
/// can be answered by automation. This holds for every `--json` run,
/// including `--do-not-relay` previews: without it, the "Send now?"
/// prompt would spill its bytes onto stdout ahead of the JSON document.
/// Called before any wallet or hash work so the failure is fast.
pub(crate) fn ensure_json_consent(json: bool, yes: bool) -> Result<()> {
    if json && !yes {
        anyhow::bail!("--json needs --yes: no prompt can be answered in machine mode");
    }
    Ok(())
}

/// Run the stamp pipeline and report what took over.
/// `Ok(true)`: the pending machinery owns recovery from here (pending
/// record saved or proofs written) - queue flush may clear the queue.
/// `Ok(false)`: nothing was sent because the user declined the send.
/// Err: the stamp failed; callers keep whatever state they hold.
pub async fn run(args: &StampArgs, verbose: bool, stagenet: bool) -> Result<bool> {
    let result = run_inner(args, verbose, stagenet).await;
    // Release the wallet files when done (success or not) so the Monero
    // GUI or anything else can open the wallet afterwards. Best-effort:
    // no wallet open / wallet unreachable are not stamp failures.
    // `finalize`, `watch` and `verify` never need an open wallet.
    let cfg = connection::load_config();
    if cfg.autoclose && !args.offline {
        let client = cfg.client().map_err(|e| anyhow::anyhow!("{e}"))?;
        if crate::wallet::rpc::close_wallet(&client).await.is_ok() {
            super::ui::note("Wallet closed. Other apps can open it now.");
        }
    }
    result
}

pub async fn run_inner(args: &StampArgs, verbose: bool, stagenet: bool) -> Result<bool> {
    if args.json {
        super::ui::set_quiet(true);
    }
    let _ = connection::ensure_dirs();
    ensure_json_consent(args.json, args.yes)?;
    let min_conf = resolve_min_confirmations(args.min_confirmations)?;
    if args.files.is_empty() {
        anyhow::bail!("No files given.");
    }
    // UX7: accept directories (top level, or --recursive). Shell globs keep
    // working: they arrive as plain file lists.
    let inputs = expand_inputs(&args.files, args.recursive)?;
    if inputs.is_empty() {
        anyhow::bail!("No files found in the given paths.");
    }
    if inputs.len() != args.files.len() {
        super::ui::note(&format!(
            "{} path(s) expanded to {} file(s).",
            args.files.len(),
            inputs.len()
        ));
    }
    // Sign-then-stamp: detached GPG signatures are written next to each
    // file and join the same batch, so one transaction anchors both the
    // file hashes and their authorship evidence. No protocol change:
    // signatures are ordinary second inputs with their own proofs.
    let mut inputs = inputs;
    if let Some(key) = &args.sign_with {
        let mut sigs = 0usize;
        for f in inputs.clone() {
            let sig = PathBuf::from(format!("{}.sig", f.display()));
            // Never silently clobber an existing signature: a stale .sig
            // from an older file version would bind the wrong bytes.
            if sig.exists() {
                anyhow::bail!(
                    "Signature file {} already exists. Remove it (or move it aside) to sign again. Nothing stamped.",
                    sig.display()
                );
            }
            super::ui::note(&format!("Signing {} ...", f.display()));
            // No `--yes`: gpg must never overwrite an existing .sig on its
            // own; the existence check above fails first.
            // `--local-user=<value>` binds the key id to the option, so a
            // value like `--dry-run` stays a key spec and cannot be
            // re-parsed as a fresh gpg option (same family as the earlier
            // `--` separator fix for files).</think><tool_call>edit<arg_key>newString</arg_key><arg_value>            super::ui::note(&format!("Signing {} ...", f.display()));
            // No `--yes`: gpg must never overwrite an existing .sig on its
            // own; the existence check above fails first.
            // `--local-user=<value>` and `--output=<path>` bind their
            // values to the option: a key id or a dash-prefixed signature
            // path (passed as `xmrts stamp ... -- -file`) cannot be
            // re-parsed as a fresh gpg option (same family as the earlier
            // `--` separator fix for file args).
            let status = std::process::Command::new("gpg")
                .args([
                    "--detach-sign",
                    &format!("--local-user={key}"),
                    &format!("--output={}", sig.to_string_lossy()),
                    "--",
                    &f.to_string_lossy(),
                ])
                .status()
                .map_err(|e| anyhow::anyhow!("Could not run gpg ({e}). Is GnuPG installed?"))?;
            if !status.success() {
                anyhow::bail!("gpg signing failed for {}. Nothing stamped.", f.display());
            }
            inputs.push(sig);
            sigs += 1;
        }
        inputs.sort();
        super::ui::ok(&format!(
            "Signed {sigs} file(s); signatures join this batch."
        ));
    }
    let mut seen: std::collections::HashSet<String> = std::collections::HashSet::new();
    for f in &inputs {
        if !f.is_file() {
            anyhow::bail!("Cannot read file: {}", f.display());
        }
        let canon = canonical_key(f)?;
        if !seen.insert(canon) {
            anyhow::bail!("Same file twice: {}. List each file once.", f.display());
        }
    }
    // Fail fast when this run could never write its proofs: an input set
    // colliding with an existing anchored proof must stop BEFORE any wallet
    // work, i.e. before a fee is spent. (The old guard lived in
    // `write_proofs`, after relay.)
    preflight_proof_targets(&inputs, args.out_dir.as_deref())?;

    let mut hashes: Vec<([u8; 32], PathBuf)> = Vec::new();
    for f in &inputs {
        let total = std::fs::metadata(f).map(|m| m.len()).unwrap_or(0);
        let bar = super::ui::bytes_bar(&format!("Hashing {}", f.display()), total.max(1));
        let h = hash::hash_file_with_progress(f, |n| bar.inc(n))
            .with_context(|| format!("Hashing {}", f.display()))?;
        super::ui::done(&bar, &format!("Hashed {}", f.display()));
        hashes.push((h, f.clone()));
    }

    hashes.sort_by_key(|(h, _)| *h);
    // M6: dedupe identical content to one leaf. Files with the same bytes
    // share a leaf; each still gets its own proof file. HashSet for O(n).
    let mut seen_hashes: std::collections::HashSet<[u8; 32]> = std::collections::HashSet::new();
    let mut unique_hashes: Vec<[u8; 32]> = Vec::new();
    for (h, _) in &hashes {
        if seen_hashes.insert(*h) {
            unique_hashes.push(*h);
        }
    }
    if unique_hashes.len() != hashes.len() {
        super::ui::note(&format!(
            "{} file(s) share content; deduped to {} leaf/leaves.",
            hashes.len(),
            unique_hashes.len()
        ));
    }
    let (sorted, tree) = MerkleTree::build_from_unsorted(unique_hashes.clone())
        .map_err(|e| anyhow::anyhow!("Tree failed: {e}"))?;
    let root = tree.root();
    let commitment = crate::protocol::merkle::commitment_for_version(
        &root,
        tree.tree_size(),
        crate::protocol::merkle::MERKLE_V2,
    );
    super::ui::header("◆", "Stamp");
    super::ui::ok("Tree built.");
    super::ui::field("Files", &format!("{}", hashes.len()));
    super::ui::field("Root", &hex::encode(root));

    let mut cfg: WalletConfig = connection::load_config();
    if stagenet {
        cfg.network = "stagenet".to_string();
    }
    let network = Network::from_str(&cfg.network).map_err(|e| {
        anyhow::anyhow!(
            "Saved network '{}' is invalid ({e}). Fix with `xmrts connect --network mainnet`.",
            cfg.network
        )
    })?;
    let network_name = network.as_str().to_string();

    // Bare 32-byte nonce by default: the bytes look random (better than
    // the enumerable `XMRTS` magic), but the 32-byte size is unusual on
    // chain (normal nonces are 9 or 33 bytes), so it is not anonymous.
    // `magic` keeps the legacy XMRTS-tagged encoding for tooling that
    // scans for it.
    let extra_hex = match cfg.commitment.as_deref().unwrap_or("bare") {
        "magic" => {
            commitment::build_tx_extra_hex_for(&commitment, crate::protocol::merkle::MERKLE_V2)
        }
        _ => commitment::build_bare_tx_extra_hex(&commitment),
    };
    if verbose && !args.json {
        println!("Commitment: {extra_hex}");
    }

    if args.offline {
        let proofs = write_proofs(
            &hashes,
            &sorted,
            &tree,
            &network,
            &[0u8; 32],
            0,
            &[0u8; 32],
            args.out_dir.as_deref(),
        )?;
        super::ui::note("Offline run. Proofs are pending. No block yet.");
        if args.json {
            println!(
                "{}",
                serde_json::to_string(&serde_json::json!({
                    "ok": true, "pending": true, "offline": true, "final": false,
                    "warnings": ["offline run: proofs are pending, not anchored"],
                    "root": hex::encode(root),
                    "network": network_name,
                    "proofs": proofs.iter().map(|p| p.display().to_string()).collect::<Vec<_>>(),
                }))
                .unwrap()
            );
        }
        return Ok(true);
    }

    let mut client = cfg.client().map_err(|e| anyhow::anyhow!("{e}"))?;
    if cfg.wallet_dir.is_none() {
        let found = crate::wallet::discover::discover();
        if found.len() == 1 {
            let d = found[0].dir.display().to_string();
            cfg.wallet_dir = Some(d.clone());
            let _ = connection::save_config(&cfg);
            super::ui::ok(&format!("Found wallets in {d}. Using it."));
            client = cfg.client().map_err(|e| anyhow::anyhow!("{e}"))?;
        }
    }
    match crate::wallet::process::status(&cfg, &client).await {
        crate::wallet::process::SidecarStatus::Stopped => {
            super::ui::info("Helper is stopped. Starting it...");
            crate::wallet::process::start(&mut cfg)
                .await
                .map_err(|e| anyhow::anyhow!("Helper did not start: {e}"))?;
            client = cfg.client().map_err(|e| anyhow::anyhow!("{e}"))?;
            super::ui::ok("Helper is up.");
        }
        crate::wallet::process::SidecarStatus::Unhealthy(pid) => {
            anyhow::bail!("Helper (pid {pid}) stays quiet. Check `xmrts wallet status`");
        }
        crate::wallet::process::SidecarStatus::NotManaged(reason)
            if cfg.wallet_dir.is_none() && !crate::wallet::discover::discover().is_empty() =>
        {
            super::ui::note(&format!("Helper is off. {reason}"));
            super::ui::hint("Run `xmrts init` and pick a wallet folder.");
        }
        _ => {}
    }
    let version = client.get_version().await.with_context(|| {
        format!(
            "Wallet is quiet.\n\nEndpoint:\n{}\n\nTry:\n\n    xmrts doctor",
            connection::display_url(&cfg.endpoint)
        )
    })?;
    if verbose {
        super::ui::field("Wallet RPC", &format!("v{}.{}", version.0, version.1));
    }
    // Fast hint before any work: stock wallets silently ignore the
    // `extra` key, which would relay a mark-less tx. The patch bumps the
    // RPC minor 30 -> 31, so < (1, 31) is certainly stock. >= (1, 31) is
    // only a hint (a later stock release could also report 31+), so the
    // definitive gate is the tx-blob mark check in `preview_timestamp`
    // before relay: nothing is broadcast without the commitment bytes.
    if version < (1, 31) {
        anyhow::bail!(
            "Wallet RPC v{}.{} looks stock: no `extra` support. Stamping would spend a fee with no mark.\nInstall the patched monero-wallet-rpc (see README: Managed sidecar).",
            version.0,
            version.1
        );
    }
    let (address, address_checked) = match &args.address {
        Some(a) => (a.clone(), false),
        None => match client.get_address().await {
            Ok(a) => (a, true),
            Err(_) => {
                // No wallet open yet: run the open flow inline (wallet
                // list + hidden password prompt) instead of failing. The
                // password is never stored; non-interactive runs cannot
                // answer a prompt, so they still fail loudly.
                if !super::ui::is_interactive() {
                    anyhow::bail!("No open wallet. Open one with `xmrts wallet open` first");
                }
                super::ui::note("No wallet is open. Opening one now...");
                super::wallet::open_flow(&cfg, &client).await?;
                let a = client
                    .get_address()
                    .await
                    .context("Wallet still gives no address after opening it")?;
                (a, true)
            }
        },
    };
    if args.amount == 0 {
        anyhow::bail!("--amount must be at least 1 atomic unit (dust is rejected by the network).");
    }
    if args.priority > 4 {
        anyhow::bail!("--priority must be 0-4 (0 = default, 1-4 slow to fast).");
    }
    if !address_checked {
        let owned = client.owns_address(&address).await.map_err(|e| {
            anyhow::anyhow!(
                "Could not check address ownership: {e}\nSkip --address to use your own."
            )
        })?;
        if !owned {
            anyhow::bail!(
                "That address is outside this wallet:\n{address}\nSkip --address to use your own."
            );
        }
    }
    // Surface balance-fetch failures instead of rendering (0, 0): a
    // transient RPC error must not masquerade as "no unlocked funds",
    // which would send the user chasing a wallet state that may not be
    // the problem. `None` means the balance could not be read: the
    // display says so, the affordability pre-check below is skipped,
    // and a still-later `transfer` fails with its own clear error if
    // funds are genuinely missing.
    let unlocked_funds: Option<u64> = match client.get_balance().await {
        Ok((balance, unlocked)) => {
            super::ui::field("Network", &network_name);
            super::ui::field("To (self)", &super::ui::short_address(&address));
            super::ui::field(
                "Balance",
                &format!(
                    "{} ({} unlocked)",
                    transaction::format_xmr(balance),
                    transaction::format_xmr(unlocked)
                ),
            );
            if unlocked == 0 {
                super::ui::warn(
                    "No unlocked funds. The transfer will fail until outputs unlock (10 blocks).",
                );
            }
            Some(unlocked)
        }
        Err(e) => {
            super::ui::field("Network", &network_name);
            super::ui::field("To (self)", &super::ui::short_address(&address));
            super::ui::field("Balance", &format!("unavailable ({e})"));
            super::ui::note(
                "Could not read the balance from the wallet; continuing without the affordability check. If funds are actually missing, the transfer below will fail with its own error.",
            );
            None
        }
    };

    // Donations ride in the stamp tx as a fee-sized developer output,
    // matched exactly to the fee via a do_not_relay rebuild. The
    // donation address is mainnet; other networks skip it.
    let donate = cfg.donate && network_name == "mainnet";
    if cfg.donate && !donate {
        super::ui::note("Donations are on, but they apply to mainnet only. Skipping this run.");
    }

    let fee_bar = super::ui::spinner("Checking fee...");
    let previewed = if donate {
        transaction::preview_timestamp_with_donation(
            &client,
            &address,
            args.amount,
            &extra_hex,
            args.priority,
            transaction::DONATION_ADDRESS,
        )
        .await
    } else {
        transaction::preview_timestamp(&client, &address, args.amount, &extra_hex, args.priority)
            .await
            .map(|(res, tx)| (res, 0u64, tx))
    };
    super::ui::abandon(&fee_bar);
    let (preview, donation, tx_hex) = previewed.map_err(|e| {
        let msg = e.to_string();
        // `transfer` needs the wallet's own daemon link (decoy outputs).
        // "Failed to get height" means the sidecar cannot reach its daemon:
        // usually it was started before the daemon was configured, or the
        // daemon address lost its https:// scheme.
        if msg.contains("Failed to get height") || msg.contains("no connection to daemon") {
            anyhow::anyhow!(
                "Wallet said no: {e}\n\nThe wallet cannot reach its daemon, so it cannot build the tx.\nTry:\n\n    xmrts wallet stop\n    xmrts wallet start\n\nthen `xmrts doctor` (Daemon tip should move and Wallet height should catch up)."
            )
        } else {
            anyhow::anyhow!("Wallet said no: {e}")
        }
    })?;
    // One price fetch per run: the fee is known once, so the quote, the
    // "Fee" line and the donation line share it instead of calling
    // CoinGecko again (the donation is exactly the fee).
    let fee_fiat = super::ui::fiat_for(preview.fee, &cfg).await;
    super::ui::field(
        "Fee",
        &super::ui::with_fiat(&transaction::format_xmr(preview.fee), fee_fiat.clone()),
    );
    if donation > 0 {
        super::ui::field(
            "Donation to xmrts devs",
            &super::ui::with_fiat(&transaction::format_xmr(donation), fee_fiat.clone()),
        );
        super::ui::field(
            "Donation address",
            &super::ui::short_address(transaction::DONATION_ADDRESS),
        );
    }
    let needed = args
        .amount
        .saturating_add(preview.fee)
        .saturating_add(donation);
    // Skipped when the balance could not be read (unlocked_funds is
    // None): the transfer below fails with its own error instead.
    if unlocked_funds.is_some_and(|unlocked| unlocked < needed) {
        anyhow::bail!(
            "Not enough unlocked funds: need {} (amount + fee + donation) but only {} is unlocked. Wait for outputs to unlock (10 blocks) or lower --amount.",
            transaction::format_xmr(needed),
            transaction::format_xmr(unlocked_funds.unwrap_or(0))
        );
    }
    if args.amount > preview.fee.saturating_mul(100).max(1_000_000) {
        super::ui::warn(&format!(
            "Amount {} dwarfs the fee {}. It returns to you, but forces more inputs (bigger tx, higher fee). Consider the default 10000.",
            transaction::format_xmr(args.amount),
            transaction::format_xmr(preview.fee)
        ));
    }
    if let Some(cap) = args.max_fee {
        if preview.fee > cap {
            anyhow::bail!(
                "Fee {} is above --max-fee {}. Not sending.",
                transaction::format_xmr(preview.fee),
                transaction::format_xmr(cap)
            );
        }
    }
    let pending_path = pending::save(&PendingOp {
        files: inputs
            .iter()
            .map(|f| f.to_string_lossy().into_owned())
            .collect(),
        file_hashes: vec![],
        sorted_hashes: sorted.iter().map(hex::encode).collect(),
        root: hex::encode(root),
        extra_hex: extra_hex.clone(),
        txid: preview.tx_hash.clone(),
        tx_hex: tx_hex.clone(),
        fee: preview.fee,
        out_dir: args
            .out_dir
            .as_ref()
            .map(|d| d.to_string_lossy().into_owned()),
        network: network_name.clone(),
        merkle_ver: crate::protocol::merkle::MERKLE_V2,
        // Honesty first: at save time this tx is still a preview. A crash
        // between save and relay must NOT leave a record claiming a
        // broadcast that never happened. `pending::update_txid` flips
        // `relayed` to true in the same atomic write as the final txid.
        relayed: false,
    })?;

    // Machine mode never prompts: `ensure_json_consent` already required
    // --yes when --json, so interactive consent is the only remaining path.
    if !args.yes && !super::ui::confirm("Send now? [y/N] ")? {
        let _ = std::fs::remove_file(&pending_path);
        super::ui::note("Stopped. No funds spent. Nothing published.");
        if args.json {
            println!(
                "{}",
                serde_json::to_string(&serde_json::json!({"ok": false, "cancelled": true}))
                    .unwrap_or_else(|_| "{}".into())
            );
        }
        // Nothing sent and no recovery record saved: the caller must not
        // clear queue entries collected for this stamp.
        return Ok(false);
    }

    let tx_hash = if args.do_not_relay {
        super::ui::note("Kept local (--do-not-relay). Nothing sent.");
        preview.tx_hash
    } else {
        let h = transaction::relay(&client, &tx_hex).await.map_err(|e| {
            // Nothing was broadcast, so the preview txid in the pending
            // record would poison `finalize` forever. Drop the record.
            let _ = std::fs::remove_file(&pending_path);
            let msg = e.to_string();
            // Relay commits through the wallet's own daemon link. A stale
            // or unreachable daemon fails the commit even though the
            // preview built fine.
            if msg.contains("Failed to commit tx") {
                anyhow::anyhow!(
                    "Send failed: {e}\n\nThe wallet could not commit to its daemon (preview txid was {}). Check `xmrts doctor`: the daemon must be reachable and synced, and the wallet height caught up.\nIf that txid later confirms anyway, wait before re-stamping: a retry spends the same outputs and the daemon rejects it as a double spend until the first tx clears.\nIf the daemon changed since the helper started, run:\n\n    xmrts wallet stop\n    xmrts wallet start",
                    preview.tx_hash
                )
            } else {
                anyhow::anyhow!("Send failed: {e} (preview txid was {})", preview.tx_hash)
            }
        })?;
        if let Err(e) = pending::update_txid(&pending_path, &h) {
            super::ui::warn(&format!(
                "Relayed but the pending record update failed: {e}. The recover path holds: `finalize` judges the record from the chain, not from the relayed flag, so it will proceed once the tx shows up."
            ));
        }
        h
    };
    if !args.json {
        println!();
    }
    super::ui::field("Transaction", &tx_hash);
    super::ui::field(
        "Fee paid",
        &super::ui::with_fiat(&transaction::format_xmr(preview.fee), fee_fiat),
    );
    let txid_bytes: [u8; 32] = hex::decode(&tx_hash)
        .context("Wallet gave a bad tx hash")?
        .try_into()
        .map_err(|_| anyhow::anyhow!("Wallet gave a short tx hash"))?;

    let (height, block_hash) = if args.no_wait || args.do_not_relay {
        super::ui::note("Skipping wait. Proofs stay pending.");
        (0u64, [0u8; 32])
    } else {
        super::ui::note(&format!(
            "Monero averages a block every ~2 minutes; anchoring needs {min_conf} confirmation(s) (~{} minutes).",
            min_conf.saturating_mul(EST_MINUTES_PER_BLOCK)
        ));
        super::ui::hint(
            "Ctrl-C is safe here: the pending record is saved, resume with `xmrts finalize`.",
        );
        let bar = super::ui::spinner("Waiting for block...");
        let found = wait_for_confirmation(&client, &tx_hash, &bar).await;
        super::ui::abandon(&bar);
        match found {
            Some((h, bh)) => {
                super::ui::ok(&format!("Locked in block {h}."));
                (h, bh)
            }
            None => {
                super::ui::note("No block yet (normal for slow blocks). Proofs stay pending.");
                super::ui::hint("Run `xmrts finalize` once it confirms.");
                (0u64, [0u8; 32])
            }
        }
    };

    // H1+H2+H3: the wallet's word is not enough. Re-check the mark on the
    // daemon, fetch the REAL block hash (never zeros), require exact height
    // match and MIN_CONFIRMATIONS depth. Anything short stays pending.
    let (height, block_hash) = if height > 0 {
        // M5: never go pending just because no daemon was configured. Fall
        // back to the default local daemon for this read-only recheck.
        let (daemon, is_default) = match args.daemon.clone().or(cfg.daemon_endpoint.clone()) {
            Some(d) => (d, false),
            None => {
                super::ui::note(
                    "No daemon configured. Trying the default local node http://127.0.0.1:18081.",
                );
                ("http://127.0.0.1:18081".to_string(), true)
            }
        };
        {
            let d = daemon;
            if let Some(w) = connection::insecure_daemon_warning(&d) {
                super::ui::warn(&w);
            }
            let bar = super::ui::spinner("Checking chain...");
            let chain_height = crate::wallet::daemon::confirm_commitment_for_version(
                &d,
                &tx_hash,
                &commitment,
                Some(crate::protocol::merkle::MERKLE_V2),
            )
            .await;
            super::ui::abandon(&bar);
            match chain_height {
                Ok(chain_height) => {
                    if chain_height != height {
                        super::ui::warn(&format!(
                            "Wallet says block {height} but chain says {chain_height}. Proofs stay pending."
                        ));
                        (0u64, [0u8; 32])
                    } else {
                        match crate::wallet::daemon::block_hash(&d, chain_height).await {
                            Ok(bh) => {
                                // Depth gate: wait for MIN_CONFIRMATIONS burial
                                // instead of anchoring at depth 1.
                                let bar = super::ui::spinner("Waiting for confirmations...");
                                let depth = wait_for_depth(&d, chain_height, min_conf, &bar).await;
                                super::ui::abandon(&bar);
                                if depth < min_conf {
                                    super::ui::note(&format!(
                                        "Only {depth} confirmation(s); want {min_conf}+. Proofs stay pending until deep enough."
                                    ));
                                    super::ui::hint("Run `xmrts finalize` once it buries deeper.");
                                    (0u64, [0u8; 32])
                                } else {
                                    super::ui::ok("Chain holds your mark.");
                                    (chain_height, bh)
                                }
                            }
                            Err(e) => {
                                super::ui::warn(&format!(
                                    "Block hash missed ({e}). Proofs stay pending."
                                ));
                                super::ui::hint("Run `xmrts finalize` once the daemon answers.");
                                (0u64, [0u8; 32])
                            }
                        }
                    }
                }
                Err(e) => {
                    if is_default {
                        super::ui::warn(&format!(
                            "Default local daemon did not confirm ({e}). Proofs stay pending."
                        ));
                    } else {
                        super::ui::warn(&format!("Tx is in but mark is missing: {e}"));
                    }
                    super::ui::hint(
                        "Set one with `xmrts connect --daemon <url>` or run `xmrts finalize` later.",
                    );
                    (0u64, [0u8; 32])
                }
            }
        }
    } else {
        (0u64, block_hash)
    };

    let proofs = write_proofs(
        &hashes,
        &sorted,
        &tree,
        &network,
        &txid_bytes,
        height,
        &block_hash,
        args.out_dir.as_deref(),
    )?;
    if height > 0 {
        let _ = std::fs::remove_file(&pending_path);
        super::stats::record(&super::stats::HistoryEntry {
            txid: hex::encode(txid_bytes),
            fee: preview.fee,
            files: hashes.len(),
            height,
            network: network_name.clone(),
            time_unix: super::stats::now_unix(),
        });
        super::ui::ok(&format!("Done. Files prove no later than block {height}."));
    }
    if args.json {
        let pending = height == 0;
        println!(
            "{}",
            serde_json::to_string(&serde_json::json!({
                "ok": true, "pending": pending, "final": !pending,
                "warnings": if pending { vec!["still pending: not buried deep enough; run `xmrts finalize` later".to_string()] } else { Vec::<String>::new() },
                "txid": hex::encode(txid_bytes),
                "block_height": height,
                "root": hex::encode(root),
                "network": network_name,
                "donation": donation,
                "proofs": proofs.iter().map(|p| p.display().to_string()).collect::<Vec<_>>(),
            }))
            .unwrap()
        );
    }
    Ok(true)
}

/// Canonical string for cross-walk identity. Used by stamp and audit
/// directory walks as a cycle guard: the same physical dir twice means
/// stop, not loop forever.
pub(crate) fn canonical_key(p: &Path) -> Result<String> {
    p.canonicalize()
        .map(|c| c.to_string_lossy().into_owned())
        .map_err(|e| anyhow::anyhow!("cannot canonicalize {}: {e}", p.display()))
}

/// Expand stamp inputs: plain files pass through, directories expand to
/// their files (top level, or depth-first with `--recursive`). Output is
/// sorted for determinism. Broken symlinks and missing paths are errors
/// for explicit args. Directory walks skip `*.xmrts` proof files (so a
/// folder that already holds proofs does not hash them into `.xmrts.xmrts`)
/// and never follow symlinks (prevents cycles like `a -> ..` from
/// collapsing into a misleading "Same file twice").
fn expand_inputs(paths: &[PathBuf], recursive: bool) -> Result<Vec<PathBuf>> {
    let mut out: Vec<PathBuf> = Vec::new();
    let mut visited_dirs: std::collections::HashSet<String> = std::collections::HashSet::new();
    let mut skipped_proofs = 0usize;
    let mut skipped_symlinks = 0usize;
    for p in paths {
        // Explicit symlink to a file: hash the target (intentional use).
        // Explicit symlink to a dir: walk it once, but never follow
        // nested symlinks inside (see collect_dir).
        if p.is_file() {
            if is_xmrts_proof(p) {
                anyhow::bail!(
                    "Refusing to stamp proof file itself: {}. Stamp the original file instead.",
                    p.display()
                );
            }
            out.push(p.clone());
        } else if p.is_dir() {
            collect_dir(
                p,
                recursive,
                &mut out,
                &mut visited_dirs,
                &mut skipped_proofs,
                &mut skipped_symlinks,
            )?;
        } else {
            anyhow::bail!("Cannot read file: {}", p.display());
        }
    }
    out.sort();
    if skipped_proofs > 0 {
        super::ui::note(&format!(
            "Skipped {skipped_proofs} proof file(s) (*.xmrts)."
        ));
    }
    if skipped_symlinks > 0 {
        super::ui::note(&format!(
            "Skipped {skipped_symlinks} symlink(s) (not followed)."
        ));
    }
    Ok(out)
}

fn is_xmrts_proof(p: &Path) -> bool {
    p.extension()
        .is_some_and(|e| e.eq_ignore_ascii_case("xmrts"))
}

fn collect_dir(
    dir: &Path,
    recursive: bool,
    out: &mut Vec<PathBuf>,
    visited: &mut std::collections::HashSet<String>,
    skipped_proofs: &mut usize,
    skipped_symlinks: &mut usize,
) -> Result<()> {
    // Cycle guard: same canonical dir twice (e.g. via an explicit
    // symlinked dir arg + its target) means stop, not loop forever.
    let canon = canonical_key(dir)?;
    if !visited.insert(canon) {
        return Ok(());
    }
    let mut entries: Vec<PathBuf> = std::fs::read_dir(dir)
        .with_context(|| format!("Reading dir {}", dir.display()))?
        .filter_map(|e| e.ok().map(|e| e.path()))
        .collect();
    entries.sort();
    for e in entries {
        // Never follow symlinks: lstat first. This skips symlinked files
        // and dirs alike, including broken links and cycles.
        match std::fs::symlink_metadata(&e) {
            Ok(md) if md.file_type().is_symlink() => {
                *skipped_symlinks += 1;
                continue;
            }
            Err(_) => {
                anyhow::bail!("Cannot read file: {}", e.display());
            }
            _ => {}
        }
        if e.is_file() {
            if is_xmrts_proof(&e) {
                *skipped_proofs += 1;
                continue;
            }
            out.push(e);
        } else if e.is_dir() && recursive {
            collect_dir(&e, true, out, visited, skipped_proofs, skipped_symlinks)?;
        }
    }
    Ok(())
}

/// Poll the wallet for the first confirmation. Monero averages a block
/// every ~2 minutes, so we wait up to ~10 minutes (120 x 5s) with a
/// visible countdown; afterwards `xmrts finalize` finishes the job.
async fn wait_for_confirmation(
    client: &crate::wallet::rpc::WalletRpc,
    txid: &str,
    progress: &indicatif::ProgressBar,
) -> Option<(u64, [u8; 32])> {
    const ROUNDS: u64 = 120;
    const STEP_SECS: u64 = 5;
    for i in 0..ROUNDS {
        tokio::time::sleep(std::time::Duration::from_secs(STEP_SECS)).await;
        let elapsed = (i + 1) * STEP_SECS;
        let remain = (ROUNDS - i - 1) * STEP_SECS;
        progress.set_message(format!(
            "Waiting for block... {elapsed}s in, ~{remain}s left (blocks average ~2 min; up to ~10 min wait)"
        ));
        if let Ok(v) = crate::wallet::rpc::get_transfer_by_txid(client, txid).await {
            let h = v
                .get("transfer")
                .and_then(|t| t.get("height"))
                .or_else(|| v.get("height"))
                .and_then(|h| h.as_u64())
                .unwrap_or(0);
            if h > 0 {
                return Some((h, [0u8; 32]));
            }
        }
    }
    None
}

/// Poll the daemon until `block_height` is buried `min_conf` deep
/// (~2 minutes per confirmation at 5s polls: 24 rounds each). Returns
/// the depth reached; callers stay pending when it is still shallow.
async fn wait_for_depth(
    daemon: &str,
    block_height: u64,
    min_conf: u64,
    progress: &indicatif::ProgressBar,
) -> u64 {
    const STEP_SECS: u64 = 5;
    // ~2 min/block of polling per required confirmation (24 x 5s).
    let rounds: u64 = min_conf.saturating_mul(24).max(24);
    let mut depth = 1;
    for i in 0..rounds {
        if let Ok((_, tip)) = crate::wallet::daemon::get_info(daemon).await {
            // `get_info.height` is the chain length (top + 1): no +1 here.
            depth = crate::wallet::daemon::confirmations(tip, block_height);
            if depth >= min_conf {
                return depth;
            }
        }
        let remain = (rounds - i - 1) * STEP_SECS;
        progress.set_message(format!(
            "Waiting for confirmations... {depth}/{min_conf} (~{remain}s left)"
        ));
        tokio::time::sleep(std::time::Duration::from_secs(STEP_SECS)).await;
    }
    depth
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn write_proofs(
    sorted_inputs: &[([u8; 32], PathBuf)],
    sorted: &[[u8; 32]],
    tree: &MerkleTree,
    network: &Network,
    txid: &[u8; 32],
    height: u64,
    block_hash: &[u8; 32],
    out_dir: Option<&Path>,
) -> Result<Vec<PathBuf>> {
    // M6: one leaf per distinct hash; files with identical content share
    // the same leaf_index.
    let mut written: Vec<PathBuf> = Vec::new();
    let mut seen_paths: std::collections::HashSet<PathBuf> = std::collections::HashSet::new();
    let mut index_of: HashMap<[u8; 32], u64> = HashMap::new();
    for (i, h) in sorted.iter().enumerate() {
        index_of.insert(*h, i as u64);
    }
    for (h, path) in sorted_inputs {
        let leaf_index = *index_of
            .get(h)
            .ok_or_else(|| anyhow::anyhow!("Tree failed: file hash missing from deduped tree"))?;
        let _ = sorted;
        let siblings = tree
            .proof_for(leaf_index)
            .map_err(|e| anyhow::anyhow!("Tree failed: {e}"))?;
        // Pending proofs keep the txid when known (e.g. `--no-wait` after
        // relay): `is_pending()` keys on `block_height == 0`, so the txid
        // survives and `finalize` can upgrade the proof file itself without
        // the pending record. Offline proofs keep zeros (no tx yet).
        let proof = if height == 0 {
            Proof::new(
                *network,
                *h,
                leaf_index,
                tree.tree_size(),
                tree.root(),
                *txid,
                0,
                [0u8; 32],
                siblings,
            )
        } else {
            Proof::new(
                *network,
                *h,
                leaf_index,
                tree.tree_size(),
                tree.root(),
                *txid,
                height,
                *block_hash,
                siblings,
            )
        }
        .map_err(|e| anyhow::anyhow!("Proof failed: {e}"))?;
        let out = proof_path_for(path, out_dir)?;
        // Two inputs with the same file name (e.g. a/x.txt + b/x.txt with
        // one --out-dir) would silently overwrite each other: fail instead.
        if !seen_paths.insert(out.clone()) {
            anyhow::bail!(
                "Two inputs map to the same proof file {}. Use separate --out-dir runs.",
                out.display()
            );
        }
        // Never silently replace an existing proof: the earlier anchored
        // timestamp is the valuable one. Re-stamping the same files must
        // not swap it for a later proof. The one exception is the
        // pending -> anchored upgrade (`finalize`, or `stamp` after the
        // depth gate): overwriting a pending proof with its anchored
        // version is the intended finish step. Anchored/foreign collisions
        // already bailed in `preflight_proof_targets` before any fee was
        // spent; this is the backstop (e.g. a file appearing mid-run).
        match proof_target_status(&out)? {
            ProofTarget::Pending if height != 0 => {
                super::ui::note(&format!(
                    "Upgrading pending proof {} to anchored (block {height}).",
                    out.display()
                ));
            }
            ProofTarget::Pending => {
                anyhow::bail!(
                    "Proof {} already exists (pending). Remove it or use --out-dir to re-stamp.",
                    out.display()
                );
            }
            ProofTarget::Anchored(block_height) => {
                anyhow::bail!(
                    "Proof {} already exists and is anchored (block {}). Refusing to replace the earlier timestamp. Remove it or use --out-dir if you really want a later proof.",
                    out.display(),
                    block_height
                );
            }
            ProofTarget::Foreign => {
                anyhow::bail!(
                    "File {} already exists and is not a valid proof. Refusing to overwrite.",
                    out.display()
                );
            }
            ProofTarget::Free => {}
        }
        std::fs::write(&out, proof.to_bytes())
            .with_context(|| format!("Writing {}", out.display()))?;
        super::ui::ok(&format!("Proof: {}", out.display()));
        written.push(out);
    }
    Ok(written)
}

/// What already sits at a would-be proof path.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ProofTarget {
    /// Nothing there: safe to write.
    Free,
    /// A pending proof: only a run that anchors may replace it.
    Pending,
    /// An anchored proof at this block height: never replace implicitly.
    Anchored(u64),
    /// Exists but is not a parseable proof: never touch.
    Foreign,
}

/// Classify what sits at a would-be proof path. Missing files are `Free`;
/// existing-but-unreadable files (permissions etc.) are hard errors.
pub(crate) fn proof_target_status(out: &Path) -> Result<ProofTarget> {
    let raw = match std::fs::read(out) {
        Ok(b) => b,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(ProofTarget::Free),
        Err(e) => {
            anyhow::bail!("Proof {} exists but cannot be read: {e}", out.display());
        }
    };
    match Proof::from_bytes(&raw) {
        Ok(p) if p.is_pending() => Ok(ProofTarget::Pending),
        Ok(p) => Ok(ProofTarget::Anchored(p.block_height)),
        Err(_) => Ok(ProofTarget::Foreign),
    }
}

/// Pre-flight guard: every input must map to a writable proof path BEFORE
/// any hashing, fee quote, or relay. An anchored (or foreign) collision, or
/// two inputs sharing one proof path via `--out-dir`, bails here so no fee
/// is ever spent on a run that could not write its proofs. A pending
/// collision only warns: a run that anchors upgrades it, otherwise
/// `write_proofs` still refuses after the fact — prefer `finalize` first.
fn preflight_proof_targets(inputs: &[PathBuf], out_dir: Option<&Path>) -> Result<()> {
    let mut seen: std::collections::HashSet<PathBuf> = std::collections::HashSet::new();
    for input in inputs {
        let out = proof_path_for(input, out_dir)?;
        if !seen.insert(out.clone()) {
            anyhow::bail!(
                "Two inputs map to the same proof file {}. Use separate --out-dir runs.",
                out.display()
            );
        }
        match proof_target_status(&out)? {
            ProofTarget::Free => {}
            ProofTarget::Pending => {
                super::ui::warn(&format!(
                    "Proof {} already exists (pending). This run replaces it only if the new tx anchors; otherwise it fails. Prefer `xmrts finalize` first.",
                    out.display()
                ));
            }
            ProofTarget::Anchored(block_height) => {
                anyhow::bail!(
                    "Proof {} already exists and is anchored (block {}). Refusing to replace the earlier timestamp. Remove it or use --out-dir if you really want a later proof.",
                    out.display(),
                    block_height
                );
            }
            ProofTarget::Foreign => {
                anyhow::bail!(
                    "File {} already exists and is not a valid proof. Refusing to overwrite.",
                    out.display()
                );
            }
        }
    }
    Ok(())
}

pub(crate) fn proof_path_for(input: &Path, out_dir: Option<&Path>) -> Result<PathBuf> {
    let file_name = input
        .file_name()
        .map(|s| format!("{}.xmrts", s.to_string_lossy()))
        .ok_or_else(|| anyhow::anyhow!("Bad file name: {}", input.display()))?;
    match out_dir {
        Some(d) => {
            std::fs::create_dir_all(d)?;
            Ok(d.join(file_name))
        }
        None => Ok(PathBuf::from(format!("{}.xmrts", input.display()))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn anchored_proof_bytes() -> Vec<u8> {
        Proof::new(
            Network::Mainnet,
            [0x11u8; 32],
            0,
            1,
            [0x22u8; 32],
            [0x33u8; 32],
            3_783_935,
            [0xabu8; 32],
            vec![],
        )
        .unwrap()
        .to_bytes()
    }

    fn pending_proof_bytes() -> Vec<u8> {
        Proof::new_pending(Network::Mainnet, [0x11u8; 32], 0, 1, [0x22u8; 32], vec![])
            .unwrap()
            .to_bytes()
    }

    #[test]
    fn preflight_refuses_anchored_before_any_wallet_work() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("LICENSE");
        std::fs::write(&file, b"license text").unwrap();
        std::fs::write(dir.path().join("LICENSE.xmrts"), anchored_proof_bytes()).unwrap();
        let err = preflight_proof_targets(&[file], None).unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("already exists and is anchored"), "{msg}");
        assert!(msg.contains("3783935"), "{msg}");
    }

    #[test]
    fn preflight_refuses_foreign_files_and_intra_run_collisions() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("a.txt");
        std::fs::write(&file, b"a").unwrap();
        std::fs::write(dir.path().join("a.txt.xmrts"), b"not a proof").unwrap();
        let err = preflight_proof_targets(&[file], None).unwrap_err();
        assert!(format!("{err:#}").contains("not a valid proof"));

        // Two inputs mapping to one proof file via --out-dir.
        let out = dir.path().join("out");
        let x = dir.path().join("x");
        let y = dir.path().join("y");
        std::fs::create_dir_all(&x).unwrap();
        std::fs::create_dir_all(&y).unwrap();
        std::fs::write(x.join("same.txt"), b"x").unwrap();
        std::fs::write(y.join("same.txt"), b"y").unwrap();
        let err = preflight_proof_targets(&[x.join("same.txt"), y.join("same.txt")], Some(&out))
            .unwrap_err();
        assert!(format!("{err:#}").contains("same proof file"));
    }

    #[test]
    fn preflight_passes_free_targets_and_warns_on_pending() {
        let dir = tempfile::tempdir().unwrap();
        let fresh = dir.path().join("fresh.txt");
        std::fs::write(&fresh, b"fresh").unwrap();
        assert!(preflight_proof_targets(&[fresh], None).is_ok());

        let waiting = dir.path().join("waiting.txt");
        std::fs::write(&waiting, b"waiting").unwrap();
        std::fs::write(dir.path().join("waiting.txt.xmrts"), pending_proof_bytes()).unwrap();
        // Pending only warns (an anchoring run upgrades it), never bails.
        assert!(preflight_proof_targets(&[waiting], None).is_ok());
    }

    #[test]
    fn target_status_classifies_everything_on_disk() {
        let dir = tempfile::tempdir().unwrap();
        let missing = dir.path().join("nope.xmrts");
        assert_eq!(proof_target_status(&missing).unwrap(), ProofTarget::Free);
        let anchored = dir.path().join("a.xmrts");
        std::fs::write(&anchored, anchored_proof_bytes()).unwrap();
        assert_eq!(
            proof_target_status(&anchored).unwrap(),
            ProofTarget::Anchored(3_783_935)
        );
        let pending = dir.path().join("p.xmrts");
        std::fs::write(&pending, pending_proof_bytes()).unwrap();
        assert_eq!(proof_target_status(&pending).unwrap(), ProofTarget::Pending);
        let foreign = dir.path().join("f.xmrts");
        std::fs::write(&foreign, b"junk").unwrap();
        assert_eq!(proof_target_status(&foreign).unwrap(), ProofTarget::Foreign);
    }

    #[test]
    fn json_stamp_needs_yes() {
        // Machine mode cannot answer prompts: --json without --yes must
        // fail fast and clean, for every send mode (plain, --do-not-relay),
        // so stdout stays a single parseable document.
        assert!(ensure_json_consent(true, false).is_err());
        assert!(ensure_json_consent(true, true).is_ok());
        // Interactive runs prompt as usual.
        assert!(ensure_json_consent(false, false).is_ok());
        assert!(ensure_json_consent(false, true).is_ok());
        let err = format!("{:#}", ensure_json_consent(true, false).unwrap_err());
        assert!(err.contains("--json needs --yes"), "{err}");
    }
}
