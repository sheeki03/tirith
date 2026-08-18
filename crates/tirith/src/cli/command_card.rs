//! M11 ch1 — `tirith command-card create|sign|verify|fetch`.
//!
//! Maintainer: `create` builds an unsigned card; `sign --key <priv> <card.json>`
//! stamps an ed25519 signature. User: `verify <card.json>` checks against the
//! trusted-keys dir; `fetch <url>` downloads + caches under
//! `~/.cache/tirith/cards/<sha256>.json` (the ONLY remote-I/O path).

use std::io::Write;
use std::path::Path;

use tirith_core::command_card::{
    self, key_id_for_secret_key, Card, CardError, CardSignature, VerifyFailure, CARD_SCHEMA_V2,
    CARD_SCHEMA_V3, SECRET_KEY_LEN,
};
use tirith_core::tokenize::ShellType;
use tirith_core::util::{read_regular_capped, OpenRegularError};

/// Read cap for a card JSON file in `sign`/`verify`. Matches the engine
/// hot-path `CARD_READ_CAP` so the CLI and analysis refuse the same files;
/// routing through [`read_regular_capped`] also blocks FIFO/device opens.
const CARD_READ_CAP: u64 = 64 * 1024;

/// Read cap for the ed25519 secret-key file in `sign`. A 32-byte key (raw/hex/
/// base64) is well under 4 KiB; larger is malformed. Read via
/// [`read_regular_capped`] to bound the read and refuse FIFO/device paths.
const SECRET_KEY_READ_CAP: u64 = 4096;

/// One-line terminal-safe rendering for every card-derived or path-derived
/// value in the human CLI. Structured JSON deliberately retains the raw value
/// and relies on serde's JSON escaping instead.
fn human_display_field(value: &str) -> String {
    super::sanitize_for_human_output(value, false)
}

/// Render an [`OpenRegularError`] as a human message prefixed with `what` (e.g.
/// `"read card.json"`), keeping the FIFO/device and oversized cases legible.
fn describe_open_error(what: &str, path: &str, cap: u64, e: &OpenRegularError) -> String {
    match e {
        OpenRegularError::NotFound => format!("{what} {path}: no such file"),
        OpenRegularError::NotRegularFile => {
            format!("{what} {path}: not a regular file (refusing a FIFO/device/socket)")
        }
        OpenRegularError::TooLarge => {
            format!("{what} {path}: file is larger than the {cap}-byte cap")
        }
        OpenRegularError::Io(io) => format!("{what} {path}: {io}"),
    }
}

/// Derive exact Web3 bindings through the same parser/policy compiler used by
/// enforcement. This is intentionally local-only and uses the fully resolved
/// policy for the current working directory.
fn derive_exact_web3_bindings(
    command: &str,
    approval_key_id: &str,
    shell: ShellType,
) -> Result<Option<tirith_core::command_card::Web3CardBindings>, String> {
    let cwd = std::env::current_dir()
        .ok()
        .map(|path| path.display().to_string());
    let policy = tirith_core::policy::Policy::discover(cwd.as_deref());
    if policy.web3_guard.command_card_key_ids.is_empty() {
        return Ok(None);
    }
    let policy_identity = policy.enforcement_projection_hash();
    let bindings = tirith_core::rules::web3_gate::command_card_bindings_for_command(
        command,
        shell,
        cwd.as_deref(),
        &policy.web3_guard,
        &policy_identity,
        Some(approval_key_id),
    )
    .map_err(|error| format!("derive exact Web3 bindings: {error}"))?;
    if bindings.is_some()
        && !policy
            .web3_guard
            .command_card_key_ids
            .contains(approval_key_id)
    {
        return Err(format!(
            "signing key {approval_key_id} is not listed in web3_guard.command_card_key_ids"
        ));
    }
    Ok(bindings)
}

fn configured_web3_approval_keys() -> Vec<String> {
    let cwd = std::env::current_dir()
        .ok()
        .map(|path| path.display().to_string());
    let policy = tirith_core::policy::Policy::discover(cwd.as_deref());
    policy
        .web3_guard
        .command_card_key_ids
        .iter()
        .cloned()
        .collect()
}

fn shell_binding_token(shell: ShellType) -> &'static str {
    match shell {
        ShellType::Posix => "posix",
        ShellType::Fish => "fish",
        ShellType::PowerShell => "powershell",
        ShellType::Cmd => "cmd",
    }
}

fn safe_card_command_binding(card: &Card) -> (Option<String>, Option<&str>) {
    let digest = card.command_sha256.as_deref().and_then(|digest| {
        (digest.len() == 64 && digest.bytes().all(|byte| byte.is_ascii_hexdigit()))
            .then(|| digest.to_ascii_lowercase())
    });
    let shell = card
        .command_shell
        .as_deref()
        .filter(|shell| matches!(*shell, "posix" | "fish" | "powershell" | "cmd"));
    (digest, shell)
}

fn prepare_card_for_signing_with<F>(
    mut card: Card,
    reviewed_command: &str,
    approval_key_id: &str,
    shell: ShellType,
    derive_bindings: F,
) -> Result<Card, String>
where
    F: FnOnce(
        &str,
        &str,
        ShellType,
    ) -> Result<Option<tirith_core::command_card::Web3CardBindings>, String>,
{
    // A freshly-created privacy-safe card deliberately has no raw command. When
    // more than one approval key is configured, `create` cannot know which key
    // the operator will select, so `sign` must derive the exact binding now.
    // Legacy v1 cards retain the same migration behavior. Existing reviewed
    // bindings are never replaced.
    if card.web3.is_none() && matches!(card.schema_version, 1 | CARD_SCHEMA_V3) {
        if let Some(bindings) = derive_bindings(reviewed_command, approval_key_id, shell)? {
            card = card
                .with_web3_bindings(bindings)
                .map_err(|error| format!("build exact Web3 template: {error}"))?;
        }
    }
    Ok(card)
}

fn command_card_verification_json(
    card: &Card,
    verified: bool,
    reason: Option<&str>,
) -> serde_json::Value {
    let (safe_command_sha256, safe_command_shell) = safe_card_command_binding(card);
    let web3_bindings_present = card.is_privacy_safe() && card.web3.is_some();
    // Compatibility field retained, but it must never claim capability for a
    // card that failed trust, signature, expiry, or schema verification.
    let web3_authorization_capable = verified && web3_bindings_present;
    serde_json::json!({
        "verified": verified,
        "schema_version": card.schema_version,
        "command_sha256": safe_command_sha256,
        "command_shell": safe_command_shell,
        "legacy_command_redacted": !card.command.is_empty(),
        "web3_bindings_present": web3_bindings_present,
        "web3_authorization_capable": web3_authorization_capable,
        "expires": card.expires.as_str(),
        "key_id": card.signature.as_ref().map(|signature: &CardSignature| signature.key_id.as_str()),
        "reason": reason,
    })
}

/// A legacy unsigned schema-v2 card can be migrated using the parser dialect
/// selected by the signing invocation. Existing bindings are never rewritten:
/// a different `--shell` requires regenerating and reviewing the card rather
/// than silently changing its meaning.
fn migrate_missing_web3_shell_binding(card: &mut Card, shell: ShellType) {
    if card.schema_version == CARD_SCHEMA_V2 {
        if let Some(bindings) = card.web3.as_mut() {
            if bindings.shell.is_none() {
                bindings.shell = Some(shell_binding_token(shell).to_string());
            }
        }
    }
}

/// `tirith command-card create` — build an unsigned card and print it as JSON.
///
/// Flag-driven when `--command` is supplied; otherwise prompts on the TTY.
#[allow(clippy::too_many_arguments)]
pub fn create(
    command: Option<String>,
    shell: ShellType,
    expected_domains: Vec<String>,
    script_sha256: Option<String>,
    writes: Vec<String>,
    requires_sudo: bool,
    expires: Option<String>,
    json: bool,
) -> i32 {
    // Resolve the command from `--command` or the TTY prompt, requiring it to be
    // non-empty AFTER trimming (a whitespace-only value would never match a real
    // command). Only prompt when stdin IS a terminal — a non-interactive run with
    // no `--command` emits the required-`--command` error below WITHOUT touching
    // stdin, so piped data is never consumed and attested as the wrong command.
    let command = match command {
        Some(c) => c,
        None if is_terminal::is_terminal(std::io::stdin()) => {
            prompt("command the card attests to").unwrap_or_default()
        }
        None => String::new(),
    };
    if command.trim().is_empty() {
        // Validation failure is exit 2; a broken-pipe JSON write is also 2.
        let _ = emit_error(
            json,
            "tirith command-card create",
            "a non-empty --command is required",
        );
        return 2;
    }
    let cwd = std::env::current_dir()
        .ok()
        .map(|path| path.display().to_string());
    if let Err(error) = tirith_core::rules::web3_gate::refuse_command_card_secret_material(
        &command,
        shell,
        cwd.as_deref(),
    ) {
        let _ = emit_error(json, "tirith command-card create", &error.to_string());
        return 1;
    }

    // Default expiry: 90 days out (usable but not forever).
    let expires = expires.unwrap_or_else(|| {
        let in_90 = chrono::Utc::now().date_naive() + chrono::Duration::days(90);
        in_90.format("%Y-%m-%d").to_string()
    });

    // Validate the expiry now (fail fast). Store the TRIMMED value: a padded
    // `--expires "2026-12-01 "` passes this `.trim()` check but the STRICT
    // verify-time parse (which does not trim) would reject it — a card that
    // creates but never verifies.
    let expires = expires.trim().to_string();
    if chrono::NaiveDate::parse_from_str(&expires, "%Y-%m-%d").is_err() {
        // JSON-aware error (exit 2; broken-pipe write is also 2).
        let _ = emit_error(
            json,
            "tirith command-card create",
            &format!("--expires must be YYYY-MM-DD (got '{expires}')"),
        );
        return 2;
    }

    let mut card = match Card::new_privacy_preserving(
        &command,
        shell_binding_token(shell),
        expected_domains,
        script_sha256,
        writes,
        requires_sudo,
        expires,
    ) {
        Ok(card) => card,
        Err(error) => {
            let _ = emit_error(json, "tirith command-card create", &error.to_string());
            return 1;
        }
    };

    // When policy names one approval key, `create` can emit the complete
    // unsigned exact Web3 template immediately. With several configured keys the
    // subsequent `sign --key ...` step derives the same template using the key
    // actually selected by the operator.
    let configured_web3_keys = configured_web3_approval_keys();
    if let Some(key_id) = configured_web3_keys.first() {
        match derive_exact_web3_bindings(&command, key_id, shell) {
            Ok(Some(bindings)) if configured_web3_keys.len() == 1 => {
                match card.with_web3_bindings(bindings) {
                    Ok(promoted) => card = promoted,
                    Err(error) => {
                        let _ = emit_error(
                            json,
                            "tirith command-card create",
                            &format!("build exact Web3 template: {error}"),
                        );
                        return 1;
                    }
                }
            }
            // With several configured keys, this call is a fail-closed
            // authoring preflight only: `sign --key` derives the template with
            // the key the operator actually selected.
            Ok(Some(_)) => {}
            Ok(None) => {}
            Err(error) => {
                let _ = emit_error(json, "tirith command-card create", &error);
                return 1;
            }
        }
    }

    match card.to_json_pretty() {
        Ok(s) => {
            // Pretty JSON to stdout so `create > card.json` works directly
            // (`json` accepted for parity — the card is already JSON). Fallible
            // write, not `println!`, so a stdout write error returns exit 2.
            let _ = json;
            let mut out = std::io::stdout();
            if writeln!(out, "{s}").and_then(|()| out.flush()).is_err() {
                return 2;
            }
            0
        }
        Err(e) => {
            // JSON-aware: a broken-pipe write returns 2, otherwise the semantic 1.
            if !emit_error(json, "tirith command-card create", &e.to_string()) {
                return 2;
            }
            1
        }
    }
}

/// `tirith command-card sign --key <ed25519-priv.bin> <card.json>` — sign a
/// card in place (rewrites the file with the `signature` block populated).
pub fn sign(
    key_path: &str,
    card_path: &str,
    reviewed_command: Option<&str>,
    shell: ShellType,
    json: bool,
) -> i32 {
    // Every fatal branch below: a broken-pipe JSON write → 2, otherwise 1.
    let secret = match read_secret_key(Path::new(key_path)) {
        Ok(k) => k,
        Err(e) => {
            if !emit_error(json, "tirith command-card sign", &e.to_string()) {
                return 2;
            }
            return 1;
        }
    };

    // Hardened, capped read (same guard as the engine hot path's `--card`).
    let bytes = match read_regular_capped(Path::new(card_path), CARD_READ_CAP) {
        Ok(b) => b,
        Err(e) => {
            if !emit_error(
                json,
                "tirith command-card sign",
                &describe_open_error("read", card_path, CARD_READ_CAP, &e),
            ) {
                return 2;
            }
            return 1;
        }
    };
    let mut card = match Card::from_json(&bytes) {
        Ok(c) => c,
        Err(e) => {
            if !emit_error(
                json,
                "tirith command-card sign",
                &format!("parse {card_path}: {e}"),
            ) {
                return 2;
            }
            return 1;
        }
    };

    let reviewed_command = if card.schema_version == CARD_SCHEMA_V3 {
        let Some(command) = reviewed_command else {
            if !emit_error(
                json,
                "tirith command-card sign",
                "--command is required to verify a privacy-safe card digest before signing",
            ) {
                return 2;
            }
            return 1;
        };
        if !card.command_matches_for_shell(command, shell_binding_token(shell)) {
            if !emit_error(
                json,
                "tirith command-card sign",
                "the reviewed command does not match the card digest",
            ) {
                return 2;
            }
            return 1;
        }
        command.to_string()
    } else {
        let command = reviewed_command.unwrap_or(&card.command);
        if command.is_empty()
            || !card.command_matches_for_shell(command, shell_binding_token(shell))
        {
            if !emit_error(
                json,
                "tirith command-card sign",
                "the reviewed command does not match the legacy card",
            ) {
                return 2;
            }
            return 1;
        }
        command.to_string()
    };
    let cwd = std::env::current_dir()
        .ok()
        .map(|path| path.display().to_string());
    if let Err(error) = tirith_core::rules::web3_gate::refuse_command_card_secret_material(
        &reviewed_command,
        shell,
        cwd.as_deref(),
    ) {
        if !emit_error(json, "tirith command-card sign", &error.to_string()) {
            return 2;
        }
        return 1;
    }

    let key_id = key_id_for_secret_key(&secret);
    match prepare_card_for_signing_with(
        card,
        &reviewed_command,
        &key_id,
        shell,
        derive_exact_web3_bindings,
    ) {
        Ok(prepared) => card = prepared,
        Err(error) => {
            if !emit_error(json, "tirith command-card sign", &error) {
                return 2;
            }
            return 1;
        }
    }

    migrate_missing_web3_shell_binding(&mut card, shell);

    if card.schema_version != CARD_SCHEMA_V3 {
        let selected_shell = shell_binding_token(shell);
        if card
            .web3
            .as_ref()
            .and_then(|bindings| bindings.shell.as_deref())
            .is_some_and(|bound| bound != selected_shell)
        {
            if !emit_error(
                json,
                "tirith command-card sign",
                "the selected shell differs from the reviewed legacy Web3 binding",
            ) {
                return 2;
            }
            return 1;
        }
        if let Err(error) = card.migrate_command_privacy(selected_shell) {
            if !emit_error(json, "tirith command-card sign", &error.to_string()) {
                return 2;
            }
            return 1;
        }
    }

    if let Err(e) = card.sign(&secret) {
        if !emit_error(json, "tirith command-card sign", &e.to_string()) {
            return 2;
        }
        return 1;
    }

    let out = match card.to_json_pretty() {
        Ok(s) => s,
        Err(e) => {
            if !emit_error(json, "tirith command-card sign", &e.to_string()) {
                return 2;
            }
            return 1;
        }
    };
    // Write atomically (temp-in-same-dir then rename) so a crash mid-write can't
    // truncate the card; a reader sees either the old or the fully-signed one.
    if let Err(e) = write_card_atomic(Path::new(card_path), &format!("{out}\n")) {
        if !emit_error(
            json,
            "tirith command-card sign",
            &format!("write {card_path}: {e}"),
        ) {
            return 2;
        }
        return 1;
    }

    let sig = card.signature.as_ref().expect("just signed");
    if json {
        let v = serde_json::json!({
            "signed": true,
            "card_path": card_path,
            "key_id": sig.key_id,
            "algo": sig.algo,
        });
        // A failed JSON write must exit non-zero: the card WAS signed, but a
        // consumer that saw truncated JSON must not also see success.
        if !super::write_json_stdout(&v, "tirith command-card sign: failed to write JSON output") {
            return 2;
        }
    } else {
        let card_path = human_display_field(card_path);
        let key_id = human_display_field(&sig.key_id);
        let algo = human_display_field(&sig.algo.to_string());
        println!("Signed {card_path} (key_id {}, algo {}).", key_id, algo);
    }
    0
}

/// `tirith command-card verify <card.json>` — verify a card against the
/// operator's trusted-keys directory.
///
/// Exit codes:
///   0  verified (trusted key, good signature, not expired)
///   1  NOT verified (untrusted key / bad signature / expired / unsigned)
pub fn verify(card_path: &str, json: bool) -> i32 {
    // Every fatal branch below: a broken-pipe JSON write → 2, otherwise 1.
    // Hardened, capped read (mirrors `sign` and the engine hot-path guard).
    let bytes = match read_regular_capped(Path::new(card_path), CARD_READ_CAP) {
        Ok(b) => b,
        Err(e) => {
            if !emit_error(
                json,
                "tirith command-card verify",
                &describe_open_error("read", card_path, CARD_READ_CAP, &e),
            ) {
                return 2;
            }
            return 1;
        }
    };
    let card = match Card::from_json(&bytes) {
        Ok(c) => c,
        Err(e) => {
            if !emit_error(
                json,
                "tirith command-card verify",
                &format!("parse {card_path}: {e}"),
            ) {
                return 2;
            }
            return 1;
        }
    };

    let trusted_dir = match command_card::trusted_card_keys_dir() {
        Some(d) => d,
        None => {
            if !emit_error(
                json,
                "tirith command-card verify",
                "could not resolve trusted-keys directory",
            ) {
                return 2;
            }
            return 1;
        }
    };
    let today = chrono::Utc::now().date_naive();
    let result = card.verify_against_trusted(&trusted_dir, today);

    let verified = result.is_ok();
    let reason = result.as_ref().err().map(VerifyFailure::reason);
    let web3_bindings_present = card.is_privacy_safe() && card.web3.is_some();

    if json {
        let v = command_card_verification_json(&card, verified, reason.as_deref());
        // A failed JSON write must exit non-zero even for a verified card; exit 2
        // is distinct from the "not verified" exit 1.
        if !super::write_json_stdout(
            &v,
            "tirith command-card verify: failed to write JSON output",
        ) {
            return 2;
        }
    } else {
        let (safe_command_sha256, _) = safe_card_command_binding(&card);
        // Cards are untrusted even when verification succeeds: the signer may
        // intentionally attest to a command containing terminal-control or
        // deceptive Unicode. Never render card fields before sanitizing them.
        let display_command = safe_command_sha256
            .as_deref()
            .map(|digest| format!("sha256:{digest}"))
            .unwrap_or_else(|| "<legacy command redacted>".to_string());
        let display_expiry = human_display_field(&card.expires);
        if verified {
            println!("VERIFIED: card is signed by a trusted key and has not expired.");
            println!("  command: {display_command}");
            println!("  expires: {display_expiry}");
            println!(
                "  mode: {}",
                if web3_bindings_present {
                    "privacy-safe exact Web3 binding"
                } else {
                    "diagnostic-only"
                }
            );
        } else {
            let display_reason = human_display_field(reason.as_deref().unwrap_or("unknown reason"));
            let display_trusted_dir = human_display_field(&trusted_dir.display().to_string());
            println!("NOT VERIFIED: {display_reason}");
            println!("  command: {display_command}");
            println!(
                "  trusted-keys dir: {display_trusted_dir} (drop the signer's <key_id>.pub here to trust it)"
            );
        }
    }

    if verified {
        0
    } else {
        1
    }
}

/// `tirith command-card fetch <url>` — download a card and cache it under
/// `~/.cache/tirith/cards/<sha256>.json`. THE ONLY remote-I/O path; `check`
/// never fetches.
///
/// PRIVACY: an explicit fetch reveals the user's IP + timestamp to the
/// maintainer's domain (documented in `--help`). UNIX-ONLY (v1): reuses the
/// hardened typed remote-download transaction; on Windows the no-network
/// subcommands remain and the user copies the card in manually.
#[cfg(unix)]
pub fn fetch(url: &str, json: bool) -> i32 {
    // Every fatal branch below: a broken-pipe JSON write → 2, otherwise 1.
    let cache_dir = match command_card::cards_cache_dir() {
        Some(d) => d,
        None => {
            if !emit_error(
                json,
                "tirith command-card fetch",
                "could not resolve cache directory",
            ) {
                return 2;
            }
            return 1;
        }
    };
    // Pure URL/cache binding and policy evaluation happen before the cache root
    // or any temp file exists. Domain DNS remains inside the runner, after the
    // pending authorization is consumed.
    let (binding, pending) = match prepare_command_card_fetch(url, &cache_dir) {
        Ok(prepared) => prepared,
        Err(error) => {
            if !emit_error(json, "tirith command-card fetch", &error) {
                return 2;
            }
            return 1;
        }
    };
    let operation = binding.operation();
    let dl = match tirith_core::runner::download_and_cache_command_card_authorized(
        url,
        &cache_dir,
        CARD_READ_CAP,
        pending,
        &operation,
    ) {
        Ok(downloaded) => downloaded,
        Err(error) => {
            if !emit_error(json, "tirith command-card fetch", &error) {
                return 2;
            }
            return 1;
        }
    };
    let dest = dl.path;
    let sha = dl.sha256;

    if json {
        let v = serde_json::json!({
            "cached_path": dest.display().to_string(),
            "sha256": sha,
            "final_url": dl.final_url,
        });
        // The card was cached, but a failed JSON write must still exit non-zero.
        if !super::write_json_stdout(&v, "tirith command-card fetch: failed to write JSON output") {
            return 2;
        }
    } else {
        let display_dest = human_display_field(&dest.display().to_string());
        let display_url = human_display_field(&dl.final_url);
        println!("{display_dest}");
        eprintln!(
            "Cached card from {} (sha256 {}).",
            display_url,
            tirith_core::receipt::short_hash(&sha)
        );
        eprintln!("Use it: tirith check --card {display_dest} -- \"<command>\"");
    }
    0
}

#[cfg(unix)]
fn prepare_command_card_fetch(
    url: &str,
    cache_dir: &Path,
) -> Result<
    (
        tirith_core::runner::RemoteRunBoundaryBinding,
        tirith_core::task_boundary::PendingBoundaryAuthorization<
            tirith_core::task_boundary::RemoteScriptRunBoundary,
        >,
    ),
    String,
> {
    let binding = tirith_core::runner::remote_command_card_cache_boundary_binding(
        url,
        cache_dir,
        CARD_READ_CAP,
    )?;
    let operation = binding.operation();
    let cwd = std::env::current_dir()
        .ok()
        .map(|path| path.to_string_lossy().into_owned());
    let policy = tirith_core::policy::Policy::discover(cwd.as_deref());
    let pending = tirith_core::task_boundary::prepare_locally_derived_boundary_authorization::<
        tirith_core::task_boundary::RemoteScriptRunBoundary,
    >(
        &operation,
        &policy.task_gate,
        &tirith_core::task_analysis::TaskAnalysisContext::default(),
    );
    let assessment = match &pending {
        Ok(pending) => Some(pending.assessment()),
        Err(error) => error.assessment(),
    };
    if let Some(assessment) = assessment {
        if let Err(error) = tirith_core::audit::log_task_boundary_assessment(assessment) {
            tirith_core::audit::audit_diagnostic(format!(
                "task-boundary audit append failed: {error}"
            ));
        }
    }
    let pending = pending.map_err(|error| error.to_string())?;
    Ok((binding, pending))
}

/// Read a 32-byte ed25519 secret key (raw 32 bytes, hex, or base64).
fn read_secret_key(path: &Path) -> Result<[u8; SECRET_KEY_LEN], CardError> {
    // Hardened, capped read of the operator-supplied `--key` path. Map open
    // errors onto `CardError`: missing/I/O → `Io`; non-regular/oversized →
    // `BadKey` (not a usable key file regardless of why the read refused).
    let raw = match read_regular_capped(path, SECRET_KEY_READ_CAP) {
        Ok(b) => b,
        Err(OpenRegularError::Io(_)) => {
            return Err(CardError::Io(std::io::Error::other(
                "command-card signing key could not be read",
            )))
        }
        Err(OpenRegularError::NotFound) => {
            return Err(CardError::Io(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                "command-card signing key file was not found",
            )))
        }
        Err(OpenRegularError::NotRegularFile) => {
            return Err(CardError::BadKey(
                "command-card signing key is not a regular file".to_string(),
            ))
        }
        Err(OpenRegularError::TooLarge) => {
            return Err(CardError::BadKey(
                "command-card signing key exceeds the bounded key-file size limit".to_string(),
            ))
        }
    };
    if raw.len() == SECRET_KEY_LEN {
        let mut k = [0u8; SECRET_KEY_LEN];
        k.copy_from_slice(&raw);
        return Ok(k);
    }
    // Try hex / base64, trimming whitespace.
    if let Ok(text) = std::str::from_utf8(&raw) {
        let text = text.trim();
        if let Some(decoded) = command_card::hex_decode(text) {
            if decoded.len() == SECRET_KEY_LEN {
                let mut k = [0u8; SECRET_KEY_LEN];
                k.copy_from_slice(&decoded);
                return Ok(k);
            }
        }
        use base64::Engine;
        if let Ok(decoded) = base64::engine::general_purpose::STANDARD.decode(text) {
            if decoded.len() == SECRET_KEY_LEN {
                let mut k = [0u8; SECRET_KEY_LEN];
                k.copy_from_slice(&decoded);
                return Ok(k);
            }
        }
    }
    Err(CardError::BadKey(
        "command-card signing key has an unsupported encoding or length".to_string(),
    ))
}

/// Write `contents` to `path` atomically (temp-in-same-dir, flushed, renamed)
/// so a reader/crash never sees a truncated card.
fn write_card_atomic(path: &Path, contents: &str) -> std::io::Result<()> {
    // Resolve a symlinked destination so signing updates the link's TARGET, not
    // clobbering the link with a regular file. Reuses `resolve_atomic_dest` so
    // both atomic writers canonicalize identically.
    let dest = super::resolve_atomic_dest(path);
    let dir = dest.parent().filter(|p| !p.as_os_str().is_empty());
    let mut tmp = match dir {
        Some(d) => tempfile::NamedTempFile::new_in(d)?,
        // Bare filename: temp in cwd so the rename stays on one filesystem.
        None => tempfile::NamedTempFile::new_in(".")?,
    };
    tmp.write_all(contents.as_bytes())?;
    tmp.flush()?;
    // `sync_all()` before the rename so a crash can't leave a partial card.
    tmp.as_file().sync_all()?;
    tmp.persist(&dest).map_err(|e| e.error)?;
    // Rename durability: fsync the parent dir (data is synced above, the dir
    // entry is not). LOGGED, not fatal — the persist already succeeded.
    tirith_core::util::fsync_parent_dir_logged(&dest, "signed card");
    Ok(())
}

/// Prompt on stderr and read one line from stdin. `None` if stdin is unreadable.
fn prompt(label: &str) -> Option<String> {
    eprint!("{label}: ");
    let _ = std::io::stderr().flush();
    let mut line = String::new();
    match std::io::stdin().read_line(&mut line) {
        Ok(0) | Err(_) => None,
        Ok(_) => Some(line.trim_end_matches(['\n', '\r']).to_string()),
    }
}

/// Emit an error to stderr (human) or as a JSON `{"error": ...}` object. Returns
/// `false` when the JSON write itself failed, so a `--json` caller surfaces a
/// distinct write-failure exit (2). Human mode always returns `true`.
fn emit_error(json: bool, ctx: &str, msg: &str) -> bool {
    if json {
        let v = serde_json::json!({ "error": msg });
        super::write_json_stdout(&v, &format!("{ctx}: failed to write JSON output"))
    } else {
        eprintln!("{}: {}", human_display_field(ctx), human_display_field(msg));
        true
    }
}

#[cfg(test)]
mod tests {
    use super::{
        command_card_verification_json, emit_error, human_display_field,
        migrate_missing_web3_shell_binding, prepare_card_for_signing_with, read_secret_key,
        write_card_atomic, CARD_READ_CAP, SECRET_KEY_READ_CAP,
    };

    fn exact_web3_bindings(approval_key_id: &str) -> tirith_core::command_card::Web3CardBindings {
        tirith_core::command_card::Web3CardBindings {
            shell: Some("posix".into()),
            network_policy_id: "production".into(),
            family: "evm".into(),
            chain_or_genesis: "1".into(),
            signer_kind: "hardware_wallet".into(),
            signers: vec![tirith_core::command_card::Web3CardSignerBinding {
                role: "default".into(),
                kind: "hardware_wallet".into(),
                reference_sha256: None,
            }],
            destinations: vec!["0xdead".into()],
            artifact_sha256: vec![],
            policy_identity: "policy-projection-v1".into(),
            operations: vec!["send".into()],
            approval_key_id: approval_key_id.into(),
        }
    }

    #[test]
    fn schema_v3_multikey_sign_preparation_derives_binding_for_selected_key() {
        let command = "cast send 0xdead --rpc-url https://rpc.test --ledger";
        let secret = [17u8; tirith_core::command_card::SECRET_KEY_LEN];
        let selected_key_id = tirith_core::command_card::key_id_for_secret_key(&secret);
        let card = tirith_core::command_card::Card::new_privacy_preserving(
            command,
            "posix",
            vec![],
            None,
            vec![],
            false,
            "2099-01-01".into(),
        )
        .unwrap();
        assert!(
            card.web3.is_none(),
            "multi-key create leaves selection to sign"
        );

        let mut derive_called = false;
        let mut prepared = prepare_card_for_signing_with(
            card,
            command,
            &selected_key_id,
            tirith_core::tokenize::ShellType::Posix,
            |observed_command, observed_key_id, observed_shell| {
                derive_called = true;
                assert_eq!(observed_command, command);
                assert_eq!(observed_key_id, selected_key_id);
                assert_eq!(observed_shell, tirith_core::tokenize::ShellType::Posix);
                Ok(Some(exact_web3_bindings(observed_key_id)))
            },
        )
        .unwrap();

        assert!(
            derive_called,
            "an unbound schema-v3 card must be derived at sign time"
        );
        assert_eq!(
            prepared
                .web3
                .as_ref()
                .map(|bindings| bindings.approval_key_id.as_str()),
            Some(selected_key_id.as_str())
        );
        assert!(
            prepared.command.is_empty(),
            "sign preparation must not restore raw command"
        );
        assert!(prepared.command_matches_for_shell(command, "posix"));
        prepared.sign(&secret).unwrap();
        assert_eq!(
            prepared
                .signature
                .as_ref()
                .map(|signature| signature.key_id.as_str()),
            Some(selected_key_id.as_str()),
            "the exact binding and signature must use the same selected key"
        );
    }

    #[test]
    fn verify_json_separates_binding_presence_from_verified_authorization() {
        let command = "cast send 0xdead --rpc-url https://rpc.test --ledger";
        let secret = [29u8; tirith_core::command_card::SECRET_KEY_LEN];
        let key_id = tirith_core::command_card::key_id_for_secret_key(&secret);
        let mut card = tirith_core::command_card::Card::new_privacy_preserving(
            command,
            "posix",
            vec![],
            None,
            vec![],
            false,
            "2099-01-01".into(),
        )
        .unwrap()
        .with_web3_bindings(exact_web3_bindings(&key_id))
        .unwrap();
        card.sign(&secret).unwrap();

        let untrusted = command_card_verification_json(
            &card,
            false,
            Some("card signature is from an untrusted key"),
        );
        assert_eq!(untrusted["verified"].as_bool(), Some(false));
        assert_eq!(untrusted["web3_bindings_present"].as_bool(), Some(true));
        assert_eq!(
            untrusted["web3_authorization_capable"].as_bool(),
            Some(false)
        );
        assert_eq!(untrusted["command_shell"], "posix");
        assert!(!untrusted.to_string().contains(command));

        let verified = command_card_verification_json(&card, true, None);
        assert_eq!(verified["verified"].as_bool(), Some(true));
        assert_eq!(verified["web3_bindings_present"].as_bool(), Some(true));
        assert_eq!(verified["web3_authorization_capable"].as_bool(), Some(true));
    }

    #[test]
    fn card_human_fields_strip_terminal_and_line_injection() {
        let hostile = "echo safe\x1b]52;c;YXR0YWNr\x07\x1b[2J\u{202e}\nFORGED";
        let rendered = human_display_field(hostile);
        assert_eq!(rendered, "echo safeFORGED");
        assert!(!rendered.contains('\x1b'));
        assert!(!rendered.contains('\x07'));
        assert!(!rendered.contains('\u{202e}'));
        assert!(!rendered.contains('\n'));
    }

    /// `emit_error` must propagate the JSON-write status so a `--json` caller can
    /// return a distinct write-failure exit (2). Human mode is best-effort and
    /// always reports success. (The JSON write-FAILURE path is tested at the
    /// `cli::write_json_to` seam, since real stdout can't be made to fail here.)
    #[test]
    fn emit_error_human_mode_reports_success() {
        assert!(
            emit_error(false, "tirith command-card sign", "boom"),
            "human-mode emit_error is best-effort and must report success"
        );
    }

    /// JSON mode with a working stdout reports success (end-to-end shape is
    /// covered by `command_card_sign_json_fatal_error_is_parseable_nonzero`).
    #[test]
    fn emit_error_json_mode_reports_success_when_stdout_ok() {
        assert!(
            emit_error(true, "tirith command-card sign", "boom"),
            "json-mode emit_error to a healthy stdout must report success"
        );
    }

    #[test]
    fn signing_key_read_errors_are_categorical_and_path_free() {
        let root = tempfile::tempdir().unwrap();
        let canary = "C04-private-signing-key-path";
        let missing = root.path().join(canary);
        let missing_error = read_secret_key(&missing).unwrap_err().to_string();
        assert_eq!(missing_error, "command-card signing key file was not found");

        let malformed = root.path().join(format!("{canary}-malformed"));
        std::fs::write(&malformed, b"not-a-key").unwrap();
        let malformed_error = read_secret_key(&malformed).unwrap_err().to_string();
        assert_eq!(
            malformed_error,
            "command-card signing key has an unsupported encoding or length"
        );

        let oversized = root.path().join(format!("{canary}-oversized"));
        std::fs::write(&oversized, vec![0u8; SECRET_KEY_READ_CAP as usize + 1]).unwrap();
        let oversized_error = read_secret_key(&oversized).unwrap_err().to_string();
        assert_eq!(
            oversized_error,
            "command-card signing key exceeds the bounded key-file size limit"
        );

        for rendered in [missing_error, malformed_error, oversized_error] {
            assert!(!rendered.contains(canary));
            assert!(!rendered.contains(root.path().to_string_lossy().as_ref()));
        }

        #[cfg(unix)]
        {
            let directory_error = read_secret_key(root.path()).unwrap_err().to_string();
            assert_eq!(
                directory_error,
                "command-card signing key is not a regular file"
            );
            assert!(!directory_error.contains(root.path().to_string_lossy().as_ref()));
        }
    }

    #[cfg(unix)]
    #[test]
    fn denied_command_card_fetch_creates_no_cache_or_temp_file() {
        let root = tempfile::tempdir().unwrap();
        let cache = root.path().join("cards");
        let binding = tirith_core::runner::remote_command_card_cache_boundary_binding(
            "https://1.1.1.1/card.json",
            &cache,
            CARD_READ_CAP,
        )
        .unwrap();
        let operation = binding.operation();
        assert!(operation
            .boundary_effects
            .contains(&tirith_core::effects::CommandEffectKind::NetworkEgress));
        assert!(operation
            .boundary_effects
            .contains(&tirith_core::effects::CommandEffectKind::FilesystemWrite));
        assert!(operation
            .boundary_effects
            .contains(&tirith_core::effects::CommandEffectKind::PersistenceChange));
        let gate = tirith_core::web3_policy::TaskGatePolicy {
            mode: tirith_core::web3_policy::TaskGateMode::Enforce,
            effects_denied_for_untrusted_sources: [
                tirith_core::effects::CommandEffectKind::NetworkEgress,
            ]
            .into_iter()
            .collect(),
            ..Default::default()
        };

        let result = tirith_core::task_boundary::prepare_locally_derived_boundary_authorization::<
            tirith_core::task_boundary::RemoteScriptRunBoundary,
        >(
            &operation,
            &gate,
            &tirith_core::task_analysis::TaskAnalysisContext::default(),
        );
        assert!(result.is_err());
        assert!(!cache.exists());
        assert_eq!(std::fs::read_dir(root.path()).unwrap().count(), 0);
    }

    #[test]
    fn write_card_atomic_writes_and_replaces_without_leaving_temp() {
        // F3: the write lands exactly, an overwrite fully replaces, and no temp
        // file is left behind. (The pre-rename `sync_all()` is exercised here —
        // a sync error would fail the `.unwrap()` — but is not directly
        // observable in a unit test.)
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("card.json");

        write_card_atomic(&path, "{\"first\":true}\n").unwrap();
        assert_eq!(
            std::fs::read_to_string(&path).unwrap(),
            "{\"first\":true}\n"
        );

        // Overwrite in place: the new content fully replaces the old.
        write_card_atomic(&path, "{\"second\":true}\n").unwrap();
        assert_eq!(
            std::fs::read_to_string(&path).unwrap(),
            "{\"second\":true}\n"
        );

        // The only file in the directory is the card itself — the temp file was
        // renamed (consumed), not left dangling.
        let entries: Vec<_> = std::fs::read_dir(dir.path())
            .unwrap()
            .filter_map(|e| e.ok())
            .map(|e| e.path())
            .collect();
        assert_eq!(entries.len(), 1, "no temp file left behind: {entries:?}");
        assert_eq!(entries[0], path);
    }

    #[test]
    fn signing_migrates_only_a_missing_v2_shell_binding() {
        let mut card = tirith_core::command_card::Card::new(
            "cast send 0xdead".into(),
            vec![],
            None,
            vec![],
            false,
            "2099-01-01".into(),
        );
        card.schema_version = tirith_core::command_card::CARD_SCHEMA_V2;
        card.web3 = Some(tirith_core::command_card::Web3CardBindings {
            shell: None,
            network_policy_id: "prod".into(),
            family: "evm".into(),
            chain_or_genesis: "1".into(),
            signer_kind: "hardware_wallet".into(),
            signers: vec![tirith_core::command_card::Web3CardSignerBinding {
                role: "default".into(),
                kind: "hardware_wallet".into(),
                reference_sha256: None,
            }],
            destinations: vec!["0xdead".into()],
            artifact_sha256: vec![],
            policy_identity: "policy".into(),
            operations: vec!["send".into()],
            approval_key_id: "0123456789abcdef".into(),
        });

        migrate_missing_web3_shell_binding(&mut card, tirith_core::tokenize::ShellType::PowerShell);
        assert_eq!(
            card.web3
                .as_ref()
                .and_then(|bindings| bindings.shell.as_deref()),
            Some("powershell")
        );

        migrate_missing_web3_shell_binding(&mut card, tirith_core::tokenize::ShellType::Cmd);
        assert_eq!(
            card.web3
                .as_ref()
                .and_then(|bindings| bindings.shell.as_deref()),
            Some("powershell"),
            "an existing reviewed shell binding must not be rewritten"
        );
    }

    /// Signing a SYMLINKED card must update the link's TARGET, not clobber the
    /// link with a regular file. Unix-only.
    #[cfg(unix)]
    #[test]
    fn write_card_atomic_through_symlink_updates_target_not_link() {
        use std::os::unix::fs::symlink;

        let dir = tempfile::tempdir().unwrap();
        // Real card in a SEPARATE subdir to prove the temp lands next to the
        // RESOLVED target (same filesystem), not next to the link.
        let target_dir = dir.path().join("real");
        std::fs::create_dir_all(&target_dir).unwrap();
        let target = target_dir.join("card.json");
        std::fs::write(&target, "{\"old\":true}\n").unwrap();

        let link = dir.path().join("card.json");
        symlink(&target, &link).unwrap();

        // Sign/write through the symlink.
        write_card_atomic(&link, "{\"new\":true}\n").unwrap();

        // The TARGET now holds the new content...
        assert_eq!(
            std::fs::read_to_string(&target).unwrap(),
            "{\"new\":true}\n"
        );
        // ...and the symlink is INTACT (still a symlink pointing at the target),
        // not replaced by a regular file.
        let link_meta = std::fs::symlink_metadata(&link).unwrap();
        assert!(
            link_meta.file_type().is_symlink(),
            "the card path must remain a symlink, not be clobbered by a regular file"
        );
        assert_eq!(
            std::fs::read_link(&link).unwrap(),
            target,
            "the symlink must still point at the original target"
        );
        // Reading through the link yields the updated content.
        assert_eq!(std::fs::read_to_string(&link).unwrap(), "{\"new\":true}\n");

        // No temp file left dangling in EITHER directory (it was renamed into the
        // target dir, consuming it).
        for d in [dir.path(), target_dir.as_path()] {
            let extra: Vec<_> = std::fs::read_dir(d)
                .unwrap()
                .filter_map(|e| e.ok())
                .map(|e| e.path())
                .filter(|p| p != &link && p != &target && p != &target_dir)
                .collect();
            assert!(
                extra.is_empty(),
                "no temp file left behind in {d:?}: {extra:?}"
            );
        }
    }
}
