//! M11 ch1 — `tirith command-card create|sign|verify|fetch`.
//!
//! Maintainer: `create` builds an unsigned card; `sign --key <priv> <card.json>`
//! stamps an ed25519 signature. User: `verify <card.json>` checks against the
//! trusted-keys dir; `fetch <url>` downloads + caches under
//! `~/.cache/tirith/cards/<sha256>.json` (the ONLY remote-I/O path).

use std::io::Write;
use std::path::Path;

use tirith_core::command_card::{
    self, Card, CardError, CardSignature, VerifyFailure, SECRET_KEY_LEN,
};
use tirith_core::util::{read_regular_capped, OpenRegularError};

/// Read cap for a card JSON file in `sign`/`verify`. Matches the engine
/// hot-path `CARD_READ_CAP` so the CLI and analysis refuse the same files;
/// routing through [`read_regular_capped`] also blocks FIFO/device opens.
const CARD_READ_CAP: u64 = 64 * 1024;

/// Read cap for the ed25519 secret-key file in `sign`. A 32-byte key (raw/hex/
/// base64) is well under 4 KiB; larger is malformed. Read via
/// [`read_regular_capped`] to bound the read and refuse FIFO/device paths.
const SECRET_KEY_READ_CAP: u64 = 4096;

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

/// `tirith command-card create` — build an unsigned card and print it as JSON.
///
/// Flag-driven when `--command` is supplied; otherwise prompts on the TTY.
#[allow(clippy::too_many_arguments)]
pub fn create(
    command: Option<String>,
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

    let card = Card::new(
        command,
        expected_domains,
        script_sha256,
        writes,
        requires_sudo,
        expires,
    );

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
pub fn sign(key_path: &str, card_path: &str, json: bool) -> i32 {
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
        println!(
            "Signed {card_path} (key_id {}, algo {}).",
            sig.key_id, sig.algo
        );
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

    if json {
        let v = serde_json::json!({
            "verified": verified,
            "command": card.command,
            "expires": card.expires,
            "key_id": card.signature.as_ref().map(|s: &CardSignature| s.key_id.clone()),
            "reason": reason,
        });
        // A failed JSON write must exit non-zero even for a verified card; exit 2
        // is distinct from the "not verified" exit 1.
        if !super::write_json_stdout(
            &v,
            "tirith command-card verify: failed to write JSON output",
        ) {
            return 2;
        }
    } else if verified {
        println!("VERIFIED: card is signed by a trusted key and has not expired.");
        println!("  command: {}", card.command);
        println!("  expires: {}", card.expires);
    } else {
        println!(
            "NOT VERIFIED: {}",
            reason.unwrap_or_else(|| "unknown reason".to_string())
        );
        println!("  command: {}", card.command);
        println!(
            "  trusted-keys dir: {} (drop the signer's <key_id>.pub here to trust it)",
            trusted_dir.display()
        );
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
/// hardened `#[cfg(unix)]` `runner::download_to_path`; on Windows the no-network
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
    if let Err(e) = std::fs::create_dir_all(&cache_dir) {
        if !emit_error(
            json,
            "tirith command-card fetch",
            &format!("create {}: {e}", cache_dir.display()),
        ) {
            return 2;
        }
        return 1;
    }

    // Download to a temp file, validate it parses, then move to <sha256>.json.
    // The content hash names the file, so the dest is unknown until downloaded.
    let tmp = match tempfile::NamedTempFile::new_in(&cache_dir) {
        Ok(t) => t,
        Err(e) => {
            if !emit_error(
                json,
                "tirith command-card fetch",
                &format!("temp file: {e}"),
            ) {
                return 2;
            }
            return 1;
        }
    };
    let dl = match tirith_core::runner::download_to_path(url, tmp.path(), None) {
        Ok(r) => r,
        Err(e) => {
            if !emit_error(json, "tirith command-card fetch", &e) {
                return 2;
            }
            return 1;
        }
    };

    // Reject an oversized download before reading it: every card READ refuses
    // bodies above `CARD_READ_CAP`, so a larger card would cache but never read
    // back (a dead cache entry). Gating here drops the temp, never writing it.
    if dl.size > CARD_READ_CAP {
        if !emit_error(
            json,
            "tirith command-card fetch",
            &format!(
                "downloaded card is {} bytes, exceeding the {CARD_READ_CAP}-byte read cap; \
                 not caching (it could never be read back)",
                dl.size
            ),
        ) {
            return 2;
        }
        return 1;
    }

    let bytes = match std::fs::read(tmp.path()) {
        Ok(b) => b,
        Err(e) => {
            if !emit_error(
                json,
                "tirith command-card fetch",
                &format!("read download: {e}"),
            ) {
                return 2;
            }
            return 1;
        }
    };
    // Validate it is a card before caching — refuse arbitrary content.
    if Card::from_json(&bytes).is_err() {
        if !emit_error(
            json,
            "tirith command-card fetch",
            "downloaded content is not a valid command card (JSON parse failed)",
        ) {
            return 2;
        }
        return 1;
    }

    let sha = command_card::sha256_hex(&bytes);
    let dest = cache_dir.join(format!("{sha}.json"));
    // Persist atomically. The cache is content-addressed, so a refetch is
    // idempotent; as belt-and-suspenders, treat "dest already holds these exact
    // bytes" as a cache hit rather than an error.
    if let Err(e) = tmp.persist(&dest) {
        let already_cached = e.error.kind() == std::io::ErrorKind::AlreadyExists
            && std::fs::read(&dest)
                .map(|existing| existing == bytes)
                .unwrap_or(false);
        if !already_cached {
            if !emit_error(
                json,
                "tirith command-card fetch",
                &format!("persist {}: {}", dest.display(), e.error),
            ) {
                return 2;
            }
            return 1;
        }
        // Cache hit: identical bytes already at `dest`. Report it as success.
    }
    // Rename durability: fsync the parent dir so the cached card's entry survives
    // a crash (the verify hot path reads it back). LOGGED, not propagated.
    tirith_core::util::fsync_parent_dir_logged(&dest, "cached card");

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
        println!("{}", dest.display());
        eprintln!(
            "Cached card from {} (sha256 {}).",
            dl.final_url,
            tirith_core::receipt::short_hash(&sha)
        );
        eprintln!(
            "Use it: tirith check --card {} -- \"<command>\"",
            dest.display()
        );
    }
    0
}

/// Read a 32-byte ed25519 secret key (raw 32 bytes, hex, or base64).
fn read_secret_key(path: &Path) -> Result<[u8; SECRET_KEY_LEN], CardError> {
    // Hardened, capped read of the operator-supplied `--key` path. Map open
    // errors onto `CardError`: missing/I/O → `Io`; non-regular/oversized →
    // `BadKey` (not a usable key file regardless of why the read refused).
    let raw = match read_regular_capped(path, SECRET_KEY_READ_CAP) {
        Ok(b) => b,
        Err(OpenRegularError::Io(e)) => return Err(CardError::Io(e)),
        Err(OpenRegularError::NotFound) => {
            return Err(CardError::Io(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                format!("{}: no such key file", path.display()),
            )))
        }
        Err(OpenRegularError::NotRegularFile) => {
            return Err(CardError::BadKey(format!(
                "key file {} is not a regular file (refusing a FIFO/device/socket)",
                path.display()
            )))
        }
        Err(OpenRegularError::TooLarge) => {
            return Err(CardError::BadKey(format!(
                "key file {} exceeds the {SECRET_KEY_READ_CAP}-byte cap; \
                 expected a 32-byte ed25519 key (raw, hex, or base64)",
                path.display()
            )))
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
    Err(CardError::BadKey(format!(
        "key file must contain a 32-byte ed25519 private key (raw, hex, or base64); got {} bytes",
        raw.len()
    )))
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
        eprintln!("{ctx}: {msg}");
        true
    }
}

#[cfg(test)]
mod tests {
    use super::{emit_error, write_card_atomic};

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
