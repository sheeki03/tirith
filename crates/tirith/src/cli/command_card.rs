//! M11 ch1 — `tirith command-card create|sign|verify|fetch`.
//!
//! Maintainer side: `create` builds an unsigned card from flags (or stdin
//! prompts), `sign --key <ed25519-priv.bin> <card.json>` stamps an ed25519
//! signature. User side: `verify <card.json>` checks a card against the
//! trusted-keys directory, `fetch <url>` downloads a maintainer's card and
//! caches it under `~/.cache/tirith/cards/<sha256>.json` (the ONLY remote-I/O
//! path — `tirith check` never fetches).

use std::io::Write;
use std::path::Path;

use tirith_core::command_card::{
    self, Card, CardError, CardSignature, VerifyFailure, SECRET_KEY_LEN,
};

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
    // Resolve the command from `--command` or the TTY prompt, then require it to
    // be non-empty AFTER trimming. CodeRabbit R8 #4: the `Some(c)` branch
    // previously skipped the non-empty check, so `create --command "   "` built a
    // card whose `command` is unusable (and would never match a real command).
    // Both the explicit-flag and prompt paths now reject a blank/whitespace-only
    // value with the same validation error (JSON-aware under `--json`).
    let command = match command {
        Some(c) => c,
        None => prompt("command the card attests to").unwrap_or_default(),
    };
    if command.trim().is_empty() {
        // A broken-pipe JSON write returns 2 anyway (the error never reached the
        // consumer); the validation failure is also exit 2 here, so the code is
        // unchanged either way.
        let _ = emit_error(
            json,
            "tirith command-card create",
            "a non-empty --command is required",
        );
        return 2;
    }

    // Default expiry: 90 days out, so a card created with no --expires is still
    // usable but does not last forever.
    let expires = expires.unwrap_or_else(|| {
        let in_90 = chrono::Utc::now().date_naive() + chrono::Duration::days(90);
        in_90.format("%Y-%m-%d").to_string()
    });

    // Validate the expiry parses now so `create` fails fast rather than
    // producing a card that never verifies. Store the TRIMMED value: a padded
    // `--expires "2026-12-01 "` passes this `.trim()` check but, if stored raw,
    // would later fail the STRICT `NaiveDate::parse_from_str` at verify/parse
    // time (which does not trim) — a card that creates but never verifies.
    let expires = expires.trim().to_string();
    if chrono::NaiveDate::parse_from_str(&expires, "%Y-%m-%d").is_err() {
        // CodeRabbit R9 #J: route through the JSON-aware error emitter so a
        // `--json` caller gets a parseable `{"error": …}` object, not a bare
        // stderr line. The validation failure is exit 2; a broken-pipe JSON
        // write is also 2, so the code is non-zero either way.
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
            // Pretty JSON to stdout so `tirith command-card create > card.json`
            // works directly. `json` is accepted for parity (the card is already
            // JSON). Use a FALLIBLE write — not `println!`, which panics/aborts on
            // a stdout write error — so a write failure returns the
            // JSON-write-failure exit code 2, matching this presenter's contract.
            let _ = json;
            let mut out = std::io::stdout();
            if writeln!(out, "{s}").and_then(|()| out.flush()).is_err() {
                return 2;
            }
            0
        }
        Err(e) => {
            // Same JSON-aware path as the --expires error (CodeRabbit R9 #J):
            // a serialization failure under --json must be a parseable object.
            // A broken-pipe JSON write returns 2 (the error never reached the
            // consumer); otherwise the semantic 1.
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
    // For every fatal-error branch below: a broken-pipe JSON write returns 2
    // (the `{"error": …}` never reached the consumer); otherwise the semantic 1.
    let secret = match read_secret_key(Path::new(key_path)) {
        Ok(k) => k,
        Err(e) => {
            if !emit_error(json, "tirith command-card sign", &e.to_string()) {
                return 2;
            }
            return 1;
        }
    };

    let bytes = match std::fs::read(card_path) {
        Ok(b) => b,
        Err(e) => {
            if !emit_error(
                json,
                "tirith command-card sign",
                &format!("read {card_path}: {e}"),
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
    // Write atomically: a temp file in the SAME directory then rename over the
    // target. A plain `std::fs::write` truncates in place, so a crash mid-write
    // would lose the original (unsigned) card and leave a truncated file. The
    // rename is atomic on the same filesystem, so a reader sees either the old
    // card or the fully-signed one, never a partial.
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
        // A failed JSON write (e.g. broken pipe / truncated output) must exit
        // non-zero: the card WAS signed on disk, but a piped consumer that saw
        // truncated JSON must not also see a success code.
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
    // For every fatal-error branch below: a broken-pipe JSON write returns 2
    // (the `{"error": …}` never reached the consumer); otherwise the semantic 1.
    let bytes = match std::fs::read(card_path) {
        Ok(b) => b,
        Err(e) => {
            if !emit_error(
                json,
                "tirith command-card verify",
                &format!("read {card_path}: {e}"),
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
        // A failed JSON write must exit non-zero, even for a verified card: a
        // consumer that saw truncated JSON must not read a success code. Exit 2
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

/// `tirith command-card fetch <url>` — download a maintainer's card and cache
/// it under `~/.cache/tirith/cards/<sha256>.json`. THIS IS THE ONLY remote-I/O
/// path for cards; `tirith check` never fetches.
///
/// PRIVACY: fetching a card tells the maintainer's domain that a tirith user is
/// pulling their card (an IP + timestamp + the request). This is unavoidable
/// for an explicit fetch — documented in `--help`.
///
/// UNIX-ONLY (v1): this reuses `tirith_core::runner::download_to_path`, the
/// hardened (30s-timeout / 10 MiB-cap) download path, which is `#[cfg(unix)]`
/// today — exactly like `tirith run` / `tirith fetch`. The `Fetch` CLI variant
/// is therefore compiled in only on Unix; on Windows `create`/`sign`/`verify`
/// (no network) remain available and a user copies the card to
/// `~/.cache/tirith/cards/` manually. Removing this cfg gate requires a
/// cross-platform `download_to_path`.
#[cfg(unix)]
pub fn fetch(url: &str, json: bool) -> i32 {
    // For every fatal-error branch below: a broken-pipe JSON write returns 2
    // (the `{"error": …}` never reached the consumer); otherwise the semantic 1.
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

    // Download to a temp file (reusing the hardened 30s-timeout / 10 MiB-cap
    // download path), validate it parses as a card, then move it to
    // <sha256>.json. The content hash names the file, so we cannot know the
    // destination until after the download.
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
    // Validate it is a card before caching — refuse to cache arbitrary content.
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
    // Persist atomically: NamedTempFile::persist renames within the same dir.
    // The cache is content-addressed (`<sha256>.json`), so refetching the same
    // card is IDEMPOTENT. `persist` (overwrite=true) already replaces an
    // existing same-named file on the common platforms, so a refetch normally
    // just succeeds. As belt-and-suspenders for any backend that surfaces an
    // `AlreadyExists` on the rename (or a future switch to a no-clobber
    // persist), explicitly treat "destination already holds these exact bytes"
    // as a cache hit rather than an error.
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
        // Cache hit: identical bytes already at `dest`. Fall through to report
        // the cached path as success.
    }
    // Durability of the RENAME (CodeRabbit R9 #B): fsync the parent dir so the
    // newly cached card's directory entry survives a crash — the verify hot path
    // reads this file back. The persist already succeeded, so a dir-fsync failure
    // is LOGGED, not propagated (R13 #5). Best-effort, unix-only (matches the
    // card-SIGN path's parent fsync in `write_card_atomic`).
    tirith_core::util::fsync_parent_dir_logged(&dest, "cached card");

    if json {
        let v = serde_json::json!({
            "cached_path": dest.display().to_string(),
            "sha256": sha,
            "final_url": dl.final_url,
        });
        // The card was cached on disk, but a failed JSON write must still exit
        // non-zero so a piped consumer never pairs truncated JSON with success.
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

/// Read a 32-byte ed25519 secret key from a file (raw 32 bytes, hex, or
/// base64).
fn read_secret_key(path: &Path) -> Result<[u8; SECRET_KEY_LEN], CardError> {
    let raw = std::fs::read(path).map_err(CardError::Io)?;
    if raw.len() == SECRET_KEY_LEN {
        let mut k = [0u8; SECRET_KEY_LEN];
        k.copy_from_slice(&raw);
        return Ok(k);
    }
    // Try text encodings (hex / base64), trimming whitespace.
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

/// Write `contents` to `path` atomically: a temp file in the same directory is
/// written, flushed, then renamed over `path`. The rename is atomic on the same
/// filesystem, so a concurrent reader (or a crash) never observes a truncated
/// or half-written card — it sees either the previous file or the new one.
fn write_card_atomic(path: &Path, contents: &str) -> std::io::Result<()> {
    let dir = path.parent().filter(|p| !p.as_os_str().is_empty());
    let mut tmp = match dir {
        Some(d) => tempfile::NamedTempFile::new_in(d)?,
        // No parent component (e.g. a bare filename): place the temp file in the
        // current directory so the rename stays on the same filesystem.
        None => tempfile::NamedTempFile::new_in(".")?,
    };
    tmp.write_all(contents.as_bytes())?;
    tmp.flush()?;
    // Durability: `flush()` only drains the userspace buffer into the kernel; a
    // crash/power-loss after the rename could otherwise leave a zero-length or
    // partially-written card at `path`. `sync_all()` forces the file's data (and
    // metadata) to stable storage BEFORE the rename publishes it, so a reader
    // after a crash sees either the old card or the complete new one — never a
    // truncated one.
    tmp.as_file().sync_all()?;
    tmp.persist(path).map_err(|e| e.error)?;
    // Durability of the RENAME itself: `persist()` renames the temp file over
    // `path` but does NOT fsync the containing directory. On Unix a crash right
    // after the rename can lose the new name→inode directory entry (the file's
    // data is synced above, but the directory metadata recording the new name is
    // not). fsync the parent so the rename is durable too. The persist already
    // succeeded, so a dir-fsync failure must not fail the sign — but it is LOGGED,
    // not silently dropped (CodeRabbit R13 #5). No-op on non-Unix.
    tirith_core::util::fsync_parent_dir_logged(path, "signed card");
    Ok(())
}

/// Prompt on stderr and read one line from stdin. Returns `None` if stdin is
/// not readable.
fn prompt(label: &str) -> Option<String> {
    eprint!("{label}: ");
    let _ = std::io::stderr().flush();
    let mut line = String::new();
    match std::io::stdin().read_line(&mut line) {
        Ok(0) | Err(_) => None,
        Ok(_) => Some(line.trim_end_matches(['\n', '\r']).to_string()),
    }
}

/// Emit an error to stderr (human) or as a JSON `{"error": ...}` object.
///
/// Returns `false` when the JSON write itself failed (broken pipe / truncated
/// output) so a `--json` caller can surface that as a distinct write-failure
/// exit (2) instead of pairing a semantic exit code with no JSON delivered
/// (CodeRabbit R12 #A). Human mode always returns `true` — the stderr line is
/// best-effort. Mirrors `cli::canary::emit_error` / `cli::incident::emit_error`.
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

    /// CodeRabbit R12 #A: `emit_error` must PROPAGATE the JSON-write status so a
    /// `--json` caller can return a distinct write-failure exit (2) instead of
    /// pairing a semantic code with no JSON delivered. Human mode is best-effort
    /// (stderr) and always reports success. The JSON-mode write-FAILURE → `false`
    /// path is the `cli::write_json_to` seam, unit-tested there with a
    /// deliberately-failing writer (real stdout cannot be made to fail
    /// deterministically across platforms — and on Unix a real broken pipe is
    /// SIGPIPE-killed before the write returns, per `main::run`'s SIG_DFL reset).
    #[test]
    fn emit_error_human_mode_reports_success() {
        assert!(
            emit_error(false, "tirith command-card sign", "boom"),
            "human-mode emit_error is best-effort and must report success"
        );
    }

    /// JSON mode with a working stdout writes a parseable object and reports
    /// success. (The buffer is the process stdout here; we only assert the
    /// return contract — the parseable-shape + non-zero-exit end-to-end is
    /// covered by `command_card_sign_json_fatal_error_is_parseable_nonzero` in
    /// the CLI integration suite.)
    #[test]
    fn emit_error_json_mode_reports_success_when_stdout_ok() {
        assert!(
            emit_error(true, "tirith command-card sign", "boom"),
            "json-mode emit_error to a healthy stdout must report success"
        );
    }

    #[test]
    fn write_card_atomic_writes_and_replaces_without_leaving_temp() {
        // F3 (Major): signing writes the card atomically (temp-in-same-dir then
        // rename) so a crash mid-write cannot lose the original. Prove the write
        // lands exactly, an overwrite fully replaces the prior content, and no
        // temp file is left behind in the directory.
        //
        // DURABILITY (CodeRabbit R3 #2): `write_card_atomic` now calls
        // `sync_all()` on the temp file BEFORE the rename, so a crash/power-loss
        // after the rename cannot leave a zero/partial card at `path`. fsync is
        // not directly observable in a unit test (it forces kernel buffers to
        // stable storage); the content-integrity assertions below cover the
        // userspace-visible post-condition, and the sync is exercised on every
        // call here (a sync error would surface as an `Err` from
        // `write_card_atomic` and fail the `.unwrap()`).
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
}
