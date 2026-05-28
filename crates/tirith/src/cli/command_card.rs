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
    let command = match command {
        Some(c) => c,
        None => match prompt("command the card attests to") {
            Some(c) if !c.trim().is_empty() => c,
            _ => {
                eprintln!("tirith command-card create: a non-empty --command is required");
                return 2;
            }
        },
    };

    // Default expiry: 90 days out, so a card created with no --expires is still
    // usable but does not last forever.
    let expires = expires.unwrap_or_else(|| {
        let in_90 = chrono::Utc::now().date_naive() + chrono::Duration::days(90);
        in_90.format("%Y-%m-%d").to_string()
    });

    // Validate the expiry parses now so `create` fails fast rather than
    // producing a card that never verifies.
    if chrono::NaiveDate::parse_from_str(expires.trim(), "%Y-%m-%d").is_err() {
        eprintln!("tirith command-card create: --expires must be YYYY-MM-DD (got '{expires}')");
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
            // works directly. The `json` flag is accepted for parity but the
            // card itself is already JSON.
            let _ = json; // card output is JSON regardless
            println!("{s}");
            0
        }
        Err(e) => {
            eprintln!("tirith command-card create: {e}");
            1
        }
    }
}

/// `tirith command-card sign --key <ed25519-priv.bin> <card.json>` — sign a
/// card in place (rewrites the file with the `signature` block populated).
pub fn sign(key_path: &str, card_path: &str, json: bool) -> i32 {
    let secret = match read_secret_key(Path::new(key_path)) {
        Ok(k) => k,
        Err(e) => {
            emit_error(json, "tirith command-card sign", &e.to_string());
            return 1;
        }
    };

    let bytes = match std::fs::read(card_path) {
        Ok(b) => b,
        Err(e) => {
            emit_error(
                json,
                "tirith command-card sign",
                &format!("read {card_path}: {e}"),
            );
            return 1;
        }
    };
    let mut card = match Card::from_json(&bytes) {
        Ok(c) => c,
        Err(e) => {
            emit_error(
                json,
                "tirith command-card sign",
                &format!("parse {card_path}: {e}"),
            );
            return 1;
        }
    };

    if let Err(e) = card.sign(&secret) {
        emit_error(json, "tirith command-card sign", &e.to_string());
        return 1;
    }

    let out = match card.to_json_pretty() {
        Ok(s) => s,
        Err(e) => {
            emit_error(json, "tirith command-card sign", &e.to_string());
            return 1;
        }
    };
    // Write atomically: a temp file in the SAME directory then rename over the
    // target. A plain `std::fs::write` truncates in place, so a crash mid-write
    // would lose the original (unsigned) card and leave a truncated file. The
    // rename is atomic on the same filesystem, so a reader sees either the old
    // card or the fully-signed one, never a partial.
    if let Err(e) = write_card_atomic(Path::new(card_path), &format!("{out}\n")) {
        emit_error(
            json,
            "tirith command-card sign",
            &format!("write {card_path}: {e}"),
        );
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
    let bytes = match std::fs::read(card_path) {
        Ok(b) => b,
        Err(e) => {
            emit_error(
                json,
                "tirith command-card verify",
                &format!("read {card_path}: {e}"),
            );
            return 1;
        }
    };
    let card = match Card::from_json(&bytes) {
        Ok(c) => c,
        Err(e) => {
            emit_error(
                json,
                "tirith command-card verify",
                &format!("parse {card_path}: {e}"),
            );
            return 1;
        }
    };

    let trusted_dir = match command_card::trusted_card_keys_dir() {
        Some(d) => d,
        None => {
            emit_error(
                json,
                "tirith command-card verify",
                "could not resolve trusted-keys directory",
            );
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
    let cache_dir = match command_card::cards_cache_dir() {
        Some(d) => d,
        None => {
            emit_error(
                json,
                "tirith command-card fetch",
                "could not resolve cache directory",
            );
            return 1;
        }
    };
    if let Err(e) = std::fs::create_dir_all(&cache_dir) {
        emit_error(
            json,
            "tirith command-card fetch",
            &format!("create {}: {e}", cache_dir.display()),
        );
        return 1;
    }

    // Download to a temp file (reusing the hardened 30s-timeout / 10 MiB-cap
    // download path), validate it parses as a card, then move it to
    // <sha256>.json. The content hash names the file, so we cannot know the
    // destination until after the download.
    let tmp = match tempfile::NamedTempFile::new_in(&cache_dir) {
        Ok(t) => t,
        Err(e) => {
            emit_error(
                json,
                "tirith command-card fetch",
                &format!("temp file: {e}"),
            );
            return 1;
        }
    };
    let dl = match tirith_core::runner::download_to_path(url, tmp.path(), None) {
        Ok(r) => r,
        Err(e) => {
            emit_error(json, "tirith command-card fetch", &e);
            return 1;
        }
    };

    let bytes = match std::fs::read(tmp.path()) {
        Ok(b) => b,
        Err(e) => {
            emit_error(
                json,
                "tirith command-card fetch",
                &format!("read download: {e}"),
            );
            return 1;
        }
    };
    // Validate it is a card before caching — refuse to cache arbitrary content.
    if Card::from_json(&bytes).is_err() {
        emit_error(
            json,
            "tirith command-card fetch",
            "downloaded content is not a valid command card (JSON parse failed)",
        );
        return 1;
    }

    let sha = command_card::sha256_hex(&bytes);
    let dest = cache_dir.join(format!("{sha}.json"));
    // Persist atomically: NamedTempFile::persist renames within the same dir.
    if let Err(e) = tmp.persist(&dest) {
        emit_error(
            json,
            "tirith command-card fetch",
            &format!("persist {}: {}", dest.display(), e.error),
        );
        return 1;
    }

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
    tmp.persist(path).map_err(|e| e.error)?;
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
fn emit_error(json: bool, ctx: &str, msg: &str) {
    if json {
        let v = serde_json::json!({ "error": msg });
        super::write_json_stdout(&v, &format!("{ctx}: failed to write JSON output"));
    } else {
        eprintln!("{ctx}: {msg}");
    }
}

#[cfg(test)]
mod tests {
    use super::write_card_atomic;

    #[test]
    fn write_card_atomic_writes_and_replaces_without_leaving_temp() {
        // F3 (Major): signing writes the card atomically (temp-in-same-dir then
        // rename) so a crash mid-write cannot lose the original. Prove the write
        // lands exactly, an overwrite fully replaces the prior content, and no
        // temp file is left behind in the directory.
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
