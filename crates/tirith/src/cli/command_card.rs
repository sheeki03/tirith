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
    if let Err(e) = std::fs::write(card_path, format!("{out}\n")) {
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
        super::write_json_stdout(&v, "tirith command-card sign: failed to write JSON output");
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
        super::write_json_stdout(
            &v,
            "tirith command-card verify: failed to write JSON output",
        );
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
        super::write_json_stdout(&v, "tirith command-card fetch: failed to write JSON output");
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
