//! M11 ch3 — honeytoken / canary tokens (design-decision D3).
//!
//! A *canary* is a deliberately-synthetic secret-shaped token you plant
//! somewhere you expect NOT to be read — a fake `~/.aws/credentials`, a decoy
//! `.env`, a bait line in a private repo. tirith records the token in a
//! local-first store at `state_dir()/canaries.jsonl`. When that exact token
//! later shows up in a command you run or a tool output tirith inspects, the
//! engine fires [`crate::verdict::RuleId::CanaryTokenTouched`] (High) — a strong
//! "someone touched the bait" signal.
//!
//! # D3 — local-first, no phone-home
//!
//! By DEFAULT a canary is **local-only**: detection raises a finding and writes
//! to the local audit log. tirith never operates a callback endpoint and never
//! transmits anything off the machine on the default path — consistent with the
//! "no telemetry / no phone-home" stance in `docs/security.md`.
//!
//! A canary MAY be created with an OPT-IN, USER-SELF-HOSTED `callback_url`. On
//! detection (and ONLY on detection) tirith sends one best-effort POST to that
//! URL with `{kind, detected_at, context}` — **never the token value**. The
//! callback is the single exception to tirith's no-network rule, and it is
//! gated entirely behind an explicit user-supplied `--callback-url`. A callback
//! failure is non-blocking: it is logged to the audit log and never changes the
//! verdict. See [`Canary::fire_callback`].
//!
//! # Clearly-synthetic token shapes
//!
//! Every generated token carries a literal, obviously-fake marker so it can
//! never be mistaken for a real third-party credential (which could trigger an
//! external provider's abuse / take-down workflow), while still matching
//! tirith's own credential-shape detection:
//!
//! | kind                 | shape                                           |
//! |----------------------|-------------------------------------------------|
//! | `aws-like`           | `AKIA00CANARY` + 8 base32-ish chars             |
//! | `github-like`        | `ghp_canary_` + 30 alphanumerics                |
//! | `gcp-like`           | `AIzaCANARY` + 30 url-safe chars                |
//! | `env-line`           | `TIRITH_CANARY_TOKEN=canary_` + 24 hex          |
//! | `private-key-shaped` | a PEM block whose body is `TIRITHCANARY...`     |
//!
//! The `AKIA00CANARY` infix is invalid for a real AWS key: AWS access-key IDs
//! are `AKIA` + `[A-Z2-7]{16}` (RFC 4648 base32), and `0`/`1` are NOT in that
//! alphabet — so `00CANARY` can never collide with a genuine key. The
//! `ghp_canary_` / `AIzaCANARY` / `canary_` markers serve the same purpose for
//! the other kinds. A developer who spots the token can immediately tell it is a
//! tirith canary, not a real leak. See `docs/canary-formats.md`.
//!
//! # Token-shape overlap with real creds
//!
//! Detection is a STORE lookup, not a shape match: ONLY tokens you registered
//! fire [`CanaryTokenTouched`](crate::verdict::RuleId::CanaryTokenTouched). An
//! unrelated, genuine AWS key in a paste still fires the existing
//! `CredentialInText` / `HighEntropySecret` rules — never the canary rule,
//! because that key is not in your store.
//!
//! # Hot-path cost
//!
//! [`detect`] is called on the `engine::analyze` (paste + exec) and
//! `analyze_output` paths. To keep it cheap it is backed by a per-process cache
//! (load once, 5-second TTL, invalidated on store mtime change), exactly like
//! [`crate::taint`]. When the store is absent or empty the lookup is a near-noop
//! and the engine additionally only forces past its tier-1 fast-exit for the
//! canary scan when the store is non-empty (see `engine::canary` wiring via
//! [`store_nonempty`]). A machine that has never run `tirith canary create`
//! pays nothing.

use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};

/// The synthetic token kinds `tirith canary create <kind>` understands.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CanaryKind {
    /// `AKIA00CANARY` + random — AWS-access-key-shaped, but the `00CANARY`
    /// infix is invalid for a real AWS key (`0` ∉ base32).
    AwsLike,
    /// `ghp_canary_` + random — GitHub-personal-access-token-shaped.
    GithubLike,
    /// `AIzaCANARY` + random — Google-API-key-shaped.
    GcpLike,
    /// `TIRITH_CANARY_TOKEN=canary_` + random — a full `.env` assignment line.
    EnvLine,
    /// A PEM block whose body is a `TIRITHCANARY` marker — private-key-shaped.
    PrivateKeyShaped,
}

impl CanaryKind {
    /// The CLI / store token for this kind (`aws-like`, `github-like`, …).
    pub fn as_str(self) -> &'static str {
        match self {
            CanaryKind::AwsLike => "aws-like",
            CanaryKind::GithubLike => "github-like",
            CanaryKind::GcpLike => "gcp-like",
            CanaryKind::EnvLine => "env-line",
            CanaryKind::PrivateKeyShaped => "private-key-shaped",
        }
    }

    /// Parse a `<kind>` CLI argument. Accepts the canonical hyphenated form and
    /// a couple of obvious aliases. Returns `None` on an unknown value so the
    /// CLI can print the supported list.
    pub fn parse(s: &str) -> Option<CanaryKind> {
        match s.trim().to_ascii_lowercase().as_str() {
            "aws-like" | "aws" => Some(CanaryKind::AwsLike),
            "github-like" | "github" | "gh" => Some(CanaryKind::GithubLike),
            "gcp-like" | "gcp" | "google" => Some(CanaryKind::GcpLike),
            "env-line" | "env" => Some(CanaryKind::EnvLine),
            "private-key-shaped" | "private-key" | "pem" => Some(CanaryKind::PrivateKeyShaped),
            _ => None,
        }
    }

    /// Human-readable list of accepted `<kind>` values (for error / help text).
    pub fn all() -> &'static [&'static str] {
        &[
            "aws-like",
            "github-like",
            "gcp-like",
            "env-line",
            "private-key-shaped",
        ]
    }
}

/// One recorded canary: the planted synthetic token plus its metadata.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CanaryEntry {
    /// Stable identifier for `prune`/`rotate` (first 12 hex of a random id).
    pub id: String,
    /// The synthetic token value. This is what [`detect`] matches against the
    /// scanned text. It is NEVER transmitted to a callback URL.
    pub token: String,
    /// The kind the token was generated as (`aws-like`, …). Stored as its CLI
    /// string for forward-compatible round-tripping.
    pub kind: String,
    /// RFC-3339 UTC timestamp the canary was created.
    pub created_at: String,
    /// OPT-IN, user-self-hosted callback URL. `None` = local-only (the default).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub callback_url: Option<String>,
}

/// A detection: a registered canary token was found in scanned text.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CanaryHit {
    /// The id of the matched canary.
    pub id: String,
    /// The kind of the matched canary (`aws-like`, …).
    pub kind: String,
    /// The matched canary's callback URL, if any (drives the best-effort POST).
    pub callback_url: Option<String>,
}

/// Default on-disk store path: `state_dir()/canaries.jsonl`.
pub fn store_path() -> Option<PathBuf> {
    crate::policy::state_dir().map(|d| d.join("canaries.jsonl"))
}

/// Generate a fresh, clearly-synthetic token for `kind`. Pure (RNG only) — the
/// caller decides whether to persist it.
pub fn generate_token(kind: CanaryKind) -> String {
    match kind {
        // AWS access keys are `AKIA` + 16 base32 chars. `0` is NOT in base32,
        // so `AKIA00CANARY` (12 chars) + 8 more = a 20-char `AKIA…` string that
        // can never be a real key. Suffix uses the base32 alphabet for shape.
        CanaryKind::AwsLike => format!("AKIA00CANARY{}", random_chars(BASE32, 8)),
        // `ghp_` is GitHub's PAT prefix; `canary_` makes it obviously fake.
        CanaryKind::GithubLike => format!("ghp_canary_{}", random_chars(ALNUM, 30)),
        // `AIza` is Google's API-key prefix; `CANARY` marks it synthetic.
        CanaryKind::GcpLike => format!("AIzaCANARY{}", random_chars(URLSAFE, 30)),
        // A complete `.env` assignment line, value clearly marked.
        CanaryKind::EnvLine => {
            format!("TIRITH_CANARY_TOKEN=canary_{}", random_chars(HEX, 24))
        }
        // A PEM block whose decoded-looking body is a TIRITHCANARY marker.
        CanaryKind::PrivateKeyShaped => {
            let body = format!("TIRITHCANARY{}", random_chars(BASE64ISH, 52));
            format!("-----BEGIN TIRITH CANARY PRIVATE KEY-----\n{body}\n-----END TIRITH CANARY PRIVATE KEY-----")
        }
    }
}

const ALNUM: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
const BASE32: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
const HEX: &[u8] = b"0123456789abcdef";
const URLSAFE: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
const BASE64ISH: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/// `n` random characters drawn from `alphabet`, seeded by the OS CSPRNG.
///
/// Uses `getrandom::fill` (the same OS-entropy source `baseline.rs` uses for
/// the per-install salt) — `rand` is only a dev-dependency in this crate. To
/// avoid modulo bias we sample bytes with rejection: only bytes below the
/// largest multiple of `len` that fits in a `u8` are accepted, so every
/// alphabet character is equally likely. The token's unguessability comes from
/// the OS CSPRNG; on the (astronomically unlikely) event `getrandom` fails we
/// fall back to a deterministic-but-namespaced suffix so token generation never
/// panics — a generated token is still clearly synthetic regardless.
fn random_chars(alphabet: &[u8], n: usize) -> String {
    let len = alphabet.len();
    debug_assert!((1..=256).contains(&len), "alphabet must be 1..=256 bytes");
    // Largest multiple of `len` representable in a u8; bytes >= this are
    // rejected to keep the distribution uniform.
    let limit = (256 / len) * len;

    let mut out = String::with_capacity(n);
    let mut buf = [0u8; 64];
    while out.len() < n {
        if getrandom::fill(&mut buf).is_err() {
            // Entropy unavailable — extremely rare. Pad with a fixed marker so
            // the caller still gets a clearly-synthetic, well-formed token
            // rather than a panic or an empty suffix.
            while out.len() < n {
                out.push(alphabet[out.len() % len] as char);
            }
            break;
        }
        for &b in buf.iter() {
            if out.len() >= n {
                break;
            }
            if (b as usize) < limit {
                out.push(alphabet[(b as usize) % len] as char);
            }
        }
    }
    out
}

/// A 12-hex-char random id.
fn new_id() -> String {
    random_chars(HEX, 12)
}

// ---- Store I/O ------------------------------------------------------------

/// Per-process cache of the parsed store, keyed on the resolved store path.
/// Mirrors [`crate::taint`]'s cache exactly so the hot path stays cheap.
struct CacheState {
    path: PathBuf,
    entries: Vec<CanaryEntry>,
    loaded_at: Instant,
    mtime_nanos: u128,
}

static CACHE: Mutex<Option<CacheState>> = Mutex::new(None);

const CACHE_TTL: Duration = Duration::from_secs(5);

fn mtime_nanos(path: &Path) -> u128 {
    std::fs::metadata(path)
        .and_then(|m| m.modified())
        .ok()
        .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
        .map(|d| d.as_nanos())
        .unwrap_or(0)
}

/// Parse the JSONL store, skipping blank / unparseable lines AND continuing past
/// reader I/O errors (fail-open: a corrupt line or a transient read error never
/// aborts the lookup or silently truncates later entries). Empty vec when the
/// file is absent.
///
/// NB: a previous `map_while(Result::ok)` here STOPPED at the first line that
/// returned `Err` from the reader (e.g. invalid UTF-8 mid-file), silently
/// dropping every canary AFTER it — a later touched canary would never fire.
/// We now `continue` on a line error so a single bad line cannot mask the rest
/// of the store (matching the corrupt-line-skip-but-continue contract).
fn parse_store(path: &Path) -> Vec<CanaryEntry> {
    let Ok(file) = std::fs::File::open(path) else {
        return Vec::new();
    };
    let reader = BufReader::new(file);
    let mut out = Vec::new();
    for line in reader.lines() {
        // A reader error (e.g. invalid UTF-8) skips THIS line but must not stop
        // us reading the rest — otherwise a corrupt byte hides later canaries.
        let Ok(line) = line else {
            continue;
        };
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        if let Ok(entry) = serde_json::from_str::<CanaryEntry>(trimmed) {
            out.push(entry);
        }
    }
    out
}

/// Load entries through the per-process cache. Reloads when the cached path
/// differs, the TTL expired, or the store's mtime changed.
fn cached_entries(path: &Path) -> Vec<CanaryEntry> {
    let mut guard = CACHE.lock().unwrap_or_else(|e| e.into_inner());
    let now = Instant::now();
    let cur_mtime = mtime_nanos(path);

    if let Some(state) = guard.as_ref() {
        let fresh = state.path == path
            && now.duration_since(state.loaded_at) < CACHE_TTL
            && state.mtime_nanos == cur_mtime;
        if fresh {
            return state.entries.clone();
        }
    }

    let entries = parse_store(path);
    *guard = Some(CacheState {
        path: path.to_path_buf(),
        entries: entries.clone(),
        loaded_at: now,
        mtime_nanos: cur_mtime,
    });
    entries
}

/// Drop the per-process cache. Tests that write a store directly then assert via
/// the default-path API call this so a stale earlier load is not reused.
pub fn invalidate_cache() {
    let mut guard = CACHE.lock().unwrap_or_else(|e| e.into_inner());
    *guard = None;
}

/// Append `entry` to the JSONL store at `store`, creating parent dirs and the
/// file (`0600` on Unix) as needed.
fn append_entry(store: &Path, entry: &CanaryEntry) -> std::io::Result<()> {
    if let Some(parent) = store.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let mut opts = std::fs::OpenOptions::new();
    opts.create(true).append(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let mut file = opts.open(store)?;
    let line = serde_json::to_string(entry).map_err(std::io::Error::other)?;
    writeln!(file, "{line}")?;
    Ok(())
}

/// Atomically rewrite the store to exactly `entries` (used by `prune`/`rotate`).
/// Writes a sibling temp file then renames over the target so a crash mid-write
/// never truncates the store.
fn rewrite_store(store: &Path, entries: &[CanaryEntry]) -> std::io::Result<()> {
    if let Some(parent) = store.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let dir = store.parent().unwrap_or_else(|| Path::new("."));
    let mut tmp = tempfile::NamedTempFile::new_in(dir)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        tmp.as_file()
            .set_permissions(std::fs::Permissions::from_mode(0o600))?;
    }
    for entry in entries {
        let line = serde_json::to_string(entry).map_err(std::io::Error::other)?;
        writeln!(tmp, "{line}")?;
    }
    tmp.persist(store).map_err(|e| e.error)?;
    Ok(())
}

// ---- Public store API (store-parameterized + default-path wrappers) -------

/// Create a canary of `kind` in the store at `store`, returning the recorded
/// entry. `callback_url` is the OPT-IN, user-self-hosted URL (`None` =
/// local-only, the default).
pub fn create_at(
    store: &Path,
    kind: CanaryKind,
    callback_url: Option<String>,
) -> std::io::Result<CanaryEntry> {
    let entry = CanaryEntry {
        id: new_id(),
        token: generate_token(kind),
        kind: kind.as_str().to_string(),
        created_at: chrono::Utc::now().to_rfc3339(),
        callback_url,
    };
    append_entry(store, &entry)?;
    invalidate_cache();
    Ok(entry)
}

/// Production entry point: create a canary in the default store.
pub fn create(kind: CanaryKind, callback_url: Option<String>) -> std::io::Result<CanaryEntry> {
    let store = store_path().ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::NotFound,
            "cannot determine tirith state directory",
        )
    })?;
    create_at(&store, kind, callback_url)
}

/// List every recorded canary in the store at `store`, in file order.
pub fn list_at(store: &Path) -> Vec<CanaryEntry> {
    parse_store(store)
}

/// Production entry point: list every recorded canary in the default store.
pub fn list() -> Vec<CanaryEntry> {
    match store_path() {
        Some(p) => list_at(&p),
        None => Vec::new(),
    }
}

/// Remove the canary with `id` from the store at `store`. Returns the number of
/// entries removed (0 when the id is unknown).
pub fn prune_at(store: &Path, id: &str) -> std::io::Result<usize> {
    let entries = parse_store(store);
    let before = entries.len();
    let kept: Vec<CanaryEntry> = entries.into_iter().filter(|e| e.id != id).collect();
    let removed = before - kept.len();
    if removed == 0 {
        return Ok(0);
    }
    rewrite_store(store, &kept)?;
    invalidate_cache();
    Ok(removed)
}

/// Production entry point: remove the canary with `id` from the default store.
pub fn prune(id: &str) -> std::io::Result<usize> {
    let store = store_path().ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::NotFound,
            "cannot determine tirith state directory",
        )
    })?;
    prune_at(&store, id)
}

/// Rotate the canary with `id` in the store at `store`: generate a FRESH token
/// of the SAME kind, preserving the id and callback URL. Returns the updated
/// entry, or `None` when the id is unknown.
pub fn rotate_at(store: &Path, id: &str) -> std::io::Result<Option<CanaryEntry>> {
    let mut entries = parse_store(store);
    let Some(idx) = entries.iter().position(|e| e.id == id) else {
        return Ok(None);
    };
    // Default to AwsLike only if a corrupt entry has an unknown kind string;
    // for any well-formed entry the parse round-trips the original kind.
    let kind = CanaryKind::parse(&entries[idx].kind).unwrap_or(CanaryKind::AwsLike);
    entries[idx].token = generate_token(kind);
    entries[idx].created_at = chrono::Utc::now().to_rfc3339();
    let updated = entries[idx].clone();
    rewrite_store(store, &entries)?;
    invalidate_cache();
    Ok(Some(updated))
}

/// Production entry point: rotate the canary with `id` in the default store.
pub fn rotate(id: &str) -> std::io::Result<Option<CanaryEntry>> {
    let store = store_path().ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::NotFound,
            "cannot determine tirith state directory",
        )
    })?;
    rotate_at(&store, id)
}

/// `true` when the store at `store` exists and has at least one byte. Used by
/// the engine to decide whether to force past the tier-1 fast-exit for the
/// canary scan. A cheap `metadata()` stat — no parse.
pub fn store_nonempty_at(store: &Path) -> bool {
    std::fs::metadata(store)
        .map(|m| m.len() > 0)
        .unwrap_or(false)
}

/// Production entry point for the engine's tier-1 force-past decision.
pub fn store_nonempty() -> bool {
    store_path().map(|p| store_nonempty_at(&p)).unwrap_or(false)
}

// ---- Detection ------------------------------------------------------------

/// Scan `text` against every canary registered in the store at `store`. Returns
/// one [`CanaryHit`] per matching canary (deduped by id — a token appearing
/// twice yields one hit). `text.contains(&token)` substring match: a canary
/// planted in a larger blob (e.g. a `cat ~/.aws/credentials` paste) still fires.
pub fn detect_at(store: &Path, text: &str) -> Vec<CanaryHit> {
    if text.is_empty() {
        return Vec::new();
    }
    let entries = cached_entries(store);
    let mut hits = Vec::new();
    for e in entries {
        // An empty token would `contains`-match everything; skip defensively
        // (a well-formed entry never has an empty token).
        if e.token.is_empty() {
            continue;
        }
        if text.contains(&e.token) {
            hits.push(CanaryHit {
                id: e.id,
                kind: e.kind,
                callback_url: e.callback_url,
            });
        }
    }
    hits
}

/// Production entry point: scan `text` against the default store.
pub fn detect(text: &str) -> Vec<CanaryHit> {
    match store_path() {
        Some(p) => detect_at(&p, text),
        None => Vec::new(),
    }
}

/// Fire the OPT-IN, best-effort callback for a detection. Sends ONE POST to
/// `hit.callback_url` (when set) with a JSON body of `{kind, detected_at,
/// context}` — **never the token value**. `context` is a short, caller-supplied
/// label (e.g. `"exec"`, `"paste"`, `"output"`).
///
/// This is the SINGLE network path the canary feature can take, and it fires
/// ONLY on detection of a canary that was created with an explicit
/// `--callback-url`. It is fully FIRE-AND-FORGET and fail-open:
///
/// * No callback URL → no-op (returns immediately; no thread, no network).
/// * The POST runs on a DETACHED thread, so the engine verdict NEVER waits on
///   it — a slow or hung endpoint cannot delay (or block) the command. A 1.5s
///   connect / 3s total timeout caps the detached thread's lifetime.
/// * Any error (DNS, TLS, timeout, non-2xx) is logged to the audit log via
///   [`crate::audit::log_hook_event`] and otherwise swallowed — a callback
///   NEVER blocks or alters the verdict.
///
/// The token value is deliberately NOT a parameter so it cannot leak into the
/// request body.
pub fn fire_callback(hit: &CanaryHit, context: &str) {
    let Some(url) = hit.callback_url.as_deref() else {
        return;
    };
    let url = url.trim();
    if url.is_empty() {
        return;
    }

    // Own everything the detached thread needs; nothing borrows from `hit`.
    let url = url.to_string();
    let kind = hit.kind.clone();
    let id = hit.id.clone();
    let context = context.to_string();
    let detected_at = chrono::Utc::now().to_rfc3339();

    // Detached: the engine returns its verdict without waiting on the network.
    // If the process exits before the POST completes the callback is simply
    // dropped — best-effort by design. We do not join the handle.
    let _ = std::thread::Builder::new()
        .name("tirith-canary-callback".to_string())
        .spawn(move || {
            #[derive(Serialize)]
            struct CallbackBody {
                kind: String,
                detected_at: String,
                context: String,
            }
            let body = CallbackBody {
                kind,
                detected_at,
                context,
            };

            let client = match reqwest::blocking::Client::builder()
                .connect_timeout(Duration::from_millis(1500))
                .timeout(Duration::from_secs(3))
                .build()
            {
                Ok(c) => c,
                Err(e) => {
                    log_callback_failure(&id, &format!("client build failed: {e}"));
                    return;
                }
            };

            match client.post(&url).json(&body).send() {
                Ok(resp) if resp.status().is_success() => {}
                Ok(resp) => {
                    log_callback_failure(&id, &format!("callback returned HTTP {}", resp.status()));
                }
                Err(e) => {
                    log_callback_failure(&id, &format!("callback POST failed: {e}"));
                }
            }
        });
}

/// Log a non-blocking canary-callback failure to the audit log. Reuses the
/// hook-telemetry entry shape (`integration = "canary"`). The id is recorded;
/// the token value and the callback URL are NOT (no secret / endpoint leakage).
fn log_callback_failure(id: &str, reason: &str) {
    crate::audit::log_hook_event(
        "canary",
        "callback",
        "callback_failed",
        None,
        Some(&format!("canary {id}: {reason}")),
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    fn store_in(dir: &Path) -> PathBuf {
        dir.join("canaries.jsonl")
    }

    #[test]
    fn aws_like_token_is_clearly_synthetic() {
        let tok = generate_token(CanaryKind::AwsLike);
        assert!(tok.starts_with("AKIA00CANARY"), "got {tok}");
        // `0` is not in the AWS base32 alphabet, so a real key can never carry
        // the `00CANARY` infix — this is the load-bearing "can't be mistaken
        // for a real credential" property.
        assert!(tok.contains("00CANARY"));
        assert_eq!(tok.len(), "AKIA00CANARY".len() + 8);
    }

    #[test]
    fn github_and_gcp_tokens_carry_canary_markers() {
        assert!(generate_token(CanaryKind::GithubLike).starts_with("ghp_canary_"));
        assert!(generate_token(CanaryKind::GcpLike).starts_with("AIzaCANARY"));
    }

    #[test]
    fn env_line_and_pem_are_synthetic() {
        let env = generate_token(CanaryKind::EnvLine);
        assert!(env.starts_with("TIRITH_CANARY_TOKEN=canary_"));
        let pem = generate_token(CanaryKind::PrivateKeyShaped);
        assert!(pem.contains("BEGIN TIRITH CANARY PRIVATE KEY"));
        assert!(pem.contains("TIRITHCANARY"));
    }

    #[test]
    fn tokens_are_unique_per_create() {
        let a = generate_token(CanaryKind::GithubLike);
        let b = generate_token(CanaryKind::GithubLike);
        assert_ne!(a, b, "two creates must not collide");
    }

    #[test]
    fn create_then_detect_roundtrips() {
        let dir = tempdir().unwrap();
        let store = store_in(dir.path());

        // Nothing registered → no hit.
        assert!(detect_at(&store, "some random text AKIA00CANARYZZZZZZZZ").is_empty());

        let entry = create_at(&store, CanaryKind::AwsLike, None).unwrap();
        assert_eq!(entry.kind, "aws-like");
        assert!(entry.callback_url.is_none());

        // The exact token, embedded in a larger blob, fires.
        let blob = format!(
            "cat ~/.aws/credentials\naws_access_key_id = {}\n",
            entry.token
        );
        let hits = detect_at(&store, &blob);
        assert_eq!(hits.len(), 1, "registered token must fire exactly one hit");
        assert_eq!(hits[0].id, entry.id);
        assert_eq!(hits[0].kind, "aws-like");
    }

    #[test]
    fn unrelated_real_looking_key_does_not_fire() {
        let dir = tempdir().unwrap();
        let store = store_in(dir.path());
        // Register one canary.
        let entry = create_at(&store, CanaryKind::GithubLike, None).unwrap();
        // A DIFFERENT, unrelated credential-shaped string must NOT fire the
        // canary rule — only YOUR registered token does.
        let other = "AKIAIOSFODNN7EXAMPLE and ghp_0000000000000000000000000000000000";
        assert!(detect_at(&store, other).is_empty());
        // And the registered token still fires.
        assert_eq!(detect_at(&store, &entry.token).len(), 1);
    }

    #[test]
    fn detect_dedups_per_id() {
        let dir = tempdir().unwrap();
        let store = store_in(dir.path());
        let entry = create_at(&store, CanaryKind::AwsLike, None).unwrap();
        // Token appears twice → one hit.
        let text = format!("{} and again {}", entry.token, entry.token);
        assert_eq!(detect_at(&store, &text).len(), 1);
    }

    #[test]
    fn list_returns_all_entries() {
        let dir = tempdir().unwrap();
        let store = store_in(dir.path());
        create_at(&store, CanaryKind::AwsLike, None).unwrap();
        create_at(&store, CanaryKind::GithubLike, None).unwrap();
        assert_eq!(list_at(&store).len(), 2);
    }

    #[test]
    fn prune_removes_only_the_target() {
        let dir = tempdir().unwrap();
        let store = store_in(dir.path());
        let a = create_at(&store, CanaryKind::AwsLike, None).unwrap();
        let b = create_at(&store, CanaryKind::GithubLike, None).unwrap();

        assert_eq!(prune_at(&store, &a.id).unwrap(), 1);
        let remaining = list_at(&store);
        assert_eq!(remaining.len(), 1);
        assert_eq!(remaining[0].id, b.id);

        // A token from the pruned canary no longer fires.
        assert!(detect_at(&store, &a.token).is_empty());
        assert_eq!(detect_at(&store, &b.token).len(), 1);
    }

    #[test]
    fn prune_unknown_id_is_zero() {
        let dir = tempdir().unwrap();
        let store = store_in(dir.path());
        create_at(&store, CanaryKind::AwsLike, None).unwrap();
        assert_eq!(prune_at(&store, "nope").unwrap(), 0);
    }

    #[test]
    fn rotate_changes_token_keeps_id_and_callback() {
        let dir = tempdir().unwrap();
        let store = store_in(dir.path());
        let cb = Some("https://my-self-hosted.example/hit".to_string());
        let original = create_at(&store, CanaryKind::GithubLike, cb.clone()).unwrap();

        let rotated = rotate_at(&store, &original.id).unwrap().expect("known id");
        assert_eq!(rotated.id, original.id, "id is preserved");
        assert_eq!(rotated.kind, "github-like", "kind is preserved");
        assert_eq!(rotated.callback_url, cb, "callback url is preserved");
        assert_ne!(rotated.token, original.token, "token is regenerated");
        assert!(rotated.token.starts_with("ghp_canary_"));

        // The OLD token no longer fires; the NEW one does.
        assert!(detect_at(&store, &original.token).is_empty());
        assert_eq!(detect_at(&store, &rotated.token).len(), 1);
    }

    #[test]
    fn rotate_unknown_id_is_none() {
        let dir = tempdir().unwrap();
        let store = store_in(dir.path());
        create_at(&store, CanaryKind::AwsLike, None).unwrap();
        assert!(rotate_at(&store, "nope").unwrap().is_none());
    }

    #[test]
    fn store_nonempty_reflects_create() {
        let dir = tempdir().unwrap();
        let store = store_in(dir.path());
        assert!(!store_nonempty_at(&store));
        create_at(&store, CanaryKind::AwsLike, None).unwrap();
        assert!(store_nonempty_at(&store));
    }

    #[test]
    fn corrupt_line_is_skipped_not_fatal() {
        let dir = tempdir().unwrap();
        let store = store_in(dir.path());
        std::fs::write(
            &store,
            "not json\n{\"id\":\"abc\",\"token\":\"ghp_canary_x\",\"kind\":\"github-like\",\"created_at\":\"t\"}\n\n",
        )
        .unwrap();
        let list = list_at(&store);
        assert_eq!(list.len(), 1);
        assert_eq!(list[0].id, "abc");
    }

    #[test]
    fn reader_io_error_line_does_not_truncate_later_entries() {
        // F3 (Sev-5): a reader I/O error (invalid UTF-8) on one line must skip
        // only THAT line — entries AFTER it must still load. The previous
        // `map_while(Result::ok)` stopped at the first Err, silently dropping a
        // later (possibly TOUCHED) canary.
        let dir = tempdir().unwrap();
        let store = store_in(dir.path());

        // Build: valid entry, then a line with invalid UTF-8 (0xFF), then a
        // second valid entry. `BufRead::lines()` yields Err on the bad line.
        let mut bytes: Vec<u8> = Vec::new();
        bytes.extend_from_slice(
            b"{\"id\":\"first\",\"token\":\"ghp_canary_first\",\"kind\":\"github-like\",\"created_at\":\"t\"}\n",
        );
        bytes.extend_from_slice(&[0xff, 0xfe, b'\n']); // invalid UTF-8 line
        bytes.extend_from_slice(
            b"{\"id\":\"second\",\"token\":\"ghp_canary_second\",\"kind\":\"github-like\",\"created_at\":\"t\"}\n",
        );
        std::fs::write(&store, &bytes).unwrap();

        let list = list_at(&store);
        let ids: Vec<&str> = list.iter().map(|e| e.id.as_str()).collect();
        assert!(ids.contains(&"first"), "first entry must load, got {ids:?}");
        assert!(
            ids.contains(&"second"),
            "entry AFTER the bad line must still load (no truncation), got {ids:?}"
        );

        // And detection still sees the post-error token.
        assert_eq!(detect_at(&store, "ghp_canary_second").len(), 1);
    }

    #[test]
    fn kind_parse_roundtrips_all_variants() {
        for k in [
            CanaryKind::AwsLike,
            CanaryKind::GithubLike,
            CanaryKind::GcpLike,
            CanaryKind::EnvLine,
            CanaryKind::PrivateKeyShaped,
        ] {
            assert_eq!(CanaryKind::parse(k.as_str()), Some(k));
        }
        assert!(CanaryKind::parse("not-a-kind").is_none());
    }

    #[test]
    fn fire_callback_without_url_is_noop() {
        // A local-only canary (no callback URL) must not attempt any network.
        let hit = CanaryHit {
            id: "x".to_string(),
            kind: "aws-like".to_string(),
            callback_url: None,
        };
        // Must return immediately without panicking or hanging.
        fire_callback(&hit, "exec");
    }
}
