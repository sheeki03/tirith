//! M11 ch3 — honeytoken / canary tokens (design-decision D3).
//!
//! A *canary* is a synthetic secret-shaped token you plant where you expect it
//! NOT to be read (a fake `~/.aws/credentials`, a decoy `.env`). tirith records
//! it local-first at `state_dir()/canaries.jsonl`; when that exact token later
//! appears in a command or tool output, the engine fires
//! [`crate::verdict::RuleId::CanaryTokenTouched`] (High).
//!
//! # D3 — local-first, no phone-home
//!
//! By DEFAULT a canary is local-only (finding + audit log, no network). It MAY
//! be created with an OPT-IN, user-self-hosted `--callback-url`: on detection
//! ONLY, tirith sends one best-effort POST of `{kind, detected_at, context}` —
//! NEVER the token value. This is the single exception to the no-network rule;
//! a callback failure is logged and never changes the verdict. See
//! [`fire_callback`].
//!
//! # Clearly-synthetic token shapes
//!
//! Every token carries an obviously-fake marker (`AKIA00CANARY`, `ghp_canary_`,
//! `AIzaCANARY`, `TIRITH_CANARY_TOKEN=canary_`, a `TIRITHCANARY` PEM body) so a
//! flagged value reads as tirith bait, not a real third-party credential, while
//! still matching tirith's own credential-shape detection. A clearly-labelled
//! property, not a mathematical impossibility claim — see
//! `docs/canary-formats.md`.
//!
//! Detection is a STORE lookup, not a shape match: only registered tokens fire
//! `CanaryTokenTouched`; an unrelated genuine key fires the existing
//! `CredentialInText` / `HighEntropySecret` rules instead.
//!
//! # Hot-path cost
//!
//! [`detect`] (on the analyze + analyze_output paths) is backed by a per-process
//! cache (5s TTL, mtime-invalidated), like [`crate::taint`]. An absent/empty
//! store is a near-noop and the engine only forces past tier-1 when the store is
//! non-empty (via [`store_nonempty`]), so a machine that never ran
//! `tirith canary create` pays nothing.

use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};

/// The synthetic token kinds `tirith canary create <kind>` understands.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CanaryKind {
    /// `AKIA00CANARY` + random — AWS-access-key-shaped.
    AwsLike,
    /// `ghp_canary_` + random — GitHub-PAT-shaped.
    GithubLike,
    /// `AIzaCANARY` + random — Google-API-key-shaped.
    GcpLike,
    /// `TIRITH_CANARY_TOKEN=canary_` + random — a full `.env` line.
    EnvLine,
    /// A PEM block with a `TIRITHCANARY` body — private-key-shaped.
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

    /// Parse a `<kind>` CLI argument (canonical hyphenated form + aliases).
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
    /// Stable identifier for `prune`/`rotate` (12 hex chars).
    pub id: String,
    /// The synthetic token [`detect`] matches against. NEVER transmitted.
    pub token: String,
    /// The kind's CLI string, stored for forward-compatible round-tripping.
    pub kind: String,
    /// RFC-3339 UTC creation timestamp.
    pub created_at: String,
    /// OPT-IN, user-self-hosted callback URL. `None` = local-only (default).
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
        // Keep the recognizable `AKIA` prefix + an explicit `00CANARY` marker so
        // the token is clearly synthetic; suffix is base32 purely for shape.
        CanaryKind::AwsLike => format!("AKIA00CANARY{}", random_chars(BASE32, 8)),
        CanaryKind::GithubLike => format!("ghp_canary_{}", random_chars(ALNUM, 30)),
        CanaryKind::GcpLike => format!("AIzaCANARY{}", random_chars(URLSAFE, 30)),
        CanaryKind::EnvLine => {
            format!("TIRITH_CANARY_TOKEN=canary_{}", random_chars(HEX, 24))
        }
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

/// `n` random characters from `alphabet`, seeded by the OS CSPRNG.
///
/// Uses `getrandom::fill` (`rand` is only a dev-dep). Rejection sampling avoids
/// modulo bias (only bytes below the largest `u8` multiple of `len` are kept).
/// If `getrandom` fails (astronomically unlikely) it falls back to a
/// per-call-VARYING pseudo-random suffix ([`fill_fallback_bytes`]) so generation
/// never panics and two calls don't collide (CodeRabbit R9 #H).
fn random_chars(alphabet: &[u8], n: usize) -> String {
    let len = alphabet.len();
    debug_assert!((1..=256).contains(&len), "alphabet must be 1..=256 bytes");
    // Largest u8 multiple of `len`; bytes >= this are rejected for uniformity.
    let limit = (256 / len) * len;

    let mut out = String::with_capacity(n);
    let mut buf = [0u8; 64];
    while out.len() < n {
        if getrandom::fill(&mut buf).is_err() {
            // Entropy unavailable. Fill from a per-call-varying source so the
            // bytes differ each call (deterministic cycling made `new_id` repeat).
            let mut fb = [0u8; 64];
            fill_fallback_bytes(&mut fb);
            for &b in fb.iter() {
                if out.len() >= n {
                    break;
                }
                if (b as usize) < limit {
                    out.push(alphabet[(b as usize) % len] as char);
                }
            }
            // The counter advances each call, so the loop makes progress; redraw
            // on the next iteration if this buffer was fully rejected.
            continue;
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

/// Fill `buf` with pseudo-random bytes from a per-call-VARYING seed, used ONLY
/// when `getrandom` is unavailable (CodeRabbit R9 #H). Mixes a process-lifetime
/// counter (distinct per call) + wall-clock nanos (distinct across processes),
/// expanded with SplitMix64. NOT cryptographic — it only needs to produce
/// DISTINCT tokens so repeated `new_id()` calls cannot collide.
fn fill_fallback_bytes(buf: &mut [u8; 64]) {
    use std::sync::atomic::{AtomicU64, Ordering};
    static COUNTER: AtomicU64 = AtomicU64::new(0);

    let counter = COUNTER.fetch_add(1, Ordering::Relaxed);
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0);
    let mut state = counter
        .wrapping_mul(0x9E37_79B9_7F4A_7C15)
        .wrapping_add(nanos)
        .wrapping_add(1);
    for chunk in buf.chunks_mut(8) {
        // SplitMix64 step.
        state = state.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = state;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^= z >> 31;
        let bytes = z.to_le_bytes();
        chunk.copy_from_slice(&bytes[..chunk.len()]);
    }
}

/// A 12-hex-char random id.
fn new_id() -> String {
    random_chars(HEX, 12)
}

// ---- Store I/O ------------------------------------------------------------

/// Per-process cache of the parsed store, keyed on the resolved path. Mirrors
/// [`crate::taint`]'s cache so the hot path stays cheap.
struct CacheState {
    path: PathBuf,
    entries: Vec<CanaryEntry>,
    /// `false` = a mid-file I/O fault left the tail unread, so `entries` is a
    /// PARTIAL prefix (a touched canary in the tail would read as untouched,
    /// fail-OPEN). `detect_at` surfaces it on a miss (CodeRabbit R16 #3).
    complete: bool,
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

/// Parse the JSONL store, skipping blank/unparseable lines and continuing past
/// recoverable read errors (fail-open: a bad line never masks later entries).
/// Empty vec when absent. `complete == false` flags a truncated read (a
/// persistent mid-file fault), which a previous `map_while(Result::ok)` would
/// have silently dropped the tail on.
fn parse_store(path: &Path) -> (Vec<CanaryEntry>, bool) {
    // `read_store_lines_complete` skips blanks + a single recoverable bad-UTF-8
    // line, and BREAKS (reporting `complete == false`) on any other read error.
    // An InvalidData skip is not a truncation, so `complete` stays `true`.
    let (lines, complete) = crate::util::read_store_lines_complete(path);
    let entries = lines
        .iter()
        .filter_map(|line| serde_json::from_str::<CanaryEntry>(line).ok())
        .collect();
    (entries, complete)
}

/// Load entries through the per-process cache. Reloads on path change, TTL
/// expiry, or mtime change. `complete == false` flags a truncated read so
/// `detect_at` surfaces incompleteness on a miss (CodeRabbit R16 #3).
fn cached_entries(path: &Path) -> (Vec<CanaryEntry>, bool) {
    let mut guard = CACHE.lock().unwrap_or_else(|e| e.into_inner());
    let now = Instant::now();
    let cur_mtime = mtime_nanos(path);

    if let Some(state) = guard.as_ref() {
        let fresh = state.path == path
            && now.duration_since(state.loaded_at) < CACHE_TTL
            && state.mtime_nanos == cur_mtime;
        if fresh {
            return (state.entries.clone(), state.complete);
        }
    }

    let (entries, complete) = parse_store(path);
    *guard = Some(CacheState {
        path: path.to_path_buf(),
        entries: entries.clone(),
        complete,
        loaded_at: now,
        mtime_nanos: cur_mtime,
    });
    (entries, complete)
}

/// Drop the per-process cache (so a stale earlier load is not reused).
pub fn invalidate_cache() {
    let mut guard = CACHE.lock().unwrap_or_else(|e| e.into_inner());
    *guard = None;
}

/// Exclusive cross-process advisory lock on a sibling `<store>.lock`, released
/// on drop. The three mutators (`create_at`/`prune_at`/`rotate_at`) hold it
/// across their read-modify-write so a concurrent create+prune cannot drop each
/// other's updates. Reads (`list`/`detect`) are NOT locked — the atomic rename
/// in [`rewrite_store_lines`] gives them a whole-prior-or-whole-next file.
///
/// Uses the same `fs2::FileExt` advisory locking as `audit.rs`. The `.lock` is a
/// zero-byte sentinel, only locked, left in place between calls. `pub(crate)`
/// and store-agnostic so other JSONL mutators reuse it (CodeRabbit R13f —
/// `baseline::record_at`).
pub(crate) struct StoreLock {
    file: std::fs::File,
}

impl StoreLock {
    /// Acquire the exclusive lock guarding `store` (creating parent dirs + the
    /// lock file), blocking until held. If advisory locking is unsupported here
    /// we proceed WITHOUT it (the atomic rename still prevents torn files).
    pub(crate) fn acquire(store: &Path) -> std::io::Result<Self> {
        if let Some(parent) = store.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let lock_path = lock_path_for(store);
        let mut opts = std::fs::OpenOptions::new();
        opts.create(true).read(true).write(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o600);
        }
        let file = opts.open(&lock_path)?;
        use fs2::FileExt;
        // Blocking exclusive lock. Only `Unsupported` is best-effort (proceed
        // UNLOCKED, atomic rename still prevents torn files); any other lock
        // error fails loudly so the mutation aborts rather than racing, like
        // `audit.rs`.
        if let Err(e) = file.lock_exclusive() {
            if e.kind() != std::io::ErrorKind::Unsupported {
                return Err(e);
            }
            // Unsupported blocking lock: try once more non-blocking. A
            // non-Unsupported error here still fails loudly (CodeRabbit R13e);
            // only a SECOND Unsupported degrades to unlocked.
            if let Err(e2) = file.try_lock_exclusive() {
                if e2.kind() != std::io::ErrorKind::Unsupported {
                    return Err(e2);
                }
            }
        }
        Ok(StoreLock { file })
    }
}

impl Drop for StoreLock {
    fn drop(&mut self) {
        use fs2::FileExt;
        let _ = FileExt::unlock(&self.file);
    }
}

/// Path of the sibling lock file for `store` (`<store>.lock`).
fn lock_path_for(store: &Path) -> PathBuf {
    let mut name = store.file_name().unwrap_or_default().to_os_string();
    name.push(".lock");
    match store.parent() {
        Some(parent) if !parent.as_os_str().is_empty() => parent.join(name),
        _ => PathBuf::from(name),
    }
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
    // `mode` only applies on fresh create; narrow an existing wider-perms file
    // to 0600 before appending sensitive token/callback data (CodeRabbit R13b).
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        file.set_permissions(std::fs::Permissions::from_mode(0o600))?;
    }
    let line = serde_json::to_string(entry).map_err(std::io::Error::other)?;
    writeln!(file, "{line}")?;
    // Durability: fsync so the appended line survives a crash, else a registered
    // canary could never fire. (`flush` is a no-op for `File`; `sync_all` is the
    // barrier.) Then fsync the parent dir so a first-time create's link is also
    // durable.
    file.flush()?;
    file.sync_all()?;
    crate::util::fsync_parent_dir_logged(store, "canary store");
    Ok(())
}

/// One physical store line: a parsed [`CanaryEntry`] or a raw unparseable line.
/// `prune`/`rotate` carry unparseable lines (future schema, transient hiccup)
/// THROUGH the rewrite VERBATIM rather than dropping them — that would be
/// permanent data loss (CodeRabbit R12 #F).
enum StoreLine {
    Parsed(CanaryEntry),
    Unparseable(String),
}

/// Read the store as ordered [`StoreLine`]s, preserving unparseable lines for
/// rewrite. `complete == false` (CodeRabbit R13 #1) means the read broke early
/// on a mid-file fault, so `lines` is truncated — `prune`/`rotate` must abort
/// rather than rewrite (which would drop the tail).
fn read_store_partitioned(path: &Path) -> (Vec<StoreLine>, bool) {
    // RAW (untrimmed) read (CodeRabbit R15 #3): an unparseable line is written
    // back verbatim, so it must retain its surrounding whitespace.
    let (lines, complete) = crate::util::read_store_lines_raw_complete(path);
    let parsed = lines
        .into_iter()
        .map(|line| match serde_json::from_str::<CanaryEntry>(&line) {
            Ok(entry) => StoreLine::Parsed(entry),
            Err(_) => StoreLine::Unparseable(line),
        })
        .collect();
    (parsed, complete)
}

/// Atomically rewrite the store to the given pre-serialized JSONL `lines`
/// (temp-file + rename, so a crash mid-write never truncates it).
fn rewrite_store_lines(store: &Path, lines: &[String]) -> std::io::Result<()> {
    // Resolve a symlink so the rewrite writes THROUGH it, not over it
    // (CodeRabbit R13b).
    let dest = crate::util::resolve_symlink_target(store);
    if let Some(parent) = dest.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let dir = dest.parent().unwrap_or_else(|| Path::new("."));
    let mut tmp = tempfile::NamedTempFile::new_in(dir)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        tmp.as_file()
            .set_permissions(std::fs::Permissions::from_mode(0o600))?;
    }
    for line in lines {
        writeln!(tmp, "{line}")?;
    }
    // Durability: fsync the temp body BEFORE the rename, else a crash could
    // leave the store renamed into place holding zero/garbage bytes.
    tmp.flush()?;
    tmp.as_file().sync_all()?;
    tmp.persist(&dest).map_err(|e| e.error)?;
    // Make the rename durable too (CodeRabbit R9 #B): fsync the parent dir.
    // Body+rename already succeeded, so a dir-fsync failure is logged (R13 #5).
    crate::util::fsync_parent_dir_logged(&dest, "canary store");
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
    // Normalize the callback URL HERE (single point for every caller): trim and
    // collapse a blank-after-trim value to `None`, so the store can't claim a
    // callback that `fire_callback` would trim away and no-op.
    let callback_url = callback_url.and_then(|u| {
        let t = u.trim();
        if t.is_empty() {
            None
        } else {
            Some(t.to_string())
        }
    });
    let entry = CanaryEntry {
        id: new_id(),
        token: generate_token(kind),
        kind: kind.as_str().to_string(),
        created_at: chrono::Utc::now().to_rfc3339(),
        callback_url,
    };
    // Lock across the append so a concurrent prune/rotate can't drop this entry.
    let _lock = StoreLock::acquire(store)?;
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

/// List every recorded canary in `store`, file order. A display path: returns
/// the partial prefix on an incomplete read — the DETECTION path ([`detect_at`])
/// is the one that surfaces incompleteness (CodeRabbit R16 #3).
pub fn list_at(store: &Path) -> Vec<CanaryEntry> {
    parse_store(store).0
}

/// Like [`list_at`] but also reports `complete`. `false` (unreadable/truncated
/// store) means an "empty" result is NOT proof the store is empty (CodeRabbit
/// R17 #2) — CLI `prune` uses this so it can't mistake an unreadable store for
/// "nothing to prune". An ABSENT store returns `(vec![], true)`.
pub fn list_at_complete(store: &Path) -> (Vec<CanaryEntry>, bool) {
    parse_store(store)
}

/// Production entry point: list every recorded canary in the default store.
pub fn list() -> Vec<CanaryEntry> {
    match store_path() {
        Some(p) => list_at(&p),
        None => Vec::new(),
    }
}

/// [`list_at_complete`] against the default store. An unresolvable store path is
/// `complete == false` (not a proven-empty store) so the CLI doesn't report a
/// false "nothing to prune".
pub fn list_complete() -> (Vec<CanaryEntry>, bool) {
    match store_path() {
        Some(p) => list_at_complete(&p),
        None => (Vec::new(), false),
    }
}

/// Remove the canary with `id` from the store at `store`. Returns the number of
/// entries removed (0 when the id is unknown).
pub fn prune_at(store: &Path, id: &str) -> std::io::Result<usize> {
    // Lock across the whole read-modify-write (no concurrent update slips in).
    let _lock = StoreLock::acquire(store)?;
    // RAW lines (CodeRabbit R12 #F): drop only the matching parsed entry; carry
    // every other line through verbatim so prune never loses data. Partial-read
    // guard (R13 #1): a truncated prefix must abort, not drive a rewrite that
    // drops the tail.
    let (lines, complete) = read_store_partitioned(store);
    if !complete {
        return Err(std::io::Error::other(
            "canary store could not be read completely; prune aborted to avoid truncating it",
        ));
    }
    let mut removed = 0usize;
    let mut kept_lines: Vec<String> = Vec::new();
    for sl in lines {
        match sl {
            StoreLine::Parsed(entry) if entry.id == id => removed += 1,
            StoreLine::Parsed(entry) => {
                kept_lines.push(serde_json::to_string(&entry).map_err(std::io::Error::other)?);
            }
            StoreLine::Unparseable(line) => kept_lines.push(line),
        }
    }
    if removed == 0 {
        return Ok(0);
    }
    rewrite_store_lines(store, &kept_lines)?;
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
    // Lock across the whole read-modify-write (see `prune_at`).
    let _lock = StoreLock::acquire(store)?;
    // RAW lines (CodeRabbit R12 #F): mutate only the matching parsed entry,
    // preserve every other line verbatim. Partial-read guard (R13 #1): a
    // truncated prefix must abort before a rewrite that drops the tail.
    let (lines, complete) = read_store_partitioned(store);
    if !complete {
        return Err(std::io::Error::other(
            "canary store could not be read completely; rotate aborted to avoid truncating it",
        ));
    }
    if !lines
        .iter()
        .any(|sl| matches!(sl, StoreLine::Parsed(e) if e.id == id))
    {
        return Ok(None);
    }
    let mut updated: Option<CanaryEntry> = None;
    let mut out_lines: Vec<String> = Vec::with_capacity(lines.len());
    for sl in lines {
        match sl {
            // Rotate only the FIRST matching entry; later id-duplicates are
            // preserved unchanged (ids are unique in practice).
            StoreLine::Parsed(mut entry) if entry.id == id && updated.is_none() => {
                // FAIL SAFE on an unknown `kind` (CodeRabbit R13 #A): an entry
                // from a NEWER binary parses as valid JSON but `parse` returns
                // None. Defaulting would mint a wrong-shaped token over the
                // original kind string, so abort instead (store not rewritten).
                let kind = CanaryKind::parse(&entry.kind).ok_or_else(|| {
                    std::io::Error::other(format!(
                        "cannot rotate canary `{}`: unknown kind `{}` (written by a newer tirith?)",
                        entry.id, entry.kind
                    ))
                })?;
                entry.token = generate_token(kind);
                entry.created_at = chrono::Utc::now().to_rfc3339();
                updated = Some(entry.clone());
                out_lines.push(serde_json::to_string(&entry).map_err(std::io::Error::other)?);
            }
            StoreLine::Parsed(entry) => {
                out_lines.push(serde_json::to_string(&entry).map_err(std::io::Error::other)?);
            }
            StoreLine::Unparseable(line) => out_lines.push(line),
        }
    }
    rewrite_store_lines(store, &out_lines)?;
    invalidate_cache();
    Ok(updated)
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

/// `true` when `store` exists and is non-empty — the engine's cheap (stat-only)
/// gate for whether to force past the tier-1 fast-exit for the canary scan.
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

/// Scan `text` against every registered canary, returning one [`CanaryHit`] per
/// matching canary, DEDUPED BY ID (a token twice, or a duplicate store id, fires
/// once — never the callback twice). Substring match, so a canary planted in a
/// larger blob still fires.
pub fn detect_at(store: &Path, text: &str) -> Vec<CanaryHit> {
    if text.is_empty() {
        return Vec::new();
    }
    let (entries, complete) = cached_entries(store);
    let mut hits = Vec::new();
    let mut seen_ids: std::collections::HashSet<String> = std::collections::HashSet::new();
    for e in entries {
        // An empty token would `contains`-match everything; skip defensively.
        if e.token.is_empty() {
            continue;
        }
        if text.contains(&e.token) {
            // Dedup by id (first match wins) so a duplicate id fires once.
            if seen_ids.insert(e.id.clone()) {
                hits.push(CanaryHit {
                    id: e.id,
                    kind: e.kind,
                    callback_url: e.callback_url,
                });
            }
        }
    }
    // FAIL-SAFE ON A TRUNCATED READ (CodeRabbit R16 #3): a canary in the unread
    // tail would read as untouched (fail-OPEN). We can't synthesize a hit, so
    // surface the incompleteness via a rate-limited stderr diagnostic. A
    // prefix match still fires; an InvalidData skip keeps `complete == true`.
    if !complete {
        warn_incomplete_store_once(store);
    }
    hits
}

/// One-line stderr diagnostic for a scan against an incompletely-read store,
/// deduped per `(path, mtime)` so the 5s-cache hot path doesn't spam. The
/// canary fail-safe, since a scan can't synthesize a hit (CodeRabbit R16 #3).
fn warn_incomplete_store_once(store: &Path) {
    static LAST_WARNED: Mutex<Option<(PathBuf, u128)>> = Mutex::new(None);
    let mtime = mtime_nanos(store);
    let mut guard = LAST_WARNED.lock().unwrap_or_else(|e| e.into_inner());
    let key = (store.to_path_buf(), mtime);
    if guard.as_ref() == Some(&key) {
        return;
    }
    *guard = Some(key);
    // Write fallibly so a closed/broken stderr can't panic this (CodeRabbit
    // R22 #4 — `eprintln!` panics on a write error).
    let _ = writeln!(
        std::io::stderr(),
        "tirith: warning: canary store {} could not be read completely; \
         a planted canary may not have been checked",
        store.display()
    );
}

/// Production entry point: scan `text` against the default store.
pub fn detect(text: &str) -> Vec<CanaryHit> {
    match store_path() {
        Some(p) => detect_at(&p, text),
        None => Vec::new(),
    }
}

/// Fire the OPT-IN, best-effort detection callback: ONE POST to
/// `hit.callback_url` (when set) of `{kind, detected_at, context}` — NEVER the
/// token value (it is deliberately not a parameter). The single network path
/// the feature can take. Fire-and-forget and fail-open: no URL → no-op; the
/// POST runs on a DETACHED thread (1.5s connect / 3s total) so the verdict
/// never waits; any error is logged and swallowed.
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

    // Keep an `id` copy on this side of the move so a spawn failure can still be
    // audited (the closure consumes `id`).
    let id_for_spawn_failure = id.clone();
    // Detached, not joined — the verdict never waits on the network.
    let spawn_result = std::thread::Builder::new()
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
                Err(_e) => {
                    log_callback_failure(&id, "client build failed");
                    return;
                }
            };

            match client.post(&url).json(&body).send() {
                Ok(resp) if resp.status().is_success() => {}
                Ok(resp) => {
                    // Numeric status only — never the URL.
                    log_callback_failure(
                        &id,
                        &format!("callback returned HTTP {}", resp.status().as_u16()),
                    );
                }
                Err(e) => {
                    // CRITICAL: a `reqwest::Error`'s Display embeds the (operator-
                    // private) URL, so classify to a coarse, URL-free reason
                    // instead of logging it raw.
                    log_callback_failure(&id, classify_callback_error(&e));
                }
            }
        });

    // A spawn failure dropped the callback — route it through the same audit
    // sink with a coarse, URL-free reason.
    if spawn_result.is_err() {
        log_callback_failure(&id_for_spawn_failure, "callback worker spawn failed");
    }
}

/// Map a `reqwest` send error to a coarse, URL-free reason category (the raw
/// `Display` embeds the operator-private URL and must never reach the log).
fn classify_callback_error(e: &reqwest::Error) -> &'static str {
    if e.is_timeout() {
        "callback POST failed: timeout"
    } else if e.is_connect() {
        "callback POST failed: connection error"
    } else if e.is_redirect() {
        "callback POST failed: too many redirects"
    } else if e.is_body() {
        "callback POST failed: request body error"
    } else if e.is_request() {
        "callback POST failed: request error"
    } else {
        "callback POST failed: network error"
    }
}

/// Log a canary-callback failure to the audit log (hook-telemetry shape,
/// `integration = "canary"`). Records the id only — never the token or URL.
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

    /// Make a FIFO at `path` (unix). Returns false if mkfifo is unsupported here.
    #[cfg(unix)]
    fn mkfifo_at(path: &Path) -> bool {
        use std::ffi::CString;
        let c_path = CString::new(path.as_os_str().to_str().unwrap()).unwrap();
        unsafe { libc::mkfifo(c_path.as_ptr(), 0o600) == 0 }
    }

    /// CodeRabbit R13 #1: a store whose read doesn't complete (here a FIFO) must
    /// ABORT prune/rotate, not rewrite from the partial image (which would
    /// truncate). The store is left as-is. Unix-only; can't hang (O_NONBLOCK).
    #[cfg(unix)]
    #[test]
    fn prune_and_rotate_abort_on_incomplete_read_no_truncation() {
        use std::os::unix::fs::FileTypeExt;
        let dir = tempdir().unwrap();
        let store = store_in(dir.path());
        if !mkfifo_at(&store) {
            eprintln!("skipping: mkfifo unsupported here");
            return;
        }
        // prune must abort with an error and leave the FIFO intact.
        let pruned = prune_at(&store, "deadbeef0000");
        assert!(
            pruned.is_err(),
            "prune on an unreadable store must abort, not silently rewrite"
        );
        assert!(
            std::fs::symlink_metadata(&store)
                .unwrap()
                .file_type()
                .is_fifo(),
            "the store must NOT be replaced by a regular file (no truncating rewrite)"
        );
        // rotate must likewise abort and leave the FIFO intact.
        let rotated = rotate_at(&store, "deadbeef0000");
        assert!(
            rotated.is_err(),
            "rotate on an unreadable store must abort, not silently rewrite"
        );
        assert!(
            std::fs::symlink_metadata(&store)
                .unwrap()
                .file_type()
                .is_fifo(),
            "the store must NOT be replaced by a regular file (no truncating rewrite)"
        );
    }

    /// CodeRabbit R16 #3: a store whose read doesn't complete (here a FIFO) must
    /// be flagged `complete == false` so `detect_at` surfaces it rather than
    /// treating a planted canary as untouched. Asserts the read reports
    /// incomplete and `detect_at` returns promptly. Unix-only; can't hang.
    #[cfg(unix)]
    #[test]
    fn detect_surfaces_incomplete_read_not_silent_clean() {
        let dir = tempdir().unwrap();
        let store = store_in(dir.path());
        if !mkfifo_at(&store) {
            eprintln!("skipping: mkfifo unsupported here");
            return;
        }
        invalidate_cache();

        // The read is reported INCOMPLETE for the unreadable FIFO store — this is
        // the signal `detect_at` keys on to fail safe (warn) instead of silently
        // returning "no canaries touched".
        let (_entries, complete) = cached_entries(&store);
        assert!(
            !complete,
            "an unreadable (FIFO) store must report complete == false"
        );

        // detect_at must return promptly (a blocking read would hang here) and not
        // panic; it emits the fail-safe diagnostic on the incomplete read.
        invalidate_cache();
        let _hits = detect_at(&store, "some text that could contain a canary");
    }

    #[test]
    fn aws_like_token_is_clearly_synthetic() {
        let tok = generate_token(CanaryKind::AwsLike);
        assert!(tok.starts_with("AKIA00CANARY"), "got {tok}");
        // The `00CANARY` marker is the load-bearing "clearly-synthetic" property.
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
    fn getrandom_fallback_bytes_vary_per_call() {
        // CodeRabbit R9 #H: the fallback must not be deterministic (the old code
        // cycled the same head, repeating `new_id()`s). The counter advances, so
        // two consecutive fills differ.
        let mut a = [0u8; 64];
        let mut b = [0u8; 64];
        fill_fallback_bytes(&mut a);
        fill_fallback_bytes(&mut b);
        assert_ne!(
            a, b,
            "two fallback fills in the same process must differ (counter advances)"
        );

        // And the alphabet-mapped IDs derived from successive fallback buffers
        // differ too — i.e. the collision `new_id` would have produced is gone.
        let id_from = |buf: &[u8; 64]| -> String {
            let len = HEX.len();
            let limit = (256 / len) * len;
            buf.iter()
                .filter(|&&x| (x as usize) < limit)
                .take(12)
                .map(|&x| HEX[(x as usize) % len] as char)
                .collect()
        };
        let mut c = [0u8; 64];
        let mut d = [0u8; 64];
        fill_fallback_bytes(&mut c);
        fill_fallback_bytes(&mut d);
        assert_ne!(
            id_from(&c),
            id_from(&d),
            "successive fallback-derived ids must not collide"
        );
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
    fn create_normalizes_blank_callback_url_to_none() {
        // CodeRabbit R6 #8: a whitespace-only callback URL persists as `None`, so
        // the on-disk record can't claim a callback that runtime would no-op.
        // `create_at` is the single normalization point.
        let dir = tempdir().unwrap();
        let store = store_in(dir.path());

        let entry = create_at(&store, CanaryKind::GithubLike, Some("   ".to_string())).unwrap();
        assert!(
            entry.callback_url.is_none(),
            "a blank-after-trim callback URL must normalize to None, got {:?}",
            entry.callback_url
        );
        // And it must be persisted as None too (read straight from disk, not the
        // in-process cache).
        let on_disk = parse_store(&store).0;
        assert_eq!(on_disk.len(), 1);
        assert!(on_disk[0].callback_url.is_none());

        // A real URL with surrounding whitespace is trimmed (not dropped).
        let entry2 = create_at(
            &store,
            CanaryKind::GithubLike,
            Some("  https://example.com/cb  ".to_string()),
        )
        .unwrap();
        assert_eq!(
            entry2.callback_url.as_deref(),
            Some("https://example.com/cb")
        );
    }

    /// Durability regression (CodeRabbit/Greptile R4 #1): each mutator flushes +
    /// `sync_all()` before Ok. A unit test can't observe the fsync barrier, so
    /// this asserts the precondition: after each mutator the content is readable
    /// straight from disk (via `parse_store`, not the cache). Fsyncs live in
    /// `append_entry` and `rewrite_store_lines`.
    #[test]
    fn mutators_persist_durably_to_disk() {
        let dir = tempdir().unwrap();
        let store = store_in(dir.path());

        // create → the appended line is on disk and round-trips.
        let a = create_at(&store, CanaryKind::AwsLike, None).unwrap();
        let b = create_at(&store, CanaryKind::GithubLike, None).unwrap();
        let on_disk = parse_store(&store).0;
        assert_eq!(on_disk.len(), 2, "both created entries must be on disk");
        assert!(on_disk.iter().any(|e| e.id == a.id && e.token == a.token));
        assert!(on_disk.iter().any(|e| e.id == b.id && e.token == b.token));

        // prune → the rewritten (synced) store is on disk with exactly the kept
        // entry; the pruned id is gone.
        assert_eq!(prune_at(&store, &a.id).unwrap(), 1);
        let on_disk = parse_store(&store).0;
        assert_eq!(on_disk.len(), 1, "prune must durably rewrite the store");
        assert_eq!(on_disk[0].id, b.id);

        // rotate → the rewritten (synced) store carries the fresh token for the
        // same id; the old token is gone from disk.
        let rotated = rotate_at(&store, &b.id).unwrap().expect("known id");
        assert_ne!(rotated.token, b.token, "rotate must regenerate the token");
        let on_disk = parse_store(&store).0;
        assert_eq!(on_disk.len(), 1);
        assert_eq!(on_disk[0].id, b.id);
        assert_eq!(
            on_disk[0].token, rotated.token,
            "rotated token must be the one durably written to disk"
        );
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
    fn detect_dedups_duplicate_id_store_entries() {
        // P2: two store lines can share an id (hand-edited store); both matching
        // must yield ONE hit, never firing the opt-in callback twice.
        let dir = tempdir().unwrap();
        let store = store_in(dir.path());
        std::fs::write(
            &store,
            "{\"id\":\"dup\",\"token\":\"ghp_canary_aaa\",\"kind\":\"github-like\",\"created_at\":\"t\"}\n\
             {\"id\":\"dup\",\"token\":\"ghp_canary_bbb\",\"kind\":\"github-like\",\"created_at\":\"t\"}\n",
        )
        .unwrap();
        let hits = detect_at(&store, "ghp_canary_aaa and ghp_canary_bbb");
        assert_eq!(hits.len(), 1, "duplicate id must dedup to a single hit");
        assert_eq!(hits[0].id, "dup");
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

    /// Append a future-schema line the lenient reader skips; returns the line.
    fn append_unparseable_line(store: &Path) -> String {
        let unknown = r#"{"schema":"v2","id":"future","token":"x","kind":"brand-new-kind"}"#;
        use std::io::Write as _;
        let mut f = std::fs::OpenOptions::new()
            .append(true)
            .open(store)
            .unwrap();
        writeln!(f, "{unknown}").unwrap();
        invalidate_cache();
        unknown.to_string()
    }

    #[test]
    fn prune_preserves_unparseable_lines_on_rewrite() {
        // CodeRabbit R12 #F: prune's rewrite must not drop a line the reader
        // skips. Prune one of two canaries; the unknown line survives on disk.
        let dir = tempdir().unwrap();
        let store = store_in(dir.path());
        let a = create_at(&store, CanaryKind::AwsLike, None).unwrap();
        let b = create_at(&store, CanaryKind::GithubLike, None).unwrap();
        let unknown = append_unparseable_line(&store);
        assert_eq!(
            parse_store(&store).0.len(),
            2,
            "reader skips the unknown line"
        );

        assert_eq!(prune_at(&store, &a.id).unwrap(), 1);
        // The surviving canary is still present, the unknown line preserved.
        assert_eq!(list_at(&store).len(), 1);
        assert_eq!(list_at(&store)[0].id, b.id);
        let on_disk = std::fs::read_to_string(&store).unwrap();
        assert!(
            on_disk.contains(&unknown),
            "prune must preserve the unparseable line, got:\n{on_disk}"
        );
    }

    #[test]
    fn rotate_preserves_unparseable_lines_on_rewrite() {
        // CodeRabbit R12 #F: rotate's rewrite must not drop a skipped line.
        let dir = tempdir().unwrap();
        let store = store_in(dir.path());
        let original = create_at(&store, CanaryKind::GithubLike, None).unwrap();
        let unknown = append_unparseable_line(&store);

        let rotated = rotate_at(&store, &original.id).unwrap().expect("known id");
        assert_ne!(rotated.token, original.token, "token rotated");
        let on_disk = std::fs::read_to_string(&store).unwrap();
        assert!(
            on_disk.contains(&unknown),
            "rotate must preserve the unparseable line, got:\n{on_disk}"
        );
        // The rotated entry is still readable and the new token fires.
        assert_eq!(list_at(&store).len(), 1);
        assert_eq!(detect_at(&store, &rotated.token).len(), 1);
    }

    #[test]
    fn rotate_unknown_kind_fails_safe_without_corrupting() {
        // CodeRabbit R13 #A: a future-`kind` entry parses as a valid CanaryEntry
        // (not unparseable); rotating it must fail safe and leave the store
        // untouched, not mint a wrong-shaped token over the unknown kind.
        let dir = tempdir().unwrap();
        let store = store_in(dir.path());
        // A fully-valid CanaryEntry whose `kind` is a future/unknown string.
        let future = r#"{"id":"future1","token":"sk_canary_future_abc","kind":"slack-like","created_at":"2026-01-01T00:00:00Z","callback_url":null}"#;
        {
            use std::io::Write as _;
            let mut f = std::fs::File::create(&store).unwrap();
            writeln!(f, "{future}").unwrap();
            invalidate_cache();
        }
        // It parses (so rotate reaches the kind check), confirming the precondition.
        assert_eq!(
            list_at(&store).len(),
            1,
            "future-kind entry parses as valid"
        );

        let before = std::fs::read_to_string(&store).unwrap();
        let err = rotate_at(&store, "future1").expect_err("unknown kind must fail safe");
        assert!(
            err.to_string().contains("unknown kind"),
            "error should name the unknown kind, got: {err}"
        );
        // The store is byte-for-byte unchanged: no token rewrite, no corruption.
        let after = std::fs::read_to_string(&store).unwrap();
        assert_eq!(before, after, "a failed rotate must not rewrite the store");
        assert!(
            after.contains("sk_canary_future_abc") && after.contains("slack-like"),
            "the original future-kind entry survives verbatim, got:\n{after}"
        );
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
    fn sequential_locked_mutations_each_persist_and_release_lock() {
        // F2 (Major): proves the lock is RELEASED between calls (a held lock
        // would deadlock the next acquire) and each mutation persists.
        let dir = tempdir().unwrap();
        let store = store_in(dir.path());

        let a = create_at(&store, CanaryKind::AwsLike, None).unwrap();
        // If the first create's lock were never released, this second acquire
        // would block forever; reaching the assert proves release.
        let b = create_at(&store, CanaryKind::GithubLike, None).unwrap();
        assert_eq!(list_at(&store).len(), 2, "both creates persisted");

        // A prune (its own read-modify-write under the lock) also acquires and
        // releases cleanly, and its effect persists.
        assert_eq!(prune_at(&store, &a.id).unwrap(), 1);
        let remaining = list_at(&store);
        assert_eq!(remaining.len(), 1, "prune persisted after the creates");
        assert_eq!(remaining[0].id, b.id);

        // The sibling lock file exists (left in place between calls) but the
        // lock itself is free: another acquire returns immediately.
        assert!(lock_path_for(&store).exists(), "lock sentinel persists");
        let _g = StoreLock::acquire(&store).expect("lock is free to re-acquire");
    }

    #[test]
    fn acquire_proceeds_on_supported_lock_and_persists() {
        // F1 (Major): the happy (supported-lock) path returns Ok and holds a real
        // lock across the write — not an unlocked best-effort handle.
        let dir = tempdir().unwrap();
        let store = store_in(dir.path());
        {
            let _g = StoreLock::acquire(&store).expect("supported-lock acquire succeeds");
            assert!(lock_path_for(&store).exists(), "lock sentinel created");
        }
        // After release the guarded mutator persists, confirming a real lock.
        create_at(&store, CanaryKind::AwsLike, None).unwrap();
        assert!(
            store_nonempty_at(&store),
            "mutation under a real lock persists"
        );
    }

    #[test]
    fn acquire_propagates_non_unsupported_io_errors() {
        // F1 (Major): only `Unsupported` is best-effort; any other I/O failure
        // must propagate. Force it cross-platform by placing the store under a
        // regular file, so `create_dir_all(parent)` inside `acquire` fails.
        let dir = tempdir().unwrap();
        let blocker = dir.path().join("not-a-dir");
        std::fs::write(&blocker, b"x").unwrap();
        let store = blocker.join("canaries.jsonl");
        // `StoreLock` is not `Debug`, so match instead of `expect_err`.
        match StoreLock::acquire(&store) {
            Ok(_) => panic!("acquire must fail when the store's parent cannot be created"),
            Err(err) => {
                // A real error (OS-dependent kind), not a bogus unlocked guard.
                assert_ne!(
                    err.kind(),
                    std::io::ErrorKind::Unsupported,
                    "this fixture exercises the NON-Unsupported (propagated) branch"
                );
            }
        }
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
        // F3 (Sev-5): a bad-UTF-8 line skips only THAT line; entries after it
        // still load. The old `map_while(Result::ok)` stopped at the first Err.
        let dir = tempdir().unwrap();
        let store = store_in(dir.path());

        // valid entry, then an invalid-UTF-8 line, then a second valid entry.
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

    #[test]
    fn callback_error_reason_never_contains_the_url_or_host() {
        // CRITICAL (finding D): the audit reason must not embed the
        // operator-private URL/host. Provoke a real send error and assert the
        // classified reason is a coarse category only.
        let unique_host = "canary-secret-endpoint.invalid";
        let url = format!("http://{unique_host}:9/callback");
        let client = reqwest::blocking::Client::builder()
            .connect_timeout(Duration::from_millis(200))
            .timeout(Duration::from_millis(400))
            .build()
            .expect("client build");

        // `.invalid` is reserved (RFC 6761) and never resolves, so this is a
        // deterministic connect/request failure with no real network access.
        let err = client
            .post(&url)
            .json(&serde_json::json!({"k": "v"}))
            .send()
            .expect_err("a POST to a .invalid host must fail");

        let reason = classify_callback_error(&err);
        assert!(
            !reason.contains(unique_host),
            "classified reason must not contain the callback host; got: {reason}"
        );
        assert!(
            !reason.contains("://") && !reason.contains("/callback"),
            "classified reason must not contain any URL fragment; got: {reason}"
        );
        assert!(
            reason.starts_with("callback POST failed: "),
            "classified reason must be a coarse category string; got: {reason}"
        );
    }
}
