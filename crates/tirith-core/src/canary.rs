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
//! verdict. See [`fire_callback`].
//!
//! # Clearly-synthetic token shapes
//!
//! Every generated token carries a literal, obviously-fake marker so a flagged
//! value reads as tirith bait rather than a real third-party credential
//! (reducing the chance it triggers an external provider's abuse / take-down
//! workflow), while still matching tirith's own credential-shape detection:
//!
//! | kind                 | shape                                           |
//! |----------------------|-------------------------------------------------|
//! | `aws-like`           | `AKIA00CANARY` + 8 base32-ish chars             |
//! | `github-like`        | `ghp_canary_` + 30 alphanumerics                |
//! | `gcp-like`           | `AIzaCANARY` + 30 url-safe chars                |
//! | `env-line`           | `TIRITH_CANARY_TOKEN=canary_` + 24 hex          |
//! | `private-key-shaped` | a PEM block whose body is `TIRITHCANARY...`     |
//!
//! The `AKIA00CANARY` infix keeps the recognizable `AKIA` prefix while the
//! explicit `00CANARY` marker makes the token clearly synthetic, so it is
//! unlikely to be mistaken for a genuine key. The `ghp_canary_` / `AIzaCANARY`
//! / `canary_` markers serve the same clearly-synthetic purpose for the other
//! kinds. A developer who spots the token can tell it is a tirith canary, not a
//! real leak. This is a clearly-labelled property, not a mathematical
//! impossibility claim — see `docs/canary-formats.md`.
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

use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};

/// The synthetic token kinds `tirith canary create <kind>` understands.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CanaryKind {
    /// `AKIA00CANARY` + random — AWS-access-key-shaped, with an explicit
    /// `00CANARY` marker that keeps the token clearly synthetic.
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
        // AWS access keys look like `AKIA` + 16 chars. We keep the recognizable
        // `AKIA` prefix, then embed an explicit `00CANARY` marker so the token
        // is clearly synthetic (reducing the chance it's mistaken for a real
        // key); the suffix uses a base32-style alphabet purely for shape.
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
/// fall back to a per-call-VARYING pseudo-random suffix (see
/// [`fill_fallback_bytes`]) so token generation never panics AND two calls in
/// the same process don't collide — a generated token is still clearly
/// synthetic regardless (CodeRabbit R9 #H).
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
            // Entropy unavailable — extremely rare. Fill a fresh buffer from a
            // per-CALL-varying source (process-lifetime counter + time) so the
            // remaining bytes differ on every call rather than cycling the same
            // alphabet head deterministically (which made `new_id` repeat IDs).
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
            // `fill_fallback_bytes` advances its counter each call, so the loop
            // makes progress and terminates; but guard against an alphabet whose
            // `limit` rejects this particular buffer entirely by drawing again on
            // the next `while` iteration (getrandom will be retried first).
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
/// when the OS CSPRNG (`getrandom`) is unavailable (CodeRabbit R9 #H). The seed
/// mixes a process-lifetime monotonic counter (so two calls in the same process
/// differ even at the same instant) with the wall-clock nanos (so it also
/// differs across processes/restarts), expanded with SplitMix64.
///
/// This is NOT a cryptographic RNG and makes no unguessability claim — the
/// fallback only needs to produce DISTINCT, well-formed synthetic tokens so
/// repeated `new_id()` calls cannot collide. The CSPRNG path above is the one
/// that carries the security property; this branch is the panic-free degradation.
fn fill_fallback_bytes(buf: &mut [u8; 64]) {
    use std::sync::atomic::{AtomicU64, Ordering};
    static COUNTER: AtomicU64 = AtomicU64::new(0);

    let counter = COUNTER.fetch_add(1, Ordering::Relaxed);
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0);
    // Distinct per call (counter) and per wall-clock instant (nanos).
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

/// Per-process cache of the parsed store, keyed on the resolved store path.
/// Mirrors [`crate::taint`]'s cache exactly so the hot path stays cheap.
struct CacheState {
    path: PathBuf,
    entries: Vec<CanaryEntry>,
    /// Whether the underlying store read reached EOF cleanly. `false` means a
    /// persistent mid-file I/O fault (or a present-but-unreadable store) left the
    /// tail unread, so `entries` is a PARTIAL prefix — a touched canary in the
    /// unread tail would otherwise read as untouched (fail-OPEN). `detect_at`
    /// surfaces the incompleteness on a miss (CodeRabbit R16 #3).
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
fn parse_store(path: &Path) -> (Vec<CanaryEntry>, bool) {
    // `read_store_lines_complete` skips blank lines, skips a single recoverable
    // invalid-UTF-8 line (so a corrupt byte cannot hide later canaries), and
    // BREAKS on any other (persistent) read error — reporting `complete == false`
    // — so the reader cannot spin forever and a truncated read is observable.
    // Lines that don't parse as a `CanaryEntry` are dropped (fail-open). An
    // InvalidData line skip is NOT a truncation (the file is still read to EOF),
    // so `complete` stays `true` for it.
    let (lines, complete) = crate::util::read_store_lines_complete(path);
    let entries = lines
        .iter()
        .filter_map(|line| serde_json::from_str::<CanaryEntry>(line).ok())
        .collect();
    (entries, complete)
}

/// Load entries through the per-process cache. Reloads when the cached path
/// differs, the TTL expired, or the store's mtime changed. Returns
/// `(entries, complete)` — `complete == false` flags a partial/truncated read so
/// `detect_at` can surface the incompleteness on a miss (CodeRabbit R16 #3).
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

/// Drop the per-process cache. Tests that write a store directly then assert via
/// the default-path API call this so a stale earlier load is not reused.
pub fn invalidate_cache() {
    let mut guard = CACHE.lock().unwrap_or_else(|e| e.into_inner());
    *guard = None;
}

/// An exclusive cross-process advisory lock on a sibling `<store>.lock` file,
/// released on drop. All three store mutators (`create_at`, `prune_at`,
/// `rotate_at`) hold this for the duration of their read-modify-write so two
/// concurrent commands cannot lose each other's updates: e.g. a `create`
/// appending while a `prune` rewrites the store from a now-stale snapshot would
/// otherwise silently drop the freshly-created entry. Reads (`list`/`detect`)
/// are deliberately NOT locked — they tolerate a torn view because
/// [`rewrite_store_lines`] swaps the file in atomically (rename), so a reader always
/// sees a whole prior or whole next file, never a partial one.
///
/// Uses the same `fs2::FileExt` advisory locking as `audit.rs` /
/// `session_warnings.rs`. The `.lock` file is a zero-byte sentinel: never read
/// or written, only locked, and left in place between calls (creating and
/// deleting it per-call would itself race).
struct StoreLock {
    file: std::fs::File,
}

impl StoreLock {
    /// Acquire the exclusive lock guarding `store`. Creates parent dirs and the
    /// sibling lock file as needed, then blocks until the lock is held. If
    /// advisory locking is unsupported on the platform/filesystem we proceed
    /// WITHOUT it (best-effort — never worse than the pre-lock behavior, and the
    /// atomic rename in [`rewrite_store_lines`] still prevents torn files).
    fn acquire(store: &Path) -> std::io::Result<Self> {
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
        // Blocking exclusive lock. Only an `Unsupported` error (advisory locking
        // not available on this platform/filesystem) is treated as best-effort:
        // we proceed UNLOCKED, relying on the atomic rename in [`rewrite_store_lines`]
        // to still prevent torn files. ANY OTHER lock error (EINTR-after-retry,
        // EDEADLK, ENOLCK, …) must fail loudly so the mutation aborts rather than
        // racing without the serialization guarantee — mirroring how `audit.rs`
        // hard-fails on a lock error instead of writing unlocked.
        if let Err(e) = file.lock_exclusive() {
            if e.kind() != std::io::ErrorKind::Unsupported {
                return Err(e);
            }
            // Unsupported blocking lock: best-effort. Try once more (non-blocking)
            // in case the backend supports try-locking — if that SUCCEEDS we hold
            // the lock (released by `Drop`). A non-`Unsupported` error here is still
            // a real lock failure and must fail loudly (CodeRabbit R13e), per the
            // "only Unsupported → unlocked" contract above; only a SECOND
            // `Unsupported` degrades to running unlocked.
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
    // `OpenOptionsExt::mode` above applies ONLY when the file is freshly created.
    // If `canaries.jsonl` already exists with wider permissions (created under a
    // looser umask, or by an older build), narrow it to 0600 BEFORE appending the
    // token + callback data, which are sensitive (CodeRabbit R13b). Best-effort on
    // the open handle; failure to chmod is surfaced like any other write error.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        file.set_permissions(std::fs::Permissions::from_mode(0o600))?;
    }
    let line = serde_json::to_string(entry).map_err(std::io::Error::other)?;
    writeln!(file, "{line}")?;
    // Durability: a buffered append that returns Ok before the bytes reach
    // stable storage can be lost on a crash/power-loss, leaving a registered
    // canary that never fires. Flush our user-space writer, then fsync the file
    // so the appended line survives. `flush()` is a no-op for `std::fs::File`
    // (it has no user-space buffer) but is correct and cheap if the writer type
    // ever changes; `sync_all()` is the load-bearing barrier.
    file.flush()?;
    file.sync_all()?;
    // `sync_all` persists the file's contents + inode, but NOT the parent
    // directory entry that names it. On a FIRST-TIME create a crash could
    // otherwise lose the link to `canaries.jsonl` even though `create_at`
    // returned Ok — the same "registered canary that never fires" failure the
    // content fsync above guards against. Fsync the parent dir too (best-effort,
    // logged; a no-op-ish cost on the rare subsequent appends). Mirrors the
    // durable-publish pattern used by the card/incident writers.
    crate::util::fsync_parent_dir_logged(store, "canary store");
    Ok(())
}

/// One physical line of the canary store: either a successfully-parsed
/// [`CanaryEntry`] or a raw line that did NOT parse as one.
///
/// `prune`/`rotate` read the store through [`read_store_partitioned`] so an
/// unparseable line (a future schema field, a transient hiccup) is carried
/// THROUGH the rewrite VERBATIM rather than silently dropped (CodeRabbit R12
/// #F): the fail-open reader skipping a line for a hot-path lookup is correct,
/// but dropping it on a compaction rewrite would be permanent data loss.
enum StoreLine {
    Parsed(CanaryEntry),
    Unparseable(String),
}

/// Read the store as an ordered list of [`StoreLine`]s, preserving lines that
/// do not parse as a [`CanaryEntry`] so a rewrite can write them back verbatim.
///
/// Returns `(lines, complete)`. `complete == false` (CodeRabbit R13 #1) means the
/// underlying read broke early on a real mid-file I/O fault, so `lines` is a
/// truncated prefix — `prune`/`rotate` must NOT rewrite the store from it (that
/// would permanently drop the unread tail) and abort instead.
fn read_store_partitioned(path: &Path) -> (Vec<StoreLine>, bool) {
    // RAW (untrimmed) read (CodeRabbit R15 #3): an unparseable line is kept
    // verbatim as `StoreLine::Unparseable` and written back as-is on rewrite, so
    // it must retain its original surrounding whitespace. Parseable entries are
    // unaffected — `serde_json` tolerates the whitespace.
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

/// Atomically rewrite the store to exactly the given pre-serialized JSONL
/// `lines`. Writes a sibling temp file then renames over the target so a crash
/// mid-write never truncates the store. This is the line-preserving primitive
/// `prune`/`rotate` use so unparseable lines survive the rewrite verbatim.
fn rewrite_store_lines(store: &Path, lines: &[String]) -> std::io::Result<()> {
    // Resolve a symlinked store to its real target so the rewrite writes THROUGH
    // the link rather than replacing it with a regular file (CodeRabbit R13b).
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
    // Durability: fsync the temp file's contents to stable storage BEFORE the
    // atomic rename. Without this, a crash between `persist` (the rename) and
    // the kernel flushing the temp file's data can leave the store renamed into
    // place but holding zero/garbage bytes — worse than the pre-rename state.
    // Flush the user-space writer first (a no-op for the inner `File` today, but
    // correct regardless), then `sync_all()` the underlying file.
    tmp.flush()?;
    tmp.as_file().sync_all()?;
    tmp.persist(&dest).map_err(|e| e.error)?;
    // Durability of the RENAME itself (CodeRabbit R9 #B): the body is fsync'd
    // above, but the new directory entry is not crash-durable until the parent
    // dir is fsync'd. A lost rewrite could resurrect a stale store (e.g. an
    // un-pruned canary that no longer exists, or drop a still-live one). fsync
    // the parent so the published store survives a crash. The body+rename already
    // succeeded, so a dir-fsync failure is LOGGED, not propagated (R13 #5).
    // Best-effort, unix-only.
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
    // Normalize the callback URL HERE — the single invariant for every caller
    // (CLI, tests, library). Trim surrounding whitespace and collapse a
    // blank-after-trim value to `None`. Without this, `Some("   ")` would be
    // PERSISTED as a configured callback, yet `fire_callback` trims it to empty
    // and no-ops — the store would claim "callback configured" while runtime
    // treated the canary as local-only. Storing `None` keeps disk and runtime
    // semantics identical.
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
    // Hold the store lock across the append so it cannot interleave with a
    // concurrent prune/rotate read-modify-write (which would drop this entry).
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

/// List every recorded canary in the store at `store`, in file order. A display
/// path: an incomplete read (already diagnosed on stderr by the reader) returns
/// the partial prefix rather than failing safe — the DETECTION path
/// ([`detect_at`]) is the one that surfaces incompleteness (CodeRabbit R16 #3).
pub fn list_at(store: &Path) -> Vec<CanaryEntry> {
    parse_store(store).0
}

/// Like [`list_at`] but also reports whether the store was read to COMPLETION
/// (`(entries, complete)`). `complete == false` means the read stopped on a
/// present-but-unreadable store (FIFO/device/oversized/permission/I/O) or a
/// mid-file fault, so `entries` is NOT a faithful image and an "empty" result is
/// NOT proof the store is empty (CodeRabbit R17 #2). The CLI `prune` uses this so
/// it cannot mistake an UNREADABLE store for "nothing to prune": a lenient
/// [`list_at`] would degrade such a store to an empty/partial view and report a
/// false success. An ABSENT store is genuinely empty and returns
/// `(vec![], true)`.
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

/// Production entry point for [`list_at_complete`] against the default store.
/// Returns `(entries, complete)`. When the store path cannot be resolved at all
/// the state dir is unknown — treated as `complete == false` (an unresolved
/// store is NOT a proven-empty one) so the CLI does not report a false
/// "nothing to prune".
pub fn list_complete() -> (Vec<CanaryEntry>, bool) {
    match store_path() {
        Some(p) => list_at_complete(&p),
        None => (Vec::new(), false),
    }
}

/// Remove the canary with `id` from the store at `store`. Returns the number of
/// entries removed (0 when the id is unknown).
pub fn prune_at(store: &Path, id: &str) -> std::io::Result<usize> {
    // Lock across the whole read-modify-write so a concurrent create/rotate
    // cannot slip an update in between our snapshot and our rewrite.
    let _lock = StoreLock::acquire(store)?;
    // Read RAW lines (CodeRabbit R12 #F): drop ONLY a parsed entry whose id
    // matches; carry every other line — including ones that don't parse as a
    // CanaryEntry — through the rewrite VERBATIM so prune never loses data.
    // PARTIAL-READ GUARD (CodeRabbit R13 #1): if the read broke early on a real
    // I/O fault the lines are a truncated prefix; rewriting from them would drop
    // the unread tail (still-live canaries). Abort rather than truncate.
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
    // Lock across the whole read-modify-write (see `prune_at`): a concurrent
    // create appending mid-rotate must not be lost by our rewrite.
    let _lock = StoreLock::acquire(store)?;
    // Read RAW lines (CodeRabbit R12 #F): mutate ONLY the parsed entry whose id
    // matches; preserve every other line — parsed or not — so rotate never drops
    // an unparseable (future-schema / transient) line on the rewrite.
    // PARTIAL-READ GUARD (CodeRabbit R13 #1): a truncated prefix from a broken
    // read must not drive a rewrite (it would drop the unread tail). Abort first.
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
            // Rotate only the FIRST matching entry; any later id-duplicate is
            // preserved unchanged (ids are unique in practice — a create rejects
            // a dup — but never silently drop one if the invariant is violated).
            StoreLine::Parsed(mut entry) if entry.id == id && updated.is_none() => {
                // FAIL SAFE on an unknown `kind` (CodeRabbit R13 #A). `kind` is
                // stored as a raw string for forward-compatible round-tripping, so
                // an entry written by a NEWER binary (a future kind this build does
                // not know) parses as valid JSON but `CanaryKind::parse` returns
                // None. Defaulting to AwsLike would mint an AWS-shaped token while
                // leaving the original `kind` string in place — corrupting the
                // newer entry. Abort the rotate instead (the store is not rewritten
                // because we return before `rewrite_store_lines`), mirroring the
                // forward-compat preservation of `StoreLine::Unparseable`.
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
/// one [`CanaryHit`] per matching canary, DEDUPED BY ID: a token appearing twice
/// in `text` yields one hit (we iterate entries, not text matches), and a
/// duplicate `id` in the store (the append-only store enforces no uniqueness, so
/// a hand-edited or rotated-into-collision store could carry one) also yields a
/// single hit for that id rather than firing the callback twice.
/// `text.contains(&token)` is a substring match: a canary planted in a larger
/// blob (e.g. a `cat ~/.aws/credentials` paste) still fires.
pub fn detect_at(store: &Path, text: &str) -> Vec<CanaryHit> {
    if text.is_empty() {
        return Vec::new();
    }
    let (entries, complete) = cached_entries(store);
    let mut hits = Vec::new();
    let mut seen_ids: std::collections::HashSet<String> = std::collections::HashSet::new();
    for e in entries {
        // An empty token would `contains`-match everything; skip defensively
        // (a well-formed entry never has an empty token).
        if e.token.is_empty() {
            continue;
        }
        if text.contains(&e.token) {
            // Dedup by id: a duplicate id in the store must not fire twice (one
            // detection, one callback). First match for an id wins.
            if seen_ids.insert(e.id.clone()) {
                hits.push(CanaryHit {
                    id: e.id,
                    kind: e.kind,
                    callback_url: e.callback_url,
                });
            }
        }
    }
    // FAIL-SAFE ON A TRUNCATED READ (CodeRabbit R16 #3, mirroring `taint`): the
    // store read can stop on a persistent mid-file I/O fault and yield only the
    // PREFIX it consumed. A canary planted in the UNREAD tail would then never
    // match — a touched canary reading as untouched (fail-OPEN, a detection miss).
    // We cannot synthesize a hit (no token/id/callback to attach, and firing a
    // spurious opt-in callback would be wrong), so the least-disruptive fail-safe
    // is to SURFACE the incompleteness: a one-line stderr diagnostic (rate-limited
    // per (path, mtime)) so the operator knows the canary scan was not exhaustive.
    // A genuine match in the prefix still fires normally; an InvalidData line skip
    // keeps `complete == true` and never trips this.
    if !complete {
        warn_incomplete_store_once(store);
    }
    hits
}

/// One-line stderr diagnostic when a canary scan runs against an INCOMPLETELY
/// read store, de-duplicated per `(path, mtime)` so the 5s-cache hot path does
/// not spam. Unlike `taint` (whose lookup can fail safe to a synthetic tainted
/// entry), a canary scan cannot synthesize a hit, so surfacing the incompleteness
/// is the fail-safe (CodeRabbit R16 #3).
fn warn_incomplete_store_once(store: &Path) {
    static LAST_WARNED: Mutex<Option<(PathBuf, u128)>> = Mutex::new(None);
    let mtime = mtime_nanos(store);
    let mut guard = LAST_WARNED.lock().unwrap_or_else(|e| e.into_inner());
    let key = (store.to_path_buf(), mtime);
    if guard.as_ref() == Some(&key) {
        return;
    }
    *guard = Some(key);
    // Best-effort diagnostic: write fallibly so a closed/broken stderr cannot
    // panic this helper (CodeRabbit R22 #4). `eprintln!` panics on a write error.
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

    // Keep an `id` copy on this side of the move so a SPAWN failure (the OS
    // refusing a new thread — e.g. resource limits) can still be audited: the
    // closure below consumes `id`, so without this clone a failed spawn would
    // drop the callback with no record, unlike the HTTP-path failures which all
    // reach `log_callback_failure`.
    let id_for_spawn_failure = id.clone();
    // Detached: the engine returns its verdict without waiting on the network.
    // If the process exits before the POST completes the callback is simply
    // dropped — best-effort by design. We do not join the handle.
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
                    // The URL is not given to the builder, so this error cannot
                    // carry it — but keep the audit reason coarse and URL-free
                    // for consistency with the send-error path below.
                    log_callback_failure(&id, "client build failed");
                    return;
                }
            };

            match client.post(&url).json(&body).send() {
                Ok(resp) if resp.status().is_success() => {}
                Ok(resp) => {
                    // Only the numeric status — never the URL.
                    log_callback_failure(
                        &id,
                        &format!("callback returned HTTP {}", resp.status().as_u16()),
                    );
                }
                Err(e) => {
                    // CRITICAL: a `reqwest::Error`'s Display embeds the request
                    // URL (e.g. "error sending request for url (https://…)").
                    // The callback URL is operator-private (a self-hosted
                    // endpoint), so NEVER interpolate the raw error into the
                    // audit log — classify it to a coarse, URL-free reason.
                    log_callback_failure(&id, classify_callback_error(&e));
                }
            }
        });

    // A spawn failure (the OS refused a new thread) silently dropped the
    // callback before this — route it through the same audit sink as the
    // in-thread HTTP failures, with a coarse, URL-free reason.
    if spawn_result.is_err() {
        log_callback_failure(&id_for_spawn_failure, "callback worker spawn failed");
    }
}

/// Map a `reqwest` send error to a coarse, NON-sensitive reason string. The raw
/// `Display` of a `reqwest::Error` embeds the request URL (the operator-private
/// callback endpoint), so it must never reach the audit log. This returns only
/// the error *category* — no URL, host, or other request detail.
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

    /// Make a FIFO at `path` (unix). Returns false if mkfifo is unsupported here.
    #[cfg(unix)]
    fn mkfifo_at(path: &Path) -> bool {
        use std::ffi::CString;
        let c_path = CString::new(path.as_os_str().to_str().unwrap()).unwrap();
        unsafe { libc::mkfifo(c_path.as_ptr(), 0o600) == 0 }
    }

    /// CodeRabbit R13 #1: a store whose read does NOT complete (here a FIFO, which
    /// `read_store_lines_complete` reports as incomplete because it is not a
    /// readable regular file) must ABORT prune/rotate — NOT rewrite the store from
    /// the empty/partial image, which would truncate it. The mutator returns an
    /// error and the store path is left exactly as-is (still a FIFO, never
    /// replaced by a regular file). Unix-only (needs mkfifo); cannot hang (the
    /// O_NONBLOCK open in `open_regular_capped` returns immediately).
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

    /// CodeRabbit R16 #3 (canary analog of the taint fail-safe): a store whose
    /// read does NOT complete (here a FIFO, reported incomplete by
    /// `read_store_lines_complete`) must be flagged `complete == false` so
    /// `detect_at` surfaces the incompleteness rather than treating a planted
    /// canary as definitively untouched. We assert the load-bearing precondition
    /// (the read reports incomplete) and that `detect_at` returns promptly without
    /// hanging or panicking. Unix-only (needs mkfifo); cannot hang (O_NONBLOCK).
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
        // The explicit `00CANARY` marker is what keeps the token clearly
        // synthetic, so a flagged value reads as tirith bait rather than a real
        // leaked credential — the load-bearing "clearly-labelled" property.
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
        // CodeRabbit R9 #H: the getrandom-failure fallback must NOT be
        // deterministic — the old code cycled the same alphabet head every call,
        // so `new_id()` could repeat IDs. `fill_fallback_bytes` advances a
        // process-lifetime counter (+ time), so two consecutive fills differ.
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
        // CodeRabbit R6 #8: a whitespace-only callback URL must persist as `None`,
        // not `Some("   ")`. `fire_callback` trims and no-ops on a blank URL, so
        // storing the raw blank would make the on-disk record claim a callback is
        // configured while runtime treats the canary as local-only. `create_at`
        // is the single normalization point for all callers.
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

    /// Durability regression (CodeRabbit/Greptile R4 #1): every store mutator
    /// must flush + `sync_all()` before returning Ok, so a registered/pruned/
    /// rotated canary survives a crash. A unit test cannot OBSERVE the fsync
    /// barrier directly (the kernel would have to crash between the write and
    /// the flush), so this asserts the necessary precondition: after each
    /// mutator returns Ok the written content is durably present and readable
    /// straight from the file on disk (via `parse_store`, NOT the in-process
    /// cache). If a mutator regressed to dropping the synced write, the bytes
    /// would not be on disk for `parse_store` to read back. The actual fsync
    /// calls live in `append_entry` (create) and `rewrite_store_lines`
    /// (prune/rotate).
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
        // P2: the doc promises results are "deduped by id". The append-only
        // store enforces no id-uniqueness, so two entries can share an id (e.g.
        // a hand-edited store). Both matching the text must yield ONE hit for
        // that id — never fire the (opt-in) callback twice for one id.
        let dir = tempdir().unwrap();
        let store = store_in(dir.path());
        // Two store lines with the SAME id but distinct tokens, both present in
        // the scanned text.
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

    /// Append a valid-but-unparseable line (a future-schema JSON object) to the
    /// store so the lenient reader skips it. Returns the literal line.
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
        // CodeRabbit R12 #F: prune's REWRITE must not silently drop a line the
        // lenient reader skips. Create two canaries + an unknown line, prune one,
        // and assert the unknown line survives on disk.
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
        // CodeRabbit R12 #F: rotate's REWRITE must not silently drop a line the
        // lenient reader skips.
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
        // CodeRabbit R13 #A: an entry written by a NEWER tirith with a `kind` this
        // build doesn't know still deserializes as a valid `CanaryEntry`
        // (StoreLine::Parsed) — it is NOT an unparseable line. Rotating it must
        // NOT silently mint an AWS-shaped token while leaving the unknown `kind`
        // in place (corruption). It must fail safe and leave the store untouched.
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
        // F2 (Major): the store mutators serialize behind a sibling `.lock`
        // file. This proves the lock is RELEASED between calls (a still-held
        // exclusive lock would deadlock the next blocking acquire) and that each
        // mutation's effect persists — two creates then a prune all take effect.
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
        // F1 (Major): `StoreLock::acquire` must NOT silently drop the
        // serialization guarantee on an arbitrary lock error. On a normal
        // filesystem `lock_exclusive` succeeds, so acquire returns `Ok` and the
        // guarded mutation persists — proving the happy (supported-lock) path is
        // preserved by the fix and the lock is actually held across the write.
        let dir = tempdir().unwrap();
        let store = store_in(dir.path());
        {
            let _g = StoreLock::acquire(&store).expect("supported-lock acquire succeeds");
            // The sentinel lock file is created as part of acquire.
            assert!(lock_path_for(&store).exists(), "lock sentinel created");
            // While the lock is held in THIS scope, the file handle is open and
            // the guard is live; dropping it below releases the lock.
        }
        // After release the guarded mutator works and its effect persists,
        // confirming acquire returned a real, releasable lock (not an UNLOCKED
        // best-effort handle from a swallowed error).
        create_at(&store, CanaryKind::AwsLike, None).unwrap();
        assert!(
            store_nonempty_at(&store),
            "mutation under a real lock persists"
        );
    }

    #[test]
    fn acquire_propagates_non_unsupported_io_errors() {
        // F1 (Major): only an `Unsupported` lock error is best-effort; any other
        // I/O failure during acquire must propagate as `Err`, never silently
        // proceed. We force a deterministic, cross-platform failure: point the
        // store at a path whose PARENT is an existing regular FILE, so
        // `create_dir_all(parent)` inside `acquire` fails (NotADirectory /
        // AlreadyExists) and the error is returned rather than swallowed.
        let dir = tempdir().unwrap();
        let blocker = dir.path().join("not-a-dir");
        std::fs::write(&blocker, b"x").unwrap();
        // store would live UNDER the regular file `not-a-dir` — its parent can
        // never be created.
        let store = blocker.join("canaries.jsonl");
        // `StoreLock` is not `Debug`, so match instead of `expect_err`.
        match StoreLock::acquire(&store) {
            Ok(_) => panic!("acquire must fail when the store's parent cannot be created"),
            Err(err) => {
                // It must surface a real error (the exact kind is OS-dependent),
                // proving acquire does not return a bogus unlocked guard on a
                // non-Unsupported failure.
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

    #[test]
    fn callback_error_reason_never_contains_the_url_or_host() {
        // CRITICAL (finding D): a failed callback's audit reason must NOT embed
        // the operator-private callback URL/host. A raw `reqwest::Error`'s
        // Display normally includes the request URL, so we provoke a real send
        // error against a unique, recognizable host and assert the CLASSIFIED
        // reason carries none of it — only a coarse category.
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
