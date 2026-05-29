//! M10 ch5 — per-user anomaly-detection baseline (design-decision **D2**).
//!
//! An OPT-IN sliding window of finding *observations*. When
//! `policy.baseline_enabled` is set (default **false**), the engine records one
//! observation every time a detection rule fires and, before recording, asks
//! whether the observation's *pattern* has been seen before. A first-time or
//! rarely-seen pattern surfaces an extra Info finding
//! ([`crate::verdict::RuleId::AnomalyFirstTimeInThisRepo`] /
//! [`AnomalyRareInBaseline`](crate::verdict::RuleId::AnomalyRareInBaseline))
//! alongside the normal verdict. The anomaly findings are **Info** — they never
//! change the action; they annotate "this is new for you".
//!
//! # Default OFF (D2)
//!
//! The decision recorded in `M6_TO_M14_PLAN.md` §D2 is **opt-in only**: a fresh
//! install does nothing here. `tirith baseline learn` flips
//! `policy.baseline_enabled` to `true`. When the flag is off, the engine never
//! reads or writes this store on the hot path (`engine::apply_baseline` returns
//! immediately on `!policy.baseline_enabled`), so a machine that never opted in
//! pays nothing.
//!
//! # Privacy model (D2 — salted hashes, NEVER raw values)
//!
//! The store must be safe to read, sync, or attach to a bug report without
//! leaking which hosts you contact or which repositories you work in.
//! Therefore it records **no raw hostnames and no raw paths**. Specifically:
//!
//! * **Hostname** → `sha256(salt || host)`, hex, first 16 chars. The salt is a
//!   per-install 32-byte random value at `state_dir()/baseline.salt` (mode
//!   `0600`), generated on first use. Without the salt, the hashes are not
//!   reversible via a precomputed rainbow table of common hostnames, and two
//!   installs never produce the same hash for the same host.
//! * **cwd / repo** → the same salted-sha256, first 8 chars, of the repository
//!   root (the nearest `.git` ancestor of the cwd, resolved in-process by
//!   [`crate::policy::find_repo_root`] — NOT a `git` subprocess, so the hot path
//!   never forks). When the cwd is not inside a repo, the cwd itself is hashed.
//! * **ecosystem** (`npm` / `pypi` / `docker` / …) and **sudo flag** are
//!   low-cardinality, non-identifying categoricals and are stored in the clear.
//! * **rule_id** is the public rule name, stored in the clear.
//!
//! The salt never leaves the machine and is never logged. The hashes are
//! one-way; this module offers no reverse lookup.
//!
//! # Storage model
//!
//! JSONL at `state_dir()/baseline.jsonl`: one [`Observation`] object per line,
//! appended on `record`. Two bounds keep it from growing without limit:
//!
//! * **Window 90 days** — observations older than [`WINDOW_DAYS`] are dropped on
//!   the next compaction and never counted by [`lookup_at`].
//! * **Cap 100k entries** — at [`MAX_ENTRIES`] the oldest entries are evicted
//!   (LRU by `seen_at`). Compaction (window-prune + cap-evict) runs lazily when
//!   the file's line count crosses a threshold on append, and unconditionally on
//!   `reset`.
//!
//! If a future workload makes the linear scan a bottleneck, SQLite is the
//! reserved backend (the `record` / `lookup` / `status` / `reset` API is the
//! migration boundary). JSONL is chosen for v1 to stay human-inspectable.
//!
//! # Test entry points
//!
//! Every function has a `*_at(dir, …)` form that takes an explicit state
//! directory, so tests run against a `tempfile::tempdir()` with NO writes to the
//! real `state_dir()` and NO env mutation. The production wrappers resolve
//! `state_dir()` and delegate.

use std::io::Write;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::verdict::RuleId;

/// Sliding-window length. Observations older than this are pruned and never
/// counted toward a pattern's seen-count.
pub const WINDOW_DAYS: i64 = 90;

/// Hard cap on stored observations. At this many entries the oldest are evicted
/// (LRU by `seen_at`) so the JSONL never grows without bound.
pub const MAX_ENTRIES: usize = 100_000;

/// A pattern seen fewer than this many times in the window is "rare". A pattern
/// seen zero times is "first time". The engine uses these to pick which anomaly
/// rule (if any) to surface. Three matches the plan's "seen < 3 times" rule.
pub const RARE_THRESHOLD: u32 = 3;

/// Below this many total observations, `doctor` reports "early-baseline mode":
/// the window is too sparse to trust anomaly signals (everything looks new).
pub const EARLY_BASELINE_ENTRIES: usize = 30;

/// Compact (prune-window + cap-evict) when the on-disk line count exceeds this.
/// Slightly above [`MAX_ENTRIES`] so a steady-state store compacts occasionally
/// rather than on every append.
const COMPACT_TRIGGER: usize = MAX_ENTRIES + 1_000;

/// One recorded observation: a detection rule firing, with the identifying
/// fields reduced to salted hashes / low-cardinality categoricals.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Observation {
    /// The public rule name (e.g. `"curl_pipe_shell"`).
    pub rule_id: String,
    /// Salted-sha256 (first 16 hex chars) of the URL host, when the finding
    /// referenced one. `None` when the finding had no host.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub host_hash: Option<String>,
    /// Low-cardinality ecosystem label (`npm` / `pypi` / `docker` / …), in the
    /// clear. `None` when not applicable.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ecosystem: Option<String>,
    /// Whether the command was a sudo invocation. Low-cardinality, in the clear.
    pub sudo_flag: bool,
    /// Salted-sha256 (first 8 hex chars) of the repo root (or cwd when not in a
    /// repo). `None` when no cwd was resolvable.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cwd_repo_hash: Option<String>,
    /// RFC-3339 UTC timestamp the observation was recorded. Used for the
    /// 90-day window prune and the LRU cap eviction.
    pub seen_at: String,
}

/// The identifying tuple of an observation — everything except `seen_at`. Two
/// observations with equal tuples are "the same pattern".
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct PatternKey {
    pub rule_id: String,
    pub host_hash: Option<String>,
    pub ecosystem: Option<String>,
    pub sudo_flag: bool,
    pub cwd_repo_hash: Option<String>,
}

impl PatternKey {
    /// True when this observation carries the same identifying tuple.
    fn matches(&self, obs: &Observation) -> bool {
        self.rule_id == obs.rule_id
            && self.host_hash == obs.host_hash
            && self.ecosystem == obs.ecosystem
            && self.sudo_flag == obs.sudo_flag
            && self.cwd_repo_hash == obs.cwd_repo_hash
    }

    /// Build an [`Observation`] from this key, stamped now.
    fn into_observation(self) -> Observation {
        Observation {
            rule_id: self.rule_id,
            host_hash: self.host_hash,
            ecosystem: self.ecosystem,
            sudo_flag: self.sudo_flag,
            cwd_repo_hash: self.cwd_repo_hash,
            seen_at: chrono::Utc::now().to_rfc3339(),
        }
    }
}

/// The result of a [`lookup_at`] — how many times the pattern was seen in the
/// window, and the classification the engine acts on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SeenCount {
    /// Number of in-window observations matching the looked-up pattern.
    pub count: u32,
    /// `true` when `count == 0` (never seen in the window).
    pub first_time: bool,
    /// `true` when `0 < count < RARE_THRESHOLD` (seen, but rarely).
    pub rare: bool,
}

impl SeenCount {
    fn from_count(count: u32) -> Self {
        Self {
            count,
            first_time: count == 0,
            rare: count > 0 && count < RARE_THRESHOLD,
        }
    }
}

/// One row of `tirith baseline status` — a pattern and how often it appears.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct TopPattern {
    pub rule_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub host_hash: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ecosystem: Option<String>,
    pub sudo_flag: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cwd_repo_hash: Option<String>,
    pub count: u32,
}

// ─── paths ───────────────────────────────────────────────────────────────────

/// Default JSONL store path: `state_dir()/baseline.jsonl`.
pub fn store_path() -> Option<PathBuf> {
    crate::policy::state_dir().map(|d| d.join("baseline.jsonl"))
}

/// Per-install salt file path: `state_dir()/baseline.salt`.
pub fn salt_path() -> Option<PathBuf> {
    crate::policy::state_dir().map(|d| d.join("baseline.salt"))
}

/// The store and salt paths inside an explicit state directory (test entry).
#[cfg(test)]
fn store_in(dir: &Path) -> PathBuf {
    dir.join("baseline.jsonl")
}
#[cfg(test)]
fn salt_in(dir: &Path) -> PathBuf {
    dir.join("baseline.salt")
}

// ─── salt ──────────────────────────────────────────────────────────────────--

/// Fixed salt length. The salt file must be EXACTLY this many bytes; a
/// shorter file (truncated, crash mid-write, or attacker-shrunk) is rejected and
/// regenerated, so the documented 32-byte privacy guarantee can never silently
/// degrade to a weak salt.
const SALT_LEN: usize = 32;

/// Read cap for the salt file (CodeRabbit R11 #4). The salt is exactly
/// [`SALT_LEN`] (32) bytes; 4 KiB is generous slack so a slightly-larger file is
/// still read (and then rejected as the wrong length), while a genuinely
/// oversized / attacker-grown `baseline.salt` is refused BEFORE it is allocated
/// rather than buffered whole.
const SALT_READ_CAP: u64 = 4 * 1024;

/// Per-process salt state. Resolved once (I1: no N+1 file reads on the hot path)
/// and cached, keyed on the salt path so test entry points with distinct temp
/// paths each resolve their own salt.
enum SaltState {
    /// A usable salt (read from disk or freshly generated AND persisted).
    Ready(Vec<u8>),
    /// The salt is corrupt/unreadable AND could not be persisted, so a fresh
    /// per-run salt would churn every hash and make EVERY pattern look
    /// "first time" forever (F4). Baseline is disabled for the session.
    Disabled,
}

/// Cache of `(salt_path, state)`. Reloads only when the path differs (production
/// always passes the same `state_dir()/baseline.salt`, so it loads once).
static SALT_CACHE: std::sync::Mutex<Option<(PathBuf, std::sync::Arc<SaltState>)>> =
    std::sync::Mutex::new(None);

/// One-shot guard so the "baseline disabled" warning prints at most once per
/// process even if many findings fire.
static SALT_WARNED: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

/// Resolve the per-install salt for `salt_file`, caching the result for the
/// process. See [`load_salt_state`] for the read/generate/persist logic.
fn salt_state(salt_file: &Path) -> std::sync::Arc<SaltState> {
    let mut guard = SALT_CACHE.lock().unwrap_or_else(|e| e.into_inner());
    if let Some((path, state)) = guard.as_ref() {
        if path == salt_file {
            return std::sync::Arc::clone(state);
        }
    }
    let state = std::sync::Arc::new(load_salt_state(salt_file));
    *guard = Some((salt_file.to_path_buf(), std::sync::Arc::clone(&state)));
    state
}

/// Read the salt from `salt_file` (must be exactly [`SALT_LEN`] bytes), or
/// generate a fresh 32-byte salt and persist it atomically at `0600`.
///
/// Fail-open with a floor: if the file is absent/corrupt AND the fresh salt
/// cannot be persisted, returns [`SaltState::Disabled`] (with a one-time stderr
/// warning) rather than handing back an unpersisted salt that would churn every
/// hash and fire `AnomalyFirstTimeInThisRepo` forever (F4).
fn load_salt_state(salt_file: &Path) -> SaltState {
    let mut existing_is_corrupt = false;
    // CodeRabbit R9 #C + R11 #1/#4: read the salt through the shared, race-free
    // capped helper. A FIFO/device at the salt path would block a plain
    // `std::fs::read` forever, and an oversized `baseline.salt` would be fully
    // allocated before any length check. `read_regular_capped` opens with
    // O_NONBLOCK, fstats the OPEN fd (closing the metadata→open TOCTOU), rejects
    // non-regular files, and caps the read at SALT_READ_CAP (the salt is exactly
    // SALT_LEN bytes; the cap is generous slack, so anything over it is corrupt).
    //   * NotFound          → absent: fall through to fresh-salt generation.
    //   * exactly SALT_LEN  → adopt the on-disk salt.
    //   * any other length, non-regular, oversized, or I/O error → corrupt:
    //     OVERWRITE it (I2), never adopt and never block.
    match crate::util::read_regular_capped(salt_file, SALT_READ_CAP) {
        Ok(bytes) if bytes.len() == SALT_LEN => return SaltState::Ready(bytes),
        // A short/oversized/non-regular/unreadable salt file is corrupt — must be
        // OVERWRITTEN, not adopted (I2). Remember this so persist replaces it
        // atomically rather than treating `AlreadyExists` as "another process won
        // the race".
        Ok(_) => existing_is_corrupt = true,
        Err(crate::util::OpenRegularError::NotFound) => {}
        Err(_) => existing_is_corrupt = true,
    }

    // Generate a fresh 32-byte salt from the OS RNG. On the (extremely unlikely)
    // event that the OS entropy source fails, fall back to a time-derived salt
    // so hashing never aborts — fail-open, since a weak salt only weakens the
    // privacy guarantee for this one process, it never crashes.
    let mut salt = [0u8; SALT_LEN];
    if getrandom::fill(&mut salt).is_err() {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        salt[..16].copy_from_slice(&nanos.to_le_bytes());
    }
    let salt = salt.to_vec();

    match persist_salt(salt_file, &salt, existing_is_corrupt) {
        Ok(persisted) => SaltState::Ready(persisted),
        Err(_) => {
            // Could neither read a stable salt nor write a fresh one. A per-run
            // salt would make every pattern look new on every invocation,
            // turning the anomaly signal into perpetual noise — so disable
            // baseline for this session and tell the user once.
            warn_baseline_disabled_once(salt_file);
            SaltState::Disabled
        }
    }
}

/// Install `salt` at `salt_file` (mode `0600`) and return the salt that is now
/// ON DISK.
///
/// Two cases:
///   * `replace_corrupt == false` (the file was ABSENT): claim it exclusively
///     with `create_new`. If another process created it first (greptile #4
///     concurrent-first-use race), ADOPT that process's salt by reading it back
///     instead of clobbering it — so two processes that start together never
///     diverge (one salt in memory, a different one on disk).
///   * `replace_corrupt == true` (the file existed but was the wrong length):
///     overwrite it atomically via a sibling temp file + rename (I2), so a
///     short/truncated salt is regenerated rather than adopted.
///
/// In both cases a crash mid-write never leaves a half-written salt. The absent
/// path's exclusive `create_new` followed by one `write_all` is the only writer
/// of a fresh file, and the replace path renames a fully-written temp file into
/// place.
fn persist_salt(salt_file: &Path, salt: &[u8], replace_corrupt: bool) -> std::io::Result<Vec<u8>> {
    if let Some(parent) = salt_file.parent() {
        std::fs::create_dir_all(parent)?;
    }

    if replace_corrupt {
        // Atomic overwrite of a corrupt (wrong-length) salt.
        let dir = salt_file.parent().unwrap_or_else(|| Path::new("."));
        let mut tmp = tempfile::NamedTempFile::new_in(dir)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            tmp.as_file()
                .set_permissions(std::fs::Permissions::from_mode(0o600))?;
        }
        tmp.write_all(salt)?;
        // Durability (CodeRabbit R9 #B): fsync the new salt to stable storage
        // BEFORE the rename publishes it, then fsync the parent dir so the
        // rename's directory entry is durable too. A lost overwrite would leave
        // the corrupt salt in place; a body synced but entry lost would lose the
        // new salt. Best-effort parent fsync (unix-only).
        tmp.as_file().sync_all()?;
        tmp.persist(salt_file).map_err(|e| e.error)?;
        crate::util::fsync_parent_dir(salt_file);
        return Ok(salt.to_vec());
    }

    // Absent file: try to claim it exclusively so concurrent first-use does not
    // produce two diverging salts.
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    match opts.open(salt_file) {
        Ok(mut f) => {
            f.write_all(salt)?;
            f.sync_all().ok();
            Ok(salt.to_vec())
        }
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
            // Lost the race — adopt the on-disk salt when it is the right length;
            // otherwise propagate so the caller disables baseline. Read through
            // the race-free capped helper (R11 #1) so a FIFO/device that won the
            // `create_new` race cannot block this read-back, and an oversized
            // file cannot be buffered whole.
            match crate::util::read_regular_capped(salt_file, SALT_READ_CAP) {
                Ok(bytes) if bytes.len() == SALT_LEN => Ok(bytes),
                Ok(_) => Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "concurrent salt file is corrupt",
                )),
                Err(crate::util::OpenRegularError::Io(e)) => Err(e),
                Err(_) => Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "concurrent salt file is not a usable regular file",
                )),
            }
        }
        Err(e) => Err(e),
    }
}

fn warn_baseline_disabled_once(salt_file: &Path) {
    use std::sync::atomic::Ordering;
    if !SALT_WARNED.swap(true, Ordering::Relaxed) {
        eprintln!(
            "tirith: WARNING: baseline salt at {} is unreadable and could not be \
             written; anomaly baseline is disabled for this session (run \
             `tirith doctor` to diagnose the state directory).",
            salt_file.display()
        );
    }
}

/// `true` when the baseline is disabled for this session because the salt is
/// neither readable nor writable. The engine consults this to skip the whole
/// baseline block rather than emit perpetual false `first-time` anomalies (F4).
pub fn session_disabled() -> bool {
    match salt_path() {
        Some(sp) => matches!(*salt_state(&sp), SaltState::Disabled),
        None => true,
    }
}

/// Salted-sha256 of `value`, hex, truncated to `len` chars. Used for both the
/// host hash (`len = 16`) and the cwd/repo hash (`len = 8`).
fn salted_hash(salt: &[u8], value: &str, len: usize) -> String {
    let mut hasher = Sha256::new();
    hasher.update(salt);
    hasher.update(value.as_bytes());
    let hex = format!("{:x}", hasher.finalize());
    hex.chars().take(len).collect()
}

/// Compute the host hash for a raw hostname using the salt in `salt_file`.
/// Hostnames are lowercased first so `GitHub.com` and `github.com` collapse.
/// Returns `None` when the salt is disabled for the session (F4).
pub fn hash_host_at(salt_file: &Path, host: &str) -> Option<String> {
    match &*salt_state(salt_file) {
        SaltState::Ready(salt) => Some(salted_hash(salt, &host.trim().to_ascii_lowercase(), 16)),
        SaltState::Disabled => None,
    }
}

/// Compute the cwd/repo hash. `cwd` is resolved to its repository root (nearest
/// `.git` ancestor) in-process; when not in a repo, the cwd path is hashed
/// directly. Returns `None` when no cwd is resolvable OR the salt is disabled.
pub fn hash_cwd_at(salt_file: &Path, cwd: Option<&str>) -> Option<String> {
    let resolved = crate::policy::find_repo_root(cwd)
        .map(|p| p.to_string_lossy().into_owned())
        .or_else(|| {
            cwd.map(|c| c.to_string()).or_else(|| {
                std::env::current_dir()
                    .ok()
                    .map(|p| p.display().to_string())
            })
        })?;
    match &*salt_state(salt_file) {
        SaltState::Ready(salt) => Some(salted_hash(salt, &resolved, 8)),
        SaltState::Disabled => None,
    }
}

// ─── store I/O ─────────────────────────────────────────────────────────────--

/// Parse the JSONL store, skipping blank / unparseable lines (fail-open).
fn parse_store(path: &Path) -> Vec<Observation> {
    // `read_store_lines` skips blank lines, skips a single recoverable
    // invalid-UTF-8 line, and BREAKS on any other (persistent) read error so a
    // corrupt store cannot spin the reader forever. We then drop lines that fail
    // to parse as an `Observation` (fail-open).
    crate::util::read_store_lines(path)
        .iter()
        .filter_map(|line| serde_json::from_str::<Observation>(line).ok())
        .collect()
}

/// Parse `seen_at` to a UTC timestamp; `None` when unparseable.
fn parse_seen_at(s: &str) -> Option<chrono::DateTime<chrono::Utc>> {
    chrono::DateTime::parse_from_rfc3339(s)
        .ok()
        .map(|dt| dt.with_timezone(&chrono::Utc))
}

/// `true` when `seen_at` is within `WINDOW_DAYS` of `now`. An unparseable
/// timestamp is treated as out-of-window (dropped) so a corrupt row can't
/// inflate a count forever. A FUTURE-dated row (negative age — clock skew or a
/// tampered store) is also dropped: without the `age_days >= 0` guard such rows
/// would be permanently in-window and could crowd out real observations under
/// the LRU cap.
fn in_window(seen_at: &str, now: chrono::DateTime<chrono::Utc>) -> bool {
    match parse_seen_at(seen_at) {
        Some(ts) => {
            let age_days = now.signed_duration_since(ts).num_days();
            (0..WINDOW_DAYS).contains(&age_days)
        }
        None => false,
    }
}

/// Apply the window-prune and the LRU cap to a parsed observation list.
/// Returns the retained observations in chronological order (oldest first).
fn compact(mut obs: Vec<Observation>, now: chrono::DateTime<chrono::Utc>) -> Vec<Observation> {
    // 1. Window prune.
    obs.retain(|o| in_window(&o.seen_at, now));
    // 2. LRU cap: keep the newest MAX_ENTRIES. Sort oldest→newest by seen_at;
    //    rows with unparseable timestamps already pruned above.
    if obs.len() > MAX_ENTRIES {
        obs.sort_by(|a, b| {
            let ta = parse_seen_at(&a.seen_at);
            let tb = parse_seen_at(&b.seen_at);
            ta.cmp(&tb)
        });
        let drop_count = obs.len() - MAX_ENTRIES;
        obs.drain(0..drop_count);
    }
    obs
}

/// Append `obs` to the JSONL store, creating parent dirs + the file (`0600`).
fn append_observation(store: &Path, obs: &Observation) -> std::io::Result<()> {
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
    let line = serde_json::to_string(obs).map_err(std::io::Error::other)?;
    writeln!(file, "{line}")?;
    Ok(())
}

/// Atomically rewrite the store to exactly `obs` (used by compaction + reset).
fn rewrite_store(store: &Path, obs: &[Observation]) -> std::io::Result<()> {
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
    for o in obs {
        let line = serde_json::to_string(o).map_err(std::io::Error::other)?;
        writeln!(tmp, "{line}")?;
    }
    // Durability (CodeRabbit R9 #B): fsync the compacted body to stable storage
    // BEFORE the rename, then fsync the parent dir so the rename's directory
    // entry is durable too — otherwise a crash could leave the store renamed
    // into place over zero/partial bytes, or lose the new entry entirely.
    // Best-effort parent fsync (unix-only).
    tmp.flush()?;
    tmp.as_file().sync_all()?;
    tmp.persist(store).map_err(|e| e.error)?;
    crate::util::fsync_parent_dir(store);
    Ok(())
}

/// Cheap on-disk line count (number of `\n`), used to decide whether to compact.
/// Skips lines that fail to read (invalid UTF-8) rather than stopping at the
/// first error, so a single bad byte cannot make the count short and starve the
/// compaction trigger (unbounded growth).
fn line_count(store: &Path) -> usize {
    // Same bounded-read contract as `parse_store`: a recoverable invalid-UTF-8
    // line is skipped, a persistent read error breaks the loop (never stops the
    // count short in a way that would starve the compaction trigger, and never
    // spins). `read_store_lines` already drops blank lines.
    crate::util::read_store_lines(store).len()
}

// ─── public API (test entry points) ──────────────────────────────────────────

/// Look up how many times `key`'s pattern appears in the window of the store at
/// `store`. A near-noop when the store is absent (one failed `open`).
pub fn lookup_at(store: &Path, key: &PatternKey) -> SeenCount {
    let now = chrono::Utc::now();
    let count = parse_store(store)
        .into_iter()
        .filter(|o| in_window(&o.seen_at, now) && key.matches(o))
        .count() as u32;
    SeenCount::from_count(count)
}

/// Record `key` as a new observation in the store at `store`. Appends one line,
/// then compacts (window-prune + cap-evict) when the line count crosses the
/// trigger so the file stays bounded.
pub fn record_at(store: &Path, key: PatternKey) -> std::io::Result<()> {
    let obs = key.into_observation();
    append_observation(store, &obs)?;
    if line_count(store) > COMPACT_TRIGGER {
        let now = chrono::Utc::now();
        let compacted = compact(parse_store(store), now);
        rewrite_store(store, &compacted)?;
    }
    Ok(())
}

/// Top `limit` patterns by in-window count, descending. Ties broken by rule_id
/// then the hashes for a deterministic order.
pub fn status_at(store: &Path, limit: usize) -> Vec<TopPattern> {
    let now = chrono::Utc::now();
    let mut counts: std::collections::HashMap<PatternKey, u32> = std::collections::HashMap::new();
    for o in parse_store(store) {
        if !in_window(&o.seen_at, now) {
            continue;
        }
        let key = PatternKey {
            rule_id: o.rule_id,
            host_hash: o.host_hash,
            ecosystem: o.ecosystem,
            sudo_flag: o.sudo_flag,
            cwd_repo_hash: o.cwd_repo_hash,
        };
        *counts.entry(key).or_insert(0) += 1;
    }
    let mut rows: Vec<TopPattern> = counts
        .into_iter()
        .map(|(k, count)| TopPattern {
            rule_id: k.rule_id,
            host_hash: k.host_hash,
            ecosystem: k.ecosystem,
            sudo_flag: k.sudo_flag,
            cwd_repo_hash: k.cwd_repo_hash,
            count,
        })
        .collect();
    rows.sort_by(|a, b| {
        b.count
            .cmp(&a.count)
            .then_with(|| a.rule_id.cmp(&b.rule_id))
            .then_with(|| a.host_hash.cmp(&b.host_hash))
            .then_with(|| a.ecosystem.cmp(&b.ecosystem))
            .then_with(|| a.sudo_flag.cmp(&b.sudo_flag))
            .then_with(|| a.cwd_repo_hash.cmp(&b.cwd_repo_hash))
    });
    rows.truncate(limit);
    rows
}

/// Total in-window observation count for the store at `store`. Drives the
/// `doctor` early-baseline-mode threshold.
pub fn entry_count_at(store: &Path) -> usize {
    let now = chrono::Utc::now();
    parse_store(store)
        .into_iter()
        .filter(|o| in_window(&o.seen_at, now))
        .count()
}

/// Zero the store at `store` by removing the JSONL file. The salt is left in
/// place (re-using it keeps existing-but-cleared hashes stable; removing it
/// would only churn the salt for no privacy gain). Returns the number of
/// entries removed.
pub fn reset_at(store: &Path) -> std::io::Result<usize> {
    let removed = line_count(store);
    match std::fs::remove_file(store) {
        Ok(()) => Ok(removed),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(0),
        Err(e) => Err(e),
    }
}

// ─── production wrappers ──────────────────────────────────────────────────────

/// `true` when the default store exists and has at least one byte. The engine's
/// tier-1 force-past consults this so a baseline-enabled-but-empty store still
/// reaches the record path (so the FIRST observation can be the first-time one).
pub fn store_nonempty() -> bool {
    store_path()
        .map(|p| std::fs::metadata(&p).map(|m| m.len() > 0).unwrap_or(false))
        .unwrap_or(false)
}

/// Production lookup against the default store.
pub fn lookup(key: &PatternKey) -> SeenCount {
    match store_path() {
        Some(p) => lookup_at(&p, key),
        None => SeenCount::from_count(0),
    }
}

/// Production record against the default store.
pub fn record(key: PatternKey) -> std::io::Result<()> {
    let store = store_path().ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::NotFound,
            "cannot determine tirith state directory",
        )
    })?;
    record_at(&store, key)
}

/// Production top-N status against the default store.
pub fn status(limit: usize) -> Vec<TopPattern> {
    match store_path() {
        Some(p) => status_at(&p, limit),
        None => Vec::new(),
    }
}

/// Production in-window entry count against the default store.
pub fn entry_count() -> usize {
    match store_path() {
        Some(p) => entry_count_at(&p),
        None => 0,
    }
}

/// Production reset against the default store.
pub fn reset() -> std::io::Result<usize> {
    let store = store_path().ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::NotFound,
            "cannot determine tirith state directory",
        )
    })?;
    reset_at(&store)
}

/// Production host hash using the default salt path.
pub fn hash_host(host: &str) -> Option<String> {
    hash_host_at(&salt_path()?, host)
}

/// Production cwd/repo hash using the default salt path.
pub fn hash_cwd(cwd: Option<&str>) -> Option<String> {
    let sp = salt_path()?;
    hash_cwd_at(&sp, cwd)
}

/// The anomaly rule a [`SeenCount`] maps to, if any. `None` when the pattern is
/// common enough that no anomaly finding is warranted.
pub fn anomaly_rule(seen: SeenCount) -> Option<RuleId> {
    if seen.first_time {
        Some(RuleId::AnomalyFirstTimeInThisRepo)
    } else if seen.rare {
        Some(RuleId::AnomalyRareInBaseline)
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    fn key(rule: &str) -> PatternKey {
        PatternKey {
            rule_id: rule.to_string(),
            host_hash: Some("abc123".to_string()),
            ecosystem: None,
            sudo_flag: false,
            cwd_repo_hash: Some("deadbeef".to_string()),
        }
    }

    #[test]
    fn first_observation_is_first_time() {
        let dir = tempdir().unwrap();
        let store = store_in(dir.path());
        let k = key("curl_pipe_shell");
        let seen = lookup_at(&store, &k);
        assert_eq!(seen.count, 0);
        assert!(seen.first_time);
        assert!(!seen.rare);
        assert_eq!(anomaly_rule(seen), Some(RuleId::AnomalyFirstTimeInThisRepo));
    }

    #[test]
    fn recorded_three_times_is_not_anomalous() {
        let dir = tempdir().unwrap();
        let store = store_in(dir.path());
        let k = key("curl_pipe_shell");
        for _ in 0..3 {
            record_at(&store, k.clone()).unwrap();
        }
        let seen = lookup_at(&store, &k);
        assert_eq!(seen.count, 3);
        assert!(!seen.first_time);
        assert!(!seen.rare, "3 >= RARE_THRESHOLD, not rare");
        assert_eq!(anomaly_rule(seen), None);
    }

    #[test]
    fn recorded_once_is_rare() {
        let dir = tempdir().unwrap();
        let store = store_in(dir.path());
        let k = key("curl_pipe_shell");
        record_at(&store, k.clone()).unwrap();
        let seen = lookup_at(&store, &k);
        assert_eq!(seen.count, 1);
        assert!(!seen.first_time);
        assert!(seen.rare);
        assert_eq!(anomaly_rule(seen), Some(RuleId::AnomalyRareInBaseline));
    }

    #[test]
    fn distinct_tuples_counted_separately() {
        let dir = tempdir().unwrap();
        let store = store_in(dir.path());
        let mut k2 = key("curl_pipe_shell");
        k2.sudo_flag = true; // different tuple
        record_at(&store, key("curl_pipe_shell")).unwrap();
        record_at(&store, key("curl_pipe_shell")).unwrap();
        record_at(&store, k2.clone()).unwrap();

        assert_eq!(lookup_at(&store, &key("curl_pipe_shell")).count, 2);
        assert_eq!(lookup_at(&store, &k2).count, 1);
    }

    #[test]
    fn out_of_window_observations_are_not_counted() {
        let dir = tempdir().unwrap();
        let store = store_in(dir.path());
        // Write one old (out-of-window) and one recent observation by hand.
        let old = Observation {
            rule_id: "curl_pipe_shell".to_string(),
            host_hash: Some("abc123".to_string()),
            ecosystem: None,
            sudo_flag: false,
            cwd_repo_hash: Some("deadbeef".to_string()),
            seen_at: (chrono::Utc::now() - chrono::Duration::days(WINDOW_DAYS + 5)).to_rfc3339(),
        };
        rewrite_store(&store, &[old]).unwrap();
        // The old one is out of window → first time again.
        let seen = lookup_at(&store, &key("curl_pipe_shell"));
        assert_eq!(seen.count, 0);
        assert!(seen.first_time);
    }

    #[test]
    fn status_orders_by_count_desc() {
        let dir = tempdir().unwrap();
        let store = store_in(dir.path());
        record_at(&store, key("rule_a")).unwrap();
        record_at(&store, key("rule_b")).unwrap();
        record_at(&store, key("rule_b")).unwrap();
        record_at(&store, key("rule_b")).unwrap();

        let top = status_at(&store, 20);
        assert_eq!(top.len(), 2);
        assert_eq!(top[0].rule_id, "rule_b");
        assert_eq!(top[0].count, 3);
        assert_eq!(top[1].rule_id, "rule_a");
        assert_eq!(top[1].count, 1);
    }

    #[test]
    fn status_respects_limit() {
        let dir = tempdir().unwrap();
        let store = store_in(dir.path());
        for i in 0..5 {
            record_at(&store, key(&format!("rule_{i}"))).unwrap();
        }
        assert_eq!(status_at(&store, 3).len(), 3);
    }

    #[test]
    fn reset_zeroes_the_store() {
        let dir = tempdir().unwrap();
        let store = store_in(dir.path());
        record_at(&store, key("rule_a")).unwrap();
        record_at(&store, key("rule_a")).unwrap();
        assert_eq!(entry_count_at(&store), 2);

        let removed = reset_at(&store).unwrap();
        assert_eq!(removed, 2);
        assert_eq!(entry_count_at(&store), 0);
        assert!(lookup_at(&store, &key("rule_a")).first_time);
    }

    #[test]
    fn reset_on_absent_store_is_zero() {
        let dir = tempdir().unwrap();
        let store = store_in(dir.path());
        assert_eq!(reset_at(&store).unwrap(), 0);
    }

    #[test]
    fn salt_is_persisted_and_stable() {
        let dir = tempdir().unwrap();
        let salt_file = salt_in(dir.path());
        let h1 = hash_host_at(&salt_file, "github.com").unwrap();
        // A second call reuses the persisted salt → same hash.
        let h2 = hash_host_at(&salt_file, "github.com").unwrap();
        assert_eq!(h1, h2);
        assert!(salt_file.exists(), "salt must be persisted");
        // Host hash is 16 hex chars; never the raw host.
        assert_eq!(h1.len(), 16);
        assert!(!h1.contains("github"));
    }

    #[test]
    fn salt_file_is_32_bytes() {
        // I2 regression: the persisted salt must be exactly 32 bytes (the
        // documented length), not 16.
        let dir = tempdir().unwrap();
        let salt_file = salt_in(dir.path());
        let _ = hash_host_at(&salt_file, "github.com").unwrap();
        let bytes = std::fs::read(&salt_file).unwrap();
        assert_eq!(bytes.len(), SALT_LEN);
    }

    #[test]
    fn short_salt_file_is_regenerated() {
        // I2 regression: a truncated/short salt file (e.g. 16 bytes from an old
        // version or a crash mid-write) must be rejected and regenerated to the
        // full 32 bytes, not accepted as-is.
        let dir = tempdir().unwrap();
        let salt_file = salt_in(dir.path());
        std::fs::write(&salt_file, [0u8; 16]).unwrap();
        let h = hash_host_at(&salt_file, "github.com").unwrap();
        assert_eq!(h.len(), 16);
        assert_eq!(
            std::fs::read(&salt_file).unwrap().len(),
            SALT_LEN,
            "short salt must be regenerated to 32 bytes"
        );
    }

    #[test]
    fn host_hash_is_case_insensitive() {
        let dir = tempdir().unwrap();
        let salt_file = salt_in(dir.path());
        assert_eq!(
            hash_host_at(&salt_file, "GitHub.com"),
            hash_host_at(&salt_file, "github.com")
        );
    }

    #[test]
    fn oversized_salt_file_is_rejected_and_regenerated() {
        // CodeRabbit R11 #4: an oversized `baseline.salt` must NOT be allocated
        // whole before the length check. The capped helper refuses it (over the
        // SALT_READ_CAP), so it is treated as corrupt and OVERWRITTEN with a fresh
        // 32-byte salt — hashing still works, and the on-disk file is back to
        // SALT_LEN. We isolate the salt cache by using a unique temp path.
        let dir = tempdir().unwrap();
        let salt_file = salt_in(dir.path());
        // Far larger than SALT_READ_CAP — a naive `std::fs::read` would buffer all
        // of it; the cap refuses it before allocation.
        std::fs::write(&salt_file, vec![0u8; (SALT_READ_CAP as usize) + 4096]).unwrap();

        let h = hash_host_at(&salt_file, "github.com").expect("hash succeeds after regen");
        assert_eq!(h.len(), 16);
        assert_eq!(
            std::fs::read(&salt_file).unwrap().len(),
            SALT_LEN,
            "an oversized salt must be regenerated to exactly SALT_LEN bytes"
        );
    }

    /// CodeRabbit R11 #1: a FIFO at the salt path must NOT block the salt read.
    /// The capped helper opens with O_NONBLOCK and rejects the FIFO, so the salt
    /// is treated as corrupt and regenerated atomically (overwriting the FIFO).
    /// A regression to a blocking `std::fs::read` would HANG here. Unix-only.
    #[cfg(unix)]
    #[test]
    fn fifo_salt_does_not_hang_and_regenerates() {
        use std::ffi::CString;
        let dir = tempdir().unwrap();
        let salt_file = salt_in(dir.path());
        let c_path = CString::new(salt_file.as_os_str().to_str().unwrap()).unwrap();
        if unsafe { libc::mkfifo(c_path.as_ptr(), 0o600) } != 0 {
            eprintln!("skipping: mkfifo unsupported here");
            return;
        }
        // Must complete promptly; a blocking read on the FIFO would hang. The
        // FIFO is corrupt → the salt is regenerated (the persist path replaces it
        // atomically), so hashing returns a value and the file is now a regular
        // 32-byte salt.
        let h = hash_host_at(&salt_file, "github.com").expect("hash succeeds, no hang");
        assert_eq!(h.len(), 16);
        let meta = std::fs::metadata(&salt_file).unwrap();
        assert!(
            meta.is_file(),
            "FIFO must have been replaced by a regular file"
        );
        assert_eq!(meta.len() as usize, SALT_LEN);
    }

    #[test]
    fn different_salts_give_different_hashes() {
        let dir1 = tempdir().unwrap();
        let dir2 = tempdir().unwrap();
        let h1 = hash_host_at(&salt_in(dir1.path()), "github.com").unwrap();
        let h2 = hash_host_at(&salt_in(dir2.path()), "github.com").unwrap();
        assert_ne!(h1, h2, "per-install salt must diverge hashes");
    }

    #[test]
    fn cwd_hash_is_8_chars_and_not_raw_path() {
        let dir = tempdir().unwrap();
        let salt_file = salt_in(dir.path());
        let h = hash_cwd_at(&salt_file, Some("/home/alice/secret-project")).unwrap();
        assert_eq!(h.len(), 8);
        assert!(!h.contains("alice"));
        assert!(!h.contains("secret"));
    }

    #[test]
    fn unwritable_corrupt_salt_disables_baseline() {
        // F4 regression: when the salt is unreadable AND cannot be created
        // (parent path is a FILE, not a dir → both read and create_dir_all
        // fail), hashing returns None and the session is marked disabled —
        // instead of churning a fresh per-run salt that fires
        // AnomalyFirstTimeInThisRepo forever.
        let dir = tempdir().unwrap();
        // Make the salt's parent a regular file so create_dir_all/persist fail.
        let blocker = dir.path().join("blocker");
        std::fs::write(&blocker, b"not a dir").unwrap();
        let salt_file = blocker.join("baseline.salt");

        assert!(
            hash_host_at(&salt_file, "github.com").is_none(),
            "host hash must be None when the salt cannot be read or written"
        );
        assert!(
            matches!(*salt_state(&salt_file), SaltState::Disabled),
            "salt state must be Disabled for an unreadable+unwritable salt"
        );
    }

    #[test]
    fn corrupt_line_is_skipped_not_fatal() {
        let dir = tempdir().unwrap();
        let store = store_in(dir.path());
        // A valid, recent (in-window, NOT future-dated) observation alongside a
        // junk line and a blank line.
        let recent = chrono::Utc::now().to_rfc3339();
        std::fs::write(
            &store,
            format!(
                "not json\n{{\"rule_id\":\"curl_pipe_shell\",\"sudo_flag\":false,\"seen_at\":\"{recent}\"}}\n\n"
            ),
        )
        .unwrap();
        // The one valid in-window row counts; the junk is skipped.
        let k = PatternKey {
            rule_id: "curl_pipe_shell".to_string(),
            host_hash: None,
            ecosystem: None,
            sudo_flag: false,
            cwd_repo_hash: None,
        };
        assert_eq!(lookup_at(&store, &k).count, 1);
    }

    #[test]
    fn future_dated_observation_is_out_of_window() {
        // Greptile P2 regression: a future-dated row (clock skew / tampered
        // store) must NOT count as in-window forever.
        let dir = tempdir().unwrap();
        let store = store_in(dir.path());
        let future = (chrono::Utc::now() + chrono::Duration::days(10)).to_rfc3339();
        std::fs::write(
            &store,
            format!(
                "{{\"rule_id\":\"curl_pipe_shell\",\"sudo_flag\":false,\"seen_at\":\"{future}\"}}\n"
            ),
        )
        .unwrap();
        let k = PatternKey {
            rule_id: "curl_pipe_shell".to_string(),
            host_hash: None,
            ecosystem: None,
            sudo_flag: false,
            cwd_repo_hash: None,
        };
        assert_eq!(
            lookup_at(&store, &k).count,
            0,
            "a future-dated observation must be treated as out-of-window"
        );
    }

    #[test]
    fn observation_roundtrips_through_json() {
        let obs = Observation {
            rule_id: "curl_pipe_shell".to_string(),
            host_hash: Some("abc".to_string()),
            ecosystem: Some("npm".to_string()),
            sudo_flag: true,
            cwd_repo_hash: Some("def".to_string()),
            seen_at: "2026-01-01T00:00:00+00:00".to_string(),
        };
        let json = serde_json::to_string(&obs).unwrap();
        let back: Observation = serde_json::from_str(&json).unwrap();
        assert_eq!(obs, back);
    }
}
