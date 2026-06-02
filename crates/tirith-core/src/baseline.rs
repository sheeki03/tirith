//! M10 ch5 — per-user anomaly-detection baseline (design-decision D2).
//!
//! An OPT-IN sliding window of finding observations. When
//! `policy.baseline_enabled` is set (default **false**), the engine records one
//! observation per detection-rule firing and, before recording, checks whether
//! the pattern is new/rare — surfacing an extra **Info** anomaly finding that
//! never changes the action. When the flag is off the engine never touches this
//! store on the hot path, so a machine that never opted in pays nothing.
//!
//! # Privacy model (D2 — salted hashes, NEVER raw values)
//!
//! The store must be safe to sync or attach to a bug report, so it records NO
//! raw hostnames and NO raw paths:
//!
//! * Hostname → `sha256(salt || host)`, first 16 hex chars.
//! * cwd / repo → same salted-sha256, first 8 chars, of the repo root (nearest
//!   `.git` ancestor, resolved in-process — no `git` subprocess); cwd hashed
//!   when not in a repo.
//! * ecosystem + sudo flag — low-cardinality categoricals, stored in the clear.
//! * rule_id — the public rule name, in the clear.
//!
//! The per-install 32-byte salt (`state_dir()/baseline.salt`, mode `0600`,
//! generated on first use) never leaves the machine and is never logged, so the
//! hashes are not reversible via a rainbow table and two installs never collide.
//!
//! # Storage model
//!
//! JSONL at `state_dir()/baseline.jsonl`, one [`Observation`] per line. Bounded
//! by a 90-day window ([`WINDOW_DAYS`]) and a 100k-entry LRU cap
//! ([`MAX_ENTRIES`]); compaction runs lazily past a line-count threshold and on
//! `reset`. SQLite is the reserved backend if the linear scan ever bottlenecks.
//!
//! Every function has a `*_at(dir, …)` form taking an explicit state directory
//! so tests run against a `tempdir()` with no writes to the real `state_dir()`.

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

/// A pattern seen fewer than this many times in the window is "rare"; zero is
/// "first time". Matches the plan's "seen < 3 times" rule.
pub const RARE_THRESHOLD: u32 = 3;

/// Below this many observations, `doctor` reports "early-baseline mode" (too
/// sparse to trust anomaly signals).
pub const EARLY_BASELINE_ENTRIES: usize = 30;

/// Compact when the on-disk line count exceeds this — slightly above
/// [`MAX_ENTRIES`] so a steady-state store compacts occasionally, not every append.
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

/// Fixed salt length. A file of the wrong length (truncated, crash mid-write,
/// attacker-shrunk) is rejected and regenerated, so the 32-byte privacy
/// guarantee never silently degrades to a weak salt.
const SALT_LEN: usize = 32;

/// Read cap for the salt file (R11 #4) — generous slack over [`SALT_LEN`] so an
/// oversized `baseline.salt` is refused BEFORE allocation, not buffered whole.
const SALT_READ_CAP: u64 = 4 * 1024;

/// Per-process salt state, resolved once and cached keyed on the salt path.
enum SaltState {
    /// A usable salt (read from disk or freshly generated AND persisted).
    Ready(Vec<u8>),
    /// Salt corrupt/unreadable AND unpersistable — a fresh per-run salt would
    /// churn every hash and fire `AnomalyFirstTimeInThisRepo` forever (F4), so
    /// baseline is disabled for the session.
    Disabled,
}

/// Cache of `(salt_path, state)`; reloads only when the path differs.
static SALT_CACHE: std::sync::Mutex<Option<(PathBuf, std::sync::Arc<SaltState>)>> =
    std::sync::Mutex::new(None);

/// One-shot guard so the "baseline disabled" warning prints at most once.
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
/// Fail-open with a floor: if absent/corrupt AND unpersistable, returns
/// [`SaltState::Disabled`] (with a one-time warning) rather than an unpersisted
/// salt that would churn every hash forever (F4).
fn load_salt_state(salt_file: &Path) -> SaltState {
    let mut existing_is_corrupt = false;
    // R9 #C + R11 #1/#4: read through the race-free capped helper (O_NONBLOCK +
    // fstat of the open fd) so a FIFO/device cannot block and an oversized file
    // is not buffered whole. NotFound → generate fresh; exactly SALT_LEN → adopt;
    // any other length / non-regular / I/O error → corrupt, OVERWRITE (I2).
    match crate::util::read_regular_capped(salt_file, SALT_READ_CAP) {
        Ok(bytes) if bytes.len() == SALT_LEN => return SaltState::Ready(bytes),
        // Corrupt: remember it so persist replaces atomically rather than
        // treating `AlreadyExists` as a lost race.
        Ok(_) => existing_is_corrupt = true,
        Err(crate::util::OpenRegularError::NotFound) => {}
        Err(_) => existing_is_corrupt = true,
    }

    // Fresh 32-byte salt from the OS RNG; on entropy failure fall back to a
    // time-derived salt so hashing never aborts (fail-open — a weak salt only
    // weakens privacy for this process, never crashes).
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
            // Neither readable nor writable: a per-run salt would make every
            // pattern look new forever, so disable baseline this session (F4).
            warn_baseline_disabled_once(salt_file);
            SaltState::Disabled
        }
    }
}

/// Install `salt` at `salt_file` (mode `0600`) and return the salt now ON DISK.
///
/// * `replace_corrupt == false` (absent): claim it exclusively with
///   `create_new`; if another process won the race, ADOPT its salt rather than
///   clobber it, so two co-starting processes never diverge.
/// * `replace_corrupt == true` (wrong-length): overwrite atomically via temp +
///   rename (I2) so a short salt is regenerated, not adopted.
///
/// Both paths are crash-durable: a mid-write crash never leaves a half-written
/// salt, and both fsync the body AND the parent directory.
fn persist_salt(salt_file: &Path, salt: &[u8], replace_corrupt: bool) -> std::io::Result<Vec<u8>> {
    if let Some(parent) = salt_file.parent() {
        std::fs::create_dir_all(parent)?;
    }

    if replace_corrupt {
        // Atomic overwrite. Resolve a symlinked path to its real target so the
        // rewrite writes THROUGH the link (R13b); the temp must live in the
        // target's dir for the rename to stay atomic.
        let dest = crate::util::resolve_symlink_target(salt_file);
        let dir = dest.parent().unwrap_or_else(|| Path::new("."));
        let mut tmp = tempfile::NamedTempFile::new_in(dir)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            tmp.as_file()
                .set_permissions(std::fs::Permissions::from_mode(0o600))?;
        }
        tmp.write_all(salt)?;
        // Durability (R9 #B): fsync the body BEFORE the rename publishes it, then
        // fsync the parent dir so the rename's directory entry is durable too.
        tmp.as_file().sync_all()?;
        tmp.persist(&dest).map_err(|e| e.error)?;
        crate::util::fsync_parent_dir_logged(&dest, "baseline salt");
        return Ok(salt.to_vec());
    }

    // Absent file: claim it exclusively so concurrent first-use does not diverge.
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
            // Durability (R12 #C): fsync the body, then the parent dir so the
            // freshly-created file's directory entry survives a crash — without
            // it the next run would regenerate a DIFFERENT salt.
            f.sync_all()?;
            crate::util::fsync_parent_dir_logged(salt_file, "baseline salt");
            Ok(salt.to_vec())
        }
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
            // Lost the race — adopt the winner's salt.
            adopt_concurrent_salt(salt_file)
        }
        Err(e) => Err(e),
    }
}

/// Bounded re-read budget for adopting a concurrently-created salt: the race
/// winner creates a 0-byte file and only THEN writes the salt, so a loser may
/// see a short file. Retrying briefly keeps a transient race from disabling
/// baseline. ~100 ms worst case, only on the rare losing side.
const SALT_ADOPT_ATTEMPTS: usize = 10;
const SALT_ADOPT_BACKOFF: std::time::Duration = std::time::Duration::from_millis(10);

/// Read the salt written by the `create_new` race winner, tolerating the brief
/// created-but-not-yet-written window (R13 #J). Reads through the race-free
/// capped helper (R11 #1). A short read is retried; a wrong-but-stable length,
/// non-regular file, or exhausted retries errors so the caller disables baseline
/// (never adopts a wrong salt).
fn adopt_concurrent_salt(salt_file: &Path) -> std::io::Result<Vec<u8>> {
    for attempt in 0..SALT_ADOPT_ATTEMPTS {
        match crate::util::read_regular_capped(salt_file, SALT_READ_CAP) {
            Ok(bytes) if bytes.len() == SALT_LEN => return Ok(bytes),
            // Short/empty: winner not done writing yet — retry (not after the last).
            Ok(bytes) if bytes.len() < SALT_LEN => {
                if attempt + 1 < SALT_ADOPT_ATTEMPTS {
                    std::thread::sleep(SALT_ADOPT_BACKOFF);
                }
            }
            // Longer than a salt is genuinely corrupt, not a partial write.
            Ok(_) => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "concurrent salt file is corrupt",
                ));
            }
            Err(crate::util::OpenRegularError::Io(e)) => return Err(e),
            Err(_) => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "concurrent salt file is not a usable regular file",
                ));
            }
        }
    }
    // Only short reads: the winner never completed (e.g. crashed mid-write).
    Err(std::io::Error::new(
        std::io::ErrorKind::InvalidData,
        "concurrent salt file did not reach full length",
    ))
}

fn warn_baseline_disabled_once(salt_file: &Path) {
    use std::sync::atomic::Ordering;
    if !SALT_WARNED.swap(true, Ordering::Relaxed) {
        // Write fallibly so a closed/broken stderr cannot panic this helper
        // (R22 #4) — `eprintln!` would.
        let _ = writeln!(
            std::io::stderr(),
            "tirith: WARNING: baseline salt at {} is unreadable and could not be \
             written; anomaly baseline is disabled for this session (run \
             `tirith doctor` to diagnose the state directory).",
            salt_file.display()
        );
    }
}

/// `true` when baseline is disabled this session (salt neither readable nor
/// writable). The engine skips the whole baseline block rather than emit
/// perpetual false `first-time` anomalies (F4).
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
    // `read_store_lines` skips blank/recoverable-bad lines and breaks on a
    // persistent read error (never spins); we then drop unparseable lines.
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

/// `true` when `seen_at` is within `WINDOW_DAYS` of `now`. Unparseable or
/// FUTURE-dated rows (clock skew / tampered store — negative age) are dropped so
/// a corrupt row can't stay permanently in-window and crowd out real entries.
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
    obs.retain(|o| in_window(&o.seen_at, now));
    // LRU cap: keep the newest MAX_ENTRIES (sort oldest→newest by seen_at).
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

/// Atomically rewrite the store to exactly the given pre-serialized JSONL lines
/// (temp file + rename, so a crash never truncates). The line-preserving
/// primitive compaction uses so an unparseable line survives VERBATIM (R12 #F).
fn rewrite_store_lines(store: &Path, lines: &[String]) -> std::io::Result<()> {
    // Resolve a symlinked store to its real target so the rewrite writes THROUGH
    // the link, not replacing it with a regular file (R13b).
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
    // Durability (R9 #B): fsync the body BEFORE the rename, then the parent dir
    // so the rename's directory entry is durable too.
    tmp.flush()?;
    tmp.as_file().sync_all()?;
    tmp.persist(&dest).map_err(|e| e.error)?;
    crate::util::fsync_parent_dir_logged(&dest, "baseline store");
    Ok(())
}

/// Cheap on-disk line count, used to decide whether to compact. Skips
/// unreadable lines rather than stopping early, so a bad byte cannot starve the
/// compaction trigger (unbounded growth).
fn line_count(store: &Path) -> usize {
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

/// Record `key` as a new observation: append one line, then compact past the
/// line-count trigger so the file stays bounded.
///
/// CROSS-PROCESS LOCK (R13f): append + (conditional) compaction run under the
/// shared [`crate::canary::StoreLock`] for the whole sequence — without it, a
/// concurrent compaction (a rewrite from a pre-append snapshot) could silently
/// drop the append and undercount the baseline. Degrades to best-effort where
/// advisory locking is absent (the atomic rewrite still prevents torn files).
pub fn record_at(store: &Path, key: PatternKey) -> std::io::Result<()> {
    let _lock = crate::canary::StoreLock::acquire(store)?;
    let obs = key.into_observation();
    append_observation(store, &obs)?;
    if line_count(store) > COMPACT_TRIGGER {
        compact_store_at(store, chrono::Utc::now())?;
    }
    Ok(())
}

/// Compact in place: window-prune + LRU-cap the PARSED observations and
/// atomically rewrite. Factored out of [`record_at`] so the data-preservation
/// contract is testable without writing >100k lines.
///
/// Lossy for PARSED rows, but a valid-but-momentarily-unparseable line (future
/// schema field, transient hiccup) is carried THROUGH the rewrite VERBATIM
/// (R12 #F) — strictly safer than deleting a real observation that failed to
/// parse once.
fn compact_store_at(store: &Path, now: chrono::DateTime<chrono::Utc>) -> std::io::Result<()> {
    // PARTIAL-READ GUARD (R13 #1): compaction rewrites from the lines just read,
    // so an incomplete read (a real mid-file I/O fault) would PERMANENTLY DROP
    // the unread tail — skip compaction and leave the store intact; the append
    // already succeeded and the next `record_at` retries. RAW (untrimmed) read
    // (R15 #3) so a preserved unparseable line keeps its whitespace.
    let (lines, complete) = crate::util::read_store_lines_raw_complete(store);
    if !complete {
        return Ok(());
    }
    let mut parsed: Vec<Observation> = Vec::new();
    let mut preserved: Vec<String> = Vec::new();
    for line in lines {
        match serde_json::from_str::<Observation>(&line) {
            Ok(o) => parsed.push(o),
            Err(_) => preserved.push(line),
        }
    }
    let compacted = compact(parsed, now);
    let mut out_lines: Vec<String> = Vec::with_capacity(compacted.len() + preserved.len());
    for o in &compacted {
        out_lines.push(serde_json::to_string(o).map_err(std::io::Error::other)?);
    }
    out_lines.extend(preserved);
    rewrite_store_lines(store, &out_lines)
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

/// Zero the store by removing the JSONL file (the salt is left in place — re-use
/// keeps cleared hashes stable, removal gains no privacy). Returns the count
/// removed.
pub fn reset_at(store: &Path) -> std::io::Result<usize> {
    let removed = line_count(store);
    match std::fs::remove_file(store) {
        Ok(()) => Ok(removed),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(0),
        Err(e) => Err(e),
    }
}

// ─── production wrappers ──────────────────────────────────────────────────────

/// `true` when the default store exists and is non-empty. The engine's tier-1
/// force-past consults this so an enabled-but-empty store still reaches the
/// record path (the FIRST observation can be the first-time one).
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

    /// R13 #1: an incomplete read must SKIP compaction rather than truncate the
    /// store. A FIFO is reported incomplete, so compaction is a no-op and the
    /// FIFO is left intact. Unix-only; cannot hang (O_NONBLOCK).
    #[cfg(unix)]
    #[test]
    fn compact_skips_on_incomplete_read_no_truncation() {
        use std::ffi::CString;
        use std::os::unix::fs::FileTypeExt;
        let dir = tempdir().unwrap();
        let store = store_in(dir.path());
        let c_path = CString::new(store.as_os_str().to_str().unwrap()).unwrap();
        if unsafe { libc::mkfifo(c_path.as_ptr(), 0o600) } != 0 {
            eprintln!("skipping: mkfifo unsupported here");
            return;
        }
        // Must be a no-op and must NOT rewrite the FIFO into a regular file.
        compact_store_at(&store, chrono::Utc::now()).expect("incomplete read skips, returns Ok");
        assert!(
            std::fs::symlink_metadata(&store)
                .unwrap()
                .file_type()
                .is_fifo(),
            "the store must NOT be replaced by a regular file (no truncating rewrite)"
        );
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
        k2.sudo_flag = true;
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
        // One old (out-of-window) observation by hand.
        let old = Observation {
            rule_id: "curl_pipe_shell".to_string(),
            host_hash: Some("abc123".to_string()),
            ecosystem: None,
            sudo_flag: false,
            cwd_repo_hash: Some("deadbeef".to_string()),
            seen_at: (chrono::Utc::now() - chrono::Duration::days(WINDOW_DAYS + 5)).to_rfc3339(),
        };
        rewrite_store_lines(&store, &[serde_json::to_string(&old).unwrap()]).unwrap();
        // Out of window → first time again.
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
    fn compaction_preserves_unparseable_lines_and_prunes_parsed() {
        // R12 #F: compaction window-prunes PARSED rows without dropping an
        // unparseable line. Hand-build a store with one in-window obs, one
        // out-of-window (pruned), and one unparseable line (preserved verbatim).
        let dir = tempdir().unwrap();
        let store = store_in(dir.path());
        let now = chrono::Utc::now();

        let in_window_obs = Observation {
            rule_id: "rule_keep".to_string(),
            host_hash: None,
            ecosystem: None,
            sudo_flag: false,
            cwd_repo_hash: None,
            seen_at: now.to_rfc3339(),
        };
        let old_obs = Observation {
            rule_id: "rule_old".to_string(),
            host_hash: None,
            ecosystem: None,
            sudo_flag: false,
            cwd_repo_hash: None,
            seen_at: (now - chrono::Duration::days(WINDOW_DAYS + 5)).to_rfc3339(),
        };
        let unknown =
            r#"{"schema":"v2","rule_id":"future","seen_at":"2026-01-01T00:00:00Z","extra":true}"#;
        {
            use std::io::Write as _;
            let mut f = std::fs::File::create(&store).unwrap();
            writeln!(f, "{}", serde_json::to_string(&in_window_obs).unwrap()).unwrap();
            writeln!(f, "{}", serde_json::to_string(&old_obs).unwrap()).unwrap();
            writeln!(f, "{unknown}").unwrap();
        }
        // The unknown line is NOT a parseable Observation (it parses if it happens
        // to match; assert it does not so the test is meaningful).
        assert_eq!(
            parse_store(&store).len(),
            2,
            "only the two real observations parse; the v2 line is skipped"
        );

        compact_store_at(&store, now).unwrap();

        let on_disk = std::fs::read_to_string(&store).unwrap();
        // Out-of-window parsed row pruned…
        assert!(
            !on_disk.contains("rule_old"),
            "out-of-window observation must be pruned, got:\n{on_disk}"
        );
        // …in-window parsed row kept…
        assert!(
            on_disk.contains("rule_keep"),
            "in-window observation must be kept, got:\n{on_disk}"
        );
        // …and the unparseable line PRESERVED verbatim.
        assert!(
            on_disk.contains(unknown),
            "compaction must preserve the unparseable line, got:\n{on_disk}"
        );
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

    /// R12 #C: the first-create (absent-file) `persist_salt` path is crash-durable
    /// like the overwrite path (fsyncs body + parent dir). fsync isn't observable,
    /// but this proves the salt persists exactly. A nested dir forces the
    /// parent-dir creation + fsync path.
    #[test]
    fn persist_salt_first_create_persists_exactly_and_is_durable() {
        let dir = tempdir().unwrap();
        // Nested, not-yet-existing parent → create_dir_all + parent fsync run.
        let salt_file = dir.path().join("nested").join("salt.bin");
        let salt = [7u8; SALT_LEN];

        let written = persist_salt(&salt_file, &salt, /* replace_corrupt */ false).unwrap();
        assert_eq!(
            written,
            salt.to_vec(),
            "first create returns the salt it wrote"
        );

        let on_disk = std::fs::read(&salt_file).unwrap();
        assert_eq!(on_disk, salt.to_vec(), "salt is persisted byte-for-byte");
        assert_eq!(on_disk.len(), SALT_LEN);

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&salt_file).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600, "fresh salt must be created mode 0600");
        }
    }

    #[test]
    fn adopt_concurrent_salt_accepts_complete_file() {
        // A salt the winner has fully written is adopted on the first read.
        let dir = tempdir().unwrap();
        let salt_file = salt_in(dir.path());
        let full = [3u8; SALT_LEN];
        std::fs::write(&salt_file, full).unwrap();
        assert_eq!(adopt_concurrent_salt(&salt_file).unwrap(), full.to_vec());
    }

    #[test]
    fn adopt_concurrent_salt_rejects_oversized_without_retrying() {
        // A file LONGER than a salt is corrupt, not a partial write, so adopt
        // fails immediately (no retry burned; the capped helper refuses it).
        let dir = tempdir().unwrap();
        let salt_file = salt_in(dir.path());
        std::fs::write(&salt_file, vec![0u8; (SALT_READ_CAP as usize) + 4096]).unwrap();
        let err = adopt_concurrent_salt(&salt_file).expect_err("oversized salt is corrupt");
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
    }

    #[test]
    fn adopt_concurrent_salt_waits_for_in_progress_write() {
        // R13 #J: the race loser must not declare the salt corrupt while the
        // winner is mid-write. A background writer completes within the retry
        // budget; adopt must RETRY and return the completed salt.
        let dir = tempdir().unwrap();
        let salt_file = salt_in(dir.path());
        let full = [9u8; SALT_LEN];
        // The winner created the file and wrote only a short prefix so far.
        std::fs::write(&salt_file, &full[..8]).unwrap();

        let writer_path = salt_file.clone();
        let handle = std::thread::spawn(move || {
            std::thread::sleep(std::time::Duration::from_millis(20));
            std::fs::write(&writer_path, full).unwrap();
        });
        let adopted = adopt_concurrent_salt(&salt_file)
            .expect("adopt must wait for the in-progress write, not fail");
        handle.join().unwrap();
        assert_eq!(adopted, full.to_vec(), "adopt returns the completed salt");
    }

    #[test]
    fn salt_file_is_32_bytes() {
        // I2 regression: the persisted salt must be exactly 32 bytes, not 16.
        let dir = tempdir().unwrap();
        let salt_file = salt_in(dir.path());
        let _ = hash_host_at(&salt_file, "github.com").unwrap();
        let bytes = std::fs::read(&salt_file).unwrap();
        assert_eq!(bytes.len(), SALT_LEN);
    }

    #[test]
    fn short_salt_file_is_regenerated() {
        // I2 regression: a truncated/short salt file must be rejected and
        // regenerated to the full 32 bytes, not accepted as-is.
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
        // R11 #4: an oversized `baseline.salt` is refused by the capped helper
        // before allocation, treated as corrupt, and OVERWRITTEN with a fresh
        // 32-byte salt. Unique temp path isolates the salt cache.
        let dir = tempdir().unwrap();
        let salt_file = salt_in(dir.path());
        std::fs::write(&salt_file, vec![0u8; (SALT_READ_CAP as usize) + 4096]).unwrap();

        let h = hash_host_at(&salt_file, "github.com").expect("hash succeeds after regen");
        assert_eq!(h.len(), 16);
        assert_eq!(
            std::fs::read(&salt_file).unwrap().len(),
            SALT_LEN,
            "an oversized salt must be regenerated to exactly SALT_LEN bytes"
        );
    }

    #[cfg(unix)]
    #[test]
    fn corrupt_salt_regen_through_symlink_updates_target_not_link() {
        // R13b: the corrupt-salt rewrite must write THROUGH a symlinked path to
        // the real target, not replace the symlink. Seed a short (corrupt) salt
        // at the target, symlink to it, regenerate via hashing.
        use std::os::unix::fs::symlink;
        let dir = tempdir().unwrap();
        let target_dir = dir.path().join("real");
        std::fs::create_dir_all(&target_dir).unwrap();
        let target = target_dir.join("baseline.salt");
        std::fs::write(&target, [0u8; 16]).unwrap(); // wrong length → corrupt → regen

        let link = dir.path().join("baseline.salt");
        symlink(&target, &link).unwrap();

        let h = hash_host_at(&link, "github.com").expect("hash succeeds after regen");
        assert_eq!(h.len(), 16);
        // The symlink is intact (still a symlink to the target)...
        assert!(
            std::fs::symlink_metadata(&link)
                .unwrap()
                .file_type()
                .is_symlink(),
            "the salt symlink must be preserved, not replaced by a regular file"
        );
        // ...and the regenerated 32-byte salt landed in the TARGET, through the link.
        assert_eq!(
            std::fs::read(&target).unwrap().len(),
            SALT_LEN,
            "the fresh salt must be written through the link into the real target"
        );
    }

    /// R11 #1: a FIFO at the salt path must NOT block the read. The capped helper
    /// (O_NONBLOCK) rejects it, so the salt is regenerated atomically. A blocking
    /// `std::fs::read` regression would HANG here. Unix-only.
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
        // Must complete promptly (a blocking read would hang); the FIFO is
        // regenerated into a regular 32-byte salt.
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
        // F4 regression: when the salt is unreadable AND unwritable (parent is a
        // FILE), hashing returns None and the session is disabled — instead of
        // churning a per-run salt that fires AnomalyFirstTimeInThisRepo forever.
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
        // A valid recent observation alongside a junk line and a blank line.
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
        // Greptile P2 regression: a future-dated row (clock skew / tampered store)
        // must NOT count as in-window forever.
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
