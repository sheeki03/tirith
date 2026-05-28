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

use std::io::{BufRead, BufReader, Write};
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

/// Load the per-install salt from `salt_path`, generating and persisting a fresh
/// 32-byte random salt (mode `0600`) when absent. Returns the raw salt bytes.
///
/// On any I/O failure the call still returns a usable in-memory salt (generated
/// fresh) so hashing never fails the hot path; a non-persisted salt only means
/// the hashes won't be stable across processes, which is acceptable fail-open
/// behavior (worst case: a pattern looks new once more than it should).
fn load_or_create_salt(salt_file: &Path) -> Vec<u8> {
    if let Ok(bytes) = std::fs::read(salt_file) {
        if bytes.len() >= 16 {
            return bytes;
        }
    }
    // Generate a fresh 32-byte salt from the OS RNG. On the (extremely unlikely)
    // event that the OS entropy source fails, fall back to a time-derived salt
    // so hashing never aborts the hot path — fail-open, since a weak salt only
    // weakens the privacy guarantee for this one process, it never crashes.
    let mut salt = [0u8; 32];
    if getrandom::fill(&mut salt).is_err() {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        salt[..16].copy_from_slice(&nanos.to_le_bytes());
    }
    let salt = salt.to_vec();

    // Best-effort persist at 0600. A failure here is non-fatal.
    if let Some(parent) = salt_file.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    let mut opts = std::fs::OpenOptions::new();
    opts.create(true).write(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    if let Ok(mut f) = opts.open(salt_file) {
        let _ = f.write_all(&salt);
    }
    salt
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
pub fn hash_host_at(salt_file: &Path, host: &str) -> String {
    let salt = load_or_create_salt(salt_file);
    salted_hash(&salt, &host.trim().to_ascii_lowercase(), 16)
}

/// Compute the cwd/repo hash. `cwd` is resolved to its repository root (nearest
/// `.git` ancestor) in-process; when not in a repo, the cwd path is hashed
/// directly. Returns `None` only when no cwd is resolvable.
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
    let salt = load_or_create_salt(salt_file);
    Some(salted_hash(&salt, &resolved, 8))
}

// ─── store I/O ─────────────────────────────────────────────────────────────--

/// Parse the JSONL store, skipping blank / unparseable lines (fail-open).
fn parse_store(path: &Path) -> Vec<Observation> {
    let Ok(file) = std::fs::File::open(path) else {
        return Vec::new();
    };
    let reader = BufReader::new(file);
    let mut out = Vec::new();
    for line in reader.lines().map_while(Result::ok) {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        if let Ok(obs) = serde_json::from_str::<Observation>(trimmed) {
            out.push(obs);
        }
    }
    out
}

/// Parse `seen_at` to a UTC timestamp; `None` when unparseable.
fn parse_seen_at(s: &str) -> Option<chrono::DateTime<chrono::Utc>> {
    chrono::DateTime::parse_from_rfc3339(s)
        .ok()
        .map(|dt| dt.with_timezone(&chrono::Utc))
}

/// `true` when `seen_at` is within `WINDOW_DAYS` of `now`. An unparseable
/// timestamp is treated as out-of-window (dropped) so a corrupt row can't
/// inflate a count forever.
fn in_window(seen_at: &str, now: chrono::DateTime<chrono::Utc>) -> bool {
    match parse_seen_at(seen_at) {
        Some(ts) => now.signed_duration_since(ts).num_days() < WINDOW_DAYS,
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
    tmp.persist(store).map_err(|e| e.error)?;
    Ok(())
}

/// Cheap on-disk line count (number of `\n`), used to decide whether to compact.
fn line_count(store: &Path) -> usize {
    let Ok(file) = std::fs::File::open(store) else {
        return 0;
    };
    BufReader::new(file)
        .lines()
        .map_while(Result::ok)
        .filter(|l| !l.trim().is_empty())
        .count()
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
    salt_path().map(|sp| hash_host_at(&sp, host))
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
        let h1 = hash_host_at(&salt_file, "github.com");
        // A second call reuses the persisted salt → same hash.
        let h2 = hash_host_at(&salt_file, "github.com");
        assert_eq!(h1, h2);
        assert!(salt_file.exists(), "salt must be persisted");
        // Host hash is 16 hex chars; never the raw host.
        assert_eq!(h1.len(), 16);
        assert!(!h1.contains("github"));
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
    fn different_salts_give_different_hashes() {
        let dir1 = tempdir().unwrap();
        let dir2 = tempdir().unwrap();
        let h1 = hash_host_at(&salt_in(dir1.path()), "github.com");
        let h2 = hash_host_at(&salt_in(dir2.path()), "github.com");
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
    fn corrupt_line_is_skipped_not_fatal() {
        let dir = tempdir().unwrap();
        let store = store_in(dir.path());
        std::fs::write(
            &store,
            "not json\n{\"rule_id\":\"curl_pipe_shell\",\"sudo_flag\":false,\"seen_at\":\"2099-01-01T00:00:00Z\"}\n\n",
        )
        .unwrap();
        // The one valid (future-dated, in-window) row counts; the junk is skipped.
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
