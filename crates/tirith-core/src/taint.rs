//! M10 ch3 — tainted-content tracking.
//!
//! A *taint* records that a file was written from a risky source (a download
//! from an untrusted URL, an `install <url>` payload). The mark persists in a
//! JSONL store at `state_dir()/taint.jsonl` so a later `bash ./install.sh` fires
//! [`crate::verdict::RuleId::ExecOfTaintedFile`] and `source ./tainted.sh` fires
//! [`crate::verdict::RuleId::CommandSourcedFromTaintedFile`].
//!
//! Limitations / design (v1):
//! * **Path-keyed, not inode-keyed** — the key is the absolute, lexically-
//!   normalized path, so `mv ./install.sh ./run.sh` LOSES the mark. Inode
//!   tracking is fragile across filesystems / write-rename editors and the
//!   threat model is dominated by `download → execute-by-the-same-path`.
//! * **JSONL backend** — one object per line; the public API
//!   (`mark_tainted` / `is_tainted` / `list_taints` / `clear_taint`) is the
//!   migration boundary if a future workload needs SQLite.
//! * **Hot-path cost** — [`is_tainted`] runs once per exec-leader, backed by a
//!   per-process cache (5s TTL, mtime-invalidated). The engine only forces past
//!   tier-1 for the taint check when the store is non-empty, so a machine that
//!   never ran `tirith fetch --save` pays nothing.
//! * **Never auto-cleared** — `chmod +x` / `bash -n` do NOT clear a mark; only
//!   an explicit [`clear_taint`] (`tirith taint clear <file>`) does.

use std::io::Write;
use std::path::{Component, Path, PathBuf};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};

/// One recorded taint: a file written from a risky source.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TaintEntry {
    /// Absolute, lexically-normalized path of the tainted file (the store key).
    pub path: String,
    /// Where the taint came from — a short label, e.g. `"fetch --save"`,
    /// `"install <url>"`. Free-form; used only for display in
    /// `tirith taint list|explain`.
    pub origin: String,
    /// RFC-3339 UTC timestamp the mark was recorded.
    pub marked_at: String,
    /// The source URL the content was downloaded from, when known.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_url: Option<String>,
    /// The source git repository, when known (e.g. from a `tirith run` receipt's
    /// `git_repo`). Distinct from `source_url`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_repo: Option<String>,
}

/// Default on-disk store path: `state_dir()/taint.jsonl`.
pub fn store_path() -> Option<PathBuf> {
    crate::policy::state_dir().map(|d| d.join("taint.jsonl"))
}

/// Lexically normalize a path to an absolute key WITHOUT touching the filesystem
/// (no `canonicalize` — the file may not exist yet at `mark` time, and both
/// `mark` and `is_tainted` must compute the SAME key). Resolves `.`/`..`,
/// prefixes relative paths with `cwd` (else process cwd); symlinks NOT resolved.
pub fn normalize_key(path: &Path, cwd: Option<&Path>) -> PathBuf {
    let base: PathBuf = if path.is_absolute() {
        PathBuf::new()
    } else {
        cwd.map(PathBuf::from)
            .or_else(|| std::env::current_dir().ok())
            .unwrap_or_default()
    };

    let mut out = base;
    for comp in path.components() {
        match comp {
            Component::CurDir => {}
            Component::ParentDir => {
                out.pop();
            }
            Component::Prefix(p) => {
                // Windows drive/UNC prefix seeds `out` (no-op on Unix).
                out = PathBuf::from(p.as_os_str());
            }
            Component::RootDir => {
                // Append (not replace) the root anchor so Windows `C:` + `\`
                // stays `C:\`; on Unix this turns empty `out` into `/`. Matches
                // cargo's `normalize_path` ordering.
                out.push(comp.as_os_str());
            }
            Component::Normal(seg) => out.push(seg),
        }
    }
    out
}

/// Per-process cache of the parsed store, keyed on the resolved store path.
struct CacheState {
    path: PathBuf,
    entries: Vec<TaintEntry>,
    /// `false` when the read did not reach EOF (mid-file I/O fault or unreadable
    /// store), so `entries` is a PARTIAL prefix — a miss is NOT "not tainted"
    /// (CodeRabbit R16 #3, fail-safe).
    complete: bool,
    loaded_at: Instant,
    /// `present` is tracked apart from `mtime_nanos` so an absent store and a
    /// present-but-unstattable one are never conflated (see [`stat_signature`]).
    existed: bool,
    mtime_nanos: u128,
}

static CACHE: Mutex<Option<CacheState>> = Mutex::new(None);

const CACHE_TTL: Duration = Duration::from_secs(5);

/// Cache-invalidation stat for the store path: `(present, mtime_nanos)`.
///
/// FAIL-SAFE + symlink-aware (CodeRabbit R13b): `symlink_metadata` (lstat) so a
/// planted symlink reads as present, and ONLY a genuine `NotFound` maps to absent
/// `(false, 0)`. Every other stat error maps to present `(true, 0)` so it busts
/// the cache and forces a re-read that fails safe via [`is_tainted_at`].
fn stat_signature(path: &Path) -> (bool, u128) {
    match std::fs::symlink_metadata(path) {
        Ok(m) => {
            let nanos = m
                .modified()
                .ok()
                .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
                .map(|d| d.as_nanos())
                .unwrap_or(0);
            (true, nanos)
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => (false, 0),
        Err(_) => (true, 0),
    }
}

/// Parse the JSONL store, skipping blank/unparseable lines (fail-open). Returns
/// `(entries, complete)`. `complete == false` means the read did NOT reach EOF
/// (a partial prefix); a skipped invalid-UTF-8 line is NOT a truncation and keeps
/// `complete == true`. [`is_tainted_at`] fails safe on an incomplete read
/// (CodeRabbit R16 #3): a miss against a partial prefix is "unknown", not "clean".
fn parse_store(path: &Path) -> (Vec<TaintEntry>, bool) {
    let (lines, complete) = crate::util::read_store_lines_complete(path);
    let entries = lines
        .iter()
        .filter_map(|line| serde_json::from_str::<TaintEntry>(line).ok())
        .collect();
    (entries, complete)
}

/// Load entries through the per-process cache (reloads on path change, TTL
/// expiry, or mtime change). `complete == false` flags a partial read so the
/// lookup can fail safe (CodeRabbit R16 #3).
fn cached_entries(path: &Path) -> (Vec<TaintEntry>, bool) {
    let mut guard = CACHE.lock().unwrap_or_else(|e| e.into_inner());
    let now = Instant::now();
    let (existed, cur_mtime) = stat_signature(path);

    if let Some(state) = guard.as_ref() {
        let fresh = state.path == path
            && now.duration_since(state.loaded_at) < CACHE_TTL
            && state.existed == existed
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
        existed,
        mtime_nanos: cur_mtime,
    });
    (entries, complete)
}

/// Drop the per-process cache. Tests that write a store directly call this; the
/// engine relies on mtime + TTL invalidation instead.
pub fn invalidate_cache() {
    let mut guard = CACHE.lock().unwrap_or_else(|e| e.into_inner());
    *guard = None;
}

/// Append `entry` to the JSONL store (creating parent dirs + the `0600` file).
/// A prior entry for the same path is left in place — `is_tainted` returns the
/// LAST match, so an append is an effective update.
fn append_entry(store: &Path, entry: &TaintEntry) -> std::io::Result<()> {
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

/// Mark `path` tainted in the store at `store`. `cwd` controls relative-path
/// normalization (`None` = process cwd). Returns the recorded [`TaintEntry`].
pub fn mark_tainted_at(
    store: &Path,
    path: &Path,
    cwd: Option<&Path>,
    origin: impl Into<String>,
    source_url: Option<String>,
    source_repo: Option<String>,
) -> std::io::Result<TaintEntry> {
    let key = normalize_key(path, cwd);
    let entry = TaintEntry {
        path: key.to_string_lossy().into_owned(),
        origin: origin.into(),
        marked_at: chrono::Utc::now().to_rfc3339(),
        source_url,
        source_repo,
    };
    append_entry(store, &entry)?;
    invalidate_cache();
    Ok(entry)
}

/// Production entry point: mark `path` tainted in the default store.
pub fn mark_tainted(
    path: &Path,
    origin: impl Into<String>,
    source_url: Option<String>,
    source_repo: Option<String>,
) -> std::io::Result<TaintEntry> {
    let store = store_path().ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::NotFound,
            "cannot determine tirith state directory",
        )
    })?;
    mark_tainted_at(&store, path, None, origin, source_url, source_repo)
}

/// Origin label on the synthetic [`TaintEntry`] returned when the store could
/// not be read completely and the queried path was absent from the prefix.
pub const UNKNOWN_TAINT_ORIGIN: &str =
    "taint store could not be read completely — treated as tainted (fail-safe)";

/// Look up `path` in the store (cached). Returns the LAST entry for the
/// normalized key, or `None` if not tainted. `cwd` controls normalization.
///
/// FAIL-SAFE ON A TRUNCATED READ (CodeRabbit R16 #3): an incomplete read yields
/// only a PREFIX, so a miss for a path in the unread tail would read "not
/// tainted" (fail-OPEN). When the read was INCOMPLETE and the key is absent we
/// return a synthetic [`UNKNOWN_TAINT_ORIGIN`] entry (not `None`) plus a stderr
/// diagnostic, so the check errs toward "tainted". A hit is returned as-is; a
/// COMPLETE read (incl. one that skipped a recoverable invalid-UTF-8 line) keeps
/// the prior semantics — a miss is a clean `None`.
pub fn is_tainted_at(store: &Path, path: &Path, cwd: Option<&Path>) -> Option<TaintEntry> {
    let key = normalize_key(path, cwd);
    let key_str = key.to_string_lossy();
    let (entries, complete) = cached_entries(store);
    if let Some(found) = entries.into_iter().rev().find(|e| e.path == key_str) {
        return Some(found);
    }
    if !complete {
        // Incomplete read + miss → taint state UNKNOWN, not proven-clean: fail
        // safe with a synthetic entry and warn once (rate-limited).
        warn_incomplete_store_once(store);
        return Some(unknown_taint_entry(&key_str));
    }
    None
}

/// Synthetic [`TaintEntry`] for the fail-safe "store unreadable, taint unknown"
/// case: the queried `path` plus a labelled origin, no source fields.
fn unknown_taint_entry(path: &str) -> TaintEntry {
    TaintEntry {
        path: path.to_string(),
        origin: UNKNOWN_TAINT_ORIGIN.to_string(),
        marked_at: chrono::Utc::now().to_rfc3339(),
        source_url: None,
        source_repo: None,
    }
}

/// Stderr diagnostic when a lookup runs against an INCOMPLETELY read store,
/// de-duplicated per `(path, mtime)`. The result is fail-safe regardless; this
/// just tells the operator why an unmarked path is being flagged.
fn warn_incomplete_store_once(store: &Path) {
    static LAST_WARNED: Mutex<Option<(PathBuf, u128)>> = Mutex::new(None);
    let mtime = stat_signature(store).1;
    let mut guard = LAST_WARNED.lock().unwrap_or_else(|e| e.into_inner());
    let key = (store.to_path_buf(), mtime);
    if guard.as_ref() == Some(&key) {
        return;
    }
    *guard = Some(key);
    // Write fallibly so a closed stderr cannot panic this helper (CodeRabbit R22 #4).
    let _ = writeln!(
        std::io::stderr(),
        "tirith: warning: taint store {} could not be read completely; \
         treating unresolved paths as tainted (fail-safe)",
        store.display()
    );
}

/// Stderr diagnostic when `list_taints_at` builds output from an INCOMPLETELY
/// read store (CodeRabbit R18 #5), de-duplicated per `(path, mtime)`. The wording
/// is LIST-specific (may be truncated) and uses a SEPARATE rate-limit static from
/// [`warn_incomplete_store_once`] so neither warning suppresses the other.
fn warn_incomplete_list_once(store: &Path) {
    static LAST_WARNED: Mutex<Option<(PathBuf, u128)>> = Mutex::new(None);
    let mtime = stat_signature(store).1;
    let mut guard = LAST_WARNED.lock().unwrap_or_else(|e| e.into_inner());
    let key = (store.to_path_buf(), mtime);
    if guard.as_ref() == Some(&key) {
        return;
    }
    *guard = Some(key);
    let _ = writeln!(
        std::io::stderr(),
        "tirith: warning: taint store {} could not be read completely; \
         the listing below may be truncated (some taints may be missing)",
        store.display()
    );
}

/// Production entry point: look up `path` in the default store.
pub fn is_tainted(path: &Path, cwd: Option<&Path>) -> Option<TaintEntry> {
    let store = store_path()?;
    is_tainted_at(&store, path, cwd)
}

/// `true` when the store exists and is non-empty. The engine uses this (a cheap
/// stat, no parse) to decide whether to force past the tier-1 fast-exit.
pub fn store_nonempty_at(store: &Path) -> bool {
    std::fs::metadata(store)
        .map(|m| m.len() > 0)
        .unwrap_or(false)
}

/// Production entry point for the engine's tier-1 force-past decision.
pub fn store_nonempty() -> bool {
    store_path().map(|p| store_nonempty_at(&p)).unwrap_or(false)
}

/// List all taints in the store, de-duplicated by path (LAST entry per path
/// wins, mirroring [`is_tainted_at`]), ordered by first appearance.
pub fn list_taints_at(store: &Path) -> Vec<TaintEntry> {
    // Display path: an incomplete read yields a partial prefix — we list what we
    // could read (the lookup path is the one that fails safe). A silent
    // truncation would hide taints, so warn (CodeRabbit R18 #5).
    let (entries, complete) = parse_store(store);
    if !complete {
        warn_incomplete_list_once(store);
    }
    let mut order: Vec<String> = Vec::new();
    let mut latest: std::collections::HashMap<String, TaintEntry> =
        std::collections::HashMap::new();
    for entry in entries {
        if !latest.contains_key(&entry.path) {
            order.push(entry.path.clone());
        }
        latest.insert(entry.path.clone(), entry);
    }
    order
        .into_iter()
        .filter_map(|p| latest.remove(&p))
        .collect()
}

/// Production entry point: list all taints in the default store.
pub fn list_taints() -> Vec<TaintEntry> {
    match store_path() {
        Some(p) => list_taints_at(&p),
        None => Vec::new(),
    }
}

/// Remove every entry for `path` by rewriting the store without the matching
/// lines. `cwd` controls normalization. Returns the count removed.
///
/// REWRITE DATA-SAFETY (CodeRabbit R12 #F): compaction operates on RAW lines so a
/// valid-but-unparseable line (a future schema field) is PRESERVED VERBATIM — a
/// line is dropped ONLY when it parses as a `TaintEntry` matching the key.
pub fn clear_taint_at(store: &Path, path: &Path, cwd: Option<&Path>) -> std::io::Result<usize> {
    let key = normalize_key(path, cwd);
    let key_str = key.to_string_lossy().into_owned();

    // PARTIAL-READ GUARD (CodeRabbit R13 #1): rewriting from a truncated prefix
    // would permanently drop the unread tail — including still-live markers for
    // OTHER paths (a security miss). On an incomplete read, ABORT rather than
    // truncate. RAW (untrimmed) read (CodeRabbit R15 #3) keeps unknown lines'
    // whitespace intact; serde tolerates it for parseable entries.
    let (lines, complete) = crate::util::read_store_lines_raw_complete(store);
    if !complete {
        return Err(std::io::Error::other(
            "taint store could not be read completely; clear aborted to avoid truncating it",
        ));
    }
    let mut removed = 0usize;
    let mut kept_lines: Vec<String> = Vec::new();
    for line in lines {
        // Drop only a TaintEntry matching the key; keep unparseable lines verbatim.
        match serde_json::from_str::<TaintEntry>(&line) {
            Ok(entry) if entry.path == key_str => removed += 1,
            _ => kept_lines.push(line),
        }
    }

    if removed == 0 {
        return Ok(0);
    }

    rewrite_store_lines(store, &kept_lines)?;
    invalidate_cache();
    Ok(removed)
}

/// Production entry point: clear every taint for `path` from the default store.
pub fn clear_taint(path: &Path, cwd: Option<&Path>) -> std::io::Result<usize> {
    let store = store_path().ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::NotFound,
            "cannot determine tirith state directory",
        )
    })?;
    clear_taint_at(&store, path, cwd)
}

/// Atomically rewrite the store to exactly the given pre-serialized JSONL `lines`
/// (temp file + rename, so a crash mid-write never truncates). The line-preserving
/// primitive `clear_taint_at` uses to write back RAW lines without round-tripping
/// through serde (CodeRabbit R12 #F).
fn rewrite_store_lines(store: &Path, lines: &[String]) -> std::io::Result<()> {
    // Resolve a symlinked store so the rewrite writes THROUGH the link rather
    // than replacing it with a regular file (CodeRabbit R13b).
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
    // Durability (CodeRabbit R9 #B): fsync the body before the rename, then the
    // parent dir, so a lost rewrite can't drop a live marker or resurrect a
    // cleared one. Best-effort parent fsync (unix-only).
    tmp.flush()?;
    tmp.as_file().sync_all()?;
    tmp.persist(&dest).map_err(|e| e.error)?;
    crate::util::fsync_parent_dir_logged(&dest, "taint store");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    fn store_in(dir: &Path) -> PathBuf {
        dir.join("taint.jsonl")
    }

    #[cfg(unix)]
    #[test]
    fn stat_signature_distinguishes_absent_from_present_unreadable() {
        // CodeRabbit R13b: only a genuinely-missing path is `(false, _)`; a dangling
        // symlink is present, so it busts the cache and forces a fail-safe re-read.
        use std::os::unix::fs::symlink;
        let dir = tempdir().unwrap();
        let missing = dir.path().join("nope.jsonl");
        assert_eq!(stat_signature(&missing), (false, 0), "absent → (false, 0)");

        let link = dir.path().join("dangling.jsonl");
        symlink(&missing, &link).unwrap();
        assert!(
            stat_signature(&link).0,
            "a dangling symlink must read as PRESENT, not absent"
        );

        let real = store_in(dir.path());
        std::fs::write(&real, b"{}\n").unwrap();
        assert!(stat_signature(&real).0, "a real store reads as present");
    }

    /// CodeRabbit R13 #1: `clear` must NOT rewrite from an incomplete read. A FIFO
    /// store reads as incomplete, so clear aborts and leaves the FIFO intact —
    /// never a truncated regular file. Unix-only; cannot hang (O_NONBLOCK).
    #[cfg(unix)]
    #[test]
    fn clear_aborts_on_incomplete_read_no_truncation() {
        use std::ffi::CString;
        use std::os::unix::fs::FileTypeExt;
        let dir = tempdir().unwrap();
        let store = store_in(dir.path());
        let c_path = CString::new(store.as_os_str().to_str().unwrap()).unwrap();
        if unsafe { libc::mkfifo(c_path.as_ptr(), 0o600) } != 0 {
            eprintln!("skipping: mkfifo unsupported here");
            return;
        }
        let res = clear_taint_at(&store, Path::new("/tmp/install.sh"), None);
        assert!(
            res.is_err(),
            "clear on an unreadable store must abort, not silently rewrite"
        );
        assert!(
            std::fs::symlink_metadata(&store)
                .unwrap()
                .file_type()
                .is_fifo(),
            "the store must NOT be replaced by a regular file (no truncating rewrite)"
        );
    }

    // The Unix-path-shape assertions below are `#[cfg(unix)]` because `/work/repo`
    // is not absolute on Windows. The `normalize_key` LOGIC is portable (routes
    // every component through `std::path::Component`); the `#[cfg(windows)]` twins
    // exercise it with drive-letter paths.
    #[cfg(unix)]
    #[test]
    fn normalize_key_resolves_relative_against_cwd() {
        let cwd = Path::new("/work/repo");
        let key = normalize_key(Path::new("./install.sh"), Some(cwd));
        assert_eq!(key, PathBuf::from("/work/repo/install.sh"));
    }

    #[cfg(unix)]
    #[test]
    fn normalize_key_resolves_parent_components() {
        let cwd = Path::new("/work/repo/sub");
        let key = normalize_key(Path::new("../install.sh"), Some(cwd));
        assert_eq!(key, PathBuf::from("/work/repo/install.sh"));
    }

    #[cfg(unix)]
    #[test]
    fn normalize_key_keeps_absolute_untouched() {
        let key = normalize_key(Path::new("/tmp/x/./y"), Some(Path::new("/work")));
        assert_eq!(key, PathBuf::from("/tmp/x/y"));
    }

    // Windows twins exercise the `Component::Prefix` / `RootDir` arms. They assert
    // the load-bearing INVARIANT (relative-against-cwd == equivalent absolute)
    // rather than the exact key string, which depends on Windows display details.
    #[cfg(windows)]
    #[test]
    fn normalize_key_resolves_relative_against_cwd_windows() {
        let cwd = Path::new(r"C:\work\repo");
        let from_rel = normalize_key(Path::new(r".\install.sh"), Some(cwd));
        let from_abs = normalize_key(Path::new(r"C:\work\repo\install.sh"), None);
        assert_eq!(from_rel, from_abs);
    }

    #[cfg(windows)]
    #[test]
    fn normalize_key_resolves_parent_components_windows() {
        let cwd = Path::new(r"C:\work\repo\sub");
        let from_rel = normalize_key(Path::new(r"..\install.sh"), Some(cwd));
        let from_abs = normalize_key(Path::new(r"C:\work\repo\install.sh"), None);
        assert_eq!(from_rel, from_abs);
    }

    #[cfg(windows)]
    #[test]
    fn normalize_key_keeps_absolute_untouched_windows() {
        // `.`-component normalization is idempotent: the dotted and clean forms
        // of the same absolute path must produce the same key.
        let dotted = normalize_key(Path::new(r"C:\tmp\x\.\y"), Some(Path::new(r"C:\work")));
        let clean = normalize_key(Path::new(r"C:\tmp\x\y"), None);
        assert_eq!(dotted, clean);
    }

    #[cfg(unix)]
    #[test]
    fn mark_then_is_tainted_roundtrips() {
        let dir = tempdir().unwrap();
        let store = store_in(dir.path());
        let cwd = Path::new("/work/repo");

        assert!(is_tainted_at(&store, Path::new("./install.sh"), Some(cwd)).is_none());

        let entry = mark_tainted_at(
            &store,
            Path::new("./install.sh"),
            Some(cwd),
            "fetch --save",
            Some("https://untrusted.example/install.sh".to_string()),
            None,
        )
        .unwrap();
        assert_eq!(entry.path, "/work/repo/install.sh");
        assert_eq!(entry.origin, "fetch --save");

        let found = is_tainted_at(&store, Path::new("./install.sh"), Some(cwd))
            .expect("path should be tainted after mark");
        assert_eq!(found.path, "/work/repo/install.sh");
        assert_eq!(
            found.source_url.as_deref(),
            Some("https://untrusted.example/install.sh")
        );
        // Same file reached via an absolute path must hit the same key.
        let found_abs =
            is_tainted_at(&store, Path::new("/work/repo/install.sh"), None).expect("abs lookup");
        assert_eq!(found_abs.path, found.path);
    }

    // Windows twin of the round-trip: a relative mark and a drive-letter absolute
    // lookup must agree on the same normalized key. Asserts the round-trip
    // INVARIANT (mark→find via both relative and absolute forms) rather than the
    // exact stored string, which depends on Windows path-display details.
    #[cfg(windows)]
    #[test]
    fn mark_then_is_tainted_roundtrips_windows() {
        let dir = tempdir().unwrap();
        let store = store_in(dir.path());
        let cwd = Path::new(r"C:\work\repo");

        assert!(is_tainted_at(&store, Path::new(r".\install.sh"), Some(cwd)).is_none());

        let entry = mark_tainted_at(
            &store,
            Path::new(r".\install.sh"),
            Some(cwd),
            "fetch --save",
            Some("https://untrusted.example/install.sh".to_string()),
            None,
        )
        .unwrap();
        assert_eq!(entry.origin, "fetch --save");

        // The relative mark must be findable via the relative form...
        let found = is_tainted_at(&store, Path::new(r".\install.sh"), Some(cwd))
            .expect("path should be tainted after mark");
        assert_eq!(
            found.source_url.as_deref(),
            Some("https://untrusted.example/install.sh")
        );
        // ...and via the equivalent absolute drive-letter form (same key).
        let found_abs =
            is_tainted_at(&store, Path::new(r"C:\work\repo\install.sh"), None).expect("abs lookup");
        assert_eq!(found_abs.path, found.path);
        assert_eq!(found.path, entry.path);
    }

    /// CodeRabbit R16 #3: a lookup miss against an INCOMPLETE read must fail SAFE
    /// (synthetic `UNKNOWN_TAINT_ORIGIN` entry, never `None`), else a path in the
    /// unread tail reads "not tainted" (fail-OPEN). FIFO store; Unix-only, no hang.
    #[cfg(unix)]
    #[test]
    fn lookup_fails_safe_on_incomplete_read_not_clean() {
        use std::ffi::CString;
        let dir = tempdir().unwrap();
        let store = store_in(dir.path());
        let c_path = CString::new(store.as_os_str().to_str().unwrap()).unwrap();
        if unsafe { libc::mkfifo(c_path.as_ptr(), 0o600) } != 0 {
            eprintln!("skipping: mkfifo unsupported here");
            return;
        }
        invalidate_cache();

        // A path never marked tainted, queried against an unreadable (incomplete)
        // store, must NOT come back clean — it fails safe to a synthetic entry.
        let res = is_tainted_at(&store, Path::new("/tmp/never-marked.sh"), None);
        let entry = res.expect("an incomplete-read lookup miss must fail safe to Some, not None");
        assert_eq!(
            entry.origin, UNKNOWN_TAINT_ORIGIN,
            "the fail-safe entry must carry the unknown-store origin"
        );
        assert_eq!(entry.path, "/tmp/never-marked.sh");
    }

    #[test]
    fn lookup_on_complete_read_miss_is_clean_none() {
        // Contrast: a normal (complete) read with a genuine miss stays a clean
        // `None`. This pins that the fail-safe path is NOT entered on the common
        // path — only on an incomplete read.
        let dir = tempdir().unwrap();
        let store = store_in(dir.path());
        let cwd = Path::new("/work/repo");
        mark_tainted_at(&store, Path::new("./a.sh"), Some(cwd), "x", None, None).unwrap();
        // A different path on a fully-readable store → definitively not tainted.
        assert!(
            is_tainted_at(&store, Path::new("./b.sh"), Some(cwd)).is_none(),
            "a miss on a COMPLETE read must stay a clean None"
        );
    }

    #[test]
    fn untainted_path_returns_none() {
        let dir = tempdir().unwrap();
        let store = store_in(dir.path());
        let cwd = Path::new("/work/repo");
        mark_tainted_at(
            &store,
            Path::new("./a.sh"),
            Some(cwd),
            "fetch --save",
            None,
            None,
        )
        .unwrap();
        assert!(is_tainted_at(&store, Path::new("./b.sh"), Some(cwd)).is_none());
    }

    #[test]
    fn clear_removes_only_the_target() {
        let dir = tempdir().unwrap();
        let store = store_in(dir.path());
        let cwd = Path::new("/work/repo");
        mark_tainted_at(&store, Path::new("./a.sh"), Some(cwd), "x", None, None).unwrap();
        mark_tainted_at(&store, Path::new("./b.sh"), Some(cwd), "x", None, None).unwrap();

        let removed = clear_taint_at(&store, Path::new("./a.sh"), Some(cwd)).unwrap();
        assert_eq!(removed, 1);

        assert!(is_tainted_at(&store, Path::new("./a.sh"), Some(cwd)).is_none());
        assert!(is_tainted_at(&store, Path::new("./b.sh"), Some(cwd)).is_some());
    }

    #[test]
    fn clear_nonexistent_path_is_zero() {
        let dir = tempdir().unwrap();
        let store = store_in(dir.path());
        let removed = clear_taint_at(&store, Path::new("/nope.sh"), None).unwrap();
        assert_eq!(removed, 0);
    }

    #[cfg(unix)]
    #[test]
    fn clear_preserves_unparseable_lines_on_rewrite() {
        // CodeRabbit R12 #F: the lenient reader skips an unparseable line, but the
        // `clear` rewrite must NOT drop it. Real entry + a future-schema line,
        // clear the real entry, assert the unknown line survives.
        let dir = tempdir().unwrap();
        let store = store_in(dir.path());
        let cwd = Path::new("/work/repo");

        mark_tainted_at(&store, Path::new("./a.sh"), Some(cwd), "x", None, None).unwrap();
        // A line the reader cannot parse as a TaintEntry but must not lose.
        let unknown = r#"{"schema":"v2","path":"/work/repo/future.sh","kind":"something-new"}"#;
        {
            use std::io::Write as _;
            let mut f = std::fs::OpenOptions::new()
                .append(true)
                .open(&store)
                .unwrap();
            writeln!(f, "{unknown}").unwrap();
        }
        invalidate_cache();

        // Sanity: the reader skips the unknown line (only the real entry visible).
        let (parsed, complete) = parse_store(&store);
        assert!(complete, "a clean read of a regular file is complete");
        assert_eq!(parsed.len(), 1, "reader skips the unknown line");

        let removed = clear_taint_at(&store, Path::new("./a.sh"), Some(cwd)).unwrap();
        assert_eq!(removed, 1, "the real entry is cleared");

        // The unknown line MUST still be on disk verbatim after the rewrite.
        let on_disk = std::fs::read_to_string(&store).unwrap();
        assert!(
            on_disk.contains(unknown),
            "the unparseable line must survive the clear rewrite, got:\n{on_disk}"
        );
        // And the cleared entry's key is gone.
        assert!(!on_disk.contains("/work/repo/a.sh"));
    }

    #[test]
    fn list_dedups_by_path_last_wins() {
        let dir = tempdir().unwrap();
        let store = store_in(dir.path());
        let cwd = Path::new("/work/repo");
        mark_tainted_at(&store, Path::new("./a.sh"), Some(cwd), "first", None, None).unwrap();
        mark_tainted_at(&store, Path::new("./b.sh"), Some(cwd), "x", None, None).unwrap();
        mark_tainted_at(&store, Path::new("./a.sh"), Some(cwd), "second", None, None).unwrap();

        let list = list_taints_at(&store);
        assert_eq!(list.len(), 2, "two distinct paths");
        let a = list.iter().find(|e| e.path.ends_with("a.sh")).unwrap();
        assert_eq!(a.origin, "second", "last entry per path wins");
    }

    #[test]
    fn store_nonempty_reflects_marks() {
        let dir = tempdir().unwrap();
        let store = store_in(dir.path());
        assert!(!store_nonempty_at(&store));
        mark_tainted_at(&store, Path::new("./a.sh"), None, "x", None, None).unwrap();
        assert!(store_nonempty_at(&store));
    }

    #[test]
    fn corrupt_line_is_skipped_not_fatal() {
        let dir = tempdir().unwrap();
        let store = store_in(dir.path());
        std::fs::write(
            &store,
            "not json\n{\"path\":\"/work/repo/a.sh\",\"origin\":\"x\",\"marked_at\":\"t\"}\n\n",
        )
        .unwrap();
        let list = list_taints_at(&store);
        assert_eq!(list.len(), 1);
        assert_eq!(list[0].path, "/work/repo/a.sh");
    }
}
