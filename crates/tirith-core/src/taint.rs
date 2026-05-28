//! M10 ch3 — tainted-content tracking.
//!
//! A *taint* records that a file on disk was written from a risky source (a
//! download from an untrusted URL, an `install <url>` payload kept on disk). The
//! mark persists in a JSONL store at `state_dir()/taint.jsonl` so a later
//! `bash ./install.sh` against the same path can fire
//! [`crate::verdict::RuleId::ExecOfTaintedFile`], and a `source ./tainted.sh`
//! can fire [`crate::verdict::RuleId::CommandSourcedFromTaintedFile`].
//!
//! # Path-key vs inode (documented limitation)
//!
//! The store is **path-keyed**, not inode-keyed. The key is the absolute,
//! lexically-normalized path of the file. This means `mv ./install.sh
//! ./run.sh` LOSES the mark — the new path has no entry. This is a deliberate
//! v1 simplification: inode tracking is fragile across filesystems, bind
//! mounts, and editors that write-rename on save, and the threat model (run a
//! freshly-downloaded installer) is dominated by the direct
//! `download → execute-by-the-same-path` flow. A `mv`-then-execute evasion is
//! out of v1 scope and noted here so a future inode-aware backend is an
//! informed change, not a surprise.
//!
//! # Backend choice (documented)
//!
//! JSONL for v1: one `{path, origin, marked_at, source_url, source_repo}`
//! object per line, appended on `mark`, rewritten on `clear`. This is simple,
//! human-inspectable, and fast enough while the store holds the handful of
//! files a workstation downloads-and-keeps. If a future workload makes the
//! linear scan a bottleneck (thousands of marks), migrate to SQLite — the
//! public API here (`mark_tainted` / `is_tainted` / `list_taints` /
//! `clear_taint`) is the migration boundary and would not change.
//!
//! # Hot-path cost
//!
//! [`is_tainted`] is called once per exec-leader on the `engine::analyze` hot
//! path. To keep that cheap it is backed by a per-process cache (load once,
//! 5-second TTL, invalidated on store mtime change). When the store is absent
//! or empty the lookup is a near-noop: a single `metadata()` stat that resolves
//! to an empty map, then an `O(1)` map miss. The engine additionally only
//! forces past its tier-1 fast-exit for the taint check when the store is
//! non-empty (see `engine::taint_store_nonempty`), so a machine that has never
//! run `tirith fetch --save` pays nothing.
//!
//! # Auto-clear policy (documented)
//!
//! A taint is NEVER auto-cleared. Specifically, `chmod +x ./install.sh` and a
//! `bash -n ./install.sh` (syntax-only parse check) do NOT clear the mark — the
//! file's provenance does not change because you made it executable or parsed
//! it. The mark persists until an explicit [`clear_taint`] (the
//! `tirith taint clear <file>` command).

use std::io::{BufRead, BufReader, Write};
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

/// Lexically normalize a path to an absolute key WITHOUT touching the
/// filesystem (no `canonicalize` — the file may not exist yet at `mark` time,
/// and we must produce the SAME key the exec-leader lookup will compute).
///
/// Resolves `.` and `..` components lexically and prefixes a relative path with
/// `cwd` (falling back to the process cwd). Symlinks are NOT resolved — a
/// path-keyed store keys on the path the user typed, normalized, which is what
/// both the `mark` and the `is_tainted` sides see.
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
                // Drive/UNC prefix on Windows is always the first component of
                // an absolute path; seed `out` with it. (No-op on Unix.)
                out = PathBuf::from(p.as_os_str());
            }
            Component::RootDir => {
                // Append the root anchor to whatever prefix `out` already holds,
                // rather than replacing it: on Windows `C:` + `\` must stay
                // `C:\` (replacing it would drop the drive and collide across
                // drives); on Unix this turns an empty `out` into `/`. This is
                // cargo's canonical `normalize_path` ordering.
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
    loaded_at: Instant,
    /// Store-file mtime at load time (nanos since epoch), for invalidation.
    mtime_nanos: u128,
}

static CACHE: Mutex<Option<CacheState>> = Mutex::new(None);

const CACHE_TTL: Duration = Duration::from_secs(5);

/// File mtime as nanos since UNIX epoch; 0 when the file is absent/unstattable.
fn mtime_nanos(path: &Path) -> u128 {
    std::fs::metadata(path)
        .and_then(|m| m.modified())
        .ok()
        .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
        .map(|d| d.as_nanos())
        .unwrap_or(0)
}

/// Parse the JSONL store, skipping blank and unparseable lines (fail-open: a
/// corrupt line never aborts the lookup). Returns an empty vec when the file is
/// absent.
fn parse_store(path: &Path) -> Vec<TaintEntry> {
    let Ok(file) = std::fs::File::open(path) else {
        return Vec::new();
    };
    let reader = BufReader::new(file);
    let mut out = Vec::new();
    // Skip blank / unparseable lines AND continue past reader I/O errors
    // (invalid UTF-8 mid-file). A previous `map_while(Result::ok)` stopped at
    // the first reader Err, silently dropping every entry after it.
    for line in reader.lines() {
        let Ok(line) = line else {
            continue;
        };
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        if let Ok(entry) = serde_json::from_str::<TaintEntry>(trimmed) {
            out.push(entry);
        }
    }
    out
}

/// Load entries through the per-process cache. Reloads when the cached path
/// differs, the TTL expired, or the store's mtime changed.
fn cached_entries(path: &Path) -> Vec<TaintEntry> {
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
/// the default-path API call this so a stale earlier load is not reused. The
/// engine never needs it (mtime + TTL invalidation cover the real flow).
pub fn invalidate_cache() {
    let mut guard = CACHE.lock().unwrap_or_else(|e| e.into_inner());
    *guard = None;
}

/// Append `entry` to the JSONL store at `store`, creating parent dirs and the
/// file (`0600` on Unix) as needed. If a prior entry for the same path exists it
/// is left in place — `is_tainted` returns the LAST matching entry, so an append
/// is an effective update. (A periodic compaction is unnecessary for the v1
/// workload; `clear` rewrites the whole file.)
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
/// normalization (tests pass an explicit cwd; production passes `None` to use
/// the process cwd). The recorded `path` is the normalized absolute key.
///
/// Returns the recorded [`TaintEntry`].
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

/// Production entry point: mark `path` tainted in the default store
/// (`state_dir()/taint.jsonl`), normalizing relative paths against the process
/// cwd.
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

/// Look up `path` in the store at `store` (cached). Returns the LAST recorded
/// entry for the normalized key, or `None` if the path is not tainted. `cwd`
/// controls relative-path normalization.
pub fn is_tainted_at(store: &Path, path: &Path, cwd: Option<&Path>) -> Option<TaintEntry> {
    let key = normalize_key(path, cwd);
    let key_str = key.to_string_lossy();
    let entries = cached_entries(store);
    entries.into_iter().rev().find(|e| e.path == key_str)
}

/// Production entry point: look up `path` in the default store, normalizing
/// relative paths against `cwd` (or the process cwd when `cwd` is `None`).
pub fn is_tainted(path: &Path, cwd: Option<&Path>) -> Option<TaintEntry> {
    let store = store_path()?;
    is_tainted_at(&store, path, cwd)
}

/// `true` when the store at `store` exists and has at least one byte. Used by
/// the engine to decide whether to force past the tier-1 fast-exit for the
/// per-leader taint check. A cheap `metadata()` stat — no parse.
pub fn store_nonempty_at(store: &Path) -> bool {
    std::fs::metadata(store)
        .map(|m| m.len() > 0)
        .unwrap_or(false)
}

/// Production entry point for the engine's tier-1 force-past decision.
pub fn store_nonempty() -> bool {
    store_path().map(|p| store_nonempty_at(&p)).unwrap_or(false)
}

/// List all taints in the store at `store`, de-duplicated by path (the LAST
/// recorded entry per path wins, mirroring [`is_tainted_at`]). Order is by
/// first appearance.
pub fn list_taints_at(store: &Path) -> Vec<TaintEntry> {
    let entries = parse_store(store);
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

/// Remove every entry for `path` from the store at `store` by rewriting the file
/// without the matching lines. `cwd` controls relative-path normalization.
/// Returns the number of entries removed.
pub fn clear_taint_at(store: &Path, path: &Path, cwd: Option<&Path>) -> std::io::Result<usize> {
    let key = normalize_key(path, cwd);
    let key_str = key.to_string_lossy().into_owned();

    let entries = parse_store(store);
    let before = entries.len();
    let kept: Vec<TaintEntry> = entries.into_iter().filter(|e| e.path != key_str).collect();
    let removed = before - kept.len();

    if removed == 0 {
        return Ok(0);
    }

    rewrite_store(store, &kept)?;
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

/// Atomically rewrite the store to exactly `entries` (used by `clear`). Writes a
/// sibling temp file then renames over the target so a crash mid-write never
/// truncates the store.
fn rewrite_store(store: &Path, entries: &[TaintEntry]) -> std::io::Result<()> {
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

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    fn store_in(dir: &Path) -> PathBuf {
        dir.join("taint.jsonl")
    }

    // The Unix-path-shape assertions below are gated `#[cfg(unix)]` because
    // `/work/repo` is NOT an absolute path on Windows (no drive prefix), so
    // `normalize_key` would take the cwd-prefix branch and the expected key
    // would be `<cwd>/work/repo/...`, not `/work/repo/...`. The `normalize_key`
    // LOGIC itself is portable — it routes every component through
    // `std::path::Component` (RootDir / Prefix / ParentDir / Normal) rather
    // than splitting on a hard-coded `/`, so drive letters and `\` separators
    // are handled by `std::path` on Windows. The `#[cfg(windows)]` twins below
    // exercise the same code with drive-letter absolute paths.
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

    // Windows twins: drive-letter absolute paths exercise the `Component::Prefix`
    // and `Component::RootDir` arms of `normalize_key`. Rather than pin the exact
    // string form of the normalized key (which depends on Windows path display
    // details), these assert the load-bearing INVARIANT directly: a relative
    // path resolved against a cwd produces the SAME key as the equivalent
    // absolute path. That's the property taint-keying actually relies on, and
    // comparing two `normalize_key` outputs to each other is correct on any host.
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
