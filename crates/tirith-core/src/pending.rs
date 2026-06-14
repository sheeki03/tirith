//! First-class pending-decision registry.
//!
//! Tracks decisions that were left in an unresolved state (a restored file, a
//! suppressed finding, a deferred prompt, an open finding) so an operator can
//! later list them and explicitly resolve each one. This module is purely a
//! bookkeeping store: it never changes verdict or audit logic and never runs a
//! restore. It persists a single JSON map at `state_dir()/pending.json`.
//!
//! The store is keyed by an 8-char id (derived from a v4 uuid) so callers can
//! reference an entry on the CLI without copy-pasting a full uuid.

use std::collections::BTreeMap;
use std::path::PathBuf;

use fs2::FileExt;
use serde::{Deserialize, Serialize};

/// Where a pending decision originated.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum PendingSource {
    /// A file restore that was offered/performed and may need rollback review.
    Restore,
    /// A finding that was suppressed (allowlist/policy) and is pending review.
    Suppressed,
    /// A prompt that was deferred rather than answered.
    Deferred,
    /// A raw finding recorded for later disposition.
    Finding,
}

/// Lifecycle state of a pending decision.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum PendingStatus {
    /// Not yet resolved.
    Pending,
    /// Operator chose to keep the change/finding as-is.
    Kept,
    /// Operator rolled the change back.
    RolledBack,
    /// Operator approved the decision.
    Approved,
    /// Operator denied the decision.
    Denied,
    /// Aged out past the configured retention window.
    Expired,
}

impl PendingStatus {
    /// Whether this status counts as a terminal (resolved) state.
    pub fn is_resolved(&self) -> bool {
        !matches!(self, PendingStatus::Pending)
    }
}

/// A single pending decision record.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct PendingDecision {
    /// 8-char id (uuid-derived). Generated on register when empty.
    pub id: String,
    /// RFC3339 creation timestamp.
    pub created_at: String,
    /// Where this decision came from.
    pub source: PendingSource,
    /// Rule ids associated with the decision (may be empty).
    pub rule_ids: Vec<String>,
    /// Highest associated severity, as a lowercase string.
    pub severity: String,
    /// Redacted command/context preview (caller is responsible for redaction).
    pub command_redacted: String,
    /// Current lifecycle status.
    pub status: PendingStatus,
    /// RFC3339 timestamp of resolution, if resolved.
    pub resolved_at: Option<String>,
    /// Who/what resolved it (e.g. "cli", an operator id).
    pub resolved_by: Option<String>,
    /// Free-form reason supplied at resolution time.
    pub reason: Option<String>,
    /// Auxiliary references (e.g. `checkpoint_id`, `session_id`).
    pub refs: BTreeMap<String, String>,
}

/// Path to the pending-decision store: `state_dir()/pending.json`.
fn store_path() -> Option<PathBuf> {
    crate::policy::state_dir().map(|d| d.join("pending.json"))
}

/// Load the full map from disk. A missing file (or no state dir) is treated as an
/// empty map. Any OTHER read error, or a parse error, is returned as `Err` so the
/// caller FAILS CLOSED: a mutating caller must not save an empty snapshot over a
/// real-but-unreadable store, and a read-only caller should surface "cannot read
/// store" rather than print an empty list as if the store were genuinely empty.
fn load_map() -> Result<BTreeMap<String, PendingDecision>, String> {
    let Some(path) = store_path() else {
        return Ok(BTreeMap::new());
    };
    let contents = match std::fs::read_to_string(&path) {
        Ok(c) => c,
        // A missing file is the normal "no decisions yet" case: empty map, silent.
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(BTreeMap::new()),
        // Any OTHER read error (permission denied, transient I/O) must NOT be
        // collapsed to an empty map: a subsequent save under `with_store_locked`
        // would then overwrite a real `pending.json`. Fail closed.
        Err(e) => {
            return Err(format!("cannot read pending store {}: {e}", path.display()));
        }
    };
    if contents.trim().is_empty() {
        return Ok(BTreeMap::new());
    }
    serde_json::from_str(&contents).map_err(|e| {
        format!(
            "cannot parse pending store {} (refusing to overwrite it): {e}",
            path.display()
        )
    })
}

/// Atomically persist the map to `state_dir()/pending.json` via a temp file +
/// rename, mirroring the `last_trigger`/checkpoint persistence pattern.
fn save_map(map: &BTreeMap<String, PendingDecision>) -> Result<(), String> {
    let path = store_path().ok_or_else(|| "state dir unavailable".to_string())?;
    let dir = path
        .parent()
        .ok_or_else(|| "pending store has no parent dir".to_string())?;
    std::fs::create_dir_all(dir).map_err(|e| format!("create state dir: {e}"))?;

    let json = serde_json::to_string_pretty(map).map_err(|e| format!("serialize: {e}"))?;

    use std::io::Write;
    use tempfile::NamedTempFile;

    let mut tmp = NamedTempFile::new_in(dir).map_err(|e| format!("create temp file: {e}"))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = tmp
            .as_file()
            .set_permissions(std::fs::Permissions::from_mode(0o600));
    }
    tmp.write_all(json.as_bytes())
        .map_err(|e| format!("write temp file: {e}"))?;
    // fsync the temp file before the rename so a crash between write and flush
    // cannot leave `pending.json` empty/truncated (matches `write_file_atomic` in
    // crates/tirith/src/cli/mod.rs). This is a regular file, so sync_all is safe
    // on Windows, unlike a directory fsync.
    tmp.as_file()
        .sync_all()
        .map_err(|e| format!("sync temp file: {e}"))?;
    tmp.persist(&path)
        .map_err(|e| format!("persist pending store: {e}"))?;
    // fsync the PARENT directory so the new name -> inode entry from the rename is
    // crash-durable: without it, a crash in the window after `persist` returned
    // (and `register` reported success / `check --defer` exited 4) could drop the
    // new `pending.json`. The publish already succeeded, so a dir-fsync failure is
    // LOGGED, not propagated (matches `write_file_atomic` in
    // crates/tirith/src/cli/mod.rs); opening a directory as a File fails on Windows,
    // where this helper is a no-op.
    crate::util::fsync_parent_dir_logged(&path, "pending store write");
    Ok(())
}

/// Path to the cross-process lock file guarding the store: `pending.json.lock`.
///
/// A DEDICATED lock file (stable inode) is used rather than locking `pending.json`
/// directly, because `save_map` replaces the data file via an atomic temp+rename.
/// Locking the data file and then renaming over it would let a second process
/// acquire the lock on the now-stale inode and clobber the first writer; locking
/// a separate file that is never renamed avoids that race while still serialising
/// the whole load/modify/save sequence across processes.
fn lock_path() -> Option<PathBuf> {
    crate::policy::state_dir().map(|d| d.join("pending.json.lock"))
}

/// Run `mutate` over the store map under a cross-process exclusive lock, holding
/// the lock across the entire load -> mutate -> save sequence so concurrent
/// `register` / `resolve` / expiry calls cannot start from the same snapshot and
/// clobber each other.
///
/// The closure returns `(value, mutated)`: `save_map` runs ONLY when `mutated` is
/// true. A read-only or no-op call (`resolve` of a missing/already-resolved id,
/// `expire_older_than` that expires nothing) therefore neither writes nor CREATES
/// `pending.json` on a disk-full / read-only / empty-store path, so it returns its
/// `Ok(false)` / `Ok(0)` value instead of failing on a spurious save. Returns the
/// closure's value on success. If the state dir is unavailable, the lock cannot be
/// acquired, or a (needed) save fails, an `Err` is returned and the closure's
/// effect is not persisted.
fn with_store_locked<T, F>(mutate: F) -> Result<T, String>
where
    F: FnOnce(&mut BTreeMap<String, PendingDecision>) -> (T, bool),
{
    let lp = lock_path().ok_or_else(|| "state dir unavailable".to_string())?;
    if let Some(dir) = lp.parent() {
        std::fs::create_dir_all(dir).map_err(|e| format!("create state dir: {e}"))?;
    }

    // Open (creating if needed) and exclusively lock the dedicated lock file.
    let mut open_opts = std::fs::OpenOptions::new();
    open_opts.read(true).write(true).create(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        open_opts.mode(0o600);
    }
    let lock_file = open_opts
        .open(&lp)
        .map_err(|e| format!("open pending lock {}: {e}", lp.display()))?;
    lock_file
        .lock_exclusive()
        .map_err(|e| format!("lock pending store {}: {e}", lp.display()))?;

    // Critical section: load, mutate, save, all while the lock is held. A load
    // failure (unreadable or corrupt store) FAILS CLOSED here: we release the lock
    // and return the error WITHOUT saving, so a real-but-unreadable store is never
    // clobbered with an empty snapshot.
    let load_result = load_map();
    let mut map = match load_result {
        Ok(m) => m,
        Err(e) => {
            let _ = FileExt::unlock(&lock_file);
            return Err(e);
        }
    };
    let (out, mutated) = mutate(&mut map);
    // Persist ONLY when the closure actually changed the map. A no-op must not
    // write (or create) the store: that would turn a read-only/disk-full failure
    // into an error for an operation that logically did nothing, and would
    // materialise `pending.json` during a pure `pending list` / no-op expiry.
    let save_result = if mutated { save_map(&map) } else { Ok(()) };

    // Release the lock regardless of the save outcome.
    let _ = FileExt::unlock(&lock_file);
    save_result?;
    Ok(out)
}

/// Generate an 8-char id from a v4 uuid (hyphen-stripped hex prefix).
fn generate_id() -> String {
    uuid::Uuid::new_v4()
        .to_string()
        .chars()
        .filter(|c| *c != '-')
        .take(8)
        .collect()
}

/// Current RFC3339 timestamp.
fn now_rfc3339() -> String {
    chrono::Utc::now().to_rfc3339()
}

/// Register a pending decision, returning its id.
///
/// If `decision.id` is empty an 8-char id is generated (retried on the rare
/// chance of a collision with an existing entry). `created_at` is filled in
/// when empty. The updated map is written atomically.
///
/// If `decision.id` is NON-empty and already present in the store, this returns
/// `Err` rather than silently clobbering the existing entry (which would destroy
/// its resolution history). The empty-id auto-generation path is unaffected.
pub fn register(mut decision: PendingDecision) -> Result<String, String> {
    // The whole id-generation + insert + save runs under the cross-process lock,
    // so two concurrent registers cannot pick the same generated id off the same
    // snapshot or drop each other's entry.
    with_store_locked(move |map| {
        if decision.id.trim().is_empty() {
            let mut id = generate_id();
            while map.contains_key(&id) {
                id = generate_id();
            }
            decision.id = id;
        } else if map.contains_key(decision.id.trim()) {
            // An explicit id that already exists must NOT overwrite the stored
            // entry (that would silently drop its resolution history). Fail closed.
            // No insert happened, so the map was NOT mutated and must not be saved.
            return (
                Err(format!("pending id already exists: {}", decision.id.trim())),
                false,
            );
        }
        if decision.created_at.trim().is_empty() {
            decision.created_at = now_rfc3339();
        }

        let id = decision.id.clone();
        map.insert(id.clone(), decision);
        // A new entry was inserted: persist it.
        (Ok(id), true)
    })?
}

/// Resolve a pending decision idempotently.
///
/// Returns `Ok(false)` when the id is missing or the entry is already resolved
/// (terminal state); `Ok(true)` when this call transitioned it. The supplied
/// `status` should be a terminal variant; passing `Pending` is a no-op resolve
/// and returns `false`.
pub fn resolve(
    id: &str,
    status: PendingStatus,
    reason: Option<String>,
    resolved_by: Option<String>,
) -> Result<bool, String> {
    if !status.is_resolved() {
        // Resolving to a non-terminal state is meaningless; treat as no-op.
        return Ok(false);
    }

    // Load + check + mutate + save under the cross-process lock so a concurrent
    // resolve/expire cannot race the status transition.
    with_store_locked(move |map| {
        // A missing id is a no-op resolve: `Ok(false)` with NO write, so a
        // read-only / disk-full store still answers cleanly instead of erroring.
        let Some(entry) = map.get_mut(id) else {
            return (false, false);
        };
        // Already-terminal: idempotent no-op, likewise not persisted.
        if entry.status.is_resolved() {
            return (false, false);
        }
        entry.status = status;
        entry.resolved_at = Some(now_rfc3339());
        entry.reason = reason;
        entry.resolved_by = resolved_by;
        // A real transition: persist it. (`true` return value, `true` mutated.)
        (true, true)
    })
}

/// Mark every still-`Pending` entry older than `secs` seconds as `Expired`.
/// Returns the number of entries transitioned. Entries with an unparseable
/// `created_at` are left untouched.
pub fn expire_older_than(secs: i64) -> Result<usize, String> {
    let cutoff = chrono::Utc::now() - chrono::Duration::seconds(secs);

    // Sweep + save under the cross-process lock so the load/modify/save cannot be
    // clobbered by a concurrent register/resolve.
    with_store_locked(move |map| {
        let mut expired = 0usize;
        for entry in map.values_mut() {
            if entry.status.is_resolved() {
                continue;
            }
            let created = match chrono::DateTime::parse_from_rfc3339(&entry.created_at) {
                Ok(t) => t.with_timezone(&chrono::Utc),
                Err(_) => continue,
            };
            if created < cutoff {
                entry.status = PendingStatus::Expired;
                entry.resolved_at = Some(now_rfc3339());
                entry.resolved_by = Some("expiry".to_string());
                expired += 1;
            }
        }
        // Persist ONLY if something actually expired. A sweep that changes nothing
        // (empty store, or nothing old enough) must NOT create/rewrite
        // `pending.json`; otherwise `pending list` would materialise an empty
        // store as a side effect.
        let mutated = expired > 0;
        (expired, mutated)
    })
}

/// All decisions, newest first (by `created_at`, then id for stability).
///
/// Returns `Err` when the store exists but cannot be read or parsed, so callers
/// surface "cannot read store" rather than printing an empty list as if the store
/// were genuinely empty. A missing store (no decisions yet) is `Ok(empty)`.
pub fn load_all() -> Result<Vec<PendingDecision>, String> {
    let mut all: Vec<PendingDecision> = load_map()?.into_values().collect();
    all.sort_by(|a, b| {
        b.created_at
            .cmp(&a.created_at)
            .then_with(|| a.id.cmp(&b.id))
    });
    Ok(all)
}

/// Only the still-`Pending` decisions, newest first. Propagates a store read/parse
/// error (see [`load_all`]).
pub fn list_unresolved() -> Result<Vec<PendingDecision>, String> {
    Ok(load_all()?
        .into_iter()
        .filter(|d| !d.status.is_resolved())
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// RAII guard that sets `XDG_STATE_HOME` to a test path and restores the prior
    /// value (or unsets it) in `drop`. Using a Drop guard rather than an
    /// immediately-invoked closure means the restore still runs when a panicking
    /// `assert!`/`unwrap()` unwinds the test (a closure-and-`return` pattern would
    /// unwind PAST the restore and LEAK the override into later tests).
    struct XdgStateGuard {
        prev: Option<String>,
    }

    impl XdgStateGuard {
        fn set(path: &std::path::Path) -> Self {
            let prev = std::env::var("XDG_STATE_HOME").ok();
            // SAFETY: serialized by crate::TEST_ENV_LOCK across all modules; the
            // caller holds that lock for the lifetime of this guard.
            unsafe { std::env::set_var("XDG_STATE_HOME", path) };
            Self { prev }
        }
    }

    impl Drop for XdgStateGuard {
        fn drop(&mut self) {
            // SAFETY: still under crate::TEST_ENV_LOCK (held by the test body).
            match self.prev.take() {
                Some(val) => unsafe { std::env::set_var("XDG_STATE_HOME", val) },
                None => unsafe { std::env::remove_var("XDG_STATE_HOME") },
            }
        }
    }

    /// Build a minimal pending decision for tests.
    fn sample(source: PendingSource, severity: &str) -> PendingDecision {
        PendingDecision {
            id: String::new(),
            created_at: String::new(),
            source,
            rule_ids: vec!["pipe_to_interpreter".to_string()],
            severity: severity.to_string(),
            command_redacted: "curl https://example.com | sh".to_string(),
            status: PendingStatus::Pending,
            resolved_at: None,
            resolved_by: None,
            reason: None,
            refs: BTreeMap::new(),
        }
    }

    #[test]
    fn register_load_resolve_export_roundtrip() {
        let _guard = crate::TEST_ENV_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());

        let tmp = tempfile::tempdir().unwrap();
        // Restores XDG_STATE_HOME on drop even if an assertion below panics.
        let _xdg = XdgStateGuard::set(tmp.path());

        // register generates an id and creation timestamp.
        let id = register(sample(PendingSource::Restore, "high")).unwrap();
        assert_eq!(id.len(), 8, "generated id must be 8 chars");

        // load_all / list_unresolved see the new entry.
        let all = load_all().unwrap();
        assert_eq!(all.len(), 1);
        assert_eq!(all[0].id, id);
        assert!(!all[0].created_at.is_empty());
        assert_eq!(list_unresolved().unwrap().len(), 1);

        // first resolve transitions the entry.
        let first = resolve(
            &id,
            PendingStatus::Kept,
            Some("looks fine".to_string()),
            Some("cli".to_string()),
        )
        .unwrap();
        assert!(first, "first resolve should return true");

        // double-resolve is idempotent: returns false, status unchanged.
        let second = resolve(&id, PendingStatus::Denied, None, Some("cli".to_string())).unwrap();
        assert!(!second, "double-resolve should return false");

        // resolving an unknown id returns false.
        assert!(!resolve("deadbeef", PendingStatus::Kept, None, None).unwrap());

        // resolved entry drops out of the unresolved list but stays in load_all.
        assert_eq!(list_unresolved().unwrap().len(), 0);
        let all = load_all().unwrap();
        assert_eq!(all.len(), 1);
        assert_eq!(all[0].status, PendingStatus::Kept);
        assert_eq!(all[0].reason.as_deref(), Some("looks fine"));
        assert!(all[0].resolved_at.is_some());

        // export shape: pretty JSON of load_all() must round-trip.
        let exported = serde_json::to_string_pretty(&load_all().unwrap()).unwrap();
        let parsed: Vec<PendingDecision> = serde_json::from_str(&exported).unwrap();
        assert_eq!(parsed.len(), 1);
        assert_eq!(parsed[0].id, id);
    }

    #[test]
    fn concurrent_registers_do_not_lose_entries() {
        // Without an interprocess lock, two register() calls that load the same
        // snapshot and save back race: the last rename wins and drops the other
        // entry. With the lock held across load/modify/save, every entry lands.
        // fs2 uses flock() on Unix, which serialises distinct file handles even
        // within one process, so threads here genuinely contend on the lock.
        let _guard = crate::TEST_ENV_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());

        let tmp = tempfile::tempdir().unwrap();
        let _xdg = XdgStateGuard::set(tmp.path());

        const THREADS: usize = 8;
        const PER_THREAD: usize = 3;
        std::thread::scope(|scope| {
            for t in 0..THREADS {
                scope.spawn(move || {
                    for i in 0..PER_THREAD {
                        let mut d = sample(PendingSource::Finding, "low");
                        // A stable, unique id per (thread, i) so we can count
                        // exact survivors regardless of generation.
                        d.id = format!("t{t:02}i{i}");
                        let _ = register(d);
                    }
                });
            }
        });

        let all = load_all().unwrap();
        assert_eq!(
            all.len(),
            THREADS * PER_THREAD,
            "every concurrent register must survive the lock-protected save"
        );
    }

    #[test]
    fn missing_file_is_empty_and_expiry_marks_expired() {
        let _guard = crate::TEST_ENV_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());

        let tmp = tempfile::tempdir().unwrap();
        let _xdg = XdgStateGuard::set(tmp.path());

        // No file yet: every reader tolerates the missing store (Ok(empty)).
        assert!(load_all().unwrap().is_empty());
        assert!(list_unresolved().unwrap().is_empty());

        // Seed one entry with an ancient created_at directly through the
        // map so we control the timestamp.
        let id = register(sample(PendingSource::Suppressed, "medium")).unwrap();

        // Nothing older than a day yet: expiry is a no-op.
        assert_eq!(expire_older_than(86_400).unwrap(), 0);
        assert_eq!(list_unresolved().unwrap().len(), 1);

        // Everything older than 0 seconds expires the lone pending entry.
        // (created_at is "now", so allow a tiny negative window.)
        let n = expire_older_than(-1).unwrap();
        assert_eq!(n, 1, "the single pending entry should expire");

        let all = load_all().unwrap();
        assert_eq!(all.len(), 1);
        assert_eq!(all[0].id, id);
        assert_eq!(all[0].status, PendingStatus::Expired);
        assert!(all[0].resolved_at.is_some());

        // Re-running expiry does not double-count the now-terminal entry.
        assert_eq!(expire_older_than(-1).unwrap(), 0);
    }

    #[test]
    fn corrupt_store_fails_closed_and_is_not_truncated() {
        // A10: an unparseable `pending.json` must make a mutating op (register)
        // return Err and must NOT be overwritten with an empty snapshot. Read-only
        // callers (load_all/list_unresolved) must surface the error too.
        let _guard = crate::TEST_ENV_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());

        let tmp = tempfile::tempdir().unwrap();
        let _xdg = XdgStateGuard::set(tmp.path());

        // Plant a corrupt store at the exact path load_map() reads.
        let path = store_path().expect("store path under XDG_STATE_HOME");
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        let corrupt = b"{ this is not valid json";
        std::fs::write(&path, corrupt).unwrap();

        // Read-only callers fail closed (Err), not an empty Ok.
        assert!(load_all().is_err(), "load_all must surface the parse error");
        assert!(
            list_unresolved().is_err(),
            "list_unresolved must surface the parse error"
        );

        // A mutating op must fail closed AND leave the corrupt bytes intact
        // (no empty-snapshot overwrite).
        let reg = register(sample(PendingSource::Restore, "high"));
        assert!(
            reg.is_err(),
            "register over a corrupt store must fail closed: {reg:?}"
        );
        let after = std::fs::read(&path).unwrap();
        assert_eq!(
            after, corrupt,
            "the corrupt store must NOT be truncated/overwritten"
        );
    }

    #[test]
    fn noop_mutations_do_not_create_or_write_the_store() {
        // C8: `with_store_locked` saves ONLY on a real mutation. A no-op expiry on
        // an empty store must NOT create `pending.json`, and `resolve` of a missing
        // id must return `Ok(false)` without writing. (Previously every locked op
        // saved unconditionally, materialising the store during a pure list and
        // turning a read-only path into an error for a logically no-op resolve.)
        let _guard = crate::TEST_ENV_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());

        let tmp = tempfile::tempdir().unwrap();
        let _xdg = XdgStateGuard::set(tmp.path());

        let path = store_path().expect("store path under XDG_STATE_HOME");
        assert!(!path.exists(), "precondition: no store file yet");

        // A no-op expiry over an empty store must NOT create the file.
        assert_eq!(
            expire_older_than(0).unwrap(),
            0,
            "nothing to expire on an empty store"
        );
        assert!(
            !path.exists(),
            "expire_older_than on an empty store must NOT create pending.json"
        );

        // A read-only listing must likewise leave no file behind.
        assert!(list_unresolved().unwrap().is_empty());
        assert!(
            !path.exists(),
            "listing an empty store must NOT create pending.json"
        );

        // resolve() of a missing id returns Ok(false) and writes nothing.
        assert!(
            !resolve("deadbeef", PendingStatus::Kept, None, None).unwrap(),
            "resolving a missing id returns Ok(false)"
        );
        assert!(
            !path.exists(),
            "resolving a missing id must NOT create pending.json"
        );

        // Now register one entry so the store exists, then resolve it twice: the
        // SECOND (already-resolved) resolve is a no-op and must not rewrite.
        let id = register(sample(PendingSource::Restore, "high")).unwrap();
        assert!(path.exists(), "register creates the store");
        assert!(resolve(&id, PendingStatus::Kept, None, Some("cli".to_string())).unwrap());
        let after_first = std::fs::read(&path).unwrap();
        // The idempotent second resolve returns false and must not touch bytes.
        assert!(!resolve(&id, PendingStatus::Denied, None, None).unwrap());
        let after_second = std::fs::read(&path).unwrap();
        assert_eq!(
            after_first, after_second,
            "an already-resolved resolve must NOT rewrite the store"
        );
    }

    #[test]
    fn register_explicit_duplicate_id_errors_and_preserves_entry() {
        // G4: registering a second decision with an already-present EXPLICIT id
        // must return Err and must NOT clobber the existing entry (which would
        // destroy its resolution history). The empty-id auto-generation path is
        // unaffected and exercised elsewhere.
        let _guard = crate::TEST_ENV_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());

        let tmp = tempfile::tempdir().unwrap();
        let _xdg = XdgStateGuard::set(tmp.path());

        // Seed an entry under a fixed id, then resolve it so it carries history.
        let mut first = sample(PendingSource::Restore, "high");
        first.id = "fixed001".to_string();
        assert_eq!(register(first).unwrap(), "fixed001");
        assert!(
            resolve(
                "fixed001",
                PendingStatus::Kept,
                Some("kept it".to_string()),
                Some("cli".to_string()),
            )
            .unwrap(),
            "first resolve should transition the entry"
        );

        // A second register under the SAME explicit id must fail closed.
        let mut clash = sample(PendingSource::Finding, "low");
        clash.id = "fixed001".to_string();
        clash.command_redacted = "different command".to_string();
        let reg = register(clash);
        assert!(
            reg.is_err(),
            "registering a duplicate explicit id must return Err: {reg:?}"
        );

        // The stored entry must be the ORIGINAL one, with its resolution intact.
        let all = load_all().unwrap();
        assert_eq!(all.len(), 1, "no second entry should have been inserted");
        let stored = &all[0];
        assert_eq!(stored.id, "fixed001");
        assert_eq!(stored.source, PendingSource::Restore, "source unchanged");
        assert_eq!(stored.status, PendingStatus::Kept, "resolution preserved");
        assert_eq!(stored.reason.as_deref(), Some("kept it"));
        assert_eq!(
            stored.command_redacted, "curl https://example.com | sh",
            "the original command must NOT be overwritten"
        );
    }
}
