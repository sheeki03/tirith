//! M11 ch5 — incident mode (L2 #21).
//!
//! An *incident* is a manually-declared "under attack" posture. While active,
//! three levers turn the screws: `fail_mode` is forced to
//! [`crate::policy::FailMode::Closed`], the `TIRITH=0` env bypass (interactive
//! AND non-interactive) is disabled, and the rules in [`INCIDENT_ELEVATED_RULES`]
//! are elevated. On the `tirith check` exec path the operative levers are the
//! bypass-disable and the elevation (the verdict's action derives from severity,
//! so elevation — not `fail_mode` — is what makes more commands block).
//!
//! # Corrupt flag → fail SAFE (NOT fail-open)
//!
//! The flag file's mere *existence* signals an active incident. A corrupt/
//! truncated file is treated as **active** (overlay applied + stderr warning),
//! never silently dropped — distinguishing "absent" from "present-but-corrupt"
//! is what keeps the guarantee honest. See [`read_flag_at`] / [`active_cached`].
//!
//! # Zero new RuleIds
//!
//! Incident mode adds NO new [`crate::verdict::RuleId`]; it layers runtime
//! overrides on the loaded [`crate::policy::Policy`] (`fail_mode` → Closed,
//! both `allow_bypass_env*` → false, and a severity-override per
//! [`INCIDENT_ELEVATED_RULES`] entry applied ONLY when the policy does not
//! already pin it higher — we never downgrade an operator's override). The merge
//! lives in [`crate::policy::Policy::apply_runtime_overrides`], behind a 5s stat
//! cache so the no-incident path is a near-noop.
//!
//! # Lockout safety (CRITICAL)
//!
//! Active state is a single JSON file at `state_dir()/incident_active.json`;
//! deleting it ends the incident. `tirith incident stop` is a DIRECT deletion of
//! that file — NOT routed through `tirith check`, so it is not subject to the
//! incident's own fail-closed policy. Were it gated, a stuck incident on a
//! machine with `allow_bypass_env: false` would be unrecoverable. `stop` must
//! ALWAYS succeed (pinned by the lockout test).
//!
//! # Concurrent starts
//!
//! [`start`] uses `create_new` (O_EXCL) so a second `start` fails with
//! [`StartError::AlreadyActive`] (carrying the existing `started_at`) rather than
//! overwriting the original reason/timestamp.
//!
//! # Honest scope
//!
//! The flag file is user-writable: an attacker with the operator's shell can
//! delete it like any other tirith state file. This is operator-trust — a
//! footgun aid, not an adversary-resistant control (same model as the M8
//! sudo-session and the M11 canary store).

use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

use crate::verdict::{RuleId, Severity};

/// Rules incident mode elevates, with the forced severity while active.
///
/// Grep-traceability invariant: every entry MUST be a real [`RuleId`] variant;
/// `incident_elevated_rules_exist` round-trips each through serde to catch a
/// renamed/removed variant at test time. The merge only ever ELEVATES — it never
/// lowers an operator's pinned severity or a rule's baseline.
pub const INCIDENT_ELEVATED_RULES: &[(RuleId, Severity)] = &[
    // Credential-file sweep — mid-incident, "collecting secrets to exfiltrate".
    (RuleId::CredentialFileSweep, Severity::Critical),
    // base64-decode-then-execute — textbook obfuscated payload.
    (RuleId::Base64DecodeExecute, Severity::Critical),
    // M9 ch5 — leader binary modified in the last few minutes (just-dropped signal).
    (RuleId::ExecRecentlyModified, Severity::High),
    // M9 ch5 — leader binary world-writable (more alarming mid-incident).
    (RuleId::ExecWorldWritable, Severity::High),
];

/// Default on-disk path of the incident-active flag: `state_dir()/incident_active.json`.
pub fn flag_path() -> Option<PathBuf> {
    crate::policy::state_dir().map(|d| d.join("incident_active.json"))
}

/// On-disk shape of the incident-active flag file.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IncidentState {
    /// Unix epoch seconds when the incident was declared.
    pub started_at: u64,
    /// Best-effort starter identity (`$USER`/`$LOGNAME`, else `"unknown"`). Advisory.
    #[serde(default)]
    pub started_by: String,
    /// Operator-supplied reason, stored verbatim.
    #[serde(default)]
    pub reason: String,
}

/// Upper bound on the stored `reason` (bytes); a longer reason is TRUNCATED with
/// a marker before write. WHY (CodeRabbit R16 #1): capping well below
/// [`FLAG_READ_CAP`] guarantees a flag written by [`start_at`] always reads back
/// `Valid` rather than self-`Corrupt` (the reader rejects oversized bodies).
pub const MAX_REASON_BYTES: usize = 8 * 1024;

/// Marker appended to a truncated `reason` so the drop is obvious.
const REASON_TRUNCATED_MARKER: &str = "… [truncated]";

/// Truncate `reason` to [`MAX_REASON_BYTES`] (UTF-8 boundary), appending
/// [`REASON_TRUNCATED_MARKER`] on truncation. Result stays vastly under [`FLAG_READ_CAP`].
fn cap_reason(reason: String) -> String {
    if reason.len() <= MAX_REASON_BYTES {
        return reason;
    }
    let mut out = crate::util::truncate_bytes(&reason, MAX_REASON_BYTES);
    out.push_str(REASON_TRUNCATED_MARKER);
    out
}

impl IncidentState {
    /// Fresh incident state at `now()`. Both env-influenced fields are bounded
    /// (`reason` via [`MAX_REASON_BYTES`], `started_by` via [`current_user`]) so
    /// the serialized body can never exceed [`FLAG_READ_CAP`] — a flag written by
    /// [`start_at`] always reads back [`FlagRead::Valid`].
    pub fn now(reason: impl Into<String>) -> Self {
        Self {
            started_at: unix_now(),
            started_by: current_user(),
            reason: cap_reason(reason.into()),
        }
    }

    /// RFC-3339 display of `started_at`, falling back to raw epoch seconds when
    /// outside chrono's range.
    pub fn started_at_display(&self) -> String {
        chrono::DateTime::from_timestamp(self.started_at as i64, 0)
            .map(|dt| dt.to_rfc3339())
            .unwrap_or_else(|| format!("{} (epoch seconds)", self.started_at))
    }
}

/// Why a [`start`] failed.
#[derive(Debug)]
pub enum StartError {
    /// An incident is already active; carries the existing state for the CLI.
    AlreadyActive(Box<IncidentState>),
    /// `state_dir()` could not be resolved.
    NoStateDir,
    /// A filesystem error while creating the flag file.
    Io(std::io::Error),
}

impl std::fmt::Display for StartError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            StartError::AlreadyActive(s) => write!(
                f,
                "an incident is already active since {} (reason: {})",
                s.started_at_display(),
                if s.reason.is_empty() {
                    "<none>"
                } else {
                    &s.reason
                }
            ),
            StartError::NoStateDir => write!(f, "could not resolve tirith state dir"),
            StartError::Io(e) => write!(f, "{e}"),
        }
    }
}

impl std::error::Error for StartError {}

/// Tri-state read of the incident flag. Distinguishing `Absent` from `Corrupt`
/// is load-bearing for fail-SAFE: a corrupt flag means an incident WAS started
/// and the file got mangled, so we keep enforcing — never fall back to "none".
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FlagRead {
    /// No flag file → no incident (common path).
    Absent,
    /// Present and parsed cleanly.
    Valid(IncidentState),
    /// Present but unreadable/unparseable → treated as ACTIVE (fail-safe).
    Corrupt,
}

/// Synthetic [`IncidentState`] for a corrupt flag: `started_at: 0` + a marker
/// reason make the degraded state obvious while still driving the overlay.
pub fn corrupt_placeholder_state() -> IncidentState {
    IncidentState {
        started_at: 0,
        started_by: String::new(),
        reason: CORRUPT_FLAG_REASON.to_string(),
    }
}

/// Marker reason stamped on the synthetic state for a corrupt flag.
pub const CORRUPT_FLAG_REASON: &str =
    "incident flag file is corrupt — fail-closed posture applied (run `tirith incident status`)";

/// Un-cached tri-state read of the incident flag (the hot path uses [`active_cached`]).
pub fn read_flag() -> FlagRead {
    match flag_path() {
        Some(path) => read_flag_at(&path),
        None => FlagRead::Absent,
    }
}

/// Hot-path read cap for the flag (a tiny JSON object); anything larger is
/// treated as corrupt rather than buffered.
const FLAG_READ_CAP: u64 = 64 * 1024;

/// [`read_flag`] against an explicit path (test seam). Distinguishes absent
/// (→ [`FlagRead::Absent`]) from present-but-unparseable (→ [`FlagRead::Corrupt`]).
///
/// HOT-PATH HARDENING (CodeRabbit R9 #C / R11 #1): the path is read on every exec,
/// and an attacker who can write the state dir could plant a FIFO/device (a plain
/// `read` blocks forever) or a huge file. [`crate::util::read_regular_capped`]
/// opens `O_NONBLOCK`, `fstat`s the OPEN fd (closing the stat→open TOCTOU),
/// rejects non-regular files, and caps at [`FLAG_READ_CAP`]. Mapping is fail-SAFE:
/// `ENOENT` is the only `Absent`; everything else is `Corrupt`.
pub fn read_flag_at(path: &Path) -> FlagRead {
    let bytes = match crate::util::read_regular_capped(path, FLAG_READ_CAP) {
        Ok(b) => b,
        // ENOENT from the symlink-following open. A DANGLING SYMLINK also opens
        // ENOENT yet a sentinel WAS placed — mapping it to `Absent` would turn
        // incident mode OFF (fail-OPEN). Distinguish via `symlink_metadata` (no
        // follow): only a genuinely-missing entry stays `Absent`; any present
        // entry is fail-safe ACTIVE → Corrupt. `stop_at` clears such a sentinel.
        Err(crate::util::OpenRegularError::NotFound) => {
            return match std::fs::symlink_metadata(path) {
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => FlagRead::Absent,
                _ => FlagRead::Corrupt,
            };
        }
        // Non-regular / oversized / any open-read error on a present path is
        // fail-safe ACTIVE → Corrupt.
        Err(_) => return FlagRead::Corrupt,
    };
    match serde_json::from_slice(&bytes) {
        Ok(state) => FlagRead::Valid(state),
        Err(_) => FlagRead::Corrupt,
    }
}

/// Read incident state for the CLI. `None` only when no flag exists; a corrupt
/// flag yields [`corrupt_placeholder_state`] (fail-safe). The engine hot path
/// uses [`active_cached`].
pub fn read_state() -> Option<IncidentState> {
    match read_flag() {
        FlagRead::Absent => None,
        FlagRead::Valid(state) => Some(state),
        FlagRead::Corrupt => Some(corrupt_placeholder_state()),
    }
}

/// [`read_state`] against an explicit path (test seam).
pub fn read_state_at(path: &Path) -> Option<IncidentState> {
    match read_flag_at(path) {
        FlagRead::Absent => None,
        FlagRead::Valid(state) => Some(state),
        FlagRead::Corrupt => Some(corrupt_placeholder_state()),
    }
}

/// Declare an incident: atomically create the `0o600` flag file. Fails with
/// [`StartError::AlreadyActive`] (O_EXCL) rather than overwriting an in-flight one.
pub fn start(reason: impl Into<String>) -> Result<IncidentState, StartError> {
    let path = flag_path().ok_or(StartError::NoStateDir)?;
    start_at(&path, reason)
}

/// [`start`] against an explicit path (test seam).
///
/// Published ATOMICALLY: the full JSON body is written to a sibling temp file,
/// then `hard_link` claims the final path — a concurrent [`active_cached`] sees
/// no file or a COMPLETE one, never the empty O_EXCL-create→write window.
/// `AlreadyExists` surfaces the existing state. If `hard_link` is unsupported we
/// fall back to O_EXCL-then-write (a momentary empty file is itself fail-SAFE).
pub fn start_at(path: &Path, reason: impl Into<String>) -> Result<IncidentState, StartError> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(StartError::Io)?;
    }
    let state = IncidentState::now(reason);
    let body =
        serde_json::to_vec_pretty(&state).map_err(|e| StartError::Io(std::io::Error::other(e)))?;

    // Write the FULL body to a sibling temp file, then claim the final path via
    // hard_link. NamedTempFile cleans up on drop, so a loser never strays.
    let dir = path.parent().filter(|p| !p.as_os_str().is_empty());
    let tmp_result = match dir {
        Some(d) => tempfile::NamedTempFile::new_in(d),
        None => tempfile::NamedTempFile::new_in("."),
    };
    if let Ok(mut tmp) = tmp_result {
        use std::io::Write as _;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            // Best-effort 0600 before the temp file becomes the flag.
            let _ = tmp
                .as_file()
                .set_permissions(std::fs::Permissions::from_mode(0o600));
        }
        // fsync the body BEFORE `hard_link` publishes the inode; `flush()` only
        // drains the userspace buffer, so without this a crash could leave a
        // partial flag (still fail-safe, but the reason would be lost).
        if tmp.write_all(&body).is_ok() && tmp.flush().is_ok() && tmp.as_file().sync_all().is_ok() {
            match std::fs::hard_link(tmp.path(), path) {
                Ok(()) => {
                    // Won the race. Drop `tmp` to unlink the temp name (the linked
                    // final path keeps the inode), then dir-fsync the new entry.
                    drop(tmp);
                    fsync_parent_dir(path);
                    invalidate_cache();
                    return Ok(state);
                }
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                    return Err(already_active(path));
                }
                // hard_link unsupported / other error → fall through to O_EXCL.
                Err(_) => {}
            }
        }
    }

    // Fallback: O_EXCL create then write. TRANSACTIONAL on error (REMOVE the
    // just-created file, else a partial flag would turn incident mode ON while
    // `start` reports Err); DURABLE on success (fsync before Ok). See
    // `finish_excl_write`.
    let mut opts = std::fs::OpenOptions::new();
    // create_new => O_EXCL: fail rather than clobber a concurrent incident.
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    match opts.open(path) {
        Ok(f) => {
            finish_excl_write(f, &body, path)?;
            // fsync the parent so the new directory entry survives a crash.
            fsync_parent_dir(path);
            invalidate_cache();
            Ok(state)
        }
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => Err(already_active(path)),
        Err(e) => Err(StartError::Io(e)),
    }
}

/// fsync the directory CONTAINING the flag so the new entry (from `hard_link` or
/// O_EXCL) is crash-durable, not just the body (CodeRabbit R7 #3). Routes through
/// [`crate::util::fsync_parent_dir_logged`] (R13 #5): best-effort, unix-only, and
/// LOGGED — a dir-fsync failure must never make `start`/`stop` report an error.
fn fsync_parent_dir(path: &Path) {
    crate::util::fsync_parent_dir_logged(path, "incident flag");
}

/// Write `body` to the just-O_EXCL-created `file`, flush, fsync as one fallible
/// unit. On ANY failure REMOVE `path` (a partial flag would wrongly turn incident
/// mode on) then surface the original error; on success the body is durable.
/// Split out so the cleanup path is unit-testable via a read-only handle.
fn finish_excl_write(mut file: std::fs::File, body: &[u8], path: &Path) -> Result<(), StartError> {
    use std::io::Write as _;
    let write_result = file
        .write_all(body)
        .and_then(|()| file.flush())
        .and_then(|()| file.sync_all());
    if let Err(e) = write_result {
        // Best-effort cleanup: drop the handle, unlink the partial flag (a remove
        // failure is swallowed — the write error is what matters).
        drop(file);
        let removed = std::fs::remove_file(path).is_ok();
        // Make the rollback unlink crash-durable too (CodeRabbit R9 #B), else a
        // crash could resurrect the partial flag → incident mode wrongly ON.
        if removed {
            fsync_parent_dir(path);
        }
        return Err(StartError::Io(e));
    }
    Ok(())
}

/// Build [`StartError::AlreadyActive`] for a lost race, surfacing the EXISTING
/// on-disk state (a corrupt flag reads back as CORRUPT_FLAG_REASON, F9). The
/// empty fallback only fires in the TOCTOU window where the file just vanished.
fn already_active(path: &Path) -> StartError {
    let existing = read_state_at(path).unwrap_or_else(|| IncidentState {
        started_at: 0,
        started_by: String::new(),
        reason: String::new(),
    });
    StartError::AlreadyActive(Box::new(existing))
}

/// End an incident: delete the flag file (idempotent — a missing flag is
/// success). The lockout-safe recovery path: a plain unlink, never gated by the
/// incident's own policy. `Ok(true)` if a flag was removed, else `Ok(false)`.
pub fn stop() -> Result<bool, String> {
    let path = match flag_path() {
        Some(p) => p,
        None => return Ok(false),
    };
    stop_at(&path)
}

/// [`stop`] against an explicit path (test seam).
///
/// LOCKOUT SAFETY: `read_flag_at` reads any non-`NotFound` error as active —
/// including a DIRECTORY at the path (EISDIR). A plain `remove_file` would error
/// on it and stick the posture fail-closed, so `stop` falls back to
/// `remove_dir_all`. It must ALWAYS be able to clear the active posture.
pub fn stop_at(path: &Path) -> Result<bool, String> {
    let removed = match std::fs::remove_file(path) {
        Ok(()) => true,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => false,
        Err(file_err) => {
            // Not an unlinkable file. A directory (the EISDIR case `read_flag_at`
            // reads as active) is removed recursively; a vanished path is
            // idempotent success; anything else is a real error.
            match std::fs::metadata(path) {
                Ok(meta) if meta.is_dir() => std::fs::remove_dir_all(path)
                    .map(|()| true)
                    .map_err(|e| format!("remove dir {}: {e}", path.display()))?,
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => false,
                _ => return Err(format!("remove {}: {file_err}", path.display())),
            }
        }
    };
    // DURABILITY (CodeRabbit R8 #2): fsync the parent so the removal survives a
    // crash, else the flag could resurrect → incident mode wrongly ACTIVE.
    // Best-effort, unix-only, only after an actual removal.
    if removed {
        fsync_parent_dir(path);
    }
    invalidate_cache();
    Ok(removed)
}

/// Per-process cache of "is an incident active?", keyed on the flag path.
/// Mirrors [`crate::canary`]'s cache: 5s TTL, re-stat on mtime. The no-incident
/// path costs one `metadata()` stat (none within the TTL window).
struct CacheState {
    path: PathBuf,
    state: Option<IncidentState>,
    loaded_at: Instant,
    mtime_nanos: u128,
    existed: bool,
}

static CACHE: Mutex<Option<CacheState>> = Mutex::new(None);

const CACHE_TTL: Duration = Duration::from_secs(5);

/// Cache-invalidation stat for the flag path → `(present, mtime_nanos)`.
///
/// FAIL-SAFE + symlink-aware (CodeRabbit R13 #E): `symlink_metadata` (lstat) so a
/// dangling symlink reads as present (→ Corrupt → active), and ONLY a genuine
/// `NotFound` maps to absent `(false, 0)`; every other error maps to present
/// `(true, 0)` so it forces a re-read instead of masking the Corrupt→active path.
fn mtime_nanos(path: &Path) -> (bool, u128) {
    match std::fs::symlink_metadata(path) {
        Ok(m) => {
            let nanos = m
                .modified()
                .ok()
                .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
                .map(|d| d.as_nanos())
                .unwrap_or(0);
            (true, nanos)
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => (false, 0),
        // Present but unstattable → present-and-changed so the cache re-reads.
        Err(_) => (true, 0),
    }
}

/// Hot-path read of the active incident state through the 5s cache. `None` ONLY
/// when the flag is absent; a corrupt flag is FAIL-SAFE → [`corrupt_placeholder_state`]
/// + a stderr warning so the overlay still applies.
pub fn active_cached() -> Option<IncidentState> {
    let path = flag_path()?;
    let mut guard = CACHE.lock().unwrap_or_else(|e| e.into_inner());
    let now = Instant::now();
    let (existed, cur_mtime) = mtime_nanos(&path);

    if let Some(state) = guard.as_ref() {
        let fresh = state.path == path
            && now.duration_since(state.loaded_at) < CACHE_TTL
            && state.existed == existed
            && state.mtime_nanos == cur_mtime;
        if fresh {
            return state.state.clone();
        }
    }

    // Cache miss / stale: re-read. Absent → None; Corrupt → fail-safe synthetic
    // state + a rate-limited stderr warning; Valid → the parsed state.
    let parsed = match read_flag_at(&path) {
        FlagRead::Absent => None,
        FlagRead::Valid(state) => Some(state),
        FlagRead::Corrupt => {
            warn_corrupt_flag_once(&path, cur_mtime);
            Some(corrupt_placeholder_state())
        }
    };
    *guard = Some(CacheState {
        path: path.clone(),
        state: parsed.clone(),
        loaded_at: now,
        mtime_nanos: cur_mtime,
        existed,
    });
    parsed
}

/// Stderr warning for an honored corrupt flag, de-duplicated per `(path, mtime)`.
fn warn_corrupt_flag_once(path: &Path, mtime: u128) {
    use std::sync::Mutex as StdMutex;
    static LAST_WARNED: StdMutex<Option<(PathBuf, u128)>> = StdMutex::new(None);
    let mut guard = LAST_WARNED.lock().unwrap_or_else(|e| e.into_inner());
    let key = (path.to_path_buf(), mtime);
    if guard.as_ref() == Some(&key) {
        return;
    }
    *guard = Some(key);
    // Write fallibly so a closed stderr cannot panic this helper (CodeRabbit R22 #4).
    use std::io::Write as _;
    let _ = writeln!(
        std::io::stderr(),
        "tirith: incident flag corrupt — applying fail-closed posture; \
         run `tirith incident status`"
    );
}

/// `true` when an incident is active (cached). Boolean convenience over [`active_cached`].
pub fn is_active() -> bool {
    active_cached().is_some()
}

/// Drop the per-process cache. Tests that write/delete the flag directly call this.
pub fn invalidate_cache() {
    let mut guard = CACHE.lock().unwrap_or_else(|e| e.into_inner());
    *guard = None;
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Upper bound on `started_by` (CodeRabbit R13 #D) — the env-derived analogue of
/// [`MAX_REASON_BYTES`], so [`IncidentState::now`]'s body-size invariant holds for
/// every field.
const MAX_STARTED_BY_BYTES: usize = 256;

/// Cap `label` to [`MAX_STARTED_BY_BYTES`] (UTF-8 boundary). No truncation marker
/// — `started_by` is advisory and a label this long is already pathological.
fn cap_started_by(label: String) -> String {
    if label.len() <= MAX_STARTED_BY_BYTES {
        label
    } else {
        crate::util::truncate_bytes(&label, MAX_STARTED_BY_BYTES)
    }
}

/// Best-effort `started_by` from `$USER`/`$LOGNAME`/`$USERNAME` (else `"unknown"`),
/// capped via [`cap_started_by`] so an oversized env value can't bloat the flag body.
fn current_user() -> String {
    let raw = std::env::var("USER")
        .or_else(|_| std::env::var("LOGNAME"))
        .or_else(|_| std::env::var("USERNAME")) // Windows
        .ok()
        .filter(|s| !s.trim().is_empty())
        .unwrap_or_else(|| "unknown".to_string());
    cap_started_by(raw)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    fn flag_in(dir: &Path) -> PathBuf {
        dir.join("incident_active.json")
    }

    #[test]
    fn elevated_rules_are_real_ruleids() {
        // Grep-traceability: every entry must round-trip through serde (a live
        // RuleId variant), which also pins the snake_case override-map key.
        for (rule, sev) in INCIDENT_ELEVATED_RULES {
            let key = serde_json::to_value(rule)
                .ok()
                .and_then(|v| v.as_str().map(String::from));
            assert!(
                key.is_some(),
                "RuleId {rule:?} does not serialize to a string"
            );
            assert!(serde_json::to_value(sev).is_ok());
        }
        // The four spec-mandated rules must be present.
        let keys: Vec<&RuleId> = INCIDENT_ELEVATED_RULES.iter().map(|(r, _)| r).collect();
        assert!(keys.contains(&&RuleId::CredentialFileSweep));
        assert!(keys.contains(&&RuleId::Base64DecodeExecute));
        assert!(keys.contains(&&RuleId::ExecRecentlyModified));
        assert!(keys.contains(&&RuleId::ExecWorldWritable));
    }

    #[test]
    fn start_creates_flag_and_status_reads_it() {
        let dir = tempdir().unwrap();
        let flag = flag_in(dir.path());
        assert!(read_state_at(&flag).is_none(), "no incident before start");

        let state = start_at(&flag, "suspicious paste").unwrap();
        assert_eq!(state.reason, "suspicious paste");
        assert!(state.started_at > 0);

        let read = read_state_at(&flag).expect("flag present after start");
        assert_eq!(read.reason, "suspicious paste");
        assert_eq!(read.started_at, state.started_at);
    }

    #[test]
    fn start_publishes_full_state_atomically_never_empty() {
        // F5 (Major): the flag is published with its full body already present
        // (hard_link of a written temp file), so it is never empty/partial. Proves
        // the post-condition: file exists, non-empty, parses to the started state.
        let dir = tempdir().unwrap();
        let flag = flag_in(dir.path());

        let state = start_at(&flag, "atomic publish").unwrap();

        let bytes = std::fs::read(&flag).expect("flag file present after start");
        assert!(!bytes.is_empty(), "published flag must never be empty");
        let parsed: IncidentState =
            serde_json::from_slice(&bytes).expect("published flag is complete, valid JSON");
        assert_eq!(parsed.reason, "atomic publish");
        assert_eq!(parsed.started_at, state.started_at);

        assert!(matches!(read_flag_at(&flag), FlagRead::Valid(_)));
        // No stray temp file left besides the flag itself.
        let stray: Vec<_> = std::fs::read_dir(dir.path())
            .unwrap()
            .filter_map(|e| e.ok())
            .filter(|e| e.path() != flag)
            .collect();
        assert!(
            stray.is_empty(),
            "atomic publish must not leave a temp file behind, found: {stray:?}"
        );
    }

    #[test]
    fn excl_write_failure_leaves_no_flag_so_incident_reads_inactive() {
        // CodeRabbit R6 #3: a write failure must leave NO partial flag (else
        // incident mode turns ON while `start` reports Err). Force the failure
        // with a read-only handle and assert no flag remains.
        let dir = tempdir().unwrap();
        let flag = flag_in(dir.path());

        // Create the flag, reopen read-only to model "O_EXCL-created, write fails".
        std::fs::File::create(&flag).unwrap();
        let ro = std::fs::OpenOptions::new().read(true).open(&flag).unwrap();

        let err = finish_excl_write(ro, b"{\"x\":1}", &flag).unwrap_err();
        assert!(
            matches!(err, StartError::Io(_)),
            "write to a RO fd must error"
        );

        // The partial flag is gone → the read path is inactive (matching the Err).
        assert!(
            !flag.exists(),
            "a failed excl write must leave no flag behind"
        );
        assert!(matches!(read_flag_at(&flag), FlagRead::Absent));
        assert!(read_state_at(&flag).is_none());
    }

    #[test]
    fn excl_write_success_is_durable_and_complete() {
        // The O_EXCL success path fsyncs before returning → reads back Valid.
        let dir = tempdir().unwrap();
        let flag = flag_in(dir.path());

        let state = IncidentState::now("excl durable");
        let body = serde_json::to_vec_pretty(&state).unwrap();
        let f = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&flag)
            .unwrap();
        finish_excl_write(f, &body, &flag).expect("excl write succeeds");

        let bytes = std::fs::read(&flag).unwrap();
        assert!(!bytes.is_empty());
        let parsed: IncidentState = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(parsed.reason, "excl durable");
        assert!(matches!(read_flag_at(&flag), FlagRead::Valid(_)));
    }

    #[test]
    fn second_start_errors_already_active_without_overwriting() {
        let dir = tempdir().unwrap();
        let flag = flag_in(dir.path());

        let first = start_at(&flag, "first reason").unwrap();
        // A second start must fail and must NOT clobber the original.
        let err = start_at(&flag, "second reason").unwrap_err();
        match err {
            StartError::AlreadyActive(existing) => {
                assert_eq!(existing.reason, "first reason");
                assert_eq!(existing.started_at, first.started_at);
            }
            other => panic!("expected AlreadyActive, got {other:?}"),
        }
        // On disk, the original reason survives.
        assert_eq!(read_state_at(&flag).unwrap().reason, "first reason");
    }

    #[test]
    fn stop_removes_flag_and_is_idempotent() {
        let dir = tempdir().unwrap();
        let flag = flag_in(dir.path());

        start_at(&flag, "x").unwrap();
        assert!(stop_at(&flag).unwrap(), "first stop removes the flag");
        assert!(read_state_at(&flag).is_none(), "flag gone after stop");
        // Idempotent — stopping an already-stopped incident is success, not error.
        assert!(
            !stop_at(&flag).unwrap(),
            "second stop finds nothing, still Ok"
        );
    }

    #[test]
    fn stop_succeeds_even_with_fail_closed_policy_in_play() {
        // Lockout-safety unit: stop is a plain unlink with no policy in the
        // path. We can't easily fake fail-closed here (that lives in the CLI
        // integration test), but we CAN prove stop never consults policy: it
        // operates purely on the file and succeeds.
        let dir = tempdir().unwrap();
        let flag = flag_in(dir.path());
        start_at(&flag, "lockout drill").unwrap();
        // Even if the rest of the world is fail-closed, this returns Ok(true).
        assert!(stop_at(&flag).unwrap());
    }

    #[test]
    fn corrupt_flag_fails_safe_to_active() {
        // F1 (Sev-7): an EXISTING-but-corrupt flag must fail SAFE (active), not
        // fall through to "no incident". The file's existence is the signal.
        let dir = tempdir().unwrap();
        let flag = flag_in(dir.path());
        std::fs::write(&flag, b"this is not json").unwrap();

        assert_eq!(read_flag_at(&flag), FlagRead::Corrupt);

        // read_state_at yields the synthetic placeholder, NOT None.
        let state = read_state_at(&flag).expect("corrupt flag must read as active");
        assert_eq!(state.started_at, 0);
        assert_eq!(state.reason, CORRUPT_FLAG_REASON);
    }

    #[test]
    fn stop_clears_a_directory_sentinel_no_lockout() {
        // LOCKOUT SAFETY (finding E): a directory at the flag path reads as active
        // (EISDIR → Corrupt), and a plain `remove_file` errors on it. `stop` must
        // still clear it. Use a NON-EMPTY directory (so `remove_dir` would fail too).
        let dir = tempdir().unwrap();
        let flag = flag_in(dir.path());
        std::fs::create_dir_all(&flag).unwrap();
        std::fs::write(flag.join("stray-child"), b"x").unwrap();

        // Precondition: the directory sentinel reads as an ACTIVE incident.
        assert_eq!(read_flag_at(&flag), FlagRead::Corrupt);
        assert!(
            read_state_at(&flag).is_some(),
            "a directory at the flag path must read as active (fail-safe)"
        );

        // stop must succeed and report it removed something.
        assert!(
            stop_at(&flag).unwrap(),
            "stop must clear a directory sentinel, not error out"
        );

        // Genuinely cleared afterwards — no lockout.
        assert_eq!(read_flag_at(&flag), FlagRead::Absent);
        assert!(
            read_state_at(&flag).is_none(),
            "after stop the directory sentinel is gone and the incident reads inactive"
        );
        assert!(!stop_at(&flag).unwrap());
    }

    #[test]
    fn absent_flag_reads_as_none() {
        // Contrast: a truly-absent flag is NOT an incident.
        let dir = tempdir().unwrap();
        let flag = flag_in(dir.path());
        assert_eq!(read_flag_at(&flag), FlagRead::Absent);
        assert!(read_state_at(&flag).is_none());
    }

    #[test]
    fn valid_flag_reads_as_valid() {
        let dir = tempdir().unwrap();
        let flag = flag_in(dir.path());
        start_at(&flag, "real incident").unwrap();
        match read_flag_at(&flag) {
            FlagRead::Valid(s) => assert_eq!(s.reason, "real incident"),
            other => panic!("expected Valid, got {other:?}"),
        }
    }

    /// CodeRabbit R9 #C: a FIFO at the flag path would block a plain `read`
    /// forever. `read_regular_capped` opens `O_NONBLOCK` and refuses non-regular
    /// files, so the FIFO reads `Corrupt` (fail-safe) and returns promptly; a
    /// regression to a blocking read would HANG this test. Unix-only.
    #[cfg(unix)]
    #[test]
    fn fifo_flag_is_corrupt_and_does_not_hang() {
        use std::ffi::CString;
        let dir = tempdir().unwrap();
        let flag = flag_in(dir.path());
        let c_path = CString::new(flag.as_os_str().to_str().unwrap()).unwrap();
        let rc = unsafe { libc::mkfifo(c_path.as_ptr(), 0o600) };
        if rc != 0 {
            eprintln!("skipping: mkfifo unsupported here");
            return;
        }
        // Must complete promptly; a blocking read would hang. Non-regular → active.
        assert_eq!(read_flag_at(&flag), FlagRead::Corrupt);
        assert!(
            read_state_at(&flag).is_some(),
            "a FIFO at the flag path must read as active (fail-safe), not hang"
        );
    }

    /// CodeRabbit R9 #C: a symlink to a FIFO must also be rejected — the
    /// `O_NONBLOCK` open follows the link, `fstat`s the target, and refuses it.
    /// Unix-only.
    #[cfg(unix)]
    #[test]
    fn symlink_flag_to_fifo_is_corrupt_and_does_not_hang() {
        use std::ffi::CString;
        let dir = tempdir().unwrap();
        let real_fifo = dir.path().join("real.fifo");
        let c_path = CString::new(real_fifo.as_os_str().to_str().unwrap()).unwrap();
        let rc = unsafe { libc::mkfifo(c_path.as_ptr(), 0o600) };
        if rc != 0 {
            eprintln!("skipping: mkfifo unsupported here");
            return;
        }
        let flag = flag_in(dir.path());
        std::os::unix::fs::symlink(&real_fifo, &flag).unwrap();
        assert_eq!(read_flag_at(&flag), FlagRead::Corrupt);
        assert!(read_state_at(&flag).is_some());
    }

    /// CodeRabbit R16 #2: a DANGLING SYMLINK opens ENOENT yet a sentinel WAS
    /// placed — it must read `Corrupt` (fail-safe), not `Absent` (fail-open). A
    /// truly-absent path still reads `Absent`, and `stop` must clear the dangling
    /// symlink (lockout). Unix-only.
    #[cfg(unix)]
    #[test]
    fn dangling_symlink_flag_is_corrupt_not_absent() {
        let dir = tempdir().unwrap();
        let flag = flag_in(dir.path());

        // Contrast: a path with no entry at all is genuinely Absent.
        assert_eq!(read_flag_at(&flag), FlagRead::Absent);

        // Symlink to a non-existent target: the open returns ENOENT, but the entry exists.
        let missing_target = dir.path().join("does-not-exist.json");
        std::os::unix::fs::symlink(&missing_target, &flag).unwrap();

        // Must be Corrupt (fail-safe active), NOT Absent.
        assert_eq!(
            read_flag_at(&flag),
            FlagRead::Corrupt,
            "a dangling symlink sentinel must read as Corrupt (active), not Absent"
        );
        assert!(
            read_state_at(&flag).is_some(),
            "a dangling symlink at the flag path must read as an active incident"
        );

        // Lockout safety: stop must still clear the dangling symlink.
        assert!(
            stop_at(&flag).unwrap(),
            "stop must clear a dangling symlink sentinel"
        );
        assert_eq!(read_flag_at(&flag), FlagRead::Absent);
    }

    #[test]
    fn oversized_flag_is_corrupt() {
        // CodeRabbit R9 #C: an oversized flag is corrupt (fail-safe), not buffered.
        // One byte over the cap trips the guard.
        let dir = tempdir().unwrap();
        let flag = flag_in(dir.path());
        let big = vec![b' '; (FLAG_READ_CAP as usize) + 1];
        std::fs::write(&flag, &big).unwrap();
        assert_eq!(read_flag_at(&flag), FlagRead::Corrupt);
        assert!(
            read_state_at(&flag).is_some(),
            "an oversized flag must read as active (fail-safe), not be buffered"
        );
    }

    #[test]
    fn start_with_oversized_reason_reads_back_valid_not_corrupt() {
        // CodeRabbit R16 #1: a `--reason` larger than the read cap used to write a
        // self-corrupt flag. `IncidentState::now` now caps it, so it reads Valid.
        let dir = tempdir().unwrap();
        let flag = flag_in(dir.path());

        // A reason an order of magnitude over the read cap.
        let huge = "A".repeat((FLAG_READ_CAP as usize) * 4);
        let state = start_at(&flag, huge).unwrap();

        // Capped well under the read cap and carries the truncation marker.
        assert!(
            state.reason.len() <= MAX_REASON_BYTES + REASON_TRUNCATED_MARKER.len(),
            "reason must be capped, got {} bytes",
            state.reason.len()
        );
        assert!(state.reason.ends_with(REASON_TRUNCATED_MARKER));

        // The written body is within the read cap → reads back Valid.
        let on_disk = std::fs::read(&flag).unwrap();
        assert!(
            (on_disk.len() as u64) <= FLAG_READ_CAP,
            "written flag body must be <= FLAG_READ_CAP, got {} bytes",
            on_disk.len()
        );
        match read_flag_at(&flag) {
            FlagRead::Valid(s) => {
                assert!(s.reason.ends_with(REASON_TRUNCATED_MARKER));
            }
            other => panic!("an oversized-reason flag must read back Valid, got {other:?}"),
        }
    }

    #[test]
    fn started_by_is_capped_so_body_stays_within_read_cap() {
        // CodeRabbit R13 #D: a multi-KiB `$USER` could push the body past the read
        // cap (self-corrupt flag). `cap_started_by` now bounds it.
        let huge = "U".repeat((FLAG_READ_CAP as usize) * 4);
        let capped = cap_started_by(huge);
        assert!(
            capped.len() <= MAX_STARTED_BY_BYTES,
            "started_by must be capped, got {} bytes",
            capped.len()
        );

        // Worst case: both env-influenced fields at their caps must still fit.
        let dir = tempdir().unwrap();
        let flag = flag_in(dir.path());
        let state = IncidentState {
            started_at: 1_700_000_000,
            started_by: cap_started_by("L".repeat(10_000)),
            reason: cap_reason("R".repeat((FLAG_READ_CAP as usize) * 4)),
        };
        let body = serde_json::to_vec_pretty(&state).unwrap();
        assert!(
            (body.len() as u64) <= FLAG_READ_CAP,
            "worst-case body must be <= FLAG_READ_CAP, got {} bytes",
            body.len()
        );
        std::fs::write(&flag, &body).unwrap();
        match read_flag_at(&flag) {
            FlagRead::Valid(_) => {}
            other => panic!("a capped-field flag must read back Valid, got {other:?}"),
        }
    }

    #[test]
    fn normal_started_by_is_not_truncated() {
        // A genuine username is returned verbatim.
        assert_eq!(cap_started_by("alice".to_string()), "alice");
    }

    #[test]
    fn normal_reason_is_not_truncated() {
        // A genuine reason is stored verbatim.
        let dir = tempdir().unwrap();
        let flag = flag_in(dir.path());
        let reason = "compromised CI token, rotating now";
        let state = start_at(&flag, reason).unwrap();
        assert_eq!(state.reason, reason);
        assert!(!state.reason.contains(REASON_TRUNCATED_MARKER));
    }

    #[test]
    fn started_at_display_is_rfc3339_for_sane_timestamps() {
        let s = IncidentState {
            started_at: 1_700_000_000,
            started_by: "tester".to_string(),
            reason: "demo".to_string(),
        };
        let disp = s.started_at_display();
        assert!(disp.contains("2023"), "got {disp}");
    }

    #[cfg(unix)]
    #[test]
    fn mtime_nanos_treats_dangling_symlink_as_present_not_absent() {
        // CodeRabbit R13 #E: a dangling symlink used to stat as absent (via
        // `metadata`), so the 5s cache masked the Corrupt→active fail-safe.
        // `symlink_metadata` now lstat-sees the link as present.
        use std::os::unix::fs::symlink;
        let dir = tempdir().unwrap();
        let missing = dir.path().join("does-not-exist");
        let link = dir.path().join("flag-link");
        symlink(&missing, &link).unwrap();
        assert!(
            mtime_nanos(&link).0,
            "a dangling symlink must read as PRESENT (forces re-read → Corrupt → active)"
        );
        // A genuinely missing path is still the only thing reported absent.
        assert_eq!(mtime_nanos(&missing), (false, 0));
        // A real regular file is present.
        let real = dir.path().join("real");
        std::fs::write(&real, b"{}").unwrap();
        assert!(mtime_nanos(&real).0);
    }
}
