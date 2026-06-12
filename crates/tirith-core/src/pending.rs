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

/// Load the full map from disk. A missing file is treated as an empty map.
/// A corrupt file is reported and treated as empty so the CLI stays usable.
fn load_map() -> BTreeMap<String, PendingDecision> {
    let Some(path) = store_path() else {
        return BTreeMap::new();
    };
    let contents = match std::fs::read_to_string(&path) {
        Ok(c) => c,
        Err(_) => return BTreeMap::new(),
    };
    if contents.trim().is_empty() {
        return BTreeMap::new();
    }
    match serde_json::from_str(&contents) {
        Ok(map) => map,
        Err(e) => {
            eprintln!(
                "tirith: pending: ignoring unreadable store {}: {e}",
                path.display()
            );
            BTreeMap::new()
        }
    }
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
    tmp.persist(&path)
        .map_err(|e| format!("persist pending store: {e}"))?;
    Ok(())
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
pub fn register(mut decision: PendingDecision) -> Result<String, String> {
    let mut map = load_map();

    if decision.id.trim().is_empty() {
        let mut id = generate_id();
        while map.contains_key(&id) {
            id = generate_id();
        }
        decision.id = id;
    }
    if decision.created_at.trim().is_empty() {
        decision.created_at = now_rfc3339();
    }

    let id = decision.id.clone();
    map.insert(id.clone(), decision);
    save_map(&map)?;
    Ok(id)
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

    let mut map = load_map();
    let Some(entry) = map.get_mut(id) else {
        return Ok(false);
    };
    if entry.status.is_resolved() {
        return Ok(false);
    }

    entry.status = status;
    entry.resolved_at = Some(now_rfc3339());
    entry.reason = reason;
    entry.resolved_by = resolved_by;

    save_map(&map)?;
    Ok(true)
}

/// Mark every still-`Pending` entry older than `secs` seconds as `Expired`.
/// Returns the number of entries transitioned. Entries with an unparseable
/// `created_at` are left untouched.
pub fn expire_older_than(secs: i64) -> Result<usize, String> {
    let mut map = load_map();
    let cutoff = chrono::Utc::now() - chrono::Duration::seconds(secs);
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

    if expired > 0 {
        save_map(&map)?;
    }
    Ok(expired)
}

/// All decisions, newest first (by `created_at`, then id for stability).
pub fn load_all() -> Vec<PendingDecision> {
    let mut all: Vec<PendingDecision> = load_map().into_values().collect();
    all.sort_by(|a, b| {
        b.created_at
            .cmp(&a.created_at)
            .then_with(|| a.id.cmp(&b.id))
    });
    all
}

/// Only the still-`Pending` decisions, newest first.
pub fn list_unresolved() -> Vec<PendingDecision> {
    load_all()
        .into_iter()
        .filter(|d| !d.status.is_resolved())
        .collect()
}

#[cfg(test)]
// The tests wrap their body in an immediately-invoked closure so the env-var
// restore below always runs; that trips these two lints harmlessly here.
#[allow(clippy::redundant_closure_call, clippy::let_unit_value)]
mod tests {
    use super::*;

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
        let prev = std::env::var("XDG_STATE_HOME").ok();
        // SAFETY: serialized by crate::TEST_ENV_LOCK across all modules.
        unsafe { std::env::set_var("XDG_STATE_HOME", tmp.path()) };

        let result = (|| {
            // register generates an id and creation timestamp.
            let id = register(sample(PendingSource::Restore, "high")).unwrap();
            assert_eq!(id.len(), 8, "generated id must be 8 chars");

            // load_all / list_unresolved see the new entry.
            let all = load_all();
            assert_eq!(all.len(), 1);
            assert_eq!(all[0].id, id);
            assert!(!all[0].created_at.is_empty());
            assert_eq!(list_unresolved().len(), 1);

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
            let second =
                resolve(&id, PendingStatus::Denied, None, Some("cli".to_string())).unwrap();
            assert!(!second, "double-resolve should return false");

            // resolving an unknown id returns false.
            assert!(!resolve("deadbeef", PendingStatus::Kept, None, None).unwrap());

            // resolved entry drops out of the unresolved list but stays in load_all.
            assert_eq!(list_unresolved().len(), 0);
            let all = load_all();
            assert_eq!(all.len(), 1);
            assert_eq!(all[0].status, PendingStatus::Kept);
            assert_eq!(all[0].reason.as_deref(), Some("looks fine"));
            assert!(all[0].resolved_at.is_some());

            // export shape: pretty JSON of load_all() must round-trip.
            let exported = serde_json::to_string_pretty(&load_all()).unwrap();
            let parsed: Vec<PendingDecision> = serde_json::from_str(&exported).unwrap();
            assert_eq!(parsed.len(), 1);
            assert_eq!(parsed[0].id, id);
        })();

        // Restore env regardless of assertion outcome.
        match prev {
            Some(val) => unsafe { std::env::set_var("XDG_STATE_HOME", val) },
            None => unsafe { std::env::remove_var("XDG_STATE_HOME") },
        }
        result
    }

    #[test]
    fn missing_file_is_empty_and_expiry_marks_expired() {
        let _guard = crate::TEST_ENV_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());

        let tmp = tempfile::tempdir().unwrap();
        let prev = std::env::var("XDG_STATE_HOME").ok();
        // SAFETY: serialized by crate::TEST_ENV_LOCK across all modules.
        unsafe { std::env::set_var("XDG_STATE_HOME", tmp.path()) };

        let result = (|| {
            // No file yet: every reader tolerates the missing store.
            assert!(load_all().is_empty());
            assert!(list_unresolved().is_empty());

            // Seed one entry with an ancient created_at directly through the
            // map so we control the timestamp.
            let id = register(sample(PendingSource::Suppressed, "medium")).unwrap();

            // Nothing older than a day yet: expiry is a no-op.
            assert_eq!(expire_older_than(86_400).unwrap(), 0);
            assert_eq!(list_unresolved().len(), 1);

            // Everything older than 0 seconds expires the lone pending entry.
            // (created_at is "now", so allow a tiny negative window.)
            let n = expire_older_than(-1).unwrap();
            assert_eq!(n, 1, "the single pending entry should expire");

            let all = load_all();
            assert_eq!(all.len(), 1);
            assert_eq!(all[0].id, id);
            assert_eq!(all[0].status, PendingStatus::Expired);
            assert!(all[0].resolved_at.is_some());

            // Re-running expiry does not double-count the now-terminal entry.
            assert_eq!(expire_older_than(-1).unwrap(), 0);
        })();

        match prev {
            Some(val) => unsafe { std::env::set_var("XDG_STATE_HOME", val) },
            None => unsafe { std::env::remove_var("XDG_STATE_HOME") },
        }
        result
    }
}
