//! Cross-event correlation over a bounded, per-session ring of typed events.
//!
//! This module is PURE: it performs no I/O, reads no clock of its own, and
//! touches no global state. Callers (see [`crate::session_warnings`]) own the
//! buffer's persistence and pass the current time in explicitly. That keeps the
//! correlation logic trivially testable and keeps it OFF the hot path: events
//! are recorded after a verdict is finalized, and correlation runs only when a
//! session-level consumer asks for it, never during tier-1/2/3 analysis.
//!
//! The correlations here are "A THEN B within a window" patterns: behaviours
//! that are individually unremarkable but, in sequence and close in time, look
//! like an exfiltration or destruction chain. Each rule maps to a dedicated
//! [`RuleId`] variant flagged `EXTERNALLY_TRIGGERED_RULES` (session/post-process,
//! no PATTERN_TABLE entry).

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::verdict::{RuleId, Severity};

/// The class of a recorded event. Deliberately coarse: correlation reasons about
/// "what kind of thing happened", and finer detail lives in
/// [`TypedEvent::metadata`].
#[derive(Serialize, Deserialize, Clone, Copy, PartialEq, Eq, Debug)]
#[serde(rename_all = "snake_case")]
pub enum EventKind {
    /// A process/command was executed.
    ProcessExec,
    /// A file was written (created or modified).
    FileWrite,
    /// A file was deleted / unlinked.
    FileDelete,
    /// A `git push --force` (or `-f`) was run.
    GitForcePush,
    /// A network egress (curl/wget/http client, or a network-class rule fired).
    Network,
    /// A secret-bearing file was written (`.env`, `id_rsa`, `.npmrc`, ...).
    SecretWrite,
    /// A pipe-to-shell shape (`curl ... | sh`).
    ShellPipe,
    /// A package install (npm/pip/cargo/brew ...).
    PackageInstall,
}

/// One recorded, time-stamped event. `path` / `host` / `domain` and any other
/// detail live in [`Self::metadata`] so the struct stays stable as new
/// correlations want new context.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct TypedEvent {
    /// RFC 3339 UTC timestamp (`chrono::Utc::now().to_rfc3339()`), lexically
    /// comparable against other events recorded the same way.
    pub timestamp: String,
    /// The class of event.
    pub kind: EventKind,
    /// The rule id (or command-derived label) that produced this event.
    pub rule_id: String,
    /// Free-form context: `path`, `host`, `domain`, a `manifest` flag, etc.
    pub metadata: BTreeMap<String, String>,
}

impl TypedEvent {
    /// Convenience constructor used by recorders and tests.
    pub fn new(timestamp: &str, kind: EventKind, rule_id: &str) -> Self {
        Self {
            timestamp: timestamp.to_string(),
            kind,
            rule_id: rule_id.to_string(),
            metadata: BTreeMap::new(),
        }
    }

    /// Builder-style metadata insert.
    pub fn with_meta(mut self, key: &str, value: &str) -> Self {
        self.metadata.insert(key.to_string(), value.to_string());
        self
    }

    /// Borrow the `path` metadatum, if present.
    fn path(&self) -> Option<&str> {
        self.metadata.get("path").map(|s| s.as_str())
    }
}

/// A correlation that fired. Mirrors the shape of a [`crate::verdict::Finding`]
/// closely enough that a consumer can surface it as one, but stays decoupled so
/// this module never depends on the full finding/evidence machinery.
#[derive(Clone, Debug)]
pub struct CorrelationHit {
    /// The dedicated correlation rule that matched.
    pub rule_id: RuleId,
    /// Severity for the surfaced finding.
    pub severity: Severity,
    /// Short title.
    pub title: String,
    /// Human-readable description of the matched sequence.
    pub description: String,
}

/// Window, in seconds, for each correlation rule.
const SECRET_THEN_NETWORK_WINDOW_SECS: i64 = 30;
const DEP_CHANGE_THEN_NETWORK_WINDOW_SECS: i64 = 60;
const DELETE_THEN_FORCE_PUSH_WINDOW_SECS: i64 = 60;
const MASS_DELETE_WINDOW_SECS: i64 = 20;
/// How many file deletions inside [`MASS_DELETE_WINDOW_SECS`] constitute a mass
/// deletion.
const MASS_DELETE_THRESHOLD: usize = 3;

/// Metadata key set on a [`EventKind::FileWrite`] event whose target basename is
/// a dependency manifest. Lets the dependency-change correlation distinguish a
/// manifest write from an arbitrary file write without a second event kind.
pub const MANIFEST_FLAG_KEY: &str = "manifest";

/// Returns true if `basename` (a file's final path component) is a recognised
/// dependency manifest / lockfile. Conservative and exact-match where possible;
/// lockfiles use a small suffix/contains set so `pnpm-lock.yaml`,
/// `package-lock.json`, etc. all match.
pub fn is_dependency_manifest(basename: &str) -> bool {
    const EXACT: &[&str] = &[
        "package.json",
        "cargo.toml",
        "requirements.txt",
        "go.mod",
        "go.sum",
        "gemfile",
        "pipfile",
        "pyproject.toml",
        "build.gradle",
        "pom.xml",
        "composer.json",
        "package-lock.json",
        "yarn.lock",
        "cargo.lock",
        "poetry.lock",
        "pipfile.lock",
        "gemfile.lock",
        "composer.lock",
    ];
    let lower = basename.to_ascii_lowercase();
    if EXACT.contains(&lower.as_str()) {
        return true;
    }
    // Lockfile families whose prefix varies (pnpm-lock.yaml, npm-shrinkwrap.json).
    lower.contains("pnpm-lock") || lower == "npm-shrinkwrap.json"
}

/// Compute the RFC 3339 cutoff string for `now_rfc3339 - window_secs`. Returns
/// `None` if `now_rfc3339` does not parse; callers then skip that rule (fail
/// safe: a malformed clock string never fabricates a correlation).
fn cutoff(now_rfc3339: &str, window_secs: i64) -> Option<String> {
    let now = chrono::DateTime::parse_from_rfc3339(now_rfc3339).ok()?;
    let cut = now - chrono::Duration::seconds(window_secs);
    // Render in the SAME shape recorders use (`Utc::now().to_rfc3339()`), so the
    // returned string is lexically comparable against event timestamps.
    Some(cut.with_timezone(&chrono::Utc).to_rfc3339())
}

/// True if `ts` (an event timestamp) is within `[cutoff, now]` for `now`'s
/// window. Both `ts` and `cutoff` are RFC 3339 UTC strings produced the same
/// way, so a lexical compare is an instant compare.
fn within_window(ts: &str, cutoff: &str, now_rfc3339: &str) -> bool {
    ts >= cutoff && ts <= now_rfc3339
}

/// Run every correlation rule over `events` as of `now_rfc3339` (an RFC 3339 UTC
/// instant). `events` need not be sorted. Returns one [`CorrelationHit`] per rule
/// that matched (a rule fires at most once per call).
pub fn correlate(events: &[TypedEvent], now_rfc3339: &str) -> Vec<CorrelationHit> {
    let mut hits = Vec::new();

    if let Some(hit) = secret_then_network(events, now_rfc3339) {
        hits.push(hit);
    }
    if let Some(hit) = dependency_change_then_network(events, now_rfc3339) {
        hits.push(hit);
    }
    if let Some(hit) = delete_then_force_push(events, now_rfc3339) {
        hits.push(hit);
    }
    if let Some(hit) = mass_file_deletion(events, now_rfc3339) {
        hits.push(hit);
    }

    hits
}

/// Find the earliest event of `kind` within the window, returning the event.
fn earliest_in_window<'a>(
    events: &'a [TypedEvent],
    kind: EventKind,
    cutoff: &str,
    now_rfc3339: &str,
) -> Option<&'a TypedEvent> {
    events
        .iter()
        .filter(|e| e.kind == kind && within_window(&e.timestamp, cutoff, now_rfc3339))
        .min_by(|a, b| a.timestamp.cmp(&b.timestamp))
}

/// `B` of kind `b_kind` happened at-or-after `after_ts`, within the window.
fn any_after<'a>(
    events: &'a [TypedEvent],
    b_kind: EventKind,
    after_ts: &str,
    cutoff: &str,
    now_rfc3339: &str,
) -> Option<&'a TypedEvent> {
    events.iter().find(|e| {
        e.kind == b_kind
            && within_window(&e.timestamp, cutoff, now_rfc3339)
            && e.timestamp.as_str() >= after_ts
    })
}

/// SecretWrite THEN Network within 30s -> CRITICAL.
fn secret_then_network(events: &[TypedEvent], now_rfc3339: &str) -> Option<CorrelationHit> {
    let cut = cutoff(now_rfc3339, SECRET_THEN_NETWORK_WINDOW_SECS)?;
    let secret = earliest_in_window(events, EventKind::SecretWrite, &cut, now_rfc3339)?;
    let net = any_after(
        events,
        EventKind::Network,
        &secret.timestamp,
        &cut,
        now_rfc3339,
    )?;
    let host = net
        .metadata
        .get("host")
        .or_else(|| net.metadata.get("domain"))
        .map(|h| h.as_str())
        .unwrap_or("a network destination");
    Some(CorrelationHit {
        rule_id: RuleId::SecretWriteThenNetwork,
        severity: Severity::Critical,
        title: "Secret write followed by network egress".to_string(),
        description: format!(
            "A secret-bearing file was written, then a network call to {host} ran within {SECRET_THEN_NETWORK_WINDOW_SECS}s. This is the shape of a credential-exfiltration chain."
        ),
    })
}

/// Dependency-manifest FileWrite THEN Network within 60s -> WARN.
fn dependency_change_then_network(
    events: &[TypedEvent],
    now_rfc3339: &str,
) -> Option<CorrelationHit> {
    let cut = cutoff(now_rfc3339, DEP_CHANGE_THEN_NETWORK_WINDOW_SECS)?;
    // A manifest write is a FileWrite carrying the manifest flag, OR (defence in
    // depth) a FileWrite whose path basename is itself a known manifest.
    let manifest_write = events
        .iter()
        .filter(|e| {
            e.kind == EventKind::FileWrite && within_window(&e.timestamp, &cut, now_rfc3339)
        })
        .filter(|e| {
            e.metadata.get(MANIFEST_FLAG_KEY).map(|v| v == "true") == Some(true)
                || e.path()
                    .map(basename)
                    .map(is_dependency_manifest)
                    .unwrap_or(false)
        })
        .min_by(|a, b| a.timestamp.cmp(&b.timestamp))?;
    let net = any_after(
        events,
        EventKind::Network,
        &manifest_write.timestamp,
        &cut,
        now_rfc3339,
    )?;
    let what = manifest_write
        .path()
        .map(basename)
        .filter(|b| !b.is_empty())
        .unwrap_or("a dependency manifest");
    let host = net
        .metadata
        .get("host")
        .or_else(|| net.metadata.get("domain"))
        .map(|h| h.as_str())
        .unwrap_or("a network destination");
    Some(CorrelationHit {
        rule_id: RuleId::DependencyChangeThenNetwork,
        severity: Severity::Medium,
        title: "Dependency manifest change followed by network egress".to_string(),
        description: format!(
            "{what} was modified, then a network call to {host} ran within {DEP_CHANGE_THEN_NETWORK_WINDOW_SECS}s. A dependency edit that immediately phones out can indicate a poisoned install step."
        ),
    })
}

/// FileDelete THEN GitForcePush within 60s -> CRITICAL.
fn delete_then_force_push(events: &[TypedEvent], now_rfc3339: &str) -> Option<CorrelationHit> {
    let cut = cutoff(now_rfc3339, DELETE_THEN_FORCE_PUSH_WINDOW_SECS)?;
    let del = earliest_in_window(events, EventKind::FileDelete, &cut, now_rfc3339)?;
    let push = any_after(
        events,
        EventKind::GitForcePush,
        &del.timestamp,
        &cut,
        now_rfc3339,
    )?;
    let _ = push;
    Some(CorrelationHit {
        rule_id: RuleId::DeleteThenForcePush,
        severity: Severity::Critical,
        title: "File deletion followed by git force-push".to_string(),
        description: format!(
            "A file was deleted, then a `git push --force` ran within {DELETE_THEN_FORCE_PUSH_WINDOW_SECS}s. Deleting then force-pushing can erase history and overwrite a remote branch."
        ),
    })
}

/// >= 3 FileDelete within 20s, EXCLUDING build-artifact paths -> CRITICAL.
fn mass_file_deletion(events: &[TypedEvent], now_rfc3339: &str) -> Option<CorrelationHit> {
    let cut = cutoff(now_rfc3339, MASS_DELETE_WINDOW_SECS)?;
    let count = events
        .iter()
        .filter(|e| {
            e.kind == EventKind::FileDelete && within_window(&e.timestamp, &cut, now_rfc3339)
        })
        // A delete with NO path is counted (conservative: we cannot prove it is
        // a build artifact). A delete WITH a build-artifact path is excluded.
        .filter(|e| {
            e.path()
                .map(|p| !crate::util_build_dirs::is_build_artifact_path(p))
                .unwrap_or(true)
        })
        .count();
    if count >= MASS_DELETE_THRESHOLD {
        Some(CorrelationHit {
            rule_id: RuleId::MassFileDeletion,
            severity: Severity::Critical,
            title: "Mass file deletion in a short window".to_string(),
            description: format!(
                "{count} non-build files were deleted within {MASS_DELETE_WINDOW_SECS}s. A burst of deletions can be destructive (ransomware-like or an accidental recursive wipe)."
            ),
        })
    } else {
        None
    }
}

/// Final path component, split on both `/` and `\`.
fn basename(path: &str) -> &str {
    path.rsplit(['/', '\\']).next().unwrap_or(path)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `base + offset_secs`, rendered the way recorders render timestamps.
    fn ts(base: chrono::DateTime<chrono::Utc>, offset_secs: i64) -> String {
        (base + chrono::Duration::seconds(offset_secs)).to_rfc3339()
    }

    fn now() -> chrono::DateTime<chrono::Utc> {
        chrono::Utc::now()
    }

    fn ev(timestamp: String, kind: EventKind) -> TypedEvent {
        TypedEvent {
            timestamp,
            kind,
            rule_id: "test".to_string(),
            metadata: BTreeMap::new(),
        }
    }

    fn ev_path(timestamp: String, kind: EventKind, path: &str) -> TypedEvent {
        let mut e = ev(timestamp, kind);
        e.metadata.insert("path".to_string(), path.to_string());
        e
    }

    fn fired(hits: &[CorrelationHit], rule: RuleId) -> bool {
        hits.iter().any(|h| h.rule_id == rule)
    }

    // --- SecretWrite THEN Network -------------------------------------------

    #[test]
    fn secret_then_network_fires_in_window() {
        let base = now();
        // Place both events comfortably inside the 30s window, secret first.
        let events = vec![
            ev(ts(base, -20), EventKind::SecretWrite),
            ev(ts(base, -10), EventKind::Network),
        ];
        let hits = correlate(&events, &base.to_rfc3339());
        assert!(fired(&hits, RuleId::SecretWriteThenNetwork));
    }

    #[test]
    fn secret_then_network_outside_window_does_not_fire() {
        let base = now();
        // Secret is 40s before now: outside the 30s window.
        let events = vec![
            ev(ts(base, -40), EventKind::SecretWrite),
            ev(ts(base, -38), EventKind::Network),
        ];
        let hits = correlate(&events, &base.to_rfc3339());
        assert!(!fired(&hits, RuleId::SecretWriteThenNetwork));
    }

    #[test]
    fn secret_then_network_wrong_order_does_not_fire() {
        let base = now();
        // Network BEFORE the secret write: not the "A then B" sequence.
        let events = vec![
            ev(ts(base, -20), EventKind::Network),
            ev(ts(base, -10), EventKind::SecretWrite),
        ];
        let hits = correlate(&events, &base.to_rfc3339());
        assert!(!fired(&hits, RuleId::SecretWriteThenNetwork));
    }

    // --- DependencyChange THEN Network --------------------------------------

    #[test]
    fn dependency_change_then_network_fires_via_flag() {
        let base = now();
        let mut write = ev(ts(base, -50), EventKind::FileWrite);
        write
            .metadata
            .insert(MANIFEST_FLAG_KEY.to_string(), "true".to_string());
        let events = vec![write, ev(ts(base, -10), EventKind::Network)];
        let hits = correlate(&events, &base.to_rfc3339());
        assert!(fired(&hits, RuleId::DependencyChangeThenNetwork));
        // It is a WARN-class (Medium) correlation, not CRITICAL.
        let hit = hits
            .iter()
            .find(|h| h.rule_id == RuleId::DependencyChangeThenNetwork)
            .unwrap();
        assert_eq!(hit.severity, Severity::Medium);
    }

    #[test]
    fn dependency_change_then_network_fires_via_basename() {
        let base = now();
        let events = vec![
            ev_path(ts(base, -50), EventKind::FileWrite, "repo/package.json"),
            ev(ts(base, -5), EventKind::Network),
        ];
        let hits = correlate(&events, &base.to_rfc3339());
        assert!(fired(&hits, RuleId::DependencyChangeThenNetwork));
    }

    #[test]
    fn dependency_change_non_manifest_write_does_not_fire() {
        let base = now();
        let events = vec![
            ev_path(ts(base, -50), EventKind::FileWrite, "src/main.rs"),
            ev(ts(base, -5), EventKind::Network),
        ];
        let hits = correlate(&events, &base.to_rfc3339());
        assert!(!fired(&hits, RuleId::DependencyChangeThenNetwork));
    }

    #[test]
    fn dependency_change_then_network_outside_window_does_not_fire() {
        let base = now();
        // Manifest write 70s ago: outside the 60s window.
        let events = vec![
            ev_path(ts(base, -70), EventKind::FileWrite, "go.mod"),
            ev(ts(base, -65), EventKind::Network),
        ];
        let hits = correlate(&events, &base.to_rfc3339());
        assert!(!fired(&hits, RuleId::DependencyChangeThenNetwork));
    }

    // --- FileDelete THEN GitForcePush ---------------------------------------

    #[test]
    fn delete_then_force_push_fires_in_window() {
        let base = now();
        let events = vec![
            ev(ts(base, -40), EventKind::FileDelete),
            ev(ts(base, -5), EventKind::GitForcePush),
        ];
        let hits = correlate(&events, &base.to_rfc3339());
        assert!(fired(&hits, RuleId::DeleteThenForcePush));
    }

    #[test]
    fn delete_then_force_push_wrong_order_does_not_fire() {
        let base = now();
        let events = vec![
            ev(ts(base, -40), EventKind::GitForcePush),
            ev(ts(base, -5), EventKind::FileDelete),
        ];
        let hits = correlate(&events, &base.to_rfc3339());
        assert!(!fired(&hits, RuleId::DeleteThenForcePush));
    }

    #[test]
    fn delete_then_force_push_outside_window_does_not_fire() {
        let base = now();
        // Delete 90s ago: outside the 60s window.
        let events = vec![
            ev(ts(base, -90), EventKind::FileDelete),
            ev(ts(base, -80), EventKind::GitForcePush),
        ];
        let hits = correlate(&events, &base.to_rfc3339());
        assert!(!fired(&hits, RuleId::DeleteThenForcePush));
    }

    // --- Mass file deletion --------------------------------------------------

    #[test]
    fn mass_deletion_fires_at_threshold() {
        let base = now();
        let events = vec![
            ev_path(ts(base, -15), EventKind::FileDelete, "src/a.rs"),
            ev_path(ts(base, -10), EventKind::FileDelete, "src/b.rs"),
            ev_path(ts(base, -5), EventKind::FileDelete, "src/c.rs"),
        ];
        let hits = correlate(&events, &base.to_rfc3339());
        assert!(fired(&hits, RuleId::MassFileDeletion));
    }

    #[test]
    fn mass_deletion_below_threshold_does_not_fire() {
        let base = now();
        let events = vec![
            ev_path(ts(base, -15), EventKind::FileDelete, "src/a.rs"),
            ev_path(ts(base, -5), EventKind::FileDelete, "src/b.rs"),
        ];
        let hits = correlate(&events, &base.to_rfc3339());
        assert!(!fired(&hits, RuleId::MassFileDeletion));
    }

    #[test]
    fn mass_deletion_excludes_build_artifacts() {
        let base = now();
        // Three deletes, but all under build-artifact dirs: must NOT trip.
        let events = vec![
            ev_path(ts(base, -15), EventKind::FileDelete, "node_modules/a.js"),
            ev_path(ts(base, -10), EventKind::FileDelete, "target/debug/b"),
            ev_path(ts(base, -5), EventKind::FileDelete, "dist/c.js"),
        ];
        let hits = correlate(&events, &base.to_rfc3339());
        assert!(!fired(&hits, RuleId::MassFileDeletion));
    }

    #[test]
    fn mass_deletion_mixes_build_and_source_counts_only_source() {
        let base = now();
        // Two build-artifact deletes + two real source deletes = 2 counted: below
        // the threshold of 3, so it must NOT fire.
        let events = vec![
            ev_path(ts(base, -15), EventKind::FileDelete, "node_modules/a.js"),
            ev_path(ts(base, -14), EventKind::FileDelete, "target/b"),
            ev_path(ts(base, -10), EventKind::FileDelete, "src/x.rs"),
            ev_path(ts(base, -5), EventKind::FileDelete, "src/y.rs"),
        ];
        let hits = correlate(&events, &base.to_rfc3339());
        assert!(!fired(&hits, RuleId::MassFileDeletion));

        // Add a third real source delete: now it fires.
        let mut events = events;
        events.push(ev_path(ts(base, -3), EventKind::FileDelete, "src/z.rs"));
        let hits = correlate(&events, &base.to_rfc3339());
        assert!(fired(&hits, RuleId::MassFileDeletion));
    }

    #[test]
    fn mass_deletion_outside_window_does_not_fire() {
        let base = now();
        // All deletes are >20s old.
        let events = vec![
            ev_path(ts(base, -40), EventKind::FileDelete, "src/a.rs"),
            ev_path(ts(base, -35), EventKind::FileDelete, "src/b.rs"),
            ev_path(ts(base, -30), EventKind::FileDelete, "src/c.rs"),
        ];
        let hits = correlate(&events, &base.to_rfc3339());
        assert!(!fired(&hits, RuleId::MassFileDeletion));
    }

    // --- helpers + isolation -------------------------------------------------

    #[test]
    fn empty_events_yield_no_hits() {
        let base = now();
        assert!(correlate(&[], &base.to_rfc3339()).is_empty());
    }

    #[test]
    fn malformed_now_is_safe_no_hits() {
        // A clock string that does not parse must never fabricate a correlation.
        let events = vec![
            ev(
                "2026-01-01T00:00:00+00:00".to_string(),
                EventKind::SecretWrite,
            ),
            ev("2026-01-01T00:00:05+00:00".to_string(), EventKind::Network),
        ];
        let hits = correlate(&events, "not-a-timestamp");
        assert!(hits.is_empty());
    }

    #[test]
    fn is_dependency_manifest_matches_known_and_rejects_others() {
        assert!(is_dependency_manifest("package.json"));
        assert!(is_dependency_manifest("Cargo.toml"));
        assert!(is_dependency_manifest("requirements.txt"));
        assert!(is_dependency_manifest("go.mod"));
        assert!(is_dependency_manifest("pnpm-lock.yaml"));
        assert!(is_dependency_manifest("package-lock.json"));
        assert!(!is_dependency_manifest("main.rs"));
        assert!(!is_dependency_manifest("README.md"));
    }

    #[test]
    fn basename_splits_both_separators() {
        assert_eq!(basename("a/b/c.txt"), "c.txt");
        assert_eq!(basename("a\\b\\c.txt"), "c.txt");
        assert_eq!(basename("nodir"), "nodir");
    }
}
