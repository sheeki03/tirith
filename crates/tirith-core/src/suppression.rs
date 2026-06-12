//! W6 — per-rule suppression cooldown (pure logic).
//!
//! Collapses repeated identical findings within a cooldown window so the same
//! rule does not prompt or alert over and over in one session. This is NOT a
//! detection or policy layer and it NEVER drops data: the caller still records a
//! compact audit rollup (and a pending rollup entry) for every suppressed hit.
//!
//! The cooldown state itself is a `rule_key -> expires_at` map that lives on the
//! persisted session record (see `session_warnings`), so one-shot CLI / hook
//! invocations (separate processes) honor a cooldown started by an earlier one.
//! An in-memory-only map would reset on every process.

use std::collections::BTreeMap;

/// Default cooldown window for a repeated identical finding (30 minutes).
pub const DEFAULT_COOLDOWN_SECS: u64 = 1800;

/// Build the cooldown map key for a fired rule, optionally scoped to a target
/// (e.g. a domain or path) so one target's cooldown does not silence another.
pub fn cooldown_key(rule_id: &str, target: Option<&str>) -> String {
    match target {
        Some(t) if !t.is_empty() => format!("{rule_id}|{t}"),
        _ => rule_id.to_string(),
    }
}

/// Whether `expires_at` is still in the future relative to `now`. Both are
/// RFC3339 UTC timestamps produced by `chrono::Utc::now().to_rfc3339()`, which
/// are lexicographically comparable (same offset form), matching how
/// `session_warnings` compares its window timestamps.
pub fn is_active(expires_at: &str, now: &str) -> bool {
    expires_at > now
}

/// Check the cooldown for `key` against `now`, pruning the entry if it has
/// expired. Returns `true` when the key is CURRENTLY suppressed (within its
/// window), in which case the caller should collapse the finding into a rollup
/// rather than surfacing it again.
pub fn is_suppressed(cooldowns: &mut BTreeMap<String, String>, key: &str, now: &str) -> bool {
    match cooldowns.get(key) {
        Some(exp) if is_active(exp, now) => true,
        Some(_) => {
            cooldowns.remove(key);
            false
        }
        None => false,
    }
}

/// Start or extend the cooldown for `key`, expiring at `expires_at` (RFC3339).
pub fn record(cooldowns: &mut BTreeMap<String, String>, key: &str, expires_at: String) {
    cooldowns.insert(key.to_string(), expires_at);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn key_scoping() {
        assert_eq!(cooldown_key("r1", None), "r1");
        assert_eq!(cooldown_key("r1", Some("")), "r1");
        assert_eq!(cooldown_key("r1", Some("evil.com")), "r1|evil.com");
    }

    #[test]
    fn cooldown_lifecycle() {
        let mut cd = BTreeMap::new();
        // Not suppressed before recording.
        assert!(!is_suppressed(&mut cd, "r1", "2026-06-12T00:00:00+00:00"));
        // Record a cooldown that expires in the future.
        record(&mut cd, "r1", "2026-06-12T01:00:00+00:00".to_string());
        assert!(is_suppressed(&mut cd, "r1", "2026-06-12T00:30:00+00:00"));
        // Past the window: not suppressed, and the stale entry is pruned.
        assert!(!is_suppressed(&mut cd, "r1", "2026-06-12T02:00:00+00:00"));
        assert!(!cd.contains_key("r1"));
    }
}
