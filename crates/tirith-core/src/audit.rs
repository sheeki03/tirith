use std::fs::{self, OpenOptions};
use std::io::Write;
#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;
use std::path::PathBuf;

use fs2::FileExt;
use serde::Serialize;

use crate::verdict::Verdict;

fn audit_diagnostics_enabled() -> bool {
    matches!(
        std::env::var("TIRITH_AUDIT_DEBUG")
            .ok()
            .map(|v| v.trim().to_ascii_lowercase())
            .as_deref(),
        Some("1" | "true" | "yes")
    )
}

/// Emit a non-fatal diagnostic only when debug logging is enabled.
///
/// This is used for auxiliary/background paths that must never interfere with
/// shell-hook execution or change the command verdict.
pub fn audit_diagnostic(msg: impl AsRef<str>) {
    if audit_diagnostics_enabled() {
        eprintln!("{}", msg.as_ref());
    }
}

/// An audit log entry.
#[derive(Debug, Clone, Serialize)]
pub struct AuditEntry {
    pub timestamp: String,
    pub session_id: String,
    pub action: String,
    pub rule_ids: Vec<String>,
    pub command_redacted: String,
    pub bypass_requested: bool,
    pub bypass_honored: bool,
    pub interactive: bool,
    pub policy_path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub event_id: Option<String>,
    pub tier_reached: u8,

    /// Tagged-union discriminator — "verdict", "hook_telemetry", or "trust_change".
    pub entry_type: String,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub event: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub integration: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hook_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub elapsed_ms: Option<f64>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub raw_action: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub raw_rule_ids: Option<Vec<String>>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub trust_pattern: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub trust_rule_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub trust_action: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub trust_ttl_expires: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub trust_scope: Option<String>,

    /// Best-effort origin of the caller. Populated by [`log_verdict_with_raw`]
    /// (via [`log_verdict_with_origin`]) for verdict entries; left `None` for
    /// `hook_telemetry` and `trust_change` entries. Old log files without
    /// this field still parse (serde-default on read).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub agent_origin: Option<crate::agent_origin::AgentOrigin>,
}

/// Outcome of an audit-log append.
///
/// The distinction matters for callers that want to surface a failed write:
/// [`AuditWrite::Skipped`] is *not* an error (the user turned logging off, or
/// no log path could be resolved), whereas [`AuditWrite::Failed`] is a real I/O
/// failure that broke the "recorded transaction" promise.
enum AuditWrite {
    /// The entry was written; the serialized line is carried for the optional
    /// remote-upload spool.
    Written(String),
    /// Logging was intentionally not performed — `TIRITH_LOG=0`, or no log
    /// path. Not an error.
    Skipped,
    /// A real write failure. The string is a human-readable reason.
    Failed(String),
}

/// Shared I/O helper: serialize an AuditEntry and append it to the audit log.
/// Handles TIRITH_LOG check, path resolution, dir creation, symlink guard,
/// open, lock, write, sync, unlock. Never panics or changes behavior on failure;
/// a real write failure is reported as [`AuditWrite::Failed`] so callers may
/// surface it.
fn append_to_audit_log(entry: &AuditEntry, log_path: Option<PathBuf>) -> AuditWrite {
    if std::env::var("TIRITH_LOG").ok().as_deref() == Some("0") {
        return AuditWrite::Skipped;
    }

    let Some(path) = log_path.or_else(default_log_path) else {
        return AuditWrite::Skipped;
    };

    if let Some(parent) = path.parent() {
        if let Err(e) = fs::create_dir_all(parent) {
            let reason = format!("cannot create log dir {}: {e}", parent.display());
            audit_diagnostic(format!("tirith: audit: {reason}"));
            return AuditWrite::Failed(reason);
        }
    }

    let line = match serde_json::to_string(entry) {
        Ok(l) => l,
        Err(e) => {
            let reason = format!("failed to serialize entry: {e}");
            audit_diagnostic(format!("tirith: audit: {reason}"));
            return AuditWrite::Failed(reason);
        }
    };

    // Refuse to follow symlinks — prevents an attacker with write access in the
    // log directory from redirecting audit output to an arbitrary file.
    #[cfg(unix)]
    {
        match std::fs::symlink_metadata(&path) {
            Ok(meta) if meta.file_type().is_symlink() => {
                let reason = format!("refusing to follow symlink at {}", path.display());
                audit_diagnostic(format!("tirith: audit: {reason}"));
                return AuditWrite::Failed(reason);
            }
            _ => {}
        }
    }

    let mut open_opts = OpenOptions::new();
    open_opts.create(true).append(true);
    #[cfg(unix)]
    {
        open_opts.mode(0o600);
        open_opts.custom_flags(libc::O_NOFOLLOW);
    }
    let file = open_opts.open(&path);

    let file = match file {
        Ok(f) => f,
        Err(e) => {
            let reason = format!("cannot open {}: {e}", path.display());
            audit_diagnostic(format!("tirith: audit: {reason}"));
            return AuditWrite::Failed(reason);
        }
    };

    // Enforce 0600 even on pre-existing files created before this tightening.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = file.set_permissions(std::fs::Permissions::from_mode(0o600));
    }

    if let Err(e) = file.lock_exclusive() {
        let reason = format!("cannot lock {}: {e}", path.display());
        audit_diagnostic(format!("tirith: audit: {reason}"));
        return AuditWrite::Failed(reason);
    }

    let mut writer = std::io::BufWriter::new(&file);
    if let Err(e) = writeln!(writer, "{line}") {
        let reason = format!("write failed: {e}");
        audit_diagnostic(format!("tirith: audit: {reason}"));
        let _ = fs2::FileExt::unlock(&file);
        return AuditWrite::Failed(reason);
    }
    if let Err(e) = writer.flush() {
        let reason = format!("flush failed: {e}");
        audit_diagnostic(format!("tirith: audit: {reason}"));
        let _ = fs2::FileExt::unlock(&file);
        return AuditWrite::Failed(reason);
    }
    // A failed `sync_all()` means the line reached the OS buffer but was not
    // durably flushed to disk — the "recorded transaction" promise is not met.
    // Report it as a real write failure so the caller can surface it, rather
    // than claiming the entry was written.
    if let Err(e) = file.sync_all() {
        let reason = format!("sync failed: {e}");
        audit_diagnostic(format!("tirith: audit: {reason}"));
        let _ = fs2::FileExt::unlock(&file);
        return AuditWrite::Failed(reason);
    }
    let _ = fs2::FileExt::unlock(&file);

    AuditWrite::Written(line)
}

/// Append an entry to the audit log. Never panics or changes verdict on failure.
///
/// `custom_dlp_patterns` are Team-tier regex patterns applied alongside built-in
/// DLP redaction before the command is written to the log.
///
/// Returns `Ok(())` when the entry was written *or* logging was intentionally
/// not performed (`TIRITH_LOG=0`, no resolvable log path). Returns `Err(reason)`
/// only on a real write failure — a caller that promises a "recorded
/// transaction" can surface that failure as a non-fatal notice. The result is
/// `#[must_use]`: a caller that genuinely does not care must `let _ =` it.
#[must_use = "a failed audit write is silently lost unless the Result is handled"]
pub fn log_verdict(
    verdict: &Verdict,
    command: &str,
    log_path: Option<PathBuf>,
    event_id: Option<String>,
    custom_dlp_patterns: &[String],
) -> Result<(), String> {
    log_verdict_with_raw(
        verdict,
        command,
        log_path,
        event_id,
        custom_dlp_patterns,
        None,
        None,
    )
}

/// Like `log_verdict` but accepts optional raw (pre-post-processing) action and rule_ids.
///
/// `raw_action` captures the engine's original action before overrides/escalation.
/// `raw_rule_ids` captures all rule_ids from raw detection (before paranoia).
///
/// Returns `Err(reason)` only on a real write failure (see [`log_verdict`]).
#[must_use = "a failed audit write is silently lost unless the Result is handled"]
pub fn log_verdict_with_raw(
    verdict: &Verdict,
    command: &str,
    log_path: Option<PathBuf>,
    event_id: Option<String>,
    custom_dlp_patterns: &[String],
    raw_action: Option<String>,
    raw_rule_ids: Option<Vec<String>>,
) -> Result<(), String> {
    let entry = AuditEntry {
        timestamp: chrono::Utc::now().to_rfc3339(),
        session_id: crate::session::resolve_session_id(),
        action: format!("{:?}", verdict.action),
        rule_ids: verdict
            .findings
            .iter()
            .map(|f| f.rule_id.to_string())
            .collect(),
        command_redacted: redact_command(command, custom_dlp_patterns),
        bypass_requested: verdict.bypass_requested,
        bypass_honored: verdict.bypass_honored,
        interactive: verdict.interactive_detected,
        policy_path: verdict.policy_path_used.clone(),
        event_id,
        tier_reached: verdict.tier_reached,
        entry_type: "verdict".to_string(),
        event: None,
        integration: None,
        hook_type: None,
        detail: None,
        elapsed_ms: None,
        raw_action,
        raw_rule_ids,
        trust_pattern: None,
        trust_rule_id: None,
        trust_action: None,
        trust_ttl_expires: None,
        trust_scope: None,
        // M4 item 8: carry the caller's self-identified origin through to
        // the audit entry when the verdict path set one. The origin is
        // already consulted for enforcement upstream of this call (see
        // `escalation::apply_agent_rules`); the audit record preserves it
        // so downstream tooling can attribute verdicts after the fact.
        agent_origin: verdict.agent_origin.clone(),
    };

    let line = match append_to_audit_log(&entry, log_path) {
        AuditWrite::Written(l) => l,
        // Logging was intentionally off — not a failure the caller should hear
        // about.
        AuditWrite::Skipped => return Ok(()),
        // A real write failure — the "recorded transaction" promise broke.
        AuditWrite::Failed(reason) => return Err(reason),
    };

    // If a policy server is configured via env vars, spool the redacted audit
    // entry for background upload.
    let server_url = std::env::var("TIRITH_SERVER_URL")
        .ok()
        .filter(|s| !s.is_empty());
    let api_key = std::env::var("TIRITH_API_KEY")
        .ok()
        .filter(|s| !s.is_empty());
    if let (Some(url), Some(key)) = (server_url, api_key) {
        crate::audit_upload::spool_and_upload(&line, &url, &key, None, None);
    }
    Ok(())
}

/// Log a hook telemetry event to the audit log. Never panics or changes behavior on failure.
///
/// This reuses the same log file and I/O pattern as `log_verdict`, but with
/// `entry_type = "hook_telemetry"` and `action = "hook"` (sentinel).
pub fn log_hook_event(
    integration: &str,
    hook_type: &str,
    event: &str,
    elapsed_ms: Option<f64>,
    detail: Option<&str>,
) {
    let entry = AuditEntry {
        timestamp: chrono::Utc::now().to_rfc3339(),
        session_id: crate::session::resolve_session_id(),
        action: "hook".to_string(),
        rule_ids: vec![],
        command_redacted: String::new(),
        bypass_requested: false,
        bypass_honored: false,
        interactive: false,
        policy_path: None,
        event_id: None,
        tier_reached: 0,
        entry_type: "hook_telemetry".to_string(),
        event: Some(event.to_string()),
        integration: Some(integration.to_string()),
        hook_type: Some(hook_type.to_string()),
        detail: detail.map(String::from),
        elapsed_ms,
        raw_action: None,
        raw_rule_ids: None,
        trust_pattern: None,
        trust_rule_id: None,
        trust_action: None,
        trust_ttl_expires: None,
        trust_scope: None,
        // Hook telemetry already carries `integration` (the hook name); we
        // deliberately do NOT synthesize an `AgentOrigin::Agent` here because
        // a hook event isn't a verdict — it's a probe / heartbeat from the
        // shell hook. Chunk 2+ may revisit and emit a synthetic origin for
        // hook events that originated from a known agent integration.
        agent_origin: None,
    };

    // Telemetry / trust-change entries are best-effort; a write failure here is
    // not surfaced to the user (unlike `log_verdict`'s recorded-transaction
    // promise). The diagnostic inside `append_to_audit_log` still fires under
    // `TIRITH_AUDIT_DEBUG`.
    let _ = append_to_audit_log(&entry, None);
}

/// Log a trust change (add/remove) to the audit log. Never panics or changes behavior on failure.
///
/// This reuses the same log file and I/O pattern as `log_verdict`, but with
/// `entry_type = "trust_change"` and `action = "trust"` (sentinel).
pub fn log_trust_change(
    pattern: &str,
    rule_id: Option<&str>,
    trust_action: &str,
    ttl_expires: Option<&str>,
    scope: &str,
) {
    let entry = AuditEntry {
        timestamp: chrono::Utc::now().to_rfc3339(),
        session_id: crate::session::resolve_session_id(),
        action: "trust".to_string(),
        rule_ids: vec![],
        command_redacted: String::new(),
        bypass_requested: false,
        bypass_honored: false,
        interactive: false,
        policy_path: None,
        event_id: None,
        tier_reached: 0,
        entry_type: "trust_change".to_string(),
        event: None,
        integration: None,
        hook_type: None,
        detail: None,
        elapsed_ms: None,
        raw_action: None,
        raw_rule_ids: None,
        trust_pattern: Some(pattern.to_string()),
        trust_rule_id: rule_id.map(String::from),
        trust_action: Some(trust_action.to_string()),
        trust_ttl_expires: ttl_expires.map(String::from),
        trust_scope: Some(scope.to_string()),
        // Trust changes are operator/admin actions, not commands attributed
        // to an agent. Leaving `agent_origin` as `None` keeps the entry
        // type's semantics clear.
        agent_origin: None,
    };

    // Telemetry / trust-change entries are best-effort; a write failure here is
    // not surfaced to the user (unlike `log_verdict`'s recorded-transaction
    // promise). The diagnostic inside `append_to_audit_log` still fires under
    // `TIRITH_AUDIT_DEBUG`.
    let _ = append_to_audit_log(&entry, None);
}

fn default_log_path() -> Option<PathBuf> {
    crate::policy::data_dir().map(|d| d.join("log.jsonl"))
}

/// Public accessor for the audit log path so out-of-crate readers
/// (e.g. `tirith trust audit`, M6 ch3) can locate it without hard-coding
/// `data_dir()/log.jsonl`.
pub fn audit_log_path() -> Option<PathBuf> {
    default_log_path()
}

fn redact_command(cmd: &str, custom_patterns: &[String]) -> String {
    let dlp_redacted = crate::redact::redact_with_custom(cmd, custom_patterns);
    let prefix = crate::util::truncate_bytes(&dlp_redacted, 80);
    if prefix.len() == dlp_redacted.len() {
        dlp_redacted
    } else {
        format!(
            "{}[...redacted {} bytes]",
            prefix,
            dlp_redacted.len() - prefix.len()
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::verdict::{Action, Verdict};

    #[test]
    fn test_tirith_log_disabled() {
        let _guard = crate::TEST_ENV_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let dir = tempfile::tempdir().unwrap();
        let log_path = dir.path().join("test.jsonl");

        unsafe { std::env::set_var("TIRITH_LOG", "0") };

        let verdict = Verdict {
            action: Action::Allow,
            findings: vec![],
            tier_reached: 1,
            timings_ms: crate::verdict::Timings {
                tier0_ms: 0.0,
                tier1_ms: 0.0,
                tier2_ms: None,
                tier3_ms: None,
                total_ms: 0.0,
            },
            bypass_requested: false,
            bypass_honored: false,
            bypass_available: false,
            interactive_detected: false,
            policy_path_used: None,
            urls_extracted_count: None,
            requires_approval: None,
            approval_timeout_secs: None,
            approval_fallback: None,
            approval_rule: None,
            approval_description: None,
            escalation_reason: None,
            agent_origin: None,
        };

        // TIRITH_LOG=0 is an intentional skip, not a failure → Ok(()).
        assert!(
            log_verdict(&verdict, "test cmd", Some(log_path.clone()), None, &[]).is_ok(),
            "TIRITH_LOG=0 is an intentional skip, not a write failure"
        );

        assert!(
            !log_path.exists(),
            "log file should not be created when TIRITH_LOG=0"
        );

        unsafe { std::env::remove_var("TIRITH_LOG") };
    }

    #[test]
    fn test_audit_diagnostics_disabled_by_default() {
        let _guard = crate::TEST_ENV_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        unsafe { std::env::remove_var("TIRITH_AUDIT_DEBUG") };
        assert!(!audit_diagnostics_enabled());
    }

    #[test]
    fn test_audit_diagnostics_enabled_by_env() {
        let _guard = crate::TEST_ENV_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        unsafe { std::env::set_var("TIRITH_AUDIT_DEBUG", "true") };
        assert!(audit_diagnostics_enabled());
        unsafe { std::env::remove_var("TIRITH_AUDIT_DEBUG") };
    }

    #[cfg(unix)]
    #[test]
    fn test_audit_log_permissions_0600() {
        use std::os::unix::fs::PermissionsExt;

        // Test the OpenOptions pattern directly — avoids env var races with
        // test_tirith_log_disabled (which sets TIRITH_LOG=0 in the same process).
        let dir = tempfile::tempdir().unwrap();
        let log_path = dir.path().join("test_perms.jsonl");

        {
            use std::io::Write;
            let mut open_opts = OpenOptions::new();
            open_opts.create(true).append(true);
            use std::os::unix::fs::OpenOptionsExt;
            open_opts.mode(0o600);
            let mut f = open_opts.open(&log_path).unwrap();
            writeln!(f, "test").unwrap();
        }

        let meta = std::fs::metadata(&log_path).unwrap();
        assert_eq!(
            meta.permissions().mode() & 0o777,
            0o600,
            "audit log should be 0600"
        );
    }

    #[cfg(unix)]
    #[test]
    fn test_remote_audit_upload_spools_when_configured() {
        let _guard = crate::TEST_ENV_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());

        let dir = tempfile::tempdir().unwrap();
        let log_path = dir.path().join("audit.jsonl");
        let state_home = dir.path().join("state");

        // Invalid local URL so drain returns early after spooling.
        unsafe { std::env::set_var("TIRITH_SERVER_URL", "http://127.0.0.1") };
        unsafe { std::env::set_var("TIRITH_API_KEY", "dummy") };
        unsafe { std::env::set_var("XDG_STATE_HOME", &state_home) };
        unsafe { std::env::remove_var("TIRITH_LOG") };

        let verdict = Verdict {
            action: Action::Allow,
            findings: vec![],
            tier_reached: 1,
            timings_ms: crate::verdict::Timings {
                tier0_ms: 0.0,
                tier1_ms: 0.0,
                tier2_ms: None,
                tier3_ms: None,
                total_ms: 0.0,
            },
            bypass_requested: false,
            bypass_honored: false,
            bypass_available: false,
            interactive_detected: false,
            policy_path_used: None,
            urls_extracted_count: None,
            requires_approval: None,
            approval_timeout_secs: None,
            approval_fallback: None,
            approval_rule: None,
            approval_description: None,
            escalation_reason: None,
            agent_origin: None,
        };

        let _ = log_verdict(&verdict, "echo hello", Some(log_path), None, &[]);

        let spool = state_home.join("tirith").join("audit-queue.jsonl");
        assert!(spool.exists(), "remote audit events should be spooled");

        unsafe { std::env::remove_var("XDG_STATE_HOME") };
        unsafe { std::env::remove_var("TIRITH_API_KEY") };
        unsafe { std::env::remove_var("TIRITH_SERVER_URL") };
    }

    #[cfg(unix)]
    #[test]
    fn test_audit_refuses_symlink() {
        // Hermetic: hold the env lock and pin every input that could otherwise
        // route this through `AuditWrite::Skipped` (which would yield `Ok` and
        // silently break the assertion). A runner-set `TIRITH_LOG=0` would skip
        // logging entirely; an `XDG_STATE_HOME`/`APPDATA` difference only
        // affects the remote-upload spool but is pinned for full isolation.
        // The log path itself is the explicit `symlink_path` below.
        let _guard = crate::TEST_ENV_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());

        let dir = tempfile::tempdir().unwrap();
        let state_home = dir.path().join("state");
        unsafe { std::env::set_var("TIRITH_LOG", "1") };
        unsafe { std::env::set_var("XDG_STATE_HOME", &state_home) };
        unsafe { std::env::set_var("APPDATA", &state_home) };
        unsafe { std::env::remove_var("TIRITH_SERVER_URL") };
        unsafe { std::env::remove_var("TIRITH_API_KEY") };

        let target = dir.path().join("target");
        std::fs::write(&target, "original").unwrap();

        let symlink_path = dir.path().join("log.jsonl");
        std::os::unix::fs::symlink(&target, &symlink_path).unwrap();

        let verdict = Verdict {
            action: Action::Allow,
            findings: vec![],
            tier_reached: 1,
            timings_ms: crate::verdict::Timings {
                tier0_ms: 0.0,
                tier1_ms: 0.0,
                tier2_ms: None,
                tier3_ms: None,
                total_ms: 0.0,
            },
            bypass_requested: false,
            bypass_honored: false,
            bypass_available: false,
            interactive_detected: false,
            policy_path_used: None,
            urls_extracted_count: None,
            requires_approval: None,
            approval_timeout_secs: None,
            approval_fallback: None,
            approval_rule: None,
            approval_description: None,
            escalation_reason: None,
            agent_origin: None,
        };

        // Refusing the symlink is a real write failure → Err, so the caller
        // can surface it.
        let result = log_verdict(&verdict, "test cmd", Some(symlink_path), None, &[]);
        assert!(
            result.is_err(),
            "refusing a symlinked log path must report a write failure"
        );

        assert_eq!(
            std::fs::read_to_string(&target).unwrap(),
            "original",
            "audit should refuse to write through symlink"
        );

        unsafe { std::env::remove_var("TIRITH_LOG") };
        unsafe { std::env::remove_var("XDG_STATE_HOME") };
        unsafe { std::env::remove_var("APPDATA") };
    }

    /// CR2: a write that reaches `append_to_audit_log` but cannot be durably
    /// recorded must surface as a write failure, not a silent success. The
    /// symlink-refusal path is one such failure and is the closest
    /// deterministically-triggerable proxy for the `sync_all()` failure the
    /// CR2 fix also now reports — both return `AuditWrite::Failed` → `Err`.
    #[cfg(unix)]
    #[test]
    fn test_audit_durability_failure_is_reported() {
        let _guard = crate::TEST_ENV_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());

        let dir = tempfile::tempdir().unwrap();
        let state_home = dir.path().join("state");
        unsafe { std::env::set_var("TIRITH_LOG", "1") };
        unsafe { std::env::set_var("XDG_STATE_HOME", &state_home) };
        unsafe { std::env::set_var("APPDATA", &state_home) };
        unsafe { std::env::remove_var("TIRITH_SERVER_URL") };
        unsafe { std::env::remove_var("TIRITH_API_KEY") };

        // A directory cannot be opened for append — `append_to_audit_log` must
        // report this as `AuditWrite::Failed`, never silently succeed.
        let log_path = dir.path().join("not-a-file");
        std::fs::create_dir(&log_path).unwrap();

        let verdict = Verdict {
            action: Action::Allow,
            findings: vec![],
            tier_reached: 1,
            timings_ms: crate::verdict::Timings {
                tier0_ms: 0.0,
                tier1_ms: 0.0,
                tier2_ms: None,
                tier3_ms: None,
                total_ms: 0.0,
            },
            bypass_requested: false,
            bypass_honored: false,
            bypass_available: false,
            interactive_detected: false,
            policy_path_used: None,
            urls_extracted_count: None,
            requires_approval: None,
            approval_timeout_secs: None,
            approval_fallback: None,
            approval_rule: None,
            approval_description: None,
            escalation_reason: None,
            agent_origin: None,
        };

        let result = log_verdict(&verdict, "test cmd", Some(log_path), None, &[]);
        assert!(
            result.is_err(),
            "an audit write that cannot be durably recorded must report a failure"
        );

        unsafe { std::env::remove_var("TIRITH_LOG") };
        unsafe { std::env::remove_var("XDG_STATE_HOME") };
        unsafe { std::env::remove_var("APPDATA") };
    }

    /// M4 item 8 chunk 1 — the verdict's `agent_origin` must flow through
    /// `log_verdict_with_raw` into the audit entry and survive the JSON
    /// round-trip cleanly.
    #[cfg(unix)]
    #[test]
    fn test_audit_entry_carries_agent_origin() {
        use crate::agent_origin::AgentOrigin;
        use crate::audit_aggregator;

        let _guard = crate::TEST_ENV_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());

        let dir = tempfile::tempdir().unwrap();
        let log_path = dir.path().join("audit.jsonl");
        let state_home = dir.path().join("state");
        unsafe {
            std::env::set_var("TIRITH_LOG", "1");
            std::env::set_var("XDG_STATE_HOME", &state_home);
            std::env::set_var("APPDATA", &state_home);
            std::env::remove_var("TIRITH_SERVER_URL");
            std::env::remove_var("TIRITH_API_KEY");
        }

        let mut verdict = Verdict {
            action: Action::Allow,
            findings: vec![],
            tier_reached: 1,
            timings_ms: crate::verdict::Timings::default(),
            bypass_requested: false,
            bypass_honored: false,
            bypass_available: false,
            interactive_detected: false,
            policy_path_used: None,
            urls_extracted_count: None,
            requires_approval: None,
            approval_timeout_secs: None,
            approval_fallback: None,
            approval_rule: None,
            approval_description: None,
            escalation_reason: None,
            agent_origin: None,
        };
        verdict.agent_origin = AgentOrigin::agent("claude-code", Some("1.2.3"));

        log_verdict(&verdict, "echo hi", Some(log_path.clone()), None, &[])
            .expect("audit write should succeed");

        let read = audit_aggregator::read_log(&log_path).expect("read_log");
        assert_eq!(read.records.len(), 1, "expected exactly one audit record");
        let rec = &read.records[0];
        match rec.agent_origin.as_ref().expect("agent_origin present") {
            AgentOrigin::Agent { tool, version } => {
                assert_eq!(tool, "claude-code");
                assert_eq!(version.as_deref(), Some("1.2.3"));
            }
            other => panic!("expected Agent variant, got {other:?}"),
        }

        unsafe {
            std::env::remove_var("TIRITH_LOG");
            std::env::remove_var("XDG_STATE_HOME");
            std::env::remove_var("APPDATA");
        }
    }

    /// M4 item 8 chunk 1 — an old log line without an `agent_origin` field
    /// must still parse cleanly (serde-default).
    #[cfg(unix)]
    #[test]
    fn test_audit_record_parses_legacy_line_without_agent_origin() {
        use crate::audit_aggregator;

        let _guard = crate::TEST_ENV_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());

        let dir = tempfile::tempdir().unwrap();
        let log_path = dir.path().join("legacy.jsonl");

        // A pre-chunk-1 audit line — no agent_origin field at all.
        let legacy = r#"{"timestamp":"2026-04-10T12:00:00+00:00","session_id":"abc","action":"Allow","rule_ids":[],"command_redacted":"echo hi","bypass_requested":false,"bypass_honored":false,"interactive":false,"tier_reached":1,"entry_type":"verdict"}"#;
        std::fs::write(&log_path, format!("{legacy}\n")).unwrap();

        let read = audit_aggregator::read_log(&log_path).expect("read_log");
        assert_eq!(read.records.len(), 1);
        assert_eq!(read.skipped_lines, 0);
        assert!(
            read.records[0].agent_origin.is_none(),
            "legacy line must parse with agent_origin = None"
        );
    }

    /// M4 item 8 chunk 1 — a verdict with `agent_origin: None` must NOT
    /// emit the field on the wire (kept clean via skip_serializing_if).
    #[cfg(unix)]
    #[test]
    fn test_audit_entry_omits_field_when_no_origin() {
        let _guard = crate::TEST_ENV_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());

        let dir = tempfile::tempdir().unwrap();
        let log_path = dir.path().join("noorigin.jsonl");
        let state_home = dir.path().join("state");
        unsafe {
            std::env::set_var("TIRITH_LOG", "1");
            std::env::set_var("XDG_STATE_HOME", &state_home);
            std::env::set_var("APPDATA", &state_home);
            std::env::remove_var("TIRITH_SERVER_URL");
            std::env::remove_var("TIRITH_API_KEY");
        }

        let verdict = Verdict {
            action: Action::Allow,
            findings: vec![],
            tier_reached: 1,
            timings_ms: crate::verdict::Timings::default(),
            bypass_requested: false,
            bypass_honored: false,
            bypass_available: false,
            interactive_detected: false,
            policy_path_used: None,
            urls_extracted_count: None,
            requires_approval: None,
            approval_timeout_secs: None,
            approval_fallback: None,
            approval_rule: None,
            approval_description: None,
            escalation_reason: None,
            agent_origin: None,
        };
        log_verdict(&verdict, "echo hi", Some(log_path.clone()), None, &[])
            .expect("audit write should succeed");

        let line = std::fs::read_to_string(&log_path).unwrap();
        assert!(
            !line.contains("agent_origin"),
            "the field must be omitted when None: line was {line}"
        );

        unsafe {
            std::env::remove_var("TIRITH_LOG");
            std::env::remove_var("XDG_STATE_HOME");
            std::env::remove_var("APPDATA");
        }
    }
}
