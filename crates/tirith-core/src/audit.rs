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

    // --- Tagged-union discriminator ---
    pub entry_type: String,

    // --- Hook telemetry fields ---
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

    // --- Raw verdict fields (before post-processing) ---
    #[serde(skip_serializing_if = "Option::is_none")]
    pub raw_action: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub raw_rule_ids: Option<Vec<String>>,

    // --- Trust change fields ---
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
}

/// Shared I/O helper: serialize an AuditEntry and append it to the audit log.
/// Handles TIRITH_LOG check, path resolution, dir creation, symlink guard,
/// open, lock, write, sync, unlock. Never panics or changes behavior on failure.
fn append_to_audit_log(entry: &AuditEntry, log_path: Option<PathBuf>) -> Option<String> {
    // Early exit if logging disabled
    if std::env::var("TIRITH_LOG").ok().as_deref() == Some("0") {
        return None;
    }

    let path = log_path.or_else(default_log_path)?;

    // Ensure directory exists
    if let Some(parent) = path.parent() {
        if let Err(e) = fs::create_dir_all(parent) {
            audit_diagnostic(format!(
                "tirith: audit: cannot create log dir {}: {e}",
                parent.display()
            ));
            return None;
        }
    }

    let line = match serde_json::to_string(entry) {
        Ok(l) => l,
        Err(e) => {
            audit_diagnostic(format!("tirith: audit: failed to serialize entry: {e}"));
            return None;
        }
    };

    // Refuse to follow symlinks (GHSA-c6rj-wmf4-6963)
    #[cfg(unix)]
    {
        match std::fs::symlink_metadata(&path) {
            Ok(meta) if meta.file_type().is_symlink() => {
                audit_diagnostic(format!(
                    "tirith: audit: refusing to follow symlink at {}",
                    path.display()
                ));
                return None;
            }
            _ => {}
        }
    }

    // Open, lock, append, fsync, unlock
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
            audit_diagnostic(format!(
                "tirith: audit: cannot open {}: {e}",
                path.display()
            ));
            return None;
        }
    };

    // Harden legacy files: enforce 0600 on existing files too
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = file.set_permissions(std::fs::Permissions::from_mode(0o600));
    }

    if let Err(e) = file.lock_exclusive() {
        audit_diagnostic(format!(
            "tirith: audit: cannot lock {}: {e}",
            path.display()
        ));
        return None;
    }

    let mut writer = std::io::BufWriter::new(&file);
    if let Err(e) = writeln!(writer, "{line}") {
        audit_diagnostic(format!("tirith: audit: write failed: {e}"));
        let _ = fs2::FileExt::unlock(&file);
        return None;
    }
    if let Err(e) = writer.flush() {
        audit_diagnostic(format!("tirith: audit: flush failed: {e}"));
    }
    if let Err(e) = file.sync_all() {
        audit_diagnostic(format!("tirith: audit: sync failed: {e}"));
    }
    let _ = fs2::FileExt::unlock(&file);

    Some(line)
}

/// Append an entry to the audit log. Never panics or changes verdict on failure.
///
/// `custom_dlp_patterns` are Team-tier regex patterns applied alongside built-in
/// DLP redaction before the command is written to the log.
pub fn log_verdict(
    verdict: &Verdict,
    command: &str,
    log_path: Option<PathBuf>,
    event_id: Option<String>,
    custom_dlp_patterns: &[String],
) {
    log_verdict_with_raw(
        verdict,
        command,
        log_path,
        event_id,
        custom_dlp_patterns,
        None,
        None,
    );
}

/// Like `log_verdict` but accepts optional raw (pre-post-processing) action and rule_ids.
///
/// `raw_action` captures the engine's original action before overrides/escalation.
/// `raw_rule_ids` captures all rule_ids from raw detection (before paranoia).
pub fn log_verdict_with_raw(
    verdict: &Verdict,
    command: &str,
    log_path: Option<PathBuf>,
    event_id: Option<String>,
    custom_dlp_patterns: &[String],
    raw_action: Option<String>,
    raw_rule_ids: Option<Vec<String>>,
) {
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
    };

    let line = match append_to_audit_log(&entry, log_path) {
        Some(l) => l,
        None => return,
    };

    // --- Remote audit upload (Phase 10) ---
    // Check if a policy server is configured via env vars. If so, spool the
    // redacted audit entry for background upload.
    let server_url = std::env::var("TIRITH_SERVER_URL")
        .ok()
        .filter(|s| !s.is_empty());
    let api_key = std::env::var("TIRITH_API_KEY")
        .ok()
        .filter(|s| !s.is_empty());
    if let (Some(url), Some(key)) = (server_url, api_key) {
        crate::audit_upload::spool_and_upload(&line, &url, &key, None, None);
    }
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
    };

    append_to_audit_log(&entry, None);
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
    };

    append_to_audit_log(&entry, None);
}

fn default_log_path() -> Option<PathBuf> {
    crate::policy::data_dir().map(|d| d.join("log.jsonl"))
}

fn redact_command(cmd: &str, custom_patterns: &[String]) -> String {
    // Apply DLP redaction: built-in patterns + custom policy patterns (Team)
    let dlp_redacted = crate::redact::redact_with_custom(cmd, custom_patterns);
    // Then truncate to 80 bytes (UTF-8 safe)
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

        // Set TIRITH_LOG=0 to disable logging
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
        };

        log_verdict(&verdict, "test cmd", Some(log_path.clone()), None, &[]);

        // File should not have been created
        assert!(
            !log_path.exists(),
            "log file should not be created when TIRITH_LOG=0"
        );

        // Clean up env var
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

        // Use an invalid local URL so drain returns early after spooling.
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
        };

        log_verdict(&verdict, "echo hello", Some(log_path), None, &[]);

        let spool = state_home.join("tirith").join("audit-queue.jsonl");
        assert!(spool.exists(), "remote audit events should be spooled");

        unsafe { std::env::remove_var("XDG_STATE_HOME") };
        unsafe { std::env::remove_var("TIRITH_API_KEY") };
        unsafe { std::env::remove_var("TIRITH_SERVER_URL") };
    }

    #[cfg(unix)]
    #[test]
    fn test_audit_refuses_symlink() {
        let dir = tempfile::tempdir().unwrap();
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
        };

        log_verdict(&verdict, "test cmd", Some(symlink_path), None, &[]);

        // Target file should be untouched
        assert_eq!(
            std::fs::read_to_string(&target).unwrap(),
            "original",
            "audit should refuse to write through symlink"
        );
    }
}
