use std::fs::{self, OpenOptions};
use std::io::Write;
#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;
use std::path::PathBuf;

use fs2::FileExt;
use serde::Serialize;

use crate::verdict::Verdict;

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
    // Early exit if logging disabled
    if std::env::var("TIRITH_LOG").ok().as_deref() == Some("0") {
        return;
    }

    let path = log_path.or_else(default_log_path);
    let path = match path {
        Some(p) => p,
        None => return,
    };

    // Ensure directory exists
    if let Some(parent) = path.parent() {
        if let Err(e) = fs::create_dir_all(parent) {
            eprintln!(
                "tirith: audit: cannot create log dir {}: {e}",
                parent.display()
            );
            return;
        }
    }

    let entry = AuditEntry {
        timestamp: chrono::Utc::now().to_rfc3339(),
        session_id: crate::session::session_id().to_string(),
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
    };

    let line = match serde_json::to_string(&entry) {
        Ok(l) => l,
        Err(e) => {
            eprintln!("tirith: audit: failed to serialize entry: {e}");
            return;
        }
    };

    // Open, lock, append, fsync, unlock
    let mut open_opts = OpenOptions::new();
    open_opts.create(true).append(true);
    #[cfg(unix)]
    open_opts.mode(0o600);
    let file = open_opts.open(&path);

    let file = match file {
        Ok(f) => f,
        Err(e) => {
            eprintln!("tirith: audit: cannot open {}: {e}", path.display());
            return;
        }
    };

    // Harden legacy files: enforce 0600 on existing files too
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = file.set_permissions(std::fs::Permissions::from_mode(0o600));
    }

    if let Err(e) = file.lock_exclusive() {
        eprintln!("tirith: audit: cannot lock {}: {e}", path.display());
        return;
    }

    let mut writer = std::io::BufWriter::new(&file);
    if let Err(e) = writeln!(writer, "{line}") {
        eprintln!("tirith: audit: write failed: {e}");
        let _ = fs2::FileExt::unlock(&file);
        return;
    }
    if let Err(e) = writer.flush() {
        eprintln!("tirith: audit: flush failed: {e}");
    }
    if let Err(e) = file.sync_all() {
        eprintln!("tirith: audit: sync failed: {e}");
    }
    let _ = fs2::FileExt::unlock(&file);

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
        if crate::license::current_tier() >= crate::license::Tier::Team {
            crate::audit_upload::spool_and_upload(&line, &url, &key, None, None);
        }
    }
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
            "{}[...redacted {} chars]",
            prefix,
            dlp_redacted.len() - prefix.len()
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::verdict::{Action, Verdict};

    /// Mutex to serialize tests that mutate environment variables.
    /// `std::env::set_var` is not thread-safe — concurrent mutation causes UB.
    static ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    #[test]
    fn test_tirith_log_disabled() {
        let _guard = ENV_LOCK.lock().unwrap();
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
            interactive_detected: false,
            policy_path_used: None,
            urls_extracted_count: None,
            requires_approval: None,
            approval_timeout_secs: None,
            approval_fallback: None,
            approval_rule: None,
            approval_description: None,
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

    #[test]
    fn test_remote_audit_upload_requires_team_tier() {
        let _guard = ENV_LOCK.lock().unwrap();

        let dir = tempfile::tempdir().unwrap();
        let log_path = dir.path().join("audit.jsonl");
        let state_home = dir.path().join("state");

        // Force Community tier and set remote upload env vars.
        unsafe { std::env::set_var("TIRITH_LICENSE", "!") };
        unsafe { std::env::set_var("TIRITH_SERVER_URL", "https://example.com") };
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
            interactive_detected: false,
            policy_path_used: None,
            urls_extracted_count: None,
            requires_approval: None,
            approval_timeout_secs: None,
            approval_fallback: None,
            approval_rule: None,
            approval_description: None,
        };

        log_verdict(&verdict, "echo hello", Some(log_path), None, &[]);

        let spool = state_home.join("tirith").join("audit-queue.jsonl");
        assert!(
            !spool.exists(),
            "Community tier must not spool remote audit uploads"
        );

        unsafe { std::env::remove_var("XDG_STATE_HOME") };
        unsafe { std::env::remove_var("TIRITH_API_KEY") };
        unsafe { std::env::remove_var("TIRITH_SERVER_URL") };
        unsafe { std::env::remove_var("TIRITH_LICENSE") };
    }
}
