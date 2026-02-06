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
pub fn log_verdict(
    verdict: &Verdict,
    command: &str,
    log_path: Option<PathBuf>,
    event_id: Option<String>,
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
        let _ = fs::create_dir_all(parent);
    }

    let entry = AuditEntry {
        timestamp: chrono::Utc::now().to_rfc3339(),
        action: format!("{:?}", verdict.action),
        rule_ids: verdict
            .findings
            .iter()
            .map(|f| f.rule_id.to_string())
            .collect(),
        command_redacted: redact_command(command),
        bypass_requested: verdict.bypass_requested,
        bypass_honored: verdict.bypass_honored,
        interactive: verdict.interactive_detected,
        policy_path: verdict.policy_path_used.clone(),
        event_id,
        tier_reached: verdict.tier_reached,
    };

    let line = match serde_json::to_string(&entry) {
        Ok(l) => l,
        Err(_) => return,
    };

    // Open, lock, append, fsync, unlock
    let mut open_opts = OpenOptions::new();
    open_opts.create(true).append(true);
    #[cfg(unix)]
    open_opts.mode(0o600);
    let file = open_opts.open(&path);

    let file = match file {
        Ok(f) => f,
        Err(_) => return,
    };

    // Harden legacy files: enforce 0600 on existing files too
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = file.set_permissions(std::fs::Permissions::from_mode(0o600));
    }

    if file.lock_exclusive().is_err() {
        return;
    }

    let mut writer = std::io::BufWriter::new(&file);
    let _ = writeln!(writer, "{line}");
    let _ = writer.flush();
    let _ = file.sync_all();
    let _ = fs2::FileExt::unlock(&file);
}

fn default_log_path() -> Option<PathBuf> {
    crate::policy::data_dir().map(|d| d.join("log.jsonl"))
}

fn redact_command(cmd: &str) -> String {
    // Redact: keep first 80 bytes (UTF-8 safe), replace the rest
    let prefix = crate::util::truncate_bytes(cmd, 80);
    if prefix.len() == cmd.len() {
        cmd.to_string()
    } else {
        format!("{}[...redacted {} chars]", prefix, cmd.len() - prefix.len())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::verdict::{Action, Verdict};

    #[test]
    fn test_tirith_log_disabled() {
        let dir = tempfile::tempdir().unwrap();
        let log_path = dir.path().join("test.jsonl");

        // Set TIRITH_LOG=0 to disable logging
        std::env::set_var("TIRITH_LOG", "0");

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
        };

        log_verdict(&verdict, "test cmd", Some(log_path.clone()), None);

        // File should not have been created
        assert!(
            !log_path.exists(),
            "log file should not be created when TIRITH_LOG=0"
        );

        // Clean up env var
        std::env::remove_var("TIRITH_LOG");
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
}
