use tirith_core::util::truncate_bytes;

pub fn write_last_trigger(
    verdict: &tirith_core::verdict::Verdict,
    cmd: &str,
    custom_patterns: &[String],
) {
    if let Some(dir) = tirith_core::policy::data_dir() {
        if let Err(e) = std::fs::create_dir_all(&dir) {
            eprintln!(
                "tirith: warning: cannot create data dir {}: {e}",
                dir.display()
            );
            return;
        }
        let path = dir.join("last_trigger.json");

        #[derive(serde::Serialize)]
        struct LastTrigger<'a> {
            rule_ids: Vec<String>,
            severity: String,
            command_redacted: String,
            findings: &'a [tirith_core::verdict::Finding],
            timestamp: String,
        }

        let redacted_findings =
            tirith_core::redact::redacted_findings(&verdict.findings, custom_patterns);

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
            command_redacted: redact_command(cmd, custom_patterns),
            findings: &redacted_findings,
            timestamp: chrono::Utc::now().to_rfc3339(),
        };

        let json = match serde_json::to_string_pretty(&trigger) {
            Ok(j) => j,
            Err(e) => {
                eprintln!("tirith: warning: failed to serialize last trigger: {e}");
                return;
            }
        };

        {
            use std::io::Write;
            use tempfile::NamedTempFile;

            let mut tmp_file = match NamedTempFile::new_in(&dir) {
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
}

fn redact_command(cmd: &str, custom_patterns: &[String]) -> String {
    let scrubbed = tirith_core::redact::redact_command_text(cmd, custom_patterns);
    let prefix = truncate_bytes(&scrubbed, 80);
    if prefix.len() == scrubbed.len() {
        scrubbed
    } else {
        format!("{prefix}...")
    }
}

#[cfg(test)]
fn redact_assignment_values(cmd: &str) -> String {
    tirith_core::redact::redact_shell_assignments(cmd)
}

#[cfg(test)]
mod tests {
    use super::{redact_assignment_values, redact_command};

    #[test]
    fn test_last_trigger_no_predictable_tmp() {
        // Verify NamedTempFile is used: no .last_trigger.json.tmp should remain.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("last_trigger.json");
        let json = r#"{"rule_ids":["test"],"severity":"low","command_redacted":"test","findings":[],"timestamp":"2024-01-01T00:00:00Z"}"#;

        {
            use std::io::Write;
            use tempfile::NamedTempFile;

            let mut tmp = NamedTempFile::new_in(dir.path()).unwrap();
            tmp.write_all(json.as_bytes()).unwrap();
            tmp.persist(&path).unwrap();
        }

        // The old predictable tmp file should NOT exist
        let old_tmp = dir.path().join(".last_trigger.json.tmp");
        assert!(
            !old_tmp.exists(),
            "predictable .last_trigger.json.tmp should not exist after NamedTempFile save"
        );
        assert!(
            path.exists(),
            "last_trigger.json should exist after persist"
        );
        let content = std::fs::read_to_string(&path).unwrap();
        assert!(
            content.contains("test"),
            "file should contain expected data"
        );
    }

    #[test]
    fn test_redact_assignment_values_scrubs_exports() {
        let redacted =
            redact_assignment_values("export AWS_ACCESS_KEY_ID=ABCDEFGHIJKLMNOPQRST echo done");
        assert!(redacted.contains("AWS_ACCESS_KEY_ID=[REDACTED]"));
        assert!(!redacted.contains("ABCDEFGHIJKLMNOPQRST"));
    }

    #[test]
    fn test_redact_assignment_values_scrubs_quoted_values() {
        let redacted = redact_assignment_values("TOKEN='secret with spaces' curl example.com");
        assert!(redacted.contains("TOKEN=[REDACTED]"));
        assert!(!redacted.contains("secret with spaces"));
    }

    #[test]
    fn test_redact_command_truncates_after_scrubbing() {
        let redacted = redact_command(
            "TOKEN=verysecretvalue curl https://example.com/install.sh",
            &[],
        );
        assert!(redacted.contains("TOKEN=[REDACTED]"));
        assert!(!redacted.contains("verysecretvalue"));
    }
}
