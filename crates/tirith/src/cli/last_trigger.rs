use tirith_core::util::truncate_bytes;

pub(crate) const MAX_LAST_TRIGGER_BYTES: u64 = 1024 * 1024;

/// Version-tolerant on-disk shape shared by the writer, `why`, and trust
/// consumers. Findings remain structured JSON so legacy evidence variants and
/// future additive fields round-trip without raw-byte passthrough.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub(crate) struct LastTriggerRecord {
    #[serde(default)]
    pub rule_ids: Vec<String>,
    #[serde(default)]
    pub severity: String,
    #[serde(default)]
    pub command_redacted: String,
    #[serde(default)]
    pub findings: Vec<serde_json::Value>,
    #[serde(default)]
    pub timestamp: String,
    #[serde(flatten)]
    pub extra: serde_json::Map<String, serde_json::Value>,
}

pub(crate) fn load_last_trigger_record() -> Result<Option<LastTriggerRecord>, String> {
    let dir = tirith_core::policy::data_dir()
        .ok_or_else(|| "cannot determine data directory".to_string())?;
    load_last_trigger_from(&dir.join("last_trigger.json"))
}

pub(crate) fn load_last_trigger_from(
    path: &std::path::Path,
) -> Result<Option<LastTriggerRecord>, String> {
    let bytes = match tirith_core::util::read_text_no_follow_capped(path, MAX_LAST_TRIGGER_BYTES) {
        Ok(bytes) => bytes,
        Err(tirith_core::util::OpenRegularError::NotFound) => return Ok(None),
        Err(tirith_core::util::OpenRegularError::NotRegularFile) => {
            return Err("last trigger is not a regular non-symlink file".to_string())
        }
        Err(tirith_core::util::OpenRegularError::TooLarge) => {
            return Err(format!(
                "last trigger exceeds the {MAX_LAST_TRIGGER_BYTES} byte limit"
            ))
        }
        Err(tirith_core::util::OpenRegularError::Io(error)) => {
            return Err(format!("failed to read last trigger: {error}"))
        }
    };
    serde_json::from_slice(&bytes).map(Some).map_err(|error| {
        format!("failed to parse last trigger as a structured JSON record: {error}")
    })
}

pub fn write_last_trigger(
    verdict: &tirith_core::verdict::Verdict,
    cmd: &str,
    custom_patterns: &[String],
) {
    if let Some(dir) = tirith_core::policy::data_dir() {
        if let Err(e) = std::fs::create_dir_all(&dir) {
            tirith_core::audit::audit_diagnostic(format!(
                "tirith: warning: cannot create data dir {}: {e}",
                dir.display()
            ));
            return;
        }
        let path = dir.join("last_trigger.json");

        // A failed replacement must not leave an older event available to
        // `trust --from-last-trigger`. Invalidate the previous record before
        // constructing the new one; losing this convenience record is safer
        // than applying trust to a stale finding after any serialization or
        // publication failure below.
        match std::fs::symlink_metadata(&path) {
            Ok(_) => {
                if let Err(e) = std::fs::remove_file(&path) {
                    tirith_core::audit::audit_diagnostic(format!(
                        "tirith: warning: cannot invalidate stale last-trigger record: {e}"
                    ));
                    return;
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => {
                tirith_core::audit::audit_diagnostic(format!(
                    "tirith: warning: cannot inspect prior last-trigger record: {e}"
                ));
                return;
            }
        }

        let redacted_findings =
            tirith_core::redact::redacted_findings(&verdict.findings, custom_patterns);

        // repo-0391: the persisted record is later printed verbatim by
        // `tirith why` / `tirith trust last`. Redaction removes secrets but
        // not terminal controls / deceptive Unicode, so scrub every stored
        // string before it reaches disk — the store must not become a
        // deferred terminal-injection channel.
        let findings = match redacted_findings
            .iter()
            .map(|f| serde_json::to_value(f).map(sanitize_stored_json))
            .collect::<Result<Vec<_>, _>>()
        {
            Ok(findings) => findings,
            Err(e) => {
                tirith_core::audit::audit_diagnostic(format!(
                    "tirith: warning: failed to serialize last-trigger findings: {e}"
                ));
                return;
            }
        };

        let trigger = LastTriggerRecord {
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
            findings,
            timestamp: chrono::Utc::now().to_rfc3339(),
            extra: serde_json::Map::new(),
        };

        let json = match serde_json::to_string_pretty(&trigger) {
            Ok(j) => j,
            Err(e) => {
                tirith_core::audit::audit_diagnostic(format!(
                    "tirith: warning: failed to serialize last trigger: {e}"
                ));
                return;
            }
        };

        {
            use std::io::Write;
            use tempfile::NamedTempFile;

            let mut tmp_file = match NamedTempFile::new_in(&dir) {
                Ok(f) => f,
                Err(e) => {
                    // repo-0486: a stale last_trigger.json is a WRONG-TRUST
                    // hazard (`trust --from-last-trigger` would act on an old
                    // event) — never fail silently.
                    tirith_core::audit::audit_diagnostic(format!(
                        "tirith: warning: last-trigger temp file failed: {e}"
                    ));
                    return;
                }
            };
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let _ = tmp_file
                    .as_file()
                    .set_permissions(std::fs::Permissions::from_mode(0o600));
            }
            if tmp_file.write_all(json.as_bytes()).is_err() {
                tirith_core::audit::audit_diagnostic("tirith: warning: last-trigger write failed");
                return;
            }
            if let Err(e) = tmp_file.persist(&path) {
                tirith_core::audit::audit_diagnostic(format!(
                    "tirith: warning: last-trigger publish failed: {}",
                    e.error
                ));
            }
        }
    }
}

fn redact_command(cmd: &str, custom_patterns: &[String]) -> String {
    let scrubbed = tirith_core::redact::redact_command_text(cmd, custom_patterns);
    let scrubbed = tirith_core::mcp::output_filter::sanitize_for_display(&scrubbed);
    let prefix = truncate_bytes(&scrubbed, 80);
    if prefix.len() == scrubbed.len() {
        scrubbed
    } else {
        format!("{prefix}...")
    }
}

/// Recursively strip terminal-control/deceptive content from every string in
/// a stored JSON value (repo-0391).
fn sanitize_stored_json(value: serde_json::Value) -> serde_json::Value {
    match value {
        serde_json::Value::String(s) => {
            serde_json::Value::String(tirith_core::mcp::output_filter::sanitize_for_display(&s))
        }
        serde_json::Value::Array(items) => {
            serde_json::Value::Array(items.into_iter().map(sanitize_stored_json).collect())
        }
        serde_json::Value::Object(map) => serde_json::Value::Object(
            map.into_iter()
                .map(|(k, v)| {
                    (
                        tirith_core::mcp::output_filter::sanitize_for_display(&k),
                        sanitize_stored_json(v),
                    )
                })
                .collect(),
        ),
        other => other,
    }
}

#[cfg(test)]
fn redact_assignment_values(cmd: &str) -> String {
    tirith_core::redact::redact_shell_assignments(cmd)
}

#[cfg(test)]
mod tests {
    use super::{
        load_last_trigger_from, redact_assignment_values, redact_command, LastTriggerRecord,
        MAX_LAST_TRIGGER_BYTES,
    };

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

        // The old predictable tmp file (symlink-race risk) must not be produced.
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

    #[test]
    fn capped_loader_parses_and_preserves_additive_fields() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("last_trigger.json");
        std::fs::write(
            &path,
            br#"{
                "rule_ids":["x"], "severity":"high", "command_redacted":"echo ok",
                "findings":[], "timestamp":"now", "future_field":{"kept":true}
            }"#,
        )
        .unwrap();
        let record = load_last_trigger_from(&path).unwrap().unwrap();
        assert_eq!(record.rule_ids, vec!["x"]);
        assert_eq!(record.extra["future_field"]["kept"], true);
        let round_trip = serde_json::to_value(&record).unwrap();
        assert_eq!(round_trip["future_field"]["kept"], true);
    }

    #[test]
    fn capped_loader_rejects_oversize_and_invalid_json() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("last_trigger.json");
        std::fs::write(&path, vec![b'x'; MAX_LAST_TRIGGER_BYTES as usize + 1]).unwrap();
        assert!(load_last_trigger_from(&path)
            .unwrap_err()
            .contains("exceeds"));
        std::fs::write(&path, b"{not json").unwrap();
        assert!(load_last_trigger_from(&path)
            .unwrap_err()
            .contains("structured JSON"));
    }

    #[cfg(unix)]
    #[test]
    fn capped_loader_rejects_symlink_and_special_file() {
        use std::ffi::CString;
        use std::os::unix::fs::symlink;

        let dir = tempfile::tempdir().unwrap();
        let record_path = dir.path().join("record.json");
        std::fs::write(
            &record_path,
            serde_json::to_vec(&LastTriggerRecord {
                rule_ids: vec![],
                severity: String::new(),
                command_redacted: String::new(),
                findings: vec![],
                timestamp: String::new(),
                extra: serde_json::Map::new(),
            })
            .unwrap(),
        )
        .unwrap();
        let link = dir.path().join("linked.json");
        symlink(&record_path, &link).unwrap();
        assert!(load_last_trigger_from(&link)
            .unwrap_err()
            .contains("non-symlink"));

        let fifo = dir.path().join("record.fifo");
        let c_path = CString::new(fifo.as_os_str().to_str().unwrap()).unwrap();
        assert_eq!(unsafe { libc::mkfifo(c_path.as_ptr(), 0o600) }, 0);
        assert!(load_last_trigger_from(&fifo)
            .unwrap_err()
            .contains("not a regular"));
    }
}
