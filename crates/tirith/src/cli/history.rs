use tirith_core::history::{Availability, HistoryFilter, HistoryReader};

pub(crate) fn projection(
    history: &tirith_core::history::HistoryQueryResult,
    patterns: &[String],
) -> serde_json::Value {
    let mut output = tirith_core::history::display_projection(history, patterns);
    output["annotations"] = super::feedback::read_for_history(history);
    output["audit_recording"] = super::audit_health::read().projection();
    if serde_json::to_vec_pretty(&output).map_or(true, |bytes| {
        bytes.len() > tirith_core::verdict::MAX_PRESENTATION_BYTES
    }) {
        output["events"] = serde_json::json!([]);
        output["presentation_incomplete"] = true.into();
        output["omitted_events"] = history.events.len().into();
    }
    output
}

/// One bounded recent-history snapshot. Persistent cursors belong to a live
/// service instance and are deliberately not advertised by this short-lived CLI.
pub fn recent(
    limit: usize,
    since: Option<String>,
    until: Option<String>,
    action: Option<String>,
    rule: Option<String>,
    json: bool,
) -> i32 {
    let result = (|| -> Result<i32, String> {
        let action = action
            .map(|value| serde_json::from_value(value.into()))
            .transpose()
            .map_err(|_| "action must be allow, warn, warn_ack, or block")?;
        let rule = rule
            .map(|value| serde_json::from_value(value.into()))
            .transpose()
            .map_err(|_| "rule must be a recognized rule ID")?;
        let path =
            tirith_core::audit::audit_log_path().ok_or("audit log location is unavailable")?;
        let _diagnostics = tirith_core::policy::PolicyDiagnosticCapture::start();
        let cwd = std::env::current_dir()
            .ok()
            .map(|path| path.display().to_string());
        let policy = tirith_core::policy_snapshot::EffectivePolicySnapshot::resolve(
            cwd.as_deref(),
            tirith_core::policy_snapshot::ResolutionMode::Runtime,
        );
        let history = HistoryReader::new(path).recent(
            HistoryFilter {
                since,
                until,
                action,
                rule,
            },
            limit,
            std::env::var("TIRITH_LOG").ok().as_deref() != Some("0"),
        )?;
        let patterns = tirith_core::policy::captured_policy_dlp_patterns_or(
            &policy.policy.dlp_custom_patterns,
        );
        let mut output = projection(&history, &patterns);
        let compiled = tirith_core::redact::CompiledCustomPatterns::new_silent(&patterns);
        for diagnostic in
            tirith_core::policy::drain_captured_policy_diagnostics_for_output(&compiled)
        {
            eprintln!("{diagnostic}");
        }
        if let Some(object) = output.as_object_mut() {
            object.remove("next_cursor");
            object.insert("kind".into(), "history_recent".into());
            object.insert("read_mode".into(), "bounded_recent_snapshot".into());
        }
        if json {
            if !super::write_json_stdout(&output, "tirith audit recent: failed to write result") {
                return Ok(1);
            }
        } else {
            eprintln!(
                "History: {:?}; {} recorded entries in this page",
                history.availability,
                history.events.len()
            );
            if let Some(detail) = output["audit_recording"]["detail"].as_str() {
                eprintln!("  Audit recording: {detail}");
            }
            if history.earlier_history_uninspected || history.more_available {
                eprintln!("  Partial coverage: older or additional history was not inspected in this page.");
            }
            if history.incomplete_tail {
                eprintln!("  An unfinished trailing record will be retried on the next read.");
            }
            if history.malformed_lines + history.oversized_lines > 0 {
                eprintln!(
                    "  Skipped {} malformed and {} oversized records.",
                    history.malformed_lines, history.oversized_lines
                );
            }
            if let Some(detail) = history.detail {
                eprintln!("  {detail}");
            }
            if let Some(events) = output["events"].as_array() {
                for event in events {
                    let record = &event["record"];
                    eprintln!(
                        "  {}  {}  {}",
                        record["timestamp"].as_str().unwrap_or("unknown time"),
                        record["action"].as_str().unwrap_or("unknown action"),
                        record["command_redacted"].as_str().unwrap_or("")
                    );
                }
            }
            eprintln!("  Recorded checks do not establish execution. Use 'tirith audit verify' to verify the audit chain.");
        }
        Ok(
            if matches!(
                history.availability,
                Availability::Unreadable | Availability::Corrupt | Availability::RefreshRequired
            ) {
                1
            } else {
                0
            },
        )
    })();
    result.unwrap_or_else(|error| {
        eprintln!(
            "tirith audit recent: {}",
            tirith_core::output::sanitize_human_field(
                &error,
                &tirith_core::policy::captured_policy_dlp_patterns_or(&[])
            )
        );
        1
    })
}
