//! Deliberately selected, freshly redacted diagnostics. No automatic sharing.
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use tirith_core::history::{HistoryFilter, HistoryReader};
use tirith_core::policy::{captured_policy_dlp_patterns_or, PolicyDiagnosticCapture};
use tirith_core::policy_snapshot::{EffectivePolicySnapshot, ResolutionMode};
use tirith_core::redact::CompiledCustomPatterns;

const MAX_SELECTIONS: usize = 10;
const MAX_BUNDLE_BYTES: usize = 256 * 1024;

#[derive(Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Selection {
    #[serde(default)]
    pub operation_ids: Vec<String>,
    #[serde(default)]
    pub incident_ids: Vec<String>,
}

impl Selection {
    fn validate(&self) -> Result<(), String> {
        if self.operation_ids.len() + self.incident_ids.len() > MAX_SELECTIONS {
            return Err("select at most ten operations and incidents in one bundle".into());
        }
        for values in [&self.operation_ids, &self.incident_ids] {
            let mut seen = BTreeSet::new();
            for id in values {
                if !uuid::Uuid::parse_str(id).is_ok_and(|value| value.to_string() == *id)
                    || !seen.insert(id)
                {
                    return Err("bundle selections must be unique canonical UUIDs".into());
                }
            }
        }
        Ok(())
    }
}

/// Exports are intentionally display copies. Their identities cannot authorize
/// an operation, verify a signed log, or establish command execution.
pub(crate) fn preview(selection: &Selection, cwd: Option<&str>) -> Result<Value, String> {
    preview_with_snapshot(selection, cwd).map(|(report, _)| report)
}

fn preview_with_snapshot(
    selection: &Selection,
    cwd: Option<&str>,
) -> Result<(Value, EffectivePolicySnapshot), String> {
    selection.validate()?;
    let _capture = PolicyDiagnosticCapture::start();
    let snapshot = EffectivePolicySnapshot::resolve(cwd, ResolutionMode::Runtime);
    let home = home::home_dir();
    // Preserve the original strings until custom DLP has seen them. Replacing
    // the home prefix first can defeat a rule covering a path and its suffix.
    let diagnostics = super::doctor::build_bundle_text(None);
    // Gather before the final privacy union: nested diagnostic producers may
    // encounter additional authoritative DLP sources.
    let mut selected_operations = Vec::new();
    if !selection.operation_ids.is_empty() {
        let service = super::setup::change_plan::MutationService::current().ok();
        for id in &selection.operation_ids {
            selected_operations.push((
                id,
                service
                    .as_ref()
                    .and_then(|service| service.read_status(id).ok()),
                super::selfupdate::lifecycle_operations::support_status(id).ok(),
            ));
        }
    }
    let history = if selection.incident_ids.is_empty() {
        None
    } else {
        let path =
            tirith_core::audit::audit_log_path().ok_or("audit history location is unavailable")?;
        Some(HistoryReader::new(path).query(
            None,
            HistoryFilter::default(),
            500,
            std::env::var("TIRITH_LOG").ok().as_deref() != Some("0"),
        )?)
    };
    let patterns = captured_policy_dlp_patterns_or(&snapshot.policy.dlp_custom_patterns);
    let compiled = CompiledCustomPatterns::new_silent(&patterns);
    let mut operations = Vec::new();
    for (id, status, lifecycle) in selected_operations {
        let entry = match (status, lifecycle) {
            (Some(status), None) => {
                let mut content = super::profile::status_projection(&status, &compiled)?;
                redact_home(&mut content, home.as_deref());
                bounded_entry("operation", id, content)
            }
            (None, Some(status)) => {
                let mut content = serde_json::to_value(status)
                    .map_err(|_| "cannot project selected lifecycle operation")?;
                redact_lifecycle(&mut content, &compiled);
                redact_home(&mut content, home.as_deref());
                bounded_entry("operation", id, content)
            }
            _ => json!({"kind":"operation", "id":id, "availability":"unavailable",
                "detail":"The selected private operation was absent, unreadable, or ambiguous; it was not reconciled or replayed."}),
        };
        operations.push(entry);
    }
    let mut incidents = Vec::new();
    let history_coverage = if let Some(history) = history {
        for id in &selection.incident_ids {
            let matches: Vec<_> = history
                .events
                .iter()
                .enumerate()
                .filter(|(_, event)| event.record.event_id.as_deref() == Some(id))
                .collect();
            // A duplicate ID is ambiguous and must never select an arbitrary
            // record as the incident the operator intended.
            let entry = if matches.len() == 1 {
                // Bound each selected incident independently. A large unrelated
                // record may otherwise erase the page's events projection.
                let mut selected = history.clone();
                selected.events = vec![matches[0].1.clone()];
                let projected = tirith_core::history::display_projection(&selected, &patterns);
                match projected
                    .get("events")
                    .and_then(Value::as_array)
                    .and_then(|events| events.first())
                {
                    Some(content) => {
                        let mut content = content.clone();
                        redact_home(&mut content, home.as_deref());
                        bounded_entry("incident", id, content)
                    }
                    None => {
                        json!({"kind":"incident", "id":id, "availability":"withheld_output_limit"})
                    }
                }
            } else {
                json!({"kind":"incident", "id":id, "availability":"unavailable",
                    "detail":"The incident was absent or ambiguous in the bounded recent history; older history was not searched."})
            };
            incidents.push(entry);
        }
        json!({"availability":history.availability, "inspected_bytes":history.inspected_bytes,
            "earlier_history_uninspected":history.earlier_history_uninspected,
            "more_available":history.more_available, "malformed_lines":history.malformed_lines,
            "oversized_lines":history.oversized_lines, "incomplete_tail":history.incomplete_tail,
            "integrity":"not_verified", "record_limit":500, "byte_limit":2097152})
    } else {
        json!({"availability":"not_selected", "inspected_bytes":0})
    };
    let text = tirith_core::redact::redact_sanitize_redact_with_compiled(&diagnostics, &compiled);
    let text = super::doctor::redact_home_path(&text, home.as_deref());
    let text_omitted = text.len() > 64 * 1024;
    let policy_diagnostics =
        tirith_core::policy::drain_captured_policy_diagnostics_for_output(&compiled);
    let mut report = json!({
        "schema_version":1, "kind":"support_bundle", "version":env!("CARGO_PKG_VERSION"),
        "generated_at":chrono::Utc::now().to_rfc3339(), "shared":false,
        "notice":"Review this local display copy before sharing. Selected records are not execution evidence or a verified audit chain.",
        "diagnostic_text":if text_omitted {"[diagnostic text withheld: exceeds 64 KiB]"} else {&text},
        "diagnostic_text_omitted":text_omitted,
        "operations":operations, "incidents":incidents, "history_coverage":history_coverage,
        "policy_diagnostics":policy_diagnostics, "redaction":"fresh_runtime_policy_union",
        "output_limit_bytes":MAX_BUNDLE_BYTES, "presentation_incomplete":false
    });
    // Whole entries are withheld, never raw/truncated prefixes. Measure the
    // actual pretty JSON because escaping can expand the display substantially.
    while serde_json::to_vec_pretty(&report)
        .map_err(|_| "cannot measure support bundle")?
        .len()
        > MAX_BUNDLE_BYTES
    {
        report["presentation_incomplete"] = true.into();
        let mut removed = false;
        for group in ["operations", "incidents"] {
            if let Some(entry) = report[group].as_array_mut().and_then(|entries| {
                entries
                    .iter_mut()
                    .rev()
                    .find(|e| e.get("content").is_some())
            }) {
                entry.as_object_mut().unwrap().remove("content");
                entry["availability"] = "withheld_output_limit".into();
                removed = true;
                break;
            }
        }
        if !removed {
            report["diagnostic_text"] =
                "[diagnostic text withheld: serialized output limit]".into();
            report["diagnostic_text_omitted"] = true.into();
            report["policy_diagnostics"] =
                json!(["Policy diagnostics withheld: serialized output limit"]);
        }
    }
    Ok((report, snapshot))
}

fn redact_lifecycle(value: &mut Value, compiled: &CompiledCustomPatterns) {
    // UUIDs, phases, action enums, and timestamps remain protocol fields. Only
    // selected human-readable evidence receives display redaction.
    for pointer in [
        "/operation/preview/current_version",
        "/operation/preview/candidate_version",
        "/operation/preview/evidence",
        "/operation/preview/issues",
        "/operation/next_action",
        "/selected_failure_detail",
    ] {
        if let Some(content) = value.pointer_mut(pointer) {
            tirith_core::redact::redact_json_strings(content, compiled);
        }
    }
}

fn bounded_entry(kind: &str, id: &str, content: Value) -> Value {
    if serde_json::to_vec_pretty(&content).map_or(true, |bytes| bytes.len() > 16 * 1024) {
        json!({"kind":kind,"id":id,"availability":"withheld_output_limit"})
    } else {
        json!({"kind":kind,"id":id,"availability":"available","content":content})
    }
}

fn redact_home(value: &mut Value, home: Option<&Path>) {
    match value {
        Value::String(text) => *text = super::doctor::redact_home_path(text, home),
        Value::Array(values) => values.iter_mut().for_each(|v| redact_home(v, home)),
        Value::Object(values) => values.values_mut().for_each(|v| redact_home(v, home)),
        _ => {}
    }
}

/// Write an already projected report only to an operator-private derived path.
/// This is an export, not a configuration mutation or share operation.
fn save(
    report: &Value,
    snapshot: &EffectivePolicySnapshot,
    selection: &Selection,
    cwd: Option<&str>,
) -> Result<PathBuf, String> {
    use super::setup::change_plan::{
        Edit, JobState, MutationService, OperationKind, RequestedChange,
    };
    let root = tirith_core::policy::state_dir().ok_or("private state directory is unavailable")?;
    let dir = root.join("support");
    let id = uuid::Uuid::new_v4().to_string();
    let path = dir.join(format!("tirith-bundle-{id}.json"));
    let text = serde_json::to_string_pretty(report).map_err(|_| "cannot encode support bundle")?;
    if text.len() > MAX_BUNDLE_BYTES {
        return Err("support bundle exceeds output limit".into());
    }
    let service = MutationService::current()?;
    // The original capture binds the privacy rules used by the report. A policy
    // change refuses publication instead of trying to redact an already altered
    // string under a different policy. The shared writer also enforces task scope.
    service.plan_with_preimages_and_intent(
        &id,
        OperationKind::ExportSupport,
        vec![RequestedChange {
            target: path.clone(),
            scope_root: root.clone(),
            edit: Edit::PrivateFile(text),
            activation: false,
            description: "Save the selected redacted support report locally".into(),
        }],
        snapshot,
        &std::collections::BTreeMap::from([(path.clone(), None)]),
        &json!({"kind":"support_export_v1","selection":selection,"cwd":cwd,"report":report}),
    )?;
    let status = service.apply(&id, snapshot)?;
    if !matches!(
        status.state,
        JobState::Completed | JobState::CompletedWithRecovery
    ) {
        return Err(format!(
            "support export did not complete; inspect saved operation {id}"
        ));
    }
    super::setup::fs_helpers::read_snapshot_scoped(&path, &root)?.require_private()?;
    Ok(path)
}

pub(crate) fn run(
    preview_only: bool,
    operation_ids: Vec<String>,
    incident_ids: Vec<String>,
    json_output: bool,
) -> i32 {
    let result = (|| -> Result<(), String> {
        let cwd = std::env::current_dir()
            .ok()
            .map(|path| path.display().to_string());
        let selection = Selection {
            operation_ids,
            incident_ids,
        };
        let (report, snapshot) = preview_with_snapshot(&selection, cwd.as_deref())?;
        if preview_only {
            if json_output {
                if !super::write_json_stdout(&report, "tirith doctor: cannot write support preview")
                {
                    return Err("cannot write support preview".into());
                }
            } else {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&report)
                        .map_err(|_| "cannot encode support preview")?
                );
            }
        } else {
            let path = save(&report, &snapshot, &selection, cwd.as_deref())?;
            let compiled = CompiledCustomPatterns::new_silent(&captured_policy_dlp_patterns_or(
                &snapshot.policy.dlp_custom_patterns,
            ));
            let shown = tirith_core::redact::redact_sanitize_redact_with_compiled(
                &path.display().to_string(),
                &compiled,
            );
            let shown = super::doctor::redact_home_path(&shown, home::home_dir().as_deref());
            if json_output {
                if !super::write_json_stdout(
                    &json!({"schema_version":1,"bundle_path":shown,"shared":false}),
                    "tirith doctor: cannot write support export result",
                ) {
                    return Err("cannot write support export result".into());
                }
            } else {
                println!("Local diagnostic bundle: {}", shown);
                println!("Review it before sharing. No report was uploaded.");
            }
        }
        Ok(())
    })();
    match result {
        Ok(()) => 0,
        Err(error) => {
            eprintln!(
                "tirith doctor: {}",
                tirith_core::redact::redact_sanitize_redact(
                    &error,
                    &captured_policy_dlp_patterns_or(&[])
                )
            );
            1
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn lifecycle_selection_redacts_evidence_and_preserves_protocol() {
        let mut value = json!({"operation":{"operation_id":"id","phase":"cancelled","action":"update",
            "preview":{"current_version":"private-version","candidate_version":"private-candidate","evidence":"private-evidence","issues":["private-issue"]},
            "next_action":"private-instruction","published":false},"selected_failure_detail":"private-detail"});
        redact_lifecycle(
            &mut value,
            &CompiledCustomPatterns::new_silent(&[".+".into()]),
        );
        assert!(!value.to_string().contains("private-"));
        assert_eq!(value["operation"]["operation_id"], "id");
        assert_eq!(value["operation"]["phase"], "cancelled");
        assert_eq!(value["operation"]["action"], "update");
        assert_eq!(value["operation"]["published"], false);
    }
    #[test]
    fn selection_rejects_paths_duplicate_ids_and_excess_work() {
        assert!(Selection {
            operation_ids: vec!["../../policy.yaml".into()],
            incident_ids: vec![]
        }
        .validate()
        .is_err());
        let id = uuid::Uuid::new_v4().to_string();
        assert!(Selection {
            operation_ids: vec![id.clone(), id.clone()],
            incident_ids: vec![]
        }
        .validate()
        .is_err());
        assert!(Selection {
            operation_ids: (0..11).map(|_| uuid::Uuid::new_v4().to_string()).collect(),
            incident_ids: vec![]
        }
        .validate()
        .is_err());
        assert!(Selection {
            operation_ids: vec![id],
            incident_ids: vec![]
        }
        .validate()
        .is_ok());
    }
    #[test]
    fn oversized_entry_is_wholly_withheld() {
        let value = bounded_entry(
            "incident",
            "id",
            json!({"text":"secret-crossing-boundary".repeat(1000)}),
        );
        assert_eq!(value["availability"], "withheld_output_limit");
        assert!(value.get("content").is_none());
    }
}
