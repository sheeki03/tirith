use tirith_core::policy_snapshot::{EffectivePolicySnapshot, ResolutionMode};

use super::setup::change_plan::{JobState, MutationService, OperationStatus};

pub fn apply(name: &str, dry_run: bool, json: bool) -> i32 {
    match apply_inner(name, dry_run, json) {
        Ok(code) => code,
        Err(error) => {
            eprintln!(
                "tirith policy profile: {}",
                tirith_core::output::sanitize_human_field(&error, &[])
            );
            1
        }
    }
}

fn apply_inner(name: &str, dry_run: bool, json: bool) -> Result<i32, String> {
    let _diagnostics = tirith_core::policy::PolicyDiagnosticCapture::start();
    let prepared = super::profile_service::PreparedProfile::capture(name, None)?;
    for diagnostic in
        tirith_core::policy::drain_captured_policy_diagnostics_for_output(&prepared.compiled)
    {
        eprintln!("{diagnostic}");
    }
    if dry_run {
        if json {
            return Ok(
                if super::write_json_stdout(
                    &prepared.projection(),
                    "tirith policy profile: failed to write preview",
                ) {
                    0
                } else {
                    1
                },
            );
        }
        eprintln!(
            "Profile preview: {name}; {} field change(s)",
            prepared.preview.changes.len()
        );
        for change in &prepared.preview.changes {
            eprintln!("  {}: {}", change.field, change.operation);
        }
        eprintln!("  {} custom setting(s) preserved; organization, remote, repository, and incident constraints still apply", prepared.preview.custom_overrides.len());
        return Ok(0);
    }
    let id = uuid::Uuid::new_v4().to_string();
    let Some(_) = prepared.plan(&id)? else {
        if json {
            return Ok(
                if super::write_json_stdout(
                    &serde_json::json!({"schema_version": 1, "kind": "profile_change", "state": "unchanged"}),
                    "tirith policy profile: failed to write result",
                ) {
                    0
                } else {
                    1
                },
            );
        }
        eprintln!("The requested profile settings are already present.");
        return Ok(0);
    };
    let status = MutationService::current()?
        .apply(&id, &prepared.snapshot)
        .map_err(|error| {
            tirith_core::redact::redact_sanitize_redact_with_compiled(&error, &prepared.compiled)
        })?;
    show_status(&status, &prepared.compiled, json)
}

pub fn operation(id: &str, action: &str, json: bool) -> i32 {
    let _diagnostics = tirith_core::policy::PolicyDiagnosticCapture::start();
    let result = (|| {
        uuid::Uuid::parse_str(id).map_err(|_| "operation ID must be a UUID".to_string())?;
        let cwd = std::env::current_dir()
            .ok()
            .map(|v| v.display().to_string());
        let snapshot = EffectivePolicySnapshot::resolve(cwd.as_deref(), ResolutionMode::Runtime);
        let compiled = tirith_core::redact::CompiledCustomPatterns::new_silent(
            &tirith_core::policy::captured_policy_dlp_patterns_or(
                &snapshot.policy.dlp_custom_patterns,
            ),
        );
        for diagnostic in
            tirith_core::policy::drain_captured_policy_diagnostics_for_output(&compiled)
        {
            eprintln!("{diagnostic}");
        }
        let redact_error = |error: String| {
            tirith_core::redact::redact_sanitize_redact_with_compiled(&error, &compiled)
        };
        let service = MutationService::current().map_err(redact_error)?;
        let status = match action {
            "status" => service.status(id),
            "apply" => service.apply(id, &snapshot),
            "cancel" => service.cancel(id),
            "undo" => service.undo(id, &snapshot),
            _ => return Err("operation action must be status, apply, cancel, or undo".into()),
        }
        .map_err(redact_error)?;
        show_status(&status, &compiled, json)
    })();
    result.unwrap_or_else(|error: String| {
        eprintln!(
            "tirith policy operation: {}",
            tirith_core::output::sanitize_human_field(&error, &[])
        );
        1
    })
}

/// Shared shell of the journaled-operation CLIs (`audit feedback`, `policy
/// setting`): one policy-diagnostic capture held through error reporting, JSON
/// or human output, and exit 1 when the operation reports an unfinished state.
pub(crate) fn run_operation_cli(
    command: &str,
    write_failure: &str,
    json: bool,
    run: impl FnOnce() -> Result<serde_json::Value, String>,
    human: impl FnOnce(&serde_json::Value) -> String,
) -> i32 {
    let _capture = tirith_core::policy::PolicyDiagnosticCapture::start();
    match run() {
        Ok(output) => {
            if json {
                if !super::write_json_stdout(&output, write_failure) {
                    return 1;
                }
            } else {
                print!("{}", human(&output));
            }
            i32::from(
                output["state"]
                    .as_str()
                    .is_some_and(|state| !matches!(state, "unchanged" | "completed")),
            )
        }
        Err(error) => {
            let patterns = tirith_core::policy::captured_policy_dlp_patterns_or(&[]);
            eprintln!(
                "{command}: {}",
                tirith_core::redact::redact_sanitize_redact(&error, &patterns)
            );
            1
        }
    }
}

pub(crate) fn status_projection(
    status: &OperationStatus,
    compiled: &tirith_core::redact::CompiledCustomPatterns,
) -> Result<serde_json::Value, String> {
    let mut output = serde_json::to_value(status).map_err(|e| e.to_string())?;
    if let Some(detail) = output.get_mut("detail") {
        tirith_core::redact::redact_json_strings(detail, compiled);
    }
    if let Some(steps) = output
        .get_mut("steps")
        .and_then(serde_json::Value::as_array_mut)
    {
        for step in steps {
            for field in ["target", "description"] {
                if let Some(value) = step.get_mut(field) {
                    tirith_core::redact::redact_json_strings(value, compiled);
                }
            }
        }
    }
    let bytes = serde_json::to_vec_pretty(&output)
        .map_err(|_| "cannot measure operation display")?
        .len();
    if bytes >= tirith_core::verdict::MAX_PRESENTATION_BYTES {
        // A generic findings summary discards job IDs/states. Preserve control
        // semantics explicitly and refuse to present missing destinations as
        // a complete change preview.
        output["steps"] = serde_json::json!([]);
        output["detail"] = "Operation destinations exceed the display limit. Split the requested change into smaller plans before applying.".into();
        output["presentation_incomplete"] = true.into();
        output["omitted_steps"] = status.steps.len().into();
    }
    Ok(output)
}

/// The human state label: a finished apply or undo that retained platform
/// recovery material reads `<state>-with-recovery`.
pub(crate) fn human_state(output: &serde_json::Value) -> String {
    let state = output["state"].as_str().unwrap_or("unknown");
    let label = if output["recovery"] == true {
        format!("{state}-with-recovery")
    } else {
        state.to_owned()
    };
    tirith_core::output::sanitize_human_field(&label, &[])
}

/// Human text for a projected operation status (the `status_projection` JSON).
/// Used by commands whose `--json` mode prints that projection, so the
/// default mode reads as prose instead of the same JSON.
pub(crate) fn operation_human_text(output: &serde_json::Value) -> String {
    let id = tirith_core::output::sanitize_human_field(
        output["operation_id"].as_str().unwrap_or("unknown"),
        &[],
    );
    let mut text = format!(
        "Operation {id}: {}\n  Inspect: tirith policy operation {id}\n",
        human_state(output)
    );
    if let Some(detail) = output["detail"].as_str() {
        text.push_str(&format!(
            "  {}\n",
            tirith_core::output::sanitize_human_field(detail, &[])
        ));
    }
    text
}

/// Compact one-line rendering of a JSON value for human output.
pub(crate) fn human_value(value: &serde_json::Value) -> String {
    let text = match value {
        serde_json::Value::Null => "(unset)".to_string(),
        serde_json::Value::String(text) => text.clone(),
        other => other.to_string(),
    };
    tirith_core::output::sanitize_human_field(&text, &[])
}

fn show_status(
    status: &OperationStatus,
    compiled: &tirith_core::redact::CompiledCustomPatterns,
    json: bool,
) -> Result<i32, String> {
    let output = status_projection(status, compiled)?;
    if json {
        if !super::write_json_stdout(&output, "tirith policy operation: failed to write status") {
            return Ok(1);
        }
    } else {
        eprintln!(
            "Operation {}: {:?}{}",
            status.operation_id,
            status.state,
            if status.recovery { "WithRecovery" } else { "" }
        );
        eprintln!("  Inspect: tirith policy operation {}", status.operation_id);
        if let Some(detail) = output["detail"].as_str() {
            eprintln!(
                "  {}",
                tirith_core::output::sanitize_human_field(detail, &[])
            );
        }
    }
    Ok(
        if matches!(
            status.state,
            JobState::Completed | JobState::Undone | JobState::Planned | JobState::Cancelled
        ) {
            0
        } else {
            1
        },
    )
}

#[cfg(test)]
mod presentation_tests {
    use super::*;
    use crate::cli::setup::change_plan::{OperationKind, StepState, StepStatus};

    #[test]
    fn human_state_keeps_the_recovery_label_of_finished_operations() {
        let _shared_state = tirith_test_support::SharedStateGuard::acquire();
        let label = |state: &str, recovery: bool| {
            human_state(&serde_json::json!({"state": state, "recovery": recovery}))
        };
        assert_eq!(label("completed", true), "completed-with-recovery");
        assert_eq!(label("undone", true), "undone-with-recovery");
        assert_eq!(label("completed", false), "completed");
        assert_eq!(
            human_state(&serde_json::json!({"state": "planned"})),
            "planned"
        );
        assert!(operation_human_text(
            &serde_json::json!({"operation_id": "x", "state": "undone", "recovery": true})
        )
        .starts_with("Operation x: undone-with-recovery\n"));
    }

    #[test]
    fn oversized_job_display_keeps_control_identity_and_marks_missing_destinations() {
        let status = OperationStatus {
            schema_version: 1,
            operation_id: uuid::Uuid::new_v4().to_string(),
            kind: OperationKind::SetProfile,
            client_version: env!("CARGO_PKG_VERSION").into(),
            policy_identity: uuid::Uuid::new_v4().to_string(),
            state: JobState::Planned,
            recovery: false,
            no_op: false,
            irreversible: false,
            active_action: None,
            created_at: 1,
            updated_at: 1,
            detail: None,
            steps: (0..64)
                .map(|_| StepStatus {
                    target: std::path::PathBuf::from("/fixture/".to_owned() + &"a".repeat(4000)),
                    description: "Owned setting".repeat(100),
                    activation: false,
                    state: StepState::Pending,
                    recovery: false,
                })
                .collect(),
        };
        let view = status_projection(
            &status,
            &tirith_core::redact::CompiledCustomPatterns::new_silent(&[]),
        )
        .unwrap();
        assert_eq!(view["operation_id"], status.operation_id);
        assert_eq!(view["state"], "planned");
        assert_eq!(view["presentation_incomplete"], true);
        assert_eq!(view["omitted_steps"], 64);
        assert!(serde_json::to_vec_pretty(&view).unwrap().len() < 4096);
    }
}
