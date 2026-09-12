//! Local reviewed profile rollout. The shared mutation journal owns both the
//! immutable typed intent and canonical impact attachment; activation is explicit.
use super::profile_service::PreparedProfile;
use super::setup::change_plan::{MutationService, OperationKind};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::path::Path;
use tirith_core::evaluation::{FrozenEvaluation, SessionEvidence};
use tirith_core::policy::{captured_policy_dlp_patterns_or, PolicyDiagnosticCapture};
use tirith_core::policy_rollout::{
    self, ClientObservation, Exception, ExceptionOwner, RecordId, RolloutScope, Workflow,
};
use tirith_core::policy_snapshot::{EffectivePolicySnapshot, ResolutionMode};
use tirith_core::protection_profiles::ProtectionProfile;
use tirith_core::redact::CompiledCustomPatterns;
use tirith_core::tokenize::ShellType;
use tirith_core::trust_grants::{ProjectIdentity, TrustGrant, TrustGrantStore};

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RolloutRequest {
    pub profile: ProtectionProfile,
    pub commands: Vec<String>,
    pub shell: ShellType,
    pub interactive: bool,
}
#[derive(Serialize)]
struct Intent<'a> {
    kind: &'static str,
    scope: &'static str,
    cwd: &'a str,
    request: &'a RolloutRequest,
}

pub(crate) struct RolloutService {
    cwd: String,
}
impl RolloutService {
    pub fn capture(cwd: Option<&str>) -> Result<Self, String> {
        let cwd = cwd
            .map(str::to_string)
            .or_else(|| {
                std::env::current_dir()
                    .ok()
                    .and_then(|path| path.to_str().map(str::to_string))
            })
            .ok_or("cannot resolve rollout working directory")?;
        if !Path::new(&cwd).is_absolute() {
            return Err("rollout working directory must be absolute".into());
        }
        Ok(Self { cwd })
    }

    pub fn prepare(&self, id: &str, request: RolloutRequest) -> Result<Value, String> {
        RecordId::parse(id)?;
        if request.commands.is_empty()
            || request.commands.len() > 32
            || request
                .commands
                .iter()
                .any(|command| command.is_empty() || command.len() > 4096 || command.contains('\0'))
            || request.commands.iter().map(String::len).sum::<usize>() > 64 * 1024
        {
            return Err(
                "rollout requires 1–32 commands, at most 4096 bytes each and 64 KiB total".into(),
            );
        }
        let intent = Intent {
            kind: "profile_rollout_v1",
            scope: "user",
            cwd: &self.cwd,
            request: &request,
        };
        let writer = MutationService::current()?;
        if writer
            .status_for_intent(id, OperationKind::SetProfile, &intent)?
            .is_some()
        {
            return self.show(id);
        }
        let _capture = PolicyDiagnosticCapture::start();
        let prepared = PreparedProfile::capture(request.profile.as_str(), Some(&self.cwd))?;
        let (candidate, coverage) = prepared.rollout_candidate()?;
        let owner = RecordId::parse(&uuid::Uuid::new_v4().to_string())?;
        let frozen: Vec<_> = request
            .commands
            .iter()
            .map(|command| {
                FrozenEvaluation::capture(
                    tirith_core::engine::AnalysisContext {
                        input: command.clone(),
                        shell: request.shell,
                        scan_context: tirith_core::extract::ScanContext::Exec,
                        raw_bytes: None,
                        interactive: request.interactive,
                        cwd: Some(self.cwd.clone()),
                        file_path: None,
                        repo_root: None,
                        is_config_override: false,
                        clipboard_html: None,
                        card_ref: None,
                        clipboard_source:
                            tirith_core::clipboard::ClipboardSourceState::AbsentOrInvalid,
                    },
                    &prepared.snapshot,
                    tirith_core::escalation::CallerContext::Cli,
                    None,
                    SessionEvidence::Unavailable,
                )
            })
            .collect();
        let workflows: Vec<_> = frozen
            .iter()
            .map(|evidence| Workflow {
                id: RecordId::parse(&uuid::Uuid::new_v4().to_string()).unwrap(),
                evidence,
                owner: Some(owner.clone()),
            })
            .collect();
        let (grants, exception_inventory_complete) = captured_grants()?;
        let project = ProjectIdentity::capture(Some(&self.cwd)).ok();
        let exceptions: Vec<_> = grants
            .iter()
            .map(|grant| Exception {
                grant,
                owner: ExceptionOwner::LocalOperator { id: owner.clone() },
                project: project.as_ref(),
            })
            .collect();
        let now = Utc::now();
        let clients = [ClientObservation::local_runtime(
            RecordId::parse(&uuid::Uuid::new_v4().to_string())?,
            &prepared.snapshot,
            &candidate,
            now,
        )];
        let report = policy_rollout::review(policy_rollout::ImpactRequest {
            id: RecordId::parse(&uuid::Uuid::new_v4().to_string())?,
            candidate_id: RecordId::parse(id)?,
            scope: RolloutScope::PersonalUser,
            baseline: &prepared.snapshot,
            candidate: &candidate,
            candidate_coverage: coverage,
            workflows: &workflows,
            exceptions: &exceptions,
            exception_inventory_complete,
            clients: &clients,
            now,
        })?;
        // Input witnesses reject trust/policy changes between capture and the
        // separate inventory read before the report and plan are published.
        prepared
            .snapshot
            .revalidate_inputs()
            .map_err(|_| "rollout evidence changed during capture; prepare a new review")?;
        let status = prepared.plan_with_rollout_review(id, &intent, report)?;
        let report = writer
            .impact_review(id)?
            .ok_or("rollout review attachment is unavailable")?;
        let diagnostics =
            tirith_core::policy::drain_captured_policy_diagnostics_for_output(&prepared.compiled);
        project_output(
            &status,
            &report,
            &prepared.snapshot,
            &prepared.compiled,
            &diagnostics,
        )
    }

    pub fn show(&self, id: &str) -> Result<Value, String> {
        RecordId::parse(id)?;
        let writer = MutationService::current()?;
        let report = writer
            .impact_review(id)?
            .ok_or("operation is not a reviewed profile rollout")?;
        let status = writer.status(id)?;
        let _capture = PolicyDiagnosticCapture::start();
        let snapshot = EffectivePolicySnapshot::resolve(Some(&self.cwd), ResolutionMode::Runtime);
        let compiled = CompiledCustomPatterns::new_silent(&captured_policy_dlp_patterns_or(
            &snapshot.policy.dlp_custom_patterns,
        ));
        let diagnostics =
            tirith_core::policy::drain_captured_policy_diagnostics_for_output(&compiled);
        project_output(&status, &report, &snapshot, &compiled, &diagnostics)
    }

    pub fn activate(&self, id: &str, undo: bool) -> Result<Value, String> {
        RecordId::parse(id)?;
        let writer = MutationService::current()?;
        let review = writer
            .impact_review(id)?
            .ok_or("operation is not a reviewed profile rollout")?;
        if !undo
            && (review.evaluated_at > Utc::now()
                || (Utc::now() - review.evaluated_at).num_seconds()
                    >= policy_rollout::EVIDENCE_MAX_AGE_SECONDS)
        {
            return Err("rollout review is stale or has an invalid clock; prepare a new operation before activation".into());
        }
        let _capture = PolicyDiagnosticCapture::start();
        let snapshot = EffectivePolicySnapshot::resolve(Some(&self.cwd), ResolutionMode::Runtime);
        let compiled = CompiledCustomPatterns::new_silent(&captured_policy_dlp_patterns_or(
            &snapshot.policy.dlp_custom_patterns,
        ));
        let result = if undo {
            writer.undo(id, &snapshot)
        } else {
            writer.apply(id, &snapshot)
        };
        result.map_err(|error| {
            tirith_core::redact::redact_sanitize_redact_with_compiled(&error, &compiled)
        })?;
        self.show(id)
    }
}

fn captured_grants() -> Result<(Vec<TrustGrant>, bool), String> {
    let config =
        tirith_core::policy::config_dir().ok_or("operator configuration is unavailable")?;
    let store = match tirith_core::util::read_text_no_follow_capped(
        &config.join(tirith_core::trust_grants::STORE_FILE),
        tirith_core::trust_grants::STORE_READ_CAP,
    ) {
        Ok(bytes) => TrustGrantStore::parse(&bytes).map_err(str::to_string)?,
        Err(tirith_core::util::OpenRegularError::NotFound) => TrustGrantStore::default(),
        Err(_) => return Err("cannot capture bounded trust grant inventory".into()),
    };
    let legacy_absent = match tirith_core::util::read_text_no_follow_capped(
        &config.join("trust.json"),
        1024 * 1024,
    ) {
        Err(tirith_core::util::OpenRegularError::NotFound) => true,
        Ok(bytes) => serde_json::from_slice::<Value>(&bytes)
            .ok()
            .and_then(|value| {
                value
                    .get("entries")
                    .and_then(Value::as_array)
                    .map(Vec::is_empty)
            })
            .unwrap_or(false),
        _ => false,
    };
    let mut complete = legacy_absent;
    let mut grants = Vec::new();
    for decoded in store.records() {
        match decoded {
            Ok(grant) if grants.len() < policy_rollout::MAX_EXCEPTIONS => grants.push(grant),
            _ => complete = false,
        }
    }
    Ok((grants, complete))
}

fn project_output(
    status: &super::setup::change_plan::OperationStatus,
    report: &policy_rollout::ImpactReport,
    snapshot: &EffectivePolicySnapshot,
    compiled: &CompiledCustomPatterns,
    diagnostics: &[String],
) -> Result<Value, String> {
    report.validate_stored()?;
    let operation = super::profile::status_projection(status, compiled)?;
    let selected = snapshot
        .requested_profile
        .as_ref()
        .map(|selection| json!({"name":selection.name,"version":selection.version}));
    let now = Utc::now();
    let freshness = if report.evaluated_at > now {
        "invalid_timestamp"
    } else if (now - report.evaluated_at).num_seconds() >= policy_rollout::EVIDENCE_MAX_AGE_SECONDS
    {
        "stale"
    } else {
        "recent"
    };
    let mut output = json!({"schema_version":1,"kind":"policy_rollout","operation":operation,"impact":report,
        "live":{"observed_at":now,"impact_freshness":freshness,"historical_client_observations":true,"policy_identity":snapshot.identity,"selected_profile":selected,"personal_target_effective":snapshot.operator_targets.iter().find(|target|target.scope=="user").is_some_and(|target|target.effective),
            "selection_is_not_adoption_proof":true,"remote_publication":"unavailable","fleet_adoption":"unavailable"},
        "diagnostics":diagnostics.iter().take(32).map(|value|{let redacted=tirith_core::redact::redact_sanitize_redact_with_compiled(value,compiled);if redacted.len()>1024 {"[withheld: diagnostic exceeds display limit]".into()}else{redacted}}).collect::<Vec<String>>(),"omitted_diagnostics":diagnostics.len().saturating_sub(32)});
    let oversized = |value: &Value| {
        serde_json::to_vec_pretty(value).map_or(true, |bytes| bytes.len() > 480 * 1024)
    };
    if oversized(&output) {
        output["presentation_incomplete"] = true.into();
        output["operation"]["omitted_steps"] = status.steps.len().into();
        output["operation"]["steps"] = json!([]);
        output["operation"]["presentation_incomplete"] = true.into();
    }
    if oversized(&output) {
        output["diagnostics"] = json!([]);
        output["omitted_diagnostics"] = diagnostics.len().into();
    }
    if oversized(&output) {
        // Keep canonical IDs, decisions/counts, profile and freshness metadata;
        // explicitly withhold whole optional collections from this display copy.
        for group in ["workflows", "exceptions", "clients"] {
            let count = output["impact"][group].as_array().map_or(0, Vec::len);
            output["impact"][format!("omitted_{group}")] = count.into();
            output["impact"][group] = json!([]);
        }
        output["impact"]["presentation_incomplete"] = true.into();
    }
    if oversized(&output) {
        return Err("rollout display exceeds its serialized output limit".into());
    }
    Ok(output)
}

pub fn prepare_cli(
    profile: ProtectionProfile,
    commands: Vec<String>,
    shell: ShellType,
    interactive: bool,
    id: Option<&str>,
    json_output: bool,
) -> i32 {
    let id = id
        .map(str::to_string)
        .unwrap_or_else(|| uuid::Uuid::new_v4().to_string());
    run(json_output, |service| {
        service.prepare(
            &id,
            RolloutRequest {
                profile,
                commands,
                shell,
                interactive,
            },
        )
    })
}
pub fn operation_cli(id: &str, action: &str, json_output: bool) -> i32 {
    run(json_output, |service| match action {
        "show" => service.show(id),
        "activate" => service.activate(id, false),
        "undo" => service.activate(id, true),
        _ => Err("unknown rollout operation".into()),
    })
}
fn run(json_output: bool, action: impl FnOnce(&RolloutService) -> Result<Value, String>) -> i32 {
    let _capture = PolicyDiagnosticCapture::start();
    let result = RolloutService::capture(None).and_then(|service| action(&service));
    match result {
        Ok(value) => {
            if json_output {
                if !super::write_json_stdout(
                    &value,
                    "tirith policy rollout: failed to write report",
                ) {
                    return 1;
                }
            } else {
                eprintln!(
                    "Rollout {}: {}",
                    value["operation"]["operation_id"]
                        .as_str()
                        .unwrap_or("unknown"),
                    value["operation"]["state"].as_str().unwrap_or("unknown")
                );
                for (index, workflow) in value["impact"]["workflows"]
                    .as_array()
                    .into_iter()
                    .flatten()
                    .enumerate()
                {
                    eprintln!(
                        "  Workflow {}: {} -> {} ({})",
                        index + 1,
                        workflow["before"].as_str().unwrap_or("unknown"),
                        workflow["proposed"].as_str().unwrap_or("unknown"),
                        workflow["change"].as_str().unwrap_or("unavailable")
                    );
                }
                eprintln!("  Local operator scope. Remote publication and fleet adoption are unavailable.");
                eprintln!(
                    "  Activate explicitly: tirith policy rollout activate {}",
                    value["operation"]["operation_id"]
                        .as_str()
                        .unwrap_or("unknown")
                );
            }
            if matches!(
                value["operation"]["state"].as_str(),
                Some(
                    "planned"
                        | "completed"
                        | "completed_with_recovery"
                        | "undone"
                        | "undone_with_recovery"
                        | "cancelled"
                )
            ) {
                0
            } else {
                1
            }
        }
        Err(error) => {
            let patterns =
                CompiledCustomPatterns::new_silent(&captured_policy_dlp_patterns_or(&[]));
            let error =
                tirith_core::redact::redact_sanitize_redact_with_compiled(&error, &patterns);
            if json_output {
                super::write_json_stdout(
                    &json!({"schema_version":1,"kind":"policy_rollout_error","status":"refused","message":error}),
                    "cannot write rollout error",
                );
            } else {
                eprintln!("tirith policy rollout: {error}");
            }
            1
        }
    }
}

#[cfg(test)]
mod tests {
    use super::super::setup::change_plan::{JobState, OperationStatus, StepState, StepStatus};
    use super::*;

    #[test]
    fn composite_projection_stays_bounded_without_erasing_saved_operation_identity() {
        let _state = tirith_test_support::GlobalStateGuard::new().unwrap();
        let snapshot = EffectivePolicySnapshot::resolve(None, ResolutionMode::Runtime);
        let id = uuid::Uuid::new_v4().to_string();
        let now = Utc::now();
        let owner = RecordId::parse(&uuid::Uuid::new_v4().to_string()).unwrap();
        let grants: Vec<_> = (0..400)
            .map(|_| TrustGrant {
                id: uuid::Uuid::new_v4().to_string(),
                pattern: "example.com".into(),
                rule_id: None,
                scope: tirith_core::trust_grants::GrantScope::User,
                created_at: now.to_rfc3339(),
                expires_at: None,
                revoked_at: None,
                reason: None,
            })
            .collect();
        let exceptions: Vec<_> = grants
            .iter()
            .map(|grant| Exception {
                grant,
                owner: ExceptionOwner::LocalOperator { id: owner.clone() },
                project: None,
            })
            .collect();
        let report = policy_rollout::review(policy_rollout::ImpactRequest {
            id: owner.clone(),
            candidate_id: RecordId::parse(&id).unwrap(),
            scope: RolloutScope::PersonalUser,
            baseline: &snapshot,
            candidate: &snapshot.policy,
            candidate_coverage: policy_rollout::CandidateCoverage::EffectivePolicy,
            workflows: &[],
            exceptions: &exceptions,
            exception_inventory_complete: true,
            clients: &[],
            now,
        })
        .unwrap();
        let status = OperationStatus {
            schema_version: 1,
            operation_id: id.clone(),
            kind: OperationKind::SetProfile,
            client_version: env!("CARGO_PKG_VERSION").into(),
            policy_identity: snapshot.identity.clone(),
            state: JobState::Planned,
            no_op: false,
            irreversible: false,
            active_action: None,
            created_at: 0,
            updated_at: 0,
            detail: None,
            steps: vec![StepStatus {
                target: std::path::PathBuf::from("p".repeat(120000)),
                description: "d".repeat(120000),
                activation: true,
                state: StepState::Pending,
            }],
        };
        let value = project_output(
            &status,
            &report,
            &snapshot,
            &CompiledCustomPatterns::new_silent(&[]),
            &[],
        )
        .unwrap();
        assert!(serde_json::to_vec_pretty(&value).unwrap().len() <= 480 * 1024);
        assert_eq!(value["operation"]["operation_id"], id);
        assert_eq!(value["impact"]["candidate_id"], id);
        assert_eq!(value["operation"]["state"], "planned");
    }
}
