use super::super::setup::change_plan::MutationService;
use super::super::setup::shell_service::{self, ShellChange, ShellKind};
use super::super::{profile, profile_service, trust_lifecycle};
use super::{http, Service};
use serde::Deserialize;
use serde_json::{json, Value};
use tirith_core::policy::{captured_policy_dlp_patterns_or, PolicyDiagnosticCapture};
use tirith_core::policy_snapshot::{EffectivePolicySnapshot, ResolutionMode};
use tirith_core::redact::CompiledCustomPatterns;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ProfileRequest {
    profile: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct HistoryRequest {
    cursor: Option<String>,
    #[serde(default)]
    filter: tirith_core::history::HistoryFilter,
    #[serde(default = "page_limit")]
    limit: usize,
}
fn page_limit() -> usize {
    100
}

#[derive(Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
enum PlanRequest {
    RecommendedSetup {
        operation_id: String,
        change: super::super::setup::recommended::RecommendedSetup,
    },
    AuditSegment {
        operation_id: String,
        change: super::super::setup::audit_segments::SegmentChange,
    },
    AuditRetention {
        operation_id: String,
        change: super::super::setup::audit_service::AuditChange,
    },
    PolicyRollout {
        operation_id: String,
        change: super::super::rollout::RolloutRequest,
    },
    Feedback {
        operation_id: String,
        change: super::super::feedback::FeedbackRequest,
    },
    PersonalSetting {
        operation_id: String,
        change: profile_service::PersonalSettingChange,
    },
    Shell {
        operation_id: String,
        change: ShellChange,
    },
    Profile {
        operation_id: String,
        profile: String,
    },
    TrustAdd {
        operation_id: String,
        pattern: String,
        rule: Option<String>,
        ttl: Option<String>,
        #[serde(default)]
        permanent: bool,
        #[serde(default)]
        broad: bool,
        #[serde(default)]
        all_rules: bool,
        reason: Option<String>,
        scope: GrantScope,
    },
    TrustExpiry {
        operation_id: String,
        grant_id: String,
        ttl: Option<String>,
        #[serde(default)]
        permanent: bool,
    },
    TrustRevoke {
        operation_id: String,
        grant_id: String,
    },
    TrustMigrateUser {
        operation_id: String,
    },
}

#[derive(Deserialize)]
#[serde(rename_all = "snake_case")]
enum GrantScope {
    User,
    Project,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct OperationRequest {
    operation_id: String,
    action: OperationAction,
}

#[derive(Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
enum OperationAction {
    Status,
    Apply,
    Cancel,
    Undo,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ExplainTrust {
    target: String,
    scope: GrantScope,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ShellRequest {
    shell: ShellKind,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct LifecyclePrepare {
    operation_id: String,
    action: super::super::selfupdate::lifecycle_operations::Action,
}

fn body<T: serde::de::DeserializeOwned>(request: &http::Request) -> Result<T, String> {
    serde_json::from_slice(&request.body)
        .map_err(|_| "request does not match the endpoint schema".into())
}

fn snapshot(service: &Service) -> (EffectivePolicySnapshot, CompiledCustomPatterns) {
    let snapshot =
        EffectivePolicySnapshot::resolve(Some(&service.record.cwd), ResolutionMode::Runtime);
    let compiled = CompiledCustomPatterns::new_silent(&captured_policy_dlp_patterns_or(
        &snapshot.policy.dlp_custom_patterns,
    ));
    (snapshot, compiled)
}

pub(super) fn dispatch(service: &Service, request: &http::Request) -> (u16, Value) {
    if let Err(error) = service.auth.check(request) {
        return (error.status, json!({"error": error.message}));
    }
    if request.method == "GET" && request.target == "/api/session" {
        return (
            200,
            json!({"protocol": super::lifecycle::PROTOCOL, "service_id": service.record.service_id,
            "version": service.record.version, "binary_sha256": service.record.binary_sha256,
            "csrf": service.auth.csrf, "quiescing": service.quiescing.load(std::sync::atomic::Ordering::Acquire),
            "expires_in_seconds": service.auth.lifetime.saturating_sub(service.auth.issued.elapsed()).as_secs(),
            "active_jobs": super::super::setup::change_plan::active_job_count()}),
        );
    }
    let _capture = PolicyDiagnosticCapture::start();
    let result = route(service, request);
    let compiled = CompiledCustomPatterns::new_silent(&captured_policy_dlp_patterns_or(&[]));
    let diagnostics = tirith_core::policy::drain_captured_policy_diagnostics_for_output(&compiled);
    match result {
        Ok(mut value) => {
            merge_diagnostics(&mut value, diagnostics, &compiled);
            (200, value)
        }
        Err(error) => (
            409,
            json!({"error": tirith_core::redact::redact_sanitize_redact_with_compiled(&error, &compiled),
            "diagnostics": diagnostics, "refresh_required": true}),
        ),
    }
}

fn merge_diagnostics(
    value: &mut Value,
    diagnostics: Vec<String>,
    compiled: &CompiledCustomPatterns,
) {
    let Some(object) = value.as_object_mut() else {
        return;
    };
    let prior = object
        .remove("diagnostics")
        .and_then(|value| value.as_array().cloned())
        .unwrap_or_default();
    let previous_omitted = object
        .get("omitted_diagnostics")
        .and_then(Value::as_u64)
        .unwrap_or(0);
    let messages: Vec<_> = prior
        .into_iter()
        .filter_map(|value| value.as_str().map(str::to_string))
        .chain(diagnostics)
        .collect();
    let omitted = previous_omitted.saturating_add(messages.len().saturating_sub(32) as u64);
    let messages: Vec<_> = messages
        .into_iter()
        .take(32)
        .map(|message| {
            let redacted =
                tirith_core::redact::redact_sanitize_redact_with_compiled(&message, compiled);
            if redacted.len() > 1024 {
                "[withheld: diagnostic exceeds output limit]".into()
            } else {
                redacted
            }
        })
        .collect();
    object.insert("diagnostics".into(), json!(messages));
    object.insert("omitted_diagnostics".into(), json!(omitted));
}

fn route(service: &Service, request: &http::Request) -> Result<Value, String> {
    if request.target != "/api/quiesce" {
        service.revalidate_project()?;
    }
    let result = route_for_project(service, request)?;
    if request.target != "/api/quiesce" {
        service.revalidate_project()?;
    }
    Ok(result)
}

fn route_for_project(service: &Service, request: &http::Request) -> Result<Value, String> {
    let cwd = Some(service.record.cwd.as_str());
    match (request.method.as_str(), request.target.as_str()) {
        ("POST", "/api/artifacts/npm") => super::super::npm_artifact::browser::review(
            &service.record.cwd,
            body(request)?,
            &service.project_anchor,
        ),
        ("POST", "/api/project/review") => {
            #[derive(Deserialize)]
            #[serde(deny_unknown_fields)]
            struct ReviewRequest {
                #[serde(default)]
                paths: Vec<String>,
            }
            let query: ReviewRequest = body(request)?;
            super::super::project_review::inspect_retained(
                cwd,
                &query.paths,
                Some(&service.project_anchor),
            )
        }
        ("POST", "/api/project/revalidate") => {
            #[derive(Deserialize)]
            #[serde(deny_unknown_fields)]
            struct ReviewRequest {
                report_id: String,
            }
            let query: ReviewRequest = body(request)?;
            super::super::project_review::revalidate(&query.report_id, cwd)
        }
        ("POST", "/api/lifecycle/prepare") => {
            let query: LifecyclePrepare = body(request)?;
            let _admission = admission(service, request)?;
            let view = super::super::selfupdate::lifecycle_service::prepare(
                &query.operation_id,
                query.action,
            )?;
            lifecycle_projection(view, service)
        }
        ("POST", "/api/lifecycle/operation") => {
            let query: OperationRequest = body(request)?;
            let service_api = super::super::selfupdate::lifecycle_service::status;
            let view = if query.action == OperationAction::Status {
                service_api(&query.operation_id)?
            } else {
                let _admission = admission(service, request)?;
                match query.action {
                    OperationAction::Apply => {
                        let saved = service_api(&query.operation_id)?;
                        if saved.phase != super::super::selfupdate::lifecycle_operations::Phase::Prepared {
                            saved
                        } else if saved.action == super::super::selfupdate::lifecycle_operations::Action::RefreshThreatDb {
                            super::super::threatdb_cmd::lifecycle::apply(&query.operation_id)?
                        } else {
                            super::lifecycle_worker::start(&query.operation_id)?
                        }
                    }
                    OperationAction::Cancel => {
                        super::super::selfupdate::lifecycle_service::cancel(&query.operation_id)?
                    }
                    OperationAction::Undo => {
                        return Err("prepare an explicit compatible rollback from Settings".into())
                    }
                    OperationAction::Status => unreachable!(),
                }
            };
            lifecycle_projection(view, service)
        }
        ("POST", "/api/support/preview") => {
            let selection: super::super::support_bundle::Selection = body(request)?;
            super::super::support_bundle::preview(&selection, cwd)
        }
        ("GET", "/api/jobs") => {
            let _ = snapshot(service);
            let recent = MutationService::current()?.recent_statuses(30)?;
            // Inventory rows need identities and stored states, not every
            // potentially large destination. Opening a selected operation
            // obtains the complete reviewed step projection separately.
            let operations: Vec<_> = recent.operations.iter().map(|status| {
                json!({"schema_version":status.schema_version,"operation_id":status.operation_id,
                "kind":status.kind,"state":status.state,"no_op":status.no_op,"active_action":status.active_action,
                "created_at":status.created_at,"updated_at":status.updated_at,"step_count":status.steps.len()})
            }).collect();
            Ok(
                json!({"schema_version":1,"kind":"recent_operations", "operations":operations,"coverage":recent.coverage}),
            )
        }
        ("GET", "/api/activity/summary") => {
            let (policy, _) = snapshot(service);
            let mut report = service
                .aggregate
                .lock()
                .map_err(|_| "history aggregate is unavailable")?
                .refresh(
                    chrono::Utc::now(),
                    7,
                    std::env::var("TIRITH_LOG").ok().as_deref() != Some("0"),
                )?;
            let omitted = report.rules.len().saturating_sub(100);
            report.rules.truncate(100);
            let mut view = tirith_core::history_aggregate::display_projection(
                &report,
                &captured_policy_dlp_patterns_or(&policy.policy.dlp_custom_patterns),
            );
            view["omitted_rules_this_view"] = omitted.into();
            Ok(view)
        }
        ("GET", "/api/policy/tuning") => super::super::tuning::review(cwd),
        ("POST", "/api/integrations/inspect") => {
            let query: ShellRequest = body(request)?;
            shell_service::inspect(query.shell, cwd)
        }
        ("GET", "/api/state") | ("GET", "/api/integrations") => {
            let (_, compiled) = snapshot(service);
            let mut info = super::super::doctor::gather_quick_info();
            info.policy_path_used = info.policy_path_used.map(|path| {
                tirith_core::redact::redact_sanitize_redact_with_compiled(&path, &compiled)
            });
            info.protection_mode = tirith_core::redact::redact_sanitize_redact_with_compiled(
                &info.protection_mode,
                &compiled,
            );
            Ok(
                json!({"schema_version": 1, "kind": "protection_state", "shell": info,
                "package_approval": super::super::package_approval_authority::availability(),
                "audit_recording": super::super::audit_health::read().projection(),
                "project": tirith_core::redact::redact_sanitize_redact_with_compiled(&service.record.cwd, &compiled),
                "source": "local_service_inherited_context", "service_running_is_protection_evidence": false}),
            )
        }
        ("GET", "/api/policy") => {
            let (policy, compiled) = snapshot(service);
            super::super::policy::effective_snapshot_display(&policy, &compiled)
                .map_err(|_| "cannot project effective policy".into())
        }
        ("GET", "/api/exceptions") => {
            trust_lifecycle::TrustService::capture(cwd)?.list(None, true, "all")
        }
        ("GET", "/api/lifecycle") => {
            let value = serde_json::to_value(super::super::selfupdate::gather_lifecycle_facts())
                .map_err(|_| "cannot project lifecycle state")?;
            Ok(value)
        }
        ("GET", "/api/freshness") => {
            let (_, compiled) = snapshot(service);
            let mut value = serde_json::to_value(super::super::threatdb_cmd::gather_health())
                .map_err(|_| "cannot project ThreatDB health")?;
            // The signed blob stays private; the existing health projection is
            // display-only and does not mutate verification material.
            for pointer in [
                "/path",
                "/error",
                "/supplemental/path",
                "/freshness/source_evidence_error",
            ] {
                if let Some(content) = value.pointer_mut(pointer) {
                    tirith_core::redact::redact_json_strings(content, &compiled);
                }
            }
            project_update_record(&mut value["last_update"], &compiled);
            if let Some(sources) = value
                .pointer_mut("/freshness/sources")
                .and_then(Value::as_array_mut)
            {
                for source in sources {
                    for (field, canonical) in [
                        (
                            "source",
                            source["source"].as_str().is_some_and(|s| {
                                tirith_core::threatdb::operations::SOURCE_IDS.contains(&s)
                            }),
                        ),
                        (
                            "revision",
                            source["revision"].as_str().is_some_and(|s| {
                                s.len() == 40 && s.bytes().all(|b| b.is_ascii_hexdigit())
                            }),
                        ),
                        (
                            "pin_selected_at",
                            source["pin_selected_at"]
                                .as_str()
                                .is_some_and(|s| chrono::DateTime::parse_from_rfc3339(s).is_ok()),
                        ),
                    ] {
                        if !canonical {
                            if let Some(content) = source.get_mut(field) {
                                tirith_core::redact::redact_json_strings(content, &compiled);
                            }
                        }
                    }
                }
            }
            Ok(value)
        }
        ("POST", "/api/history") => {
            let query: HistoryRequest = body(request)?;
            if query
                .cursor
                .as_ref()
                .is_some_and(|cursor| uuid::Uuid::parse_str(cursor).is_err())
            {
                return Err("history cursor must be one issued by this service".into());
            }
            let (policy, _) = snapshot(service);
            let history = service
                .history
                .lock()
                .map_err(|_| "history reader is unavailable")?
                .newest_page(
                    query.cursor.as_deref(),
                    query.filter,
                    query.limit,
                    std::env::var("TIRITH_LOG").ok().as_deref() != Some("0"),
                )?;
            Ok(super::super::history::projection(
                &history,
                &captured_policy_dlp_patterns_or(&policy.policy.dlp_custom_patterns),
            ))
        }
        ("POST", "/api/profile/preview") => {
            let query: ProfileRequest = body(request)?;
            Ok(profile_service::PreparedProfile::capture(&query.profile, cwd)?.projection())
        }
        ("POST", "/api/settings/preview") => {
            let change: profile_service::PersonalSettingChange = body(request)?;
            profile_service::preview_setting(change, cwd)
        }
        ("POST", "/api/exceptions/explain") => {
            let query: ExplainTrust = body(request)?;
            trust_lifecycle::TrustService::capture(cwd)?.explain(
                &query.target,
                match query.scope {
                    GrantScope::User => "user",
                    GrantScope::Project => "project",
                },
            )
        }
        ("POST", "/api/plans") => {
            let query: PlanRequest = body(request)?;
            let _admission = admission(service, request)?;
            match query {
                PlanRequest::RecommendedSetup {
                    operation_id,
                    change,
                } => super::super::setup::recommended::prepare(&operation_id, change, cwd, false),
                PlanRequest::AuditSegment {
                    operation_id,
                    change,
                } => super::super::setup::audit_segments::prepare(&operation_id, change, cwd),
                PlanRequest::AuditRetention {
                    operation_id,
                    change,
                } => super::super::setup::audit_service::prepare(&operation_id, change, cwd),
                PlanRequest::PolicyRollout {
                    operation_id,
                    change,
                } => super::super::rollout::RolloutService::capture(cwd)?
                    .prepare(&operation_id, change),
                PlanRequest::Feedback {
                    operation_id,
                    change,
                } => super::super::feedback::prepare(&operation_id, change, cwd, false),
                PlanRequest::PersonalSetting {
                    operation_id,
                    change,
                } => profile_service::prepare_setting(&operation_id, change, cwd),
                PlanRequest::Shell {
                    operation_id,
                    change,
                } => shell_service::prepare(&operation_id, change, cwd),
                PlanRequest::Profile {
                    operation_id,
                    profile,
                } => profile_service::prepare(&operation_id, &profile, cwd),
                PlanRequest::TrustAdd {
                    operation_id,
                    pattern,
                    rule,
                    ttl,
                    permanent,
                    broad,
                    all_rules,
                    reason,
                    scope,
                } => trust_lifecycle::TrustService::capture(cwd)?.prepare(
                    &operation_id,
                    trust_lifecycle::TrustChange::Add(trust_lifecycle::AddGrantRequest {
                        pattern,
                        rule,
                        ttl,
                        permanent,
                        broad,
                        all_rules,
                        reason,
                        scope: match scope {
                            GrantScope::User => trust_lifecycle::GrantTarget::User,
                            GrantScope::Project => trust_lifecycle::GrantTarget::Project,
                        },
                    }),
                ),
                PlanRequest::TrustExpiry {
                    operation_id,
                    grant_id,
                    ttl,
                    permanent,
                } => trust_lifecycle::TrustService::capture(cwd)?.prepare(
                    &operation_id,
                    trust_lifecycle::TrustChange::Expiry {
                        id: grant_id,
                        ttl,
                        permanent,
                    },
                ),
                PlanRequest::TrustRevoke {
                    operation_id,
                    grant_id,
                } => trust_lifecycle::TrustService::capture(cwd)?.prepare(
                    &operation_id,
                    trust_lifecycle::TrustChange::Revoke { id: grant_id },
                ),
                PlanRequest::TrustMigrateUser { operation_id } => {
                    trust_lifecycle::TrustService::capture(cwd)?
                        .prepare(&operation_id, trust_lifecycle::TrustChange::MigrateUser)
                }
            }
        }
        ("POST", "/api/operations") => {
            let query: OperationRequest = body(request)?;
            uuid::Uuid::parse_str(&query.operation_id)
                .map_err(|_| "operation ID must be a UUID")?;
            let (policy, compiled) = snapshot(service);
            let mutations = MutationService::current()?;
            let status = if query.action == OperationAction::Status {
                mutations.status(&query.operation_id)?
            } else {
                let _admission = admission(service, request)?;
                match query.action {
                    OperationAction::Apply => mutations.apply_async(query.operation_id, policy)?,
                    OperationAction::Undo => mutations.undo_async(query.operation_id, policy)?,
                    OperationAction::Cancel => mutations.cancel(&query.operation_id)?,
                    OperationAction::Status => unreachable!(),
                }
            };
            let mut result = profile::status_projection(&status, &compiled)?;
            if let Some(review) = mutations.impact_review(&status.operation_id)? {
                review.validate_stored()?;
                result["impact_review"] =
                    serde_json::to_value(review).map_err(|_| "cannot project reviewed impact")?;
                if serde_json::to_vec_pretty(&result)
                    .map_err(|_| "cannot bound operation report")?
                    .len()
                    >= tirith_core::verdict::MAX_PRESENTATION_BYTES
                {
                    result["steps"] = json!([]);
                    result["impact_review"] = Value::Null;
                    result["presentation_incomplete"] = true.into();
                    result["detail"] = "This operation's combined review exceeds the display limit. Inspect a smaller plan before applying.".into();
                }
            }
            Ok(result)
        }
        ("POST", "/api/quiesce") => {
            #[derive(Deserialize)]
            #[serde(deny_unknown_fields)]
            struct Empty {}
            let _: Empty = body(request)?;
            let _guard = service
                .admission
                .lock()
                .map_err(|_| "service admission unavailable")?;
            service.auth.check(request).map_err(|error| error.message)?;
            service
                .quiescing
                .store(true, std::sync::atomic::Ordering::Release);
            Ok(
                json!({"schema_version": 1, "state": "draining", "active_jobs": super::super::setup::change_plan::active_job_count(),
                "protection_changed": false, "new_mutations_accepted": false}),
            )
        }
        _ => Err("unknown local control endpoint".into()),
    }
}

fn lifecycle_projection(
    view: super::super::selfupdate::lifecycle_operations::OperationView,
    service: &Service,
) -> Result<Value, String> {
    let (_, compiled) = snapshot(service);
    let mut value = serde_json::to_value(view).map_err(|_| "cannot project lifecycle operation")?;
    // Canonical action/phase/UUID/time fields are protocol. Candidate prose is
    // a display copy and receives the current privacy rules on every request.
    for pointer in [
        "/preview/current_version",
        "/preview/candidate_version",
        "/preview/evidence",
        "/preview/issues",
        "/next_action",
    ] {
        if let Some(content) = value.pointer_mut(pointer) {
            tirith_core::redact::redact_json_strings(content, &compiled);
        }
    }
    Ok(value)
}

fn project_update_record(value: &mut Value, compiled: &CompiledCustomPatterns) {
    let Some(object) = value.as_object_mut() else {
        return;
    };
    for (key, value) in object {
        let canonical = match (key.as_str(), value.as_str()) {
            ("status", Some("partial" | "failed" | "complete")) => true,
            ("phase", Some("primary" | "supplemental" | "complete")) => true,
            ("failure_category", Some(category)) => update_category(category),
            ("incident_key", Some(key)) => key.split_once(':').is_some_and(|(phase, category)| {
                matches!(phase, "primary" | "supplemental" | "complete")
                    && update_category(category)
            }),
            _ => false,
        };
        if !canonical {
            tirith_core::redact::redact_json_strings(value, compiled);
        }
    }
}

fn update_category(value: &str) -> bool {
    matches!(
        value,
        "integrity"
            | "rollback"
            | "rate_limit"
            | "validation"
            | "completeness"
            | "transport"
            | "operation"
    )
}

fn admission<'a>(
    service: &'a Service,
    request: &http::Request,
) -> Result<std::sync::MutexGuard<'a, ()>, String> {
    let guard = service
        .admission
        .lock()
        .map_err(|_| "service admission unavailable")?;
    service.auth.check(request).map_err(|error| error.message)?;
    if service.quiescing.load(std::sync::atomic::Ordering::Acquire) {
        return Err("service is draining; reopen it after active jobs finish".into());
    }
    service.directory_identity.revalidate()?;
    service.binary_identity.revalidate()?;
    Ok(guard)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dispatch_preserves_route_diagnostics_and_bounds_combined_output() {
        let mut value = json!({"kind":"npm_inspection", "diagnostics":["route diagnostic EARLIER_SECRET"], "omitted_diagnostics":2});
        let compiled = CompiledCustomPatterns::new_silent(&["EARLIER_SECRET".into()]);
        merge_diagnostics(&mut value, vec!["outer diagnostic".into(); 40], &compiled);
        assert_eq!(value["kind"], "npm_inspection");
        assert_eq!(value["diagnostics"].as_array().unwrap().len(), 32);
        assert!(value["diagnostics"][0]
            .as_str()
            .unwrap()
            .contains("route diagnostic"));
        assert!(!value.to_string().contains("EARLIER_SECRET"));
        assert_eq!(value["omitted_diagnostics"], 11);
    }
    #[test]
    fn plan_schema_cannot_carry_paths_commands_or_write_payloads() {
        for value in [
            json!({"kind":"profile","operation_id":uuid::Uuid::new_v4().to_string(),"profile":"balanced","path":"/tmp/policy"}),
            json!({"kind":"shell","command":"echo arbitrary"}),
            json!({"kind":"trust_add","pattern":"x","scope":"org"}),
        ] {
            assert!(serde_json::from_value::<PlanRequest>(value).is_err());
        }
    }

    #[test]
    fn update_display_preserves_canonical_state_under_broad_dlp() {
        let compiled = CompiledCustomPatterns::new_silent(&[".+".into()]);
        let mut value = json!({"status":"failed","phase":"primary","failure_category":"integrity","incident_key":"primary:integrity","next_action":"private content","consecutive_failures":2});
        project_update_record(&mut value, &compiled);
        assert_eq!(value["status"], "failed");
        assert_eq!(value["incident_key"], "primary:integrity");
        assert_eq!(value["consecutive_failures"], 2);
        assert!(!value["next_action"]
            .as_str()
            .unwrap()
            .contains("private content"));
        let mut invalid = json!({"status":"private content","incident_key":"private:token"});
        project_update_record(&mut invalid, &compiled);
        assert!(!invalid.to_string().contains("private"));
    }
}
