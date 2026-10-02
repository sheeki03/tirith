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

fn body<T: serde::de::DeserializeOwned>(request: &http::Request) -> Result<T, String> {
    serde_json::from_slice(&request.body)
        .map_err(|_| "request does not match the endpoint schema".into())
}

/// Full Runtime resolution, which may contact a configured remote policy
/// server. Only routes that show or act on the effective policy use it.
fn snapshot(service: &Service) -> (EffectivePolicySnapshot, CompiledCustomPatterns) {
    let snapshot =
        EffectivePolicySnapshot::resolve(Some(&service.record.cwd), ResolutionMode::Runtime);
    let patterns = captured_policy_dlp_patterns_or(&snapshot.policy.dlp_custom_patterns);
    service.observe_runtime(&snapshot, &patterns);
    let compiled = CompiledCustomPatterns::new_silent(&patterns);
    (snapshot, compiled)
}

/// What read-only routes take from the policy, without any network request.
struct ReadView {
    patterns: Vec<String>,
    refresh_interval_hours: u64,
}

/// A fresh no-network Runtime resolution (local inputs and the team cache)
/// plus every DLP pattern from Runtime resolutions this service already made.
/// When a legacy remote policy server is configured, the no-network
/// resolution stops before it, so the ThreatDB interval comes from the latest
/// full Runtime resolution instead.
fn read_view(service: &Service) -> ReadView {
    let local = EffectivePolicySnapshot::resolve_runtime_without_network(Some(&service.record.cwd));
    let (runtime_patterns, runtime_interval) = service.runtime_view();
    let mut patterns = captured_policy_dlp_patterns_or(&local.policy.dlp_custom_patterns);
    for pattern in local
        .policy
        .dlp_custom_patterns
        .iter()
        .cloned()
        .chain(runtime_patterns)
    {
        if !patterns.contains(&pattern) {
            patterns.push(pattern);
        }
    }
    let refresh_interval_hours = match runtime_interval {
        Some(interval) if local.remote.availability == "refused_local_mutation" => interval,
        _ => local.policy.threat_intel.auto_update_hours,
    };
    ReadView {
        patterns,
        refresh_interval_hours,
    }
}

fn read_patterns(service: &Service) -> Vec<String> {
    read_view(service).patterns
}

/// The policy a read-only route evaluates against, without any network
/// request: a fresh no-network Runtime resolution or, when a legacy remote
/// policy server makes that resolution refuse, the service's latest full
/// Runtime resolution.
fn read_snapshot(service: &Service) -> EffectivePolicySnapshot {
    let local = EffectivePolicySnapshot::resolve_runtime_without_network(Some(&service.record.cwd));
    if local.remote.availability == "refused_local_mutation" {
        if let Some(runtime) = service.runtime_snapshot() {
            return runtime;
        }
    }
    local
}

/// Route an authorized request. `grant` is the credential decision made
/// when the request was read; it is not re-derived here.
pub(super) fn dispatch(
    service: &Service,
    request: &http::Request,
    grant: &http::Grant,
) -> (u16, Value) {
    if request.method == "GET" && request.target == "/api/session" {
        return (
            200,
            json!({"protocol": super::lifecycle::PROTOCOL, "service_id": service.record.service_id,
            "version": service.record.version, "binary_sha256": service.record.binary_sha256,
            "csrf": grant.csrf, "quiescing": service.quiescing.load(std::sync::atomic::Ordering::Acquire),
            "expires_in_seconds": grant.expires_in.as_secs(),
            "active_jobs": super::super::setup::change_plan::active_job_count()}),
        );
    }
    if request.method == "POST" && request.target == "/api/session/code" {
        return sign_in_code(service, request, grant);
    }
    let _capture = PolicyDiagnosticCapture::start();
    let result = route(service, request);
    let compiled = CompiledCustomPatterns::new_silent(&captured_policy_dlp_patterns_or(&[]));
    let diagnostics = tirith_core::policy::drain_captured_policy_diagnostics_for_output(&compiled);
    match result {
        Ok(mut value) => {
            merge_diagnostics(&mut value, diagnostics, &compiled);
            if request.method == "GET" && request.target == "/api/policy" {
                bound_policy_control_inventory(&mut value);
            }
            (200, value)
        }
        Err(error) => (
            409,
            json!({"error": tirith_core::redact::redact_sanitize_redact_with_compiled(&error, &compiled),
            "diagnostics": diagnostics, "refresh_required": true}),
        ),
    }
}

/// A single-use launch code, issued only to the private service credential.
fn sign_in_code(service: &Service, request: &http::Request, grant: &http::Grant) -> (u16, Value) {
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Empty {}
    if !grant.service {
        return (
            403,
            json!({"error": "sign-in codes are issued only to the local launcher"}),
        );
    }
    if body::<Empty>(request).is_err() {
        return (
            400,
            json!({"error": "request does not match the endpoint schema"}),
        );
    }
    if service.quiescing.load(std::sync::atomic::Ordering::Acquire) {
        return (
            409,
            json!({"error": "service is draining; reopen it after active jobs finish"}),
        );
    }
    let code = super::lifecycle::secret();
    match service
        .auth
        .issue_code(code.clone(), std::time::Instant::now())
    {
        Ok(expires) => (
            200,
            json!({"schema_version": 1, "code": code, "expires_in_seconds": expires.as_secs()}),
        ),
        Err(error) => (error.status, json!({"error": error.message})),
    }
}

fn bound_policy_control_inventory(value: &mut Value) {
    if serde_json::to_vec(value).is_ok_and(|bytes| bytes.len() > http::MAX_RESPONSE) {
        if let Some(object) = value.as_object_mut() {
            if object.remove("personal_controls").is_some() {
                object.insert("personal_controls_omitted".into(), true.into());
            }
        }
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
    let (messages, omitted_now) = super::super::bounded_diagnostics(messages, 32, |message| {
        tirith_core::redact::redact_sanitize_redact_with_compiled(message, compiled)
    });
    let omitted = previous_omitted.saturating_add(omitted_now as u64);
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
        ("POST", "/api/team/rollout/prepare") => {
            #[derive(Deserialize)]
            #[serde(deny_unknown_fields)]
            struct Query {
                operation_id: String,
                change: super::super::team_rollout::ReviewInput,
            }
            let query: Query = body(request)?;
            let _admission = admission(service, request)?;
            super::super::team_rollout::TeamRolloutService::capture(cwd)?
                .prepare(&query.operation_id, query.change)
        }
        ("POST", "/api/team/rollout/rollback-plan") => {
            #[derive(Deserialize)]
            #[serde(deny_unknown_fields)]
            struct Query {
                operation_id: String,
                publication_id: String,
            }
            let query: Query = body(request)?;
            let _admission = admission(service, request)?;
            super::super::team_rollout::TeamRolloutService::capture(cwd)?
                .prepare_rollback(&query.operation_id, &query.publication_id)
        }
        ("POST", "/api/team/rollout/show") => {
            #[derive(Deserialize)]
            #[serde(deny_unknown_fields)]
            struct Query {
                operation_id: String,
                refresh: bool,
            }
            let query: Query = body(request)?;
            let _admission = admission(service, request)?;
            super::super::team_rollout::TeamRolloutService::capture(cwd)?
                .show(&query.operation_id, query.refresh)
        }
        ("POST", "/api/team/rollout/apply") => {
            #[derive(Deserialize)]
            #[serde(deny_unknown_fields)]
            struct Query {
                operation_id: String,
                review_id: String,
                rollback: bool,
            }
            let query: Query = body(request)?;
            let _admission = admission(service, request)?;
            super::super::team_rollout::TeamRolloutService::capture(cwd)?.apply(
                &query.operation_id,
                &query.review_id,
                query.rollback,
            )
        }
        ("POST", "/api/team/rollout/fleet") => {
            #[derive(Deserialize)]
            #[serde(deny_unknown_fields)]
            struct Query {}
            let _: Query = body(request)?;
            let _admission = admission(service, request)?;
            super::super::team_rollout::TeamRolloutService::capture(cwd)?.fleet()
        }
        ("GET", "/api/team/enrollment") => {
            super::super::team_enrollment::TeamEnrollmentService::capture(cwd)?.current()
        }
        ("POST", "/api/team/enrollment/activate") => {
            let query: super::super::team_enrollment::ActivateRequest = body(request)?;
            let _admission = admission(service, request)?;
            super::super::team_enrollment::TeamEnrollmentService::capture(cwd)?.activate(query)
        }
        ("POST", "/api/team/enrollment/sync") => {
            let query: super::super::team_enrollment::SelectedRequest = body(request)?;
            let _admission = admission(service, request)?;
            super::super::team_enrollment::TeamEnrollmentService::capture(cwd)?.sync(query)
        }
        ("POST", "/api/team/enrollment/disable") => {
            let query: super::super::team_enrollment::DisableRequest = body(request)?;
            let _admission = admission(service, request)?;
            super::super::team_enrollment::TeamEnrollmentService::disable(query)
        }
        ("POST", "/api/team/enrollment/repair") => {
            let query: super::super::team_enrollment::RepairRequest = body(request)?;
            let _admission = admission(service, request)?;
            super::super::team_enrollment::TeamEnrollmentService::repair(query)
        }
        ("POST", "/api/team/enrollment/abandon") => {
            let query: super::super::team_enrollment::AbandonRequest = body(request)?;
            let _admission = admission(service, request)?;
            super::super::team_enrollment::TeamEnrollmentService::abandon(query)
        }
        ("POST", "/api/team/enrollment/reconcile") => {
            let query: super::super::team_enrollment::ReconcileRequest = body(request)?;
            let _admission = admission(service, request)?;
            super::super::team_enrollment::TeamEnrollmentService::reconcile(query)
        }
        ("POST", "/api/team/enrollment/report") => {
            let query: super::super::team_enrollment::ReportRequest = body(request)?;
            let _admission = admission(service, request)?;
            super::super::team_enrollment::TeamEnrollmentService::capture(cwd)?.report(query)
        }
        ("GET", "/api/team/connection") => serde_json::to_value(
            super::super::team_connection::ConnectionService::current(false)?,
        )
        .map_err(|_| "cannot encode team connection status".into()),
        ("POST", "/api/team/connection/status") => {
            #[derive(Deserialize)]
            #[serde(deny_unknown_fields)]
            struct Query {
                refresh: bool,
            }
            let query: Query = body(request)?;
            let _admission = admission(service, request)?;
            serde_json::to_value(super::super::team_connection::ConnectionService::current(
                query.refresh,
            )?)
            .map_err(|_| "cannot encode team connection status".into())
        }
        ("POST", "/api/team/connection/connect") => {
            let query: super::super::team_connection::ConnectRequest = body(request)?;
            let _admission = admission(service, request)?;
            serde_json::to_value(super::super::team_connection::ConnectionService::connect(
                query,
            )?)
            .map_err(|_| "cannot encode team connection status".into())
        }
        ("POST", "/api/team/connection/disconnect") => {
            #[derive(Deserialize)]
            #[serde(deny_unknown_fields)]
            struct Query {
                expected_connection_id: String,
            }
            let query: Query = body(request)?;
            let _admission = admission(service, request)?;
            serde_json::to_value(
                super::super::team_connection::ConnectionService::disconnect(
                    &query.expected_connection_id,
                )?,
            )
            .map_err(|_| "cannot encode team connection status".into())
        }

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
        ("POST", "/api/threatdb/refresh") => {
            #[derive(Deserialize)]
            #[serde(deny_unknown_fields)]
            struct Empty {}
            let _: Empty = body(request)?;
            let _admission = admission(service, request)?;
            super::super::threatdb_cmd::lifecycle::guarded_refresh(std::path::Path::new(
                &service.record.cwd,
            ))?;
            Ok(
                json!({"schema_version": 1, "kind": "threatdb_refresh", "state": "completed",
                "freshness": freshness_projection(service)?}),
            )
        }
        ("POST", "/api/support/preview") => {
            let selection: super::super::support_bundle::Selection = body(request)?;
            super::super::support_bundle::preview(&selection, cwd)
        }
        ("GET", "/api/jobs") => {
            let recent = MutationService::current()?.recent_statuses(30)?;
            // Inventory rows need identities and stored states, not every
            // potentially large destination. Opening a selected operation
            // obtains the complete reviewed step projection separately.
            let operations: Vec<_> = recent.operations.iter().map(|status| {
                json!({"schema_version":status.schema_version,"operation_id":status.operation_id,
                "kind":status.kind,"state":status.state,"recovery":status.recovery,"no_op":status.no_op,"active_action":status.active_action,
                "created_at":status.created_at,"updated_at":status.updated_at,"step_count":status.steps.len()})
            }).collect();
            Ok(
                json!({"schema_version":1,"kind":"recent_operations", "operations":operations,"coverage":recent.coverage}),
            )
        }
        ("GET", "/api/activity/summary") => {
            let patterns = read_patterns(service);
            let mut report = tirith_core::history_aggregate::summarize(
                &service.history,
                chrono::Utc::now(),
                7,
                tirith_core::audit::logging_enabled(),
            )?;
            let omitted = report.rules.len().saturating_sub(100);
            report.rules.truncate(100);
            let mut view = tirith_core::history_aggregate::display_projection(&report, &patterns);
            view["omitted_rules_this_view"] = omitted.into();
            Ok(view)
        }
        ("GET", "/api/policy/tuning") => {
            super::super::tuning::review_with_patterns(read_patterns(service))
        }
        ("POST", "/api/integrations/inspect") => {
            let query: ShellRequest = body(request)?;
            shell_service::inspect(query.shell, cwd)
        }
        ("GET", "/api/state") | ("GET", "/api/integrations") => {
            let compiled = CompiledCustomPatterns::new_silent(&read_patterns(service));
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
            let mut trust = trust_lifecycle::TrustService::capture_read_only(
                cwd,
                read_snapshot(service),
                &read_patterns(service),
            )?;
            let mut value = trust.list(None, true, "all")?;
            // Policy diagnostics from the trust context's own capture are part
            // of this response (merged with the route's by `dispatch`).
            value["diagnostics"] = json!(std::mem::take(&mut trust.diagnostics));
            Ok(value)
        }
        ("GET", "/api/lifecycle") => {
            let value = serde_json::to_value(super::super::selfupdate::gather_lifecycle_facts())
                .map_err(|_| "cannot project lifecycle state")?;
            Ok(value)
        }
        ("GET", "/api/freshness") => freshness_projection(service),
        ("POST", "/api/history") => {
            let query: HistoryRequest = body(request)?;
            if query.cursor.as_ref().is_some_and(|cursor| {
                cursor.len() != tirith_core::history::CURSOR_HEX_LEN
                    || !cursor
                        .bytes()
                        .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
            }) {
                return Err("history cursor must be one issued by this service".into());
            }
            let patterns = read_patterns(service);
            let history = service.history.newest_page(
                query.cursor.as_deref(),
                query.filter,
                query.limit,
                tirith_core::audit::logging_enabled(),
            )?;
            Ok(super::super::history::projection(&history, &patterns))
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
            let mut trust = trust_lifecycle::TrustService::capture_read_only(
                cwd,
                read_snapshot(service),
                &read_patterns(service),
            )?;
            let mut value = trust.explain(
                &query.target,
                match query.scope {
                    GrantScope::User => "user",
                    GrantScope::Project => "project",
                },
            )?;
            value["diagnostics"] = json!(std::mem::take(&mut trust.diagnostics));
            Ok(value)
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
                PlanRequest::AuditRetention { operation_id } => {
                    super::super::setup::audit_service::prepare(&operation_id, cwd)
                }
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
            let mutations = MutationService::current()?;
            let (status, compiled) = if query.action == OperationAction::Status {
                // A status read never resolves the remote policy.
                let compiled = CompiledCustomPatterns::new_silent(&read_patterns(service));
                (mutations.status(&query.operation_id)?, compiled)
            } else {
                let (policy, compiled) = snapshot(service);
                let _admission = admission(service, request)?;
                let status = match query.action {
                    OperationAction::Apply => mutations.apply_async(query.operation_id, policy)?,
                    OperationAction::Undo => mutations.undo_async(query.operation_id, policy)?,
                    OperationAction::Cancel => mutations.cancel(&query.operation_id)?,
                    OperationAction::Status => unreachable!(),
                };
                (status, compiled)
            };
            let mut result = profile::status_projection(&status, &compiled)?;
            if let Some(review) = mutations.impact_review(&status.operation_id)? {
                result["impact_observation"] =
                    serde_json::to_value(review.historical_evidence_status(chrono::Utc::now())?)
                        .map_err(|_| "cannot project historical evidence status")?;
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

fn freshness_projection(service: &Service) -> Result<Value, String> {
    let view = read_view(service);
    let compiled = CompiledCustomPatterns::new_silent(&view.patterns);
    let mut value = serde_json::to_value(super::super::threatdb_cmd::gather_health_with_interval(
        view.refresh_interval_hours,
    ))
    .map_err(|_| "cannot project ThreatDB health")?;
    // The signed blob stays private; the existing health projection is
    // display-only and does not mutate verification material. Only canonical
    // protocol values (status tokens, source IDs, revisions, update phases)
    // stay verbatim; paths, errors and recovery text receive full DLP.
    tirith_core::output_contract::redact_projection(
        &mut value,
        tirith_core::output_contract::Projection::ThreatDbHealth,
        &compiled,
    );
    Ok(value)
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
    fn oversized_policy_control_inventory_preserves_policy_and_diagnostics() {
        let mut value = json!({"policy":{"allowlist":["x".repeat(450 * 1024)]},
            "resolution":{"policy_posture_sha256":"captured"},
            "personal_controls":{"strict_warn":{"effective_value":false,"reason":"y".repeat(80 * 1024)}}});
        let compiled = CompiledCustomPatterns::new_silent(&[]);
        merge_diagnostics(&mut value, vec!["captured diagnostic".into()], &compiled);
        let mut expected = value.clone();
        expected
            .as_object_mut()
            .unwrap()
            .remove("personal_controls");
        bound_policy_control_inventory(&mut value);
        assert_eq!(value["personal_controls_omitted"], true);
        assert!(value.get("personal_controls").is_none());
        assert!(serde_json::to_vec(&value).unwrap().len() <= http::MAX_RESPONSE);
        value
            .as_object_mut()
            .unwrap()
            .remove("personal_controls_omitted");
        assert_eq!(value, expected);

        let mut small =
            json!({"policy":{},"personal_controls":{"strict_warn":{"effective_value":false}}});
        let expected = small.clone();
        bound_policy_control_inventory(&mut small);
        assert_eq!(small, expected);

        let mut too_large =
            json!({"policy":{"allowlist":["x".repeat(http::MAX_RESPONSE)]},"personal_controls":{}});
        bound_policy_control_inventory(&mut too_large);
        assert!(serde_json::to_vec(&too_large).unwrap().len() > http::MAX_RESPONSE);
    }

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
    fn rollout_plan_uses_explicit_authority_scope_without_a_destination_field() {
        let mut value = json!({"kind":"policy_rollout",
            "operation_id":uuid::Uuid::new_v4().to_string(),
            "change":{"profile":"balanced", "scope":"org", "commands":["echo ready"],
                "shell":"posix", "interactive":false}});
        assert!(
            matches!(serde_json::from_value::<PlanRequest>(value.clone()).unwrap(),
            PlanRequest::PolicyRollout { change, .. }
                if change.scope == super::super::super::managed_policy::ProfileScope::Org)
        );
        for scope in ["repo", "remote", "incident"] {
            value["change"]["scope"] = scope.into();
            assert!(serde_json::from_value::<PlanRequest>(value.clone()).is_err());
        }
        value["change"]["scope"] = "org".into();
        value["change"]["path"] = "/unselected/policy.yaml".into();
        assert!(serde_json::from_value::<PlanRequest>(value).is_err());
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
        use tirith_core::output_contract::{redact_projection, Projection};
        let compiled = CompiledCustomPatterns::new_silent(&[".+".into()]);
        let mut value = json!({"status":"error","path":"/private/home/threat.db","error":"private error",
            "supplemental":{"present":true,"path":"/private/supplemental"},"counts":{"total":3},
            "freshness":{"publication_time_basis":"signed_build_timestamp","source_evidence":"unavailable",
                "source_evidence_error":"private evidence","sources":[
                    {"source":"private source","revision":"0123456789abcdef0123456789abcdef01234567",
                     "pin_selected_at":"2026-10-01T00:00:00Z","accepted":4}]},
            "last_update":{"status":"failed","phase":"primary","failure_category":"integrity","incident_key":"primary:integrity","next_action":"private content","consecutive_failures":2}});
        redact_projection(&mut value, Projection::ThreatDbHealth, &compiled);
        assert_eq!(value["status"], "error");
        assert_eq!(value["counts"]["total"], 3);
        assert_eq!(
            value["freshness"]["publication_time_basis"],
            "signed_build_timestamp"
        );
        assert_eq!(value["freshness"]["source_evidence"], "unavailable");
        let source = &value["freshness"]["sources"][0];
        assert_eq!(
            source["revision"],
            "0123456789abcdef0123456789abcdef01234567"
        );
        assert_eq!(source["pin_selected_at"], "2026-10-01T00:00:00Z");
        assert_eq!(source["accepted"], 4);
        let update = &value["last_update"];
        assert_eq!(update["status"], "failed");
        assert_eq!(update["incident_key"], "primary:integrity");
        assert_eq!(update["consecutive_failures"], 2);
        assert!(!value.to_string().contains("private"), "{value}");
        let mut invalid =
            json!({"last_update":{"status":"private content","incident_key":"private:token"}});
        redact_projection(&mut invalid, Projection::ThreatDbHealth, &compiled);
        assert!(!invalid.to_string().contains("private"));
    }
}
