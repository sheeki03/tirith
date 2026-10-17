//! Explicit optional enrollment and durable, exact client-report retries.
//! A saved cache is never projected as Applied. Only full Runtime resolution can
//! prepare an Applied self-report, and its exact request precedes every POST.
use super::setup::{self, fs_helpers::FileUpdate, TransactionOutcome};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::sync::Arc;
use tirith_core::policy::{BoundedRuntimePolicyInputs, PolicyDiagnosticCapture};
use tirith_core::policy_snapshot::{EffectivePolicySnapshot, PrivatePolicyReplayGuard};
use tirith_core::policy_team::{
    self, Capabilities, ClientReportRequest, Id, PrivateCommitment, ReportReceipt, ReportState,
    Role, SCHEMA_VERSION,
};
use tirith_core::policy_team_connection::{
    ConnectionWitness, SelectedConnection, TeamRecord, TeamRecordWitness,
};
use tirith_core::policy_team_enrollment::{
    EnrollmentWriteIntent, FetchedTeamPolicy, TeamEnrollment, TeamRuntimeEvidence,
};

#[derive(clap::Args, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ActivateRequest {
    #[arg(long)]
    pub expected_connection_id: String,
    /// Omit only when local enrollment is absent.
    #[arg(long)]
    pub expected_activation_id: Option<String>,
}
#[derive(clap::Args, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SelectedRequest {
    #[arg(long)]
    pub expected_connection_id: String,
    #[arg(long)]
    pub expected_activation_id: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct DisableRequest {
    pub expected_activation_id: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ReportRequest {
    pub expected_connection_id: String,
    pub expected_activation_id: String,
    /// Exact pending report ID. No implicit retry or freshly incremented replacement.
    pub retry_report_id: Option<String>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RepairRequest {
    pub remove_malformed: bool,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct AbandonRequest {
    pub report_id: String,
    pub acknowledge_unknown_outcome: bool,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ReconcileRequest {
    pub report_id: String,
    pub archive_id: Option<String>,
}
#[derive(clap::Subcommand)]
pub enum Action {
    /// Remove only the currently malformed enrollment, using one retained capture
    Repair {
        #[arg(long)]
        remove_malformed: bool,
        #[arg(long)]
        json: bool,
    },
    /// Archive an exact unresolved request locally; its server outcome stays unknown
    Abandon {
        #[arg(long)]
        report_id: String,
        #[arg(long)]
        acknowledge_unknown_outcome: bool,
        #[arg(long)]
        json: bool,
    },
    /// Read-only exact server reconciliation; never resubmits an Applied request
    Reconcile {
        #[arg(long)]
        report_id: String,
        #[arg(long)]
        archive_id: Option<String>,
        #[arg(long)]
        json: bool,
    },
    /// Inspect local cache and pending report without contacting the authority
    Status {
        #[arg(long)]
        json: bool,
    },
    /// Explicitly enable Runtime from a freshly authenticated Client policy fetch
    Activate {
        #[command(flatten)]
        options: ActivateRequest,
        #[arg(long)]
        json: bool,
    },
    /// Refresh the exact activation without changing its selected connection
    Sync {
        #[command(flatten)]
        options: SelectedRequest,
        #[arg(long)]
        json: bool,
    },
    /// Withdraw the exact activation offline, even when its cache is stale
    Disable {
        #[arg(long)]
        expected_activation_id: String,
        #[arg(long)]
        json: bool,
    },
    /// Report actual resolved Runtime; --retry-report-id resends exact pending bytes
    Report {
        #[command(flatten)]
        options: SelectedRequest,
        #[arg(long)]
        retry_report_id: Option<String>,
        #[arg(long)]
        json: bool,
    },
}
const NOTICE: &str = "Team policy is optional and off until explicit activation. A cached policy is an offline input, not proof of the server's current revision or a fleet Applied report. Activation and sync do not send reports.";
const REPORT_NOTICE: &str = "Reports are authenticated client self-reports after full local Runtime resolution, not independent enforcement attestation. Retry preserves the exact request. Explicit local abandonment archives its unknown server outcome; it does not cancel a request or prove no commit.";
fn error(error: impl std::fmt::Display) -> String {
    error.to_string()
}
fn id(value: &str) -> Result<Id, String> {
    Id::parse(value).map_err(|_| "a canonical nonzero UUID is required".into())
}
fn now_ms() -> Result<u64, String> {
    chrono::Utc::now()
        .timestamp_millis()
        .try_into()
        .map_err(|_| "local clock is unavailable".into())
}
fn network_allowed() -> Result<(), String> {
    if super::offline_env_active() {
        Err("team authority contact is disabled by offline mode".into())
    } else {
        Ok(())
    }
}
fn selected(expected: &Id) -> Result<Arc<ConnectionWitness>, String> {
    let selection = Arc::new(SelectedConnection::capture_current().map_err(error)?);
    if selection.connection_id() != Some(expected) {
        return Err("selected connection changed; inspect local status".into());
    }
    selection.revalidate().map_err(error)?;
    Ok(selection)
}
fn storage(outcome: TransactionOutcome) -> &'static str {
    match outcome {
        TransactionOutcome::Written => "written",
        TransactionOutcome::WrittenWithRecovery => "written_with_recovery_durability_unconfirmed",
        TransactionOutcome::Unchanged => "unchanged",
        TransactionOutcome::DryRunWouldWrite => "not_written",
    }
}
fn report_post_allowed(outcome: TransactionOutcome) -> bool {
    outcome == TransactionOutcome::Written
}
fn write_enrollment(
    intent: &EnrollmentWriteIntent,
    preview: &EffectivePolicySnapshot,
) -> Result<TransactionOutcome, String> {
    let bytes = intent
        .replacement()
        .ok_or("enrollment write requires a replacement")?
        .as_bytes();
    let text = std::str::from_utf8(bytes)
        .map_err(|_| "private enrollment encoding is invalid")?
        .to_owned();
    setup::update_private_team_record(
        &TeamRecord::Enrollment,
        |snapshot| {
            if !intent.previous().matches_private_bytes(snapshot.bytes()) {
                return Err("enrollment changed before save".into());
            }
            Ok(FileUpdate::write_text(text.clone(), 0o600)
                .with_exact_mode()
                .with_backup(false))
        },
        || {
            intent.revalidate().map_err(error)?;
            preview
                .revalidate_captured()
                .map_err(|_| "team preview inputs changed before save".into())
        },
    )
    .map_err(|_| "enrollment save was not confirmed; inspect local status before retrying".into())
}
fn expected_activation(
    current: Option<&Id>,
    configured: bool,
    expected: Option<&Id>,
) -> Result<(), String> {
    if (configured && current.is_none()) || current != expected {
        return Err(
            "enrollment changed or is malformed; inspect local status before an explicit action"
                .into(),
        );
    }
    Ok(())
}

pub(crate) struct TeamEnrollmentService {
    cwd: String,
}
impl TeamEnrollmentService {
    pub(crate) fn capture(cwd: Option<&str>) -> Result<Self, String> {
        let cwd = cwd
            .map(std::path::PathBuf::from)
            .map(Ok)
            .unwrap_or_else(std::env::current_dir)
            .map_err(|_| "working directory unavailable")?
            .canonicalize()
            .map_err(|_| "working directory unavailable")?;
        let cwd = cwd
            .to_str()
            .ok_or("working directory is not UTF-8")?
            .to_owned();
        if cwd.len() > 8192 {
            return Err("working directory exceeds its fixed bound".into());
        }
        Ok(Self { cwd })
    }
    pub(crate) fn current(&self) -> Result<Value, String> {
        let _diagnostics = PolicyDiagnosticCapture::start_silent();
        let _bounded = BoundedRuntimePolicyInputs::enter();
        let selection_id = SelectedConnection::capture_current()
            .ok()
            .and_then(|c| c.connection_id().cloned());
        let (state, activation, evidence) = match TeamEnrollment::capture_current() {
            Err(_) => ("storage_unavailable", None, None),
            Ok(witness) if !witness.configured() => ("off", None, None),
            Ok(witness) => {
                let activation = witness.activation_id().cloned();
                if activation.is_none() {
                    ("malformed", activation, None)
                } else {
                    let snapshot =
                        EffectivePolicySnapshot::resolve_runtime_without_network(Some(&self.cwd));
                    let evidence = if witness.revalidate().is_ok() {
                        snapshot.team_runtime_evidence().ok().flatten()
                    } else {
                        None
                    };
                    (
                        if evidence.is_some() {
                            "ready_offline_cache"
                        } else {
                            "runtime_refused"
                        },
                        activation,
                        evidence,
                    )
                }
            }
        };
        Ok(
            json!({"schema_version":1,"state":state,"activation_id":activation,
            "selected_connection_id":selection_id,"runtime_evidence":evidence,
            "report":report_status(),"local_write":"observed","execution_permitted":false,"notice":NOTICE}),
        )
    }
    pub(crate) fn activate(&self, request: ActivateRequest) -> Result<Value, String> {
        let connection_id = id(&request.expected_connection_id)?;
        let activation = request
            .expected_activation_id
            .as_deref()
            .map(id)
            .transpose()?;
        let enrollment = Arc::new(TeamEnrollment::capture_current().map_err(error)?);
        expected_activation(
            enrollment.activation_id(),
            enrollment.configured(),
            activation.as_ref(),
        )?;
        let connection = selected(&connection_id)?;
        network_allowed()?;
        let fetched = FetchedTeamPolicy::fetch(connection).map_err(error)?;
        let _diagnostics = PolicyDiagnosticCapture::start_silent();
        let _bounded = BoundedRuntimePolicyInputs::enter();
        let preview =
            EffectivePolicySnapshot::resolve_team_preview(Some(&self.cwd), fetched.document())
                .map_err(|_| "team policy preview refused the document or a competing authority")?;
        preview
            .revalidate_captured()
            .map_err(|_| "team preview inputs changed")?;
        let intent = enrollment
            .prepare_activation(activation.as_ref(), fetched)
            .map_err(error)?;
        let outcome = write_enrollment(&intent, &preview)?;
        let confirmed = TeamEnrollment::capture_current().ok().is_some_and(|saved| {
            saved.matches_private_bytes(intent.replacement().map(|b| b.as_bytes()))
                && saved.revalidate().is_ok()
        });
        let mut view = self.current()?;
        view["local_write"] = json!(storage(outcome));
        view["saved_bytes_confirmed"] = json!(confirmed);
        view["operation"] = json!("activate");
        Ok(view)
    }
    pub(crate) fn sync(&self, request: SelectedRequest) -> Result<Value, String> {
        let connection_id = id(&request.expected_connection_id)?;
        let activation = id(&request.expected_activation_id)?;
        let enrollment = Arc::new(TeamEnrollment::capture_current().map_err(error)?);
        expected_activation(
            enrollment.activation_id(),
            enrollment.configured(),
            Some(&activation),
        )?;
        let connection = selected(&connection_id)?;
        network_allowed()?;
        let fetched = FetchedTeamPolicy::fetch(connection).map_err(error)?;
        let _diagnostics = PolicyDiagnosticCapture::start_silent();
        let _bounded = BoundedRuntimePolicyInputs::enter();
        let preview =
            EffectivePolicySnapshot::resolve_team_preview(Some(&self.cwd), fetched.document())
                .map_err(|_| "team policy preview refused the document or a competing authority")?;
        preview
            .revalidate_captured()
            .map_err(|_| "team preview inputs changed")?;
        let intent = enrollment
            .prepare_sync(&activation, fetched)
            .map_err(error)?;
        let outcome = write_enrollment(&intent, &preview)?;
        let confirmed = TeamEnrollment::capture_current().ok().is_some_and(|saved| {
            saved.matches_private_bytes(intent.replacement().map(|b| b.as_bytes()))
                && saved.revalidate().is_ok()
        });
        let mut view = self.current()?;
        view["local_write"] = json!(storage(outcome));
        view["saved_bytes_confirmed"] = json!(confirmed);
        view["operation"] = json!("sync");
        Ok(view)
    }
    /// No current directory, valid policy, selected connection or network needed.
    pub(crate) fn disable(request: DisableRequest) -> Result<Value, String> {
        let activation = id(&request.expected_activation_id)?;
        let enrollment = Arc::new(TeamEnrollment::capture_current().map_err(error)?);
        let intent = enrollment.prepare_disable(&activation).map_err(error)?;
        let removed = setup::delete_private_team_record(
            &TeamRecord::Enrollment,
            |bytes| intent.previous().matches_private_bytes(bytes),
            || intent.revalidate().map_err(error),
        )
        .is_ok();
        drop(intent);
        drop(enrollment); // Windows delete-pending must release every read witness.
        let absent = TeamEnrollment::capture_current()
            .ok()
            .is_some_and(|w| !w.configured() && w.revalidate().is_ok());
        Ok(
            json!({"schema_version":1,"operation":"disable","state":if absent {"off"} else {"withdrawal_unconfirmed"},
            "local_write":if !removed {"withdrawal_unconfirmed"} else if cfg!(windows) {"removed_observed_namespace_durability_unconfirmed"} else {"removed"},
            "absence_confirmed":absent,"execution_permitted":false,"notice":"Enrollment withdrawal does not remove the selected connection or pending report. A future activation requires a new explicit Client fetch."}),
        )
    }
    pub(crate) fn repair(request: RepairRequest) -> Result<Value, String> {
        if !request.remove_malformed {
            return Err("explicit --remove-malformed acknowledgement is required".into());
        }
        let enrollment = Arc::new(TeamEnrollment::capture_current().map_err(error)?);
        // One invocation, one exact private generation. The random capture ID
        // is never exposed as a reusable token across status/action requests.
        let intent = enrollment
            .prepare_malformed_removal(enrollment.capture_id())
            .map_err(error)?;
        let removed = setup::delete_private_team_record(
            &TeamRecord::Enrollment,
            |bytes| intent.previous().matches_private_bytes(bytes),
            || intent.revalidate().map_err(error),
        )
        .is_ok();
        drop(intent);
        drop(enrollment);
        let absent = TeamEnrollment::capture_current()
            .ok()
            .is_some_and(|w| !w.configured() && w.revalidate().is_ok());
        Ok(
            json!({"schema_version":1,"operation":"repair","state":if absent {"off"} else {"withdrawal_unconfirmed"},
            "local_write":if !removed {"withdrawal_unconfirmed"} else if cfg!(windows) {"removed_observed_namespace_durability_unconfirmed"} else {"removed"},
            "absence_confirmed":absent,"execution_permitted":false,"notice":"Only the malformed private enrollment captured by this explicit action was selected for removal. No fields were reinterpreted; connection and report records are unchanged."}),
        )
    }
    pub(crate) fn abandon(request: AbandonRequest) -> Result<Value, String> {
        if !request.acknowledge_unknown_outcome {
            return Err(
                "explicit acknowledgement of the unknown server outcome is required".into(),
            );
        }
        let expected = id(&request.report_id)?;
        let (prior, record) = load_report()?;
        let mut record = record.ok_or("no pending report is stored")?;
        if record.request.report_id != expected || record.receipt.is_some() {
            return Err("exact unresolved report ID required for abandonment".into());
        }
        if record.phase == ReportPhase::ArchivedUnknown {
            return Ok(report_result(
                &record,
                "already_archived_outcome_unknown",
                "observed",
                None,
            ));
        }
        if record.archived.len() >= MAX_ARCHIVED_REPORTS {
            return Err("bounded report archive is full; no history was removed".into());
        }
        record.phase = ReportPhase::ArchivedUnknown;
        record.archive_id = Some(Id::new());
        let outcome = save_report(&record, &prior, || prior.revalidate().map_err(error))?;
        Ok(report_result(
            &record,
            "archived_outcome_unknown",
            storage(outcome),
            None,
        ))
    }
    pub(crate) fn reconcile(request: ReconcileRequest) -> Result<Value, String> {
        let report_id = id(&request.report_id)?;
        let archive_id = request.archive_id.as_deref().map(id).transpose()?;
        let (prior, stored) = load_report()?;
        let mut stored = stored.ok_or("no report is stored")?;
        let target = reconciliation_target(&stored, &report_id, archive_id.as_ref())?;
        let record = match target {
            None => &stored,
            Some(index) => &stored.archived[index],
        };
        let connection = selected(&record.binding.connection_id)?;
        if record.selection != connection.private_selection_commitment().map_err(error)? {
            return Err("selected native connection differs from historical report; no authority was contacted".into());
        }
        network_allowed()?;
        let (client, caps) = connection.authenticate().map_err(error)?;
        authenticated(&connection, &caps, &record.binding)?;
        prior.revalidate().map_err(error)?;
        if record.selection != connection.private_selection_commitment().map_err(error)? {
            return Err("historical report selection changed".into());
        }
        // Read-only endpoint compares the exact authenticated principal and
        // complete retained intent. No current Runtime or Applied POST here.
        let receipt = match client.reconcile_report(&record.request) {
            Ok(receipt) => receipt,
            Err(code) => {
                return Ok(report_result(
                    &stored,
                    "reconciliation_unconfirmed",
                    "observed",
                    Some(code),
                ))
            }
        };
        match target {
            None => stored.receipt = Some(receipt),
            Some(index) => stored.archived[index].receipt = Some(receipt),
        };
        stored.validate()?;
        let outcome = save_report(&stored, &prior, || prior.revalidate().map_err(error));
        match outcome {
            Ok(outcome) => Ok(report_result(
                &stored,
                "historical_receipt_confirmed",
                storage(outcome),
                None,
            )),
            Err(_) => Ok(report_result(
                &stored,
                "historical_receipt_storage_unconfirmed",
                "unconfirmed",
                None,
            )),
        }
    }
    pub(crate) fn report(&self, request: ReportRequest) -> Result<Value, String> {
        let connection_id = id(&request.expected_connection_id)?;
        let activation = id(&request.expected_activation_id)?;
        let retry = request.retry_report_id.as_deref().map(id).transpose()?;
        let enrollment = TeamEnrollment::capture_current().map_err(error)?;
        expected_activation(
            enrollment.activation_id(),
            enrollment.configured(),
            Some(&activation),
        )?;
        let (prior, stored) = load_report()?;
        // Refuse implicit replacement of any unresolved request before network.
        if retry.is_none()
            && stored
                .as_ref()
                .is_some_and(|r| r.receipt.is_none() && r.phase == ReportPhase::Active)
        {
            return Err(
                "an exact report is pending; inspect status and use --retry-report-id".into(),
            );
        }
        if let Some(retry) = &retry {
            if stored
                .as_ref()
                .is_some_and(|r| r.phase != ReportPhase::Active)
            {
                return Err("the request was archived locally and cannot be retried; use read-only reconciliation".into());
            }
            if stored.as_ref().map(|r| &r.request.report_id) != Some(retry) {
                return Err("pending report ID does not match the exact stored request".into());
            }
        }
        let connection = selected(&connection_id)?;
        let _diagnostics = PolicyDiagnosticCapture::start_silent();
        let _bounded = BoundedRuntimePolicyInputs::enter();
        let snapshot = EffectivePolicySnapshot::resolve_runtime_without_network(Some(&self.cwd));
        enrollment
            .revalidate()
            .map_err(|_| "enrollment changed before Runtime report resolution")?;
        let evidence = snapshot
            .team_runtime_evidence()
            .map_err(|_| "Runtime is invalid, stale or changed; no Applied report was prepared")?
            .ok_or("Runtime is not enrolled; no Applied report was prepared")?;
        let binding = RuntimeBinding::from(&evidence);
        if binding.activation_id != activation || binding.connection_id != connection_id {
            return Err(
                "actual Runtime does not match the explicitly selected activation and connection"
                    .into(),
            );
        }
        network_allowed()?;
        let (client, capabilities) = connection.authenticate().map_err(error)?;
        authenticated(&connection, &capabilities, &binding)?;
        let mut record = if let Some(retry) = retry {
            let record = stored.ok_or("pending report is unavailable")?;
            record.validate()?;
            if record.request.report_id != retry {
                return Err("pending report changed".into());
            }
            validate_report_context(&record, &self.cwd, &snapshot, &connection, &capabilities)?;
            if record.receipt.is_some() {
                return Ok(report_result(
                    &record,
                    "already_acknowledged",
                    "observed",
                    None,
                ));
            }
            record
        } else {
            if stored
                .as_ref()
                .filter(|r| {
                    r.binding.client_id == binding.client_id
                        && r.binding.authority_id == binding.authority_id
                })
                .and_then(|r| r.receipt.as_ref())
                .is_some_and(|receipt| {
                    capabilities
                        .client_report_sequence
                        .is_none_or(|sequence| sequence < receipt.report_sequence)
                })
            {
                return Err(
                    "authenticated report position moved backwards; no replacement prepared".into(),
                );
            }
            let sequence = capabilities
                .client_report_sequence
                .ok_or("Client report sequence is unavailable")?
                .checked_add(1)
                .filter(|sequence| *sequence <= i64::MAX as u64)
                .ok_or("Client report sequence is exhausted")?;
            let archived = carry_archives(stored.as_ref())?;
            ReportRecord {
                phase: ReportPhase::Active,
                archive_id: None,
                archived,
                schema_version: SCHEMA_VERSION,
                cwd: self.cwd.clone(),
                binding,
                selection: connection.private_selection_commitment().map_err(error)?,
                runtime_guard: snapshot.private_replay_guard(),
                request: ClientReportRequest {
                    schema_version: SCHEMA_VERSION,
                    report_id: policy_team::report_id(
                        evidence.authority_id(),
                        evidence.client_id(),
                        sequence,
                    )
                    .map_err(error)?,
                    authority_id: evidence.authority_id().clone(),
                    policy_id: evidence.policy_id().clone(),
                    report_sequence: sequence,
                    applied_revision: evidence.revision().clone(),
                    observed_unix_ms: now_ms()?,
                    client_version: env!("CARGO_PKG_VERSION").into(),
                    state: ReportState::Applied,
                    failure_reason: None,
                },
                receipt: None,
            }
        };
        record.validate()?;
        enrollment.revalidate().map_err(error)?;
        validate_report_context(&record, &self.cwd, &snapshot, &connection, &capabilities)?;
        // Even retry republishes the same bytes and requires a clean durable result.
        // An observed old file or Unchanged outcome cannot promote an earlier
        // Windows namespace-durability-unknown publication to permission for POST.
        let outcome = save_report(&record, &prior, || {
            prior.revalidate().map_err(error)?;
            enrollment.revalidate().map_err(error)?;
            validate_report_context(&record, &self.cwd, &snapshot, &connection, &capabilities)
        })?;
        if !report_post_allowed(outcome) {
            return Ok(report_result(
                &record,
                "pending_not_sent",
                storage(outcome),
                None,
            ));
        }
        drop(prior);
        let (pending, saved) = load_report()?;
        let saved = saved.ok_or("pending report disappeared before submission")?;
        if encoded(&saved)? != encoded(&record)? {
            return Err("pending report changed before submission; no request sent".into());
        }
        pending.revalidate().map_err(error)?;
        enrollment.revalidate().map_err(error)?;
        validate_report_context(&record, &self.cwd, &snapshot, &connection, &capabilities)?;
        let receipt = match client.report(&record.request) {
            Ok(receipt) => receipt,
            Err(code) => {
                return Ok(report_result(
                    &record,
                    "pending_outcome_unknown",
                    storage(outcome),
                    Some(code),
                ))
            }
        };
        record.receipt = Some(receipt);
        record.validate()?;
        // Receipt records an exact authenticated response, not current enforcement.
        // Keep the original request if local receipt persistence loses its CAS.
        let receipt_outcome =
            save_report(&record, &pending, || pending.revalidate().map_err(error));
        match receipt_outcome {
            Ok(local) => Ok(report_result(&record, "acknowledged", storage(local), None)),
            Err(_) => Ok(report_result(
                &record,
                "acknowledged_receipt_storage_unconfirmed",
                "unconfirmed",
                None,
            )),
        }
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RuntimeBinding {
    connection_id: Id,
    authority_id: Id,
    policy_id: Id,
    activation_id: Id,
    client_id: Id,
    revision: Id,
    fetched_unix_ms: u64,
}
impl From<&TeamRuntimeEvidence> for RuntimeBinding {
    fn from(e: &TeamRuntimeEvidence) -> Self {
        Self {
            connection_id: e.connection_id().clone(),
            authority_id: e.authority_id().clone(),
            policy_id: e.policy_id().clone(),
            activation_id: e.activation_id().clone(),
            client_id: e.client_id().clone(),
            revision: e.revision().clone(),
            fetched_unix_ms: e.fetched_unix_ms(),
        }
    }
}
const MAX_ARCHIVED_REPORTS: usize = 4;
#[derive(Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum ReportPhase {
    #[default]
    Active,
    ArchivedUnknown,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ReportRecord {
    #[serde(default)]
    phase: ReportPhase,
    #[serde(default)]
    archive_id: Option<Id>,
    #[serde(default)]
    archived: Vec<ReportRecord>,
    schema_version: u32,
    cwd: String,
    binding: RuntimeBinding,
    selection: PrivateCommitment,
    runtime_guard: PrivatePolicyReplayGuard,
    request: ClientReportRequest,
    receipt: Option<ReportReceipt>,
}
impl ReportRecord {
    fn validate(&self) -> Result<(), String> {
        self.validate_entry()?;
        if self.archived.len() > MAX_ARCHIVED_REPORTS
            || (self.phase == ReportPhase::ArchivedUnknown
                && self.archived.len() >= MAX_ARCHIVED_REPORTS)
        {
            return Err(
                "bounded report archive is full or invalid; its bytes were preserved".into(),
            );
        }
        let mut ids = std::collections::BTreeSet::new();
        if let Some(id) = &self.archive_id {
            ids.insert(id.as_str());
        }
        for archived in &self.archived {
            if !archived.archived.is_empty()
                || archived.phase != ReportPhase::ArchivedUnknown
                || !ids.insert(
                    archived
                        .archive_id
                        .as_ref()
                        .ok_or("archive identity unavailable")?
                        .as_str(),
                )
            {
                return Err("private report archive structure is invalid".into());
            }
            archived.validate_entry()?;
        }
        Ok(())
    }
    fn validate_entry(&self) -> Result<(), String> {
        if (self.phase == ReportPhase::Active) != self.archive_id.is_none() {
            return Err("private report archive identity is invalid".into());
        }
        if self.schema_version != SCHEMA_VERSION
            || self.cwd.is_empty()
            || self.cwd.len() > 8192
            || !std::path::Path::new(&self.cwd).is_absolute()
            || self.binding.fetched_unix_ms == 0
            || self.binding.fetched_unix_ms > self.request.observed_unix_ms
            || self.request.state != ReportState::Applied
            || self.request.failure_reason.is_some()
            || self.request.authority_id != self.binding.authority_id
            || self.request.policy_id != self.binding.policy_id
            || self.request.applied_revision != self.binding.revision
            || self.request.report_id
                != policy_team::report_id(
                    &self.binding.authority_id,
                    &self.binding.client_id,
                    self.request.report_sequence,
                )
                .map_err(error)?
        {
            return Err("private pending report is invalid; it was preserved".into());
        }
        self.request
            .validate_structure()
            .map_err(|_| "private pending report structure is invalid")?;
        if let Some(receipt) = &self.receipt {
            if receipt.schema_version != SCHEMA_VERSION
                || receipt.authority_id != self.binding.authority_id
                || receipt.policy_id != self.binding.policy_id
                || receipt.client_id != self.binding.client_id
                || receipt.report_id != self.request.report_id
                || receipt.report_sequence != self.request.report_sequence
                || receipt.received_unix_ms == 0
            {
                return Err("private report receipt is invalid; it was preserved".into());
            }
        }
        Ok(())
    }
}
fn carry_archives(previous: Option<&ReportRecord>) -> Result<Vec<ReportRecord>, String> {
    let Some(previous) = previous else {
        return Ok(Vec::new());
    };
    previous.validate()?;
    let mut archived = previous.archived.clone();
    if previous.phase == ReportPhase::ArchivedUnknown {
        if archived.len() >= MAX_ARCHIVED_REPORTS {
            return Err("bounded report archive is full; no history was removed".into());
        }
        let mut entry = previous.clone();
        entry.archived.clear();
        archived.push(entry);
    }
    Ok(archived)
}
fn reconciliation_target(
    stored: &ReportRecord,
    report_id: &Id,
    archive_id: Option<&Id>,
) -> Result<Option<usize>, String> {
    let Some(archive_id) = archive_id else {
        return if &stored.request.report_id == report_id {
            Ok(None)
        } else {
            Err(
                "the current report ID differs; historical reconciliation requires its archive ID"
                    .into(),
            )
        };
    };
    if &stored.request.report_id == report_id && stored.archive_id.as_ref() == Some(archive_id) {
        return Ok(None);
    }
    stored
        .archived
        .iter()
        .position(|r| {
            &r.request.report_id == report_id && r.archive_id.as_ref() == Some(archive_id)
        })
        .map(Some)
        .ok_or("exact report and archive identities were not found".into())
}

fn authenticated(
    connection: &ConnectionWitness,
    caps: &Capabilities,
    evidence: &RuntimeBinding,
) -> Result<(), String> {
    connection.revalidate().map_err(error)?;
    caps.validate(now_ms()?)
        .map_err(|_| "Client authentication expired or is invalid")?;
    if caps.role != Role::Client
        || caps.client_id.as_ref() != Some(&evidence.client_id)
        || caps.authority_id != evidence.authority_id
        || caps.policy_id != evidence.policy_id
        || connection.connection_id() != Some(&evidence.connection_id)
    {
        return Err("authenticated Client identity does not match actual Runtime".into());
    }
    Ok(())
}
fn validate_report_context(
    record: &ReportRecord,
    cwd: &str,
    snapshot: &EffectivePolicySnapshot,
    connection: &ConnectionWitness,
    caps: &Capabilities,
) -> Result<(), String> {
    record.validate()?;
    if record.phase != ReportPhase::Active {
        return Err("archived report cannot authorize an Applied submission".into());
    }
    let evidence = snapshot
        .team_runtime_evidence()
        .map_err(|_| "Runtime is invalid, stale or changed; pending report was preserved")?
        .ok_or("Runtime is not enrolled")?;
    if record.cwd != cwd
        || record.binding != RuntimeBinding::from(&evidence)
        || record.runtime_guard != snapshot.private_replay_guard()
        || record.selection != connection.private_selection_commitment().map_err(error)?
    {
        return Err("pending report does not match the exact current Runtime and connection; it was preserved".into());
    }
    authenticated(connection, caps, &record.binding)
}
fn encoded(record: &ReportRecord) -> Result<Vec<u8>, String> {
    record.validate()?;
    let bytes = serde_json::to_vec(record).map_err(|_| "cannot encode private report")?;
    if bytes.len() > TeamRecord::Report.cap() {
        return Err("private report exceeds its fixed bound".into());
    }
    Ok(bytes)
}
fn decode_report(bytes: &[u8]) -> Result<ReportRecord, String> {
    if bytes.len() > TeamRecord::Report.cap() {
        return Err("private report exceeds its fixed bound".into());
    }
    let record: ReportRecord = serde_json::from_slice(bytes)
        .map_err(|_| "private pending report is malformed; it was preserved")?;
    record.validate()?;
    Ok(record)
}
fn load_report() -> Result<(TeamRecordWitness, Option<ReportRecord>), String> {
    let witness = TeamRecord::Report
        .capture_current()
        .map_err(|_| "private report storage is unavailable")?;
    let record = witness.private_bytes().map(decode_report).transpose()?;
    witness.revalidate().map_err(|_| "private report changed")?;
    Ok((witness, record))
}
fn save_report(
    record: &ReportRecord,
    prior: &TeamRecordWitness,
    mut validate: impl FnMut() -> Result<(), String>,
) -> Result<TransactionOutcome, String> {
    let text = String::from_utf8(encoded(record)?).map_err(|_| "cannot encode private report")?;
    setup::update_private_team_record(
        &TeamRecord::Report,
        |snapshot| {
            prior.revalidate().map_err(error)?;
            if !prior.matches_private_bytes(snapshot.bytes()) {
                return Err("private report changed before publication".into());
            }
            Ok(FileUpdate::write_text(text.clone(), 0o600)
                .with_exact_mode()
                .with_backup(false))
        },
        || {
            prior.revalidate().map_err(error)?;
            validate()
        },
    )
    .map_err(|_| {
        "private report persistence was not confirmed; no new request should be inferred".into()
    })
}
fn report_projection(record: &ReportRecord) -> Value {
    let mut projection = report_entry_projection(record);
    projection["archived_reports"] = json!(record
        .archived
        .iter()
        .map(report_entry_projection)
        .collect::<Vec<_>>());
    projection
}
fn report_entry_projection(record: &ReportRecord) -> Value {
    json!({"state":match(record.phase,record.receipt.is_some()){(ReportPhase::Active,false)=>"pending",(ReportPhase::Active,true)=>"acknowledged",(ReportPhase::ArchivedUnknown,false)=>"archived_unknown",(ReportPhase::ArchivedUnknown,true)=>"archived_acknowledged"},"archive_id":record.archive_id,"report_id":record.request.report_id,
        "activation_id":record.binding.activation_id,"connection_id":record.binding.connection_id,"client_id":record.binding.client_id,
        "report_sequence":record.request.report_sequence,"revision":record.request.applied_revision,
        "observed_unix_ms":record.request.observed_unix_ms,"receipt":record.receipt})
}
fn report_status() -> Value {
    match load_report() {
        Ok((_, Some(record))) => report_projection(&record),
        Ok((_, None)) => json!({"state":"none"}),
        Err(_) => {
            json!({"state":"unavailable","notice":"Private pending report could not be safely interpreted; its bytes were preserved."})
        }
    }
}
fn report_result(
    record: &ReportRecord,
    outcome: &str,
    local: &str,
    failure: Option<policy_team::ErrorCode>,
) -> Value {
    json!({"schema_version":1,"operation":"report","outcome":outcome,"report":report_projection(record),
        "local_write":local,"failure_code":failure,"execution_permitted":false,"notice":REPORT_NOTICE})
}

pub(crate) fn run(action: Action) -> i32 {
    let json_output = match &action {
        Action::Repair { json, .. }
        | Action::Abandon { json, .. }
        | Action::Reconcile { json, .. }
        | Action::Status { json }
        | Action::Activate { json, .. }
        | Action::Sync { json, .. }
        | Action::Disable { json, .. }
        | Action::Report { json, .. } => *json,
    };
    let result = (|| match action {
        Action::Repair {
            remove_malformed, ..
        } => TeamEnrollmentService::repair(RepairRequest { remove_malformed }),
        Action::Abandon {
            report_id,
            acknowledge_unknown_outcome,
            ..
        } => TeamEnrollmentService::abandon(AbandonRequest {
            report_id,
            acknowledge_unknown_outcome,
        }),
        Action::Reconcile {
            report_id,
            archive_id,
            ..
        } => TeamEnrollmentService::reconcile(ReconcileRequest {
            report_id,
            archive_id,
        }),
        Action::Disable {
            expected_activation_id,
            ..
        } => TeamEnrollmentService::disable(DisableRequest {
            expected_activation_id,
        }),
        other => {
            let service = TeamEnrollmentService::capture(None)?;
            match other {
                Action::Status { .. } => service.current(),
                Action::Activate { options, .. } => service.activate(options),
                Action::Sync { options, .. } => service.sync(options),
                Action::Report {
                    options,
                    retry_report_id,
                    ..
                } => service.report(ReportRequest {
                    expected_connection_id: options.expected_connection_id,
                    expected_activation_id: options.expected_activation_id,
                    retry_report_id,
                }),
                Action::Disable { .. }
                | Action::Repair { .. }
                | Action::Abandon { .. }
                | Action::Reconcile { .. } => unreachable!(),
            }
        }
    })();
    match result {
        Ok(value) => {
            let failed = value.get("failure_code").is_some_and(|v| !v.is_null())
                || value
                    .get("outcome")
                    .and_then(Value::as_str)
                    .is_some_and(|s| {
                        (s.contains("unknown") && !s.contains("archived"))
                            || s.contains("unconfirmed")
                            || s == "pending_not_sent"
                    })
                || value
                    .get("local_write")
                    .and_then(Value::as_str)
                    .is_some_and(|s| s.contains("unconfirmed"))
                || value.get("saved_bytes_confirmed") == Some(&Value::Bool(false))
                || value.get("absence_confirmed") == Some(&Value::Bool(false));
            let emitted = if json_output {
                super::write_json_stdout(&value, "cannot write team enrollment result")
            } else {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&value)
                        .unwrap_or_else(|_| "Team enrollment result unavailable".into())
                );
                true
            };
            if emitted && !failed {
                0
            } else {
                1
            }
        }
        Err(message) => {
            if json_output {
                super::write_json_stdout(
                    &json!({"schema_version":1,"error":message,"execution_permitted":false}),
                    "cannot write team enrollment error",
                );
            } else {
                eprintln!("tirith policy team enrollment: {message}");
            }
            1
        }
    }
}

#[cfg(test)]
#[path = "team_enrollment_tests.rs"]
mod tests;
