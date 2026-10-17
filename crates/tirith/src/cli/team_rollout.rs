//! Reviewed publication to an explicitly selected team authority. Private local
//! history is a precondition record; only the authenticated server commits CAS.
use super::setup::{self, fs_helpers::FileUpdate};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::path::Path;
use tirith_core::evaluation::{FrozenEvaluation, SessionEvidence};
use tirith_core::policy::{BoundedRuntimePolicyInputs, PolicyDiagnosticCapture};
use tirith_core::policy_rollout::{
    self, CandidateCoverage, Exception, ExceptionOwner, ImpactReport, RecordId, RolloutScope,
    Workflow,
};
use tirith_core::policy_snapshot::{EffectivePolicySnapshot, PrivatePolicyReplayGuard};
use tirith_core::policy_team::*;
use tirith_core::policy_team_connection::{
    ConnectionWitness, SelectedConnection, TeamRecord, TeamRecordWitness,
};
use tirith_core::tokenize::ShellType;

#[derive(clap::Subcommand)]
pub enum Action {
    /// Capture policy impact against the current authenticated server revision
    Prepare {
        #[arg(long)]
        policy_file: std::path::PathBuf,
        #[arg(long = "command", required = true)]
        commands: Vec<String>,
        #[arg(long, default_value = "posix")]
        shell: ShellType,
        #[arg(long)]
        interactive: bool,
        #[arg(long)]
        id: Option<String>,
        #[arg(long)]
        json: bool,
    },
    /// Inspect an exact stored review; --refresh contacts the selected server
    Show {
        id: String,
        #[arg(long)]
        refresh: bool,
        #[arg(long)]
        json: bool,
    },
    /// Explicitly publish the exact reviewed candidate using server CAS
    Publish {
        id: String,
        #[arg(long)]
        reviewed: String,
        #[arg(long)]
        json: bool,
    },
    /// Prepare a fresh impact review for an eligible original publication rollback
    RollbackPlan {
        publication: String,
        #[arg(long)]
        id: Option<String>,
        #[arg(long)]
        json: bool,
    },
    /// Explicitly apply an exact reviewed rollback using server CAS
    Rollback {
        id: String,
        #[arg(long)]
        reviewed: String,
        #[arg(long)]
        json: bool,
    },
    /// Fetch current authenticated client reports, including stale and missing clients
    Fleet {
        #[arg(long)]
        json: bool,
    },
}

pub fn run(action: Action) -> i32 {
    let json_output = match &action {
        Action::Prepare { json, .. }
        | Action::Show { json, .. }
        | Action::Publish { json, .. }
        | Action::RollbackPlan { json, .. }
        | Action::Rollback { json, .. }
        | Action::Fleet { json } => *json,
    };
    let result = (|| {
        let service = TeamRolloutService::capture(None)?;
        match action {
            Action::Prepare {
                policy_file,
                commands,
                shell,
                interactive,
                id,
                ..
            } => {
                let yaml = tirith_core::util::read_text_no_follow_capped(
                    &policy_file,
                    MAX_POLICY_BYTES as u64,
                )
                .map_err(|_| "policy input is not a bounded ordinary no-follow UTF-8 file")?;
                let yaml = String::from_utf8(yaml).map_err(|_| "policy input is not UTF-8")?;
                service.prepare(
                    id.as_deref().unwrap_or(Id::new().as_str()),
                    ReviewInput {
                        yaml,
                        commands,
                        shell,
                        interactive,
                    },
                )
            }
            Action::Show { id, refresh, .. } => service.show(&id, refresh),
            Action::Publish { id, reviewed, .. } => service.apply(&id, &reviewed, false),
            Action::RollbackPlan {
                publication, id, ..
            } => {
                service.prepare_rollback(id.as_deref().unwrap_or(Id::new().as_str()), &publication)
            }
            Action::Rollback { id, reviewed, .. } => service.apply(&id, &reviewed, true),
            Action::Fleet { .. } => service.fleet(),
        }
    })();
    match result {
        Ok(value) => {
            let failed = value
                .get("failure_code")
                .is_some_and(|code| !code.is_null())
                || value
                    .pointer("/last_operation_observation/outcome")
                    .and_then(Value::as_str)
                    == Some("rejected");
            let emitted = if json_output {
                super::write_json_stdout(&value, "cannot write team rollout result")
            } else {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&value)
                        .unwrap_or_else(|_| "Team rollout result unavailable".into())
                );
                true
            };
            if emitted && !failed {
                0
            } else {
                1
            }
        }
        Err(error) => {
            let error = tirith_core::redact::redact_sanitize_redact(&error, &[]);
            if json_output {
                super::write_json_stdout(
                    &json!({"schema_version":1,"error":error,"execution_permitted":false}),
                    "cannot write team rollout error",
                );
            } else {
                eprintln!("tirith policy team rollout: {error}");
            }
            1
        }
    }
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ReviewInput {
    pub yaml: String,
    pub commands: Vec<String>,
    pub shell: ShellType,
    pub interactive: bool,
}
type Intent = OperationRequest;
#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum Phase {
    Prepared,
    Submitted,
    Observed,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Record {
    schema_version: u32,
    operation_id: Id,
    review_id: Id,
    connection_id: Id,
    selection: PrivateCommitment,
    cwd: String,
    before: PolicyDocument,
    candidate: PolicyDocument,
    input: ReviewInput,
    baseline_guard: PrivatePolicyReplayGuard,
    candidate_guard: PrivatePolicyReplayGuard,
    report: ImpactReport,
    commitment: PrivateCommitment,
    intent: Intent,
    phase: Phase,
    observation: Option<OperationStatus>,
}
fn err(error: impl std::fmt::Display) -> String {
    error.to_string()
}
fn now_ms() -> Result<u64, String> {
    Utc::now()
        .timestamp_millis()
        .try_into()
        .map_err(|_| "invalid local clock".into())
}
fn network_allowed() -> Result<(), String> {
    if super::offline_env_active() {
        Err("team authority contact is disabled by offline mode".into())
    } else {
        Ok(())
    }
}
fn validate_input(input: &ReviewInput) -> Result<(), String> {
    validate_policy(&input.yaml).map_err(err)?;
    if input.commands.is_empty()
        || input.commands.len() > 32
        || input
            .commands
            .iter()
            .any(|c| c.is_empty() || c.len() > 4096 || c.contains('\0'))
        || input.commands.iter().map(String::len).sum::<usize>() > 64 * 1024
    {
        return Err(
            "review requires 1–32 workflows, each at most 4096 bytes and 64 KiB total".into(),
        );
    }
    Ok(())
}
fn commitment(record: &Record) -> Result<PrivateCommitment, String> {
    let bytes = serde_json::to_vec(&json!({
        "schema_version":record.schema_version,"operation_id":record.operation_id,
        "review_id":record.review_id,"connection_id":record.connection_id,
        "selection":record.selection,"cwd":record.cwd,"before":record.before,
        "candidate":record.candidate,"input":record.input,
        "baseline_guard":record.baseline_guard,"candidate_guard":record.candidate_guard,
        "report":record.report,
        "action": match &record.intent { Intent::Publication(_) => json!({"kind":"publication"}), Intent::Rollback(r) => json!({"kind":"rollback","publication_id":r.publication_id}) }
    })).map_err(|_| "cannot encode private rollout commitment")?;
    Ok(PrivateCommitment::of(
        "tirith-reviewed-team-rollout-v1",
        &bytes,
    ))
}
impl Record {
    fn validate(&self, id: &Id) -> Result<(), String> {
        validate_input(&self.input)?;
        self.before.validate().map_err(err)?;
        self.candidate.validate().map_err(err)?;
        self.report.validate_stored()?;
        if self.schema_version != SCHEMA_VERSION
            || &self.operation_id != id
            || self.cwd.len() > 8192
            || !Path::new(&self.cwd).is_absolute()
            || Path::new(&self.cwd)
                .components()
                .any(|c| matches!(c, std::path::Component::ParentDir))
            || self.before.authority_id != self.candidate.authority_id
            || self.before.policy_id != self.candidate.policy_id
            || self.candidate.yaml != self.input.yaml
            || self.report.scope != RolloutScope::RemoteManaged
            || self.report.candidate_id.as_str() != id.as_str()
            || !self.report.remote_publication_available
            || commitment(self)? != self.commitment
            || (self.phase == Phase::Observed) != self.observation.is_some()
        {
            return Err(
                "private rollout history is inconsistent; preserve it and prepare a new review"
                    .into(),
            );
        }
        let (operation, authority, policy, expected) = match &self.intent {
            Intent::Publication(r) => {
                r.validate_structure().map_err(err)?;
                if r.yaml != self.candidate.yaml
                    || r.review_commitment != self.commitment
                    || self.report.evaluated_at.timestamp_millis() != r.reviewed_unix_ms as i64
                {
                    return Err("publication differs from its reviewed impact".into());
                }
                (
                    &r.operation_id,
                    &r.authority_id,
                    &r.policy_id,
                    &r.expected_revision,
                )
            }
            Intent::Rollback(r) => {
                schema(r.schema_version).map_err(err)?;
                (
                    &r.operation_id,
                    &r.authority_id,
                    &r.policy_id,
                    &r.expected_revision,
                )
            }
        };
        if operation != id
            || authority != &self.before.authority_id
            || policy != &self.before.policy_id
            || expected != &self.before.revision
        {
            return Err("stored server precondition differs from its review".into());
        }
        if let Some(observation) = &self.observation {
            self.check_observation(observation)?;
        }
        Ok(())
    }
    fn check_observation(&self, status: &OperationStatus) -> Result<(), String> {
        let (kind, publication) = match &self.intent {
            Intent::Publication(_) => (OperationKind::Publication, None),
            Intent::Rollback(r) => (OperationKind::Rollback, Some(&r.publication_id)),
        };
        if status.schema_version != SCHEMA_VERSION
            || status.operation_id != self.operation_id
            || status.authority_id != self.before.authority_id
            || status.policy_id != self.before.policy_id
            || status.expected_revision != self.before.revision
            || status.kind != kind
            || status.publication_id.as_ref() != publication
            || status.created_unix_ms == 0
            || (status.outcome == OperationOutcome::Committed)
                != status.published_revision.is_some()
            || (status.outcome == OperationOutcome::Rejected) != status.failure_code.is_some()
        {
            return Err("server observation does not match the stored operation".into());
        }
        Ok(())
    }
    fn check_selection(&self, selected: &ConnectionWitness) -> Result<(), String> {
        if selected.connection_id() != Some(&self.connection_id)
            || selected.private_selection_commitment().map_err(err)? != self.selection
        {
            return Err("selected team connection changed; this review cannot follow a replacement connection".into());
        }
        selected.revalidate().map_err(err)
    }
}
fn load(id: &Id) -> Result<(TeamRecordWitness, Record), String> {
    let witness = TeamRecord::Rollout(id.clone())
        .capture_current()
        .map_err(err)?;
    let bytes = witness
        .private_bytes()
        .ok_or("reviewed team rollout was not found")?;
    let text = std::str::from_utf8(bytes).map_err(|_| "rollout record is not UTF-8")?;
    let value = tirith_core::mcp_lock::parse_json_no_duplicates(text)
        .map_err(|_| "rollout JSON is invalid or ambiguous")?;
    let record: Record =
        serde_json::from_value(value).map_err(|_| "unsupported private rollout schema")?;
    record.validate(id)?;
    witness.revalidate().map_err(err)?;
    Ok((witness, record))
}
fn save(
    record: &Record,
    prior: &TeamRecordWitness,
    validate: impl FnMut() -> Result<(), String>,
) -> Result<setup::TransactionOutcome, String> {
    record.validate(&record.operation_id)?;
    let kind = TeamRecord::Rollout(record.operation_id.clone());
    let bytes = serde_json::to_vec(record).map_err(|_| "cannot encode private rollout")?;
    if bytes.len() > kind.cap() {
        return Err("private rollout exceeds its fixed storage bound".into());
    }
    let text = String::from_utf8(bytes.clone()).map_err(|_| "cannot encode private rollout")?;
    let outcome = setup::update_private_team_record(
        &kind,
        |snapshot| {
            if !prior.matches_private_bytes(snapshot.bytes()) {
                return Err("rollout changed before publication; inspect its status".into());
            }
            Ok(FileUpdate::write_text(text.clone(), 0o600)
                .with_exact_mode()
                .with_backup(false))
        },
        validate,
    )
    .map_err(|_| {
        "local rollout write was not confirmed; inspect its status before retrying".to_string()
    })?;
    let current = kind.capture_current().map_err(err)?;
    if current.private_bytes() != Some(bytes.as_slice()) {
        return Err("rollout changed after publication".into());
    }
    current.revalidate().map_err(err)?;
    Ok(outcome)
}

fn written_projection(
    record: &Record,
    observation: Option<&str>,
    outcome: setup::TransactionOutcome,
) -> Result<Value, String> {
    let mut view = projection(record, observation)?;
    view["local_write"] = json!(match outcome {
        setup::TransactionOutcome::Written => "written",
        setup::TransactionOutcome::WrittenWithRecovery =>
            "written_with_recovery_durability_unconfirmed",
        setup::TransactionOutcome::Unchanged => "unchanged",
        setup::TransactionOutcome::DryRunWouldWrite => "not_written",
    });
    Ok(view)
}

pub(crate) struct TeamRolloutService {
    cwd: String,
}
impl TeamRolloutService {
    pub fn capture(cwd: Option<&str>) -> Result<Self, String> {
        let path = cwd
            .map(std::path::PathBuf::from)
            .map(Ok)
            .unwrap_or_else(std::env::current_dir)
            .map_err(|_| "working directory unavailable")?;
        let cwd = path
            .canonicalize()
            .map_err(|_| "working directory unavailable")?
            .to_str()
            .ok_or("working directory is not UTF-8")?
            .to_owned();
        if cwd.len() > 8192 {
            return Err("working directory exceeds review bound".into());
        }
        Ok(Self { cwd })
    }
    pub fn prepare(&self, id: &str, input: ReviewInput) -> Result<Value, String> {
        self.prepare_inner(Id::parse(id).map_err(err)?, input, None)
    }
    pub fn prepare_rollback(&self, id: &str, publication: &str) -> Result<Value, String> {
        let publication = Id::parse(publication).map_err(err)?;
        let (_, original) = load(&publication)?;
        if !matches!(original.intent, Intent::Publication(_)) {
            return Err("rollback requires an original publication".into());
        }
        let mut input = original.input.clone();
        input.yaml = original.before.yaml.clone();
        self.prepare_inner(Id::parse(id).map_err(err)?, input, Some(original))
    }
    fn prepare_inner(
        &self,
        id: Id,
        input: ReviewInput,
        original: Option<Record>,
    ) -> Result<Value, String> {
        network_allowed()?;
        validate_input(&input)?;
        let _diagnostics = PolicyDiagnosticCapture::start_silent();
        let _bounded = BoundedRuntimePolicyInputs::enter();
        let kind = TeamRecord::Rollout(id.clone());
        let prior = kind.capture_current().map_err(err)?;
        if prior.private_bytes().is_some() {
            return Err("operation ID already has a review; show it or choose a new ID".into());
        }
        let selected = SelectedConnection::capture_current().map_err(err)?;
        let (client, capabilities) = selected.authenticate().map_err(err)?;
        if capabilities.role != Role::Publisher {
            return Err("a publisher credential is required for a rollout review".into());
        }
        let before = client.current().map_err(err)?;
        if let Some(original) = &original {
            original.check_selection(&selected)?;
            let status = client.reconcile(&original.intent).map_err(err)?;
            original.check_observation(&status)?;
            if !status.rollback_eligible
                || status.published_revision.as_ref() != Some(&before.revision)
            {
                return Err(
                    "original publication is no longer eligible for bounded rollback".into(),
                );
            }
        }
        let candidate = PolicyDocument {
            schema_version: SCHEMA_VERSION,
            authority_id: before.authority_id.clone(),
            policy_id: before.policy_id.clone(),
            revision: Id::new(),
            created_unix_ms: now_ms()?,
            policy_semantics_version: POLICY_SEMANTICS_VERSION,
            yaml: input.yaml.clone(),
        };
        let baseline =
            EffectivePolicySnapshot::resolve_team_preview(Some(&self.cwd), &before).map_err(err)?;
        let proposed = EffectivePolicySnapshot::resolve_team_preview(Some(&self.cwd), &candidate)
            .map_err(err)?;
        let frozen: Vec<_> = input
            .commands
            .iter()
            .map(|command| {
                FrozenEvaluation::capture(
                    tirith_core::engine::AnalysisContext {
                        input: command.clone(),
                        shell: input.shell,
                        scan_context: tirith_core::extract::ScanContext::Exec,
                        raw_bytes: None,
                        interactive: input.interactive,
                        cwd: Some(self.cwd.clone()),
                        file_path: None,
                        repo_root: None,
                        is_config_override: false,
                        clipboard_html: None,
                        card_ref: None,
                        clipboard_source:
                            tirith_core::clipboard::ClipboardSourceState::AbsentOrInvalid,
                    },
                    &baseline,
                    tirith_core::escalation::CallerContext::Cli,
                    None,
                    SessionEvidence::Unavailable,
                )
            })
            .collect();
        let owner = RecordId::parse(Id::new().as_str()).map_err(err)?;
        let workflows: Vec<_> = frozen
            .iter()
            .map(|evidence| Workflow {
                id: RecordId::parse(Id::new().as_str()).unwrap(),
                evidence,
                owner: Some(owner.clone()),
            })
            .collect();
        let (grants, _) = super::rollout::captured_grants()?;
        let project = tirith_core::trust_grants::ProjectIdentity::capture(Some(&self.cwd)).ok();
        let exceptions: Vec<_> = grants
            .iter()
            .map(|grant| Exception {
                grant,
                owner: ExceptionOwner::LocalOperator { id: owner.clone() },
                project: project.as_ref(),
            })
            .collect();
        let publisher = client.publisher_observation().map_err(err)?;
        let now = Utc::now();
        let reviewed_ms = now
            .timestamp_millis()
            .try_into()
            .map_err(|_| "invalid review clock")?;
        let report = policy_rollout::review_for_publisher(
            policy_rollout::ImpactRequest {
                id: RecordId::parse(Id::new().as_str()).map_err(err)?,
                candidate_id: RecordId::parse(id.as_str()).map_err(err)?,
                scope: RolloutScope::RemoteManaged,
                baseline: &baseline,
                candidate: &proposed.policy,
                candidate_coverage: CandidateCoverage::EffectivePolicy,
                workflows: &workflows,
                exceptions: &exceptions,
                exception_inventory_complete: false,
                clients: &[],
                now,
            },
            &publisher,
        )
        .map_err(err)?;
        let placeholder = PrivateCommitment::of("uninitialized", &[]);
        let intent = match &original {
            None => Intent::Publication(PublicationRequest {
                schema_version: 1,
                operation_id: id.clone(),
                authority_id: before.authority_id.clone(),
                policy_id: before.policy_id.clone(),
                expected_revision: before.revision.clone(),
                yaml: input.yaml.clone(),
                reviewed_unix_ms: reviewed_ms,
                review_commitment: placeholder.clone(),
            }),
            Some(original) => Intent::Rollback(RollbackRequest {
                schema_version: 1,
                operation_id: id.clone(),
                publication_id: original.operation_id.clone(),
                authority_id: before.authority_id.clone(),
                policy_id: before.policy_id.clone(),
                expected_revision: before.revision.clone(),
            }),
        };
        let mut record = Record {
            schema_version: 1,
            operation_id: id,
            review_id: Id::new(),
            connection_id: selected
                .connection_id()
                .ok_or("connection unavailable")?
                .clone(),
            selection: selected.private_selection_commitment().map_err(err)?,
            cwd: self.cwd.clone(),
            before,
            candidate,
            input,
            baseline_guard: baseline.private_replay_guard(),
            candidate_guard: proposed.private_replay_guard(),
            report,
            commitment: placeholder,
            intent,
            phase: Phase::Prepared,
            observation: None,
        };
        record.commitment = commitment(&record)?;
        if let Intent::Publication(request) = &mut record.intent {
            request.review_commitment = record.commitment.clone();
        }
        let outcome = save(&record, &prior, || {
            selected.revalidate().map_err(err)?;
            baseline.revalidate_captured().map_err(err)?;
            proposed.revalidate_captured().map_err(err)?;
            prior.revalidate().map_err(err)
        })?;
        written_projection(&record, None, outcome)
    }
    pub fn show(&self, id: &str, refresh: bool) -> Result<Value, String> {
        let id = Id::parse(id).map_err(err)?;
        let (witness, mut record) = load(&id)?;
        if !refresh {
            return projection(&record, None);
        }
        network_allowed()?;
        let selected = SelectedConnection::capture_current().map_err(err)?;
        record.check_selection(&selected)?;
        let client = selected.client().map_err(err)?;
        match client.reconcile(&record.intent) {
            Ok(status) => {
                record.check_observation(&status)?;
                record.phase = Phase::Observed;
                record.observation = Some(status);
                let outcome = save(&record, &witness, || {
                    selected.revalidate().map_err(err)?;
                    witness.revalidate().map_err(err)
                })?;
                written_projection(
                    &record,
                    Some("authenticated_exact_intent_observation"),
                    outcome,
                )
            }
            Err(ErrorCode::OperationNotFound) => {
                projection(&record, Some("server_has_no_record_at_this_observation"))
            }
            Err(error) => Err(err(error)),
        }
    }
    pub fn apply(&self, id: &str, reviewed: &str, rollback: bool) -> Result<Value, String> {
        let id = Id::parse(id).map_err(err)?;
        let (witness, mut record) = load(&id)?;
        if Id::parse(reviewed).map_err(err)? != record.review_id
            || self.cwd != record.cwd
            || matches!(record.intent, Intent::Rollback(_)) != rollback
        {
            return Err(
                "action, review identity or working directory differs from the reviewed operation"
                    .into(),
            );
        }
        network_allowed()?;
        let _diagnostics = PolicyDiagnosticCapture::start_silent();
        let _bounded = BoundedRuntimePolicyInputs::enter();
        let selected = SelectedConnection::capture_current().map_err(err)?;
        record.check_selection(&selected)?;
        let (client, caps) = selected.authenticate().map_err(err)?;
        if caps.role != Role::Publisher {
            return Err("publisher credential required".into());
        }
        // Reconcile durable server history before a repeated explicit submission.
        match client.reconcile(&record.intent) {
            Ok(status) => {
                record.check_observation(&status)?;
                record.phase = Phase::Observed;
                record.observation = Some(status);
                let outcome = save(&record, &witness, || {
                    selected.revalidate().map_err(err)?;
                    witness.revalidate().map_err(err)
                })?;
                return written_projection(
                    &record,
                    Some("authenticated_exact_intent_observation"),
                    outcome,
                );
            }
            Err(ErrorCode::OperationNotFound) if record.phase != Phase::Observed => {}
            Err(ErrorCode::OperationNotFound) => {
                return Err(
                    "server lost a previously observed operation; no resubmission is allowed"
                        .into(),
                )
            }
            Err(error) => return Err(err(error)),
        }
        validate_review_time(
            record
                .report
                .evaluated_at
                .timestamp_millis()
                .try_into()
                .map_err(|_| "invalid review clock")?,
            now_ms()?,
        )
        .map_err(err)?;
        let current = client.current().map_err(err)?;
        if current.revision != record.before.revision
            || serde_json::to_vec(&current).map_err(err)?
                != serde_json::to_vec(&record.before).map_err(err)?
        {
            return Err("server policy changed since review; prepare a new operation".into());
        }
        let baseline = EffectivePolicySnapshot::resolve_team_preview(Some(&self.cwd), &current)
            .map_err(err)?;
        let proposed =
            EffectivePolicySnapshot::resolve_team_preview(Some(&self.cwd), &record.candidate)
                .map_err(err)?;
        if baseline.private_replay_guard() != record.baseline_guard
            || proposed.private_replay_guard() != record.candidate_guard
        {
            return Err("local restrictions or workflow context changed since review; prepare a new operation".into());
        }
        record.phase = Phase::Submitted;
        let outcome = save(&record, &witness, || {
            selected.revalidate().map_err(err)?;
            baseline.revalidate_captured().map_err(err)?;
            proposed.revalidate_captured().map_err(err)?;
            witness.revalidate().map_err(err)
        })?;
        if outcome != setup::TransactionOutcome::Written {
            let mut view = written_projection(
                &record,
                Some("submission_journal_durability_unconfirmed_no_server_mutation_sent"),
                outcome,
            )?;
            view["failure_code"] = json!(ErrorCode::StorageUnavailable);
            return Ok(view);
        }
        let (submitted, exact) = load(&id)?;
        if exact.commitment != record.commitment || exact.phase != Phase::Submitted {
            return Err("submission history changed; inspect status".into());
        }
        selected.revalidate().map_err(err)?;
        baseline.revalidate_captured().map_err(err)?;
        proposed.revalidate_captured().map_err(err)?;
        submitted.revalidate().map_err(err)?;
        let result = match &record.intent {
            Intent::Publication(request) => client.publish(request),
            Intent::Rollback(request) => client.rollback(request),
        };
        match result {
            Ok(status) => {
                record.check_observation(&status)?;
                record.phase = Phase::Observed;
                record.observation = Some(status);
                let outcome = save(&record, &submitted, || {
                    selected.revalidate().map_err(err)?;
                    submitted.revalidate().map_err(err)
                })?;
                written_projection(
                    &record,
                    Some("authenticated_exact_intent_observation"),
                    outcome,
                )
            }
            Err(error) => {
                let mut view = projection(&record, Some("submission_outcome_not_confirmed"))?;
                view["failure_code"] = json!(error);
                Ok(view)
            }
        }
    }
    pub fn fleet(&self) -> Result<Value, String> {
        network_allowed()?;
        let selected = SelectedConnection::capture_current().map_err(err)?;
        let status = selected.client().map_err(err)?.status().map_err(err)?;
        selected.revalidate().map_err(err)?;
        Ok(
            json!({"schema_version":1,"fleet":status,"notice":"These are authenticated client reports. Missing, stale, downloaded and failed clients remain visible; reports do not independently verify enforcement."}),
        )
    }
}
fn projection(record: &Record, observation: Option<&str>) -> Result<Value, String> {
    let _diagnostics = PolicyDiagnosticCapture::start_silent();
    let _bounded = BoundedRuntimePolicyInputs::enter();
    let mut patterns =
        tirith_core::policy::Policy::discover_local_only(Some(&record.cwd)).dlp_custom_patterns;
    patterns.extend(
        validate_policy(&record.before.yaml)
            .map_err(err)?
            .dlp_custom_patterns,
    );
    patterns.extend(
        validate_policy(&record.candidate.yaml)
            .map_err(err)?
            .dlp_custom_patterns,
    );
    let compiled = tirith_core::redact::CompiledCustomPatterns::new_silent(&patterns);
    let policy = super::policy::effective_policy_display(
        &validate_policy(&record.candidate.yaml).map_err(err)?,
        &compiled,
    )
    .map_err(|_| "cannot project reviewed policy")?;
    Ok(
        json!({"schema_version":1,"operation_id":record.operation_id,"review_id":record.review_id,"connection_id":record.connection_id,"authority_id":record.before.authority_id,"policy_id":record.before.policy_id,"expected_revision":record.before.revision,"kind":match record.intent{Intent::Publication(_)=>"publication",Intent::Rollback(_)=>"rollback"},"phase":record.phase,"impact_review":record.report,"historical_evidence":record.report.historical_evidence_status(Utc::now())?,"proposed_policy":policy,"last_operation_observation":record.observation,"current_observation":observation,"activation_required_on_each_client":true,"fleet_adoption_verified":false,"notice":"Review covers the supplied workflows and this operator's local restrictions. Publishing does not activate devices or approve exceptions. Stored reports are historical; refresh contacts the selected authority."}),
    )
}
