//! Typed, restartable file mutations. Public previews contain metadata only;
//! private journals hold payloads/preimages and authorization replay guards.
//! HTTP callers select stored plan IDs; they must never accept paths or file
//! contents from a browser and turn them into `RequestedChange` values.
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use tirith_core::policy_rollout::{ImpactReport, RolloutScope};
use tirith_core::policy_snapshot::{EffectivePolicySnapshot, PrivatePolicyReplayGuard};

use super::fs_helpers;
use super::fs_transaction::{FileUpdate, TransactionOutcome, MAX_SETUP_FILE_BYTES};

const SCHEMA: u32 = 1;
const MAX_STEPS: usize = 64;
const MAX_ACTIVE_JOBS: usize = 4;
const JOB_TIMEOUT: Duration = Duration::from_secs(300);
static ACTIVE_JOBS: AtomicUsize = AtomicUsize::new(0);
static WORKER_RESERVATIONS: OnceLock<Mutex<std::collections::BTreeMap<PathBuf, JobAction>>> =
    OnceLock::new();

fn worker_reservations() -> &'static Mutex<std::collections::BTreeMap<PathBuf, JobAction>> {
    WORKER_RESERVATIONS.get_or_init(|| Mutex::new(Default::default()))
}

struct WorkerPermit {
    path: PathBuf,
}

impl Drop for WorkerPermit {
    fn drop(&mut self) {
        worker_reservations()
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .remove(&self.path);
        ACTIVE_JOBS.fetch_sub(1, Ordering::AcqRel);
    }
}

pub(crate) fn active_job_count() -> usize {
    ACTIVE_JOBS.load(Ordering::Acquire)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum OperationKind {
    SetProfile,
    RecordFeedback,
    ExportSupport,
    ExportAudit,
    DeleteAuditSegment,
    RecommendedSetup,
    RotateAudit,
    SetPersonalSetting,
    ImportPolicy,
    AddTrust,
    RevokeTrust,
    SetupShell,
    SetupIntegration,
    RemoveIntegration,
}

impl OperationKind {
    fn changes_policy(self) -> bool {
        matches!(
            self,
            Self::SetProfile
                | Self::RecommendedSetup
                | Self::SetPersonalSetting
                | Self::ImportPolicy
                | Self::AddTrust
                | Self::RevokeTrust
        )
    }
}

pub(super) fn preflight_target(
    kind: OperationKind,
    root: &Path,
    target: &Path,
    policy: &EffectivePolicySnapshot,
) -> Result<(), String> {
    crate::cli::preflight_config_write_authorization(
        root,
        target,
        true,
        &policy.policy,
        kind.changes_policy(),
    )
    .map_err(|error| refresh(error.to_string()))
}

pub(super) fn authorize_publication(
    kind: OperationKind,
    root: &Path,
    target: &Path,
    bytes: &[u8],
    policy: &EffectivePolicySnapshot,
) -> Result<(), String> {
    use tirith_core::config_write::ConfigWritePermit;
    use tirith_core::task_boundary::{BoundaryOperation, ConfigWriteBoundary, OwnedBoundary};
    let envelope = ConfigWritePermit::operation_envelope_for(
        root,
        target,
        bytes,
        true,
        &policy.policy.enforcement_projection_hash(),
        kind.changes_policy(),
    )
    .map_err(|error| refresh(error.to_string()))?;
    let operation = BoundaryOperation {
        boundary: OwnedBoundary::ConfigWrite,
        envelope: &envelope,
        adapter: tirith_core::task::IngressAdapter::Unattributed,
        boundary_effects: ConfigWritePermit::boundary_effects_for(kind.changes_policy()),
    };
    let pending = tirith_core::task_boundary::prepare_locally_derived_boundary_authorization::<
        ConfigWriteBoundary,
    >(
        &operation,
        &policy.policy.task_gate,
        &tirith_core::task_analysis::TaskAnalysisContext::default(),
    )
    .map_err(|error| {
        refresh(format!(
            "task gate refused configuration publication: {error}"
        ))
    })?;
    let permit = pending
        .consume_default_for_operation(&operation, chrono::Utc::now())
        .map_err(|error| {
            refresh(format!(
                "task gate refused configuration publication: {error}"
            ))
        })?;
    if !permit.binds_operation(&operation) {
        return Err(refresh("configuration publication authorization changed"));
    }
    Ok(())
}

/// A programmatic request from an allowlisted CLI operation. Deliberately not
/// Deserialize: browser API routes must derive targets and edits server-side.
#[derive(Serialize)]
pub(crate) struct RequestedChange {
    pub target: PathBuf,
    pub scope_root: PathBuf,
    pub edit: Edit,
    /// Inactive assets are staged first; activation references are applied last.
    pub activation: bool,
    pub description: String,
}

#[derive(Serialize)]
pub(crate) enum Edit {
    AuditRotation(tirith_core::audit::retention::RotationPlan),
    AuditSegment(super::audit_segments::SegmentPlan),
    WholeFile(String),
    PrivateFile(String),
    #[cfg(test)]
    JsonField {
        pointer: String,
        value: Option<Value>,
    },
    YamlFields(std::collections::BTreeMap<String, Option<Value>>),
    ShellHook {
        block: Option<String>,
    },
}

#[derive(Clone, Serialize, Deserialize)]
enum OwnedEdit {
    AuditRotation(tirith_core::audit::retention::RotationPlan),
    AuditSegment(super::audit_segments::SegmentPlan),
    Compound(Vec<OwnedEdit>),
    PrivateFile {
        before: Option<String>,
        after: String,
    },
    WholeFile {
        before: Option<String>,
        after: String,
    },
    Field {
        yaml: bool,
        pointer: String,
        before: Option<Value>,
        after: Option<Value>,
    },
    ShellHook {
        before: Option<String>,
        after: Option<String>,
    },
}

#[derive(Clone, Serialize, Deserialize)]
struct Step {
    target: PathBuf,
    scope_root: PathBuf,
    edit: OwnedEdit,
    activation: bool,
    description: String,
    state: StepState,
    scope_identity: ScopeIdentity,
    /// Authority inputs need full-document bindings: an unrelated policy key
    /// may itself alter authorization even when our owned leaf is unchanged.
    authority_document: Option<AuthorityDocument>,
    /// A new undo decision may retain unrelated edits made after apply. Once
    /// captured, its complete generation is immutable across compensation.
    undo_document: Option<AuthorityDocument>,
}

#[derive(Clone, Serialize, Deserialize)]
struct AuthorityDocument {
    before: Option<String>,
    after: Option<String>,
    compensation: Option<String>,
}

#[derive(Clone, Serialize, Deserialize)]
struct ScopeIdentity {
    anchor: PathBuf,
    canonical: PathBuf,
    device_inode: Option<(u64, u64)>,
}

impl ScopeIdentity {
    fn capture(root: &Path) -> Result<Self, String> {
        let mut anchor = root.to_path_buf();
        while !anchor.exists() {
            if !anchor.pop() {
                return Err("cannot identify mutation scope".into());
            }
        }
        let canonical = anchor.canonicalize().map_err(|e| e.to_string())?;
        let metadata = std::fs::metadata(&anchor).map_err(|e| e.to_string())?;
        if !metadata.is_dir() {
            return Err("mutation scope anchor is not a directory".into());
        }
        #[cfg(unix)]
        let device_inode = {
            use std::os::unix::fs::MetadataExt;
            Some((metadata.dev(), metadata.ino()))
        };
        #[cfg(windows)]
        let device_inode = Some(fs_helpers::directory_identity(&canonical)?);
        #[cfg(not(any(unix, windows)))]
        let device_inode = None;
        Ok(Self {
            anchor,
            canonical,
            device_inode,
        })
    }

    fn validate(&self) -> Result<(), String> {
        let current = Self::capture(&self.anchor)?;
        if current.anchor != self.anchor
            || current.canonical != self.canonical
            || current.device_inode != self.device_inode
        {
            return Err(refresh("mutation scope directory was moved or replaced"));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum StepState {
    Pending,
    Applying,
    Applied,
    AppliedWithRecovery,
    Compensating,
    Compensated,
    CompensatedWithRecovery,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum JobState {
    Planned,
    Running,
    CancelRequested,
    Cancelled,
    PartiallyApplied,
    Completed,
    CompletedWithRecovery,
    RefreshRequired,
    RecoveryRequired,
    Undone,
    UndoneWithRecovery,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum JobAction {
    Apply,
    Undo,
}

impl JobAction {
    fn already_finished(self, state: JobState) -> bool {
        match self {
            Self::Apply => state.completed() || state == JobState::Cancelled,
            Self::Undo => matches!(state, JobState::Undone | JobState::UndoneWithRecovery),
        }
    }
}

impl JobState {
    fn completed(self) -> bool {
        matches!(
            self,
            Self::Completed | Self::CompletedWithRecovery | Self::Undone | Self::UndoneWithRecovery
        )
    }
}

#[derive(Clone, Serialize, Deserialize)]
struct Journal {
    schema_version: u32,
    operation_id: String,
    kind: OperationKind,
    operator: String,
    client_version: String,
    payload_digest: String,
    request_digest: String,
    caller_intent_digest: Option<String>,
    #[serde(default, skip_serializing_if = "is_false")]
    no_op: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    impact_review: Option<ImpactReport>,
    policy_identity: String,
    authorization: PrivatePolicyReplayGuard,
    external_authorization: PrivatePolicyReplayGuard,
    resolution_cwd: Option<String>,
    undo_external_authorization: Option<PrivatePolicyReplayGuard>,
    shell_precondition: Option<super::shell_service::ShellPrecondition>,
    created_at: u64,
    updated_at: u64,
    state: JobState,
    active_action: Option<JobAction>,
    detail: Option<String>,
    steps: Vec<Step>,
}

#[derive(Debug, Clone, Serialize)]
pub(crate) struct StepStatus {
    pub target: PathBuf,
    pub description: String,
    pub activation: bool,
    pub state: StepState,
}

#[derive(Debug, Clone, Serialize)]
pub(crate) struct OperationStatus {
    pub schema_version: u32,
    pub operation_id: String,
    pub kind: OperationKind,
    pub client_version: String,
    pub policy_identity: String,
    pub state: JobState,
    pub no_op: bool,
    pub irreversible: bool,
    pub active_action: Option<JobAction>,
    pub created_at: u64,
    pub updated_at: u64,
    pub detail: Option<String>,
    pub steps: Vec<StepStatus>,
}

#[derive(Serialize)]
pub(crate) struct RecentOperations {
    pub schema_version: u32,
    pub operations: Vec<OperationStatus>,
    pub coverage: OperationCoverage,
}

#[derive(Serialize)]
pub(crate) struct OperationCoverage {
    pub state_source: &'static str,
    pub entries_examined: usize,
    pub records_examined: usize,
    pub invalid_names: usize,
    pub unreadable_records: usize,
    pub scan_limited: bool,
    pub results_limited: bool,
    pub running_requires_status_reconciliation: bool,
}

impl Journal {
    fn public(&self) -> OperationStatus {
        OperationStatus {
            schema_version: self.schema_version,
            operation_id: self.operation_id.clone(),
            kind: self.kind,
            client_version: self.client_version.clone(),
            policy_identity: self.policy_identity.clone(),
            state: self.state,
            no_op: self.no_op,
            irreversible: self.kind == OperationKind::DeleteAuditSegment,
            active_action: matches!(self.state, JobState::Running | JobState::CancelRequested)
                .then_some(self.active_action)
                .flatten(),
            created_at: self.created_at,
            updated_at: self.updated_at,
            detail: self.detail.clone(),
            steps: self
                .steps
                .iter()
                .map(|step| StepStatus {
                    target: step.target.clone(),
                    description: step.description.clone(),
                    activation: step.activation,
                    state: step.state,
                })
                .collect(),
        }
    }
}

#[derive(Clone)]
pub(crate) struct MutationService {
    root: PathBuf,
    scope: PathBuf,
    operator: String,
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}
fn refresh(reason: impl std::fmt::Display) -> String {
    format!("refresh-required: {reason}")
}
fn digest(value: &impl Serialize) -> Result<String, String> {
    let mut canonical = serde_json::to_value(value).map_err(|e| e.to_string())?;
    canonical.sort_all_objects();
    let bytes = serde_json::to_vec(&canonical).map_err(|e| e.to_string())?;
    Ok(format!("{:x}", Sha256::digest(bytes)))
}

fn is_false(value: &bool) -> bool {
    !*value
}

fn validate_review(
    review: &Option<ImpactReport>,
    id: &str,
    kind: OperationKind,
    identity: &str,
) -> Result<(), String> {
    let Some(review) = review else {
        return Ok(());
    };
    uuid::Uuid::parse_str(id).map_err(|_| "review operation ID must be a UUID")?;
    if kind != OperationKind::SetProfile
        || review.scope != RolloutScope::PersonalUser
        || review.candidate_id.as_str() != id
        || review.baseline_policy_identity.as_str() != identity
    {
        return Err(
            "impact review does not match its personal profile operation and baseline".into(),
        );
    }
    review.validate_stored()?;
    if serde_json::to_vec(review).map_err(|e| e.to_string())?.len() > 256 * 1024 {
        return Err("impact review exceeds the 256 KiB attachment limit".into());
    }
    Ok(())
}

fn bind_review_digest(original: String, review: &Option<ImpactReport>) -> Result<String, String> {
    match review {
        Some(review) => digest(&("tirith-impact-review-v1", original, review)),
        None => Ok(original),
    }
}

fn same_request(record: &Journal, request_digest: &str, caller_intent: Option<&str>) -> bool {
    if record.client_version != env!("CARGO_PKG_VERSION") {
        return false;
    }
    match caller_intent {
        Some(intent) => record.caller_intent_digest.as_deref() == Some(intent),
        None => record.caller_intent_digest.is_none() && record.request_digest == request_digest,
    }
}

/// Exact caller preimages travel with their prepared owned transformations.
pub(crate) struct PlanChanges<'a> {
    pub requests: Vec<RequestedChange>,
    pub preimages: &'a std::collections::BTreeMap<PathBuf, Option<String>>,
}

#[derive(Default)]
struct PlanMetadata {
    caller_intent_digest: Option<String>,
    shell_precondition: Option<super::shell_service::ShellPrecondition>,
    no_op: bool,
    impact_review: Option<ImpactReport>,
}

impl MutationService {
    pub(crate) fn current() -> Result<Self, String> {
        let target = crate::cli::shell_target::resolve_for_shell("unknown")?;
        crate::cli::shell_target::require_personal_writer(&target)?;
        let scope =
            tirith_core::policy::state_dir().ok_or("cannot resolve operation journal directory")?;
        if !scope.is_absolute()
            || scope
                .components()
                .any(|c| matches!(c, std::path::Component::ParentDir))
        {
            return Err(
                "operation state directory must be absolute without parent traversal".into(),
            );
        }
        let operator = format!(
            "{:?}:{}",
            target.operator_uid,
            target.operator_home.display()
        );
        Ok(Self {
            root: scope.join("operations"),
            scope,
            operator,
        })
    }

    fn path(&self, operation_id: &str) -> Result<PathBuf, String> {
        if operation_id.is_empty()
            || operation_id.len() > 128
            || !operation_id
                .bytes()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, b'-' | b'_'))
        {
            return Err(
                "operation ID must be 1–128 ASCII letters, digits, hyphens or underscores".into(),
            );
        }
        Ok(self.root.join(format!("{operation_id}.json")))
    }

    fn read(&self, operation_id: &str) -> Result<Journal, String> {
        let path = self.path(operation_id)?;
        let snapshot = fs_helpers::read_snapshot_scoped(&path, &self.scope)?;
        snapshot.require_private()?;
        let bytes = snapshot.bytes.as_deref().ok_or("operation not found")?;
        let record: Journal = serde_json::from_slice(bytes)
            .map_err(|_| "operation journal is malformed; retain it for recovery")?;
        if record.schema_version != SCHEMA
            || record.operation_id != operation_id
            || record.operator != self.operator
        {
            return Err("operation journal schema, ID or operator does not match".into());
        }
        validate_review(
            &record.impact_review,
            operation_id,
            record.kind,
            &record.policy_identity,
        )?;
        Ok(record)
    }

    /// A bounded, read-only inventory for a reopened browser. Persisted Running
    /// rows require the explicit status route to reconcile worker liveness.
    pub(crate) fn recent_statuses(&self, limit: usize) -> Result<RecentOperations, String> {
        if !(1..=50).contains(&limit) {
            return Err("recent operation limit must be 1–50".into());
        }
        let started = Instant::now();
        let (names, truncated) =
            fs_helpers::private_directory_names(&self.root, &self.scope, 1024)?;
        let mut coverage = OperationCoverage {
            state_source: "persisted-private-journal",
            entries_examined: names.len(),
            records_examined: 0,
            invalid_names: 0,
            unreadable_records: 0,
            scan_limited: truncated,
            results_limited: false,
            running_requires_status_reconciliation: false,
        };
        let mut operations = Vec::new();
        let mut read_bytes = 0usize;
        for name in names {
            if read_bytes >= 16 * 1024 * 1024 || started.elapsed() >= Duration::from_secs(1) {
                coverage.scan_limited = true;
                break;
            }
            let Some(id) = name
                .to_str()
                .and_then(|name| name.strip_suffix(".json"))
                .filter(|id| id.len() == 36 && uuid::Uuid::parse_str(id).is_ok())
            else {
                coverage.invalid_names += 1;
                continue;
            };
            coverage.records_examined += 1;
            let result = (|| {
                let snapshot = fs_helpers::read_snapshot_scoped(&self.path(id)?, &self.scope)?;
                snapshot.require_private()?;
                let bytes = snapshot.bytes.as_deref().ok_or("operation disappeared")?;
                read_bytes = read_bytes.saturating_add(bytes.len());
                let record: Journal =
                    serde_json::from_slice(bytes).map_err(|_| "invalid operation record")?;
                if record.schema_version != SCHEMA
                    || record.operation_id != id
                    || record.operator != self.operator
                {
                    return Err("operation record identity does not match".to_owned());
                }
                Ok(record.public())
            })();
            match result {
                Ok(status) => operations.push(status),
                Err(_) => coverage.unreadable_records += 1,
            }
        }
        operations.sort_by(|a, b| {
            b.updated_at
                .cmp(&a.updated_at)
                .then_with(|| b.operation_id.cmp(&a.operation_id))
        });
        coverage.results_limited = operations.len() > limit;
        operations.truncate(limit);
        coverage.running_requires_status_reconciliation = operations.iter().any(|operation| {
            matches!(
                operation.state,
                JobState::Running | JobState::CancelRequested
            )
        });
        Ok(RecentOperations {
            schema_version: 1,
            operations,
            coverage,
        })
    }

    fn update(
        &self,
        operation_id: &str,
        mut update: impl FnMut(&mut Journal) -> Result<(), String>,
    ) -> Result<Journal, String> {
        let path = self.path(operation_id)?;
        let mut result = None;
        fs_helpers::transactional_update(&path, &self.scope, false, |snapshot| {
            snapshot.require_private()?;
            let text = snapshot.text(&path)?.ok_or("operation not found")?;
            let mut record: Journal =
                serde_json::from_str(text).map_err(|_| "operation journal is malformed")?;
            if record.schema_version != SCHEMA
                || record.operation_id != operation_id
                || record.operator != self.operator
            {
                return Err("operation journal identity does not match".into());
            }
            update(&mut record)?;
            record.updated_at = now();
            let bytes = serde_json::to_string(&record).map_err(|e| e.to_string())?;
            result = Some(record);
            Ok(FileUpdate::write_text(bytes, 0o600))
        })?;
        result.ok_or_else(|| "operation journal update produced no result".into())
    }

    /// Persist a reviewable immutable payload before any destination is changed.
    /// Reusing an ID with different operator/kind/payload is rejected.
    #[cfg(test)]
    pub(crate) fn plan(
        &self,
        operation_id: &str,
        kind: OperationKind,
        requests: Vec<RequestedChange>,
        policy: &EffectivePolicySnapshot,
    ) -> Result<OperationStatus, String> {
        self.plan_with_preimages(
            operation_id,
            kind,
            requests,
            policy,
            &std::collections::BTreeMap::new(),
        )
    }

    /// Bind transformations derived from an earlier caller read to those exact
    /// owned preimages. Unrelated fields may change without invalidating them.
    pub(crate) fn plan_with_preimages(
        &self,
        operation_id: &str,
        kind: OperationKind,
        requests: Vec<RequestedChange>,
        policy: &EffectivePolicySnapshot,
        expected_documents: &std::collections::BTreeMap<PathBuf, Option<String>>,
    ) -> Result<OperationStatus, String> {
        self.plan_inner(
            operation_id,
            kind,
            requests,
            policy,
            expected_documents,
            PlanMetadata {
                caller_intent_digest: None,
                shell_precondition: None,
                no_op: false,
                impact_review: None,
            },
        )
    }

    /// Look up an already prepared high-level request before generating IDs or
    /// relative deadlines. Intent must include every caller choice and scope;
    /// it is serialized only into a private digest, never a second metadata file.
    pub(crate) fn status_for_intent(
        &self,
        operation_id: &str,
        kind: OperationKind,
        intent: &impl Serialize,
    ) -> Result<Option<OperationStatus>, String> {
        let path = self.path(operation_id)?;
        if fs_helpers::read_to_string_scoped(&path, &self.scope)?.is_none() {
            return Ok(None);
        }
        let record = self.read(operation_id)?;
        let expected = self.intent_digest(kind, intent)?;
        if record.kind != kind
            || record.client_version != env!("CARGO_PKG_VERSION")
            || record.caller_intent_digest.as_deref() != Some(expected.as_str())
        {
            return Err("operation ID already belongs to a different caller intent, scope or client version".into());
        }
        self.status(operation_id).map(Some)
    }

    fn intent_digest(
        &self,
        kind: OperationKind,
        intent: &impl Serialize,
    ) -> Result<String, String> {
        digest(&(
            "tirith-caller-intent-v1",
            &self.operator,
            env!("CARGO_PKG_VERSION"),
            kind,
            intent,
        ))
    }

    pub(crate) fn plan_with_preimages_and_intent(
        &self,
        operation_id: &str,
        kind: OperationKind,
        requests: Vec<RequestedChange>,
        policy: &EffectivePolicySnapshot,
        expected_documents: &std::collections::BTreeMap<PathBuf, Option<String>>,
        intent: &impl Serialize,
    ) -> Result<OperationStatus, String> {
        self.plan_inner(
            operation_id,
            kind,
            requests,
            policy,
            expected_documents,
            PlanMetadata {
                caller_intent_digest: Some(self.intent_digest(kind, intent)?),
                shell_precondition: None,
                no_op: false,
                impact_review: None,
            },
        )
    }

    pub(crate) fn plan_shell_change_with_intent(
        &self,
        operation_id: &str,
        kind: OperationKind,
        changes: PlanChanges<'_>,
        policy: &EffectivePolicySnapshot,
        intent: &impl Serialize,
        precondition: super::shell_service::ShellPrecondition,
    ) -> Result<OperationStatus, String> {
        let PlanChanges {
            requests,
            preimages: expected_documents,
        } = changes;
        if !matches!(
            kind,
            OperationKind::SetupShell
                | OperationKind::RemoveIntegration
                | OperationKind::RecommendedSetup
        ) {
            return Err("shell preconditions require a shell setup/removal operation".into());
        }
        self.plan_inner(
            operation_id,
            kind,
            requests,
            policy,
            expected_documents,
            PlanMetadata {
                caller_intent_digest: Some(self.intent_digest(kind, intent)?),
                shell_precondition: Some(precondition),
                no_op: false,
                impact_review: None,
            },
        )
    }

    /// Persist an accepted no-change intent. A retry cannot turn this UUID
    /// into a later mutation after configuration drift or a lost response.
    pub(crate) fn complete_noop_with_intent(
        &self,
        operation_id: &str,
        kind: OperationKind,
        policy: &EffectivePolicySnapshot,
        intent: &impl Serialize,
    ) -> Result<OperationStatus, String> {
        uuid::Uuid::parse_str(operation_id).map_err(|_| "operation ID must be a UUID")?;
        if let Some(status) = self.status_for_intent(operation_id, kind, intent)? {
            let record = self.read(operation_id)?;
            if record.resolution_cwd.as_deref() != policy.resolution_cwd() {
                return Err("operation ID already belongs to a different policy scope".into());
            }
            return Ok(status);
        }
        self.plan_inner(
            operation_id,
            kind,
            Vec::new(),
            policy,
            &std::collections::BTreeMap::new(),
            PlanMetadata {
                caller_intent_digest: Some(self.intent_digest(kind, intent)?),
                shell_precondition: None,
                no_op: true,
                impact_review: None,
            },
        )
    }

    /// Atomically bind a canonical diagnostic review to the immutable change.
    /// Review fields cannot grant authorization and are never replacement input.
    pub(crate) fn plan_with_preimages_intent_and_review(
        &self,
        operation_id: &str,
        kind: OperationKind,
        changes: PlanChanges<'_>,
        policy: &EffectivePolicySnapshot,
        intent: &impl Serialize,
        review: ImpactReport,
    ) -> Result<OperationStatus, String> {
        let PlanChanges {
            requests,
            preimages: expected_documents,
        } = changes;
        self.plan_inner(
            operation_id,
            kind,
            requests,
            policy,
            expected_documents,
            PlanMetadata {
                caller_intent_digest: Some(self.intent_digest(kind, intent)?),
                shell_precondition: None,
                no_op: false,
                impact_review: Some(review),
            },
        )
    }

    pub(crate) fn complete_noop_with_intent_and_review(
        &self,
        operation_id: &str,
        kind: OperationKind,
        policy: &EffectivePolicySnapshot,
        intent: &impl Serialize,
        review: ImpactReport,
    ) -> Result<OperationStatus, String> {
        self.plan_inner(
            operation_id,
            kind,
            Vec::new(),
            policy,
            &std::collections::BTreeMap::new(),
            PlanMetadata {
                caller_intent_digest: Some(self.intent_digest(kind, intent)?),
                shell_precondition: None,
                no_op: true,
                impact_review: Some(review),
            },
        )
    }

    /// A typed, validated projection; private preimages and input digests never
    /// escape through this route. Replays retain the originally accepted review.
    pub(crate) fn impact_review(&self, operation_id: &str) -> Result<Option<ImpactReport>, String> {
        let record = self.read(operation_id)?;
        validate_review(
            &record.impact_review,
            operation_id,
            record.kind,
            &record.policy_identity,
        )?;
        Ok(record.impact_review)
    }

    fn plan_inner(
        &self,
        operation_id: &str,
        kind: OperationKind,
        requests: Vec<RequestedChange>,
        policy: &EffectivePolicySnapshot,
        expected_documents: &std::collections::BTreeMap<PathBuf, Option<String>>,
        metadata: PlanMetadata,
    ) -> Result<OperationStatus, String> {
        let PlanMetadata {
            caller_intent_digest,
            shell_precondition,
            no_op,
            impact_review,
        } = metadata;
        if expected_documents.iter().any(|(path, document)| {
            !requests.iter().any(|request| &request.target == path)
                || document
                    .as_ref()
                    .is_some_and(|text| text.len() > MAX_SETUP_FILE_BYTES)
        }) {
            return Err(
                "expected preimage is oversized or does not belong to a planned target".into(),
            );
        }
        let path = self.path(operation_id)?;
        let original_request_digest = digest(&(
            kind,
            &self.operator,
            env!("CARGO_PKG_VERSION"),
            &requests,
            expected_documents,
            &shell_precondition,
        ))?;
        let request_digest = if no_op {
            digest(&(
                "tirith-noop-v1",
                &original_request_digest,
                policy.resolution_cwd(),
            ))?
        } else {
            original_request_digest
        };
        let request_digest = bind_review_digest(request_digest, &impact_review)?;
        if let Some(existing) = fs_helpers::read_to_string_scoped(&path, &self.scope)? {
            let record: Journal = serde_json::from_str(&existing)
                .map_err(|_| "existing operation journal is malformed")?;
            if record.schema_version != SCHEMA
                || record.operation_id != operation_id
                || record.operator != self.operator
                || record.kind != kind
                || record.resolution_cwd.as_deref() != policy.resolution_cwd()
                || !same_request(&record, &request_digest, caller_intent_digest.as_deref())
            {
                return Err("operation ID already belongs to a different operator, kind or immutable payload".into());
            }
            return Ok(record.public());
        }
        validate_review(&impact_review, operation_id, kind, &policy.identity)?;
        policy.revalidate_for_mutation().map_err(refresh)?;
        if let Some(precondition) = &shell_precondition {
            precondition.validate().map_err(refresh)?;
        }
        if no_op
            && (!requests.is_empty()
                || !expected_documents.is_empty()
                || caller_intent_digest.is_none())
        {
            return Err(
                "a no-change operation must contain only an immutable caller intent".into(),
            );
        }
        if (!no_op && requests.is_empty()) || requests.len() > MAX_STEPS {
            return Err(format!("operation requires 1–{MAX_STEPS} steps"));
        }
        let mut steps = Vec::with_capacity(requests.len());
        for request in requests {
            if !request.target.is_absolute()
                || !request.scope_root.is_absolute()
                || !request.target.starts_with(&request.scope_root)
                || request
                    .target
                    .components()
                    .any(|c| matches!(c, std::path::Component::ParentDir))
            {
                return Err("mutation target must be an absolute contained path".into());
            }
            if request.target.starts_with(&self.root) {
                return Err("an operation cannot edit its own journal".into());
            }
            preflight_target(kind, &request.scope_root, &request.target, policy)?;
            if steps
                .iter()
                .any(|step: &Step| step.target == request.target)
            {
                return Err("combine changes to one file into a single owned step".into());
            }
            if let Edit::AuditRotation(plan) = request.edit {
                if kind != OperationKind::RotateAudit || plan.operation_id() != operation_id {
                    return Err("audit rotation requires its exact typed operation ID".into());
                }
                if super::audit_service::observe(&plan, &request.target, &request.scope_root)?
                    != tirith_core::audit::retention::RotationState::Original
                {
                    return Err(refresh("audit history changed before planning"));
                }
                steps.push(Step {
                    scope_identity: ScopeIdentity::capture(&request.scope_root)?,
                    target: request.target,
                    scope_root: request.scope_root,
                    edit: OwnedEdit::AuditRotation(plan),
                    activation: true,
                    description: request.description,
                    state: StepState::Pending,
                    authority_document: None,
                    undo_document: None,
                });
                continue;
            }
            if let Edit::AuditSegment(plan) = request.edit {
                if plan.kind() != kind || plan.operation_id() != operation_id {
                    return Err("audit segment operation identity changed".into());
                }
                plan.validate_target(&request.target, &request.scope_root)?;
                if plan.observe()? != super::audit_segments::SegmentState::Original {
                    return Err(refresh("segment files changed before planning"));
                }
                steps.push(Step {
                    scope_identity: ScopeIdentity::capture(&request.scope_root)?,
                    target: request.target,
                    scope_root: request.scope_root,
                    edit: OwnedEdit::AuditSegment(plan),
                    activation: true,
                    description: request.description,
                    state: StepState::Pending,
                    authority_document: None,
                    undo_document: None,
                });
                continue;
            }
            if matches!(&request.edit, Edit::PrivateFile(_)) {
                fs_helpers::read_snapshot_scoped(&request.target, &request.scope_root)?
                    .require_private()?;
            }
            let live = fs_helpers::read_to_string_scoped(&request.target, &request.scope_root)?;
            let before = expected_documents
                .get(&request.target)
                .cloned()
                .unwrap_or(live);
            let edit = match request.edit {
                Edit::AuditRotation(_) | Edit::AuditSegment(_) => {
                    unreachable!("handled by retained audit backend")
                }
                Edit::WholeFile(after) => OwnedEdit::WholeFile { before, after },
                Edit::PrivateFile(after) => OwnedEdit::PrivateFile { before, after },
                #[cfg(test)]
                Edit::JsonField { pointer, value } => {
                    let document = parse_document(before.as_deref(), false)?;
                    validate_pointer(&pointer)?;
                    OwnedEdit::Field {
                        yaml: false,
                        before: document.pointer(&pointer).cloned(),
                        pointer,
                        after: value,
                    }
                }
                Edit::YamlFields(values) => capture_fields(before.as_deref(), true, values)?,
                Edit::ShellHook { block } => {
                    if let Some(block) = &block {
                        validate_hook_payload(block)?;
                    }
                    OwnedEdit::ShellHook {
                        before: hook_block(before.as_deref().unwrap_or_default())?,
                        after: block,
                    }
                }
            };
            let scope_identity = ScopeIdentity::capture(&request.scope_root)?;
            let mut step = Step {
                scope_identity,
                target: request.target,
                scope_root: request.scope_root,
                edit,
                activation: request.activation,
                description: request.description,
                state: StepState::Pending,
                authority_document: None,
                undo_document: None,
            };
            // Preflight the actual resulting document and size before journaling.
            let current = read_step(&step)?;
            let transformed = transform(&step.edit, current.as_deref(), false)?;
            if transformed
                .as_ref()
                .is_some_and(|s| s.len() > MAX_SETUP_FILE_BYTES)
            {
                return Err("planned output exceeds setup file limit".into());
            }
            if policy.input_revisions.iter().any(|input| {
                input
                    .source
                    .path
                    .as_ref()
                    .is_some_and(|path| Path::new(path) == step.target)
            }) {
                let after = transformed.or(current.clone());
                let compensation = transform(&step.edit, after.as_deref(), true)?.or(after.clone());
                step.authority_document = Some(AuthorityDocument {
                    before: current.clone(),
                    after,
                    compensation,
                });
            }
            steps.push(step);
        }
        steps.sort_by_key(|step| step.activation);
        // The digest includes private owned preimages and payload, never public output.
        let original_payload_digest = digest(&(
            kind,
            &self.operator,
            env!("CARGO_PKG_VERSION"),
            &steps,
            &shell_precondition,
        ))?;
        let payload_digest = if no_op {
            digest(&(
                "tirith-noop-v1",
                &original_payload_digest,
                policy.resolution_cwd(),
            ))?
        } else {
            original_payload_digest
        };
        let payload_digest = bind_review_digest(payload_digest, &impact_review)?;
        let record = Journal {
            schema_version: SCHEMA,
            operation_id: operation_id.into(),
            kind,
            operator: self.operator.clone(),
            client_version: env!("CARGO_PKG_VERSION").into(),
            payload_digest,
            request_digest,
            caller_intent_digest,
            no_op,
            impact_review,
            policy_identity: policy.identity.clone(),
            authorization: policy.private_replay_guard(),
            external_authorization: policy.private_external_inputs_guard(
                &steps.iter().map(|step| step.target.clone()).collect(),
            ),
            resolution_cwd: policy.resolution_cwd().map(str::to_owned),
            undo_external_authorization: None,
            shell_precondition,
            created_at: now(),
            updated_at: now(),
            state: if no_op {
                JobState::Completed
            } else {
                JobState::Planned
            },
            active_action: None,
            detail: no_op.then(|| {
                "No settings changed; this operation ID retains the accepted intent".into()
            }),
            steps,
        };
        fs_helpers::ensure_private_directory(&self.root, &self.scope)?;
        fs_helpers::transactional_update_checked(
            &path,
            &self.scope,
            false,
            |snapshot| {
                snapshot.require_private()?;
                if let Some(text) = snapshot.text(&path)? {
                    let old: Journal = serde_json::from_str(text)
                        .map_err(|_| "existing operation journal is malformed")?;
                    if old.operator != record.operator
                        || old.kind != record.kind
                        || old.resolution_cwd != record.resolution_cwd
                        || !same_request(
                            &old,
                            &record.request_digest,
                            record.caller_intent_digest.as_deref(),
                        )
                    {
                        return Err("operation ID already belongs to a different operator, kind or immutable payload".into());
                    }
                    return Ok(FileUpdate::unchanged());
                }
                Ok(FileUpdate::write_text(
                    serde_json::to_string(&record).map_err(|e| e.to_string())?,
                    0o600,
                ))
            },
            || {
                // A concurrent identical planner may already have committed
                // this journal and even finished applying it. That is replay,
                // not fresh authorization of the old preimages.
                if let Some(existing) = fs_helpers::read_to_string_scoped(&path, &self.scope)? {
                    let existing: Journal = serde_json::from_str(&existing)
                        .map_err(|_| "existing operation journal is malformed")?;
                    if existing.operator == record.operator
                        && existing.kind == record.kind
                        && existing.resolution_cwd == record.resolution_cwd
                        && same_request(
                            &existing,
                            &record.request_digest,
                            record.caller_intent_digest.as_deref(),
                        )
                    {
                        return Ok(());
                    }
                    return Err(
                        "operation ID already belongs to a different immutable payload".into(),
                    );
                }
                policy.revalidate_for_mutation().map_err(refresh)?;
                if let Some(precondition) = &record.shell_precondition {
                    precondition.validate().map_err(refresh)?;
                }
                for step in &record.steps {
                    preflight_target(record.kind, &step.scope_root, &step.target, policy)?;
                    step.scope_identity.validate()?;
                    if matches!(
                        step.edit,
                        OwnedEdit::AuditRotation(_) | OwnedEdit::AuditSegment(_)
                    ) {
                        // Plan is only a preview. Apply rechecks exact bytes under
                        // the native log lock before any archive or active write.
                        continue;
                    }
                    let current = read_step(step)?;
                    if !owned_matches(&step.edit, current.as_deref(), false)? {
                        return Err(refresh("owned field changed before plan publication"));
                    }
                }
                Ok(())
            },
        )?;
        self.status(operation_id)
    }

    pub(super) fn rotation_plan(
        &self,
        operation_id: &str,
    ) -> Result<tirith_core::audit::retention::RotationPlan, String> {
        let record = self.read(operation_id)?;
        if record.kind != OperationKind::RotateAudit || !record.state.completed() {
            return Err("source must be a completed recorded rotation".into());
        }
        record
            .steps
            .iter()
            .find_map(|step| match &step.edit {
                OwnedEdit::AuditRotation(plan) => Some(plan.clone()),
                _ => None,
            })
            .ok_or("rotation journal has no retained segment payload".into())
    }

    /// Read the private persisted result without crash reconciliation or writes.
    pub(crate) fn read_status(&self, operation_id: &str) -> Result<OperationStatus, String> {
        self.read(operation_id).map(|record| record.public())
    }

    pub(crate) fn status(&self, operation_id: &str) -> Result<OperationStatus, String> {
        let record = self.read(operation_id)?;
        if matches!(record.state, JobState::Running | JobState::CancelRequested) {
            let lock_path = self.path(operation_id)?.with_extension("execution-lock");
            if let Some(_lock) = fs_helpers::try_lock_operation(&lock_path, &self.scope)? {
                let record = self.read(operation_id)?;
                if matches!(record.state, JobState::Running | JobState::CancelRequested) {
                    return Ok(self.update(operation_id, |record| {
                        record.state = JobState::RecoveryRequired;
                        record.detail = Some("worker ended without a terminal journal result; inspect owned postconditions before retry or undo".into());
                        Ok(())
                    })?.public());
                }
                return Ok(record.public());
            }
        }
        Ok(record.public())
    }

    pub(crate) fn cancel(&self, operation_id: &str) -> Result<OperationStatus, String> {
        Ok(self
            .update(operation_id, |record| {
                if !record.state.completed() && record.state != JobState::Cancelled {
                    record.state = if record
                        .steps
                        .iter()
                        .all(|step| step.state == StepState::Pending)
                    {
                        JobState::Cancelled
                    } else {
                        JobState::CancelRequested
                    };
                }
                Ok(())
            })?
            .public())
    }

    /// File-only replay is idempotent: after an interrupted journal write, owned
    /// postconditions are checked before any further publication. No subprocess
    /// or network side effect is hidden in this service.
    pub(crate) fn apply(
        &self,
        operation_id: &str,
        policy: &EffectivePolicySnapshot,
    ) -> Result<OperationStatus, String> {
        let record = self.read(operation_id)?;
        if record.no_op {
            return Ok(record.public());
        }
        let lock_path = self.path(operation_id)?.with_extension("execution-lock");
        let Some(_execution_lock) = fs_helpers::try_lock_operation(&lock_path, &self.scope)? else {
            return self.status(operation_id);
        };
        self.apply_locked(operation_id, policy)
    }

    /// The caller retains the execution lock on this thread. Authorization and
    /// all journal state changes occur only after that lock has been acquired.
    fn apply_locked(
        &self,
        operation_id: &str,
        policy: &EffectivePolicySnapshot,
    ) -> Result<OperationStatus, String> {
        let started = Instant::now();
        let record = self.read(operation_id)?;
        if record.state.completed() || record.state == JobState::Cancelled {
            return Ok(record.public());
        }
        if record.undo_external_authorization.is_some() {
            return Err(refresh(
                "undo has begun; finish recovery or create a new plan",
            ));
        }
        let refreshed = record
            .steps
            .iter()
            .any(|step| step.state != StepState::Pending)
            .then(|| policy.refresh_runtime());
        let initial_policy = refreshed.as_ref().unwrap_or(policy);
        if let Err(error) = self.authorize(&record, initial_policy) {
            return self.refuse_apply(operation_id, error);
        }
        let record = self.read(operation_id)?;
        if record.state.completed() || record.state == JobState::Cancelled {
            return Ok(record.public());
        }
        if record.client_version != env!("CARGO_PKG_VERSION") {
            return Err(refresh("client changed; create a compatible plan"));
        }
        if self.all_postconditions(&record)? {
            return Ok(self.update(operation_id, |record| { let recovery = record.steps.iter().any(|s| matches!(s.state, StepState::Applying | StepState::AppliedWithRecovery));
                record.state = if recovery { JobState::CompletedWithRecovery } else { JobState::Completed };
                record.detail = recovery.then(|| "owned postconditions are present; an interrupted publication/journal boundary requires retained-recovery review".into());
                for step in &mut record.steps { step.state = if recovery { StepState::AppliedWithRecovery } else { StepState::Applied }; } Ok(()) })?.public());
        }
        if let Err(error) = self.authorize(&record, initial_policy) {
            return self.refuse_apply(operation_id, error);
        }
        self.update(operation_id, |record| {
            if !matches!(
                record.state,
                JobState::CancelRequested | JobState::Cancelled
            ) {
                record.state = JobState::Running;
                record.active_action = Some(JobAction::Apply);
            }
            Ok(())
        })?;
        for index in 0..record.steps.len() {
            let live = self.read(operation_id)?;
            if matches!(live.state, JobState::Cancelled | JobState::CancelRequested)
                || started.elapsed() >= JOB_TIMEOUT
            {
                return Ok(self
                    .update(operation_id, |record| {
                        let applied = record.steps.iter().any(|s| {
                            matches!(s.state, StepState::Applied | StepState::AppliedWithRecovery)
                        });
                        record.state = if applied {
                            JobState::PartiallyApplied
                        } else {
                            JobState::Cancelled
                        };
                        record.detail = Some(
                            if started.elapsed() >= JOB_TIMEOUT {
                                "job deadline reached"
                            } else {
                                "cancelled before the next publication"
                            }
                            .into(),
                        );
                        Ok(())
                    })?
                    .public());
            }
            let step = live.steps[index].clone();
            if matches!(
                step.state,
                StepState::Applied | StepState::AppliedWithRecovery
            ) {
                continue;
            }
            // Resolve after prior owned publications and outside the retained
            // filesystem writer lock. Revalidation callbacks never do network.
            let refreshed_step = live
                .steps
                .iter()
                .any(|step| step.state != StepState::Pending)
                .then(|| policy.refresh_runtime());
            let step_policy = refreshed_step.as_ref().unwrap_or(initial_policy);
            if let Err(error) = self.authorize(&live, step_policy) {
                return self.refuse_apply(operation_id, error);
            }
            self.update(operation_id, |record| {
                record.steps[index].state = StepState::Applying;
                Ok(())
            })?;
            let outcome = if let OwnedEdit::AuditRotation(plan) = &step.edit {
                super::audit_service::mutate(
                    plan,
                    &step.target,
                    &step.scope_root,
                    step_policy,
                    false,
                    || {
                        let current = self.read(operation_id)?;
                        if matches!(
                            current.state,
                            JobState::Cancelled | JobState::CancelRequested
                        ) {
                            return Err(
                                "operation cancellation requested before publication".into()
                            );
                        }
                        if started.elapsed() >= JOB_TIMEOUT {
                            return Err("operation deadline reached before publication".into());
                        }
                        self.authorize_except(&current, step_policy, Some(index))
                    },
                )
            } else if let OwnedEdit::AuditSegment(plan) = &step.edit {
                plan.mutate(step_policy, false, || {
                    let current = self.read(operation_id)?;
                    if matches!(
                        current.state,
                        JobState::Cancelled | JobState::CancelRequested
                    ) {
                        return Err("operation cancellation requested before publication".into());
                    }
                    if started.elapsed() >= JOB_TIMEOUT {
                        return Err("operation deadline reached before publication".into());
                    }
                    self.authorize_except(&current, step_policy, Some(index))
                })
            } else {
                super::fs_transaction::transactional_update_authorized(
                    &step.target,
                    &step.scope_root,
                    false,
                    |snapshot| {
                        if matches!(&step.edit, OwnedEdit::PrivateFile { .. }) {
                            snapshot.require_private()?;
                        }
                        let current = snapshot.text(&step.target)?;
                        match transform(&step.edit, current, false)? {
                            Some(text) => Ok(step_update(&step, text)),
                            None => Ok(FileUpdate::unchanged()),
                        }
                    },
                    || {
                        let current = self.read(operation_id)?;
                        if matches!(
                            current.state,
                            JobState::Cancelled | JobState::CancelRequested
                        ) {
                            return Err(
                                "operation cancellation requested before publication".into()
                            );
                        }
                        if started.elapsed() >= JOB_TIMEOUT {
                            return Err("operation deadline reached before publication".into());
                        }
                        self.authorize(&current, step_policy)
                    },
                    |bytes| {
                        authorize_publication(
                            live.kind,
                            &step.scope_root,
                            &step.target,
                            bytes,
                            step_policy,
                        )
                    },
                )
            };
            match outcome {
                Ok(outcome) => {
                    self.update(operation_id, |record| {
                        record.steps[index].state =
                            if outcome == TransactionOutcome::WrittenWithRecovery {
                                StepState::AppliedWithRecovery
                            } else {
                                StepState::Applied
                            };
                        Ok(())
                    })?;
                }
                Err(error) => {
                    return Ok(self
                        .update(operation_id, |record| {
                            record.state = if error.starts_with("refresh-required:") {
                                JobState::RefreshRequired
                            } else if error == "operation cancellation requested before publication"
                            {
                                if record.steps.iter().any(|s| {
                                    matches!(
                                        s.state,
                                        StepState::Applying
                                            | StepState::Applied
                                            | StepState::AppliedWithRecovery
                                    )
                                }) {
                                    JobState::PartiallyApplied
                                } else {
                                    JobState::Cancelled
                                }
                            } else {
                                JobState::RecoveryRequired
                            };
                            record.detail = Some(error.clone());
                            Ok(())
                        })?
                        .public());
                }
            }
        }
        Ok(self
            .update(operation_id, |record| {
                record.state = if record
                    .steps
                    .iter()
                    .any(|s| s.state == StepState::AppliedWithRecovery)
                {
                    JobState::CompletedWithRecovery
                } else {
                    JobState::Completed
                };
                record.detail = None;
                Ok(())
            })?
            .public())
    }

    fn authorize(&self, record: &Journal, policy: &EffectivePolicySnapshot) -> Result<(), String> {
        self.authorize_except(record, policy, None)
    }

    fn authorize_except(
        &self,
        record: &Journal,
        policy: &EffectivePolicySnapshot,
        except: Option<usize>,
    ) -> Result<(), String> {
        if let Some(review) = &record.impact_review {
            let age = chrono::Utc::now()
                .signed_duration_since(review.evaluated_at)
                .num_seconds();
            if !(0..tirith_core::policy_rollout::EVIDENCE_MAX_AGE_SECONDS).contains(&age) {
                return Err(refresh(
                    "policy impact review is stale or future-dated; prepare fresh evidence",
                ));
            }
        }
        if let Some(precondition) = &record.shell_precondition {
            precondition.validate().map_err(refresh)?;
        }
        if record.operator != self.operator {
            return Err(refresh("operator changed"));
        }
        policy.revalidate_for_mutation().map_err(refresh)?;
        if record.resolution_cwd.as_deref() != policy.resolution_cwd() {
            return Err(refresh("policy resolution scope changed"));
        }
        let excluded = record
            .steps
            .iter()
            .map(|step| step.target.clone())
            .collect();
        if record.external_authorization != policy.private_external_inputs_guard(&excluded) {
            return Err(refresh("external policy inputs changed since planning"));
        }
        self.validate_owned_generations_except(record, except)?;
        for step in &record.steps {
            preflight_target(record.kind, &step.scope_root, &step.target, policy)?;
        }
        Ok(())
    }

    fn refuse_apply(&self, operation_id: &str, error: String) -> Result<OperationStatus, String> {
        Ok(self
            .update(operation_id, |record| {
                record.state = JobState::RefreshRequired;
                record.detail = Some(error.clone());
                Ok(())
            })?
            .public())
    }

    fn validate_owned_generations(&self, record: &Journal) -> Result<(), String> {
        self.validate_owned_generations_except(record, None)
    }

    fn validate_owned_generations_except(
        &self,
        record: &Journal,
        except: Option<usize>,
    ) -> Result<(), String> {
        for (index, step) in record.steps.iter().enumerate() {
            if except == Some(index)
                && matches!(
                    step.edit,
                    OwnedEdit::AuditRotation(_) | OwnedEdit::AuditSegment(_)
                )
            {
                step.scope_identity.validate()?;
                continue;
            }
            if let OwnedEdit::AuditSegment(plan) = &step.edit {
                step.scope_identity.validate()?;
                plan.validate_target(&step.target, &step.scope_root)?;
                if !segment_state_matches(step.state, plan.observe()?) {
                    return Err(refresh("owned segment generation changed"));
                }
                continue;
            }
            if let OwnedEdit::AuditRotation(plan) = &step.edit {
                step.scope_identity.validate()?;
                let observed = super::audit_service::observe(plan, &step.target, &step.scope_root)?;
                if !audit_state_matches(step.state, observed) {
                    return Err(refresh("audit generation changed"));
                }
                continue;
            }
            step.scope_identity.validate()?;
            let current = read_step(step)?;
            let authority = if record.undo_external_authorization.is_some() {
                step.undo_document
                    .as_ref()
                    .or(step.authority_document.as_ref())
            } else {
                step.authority_document.as_ref()
            };
            let accepts = |after| -> Result<bool, String> {
                if let Some(authority) = authority {
                    Ok(current
                        == if after {
                            authority.after.clone()
                        } else {
                            authority.before.clone()
                        })
                } else {
                    owned_matches(&step.edit, current.as_deref(), after)
                }
            };
            let valid = match step.state {
                StepState::Pending => accepts(false)?,
                StepState::Applied | StepState::AppliedWithRecovery => accepts(true)?,
                StepState::Applying => accepts(false)? || accepts(true)?,
                StepState::Compensated
                | StepState::CompensatedWithRecovery
                | StepState::Compensating => {
                    let compensated = if let Some(authority) = authority {
                        current == authority.compensation
                    } else if matches!(
                        &step.edit,
                        OwnedEdit::WholeFile { before: None, .. }
                            | OwnedEdit::PrivateFile { before: None, .. }
                    ) {
                        current.as_deref() == Some("")
                    } else {
                        accepts(false)?
                    };
                    compensated || (step.state == StepState::Compensating && accepts(true)?)
                }
            };
            if !valid {
                return Err(refresh(
                    "owned generation or authorization document changed",
                ));
            }
        }
        Ok(())
    }

    fn capture_undo_documents(
        &self,
        record: &Journal,
    ) -> Result<Vec<Option<AuthorityDocument>>, String> {
        record
            .steps
            .iter()
            .map(|step| {
                step.scope_identity.validate()?;
                if let OwnedEdit::AuditSegment(plan) = &step.edit {
                    plan.validate_target(&step.target, &step.scope_root)?;
                    if plan.irreversible() { return Err("segment deletion is irreversible; checkpoint and deletion record remain".into()); }
                    if !segment_state_matches(step.state, plan.observe()?) { return Err(refresh("owned exported segment changed before undo")); }
                    return Ok(None);
                }
                if let OwnedEdit::AuditRotation(plan) = &step.edit {
                    let observed = super::audit_service::observe(plan, &step.target, &step.scope_root)?;
                    if !audit_state_matches(step.state, observed)
                        || observed == tirith_core::audit::retention::RotationState::AppliedWithAdditionalRecords {
                        return Err(refresh("later audit records prevent compensation"));
                    }
                    return Ok(None);
                }
                let current = read_step(step)?;
                let valid = match step.state {
                    StepState::Pending => owned_matches(&step.edit, current.as_deref(), false)?,
                    StepState::Applying => {
                        owned_matches(&step.edit, current.as_deref(), false)?
                            || owned_matches(&step.edit, current.as_deref(), true)?
                    }
                    StepState::Applied | StepState::AppliedWithRecovery => {
                        owned_matches(&step.edit, current.as_deref(), true)?
                    }
                    _ => false,
                };
                if !valid {
                    return Err(refresh("owned fields changed before undo authorization"));
                }
                let compensation = if step.state == StepState::Pending {
                    current.clone()
                } else {
                    transform(&step.edit, current.as_deref(), true)?.or(current.clone())
                };
                Ok(Some(AuthorityDocument {
                    before: current.clone(),
                    after: current,
                    compensation,
                }))
            })
            .collect()
    }

    fn all_postconditions(&self, record: &Journal) -> Result<bool, String> {
        for step in &record.steps {
            step.scope_identity.validate()?;
            if let OwnedEdit::AuditSegment(plan) = &step.edit {
                plan.validate_target(&step.target, &step.scope_root)?;
                if plan.observe()? != super::audit_segments::SegmentState::Applied {
                    return Ok(false);
                }
                continue;
            }
            if let OwnedEdit::AuditRotation(plan) = &step.edit {
                if !matches!(super::audit_service::observe(plan, &step.target, &step.scope_root)?,
                    tirith_core::audit::retention::RotationState::Applied |
                    tirith_core::audit::retention::RotationState::AppliedWithAdditionalRecords)
                {
                    return Ok(false);
                }
                continue;
            }
            let current = read_step(step)?;
            if !owned_matches(&step.edit, current.as_deref(), true)? {
                return Ok(false);
            }
        }
        Ok(true)
    }

    /// Undo touches only owned fields that still equal their planned generation.
    /// A new file's compensation is an empty file; deletion is deliberately not
    /// inferred from a pathname, preserving later unrelated content safely.
    pub(crate) fn undo(
        &self,
        operation_id: &str,
        policy: &EffectivePolicySnapshot,
    ) -> Result<OperationStatus, String> {
        let record = self.read(operation_id)?;
        if record.kind == OperationKind::DeleteAuditSegment {
            return Err(
                "segment deletion is irreversible; checkpoint and deletion record remain".into(),
            );
        }
        if record.no_op {
            return Ok(record.public());
        }
        let lock_path = self.path(operation_id)?.with_extension("execution-lock");
        let _execution_lock = fs_helpers::try_lock_operation(&lock_path, &self.scope)?
            .ok_or("operation is already applying or undoing; wait for its result")?;
        self.undo_locked(operation_id, policy)
    }

    fn undo_locked(
        &self,
        operation_id: &str,
        policy: &EffectivePolicySnapshot,
    ) -> Result<OperationStatus, String> {
        let started = Instant::now();
        let record = self.read(operation_id)?;
        if record.no_op
            || matches!(
                record.state,
                JobState::Undone | JobState::UndoneWithRecovery | JobState::Cancelled
            )
        {
            return Ok(record.public());
        }
        let refreshed = record
            .undo_external_authorization
            .is_some()
            .then(|| policy.refresh_runtime());
        let initial_policy = refreshed.as_ref().unwrap_or(policy);
        if let Some(precondition) = &record.shell_precondition {
            precondition.validate_undo().map_err(refresh)?;
        }
        initial_policy.revalidate_for_mutation().map_err(refresh)?;
        if record.resolution_cwd.as_deref() != initial_policy.resolution_cwd() {
            return Err(refresh("policy resolution scope changed"));
        }
        let undo_documents = if record.undo_external_authorization.is_some() {
            self.validate_owned_generations(&record)?;
            None
        } else {
            Some(self.capture_undo_documents(&record)?)
        };
        for step in &record.steps {
            preflight_target(record.kind, &step.scope_root, &step.target, initial_policy)?;
        }
        let record = self.read(operation_id)?;
        if matches!(
            record.state,
            JobState::Undone | JobState::UndoneWithRecovery
        ) {
            return Ok(record.public());
        }
        // Undo starts a new authorization decision, then pins external inputs
        // for every compensation and restart. Own restored inputs may rebase.
        let excluded = record
            .steps
            .iter()
            .map(|step| step.target.clone())
            .collect();
        let guard = initial_policy.private_external_inputs_guard(&excluded);
        initial_policy.revalidate_for_mutation().map_err(refresh)?;
        self.update(operation_id, |record| {
            if matches!(
                record.state,
                JobState::CancelRequested | JobState::Cancelled
            ) {
                return Err("undo cancellation requested before publication".into());
            }
            if record.undo_external_authorization.is_none() {
                let documents = undo_documents
                    .as_ref()
                    .ok_or("undo baseline was not captured")?;
                if documents.len() != record.steps.len() {
                    return Err(refresh("undo step set changed"));
                }
                for (step, document) in record.steps.iter_mut().zip(documents) {
                    step.undo_document = document.clone();
                }
                record.undo_external_authorization = Some(guard.clone());
            }
            record.state = JobState::Running;
            record.active_action = Some(JobAction::Undo);
            Ok(())
        })?;
        for index in (0..record.steps.len()).rev() {
            let live = self.read(operation_id)?;
            let step = live.steps[index].clone();
            if matches!(
                step.state,
                StepState::Pending | StepState::Compensated | StepState::CompensatedWithRecovery
            ) {
                continue;
            }
            let refreshed_step = live
                .steps
                .iter()
                .any(|step| {
                    matches!(
                        step.state,
                        StepState::Compensating
                            | StepState::Compensated
                            | StepState::CompensatedWithRecovery
                    )
                })
                .then(|| policy.refresh_runtime());
            let step_policy = refreshed_step.as_ref().unwrap_or(initial_policy);
            let outcome = (|| {
                self.authorize_undo(&live, step_policy)?;
                if started.elapsed() >= JOB_TIMEOUT {
                    return Err("undo deadline reached before the next compensation".into());
                }
                self.update(operation_id, |record| {
                    record.steps[index].state = StepState::Compensating;
                    Ok(())
                })?;
                if let OwnedEdit::AuditRotation(plan) = &step.edit {
                    return super::audit_service::mutate(
                        plan,
                        &step.target,
                        &step.scope_root,
                        step_policy,
                        true,
                        || {
                            if started.elapsed() >= JOB_TIMEOUT {
                                return Err("undo deadline reached before publication".into());
                            }
                            self.authorize_undo_except(
                                &self.read(operation_id)?,
                                step_policy,
                                Some(index),
                            )
                        },
                    );
                }
                if let OwnedEdit::AuditSegment(plan) = &step.edit {
                    return plan.mutate(step_policy, true, || {
                        if started.elapsed() >= JOB_TIMEOUT {
                            return Err("undo deadline reached before publication".into());
                        }
                        self.authorize_undo_except(
                            &self.read(operation_id)?,
                            step_policy,
                            Some(index),
                        )
                    });
                }
                super::fs_transaction::transactional_update_authorized(
                    &step.target,
                    &step.scope_root,
                    false,
                    |snapshot| {
                        if matches!(&step.edit, OwnedEdit::PrivateFile { .. }) {
                            snapshot.require_private()?;
                        }
                        match transform(&step.edit, snapshot.text(&step.target)?, true)? {
                            Some(text) => Ok(step_update(&step, text)),
                            None => Ok(FileUpdate::unchanged()),
                        }
                    },
                    || {
                        if started.elapsed() >= JOB_TIMEOUT {
                            return Err("undo deadline reached before publication".into());
                        }
                        self.authorize_undo(&self.read(operation_id)?, step_policy)
                    },
                    |bytes| {
                        authorize_publication(
                            live.kind,
                            &step.scope_root,
                            &step.target,
                            bytes,
                            step_policy,
                        )
                    },
                )
            })();
            match outcome {
                Ok(outcome) => {
                    self.update(operation_id, |record| {
                        record.steps[index].state =
                            if outcome == TransactionOutcome::WrittenWithRecovery {
                                StepState::CompensatedWithRecovery
                            } else {
                                StepState::Compensated
                            };
                        Ok(())
                    })?;
                }
                Err(error) => {
                    self.update(operation_id, |record| {
                        record.state = JobState::RecoveryRequired;
                        record.detail = Some(error.clone());
                        Ok(())
                    })?;
                    return Err(error);
                }
            }
        }
        Ok(self
            .update(operation_id, |record| {
                let recovery = record
                    .steps
                    .iter()
                    .any(|step| step.state == StepState::CompensatedWithRecovery);
                record.state = if recovery {
                    JobState::UndoneWithRecovery
                } else {
                    JobState::Undone
                };
                record.detail = recovery
                    .then(|| "undo completed with retained platform recovery material".into());
                Ok(())
            })?
            .public())
    }

    fn authorize_undo(
        &self,
        record: &Journal,
        policy: &EffectivePolicySnapshot,
    ) -> Result<(), String> {
        self.authorize_undo_except(record, policy, None)
    }

    fn authorize_undo_except(
        &self,
        record: &Journal,
        policy: &EffectivePolicySnapshot,
        except: Option<usize>,
    ) -> Result<(), String> {
        if let Some(precondition) = &record.shell_precondition {
            precondition.validate_undo().map_err(refresh)?;
        }
        if matches!(
            record.state,
            JobState::CancelRequested | JobState::Cancelled
        ) {
            return Err("undo cancellation requested before publication".into());
        }
        policy.revalidate_for_mutation().map_err(refresh)?;
        if record.resolution_cwd.as_deref() != policy.resolution_cwd() {
            return Err(refresh("policy resolution scope changed"));
        }
        let excluded = record
            .steps
            .iter()
            .map(|step| step.target.clone())
            .collect();
        if record.undo_external_authorization.as_ref()
            != Some(&policy.private_external_inputs_guard(&excluded))
        {
            return Err(refresh("external policy inputs changed since undo began"));
        }
        self.validate_owned_generations_except(record, except)?;
        for step in &record.steps {
            preflight_target(record.kind, &step.scope_root, &step.target, policy)?;
        }
        Ok(())
    }

    /// Bounded worker admission keeps long work out of HTTP request handlers.
    /// Excess requests are rejected explicitly; no unbounded pending queue.
    pub(crate) fn apply_async(
        &self,
        operation_id: String,
        policy: EffectivePolicySnapshot,
    ) -> Result<OperationStatus, String> {
        self.spawn_job(operation_id, policy, false)
    }

    pub(crate) fn undo_async(
        &self,
        operation_id: String,
        policy: EffectivePolicySnapshot,
    ) -> Result<OperationStatus, String> {
        if self.read(&operation_id)?.kind == OperationKind::DeleteAuditSegment {
            return Err(
                "segment deletion is irreversible; checkpoint and deletion record remain".into(),
            );
        }
        self.spawn_job(operation_id, policy, true)
    }

    fn spawn_job(
        &self,
        operation_id: String,
        policy: EffectivePolicySnapshot,
        undo: bool,
    ) -> Result<OperationStatus, String> {
        let action = if undo {
            JobAction::Undo
        } else {
            JobAction::Apply
        };
        let path = self.path(&operation_id)?;
        let permit = {
            let mut reservations = worker_reservations()
                .lock()
                .unwrap_or_else(|error| error.into_inner());
            if let Some(active) = reservations.get(&path) {
                if *active != action {
                    return Err("a different action is already active for this operation".into());
                }
                let current = self.read(&operation_id)?.public();
                // The first worker has reserved capacity but may not have
                // published acceptance yet. Do not return an old terminal or
                // Planned response as if it represented admitted work.
                if current.active_action == Some(action) || action.already_finished(current.state) {
                    return Ok(current);
                }
                return Err(
                    "operation admission is in progress; poll its status before retrying".into(),
                );
            }
            let current = self.read(&operation_id)?.public();
            if current.no_op || action.already_finished(current.state) {
                return Ok(current);
            }
            if ACTIVE_JOBS.load(Ordering::Acquire) >= MAX_ACTIVE_JOBS {
                return Err(
                    "operation worker capacity reached; retry after an active job completes".into(),
                );
            }
            reservations.insert(path.clone(), action);
            ACTIVE_JOBS.fetch_add(1, Ordering::AcqRel);
            WorkerPermit { path }
        };
        let service = self.clone();
        let (ready, accepted) = std::sync::mpsc::sync_channel(1);
        std::thread::Builder::new()
            .name("tirith-mutation".into())
            .spawn(move || {
                let _permit = permit;
                // Native Windows mutex ownership belongs to the thread that
                // waits on it. Acquire and release it inside this worker.
                let lock_path = match service.path(&operation_id) {
                    Ok(path) => path.with_extension("execution-lock"),
                    Err(error) => {
                        let _ = ready.send(Err(error));
                        return;
                    }
                };
                let _execution_lock = match fs_helpers::try_lock_operation(&lock_path, &service.scope) {
                    Ok(Some(lock)) => lock,
                    Ok(None) => {
                        let result = service.read(&operation_id).and_then(|record| {
                            if !matches!(record.state, JobState::Running | JobState::CancelRequested) {
                                Err("operation admission is in progress; poll its status before retrying".into())
                            } else if record.active_action.is_some_and(|active| active != action) {
                                Err("a different action is already active for this operation".into())
                            } else {
                                Ok(record.public())
                            }
                        });
                        let _ = ready.send(result);
                        return;
                    }
                    Err(error) => {
                        let _ = ready.send(Err(error));
                        return;
                    }
                };
                let record = match service.read(&operation_id) {
                    Ok(record) => record,
                    Err(error) => {
                        let _ = ready.send(Err(error));
                        return;
                    }
                };
                if action.already_finished(record.state) || record.state == JobState::Cancelled {
                    let _ = ready.send(Ok(record.public()));
                    return;
                }
                let admission = service.update(&operation_id, |record| {
                    if !matches!(record.state, JobState::CancelRequested | JobState::Cancelled) {
                        record.state = JobState::Running;
                    }
                    record.active_action = Some(action);
                    Ok(())
                });
                let admitted = match admission {
                    Ok(record) => record.public(),
                    Err(error) => {
                        let _ = ready.send(Err(error));
                        return;
                    }
                };
                let _ = ready.send(Ok(admitted));
                #[cfg(test)]
                after_worker_admission_for_test(&operation_id);
                let outcome = match action {
                    JobAction::Apply => service.apply_locked(&operation_id, &policy),
                    JobAction::Undo => service.undo_locked(&operation_id, &policy),
                };
                if let Err(error) = outcome {
                    // This worker still owns the execution lock. A failed
                    // duplicate or opposing admission never writes this state.
                    let _ = service.update(&operation_id, |record| {
                        if !record.state.completed() && record.state != JobState::Cancelled {
                            record.state = if record.state == JobState::CancelRequested {
                                JobState::PartiallyApplied
                            } else if error.starts_with("refresh-required:") {
                                JobState::RefreshRequired
                            } else {
                                JobState::RecoveryRequired
                            };
                            record.detail = Some(error.clone());
                        }
                        Ok(())
                    });
                }
            })
            .map_err(|e| format!("cannot start operation worker: {e}"))?;
        accepted.recv_timeout(Duration::from_secs(2)).map_err(|_| {
            "operation admission response timed out; inspect its status before retrying".to_owned()
        })?
    }
}

#[cfg(test)]
static WORKER_TEST_GATES: OnceLock<
    Mutex<std::collections::BTreeMap<String, std::sync::mpsc::Receiver<()>>>,
> = OnceLock::new();

#[cfg(test)]
fn after_worker_admission_for_test(id: &str) {
    let gate = WORKER_TEST_GATES
        .get_or_init(|| Mutex::new(Default::default()))
        .lock()
        .unwrap()
        .remove(id);
    if let Some(gate) = gate {
        let _ = gate.recv_timeout(Duration::from_secs(10));
    }
}

fn capture_fields(
    text: Option<&str>,
    yaml: bool,
    values: std::collections::BTreeMap<String, Option<Value>>,
) -> Result<OwnedEdit, String> {
    if values.is_empty() || values.len() > MAX_STEPS {
        return Err("owned field group must contain 1–64 fields".into());
    }
    let document = parse_document(text, yaml)?;
    let pointers: Vec<_> = values.keys().collect();
    for pointer in &pointers {
        validate_pointer(pointer)?;
        if pointers
            .iter()
            .any(|other| other != pointer && other.starts_with(&format!("{pointer}/")))
        {
            return Err("owned field pointers must not overlap".into());
        }
    }
    Ok(OwnedEdit::Compound(
        values
            .into_iter()
            .map(|(pointer, after)| OwnedEdit::Field {
                yaml,
                before: document.pointer(&pointer).cloned(),
                pointer,
                after,
            })
            .collect(),
    ))
}

fn validate_pointer(pointer: &str) -> Result<(), String> {
    if !pointer.starts_with('/')
        || pointer == "/"
        || pointer
            .split('/')
            .skip(1)
            .any(|part| part.is_empty() || part.contains('~'))
    {
        return Err(
            "owned field pointer must name nonempty object keys without escape ambiguity".into(),
        );
    }
    Ok(())
}
fn parse_document(text: Option<&str>, yaml: bool) -> Result<Value, String> {
    let Some(text) = text.filter(|s| !s.trim().is_empty()) else {
        return Ok(serde_json::json!({}));
    };
    if yaml {
        serde_yaml::from_str(text).map_err(|_| "target is not a valid YAML object".into())
    } else {
        serde_json::from_str(text).map_err(|_| "target is not a valid JSON object".into())
    }
}
fn set_field(document: &mut Value, pointer: &str, value: &Option<Value>) -> Result<(), String> {
    let keys: Vec<_> = pointer.split('/').skip(1).collect();
    let mut parent = document;
    for key in &keys[..keys.len() - 1] {
        let object = parent
            .as_object_mut()
            .ok_or_else(|| refresh("owned field parent is no longer an object"))?;
        parent = object
            .entry((*key).to_owned())
            .or_insert_with(|| serde_json::json!({}));
    }
    let object = parent
        .as_object_mut()
        .ok_or_else(|| refresh("owned field parent is no longer an object"))?;
    let key = *keys.last().ok_or("missing field key")?;
    if let Some(value) = value {
        object.insert(key.into(), value.clone());
    } else {
        object.remove(key);
    }
    Ok(())
}

const BEGIN: &str = "# BEGIN tirith-hook v1";
const END: &str = "# END tirith-hook";
fn hook_block(text: &str) -> Result<Option<String>, String> {
    let mut start = None;
    let mut found = None;
    let mut offset = 0;
    for line in text.split_inclusive('\n') {
        let trimmed = line.trim_end_matches(['\r', '\n']);
        if trimmed == BEGIN {
            if start.is_some() || found.is_some() {
                return Err(refresh("multiple/nested managed shell blocks"));
            }
            start = Some(offset);
        } else if trimmed == END {
            let begin = start
                .take()
                .ok_or_else(|| refresh("unpaired shell END marker"))?;
            found = Some(text[begin..offset + line.len()].to_owned());
        }
        offset += line.len();
    }
    if start.is_some() {
        return Err(refresh("unpaired shell BEGIN marker"));
    }
    Ok(found)
}
fn validate_hook_payload(block: &str) -> Result<(), String> {
    if hook_block(block)?.as_deref() != Some(block) {
        return Err("shell payload must be exactly one managed hook block".into());
    }
    Ok(())
}
fn read_step(step: &Step) -> Result<Option<String>, String> {
    let snapshot = fs_helpers::read_snapshot_scoped(&step.target, &step.scope_root)?;
    if matches!(&step.edit, OwnedEdit::PrivateFile { .. }) {
        snapshot.require_private()?;
    }
    snapshot
        .bytes
        .map(|bytes| String::from_utf8(bytes).map_err(|_| "owned file is not UTF-8".into()))
        .transpose()
}

fn step_update(step: &Step, text: String) -> FileUpdate {
    let update = FileUpdate::write_text(text, 0o600).with_backup(true);
    #[cfg(unix)]
    if matches!(&step.edit, OwnedEdit::PrivateFile { .. }) {
        return update.with_exact_mode();
    }
    #[cfg(not(unix))]
    let _ = step;
    update
}

fn segment_state_matches(step: StepState, state: super::audit_segments::SegmentState) -> bool {
    use super::audit_segments::SegmentState as S;
    match step {
        StepState::Pending => state == S::Original,
        StepState::Applying | StepState::Compensating => true,
        StepState::Applied | StepState::AppliedWithRecovery => state == S::Applied,
        StepState::Compensated | StepState::CompensatedWithRecovery => state == S::Original,
    }
}

fn audit_state_matches(
    step: StepState,
    state: tirith_core::audit::retention::RotationState,
) -> bool {
    use tirith_core::audit::retention::RotationState as R;
    match step {
        StepState::Pending => state == R::Original,
        StepState::Applying => !matches!(state, R::Restored),
        StepState::Applied | StepState::AppliedWithRecovery => {
            matches!(state, R::Applied | R::AppliedWithAdditionalRecords)
        }
        StepState::Compensating => !matches!(state, R::AppliedWithAdditionalRecords),
        StepState::Compensated | StepState::CompensatedWithRecovery => {
            matches!(state, R::Original | R::Restored)
        }
    }
}

fn owned_matches(edit: &OwnedEdit, current: Option<&str>, after: bool) -> Result<bool, String> {
    Ok(match edit {
        OwnedEdit::AuditRotation(_) | OwnedEdit::AuditSegment(_) => {
            return Err("audit rotation requires the retained native log backend".into())
        }
        OwnedEdit::Compound(edits) => {
            let mut matches = true;
            for edit in edits {
                matches &= owned_matches(edit, current, after)?;
            }
            matches
        }
        OwnedEdit::WholeFile {
            before,
            after: output,
        }
        | OwnedEdit::PrivateFile {
            before,
            after: output,
        } => {
            if after {
                current == Some(output.as_str())
            } else {
                current == before.as_deref()
            }
        }
        OwnedEdit::Field {
            yaml,
            pointer,
            before,
            after: output,
        } => {
            let value = parse_document(current, *yaml)?.pointer(pointer).cloned();
            value
                == if after {
                    output.clone()
                } else {
                    before.clone()
                }
        }
        OwnedEdit::ShellHook {
            before,
            after: output,
        } => {
            hook_block(current.unwrap_or_default())?
                == if after {
                    output.clone()
                } else {
                    before.clone()
                }
        }
    })
}
fn transform(
    edit: &OwnedEdit,
    current: Option<&str>,
    undo: bool,
) -> Result<Option<String>, String> {
    // New-file undo deliberately publishes an empty compensation rather than
    // deleting a pathname. Recognize that exact result on crash retry after the
    // journal's Compensating state has accepted its owned generation.
    if undo
        && current == Some("")
        && matches!(
            edit,
            OwnedEdit::WholeFile { before: None, .. } | OwnedEdit::PrivateFile { before: None, .. }
        )
    {
        return Ok(None);
    }
    if owned_matches(edit, current, !undo)? {
        return Ok(None);
    }
    if !owned_matches(edit, current, undo)? {
        return Err(refresh(
            "owned field changed since planning; unrelated edits were preserved",
        ));
    }
    let output = match edit {
        OwnedEdit::AuditRotation(_) | OwnedEdit::AuditSegment(_) => {
            return Err("audit rotation cannot use a file replacement".into())
        }
        OwnedEdit::Compound(edits) => {
            let mut output = current.unwrap_or_default().to_owned();
            for edit in edits {
                if let Some(next) = transform(edit, Some(&output), undo)? {
                    output = next;
                }
            }
            output
        }
        OwnedEdit::WholeFile { before, after } | OwnedEdit::PrivateFile { before, after } => {
            if undo {
                before.clone().unwrap_or_default()
            } else {
                after.clone()
            }
        }
        OwnedEdit::Field {
            yaml,
            pointer,
            before,
            after,
        } => {
            let mut document = parse_document(current, *yaml)?;
            set_field(&mut document, pointer, if undo { before } else { after })?;
            if *yaml {
                serde_yaml::to_string(&document).map_err(|e| e.to_string())?
            } else {
                format!(
                    "{}\n",
                    serde_json::to_string_pretty(&document).map_err(|e| e.to_string())?
                )
            }
        }
        OwnedEdit::ShellHook { before, after } => {
            let old = if undo { after } else { before };
            let replacement = if undo { before } else { after };
            let mut text = current.unwrap_or_default().to_owned();
            if let Some(old) = old {
                text = text.replacen(old, replacement.as_deref().unwrap_or_default(), 1);
            } else if let Some(replacement) = replacement {
                if !text.is_empty() && !text.ends_with('\n') {
                    text.push('\n');
                }
                text.push_str(replacement);
            }
            text
        }
    };
    Ok(Some(output))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cli::test_harness::with_fake_env;
    use tirith_core::policy_snapshot::ResolutionMode;

    const EXPECTED_COMPLETED: JobState = if cfg!(windows) {
        JobState::CompletedWithRecovery
    } else {
        JobState::Completed
    };
    const EXPECTED_UNDONE: JobState = if cfg!(windows) {
        JobState::UndoneWithRecovery
    } else {
        JobState::Undone
    };

    fn fixture(home: &Path) -> MutationService {
        MutationService {
            scope: home.to_path_buf(),
            root: home.join("private-operations"),
            operator: "fixture-user".into(),
        }
    }
    fn policy() -> EffectivePolicySnapshot {
        EffectivePolicySnapshot::resolve(None, ResolutionMode::Runtime)
    }
    fn field_request(home: &Path, value: &str) -> RequestedChange {
        RequestedChange {
            target: home.join("settings.json"),
            scope_root: home.to_path_buf(),
            edit: Edit::JsonField {
                pointer: "/tirith/profile".into(),
                value: Some(Value::String(value.into())),
            },
            activation: true,
            description: "Set the personal profile".into(),
        }
    }

    fn deny_policy_changes(snapshot: &mut EffectivePolicySnapshot) {
        snapshot.policy.task_gate.mode = tirith_core::web3_policy::TaskGateMode::Enforce;
        snapshot
            .policy
            .task_gate
            .effects_denied_for_untrusted_sources
            .insert(tirith_core::effects::CommandEffectKind::PolicyChange);
    }

    fn gate_worker(id: &str) -> std::sync::mpsc::Sender<()> {
        let (release, gate) = std::sync::mpsc::channel();
        WORKER_TEST_GATES
            .get_or_init(|| Mutex::new(Default::default()))
            .lock()
            .unwrap()
            .insert(id.into(), gate);
        release
    }

    fn wait_for_workers(expected: usize) {
        let started = Instant::now();
        while active_job_count() != expected {
            assert!(
                started.elapsed() < Duration::from_secs(10),
                "worker did not finish"
            );
            std::thread::sleep(Duration::from_millis(10));
        }
    }

    #[test]
    fn async_admission_is_durable_idempotent_and_opposing_actions_do_not_corrupt_it() {
        with_fake_env(true, |home, _| {
            let service = fixture(home);
            service
                .plan(
                    "admission",
                    OperationKind::SetProfile,
                    vec![field_request(home, "strict")],
                    &policy(),
                )
                .unwrap();
            let baseline = active_job_count();
            let release = gate_worker("admission");
            let admitted = service.apply_async("admission".into(), policy()).unwrap();
            assert_eq!(admitted.state, JobState::Running);
            assert_eq!(admitted.active_action, Some(JobAction::Apply));
            assert_eq!(
                service.status("admission").unwrap().state,
                JobState::Running
            );
            assert_eq!(active_job_count(), baseline + 1);
            let duplicate = service.apply_async("admission".into(), policy()).unwrap();
            assert_eq!(duplicate.state, JobState::Running);
            assert_eq!(active_job_count(), baseline + 1);
            assert!(service.undo_async("admission".into(), policy()).is_err());
            let mut denied = policy();
            deny_policy_changes(&mut denied);
            assert_eq!(
                service.apply("admission", &denied).unwrap().state,
                JobState::Running
            );
            assert_eq!(service.read("admission").unwrap().state, JobState::Running);
            release.send(()).unwrap();
            wait_for_workers(baseline);
            assert_eq!(
                service.status("admission").unwrap().state,
                EXPECTED_COMPLETED
            );

            let release = gate_worker("admission");
            let admitted = service.undo_async("admission".into(), policy()).unwrap();
            assert_eq!(admitted.state, JobState::Running);
            assert_eq!(admitted.active_action, Some(JobAction::Undo));
            assert_eq!(
                service
                    .undo_async("admission".into(), policy())
                    .unwrap()
                    .state,
                JobState::Running
            );
            assert!(service.apply_async("admission".into(), policy()).is_err());
            assert_eq!(service.read("admission").unwrap().state, JobState::Running);
            release.send(()).unwrap();
            wait_for_workers(baseline);
            assert_eq!(service.status("admission").unwrap().state, EXPECTED_UNDONE);
        });
    }

    #[test]
    fn cancellation_after_worker_admission_prevents_first_publication() {
        with_fake_env(true, |home, _| {
            let service = fixture(home);
            service
                .plan(
                    "admission-cancel",
                    OperationKind::SetProfile,
                    vec![field_request(home, "strict")],
                    &policy(),
                )
                .unwrap();
            let baseline = active_job_count();
            let release = gate_worker("admission-cancel");
            assert_eq!(
                service
                    .apply_async("admission-cancel".into(), policy())
                    .unwrap()
                    .state,
                JobState::Running
            );
            assert_eq!(
                service.cancel("admission-cancel").unwrap().state,
                JobState::Cancelled
            );
            release.send(()).unwrap();
            wait_for_workers(baseline);
            assert!(!home.join("settings.json").exists());
            assert_eq!(
                service.status("admission-cancel").unwrap().state,
                JobState::Cancelled
            );
        });
    }

    #[cfg(unix)]
    #[test]
    fn private_file_mode_drift_refuses_apply_and_undo_and_empty_compensation_is_reusable() {
        use std::os::unix::fs::PermissionsExt;
        with_fake_env(true, |home, _| {
            let service = fixture(home);
            let target = home.join("private-feedback.json");
            let request = |text: &str| RequestedChange {
                target: target.clone(),
                scope_root: home.into(),
                edit: Edit::PrivateFile(text.into()),
                activation: false,
                description: "Private annotation".into(),
            };
            let snapshot = policy();
            std::fs::write(&target, "before").unwrap();
            std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o600)).unwrap();
            service
                .plan(
                    "private-first",
                    OperationKind::RecordFeedback,
                    vec![request("first")],
                    &snapshot,
                )
                .unwrap();
            std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o644)).unwrap();
            let refused = service.apply("private-first", &snapshot);
            assert!(refused.is_err() || refused.unwrap().state == JobState::RefreshRequired);
            assert_eq!(std::fs::read_to_string(&target).unwrap(), "before");
            std::fs::remove_file(&target).unwrap();
            service
                .plan(
                    "private-second",
                    OperationKind::RecordFeedback,
                    vec![request("second")],
                    &snapshot,
                )
                .unwrap();
            assert_eq!(
                service.apply("private-second", &snapshot).unwrap().state,
                EXPECTED_COMPLETED
            );
            assert_eq!(
                std::fs::metadata(&target).unwrap().permissions().mode() & 0o777,
                0o600
            );
            std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o644)).unwrap();
            assert!(service.undo("private-second", &snapshot).is_err());
            assert_eq!(std::fs::read_to_string(&target).unwrap(), "second");
            std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o600)).unwrap();
            service.undo("private-second", &snapshot).unwrap();
            assert_eq!(std::fs::read_to_string(&target).unwrap(), "");
            service
                .plan(
                    "private-third",
                    OperationKind::RecordFeedback,
                    vec![request("third")],
                    &snapshot,
                )
                .unwrap();
            service.apply("private-third", &snapshot).unwrap();
            assert_eq!(std::fs::read_to_string(&target).unwrap(), "third");
        });
    }

    fn impact_fixture(id: &str, snapshot: &EffectivePolicySnapshot) -> ImpactReport {
        use tirith_core::policy_rollout::{self, CandidateCoverage, ImpactRequest, RecordId};
        policy_rollout::review(ImpactRequest {
            id: RecordId::parse(&uuid::Uuid::new_v4().to_string()).unwrap(),
            candidate_id: RecordId::parse(id).unwrap(),
            scope: RolloutScope::PersonalUser,
            baseline: snapshot,
            candidate: &snapshot.policy,
            candidate_coverage: CandidateCoverage::EffectivePolicy,
            workflows: &[],
            exceptions: &[],
            exception_inventory_complete: true,
            clients: &[],
            now: chrono::Utc::now(),
        })
        .unwrap()
    }

    #[test]
    fn impact_attachment_is_immutable_for_change_and_noop_replays() {
        with_fake_env(true, |home, _| {
            let service = fixture(home);
            let snapshot = policy();
            for no_op in [false, true] {
                let id = uuid::Uuid::new_v4().to_string();
                let review = impact_fixture(&id, &snapshot);
                let report_id = review.id.as_str().to_owned();
                if no_op {
                    service
                        .complete_noop_with_intent_and_review(
                            &id,
                            OperationKind::SetProfile,
                            &snapshot,
                            &"balanced",
                            review,
                        )
                        .unwrap();
                } else {
                    service
                        .plan_with_preimages_intent_and_review(
                            &id,
                            OperationKind::SetProfile,
                            PlanChanges {
                                requests: vec![field_request(home, "strict")],
                                preimages: &Default::default(),
                            },
                            &snapshot,
                            &"balanced",
                            review,
                        )
                        .unwrap();
                }
                let mut refreshed = policy();
                refreshed.identity = uuid::Uuid::new_v4().to_string();
                let new_review = impact_fixture(&id, &refreshed);
                service
                    .complete_noop_with_intent_and_review(
                        &id,
                        OperationKind::SetProfile,
                        &refreshed,
                        &"balanced",
                        new_review,
                    )
                    .unwrap();
                assert_eq!(
                    service.impact_review(&id).unwrap().unwrap().id.as_str(),
                    report_id
                );
                assert_eq!(service.read_status(&id).unwrap().no_op, no_op);
                assert!(service
                    .complete_noop_with_intent_and_review(
                        &id,
                        OperationKind::SetProfile,
                        &snapshot,
                        &"different",
                        impact_fixture(&id, &snapshot)
                    )
                    .is_err());
            }
            assert!(!home.join("settings.json").exists());
        });
    }

    #[test]
    fn invalid_review_binding_never_publishes_a_journal() {
        with_fake_env(true, |home, _| {
            let service = fixture(home);
            let snapshot = policy();
            let id = uuid::Uuid::new_v4().to_string();
            let mut report = impact_fixture(&id, &snapshot);
            report.scope = RolloutScope::RemoteManaged;
            assert!(service
                .complete_noop_with_intent_and_review(
                    &id,
                    OperationKind::SetProfile,
                    &snapshot,
                    &"same",
                    report
                )
                .is_err());
            assert!(!service.path(&id).unwrap().exists());
            let report = impact_fixture(&uuid::Uuid::new_v4().to_string(), &snapshot);
            assert!(service
                .complete_noop_with_intent_and_review(
                    &id,
                    OperationKind::SetProfile,
                    &snapshot,
                    &"same",
                    report
                )
                .is_err());
            assert!(!service.path(&id).unwrap().exists());
        });
    }

    #[test]
    fn no_op_intent_remains_terminal_after_drift_and_cannot_be_repurposed() {
        with_fake_env(true, |home, _| {
            let service = fixture(home);
            let snapshot = policy();
            let id = uuid::Uuid::new_v4().to_string();
            let intent = ("user", "balanced");
            let accepted = service
                .complete_noop_with_intent(&id, OperationKind::SetProfile, &snapshot, &intent)
                .unwrap();
            assert!(accepted.no_op);
            assert_eq!(accepted.state, JobState::Completed);
            assert!(accepted.steps.is_empty());
            assert!(!home.join("settings.json").exists());
            let config = tirith_core::policy::config_dir().unwrap();
            std::fs::create_dir_all(&config).unwrap();
            std::fs::write(config.join("policy.yaml"), "fail_mode: closed\n").unwrap();
            let refreshed = policy();
            let retry = service
                .plan_with_preimages_and_intent(
                    &id,
                    OperationKind::SetProfile,
                    vec![field_request(home, "would-be-a-new-write")],
                    &refreshed,
                    &Default::default(),
                    &intent,
                )
                .unwrap();
            assert!(retry.no_op);
            assert_eq!(retry.created_at, accepted.created_at);
            assert_eq!(retry.policy_identity, accepted.policy_identity);
            assert!(service
                .complete_noop_with_intent(
                    &id,
                    OperationKind::SetProfile,
                    &refreshed,
                    &("user", "strict")
                )
                .is_err());
            assert!(service
                .plan_with_preimages_and_intent(
                    &id,
                    OperationKind::SetProfile,
                    vec![field_request(home, "strict")],
                    &refreshed,
                    &Default::default(),
                    &("user", "strict")
                )
                .is_err());
            let baseline = active_job_count();
            assert!(service.apply(&id, &refreshed).unwrap().no_op);
            assert!(service.undo(&id, &refreshed).unwrap().no_op);
            assert!(service.undo_async(id.clone(), refreshed).unwrap().no_op);
            assert_eq!(active_job_count(), baseline);
            assert!(!home.join("settings.json").exists());
            assert!(!service
                .path(&id)
                .unwrap()
                .with_extension("execution-lock")
                .exists());
            assert!(service.read_status(&id).unwrap().no_op);
        });
    }

    #[test]
    fn no_op_requires_uuid_and_binds_scope_even_when_intent_omits_it() {
        with_fake_env(true, |home, _| {
            let service = fixture(home);
            assert!(service
                .complete_noop_with_intent(
                    "not-a-uuid",
                    OperationKind::SetProfile,
                    &policy(),
                    &"same"
                )
                .is_err());
            assert!(!service.root.exists());
            let id = uuid::Uuid::new_v4().to_string();
            service
                .complete_noop_with_intent(&id, OperationKind::SetProfile, &policy(), &"same")
                .unwrap();
            let scoped = EffectivePolicySnapshot::resolve(home.to_str(), ResolutionMode::Runtime);
            assert!(service
                .complete_noop_with_intent(&id, OperationKind::SetProfile, &scoped, &"same")
                .is_err());
        });
    }

    #[test]
    fn caller_intent_retries_keep_first_generated_payload_and_reject_changed_scope() {
        with_fake_env(true, |home, _| {
            let service = fixture(home);
            let policy = policy();
            let intent = ("user-scope", "add-grant", "30d");
            assert!(service
                .status_for_intent("intent", OperationKind::AddTrust, &intent)
                .unwrap()
                .is_none());
            service
                .plan_with_preimages_and_intent(
                    "intent",
                    OperationKind::AddTrust,
                    vec![field_request(home, "first-generated-uuid-and-expiry")],
                    &policy,
                    &Default::default(),
                    &intent,
                )
                .unwrap();
            let original = service.read("intent").unwrap().payload_digest;
            service
                .plan_with_preimages_and_intent(
                    "intent",
                    OperationKind::AddTrust,
                    vec![field_request(home, "regenerated-uuid-and-expiry")],
                    &policy,
                    &Default::default(),
                    &intent,
                )
                .unwrap();
            assert_eq!(service.read("intent").unwrap().payload_digest, original);
            assert!(service
                .status_for_intent(
                    "intent",
                    OperationKind::AddTrust,
                    &("another-project", "add-grant", "30d")
                )
                .is_err());
            assert_eq!(
                service.apply("intent", &policy).unwrap().state,
                EXPECTED_COMPLETED
            );
            assert!(std::fs::read_to_string(home.join("settings.json"))
                .unwrap()
                .contains("first-generated"));
            assert_eq!(
                service
                    .status_for_intent("intent", OperationKind::AddTrust, &intent)
                    .unwrap()
                    .unwrap()
                    .state,
                EXPECTED_COMPLETED
            );
        });
    }

    #[test]
    fn recent_operations_are_bounded_private_metadata_and_do_not_reconcile_by_writing() {
        with_fake_env(true, |home, _| {
            let service = fixture(home);
            assert!(service.recent_statuses(0).is_err());
            assert!(service.recent_statuses(51).is_err());
            assert!(service.recent_statuses(10).unwrap().operations.is_empty());
            assert!(!service.root.exists());
            let id = uuid::Uuid::new_v4().to_string();
            service
                .plan(
                    &id,
                    OperationKind::SetProfile,
                    vec![field_request(home, "private-payload-not-for-listing")],
                    &policy(),
                )
                .unwrap();
            service
                .update(&id, |record| {
                    record.state = JobState::Running;
                    Ok(())
                })
                .unwrap();
            let second = uuid::Uuid::new_v4().to_string();
            service
                .plan(
                    &second,
                    OperationKind::SetProfile,
                    vec![field_request(home, "other-private-payload")],
                    &policy(),
                )
                .unwrap();
            std::fs::write(service.root.join("not-an-operation.json"), "not a record").unwrap();
            let original = std::fs::read(service.path(&id).unwrap()).unwrap();
            let listed = service.recent_statuses(10).unwrap();
            assert_eq!(listed.operations.len(), 2);
            assert!(listed.coverage.invalid_names > 0);
            assert!(listed.coverage.running_requires_status_reconciliation);
            assert_eq!(std::fs::read(service.path(&id).unwrap()).unwrap(), original);
            let public = serde_json::to_string(&listed).unwrap();
            for private in [
                "private-payload",
                "external_authorization",
                "caller_intent_digest",
                "undo_document",
            ] {
                assert!(!public.contains(private), "leaked {private}");
            }
            let limited = service.recent_statuses(1).unwrap();
            assert_eq!(limited.operations.len(), 1);
            assert!(limited.coverage.results_limited);
        });
    }

    #[test]
    fn concurrent_same_intent_preparation_publishes_one_immutable_payload() {
        with_fake_env(true, |home, _| {
            let service = fixture(home);
            let policy = policy();
            let intent = ("user-scope", "30d");
            std::thread::scope(|scope| {
                let first = scope.spawn(|| {
                    service.plan_with_preimages_and_intent(
                        "intent-race",
                        OperationKind::AddTrust,
                        vec![field_request(home, "first")],
                        &policy,
                        &Default::default(),
                        &intent,
                    )
                });
                let second = scope.spawn(|| {
                    service.plan_with_preimages_and_intent(
                        "intent-race",
                        OperationKind::AddTrust,
                        vec![field_request(home, "second")],
                        &policy,
                        &Default::default(),
                        &intent,
                    )
                });
                first.join().unwrap().unwrap();
                second.join().unwrap().unwrap();
            });
            let original = service.read("intent-race").unwrap().payload_digest;
            assert_eq!(
                service.apply("intent-race", &policy).unwrap().state,
                EXPECTED_COMPLETED
            );
            assert_eq!(
                service.read("intent-race").unwrap().payload_digest,
                original
            );
        });
    }

    fn migration_fixture(
        home: &Path,
    ) -> (MutationService, EffectivePolicySnapshot, PathBuf, PathBuf) {
        let config = tirith_core::policy::config_dir().unwrap();
        std::fs::create_dir_all(&config).unwrap();
        std::fs::write(config.join("policy.yaml"), "fail_mode: open\n").unwrap();
        let legacy = config.join("trust.json");
        let grants = config.join("trust-grants.json");
        std::fs::write(
            &legacy,
            r#"{"entries":[{"pattern":"trusted.example.test","rule_id":"pipe_to_shell"}]}"#,
        )
        .unwrap();
        std::fs::write(&grants, r#"{"schema_version":1,"grants":[]}"#).unwrap();
        let policy = policy();
        let service = fixture(home);
        let changes = vec![
            RequestedChange {
                target: legacy.clone(),
                scope_root: config.clone(),
                edit: Edit::JsonField {
                    pointer: "/entries".into(),
                    value: Some(serde_json::json!([])),
                },
                activation: false,
                description: "Remove migrated legacy grant".into(),
            },
            RequestedChange {
                target: grants.clone(),
                scope_root: config,
                edit: Edit::JsonField {
                    pointer: "/grants".into(),
                    value: Some(serde_json::json!([{
                        "id": "c1be9ee4-7b03-4e9e-86db-ac11b2a962b1", "pattern": "trusted.example.test",
                        "rule_id": "pipe_to_shell", "scope": {"kind":"user"}, "created_at":"2026-01-01T00:00:00Z"
                    }])),
                },
                activation: true,
                description: "Activate scoped grant".into(),
            },
        ];
        service
            .plan("migration", OperationKind::AddTrust, changes, &policy)
            .unwrap();
        (service, policy, legacy, grants)
    }

    #[test]
    fn policy_reading_two_file_migration_and_undo_rebase_only_owned_generations() {
        with_fake_env(true, |home, _| {
            let (service, original, legacy, grants) = migration_fixture(home);
            let result = service.apply("migration", &original).unwrap();
            assert_eq!(result.state, EXPECTED_COMPLETED, "{:?}", result.detail);
            assert_eq!(
                serde_json::from_str::<Value>(&std::fs::read_to_string(&legacy).unwrap()).unwrap()
                    ["entries"],
                serde_json::json!([])
            );
            assert_eq!(
                serde_json::from_str::<Value>(&std::fs::read_to_string(&grants).unwrap()).unwrap()
                    ["grants"]
                    .as_array()
                    .unwrap()
                    .len(),
                1
            );
            let undone = service.undo("migration", &policy()).unwrap();
            assert_eq!(undone.state, EXPECTED_UNDONE);
            assert_eq!(
                serde_json::from_str::<Value>(&std::fs::read_to_string(&legacy).unwrap()).unwrap()
                    ["entries"]
                    .as_array()
                    .unwrap()
                    .len(),
                1
            );
            assert_eq!(
                serde_json::from_str::<Value>(&std::fs::read_to_string(&grants).unwrap()).unwrap()
                    ["grants"],
                serde_json::json!([])
            );
        });
    }

    #[test]
    fn rebase_refuses_external_policy_drift_after_partial_publication() {
        with_fake_env(true, |home, _| {
            let (service, original, legacy, grants) = migration_fixture(home);
            let journal = service.read("migration").unwrap();
            let first = &journal.steps[0];
            let text = fs_helpers::read_to_string_scoped(&first.target, &first.scope_root).unwrap();
            let published = transform(&first.edit, text.as_deref(), false)
                .unwrap()
                .unwrap();
            std::fs::write(&legacy, published).unwrap();
            service
                .update("migration", |journal| {
                    journal.steps[0].state = StepState::Applying;
                    journal.state = JobState::Running;
                    Ok(())
                })
                .unwrap();
            assert_eq!(
                service.status("migration").unwrap().state,
                JobState::RecoveryRequired
            );
            std::fs::write(
                tirith_core::policy::config_dir()
                    .unwrap()
                    .join("policy.yaml"),
                "fail_mode: closed\n",
            )
            .unwrap();
            let result = service.apply("migration", &original).unwrap();
            assert_eq!(result.state, JobState::RefreshRequired);
            assert!(result.detail.unwrap().contains("external policy inputs"));
            assert_eq!(
                serde_json::from_str::<Value>(&std::fs::read_to_string(&grants).unwrap()).unwrap()
                    ["grants"],
                serde_json::json!([])
            );
        });
    }

    #[test]
    fn rebase_cannot_hide_unrelated_authority_edits_inside_owned_file() {
        with_fake_env(true, |home, _| {
            let (service, _, legacy, grants) = migration_fixture(home);
            let mut document: Value =
                serde_json::from_str(&std::fs::read_to_string(&legacy).unwrap()).unwrap();
            document["unrelated_authority_metadata"] = serde_json::json!("changed");
            std::fs::write(&legacy, serde_json::to_string(&document).unwrap()).unwrap();
            let result = service.apply("migration", &policy()).unwrap();
            assert_eq!(result.state, JobState::RefreshRequired);
            assert!(result
                .detail
                .unwrap()
                .contains("authorization document changed"));
            assert_eq!(
                serde_json::from_str::<Value>(&std::fs::read_to_string(&grants).unwrap()).unwrap()
                    ["grants"],
                serde_json::json!([])
            );
        });
    }

    #[test]
    fn status_distinguishes_live_worker_lock_from_crashed_running_journal() {
        with_fake_env(true, |home, _| {
            let (service, _, _, _) = migration_fixture(home);
            service
                .update("migration", |record| {
                    record.state = JobState::Running;
                    Ok(())
                })
                .unwrap();
            let lock_path = service
                .path("migration")
                .unwrap()
                .with_extension("execution-lock");
            std::thread::scope(|threads| {
                let (ready, waiting) = std::sync::mpsc::channel();
                let (release, held) = std::sync::mpsc::channel();
                let scope = &service.scope;
                let lock_path = &lock_path;
                let worker = threads.spawn(move || {
                    let _lock = fs_helpers::try_lock_operation(lock_path, scope)
                        .unwrap()
                        .unwrap();
                    ready.send(()).unwrap();
                    let _ = held.recv_timeout(Duration::from_secs(10));
                });
                waiting.recv_timeout(Duration::from_secs(10)).unwrap();
                assert_eq!(
                    service.status("migration").unwrap().state,
                    JobState::Running
                );
                release.send(()).unwrap();
                worker.join().unwrap();
            });
            assert_eq!(
                service.status("migration").unwrap().state,
                JobState::RecoveryRequired
            );
        });
    }

    #[test]
    fn task_gate_denial_precedes_journal_and_destination_side_effects() {
        with_fake_env(true, |home, _| {
            let service = fixture(home);
            let mut policy = policy();
            deny_policy_changes(&mut policy);
            let error = service
                .plan(
                    "denied",
                    OperationKind::SetProfile,
                    vec![field_request(home, "strict")],
                    &policy,
                )
                .unwrap_err();
            assert!(error.contains("task gate"), "{error}");
            assert!(!service.root.exists());
            assert!(!home.join("settings.json").exists());
        });
    }

    #[test]
    fn task_gate_denial_blocks_apply_and_undo_before_destination_changes() {
        with_fake_env(true, |home, _| {
            let service = fixture(home);
            let policy = policy();
            service
                .plan(
                    "recheck",
                    OperationKind::SetProfile,
                    vec![field_request(home, "strict")],
                    &policy,
                )
                .unwrap();
            let mut denied = self::policy();
            deny_policy_changes(&mut denied);
            let result = service.apply("recheck", &denied).unwrap();
            assert_eq!(result.state, JobState::RefreshRequired);
            assert!(result.detail.unwrap().contains("task gate"));
            assert!(!home.join("settings.json").exists());
            // Coordination may create its private lock before authorization;
            // no destination or applied step may change on a denied request.
            assert!(service
                .read("recheck")
                .unwrap()
                .steps
                .iter()
                .all(|step| step.state == StepState::Pending));
            service.apply("recheck", &policy).unwrap();
            let original = std::fs::read(home.join("settings.json")).unwrap();
            let error = service.undo("recheck", &denied).unwrap_err();
            assert!(error.contains("task gate"), "{error}");
            assert_eq!(std::fs::read(home.join("settings.json")).unwrap(), original);
        });
    }

    #[test]
    fn caller_bound_preimages_reject_owned_edits_before_plan_capture() {
        with_fake_env(true, |home, _| {
            let service = fixture(home);
            let old = r#"{"tirith":{"profile":"balanced"}}"#;
            let expected = std::collections::BTreeMap::from([(
                home.join("settings.json"),
                Some(old.to_owned()),
            )]);
            std::fs::write(
                home.join("settings.json"),
                r#"{"tirith":{"profile":"manual"}}"#,
            )
            .unwrap();
            let error = service
                .plan_with_preimages(
                    "caller-race",
                    OperationKind::SetProfile,
                    vec![field_request(home, "strict")],
                    &policy(),
                    &expected,
                )
                .unwrap_err();
            assert!(error.starts_with("refresh-required:"), "{error}");
            assert!(std::fs::read_to_string(home.join("settings.json"))
                .unwrap()
                .contains("manual"));
            assert!(!service.path("caller-race").unwrap().exists());
        });
    }

    #[test]
    fn caller_bound_preimages_preserve_unrelated_edits_before_plan_capture() {
        with_fake_env(true, |home, _| {
            let service = fixture(home);
            let old = r#"{"tirith":{"profile":"balanced"}}"#;
            let expected = std::collections::BTreeMap::from([(
                home.join("settings.json"),
                Some(old.to_owned()),
            )]);
            std::fs::write(
                home.join("settings.json"),
                r#"{"tirith":{"profile":"balanced"},"editor":"new"}"#,
            )
            .unwrap();
            let authorization = policy();
            service
                .plan_with_preimages(
                    "caller-unrelated",
                    OperationKind::SetProfile,
                    vec![field_request(home, "strict")],
                    &authorization,
                    &expected,
                )
                .unwrap();
            assert_eq!(
                service
                    .apply("caller-unrelated", &authorization)
                    .unwrap()
                    .state,
                EXPECTED_COMPLETED
            );
            let result: Value =
                serde_json::from_str(&std::fs::read_to_string(home.join("settings.json")).unwrap())
                    .unwrap();
            assert_eq!(result["editor"], "new");
            assert_eq!(result["tirith"]["profile"], "strict");
        });
    }

    #[test]
    fn owned_field_updates_preserve_unrelated_concurrent_edits() {
        let edit = OwnedEdit::Field {
            yaml: false,
            pointer: "/tirith/profile".into(),
            before: Some(Value::String("balanced".into())),
            after: Some(Value::String("strict".into())),
        };
        let current = r#"{"tirith":{"profile":"balanced","new_setting":42},"editor":"changed"}"#;
        let result: Value =
            serde_json::from_str(&transform(&edit, Some(current), false).unwrap().unwrap())
                .unwrap();
        assert_eq!(result["editor"], "changed");
        assert_eq!(result["tirith"]["new_setting"], 42);
        assert_eq!(result["tirith"]["profile"], "strict");
        assert!(
            transform(&edit, Some(r#"{"tirith":{"profile":"other"}}"#), false)
                .unwrap_err()
                .starts_with("refresh-required:")
        );
    }

    #[test]
    fn undo_refuses_changed_owned_field_but_preserves_other_fields() {
        let edit = OwnedEdit::Field {
            yaml: false,
            pointer: "/tirith".into(),
            before: Some(Value::Bool(false)),
            after: Some(Value::Bool(true)),
        };
        let output = transform(&edit, Some(r#"{"tirith":true,"new":"keep"}"#), true)
            .unwrap()
            .unwrap();
        let value: Value = serde_json::from_str(&output).unwrap();
        assert_eq!(value["tirith"], false);
        assert_eq!(value["new"], "keep");
        assert!(transform(&edit, Some(r#"{"tirith":"changed"}"#), true).is_err());
    }

    #[test]
    fn managed_hook_edits_preserve_manual_lines_and_fail_on_ambiguous_markers() {
        let block = format!("{BEGIN}\neval \"$(tirith init --shell bash)\"\n{END}\n");
        let edit = OwnedEdit::ShellHook {
            before: None,
            after: Some(block.clone()),
        };
        let activated = transform(&edit, Some("# manual\n"), false)
            .unwrap()
            .unwrap();
        assert_eq!(activated, format!("# manual\n{block}"));
        assert_eq!(
            transform(&edit, Some(&activated), true).unwrap().unwrap(),
            "# manual\n"
        );
        assert!(hook_block(&format!("{block}{block}")).is_err());
        assert!(hook_block(&format!("{BEGIN}\nno end")).is_err());
    }

    #[test]
    fn plan_restart_apply_and_identical_retry_have_one_effect() {
        with_fake_env(true, |home, _| {
            let service = fixture(home);
            let initial = policy();
            let preview = service
                .plan(
                    "retry-1",
                    OperationKind::SetProfile,
                    vec![field_request(home, "strict")],
                    &initial,
                )
                .unwrap();
            assert_eq!(preview.state, JobState::Planned);
            assert!(!home.join("settings.json").exists());
            let fresh = policy();
            assert_ne!(initial.identity, fresh.identity);
            let result = service.apply("retry-1", &fresh).unwrap();
            assert_eq!(result.state, EXPECTED_COMPLETED);
            let generation = std::fs::metadata(home.join("settings.json"))
                .unwrap()
                .modified()
                .unwrap();
            let retry = service
                .plan(
                    "retry-1",
                    OperationKind::SetProfile,
                    vec![field_request(home, "strict")],
                    &policy(),
                )
                .unwrap();
            assert_eq!(retry.state, EXPECTED_COMPLETED);
            assert_eq!(
                service.apply("retry-1", &policy()).unwrap().state,
                EXPECTED_COMPLETED
            );
            assert_eq!(
                std::fs::metadata(home.join("settings.json"))
                    .unwrap()
                    .modified()
                    .unwrap(),
                generation
            );
            assert!(service
                .plan(
                    "retry-1",
                    OperationKind::SetProfile,
                    vec![field_request(home, "balanced")],
                    &policy()
                )
                .is_err());
            assert!(service
                .plan(
                    "retry-1",
                    OperationKind::SetupShell,
                    vec![field_request(home, "strict")],
                    &policy()
                )
                .is_err());
            let mut other_operator = service.clone();
            other_operator.operator = "someone-else".into();
            assert!(other_operator.status("retry-1").is_err());
        });
    }

    #[test]
    fn concurrent_owned_edits_require_refresh_and_unrelated_edits_survive() {
        with_fake_env(true, |home, _| {
            let service = fixture(home);
            std::fs::write(
                home.join("settings.json"),
                r#"{"tirith":{"profile":"balanced"}}"#,
            )
            .unwrap();
            let authorization = policy();
            service
                .plan(
                    "concurrent",
                    OperationKind::SetProfile,
                    vec![field_request(home, "strict")],
                    &authorization,
                )
                .unwrap();
            std::fs::write(
                home.join("settings.json"),
                r#"{"tirith":{"profile":"balanced"},"new":"keep"}"#,
            )
            .unwrap();
            assert_eq!(
                service.apply("concurrent", &authorization).unwrap().state,
                EXPECTED_COMPLETED
            );
            let value: Value =
                serde_json::from_str(&std::fs::read_to_string(home.join("settings.json")).unwrap())
                    .unwrap();
            assert_eq!(value["new"], "keep");
            service
                .plan(
                    "conflicting",
                    OperationKind::SetProfile,
                    vec![field_request(home, "balanced")],
                    &policy(),
                )
                .unwrap();
            std::fs::write(
                home.join("settings.json"),
                r#"{"tirith":{"profile":"other"},"new":"keep"}"#,
            )
            .unwrap();
            assert_eq!(
                service.apply("conflicting", &policy()).unwrap().state,
                JobState::RefreshRequired
            );
            assert!(std::fs::read_to_string(home.join("settings.json"))
                .unwrap()
                .contains("other"));
        });
    }

    #[test]
    fn cancellation_before_commit_never_changes_destination() {
        with_fake_env(true, |home, _| {
            let service = fixture(home);
            let authorization = policy();
            service
                .plan(
                    "cancel",
                    OperationKind::SetProfile,
                    vec![field_request(home, "strict")],
                    &authorization,
                )
                .unwrap();
            assert_eq!(service.cancel("cancel").unwrap().state, JobState::Cancelled);
            assert_eq!(
                service.apply("cancel", &authorization).unwrap().state,
                JobState::Cancelled
            );
            assert!(!home.join("settings.json").exists());
        });
    }

    #[test]
    fn interrupted_publication_reconciles_without_rewriting_and_retains_uncertainty() {
        with_fake_env(true, |home, _| {
            let service = fixture(home);
            let authorization = policy();
            service
                .plan(
                    "interrupted",
                    OperationKind::SetProfile,
                    vec![field_request(home, "strict")],
                    &authorization,
                )
                .unwrap();
            service
                .update("interrupted", |record| {
                    record.state = JobState::Running;
                    record.steps[0].state = StepState::Applying;
                    Ok(())
                })
                .unwrap();
            std::fs::write(
                home.join("settings.json"),
                r#"{"tirith":{"profile":"strict"},"other":"survives"}"#,
            )
            .unwrap();
            let before = std::fs::read(home.join("settings.json")).unwrap();
            let recovered = service.apply("interrupted", &authorization).unwrap();
            assert_eq!(recovered.state, JobState::CompletedWithRecovery);
            assert_eq!(std::fs::read(home.join("settings.json")).unwrap(), before);
        });
    }

    #[test]
    fn undo_is_generation_checked_and_replayable() {
        with_fake_env(true, |home, _| {
            let service = fixture(home);
            std::fs::write(
                home.join("settings.json"),
                r#"{"tirith":{"profile":"balanced"}}"#,
            )
            .unwrap();
            service
                .plan(
                    "undo",
                    OperationKind::SetProfile,
                    vec![field_request(home, "strict")],
                    &policy(),
                )
                .unwrap();
            service.apply("undo", &policy()).unwrap();
            std::fs::write(
                home.join("settings.json"),
                r#"{"tirith":{"profile":"strict"},"other":"keep"}"#,
            )
            .unwrap();
            assert_eq!(
                service.undo("undo", &policy()).unwrap().state,
                EXPECTED_UNDONE
            );
            assert_eq!(
                service.undo("undo", &policy()).unwrap().state,
                EXPECTED_UNDONE
            );
            let value: Value =
                serde_json::from_str(&std::fs::read_to_string(home.join("settings.json")).unwrap())
                    .unwrap();
            assert_eq!(value["tirith"]["profile"], "balanced");
            assert_eq!(value["other"], "keep");
        });
    }

    #[test]
    fn undo_authority_baseline_preserves_prior_unrelated_edits_and_rejects_later_drift() {
        with_fake_env(true, |home, _| {
            let service = fixture(home);
            let config = tirith_core::policy::config_dir().unwrap();
            std::fs::create_dir_all(&config).unwrap();
            let target = config.join("policy.yaml");
            std::fs::write(&target, "fail_mode: open\n").unwrap();
            let fields = std::collections::BTreeMap::from([(
                "/fail_mode".into(),
                Some(serde_json::json!("closed")),
            )]);
            service
                .plan(
                    "undo-policy",
                    OperationKind::SetProfile,
                    vec![RequestedChange {
                        target: target.clone(),
                        scope_root: config.clone(),
                        edit: Edit::YamlFields(fields.clone()),
                        activation: true,
                        description: "Change one owned policy field".into(),
                    }],
                    &policy(),
                )
                .unwrap();
            service.apply("undo-policy", &policy()).unwrap();
            std::fs::write(
                &target,
                "fail_mode: closed\nnote: keep this unrelated edit\n",
            )
            .unwrap();
            assert_eq!(
                service.undo("undo-policy", &policy()).unwrap().state,
                EXPECTED_UNDONE
            );
            let restored: Value =
                serde_yaml::from_str(&std::fs::read_to_string(&target).unwrap()).unwrap();
            assert_eq!(restored["fail_mode"], "open");
            assert_eq!(restored["note"], "keep this unrelated edit");

            service
                .plan(
                    "undo-policy-drift",
                    OperationKind::SetProfile,
                    vec![RequestedChange {
                        target: target.clone(),
                        scope_root: config,
                        edit: Edit::YamlFields(fields),
                        activation: true,
                        description: "Change one owned policy field".into(),
                    }],
                    &policy(),
                )
                .unwrap();
            service.apply("undo-policy-drift", &policy()).unwrap();
            let captured = service.read("undo-policy-drift").unwrap();
            let documents = service.capture_undo_documents(&captured).unwrap();
            let snapshot = policy();
            service
                .update("undo-policy-drift", |record| {
                    record.undo_external_authorization =
                        Some(snapshot.private_external_inputs_guard(
                            &std::iter::once(target.clone()).collect(),
                        ));
                    record.steps[0].undo_document = documents[0].clone();
                    record.steps[0].state = StepState::Compensating;
                    record.state = JobState::Running;
                    Ok(())
                })
                .unwrap();
            std::fs::write(
                &target,
                "fail_mode: closed\nnote: changed after undo began\n",
            )
            .unwrap();
            assert!(service.undo("undo-policy-drift", &policy()).is_err());
            assert!(std::fs::read_to_string(&target)
                .unwrap()
                .contains("changed after undo began"));
        });
    }

    #[test]
    fn interrupted_new_file_compensation_is_reconciled_without_rewriting() {
        with_fake_env(true, |home, _| {
            let service = fixture(home);
            let target = home.join("created.json");
            service
                .plan(
                    "undo-crash",
                    OperationKind::SetupIntegration,
                    vec![RequestedChange {
                        target: target.clone(),
                        scope_root: home.to_path_buf(),
                        edit: Edit::WholeFile("{\"managed\":true}\n".into()),
                        activation: true,
                        description: "Install managed integration".into(),
                    }],
                    &policy(),
                )
                .unwrap();
            service.apply("undo-crash", &policy()).unwrap();
            let authorization = policy();
            let excluded = std::iter::once(target.clone()).collect();
            service
                .update("undo-crash", |record| {
                    record.undo_external_authorization =
                        Some(authorization.private_external_inputs_guard(&excluded));
                    record.state = JobState::Running;
                    record.steps[0].state = StepState::Compensating;
                    Ok(())
                })
                .unwrap();
            std::fs::write(&target, "").unwrap();
            assert_eq!(
                service.undo("undo-crash", &policy()).unwrap().state,
                JobState::Undone
            );
            assert_eq!(std::fs::read(&target).unwrap(), b"");
            assert_eq!(
                service.undo("undo-crash", &policy()).unwrap().state,
                JobState::Undone
            );
        });
    }

    #[test]
    fn private_journal_material_never_appears_in_public_status() {
        with_fake_env(true, |home, _| {
            let service = fixture(home);
            let preview = service
                .plan(
                    "private",
                    OperationKind::SetProfile,
                    vec![field_request(home, "secret-value-that-must-not-appear")],
                    &policy(),
                )
                .unwrap();
            let json = serde_json::to_string(&preview).unwrap();
            for forbidden in [
                "secret-value",
                "authorization",
                "payload_digest",
                "request_digest",
                "before",
                "after",
            ] {
                assert!(!json.contains(forbidden), "{forbidden}");
            }
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                assert_eq!(
                    std::fs::metadata(&service.root)
                        .unwrap()
                        .permissions()
                        .mode()
                        & 0o777,
                    0o700
                );
                assert_eq!(
                    std::fs::metadata(service.path("private").unwrap())
                        .unwrap()
                        .permissions()
                        .mode()
                        & 0o777,
                    0o600
                );
            }
        });
    }

    #[test]
    fn scope_replacement_invalidates_pending_operation() {
        with_fake_env(true, |home, _| {
            let project = home.join("project");
            std::fs::create_dir(&project).unwrap();
            let identity = ScopeIdentity::capture(&project).unwrap();
            std::fs::rename(&project, home.join("old-project")).unwrap();
            std::fs::create_dir(&project).unwrap();
            assert!(identity.validate().is_err());
        });
    }
}
