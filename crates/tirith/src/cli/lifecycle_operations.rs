//! Private immutable lifecycle plans and durable results. Public operation views
//! are separate from these records; paths, policy guards and tool hashes never
//! become browser capabilities.

use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{de::DeserializeOwned, Deserialize, Serialize};

use crate::cli::control::identity::DirectoryIdentity;
use crate::cli::setup::fs_helpers;

const SCHEMA: u32 = 1;
const PLAN_TTL: u64 = 15 * 60;
const RECORD_CAP: usize = 2 * 1024 * 1024;
const MAX_OPERATIONS: usize = 64;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum Action {
    Update,
    Rollback,
    RefreshThreatDb,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum Phase {
    Preparing,
    Prepared,
    Accepted,
    Verifying,
    PublicationIntent,
    Published,
    Completed,
    Partial,
    Cancelled,
    RefreshRequired,
    RecoveryRequired,
    Failed,
}

impl Phase {
    fn permits(self, next: Self) -> bool {
        self == next
            || matches!(
                (self, next),
                (
                    Self::Prepared,
                    Self::Accepted | Self::Cancelled | Self::RefreshRequired
                ) | (
                    Self::Accepted,
                    Self::Verifying | Self::RefreshRequired | Self::RecoveryRequired | Self::Failed
                ) | (
                    Self::Verifying,
                    Self::PublicationIntent
                        | Self::Completed
                        | Self::Partial
                        | Self::Failed
                        | Self::RefreshRequired
                        | Self::RecoveryRequired
                ) | (
                    Self::PublicationIntent,
                    Self::Published | Self::RecoveryRequired
                ) | (
                    Self::Published,
                    Self::Completed | Self::Partial | Self::RecoveryRequired
                )
            )
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Preview {
    pub current_version: String,
    pub candidate_version: Option<String>,
    pub candidate_sequence: Option<u64>,
    pub candidate_format: Option<u32>,
    pub evidence: String,
    pub compatible: bool,
    pub issues: Vec<String>,
    pub configuration_changed: bool,
    pub integration_reload_required: bool,
    pub service_restart_required: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct OperationView {
    pub schema_version: u32,
    pub operation_id: String,
    pub action: Action,
    pub phase: Phase,
    pub created_at: u64,
    pub updated_at: u64,
    pub expires_at: u64,
    pub preview: Preview,
    pub published: bool,
    pub failure_code: Option<String>,
    pub next_action: String,
}

/// Explicitly selected support evidence. Raw failure diagnostics remain in the
/// private journal because they may include local paths and policy context.
#[derive(Debug, Clone, Serialize)]
pub(crate) struct SupportStatus {
    pub operation: OperationView,
    pub selected_failure_detail: Option<String>,
}

/// Read existing evidence without creating state, taking a write lock,
/// reconciling a phase, or reconstructing application authority.
pub(crate) fn support_status(id: &str) -> Result<SupportStatus, String> {
    Store::open_current(false)?.support_view(id)
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ImmutablePlan<P> {
    schema_version: u32,
    operation_id: String,
    client_version: String,
    operator: String,
    cwd: PathBuf,
    created_at: u64,
    expires_at: u64,
    action: Action,
    preview: Preview,
    payload: P,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct MutableStatus {
    schema_version: u32,
    operation_id: String,
    plan_sha256: String,
    phase: Phase,
    updated_at: u64,
    published: bool,
    failure_code: Option<String>,
    next_action: String,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RequestIntent {
    schema_version: u32,
    operation_id: String,
    client_version: String,
    operator: String,
    cwd: PathBuf,
    action: Action,
    created_at: u64,
    expires_at: u64,
    process_nonce: String,
}
fn process_nonce() -> &'static str {
    static NONCE: std::sync::OnceLock<String> = std::sync::OnceLock::new();
    NONCE.get_or_init(|| uuid::Uuid::new_v4().to_string())
}

pub(crate) struct Store {
    root: PathBuf,
    scope: PathBuf,
    operator: String,
    cwd: PathBuf,
    identity: DirectoryIdentity,
}

pub(crate) struct Operation<P> {
    plan: ImmutablePlan<P>,
    status: MutableStatus,
    status_bytes: Vec<u8>,
}

pub(super) fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

impl<P> Operation<P> {
    pub fn id(&self) -> &str {
        &self.plan.operation_id
    }
    pub fn plan_sha256(&self) -> &str {
        &self.status.plan_sha256
    }
    pub fn action(&self) -> Action {
        self.plan.action
    }
    pub fn payload(&self) -> &P {
        &self.plan.payload
    }
    pub fn phase(&self) -> Phase {
        self.status.phase
    }
    pub fn is_expired(&self) -> bool {
        now() >= self.plan.expires_at || now() < self.plan.created_at
    }
    pub fn view(&self) -> OperationView {
        OperationView {
            schema_version: SCHEMA,
            operation_id: self.plan.operation_id.clone(),
            action: self.plan.action,
            phase: self.status.phase,
            created_at: self.plan.created_at,
            updated_at: self.status.updated_at,
            expires_at: self.plan.expires_at,
            preview: self.plan.preview.clone(),
            published: self.status.published,
            failure_code: self.status.failure_code.clone(),
            next_action: self.status.next_action.clone(),
        }
    }
}

impl Store {
    pub fn current() -> Result<Self, String> {
        Self::open_current(true)
    }

    fn open_current(create: bool) -> Result<Self, String> {
        let target = crate::cli::shell_target::resolve_for_shell("unknown")?;
        crate::cli::shell_target::require_personal_writer(&target)?;
        #[cfg(unix)]
        if unsafe { libc::geteuid() } == 0 {
            return Err("personal lifecycle controls require a non-root operator; use the owning installation channel for administrator changes".into());
        }
        let scope =
            tirith_core::policy::state_dir().ok_or("cannot locate private lifecycle state")?;
        if !scope.is_absolute()
            || scope
                .components()
                .any(|part| matches!(part, std::path::Component::ParentDir))
        {
            return Err("lifecycle state must be absolute without traversal".into());
        }
        let root = scope.join("lifecycle/v1");
        if create {
            fs_helpers::ensure_private_directory(&root, &scope)?;
        }
        let identity = DirectoryIdentity::capture(&root)?;
        Ok(Self {
            root,
            scope,
            operator: format!(
                "{:?}:{}",
                target.operator_uid,
                target.operator_home.display()
            ),
            cwd: std::env::current_dir()
                .and_then(|dir| dir.canonicalize())
                .map_err(|_| "cannot retain operation working directory")?,
            identity,
        })
    }

    pub fn revalidate(&self) -> Result<(), String> {
        self.identity.revalidate()
    }
    pub fn handoff_identity(&self) -> Result<serde_json::Value, String> {
        self.identity.private_handoff_identity()
    }

    fn path(&self, id: &str, suffix: &str) -> Result<PathBuf, String> {
        if uuid::Uuid::parse_str(id)
            .map(|parsed| parsed.to_string())
            .ok()
            .as_deref()
            != Some(id)
        {
            return Err("lifecycle operation ID must be a canonical UUID".into());
        }
        Ok(self.root.join(format!("{id}.{suffix}")))
    }

    fn read_optional_private(&self, path: &Path) -> Result<Option<Vec<u8>>, String> {
        self.revalidate()?;
        let snapshot = fs_helpers::read_snapshot_scoped(path, &self.scope)?;
        snapshot.require_private()?;
        let Some(bytes) = snapshot.bytes else {
            return Ok(None);
        };
        if bytes.len() > RECORD_CAP {
            return Err("lifecycle operation record exceeds its size limit".into());
        }
        self.revalidate()?;
        Ok(Some(bytes))
    }
    fn read_private(&self, path: &Path) -> Result<Vec<u8>, String> {
        self.read_optional_private(path)?
            .ok_or("lifecycle operation record is missing".into())
    }

    fn write_private(
        &self,
        path: &Path,
        bytes: &[u8],
        expected: Option<&[u8]>,
    ) -> Result<(), String> {
        if bytes.len() > RECORD_CAP {
            return Err("lifecycle operation record exceeds its size limit".into());
        }
        let text = std::str::from_utf8(bytes)
            .map_err(|_| "lifecycle record is not UTF-8")?
            .to_string();
        self.revalidate()?;
        fs_helpers::transactional_update_checked(
            path,
            &self.scope,
            false,
            |snapshot| {
                snapshot.require_private()?;
                if snapshot.bytes() != expected {
                    return Err(
                        "lifecycle record changed; retain it and refresh operation status".into(),
                    );
                }
                let update = fs_helpers::FileUpdate::write_text(text.clone(), 0o600);
                #[cfg(unix)]
                let update = update.with_exact_mode();
                Ok(update)
            },
            || self.revalidate(),
        )?;
        Ok(())
    }

    fn read_intent(&self, id: &str) -> Result<Option<RequestIntent>, String> {
        self.read_optional_private(&self.path(id, "intent.json")?)?
            .map(|bytes| {
                let intent: RequestIntent = serde_json::from_slice(&bytes)
                    .map_err(|_| "lifecycle request intent is malformed")?;
                if intent.schema_version != SCHEMA
                    || intent.operation_id != id
                    || intent.operator != self.operator
                    || intent.cwd != self.cwd
                {
                    return Err("request intent operator or working directory changed".into());
                }
                Ok(intent)
            })
            .transpose()
    }

    /// Durable idempotency reservation, written before network resolution. An
    /// interrupted reservation never resolves a different latest candidate.
    pub fn reserve(&self, id: &str, action: Action) -> Result<Option<OperationView>, String> {
        let path = self.path(id, "intent.json")?;
        let _lock = fs_helpers::try_lock_operation(&self.root.join("admission.lock"), &self.scope)?
            .ok_or("another lifecycle request is being recorded; retry this same operation ID")?;
        if let Some(intent) = self.read_intent(id)? {
            if intent.action != action {
                return Err("operation ID is already bound to another action".into());
            }
            return self.view_any(id).map(Some);
        }
        let (names, limited) =
            fs_helpers::private_directory_names(&self.root, &self.scope, MAX_OPERATIONS * 7 + 1)?;
        if limited
            || names
                .iter()
                .filter(|name| name.to_string_lossy().ends_with(".intent.json"))
                .count()
                >= MAX_OPERATIONS
        {
            return Err("lifecycle evidence retention limit reached; review prior operation records before another request".into());
        }
        let created_at = now();
        if created_at == 0 {
            return Err("current clock unavailable; cannot expire request".into());
        }
        let intent = RequestIntent {
            schema_version: SCHEMA,
            operation_id: id.into(),
            client_version: env!("CARGO_PKG_VERSION").into(),
            operator: self.operator.clone(),
            cwd: self.cwd.clone(),
            action,
            created_at,
            expires_at: created_at + PLAN_TTL,
            process_nonce: process_nonce().into(),
        };
        self.write_private(
            &path,
            &serde_json::to_vec(&intent).map_err(|_| "cannot encode request intent")?,
            None,
        )?;
        Ok(None)
    }

    pub fn record_failure(&self, id: &str, error: &str) -> Result<(), String> {
        self.read_intent(id)?.ok_or("unknown lifecycle request")?;
        let bounded: String = error.chars().take(8192).collect();
        let bytes = serde_json::to_vec(
            &serde_json::json!({"schema_version":1,"operation_id":id,"diagnostic":bounded}),
        )
        .map_err(|_| "cannot encode private lifecycle diagnostic")?;
        self.write_private(&self.path(id, "failure.json")?, &bytes, None)
    }

    pub fn fail_preparation(&self, id: &str) -> Result<(), String> {
        let intent = self.read_intent(id)?.ok_or("unknown request intent")?;
        let bytes =
            serde_json::to_vec(&intent).map_err(|_| "cannot encode failed preparation binding")?;
        self.write_private(
            &self.path(id, "preparation-failed.json")?,
            super::hex_sha256(&bytes).as_bytes(),
            None,
        )
    }

    pub fn view_any(&self, id: &str) -> Result<OperationView, String> {
        let intent = self
            .read_intent(id)?
            .ok_or("unknown lifecycle operation ID")?;
        let plan_present = self
            .read_optional_private(&self.path(id, "plan.json")?)?
            .is_some();
        let status_present = self
            .read_optional_private(&self.path(id, "status.json")?)?
            .is_some();
        if plan_present && status_present {
            return self
                .load::<serde_json::Value>(id)
                .map(|operation| operation.view());
        }
        // A crash between the create-only plan and first status write leaves
        // evidence, not an applicable preview. Never recreate either record,
        // expose its private payload, or resolve a new candidate under this ID.
        let incomplete = plan_present || status_present;
        let failed = self
            .read_optional_private(&self.path(id, "preparation-failed.json")?)?
            .is_some();
        let live = !incomplete
            && !failed
            && intent.process_nonce == process_nonce()
            && now() < intent.expires_at
            && now() >= intent.created_at;
        Ok(OperationView {
            schema_version: SCHEMA, operation_id: id.into(), action: intent.action,
            phase: if live { Phase::Preparing } else { Phase::RefreshRequired },
            created_at: intent.created_at, updated_at: intent.created_at, expires_at: intent.expires_at,
            preview: Preview { current_version: intent.client_version, candidate_version: None,
                candidate_sequence: None, candidate_format: None,
                evidence: "no_verified_candidate_prepared".into(), compatible: false, issues: vec![],
                configuration_changed: false, integration_reload_required: false, service_restart_required: false },
            published: false,
            failure_code: incomplete.then(|| "operation_journal_incomplete".into()),
            next_action: if incomplete {
                "The operation journal is incomplete, so publication cannot be established and application authority cannot be reconstructed. Preserve and inspect this evidence before explicitly preparing a fresh request ID. This ID cannot resolve or apply another candidate."
            } else {
                "This request has not produced a verified preview. Retry status with the same ID; if preparation stopped, explicitly prepare a fresh request ID. This ID will never resolve another candidate."
            }.into(),
        })
    }

    fn support_view(&self, id: &str) -> Result<SupportStatus, String> {
        let operation = self.view_any(id)?;
        // Read only to validate the selected envelope and presence. Do not put
        // its diagnostic string into a support export, even after truncation.
        let failure = self.read_optional_private(&self.path(id, "failure.json")?)?;
        if let Some(bytes) = &failure {
            #[derive(Deserialize)]
            #[serde(deny_unknown_fields)]
            struct Failure {
                schema_version: u32,
                operation_id: String,
                diagnostic: String,
            }
            let record: Failure = serde_json::from_slice(bytes)
                .map_err(|_| "selected lifecycle failure record is malformed")?;
            if record.schema_version != SCHEMA
                || record.operation_id != id
                || record.diagnostic.chars().count() > 8192
            {
                return Err("selected lifecycle failure identity or bounds are invalid".into());
            }
        }
        let selected_failure_detail = if operation.failure_code.is_some() || failure.is_some() {
            Some(match operation.phase {
                Phase::RecoveryRequired | Phase::PublicationIntent | Phase::Published =>
                    "The selected operation requires publication recovery review. Do not replay the swap; raw diagnostic text remains private.",
                Phase::RefreshRequired =>
                    "The selected request has no reusable application authority. Inspect its recorded phase and prepare a fresh request only as an explicit action; raw diagnostic text remains private.",
                Phase::Failed =>
                    "Verification of the selected prepared operation failed before publication intent. Raw diagnostic text remains private.",
                Phase::Partial =>
                    "The selected refresh completed partially; consult its public result and retain the prior valid data for failed sources. Raw diagnostic text remains private.",
                _ => "A bounded failure diagnostic exists for the selected operation and remains private; inspect the public phase before any further action.",
            }.into())
        } else {
            None
        };
        self.revalidate()?;
        Ok(SupportStatus {
            operation,
            selected_failure_detail,
        })
    }

    pub fn create<P: Serialize + DeserializeOwned>(
        &self,
        id: &str,
        action: Action,
        preview: Preview,
        payload: P,
    ) -> Result<Operation<P>, String> {
        // Serialize admissions across workers so concurrent previews cannot
        // exceed the bounded operation store. No old evidence is auto-deleted.
        let _admission =
            fs_helpers::try_lock_operation(&self.root.join("admission.lock"), &self.scope)?
                .ok_or("another lifecycle preview is being recorded; retry")?;
        let (names, limited) =
            fs_helpers::private_directory_names(&self.root, &self.scope, MAX_OPERATIONS * 7 + 1)?;
        let plans = names
            .iter()
            .filter(|name| name.to_string_lossy().ends_with(".plan.json"))
            .count();
        if limited || plans >= MAX_OPERATIONS {
            return Err("lifecycle evidence retention limit reached; review completed operation records before preparing another change".into());
        }
        let intent = self
            .read_intent(id)?
            .ok_or("lifecycle request was not reserved before preparation")?;
        if intent.action != action
            || intent.client_version != env!("CARGO_PKG_VERSION")
            || intent.process_nonce != process_nonce()
            || now() >= intent.expires_at
        {
            return Err(
                "lifecycle request intent changed or expired; prepare a fresh request".into(),
            );
        }
        let id = id.to_string();
        let created_at = now();
        if created_at == 0 {
            return Err("current clock is unavailable; cannot expire lifecycle approval".into());
        }
        let plan = ImmutablePlan {
            schema_version: SCHEMA,
            operation_id: id.clone(),
            client_version: env!("CARGO_PKG_VERSION").into(),
            operator: self.operator.clone(),
            cwd: self.cwd.clone(),
            created_at,
            expires_at: created_at + PLAN_TTL,
            action,
            preview,
            payload,
        };
        let plan_bytes =
            serde_json::to_vec(&plan).map_err(|_| "cannot encode immutable lifecycle plan")?;
        let status = MutableStatus {
            schema_version: SCHEMA,
            operation_id: id.clone(),
            plan_sha256: super::hex_sha256(&plan_bytes),
            phase: Phase::Prepared,
            updated_at: created_at,
            published: false,
            failure_code: None,
            next_action: "Review the verified preview, then explicitly apply this operation ID."
                .into(),
        };
        let status_bytes =
            serde_json::to_vec(&status).map_err(|_| "cannot encode lifecycle status")?;
        self.write_private(&self.path(&id, "plan.json")?, &plan_bytes, None)?;
        self.write_private(&self.path(&id, "status.json")?, &status_bytes, None)?;
        Ok(Operation {
            plan,
            status,
            status_bytes,
        })
    }

    pub fn load<P: DeserializeOwned>(&self, id: &str) -> Result<Operation<P>, String> {
        let plan_bytes = self.read_private(&self.path(id, "plan.json")?)?;
        let status_bytes = self.read_private(&self.path(id, "status.json")?)?;
        let plan: ImmutablePlan<P> = serde_json::from_slice(&plan_bytes)
            .map_err(|_| "immutable lifecycle plan is malformed")?;
        let status: MutableStatus =
            serde_json::from_slice(&status_bytes).map_err(|_| "lifecycle result is malformed")?;
        if plan.schema_version != SCHEMA
            || status.schema_version != SCHEMA
            || plan.operation_id != id
            || status.operation_id != id
            || plan.operator != self.operator
            || plan.cwd != self.cwd
            || super::hex_sha256(&plan_bytes) != status.plan_sha256
        {
            return Err(
                "lifecycle plan/result identity changed; do not apply this operation".into(),
            );
        }
        Ok(Operation {
            plan,
            status,
            status_bytes,
        })
    }

    pub fn require_original_client<P>(&self, operation: &Operation<P>) -> Result<(), String> {
        if operation.plan.client_version != env!("CARGO_PKG_VERSION") {
            return Err("a different client created this operation; inspect its status and prepare a new change with the current client".into());
        }
        Ok(())
    }

    pub fn lock(&self, id: &str) -> Result<Option<fs_helpers::PlatformLock>, String> {
        self.revalidate()?;
        fs_helpers::try_lock_operation(&self.path(id, "lock")?, &self.scope)
    }

    pub fn transition<P>(
        &self,
        operation: &mut Operation<P>,
        phase: Phase,
        published: bool,
        failure_code: Option<&str>,
        next_action: &str,
    ) -> Result<(), String> {
        if !operation.status.phase.permits(phase) {
            return Err(
                "completed lifecycle operations cannot be replayed; prepare another operation"
                    .into(),
            );
        }
        if phase == Phase::Published && !published {
            return Err("published phase requires a recorded verified publication".into());
        }
        if operation.status.published && !published {
            return Err("a recorded publication cannot be forgotten".into());
        }
        let status = MutableStatus {
            schema_version: SCHEMA,
            operation_id: operation.id().into(),
            plan_sha256: operation.status.plan_sha256.clone(),
            phase,
            updated_at: now(),
            published,
            failure_code: failure_code.map(str::to_string),
            next_action: next_action.into(),
        };
        let bytes = serde_json::to_vec(&status).map_err(|_| "cannot encode lifecycle result")?;
        self.write_private(
            &self.path(operation.id(), "status.json")?,
            &bytes,
            Some(&operation.status_bytes),
        )?;
        operation.status = status;
        operation.status_bytes = bytes;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture() -> (tempfile::TempDir, Store) {
        let directory = tempfile::tempdir().unwrap();
        let scope = directory.path().canonicalize().unwrap();
        let root = scope.join("lifecycle/v1");
        fs_helpers::ensure_private_directory(&root, &scope).unwrap();
        let identity = DirectoryIdentity::capture(&root).unwrap();
        (
            directory,
            Store {
                root,
                scope: scope.clone(),
                operator: "fixture-operator".into(),
                cwd: scope,
                identity,
            },
        )
    }
    fn preview() -> Preview {
        Preview {
            current_version: "0.4.2".into(),
            candidate_version: Some("0.4.3".into()),
            candidate_sequence: None,
            candidate_format: None,
            evidence: "signed_fixture".into(),
            compatible: true,
            issues: vec![],
            configuration_changed: false,
            integration_reload_required: true,
            service_restart_required: true,
        }
    }
    fn prepared(store: &Store) -> Operation<serde_json::Value> {
        let id = uuid::Uuid::new_v4().to_string();
        assert!(store.reserve(&id, Action::Update).unwrap().is_none());
        store
            .create(
                &id,
                Action::Update,
                preview(),
                serde_json::json!({"private_policy_witness":"do-not-expose"}),
            )
            .unwrap()
    }

    #[test]
    fn request_uuid_is_reserved_before_resolution_and_cannot_switch_action() {
        let (_directory, store) = fixture();
        let id = uuid::Uuid::new_v4().to_string();
        assert!(store.reserve(&id, Action::Update).unwrap().is_none());
        assert_eq!(
            store.reserve(&id, Action::Update).unwrap().unwrap().phase,
            Phase::Preparing
        );
        assert!(store.reserve(&id, Action::Rollback).is_err());
        store.fail_preparation(&id).unwrap();
        assert_eq!(
            store.reserve(&id, Action::Update).unwrap().unwrap().phase,
            Phase::RefreshRequired
        );
        assert!(store.reserve("../replacement", Action::Update).is_err());
        assert!(store.reserve(&id.to_uppercase(), Action::Update).is_err());
    }

    #[test]
    fn replay_returns_same_immutable_preview_without_private_payload() {
        let (_directory, store) = fixture();
        let operation = prepared(&store);
        let replay = store
            .reserve(operation.id(), Action::Update)
            .unwrap()
            .unwrap();
        assert_eq!(replay.operation_id, operation.id());
        assert_eq!(replay.preview.candidate_version.as_deref(), Some("0.4.3"));
        let public = serde_json::to_string(&replay).unwrap();
        assert!(!public.contains("do-not-expose"));
        assert!(!public.contains("private_policy_witness"));
        assert!(store
            .create(
                operation.id(),
                Action::Update,
                preview(),
                serde_json::json!({})
            )
            .is_err());
    }

    #[test]
    fn interrupted_plan_publication_returns_no_applicable_preview() {
        let (_directory, store) = fixture();
        let operation = prepared(&store);
        std::fs::remove_file(store.path(operation.id(), "status.json").unwrap()).unwrap();
        let before = std::fs::read(store.path(operation.id(), "plan.json").unwrap()).unwrap();
        let view = store
            .reserve(operation.id(), Action::Update)
            .unwrap()
            .unwrap();
        assert_eq!(view.phase, Phase::RefreshRequired);
        assert_eq!(
            view.failure_code.as_deref(),
            Some("operation_journal_incomplete")
        );
        assert!(!view.preview.compatible);
        assert!(view.preview.candidate_version.is_none());
        assert!(!store.path(operation.id(), "status.json").unwrap().exists());
        assert_eq!(
            before,
            std::fs::read(store.path(operation.id(), "plan.json").unwrap()).unwrap()
        );
        assert!(store.load::<serde_json::Value>(operation.id()).is_err());
    }

    #[test]
    fn selected_support_view_is_read_only_and_excludes_private_failure_context() {
        let (_directory, store) = fixture();
        let mut operation = prepared(&store);
        store
            .transition(&mut operation, Phase::Accepted, false, None, "accepted")
            .unwrap();
        store
            .transition(&mut operation, Phase::Verifying, false, None, "verifying")
            .unwrap();
        store
            .record_failure(
                operation.id(),
                "/private/operator/token context=secret-fixture",
            )
            .unwrap();
        store
            .transition(
                &mut operation,
                Phase::Failed,
                false,
                Some("verification_failed"),
                "Prepare explicitly.",
            )
            .unwrap();
        let paths = ["intent.json", "plan.json", "status.json", "failure.json"];
        let before: Vec<_> = paths
            .iter()
            .map(|suffix| std::fs::read(store.path(operation.id(), suffix).unwrap()).unwrap())
            .collect();
        let support = store.support_view(operation.id()).unwrap();
        assert_eq!(support.operation.phase, Phase::Failed);
        assert!(support.selected_failure_detail.is_some());
        let json = serde_json::to_string(&support).unwrap();
        for private in [
            "private_policy_witness",
            "do-not-expose",
            "/private/operator",
            "secret-fixture",
        ] {
            assert!(!json.contains(private));
        }
        for (suffix, before) in paths.iter().zip(before) {
            assert_eq!(
                before,
                std::fs::read(store.path(operation.id(), suffix).unwrap()).unwrap()
            );
        }
        assert!(store
            .support_view(&uuid::Uuid::new_v4().to_string())
            .is_err());
        assert!(store.support_view("../another-record").is_err());
    }

    #[test]
    fn interrupted_process_intent_cannot_resolve_another_candidate() {
        let (_directory, store) = fixture();
        let id = uuid::Uuid::new_v4().to_string();
        store.reserve(&id, Action::Update).unwrap();
        let path = store.path(&id, "intent.json").unwrap();
        let bytes = store.read_private(&path).unwrap();
        let mut intent: RequestIntent = serde_json::from_slice(&bytes).unwrap();
        intent.process_nonce = "previous-process".into();
        store
            .write_private(&path, &serde_json::to_vec(&intent).unwrap(), Some(&bytes))
            .unwrap();
        assert_eq!(
            store.reserve(&id, Action::Update).unwrap().unwrap().phase,
            Phase::RefreshRequired
        );
        assert!(store
            .create(&id, Action::Update, preview(), serde_json::json!({}))
            .is_err());
    }

    #[test]
    fn plan_tampering_and_stale_status_writers_are_refused() {
        let (_directory, store) = fixture();
        let mut operation = prepared(&store);
        let mut stale = store.load::<serde_json::Value>(operation.id()).unwrap();
        store
            .transition(&mut operation, Phase::Accepted, false, None, "accepted")
            .unwrap();
        assert!(store
            .transition(&mut stale, Phase::Cancelled, false, None, "cancelled")
            .is_err());
        let path = store.path(operation.id(), "plan.json").unwrap();
        let original = store.read_private(&path).unwrap();
        let mut changed: serde_json::Value = serde_json::from_slice(&original).unwrap();
        changed["payload"]["candidate"] = serde_json::json!("substituted");
        store
            .write_private(
                &path,
                &serde_json::to_vec(&changed).unwrap(),
                Some(&original),
            )
            .unwrap();
        assert!(store.load::<serde_json::Value>(operation.id()).is_err());
    }

    #[test]
    fn publication_cannot_be_replayed_or_forgotten() {
        let (_directory, store) = fixture();
        let mut operation = prepared(&store);
        assert!(store
            .transition(
                &mut operation,
                Phase::Completed,
                true,
                None,
                "skip verification"
            )
            .is_err());
        for (phase, published) in [
            (Phase::Accepted, false),
            (Phase::Verifying, false),
            (Phase::PublicationIntent, false),
            (Phase::Published, true),
            (Phase::Completed, true),
        ] {
            store
                .transition(&mut operation, phase, published, None, "fixture")
                .unwrap();
        }
        assert!(store
            .transition(&mut operation, Phase::Accepted, true, None, "replay")
            .is_err());
        assert!(store
            .transition(&mut operation, Phase::Completed, false, None, "forget")
            .is_err());
        operation.plan.client_version = "old-client".into();
        assert!(store.require_original_client(&operation).is_err());
        assert_eq!(operation.view().phase, Phase::Completed);
    }

    #[test]
    fn directory_replacement_invalidates_original_guard() {
        let (_directory, store) = fixture();
        #[cfg(unix)]
        {
            std::fs::rename(&store.root, store.root.with_extension("retained")).unwrap();
            fs_helpers::ensure_private_directory(&store.root, &store.scope).unwrap();
            assert!(store.revalidate().is_err());
        }
        #[cfg(windows)]
        {
            assert!(std::fs::rename(&store.root, store.root.with_extension("retained")).is_err());
            store.revalidate().unwrap();
        }
    }

    #[test]
    fn retention_bounds_preserve_incomplete_requests() {
        let (_directory, store) = fixture();
        for _ in 0..MAX_OPERATIONS {
            store
                .reserve(&uuid::Uuid::new_v4().to_string(), Action::Update)
                .unwrap();
        }
        assert!(store
            .reserve(&uuid::Uuid::new_v4().to_string(), Action::Update)
            .is_err());
    }
}
