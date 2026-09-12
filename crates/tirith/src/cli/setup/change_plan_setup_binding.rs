//! Immutable setup verification intent and a live, file-only completion lease.
//! This foundation cannot start a shell, authenticate a hook, or produce a
//! blocking proof. A future coordinator must add its own qualified startup,
//! process ownership, authenticated transport and attempt/replay boundary.

use std::collections::BTreeSet;
use std::marker::PhantomData;
use std::rc::Rc;

use super::*;
use crate::cli::control::identity::{BinaryIdentity, DirectoryIdentity};
use crate::cli::setup::shell_service::{RetainedShellInputs, ShellKind, ShellPrecondition};

const VERIFICATION_SCHEMA: u32 = 1;
const MAX_UNCHANGED_INPUTS: usize = 16;
const MAX_UNCHANGED_INPUT_BYTES: u64 = 8 * 1024 * 1024;

#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum VerificationScope {
    FreshTerminalActivation,
}

/// Private request metadata, not execution authority. In particular it pins
/// the selected setup inputs, not the complete dynamic shell startup closure.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct SetupVerificationIntent {
    schema_version: u32,
    scope: VerificationScope,
    shell: ShellKind,
    unchanged_inputs: Vec<SetupVerificationDocument>,
    planned_postconditions: Vec<SetupVerificationDocument>,
}

/// Content bindings for inputs omitted from a no-op or partially changing plan.
/// Paths and low-entropy content hashes are private journal data only.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct SetupVerificationDocument {
    path: PathBuf,
    scope: PathBuf,
    bytes: u64,
    sha256: Option<String>,
}

impl SetupVerificationDocument {
    pub(in crate::cli::setup) fn observed(
        path: &Path,
        scope: &Path,
        bytes: Option<&str>,
    ) -> Result<Self, String> {
        let result = Self {
            path: path.into(),
            scope: scope.into(),
            bytes: bytes.map_or(0, |bytes| bytes.len() as u64),
            sha256: bytes.map(|bytes| format!("{:x}", Sha256::digest(bytes.as_bytes()))),
        };
        result.validate()?;
        Ok(result)
    }

    pub(in crate::cli::setup) fn is_path(&self, path: &Path) -> bool {
        self.path == path
    }

    fn validate(&self) -> Result<(), String> {
        if !self.path.is_absolute()
            || !self.scope.is_absolute()
            || !self.path.starts_with(&self.scope)
            || self.path == self.scope
            || [&self.path, &self.scope].iter().any(|path| {
                path.components()
                    .any(|part| matches!(part, std::path::Component::ParentDir))
            })
            || self.bytes > MAX_SETUP_FILE_BYTES as u64
            || self.sha256.as_ref().is_some_and(|value| {
                value.len() != 64
                    || !value
                        .bytes()
                        .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
            })
            || (self.sha256.is_none() && self.bytes != 0)
        {
            return Err(refresh("invalid unchanged setup input binding"));
        }
        Ok(())
    }

    fn matches(&self, bytes: Option<&[u8]>) -> bool {
        match (self.sha256.as_deref(), bytes) {
            (None, None) => true,
            (Some(expected), Some(bytes)) => {
                bytes.len() as u64 == self.bytes
                    && format!("{:x}", Sha256::digest(bytes)) == expected
            }
            _ => false,
        }
    }
}

/// Fixed public request metadata. It reports neither availability nor success.
#[derive(Serialize)]
pub(crate) struct SetupVerificationRequest {
    schema_version: u32,
    scope: VerificationScope,
    shell: ShellKind,
}

impl SetupVerificationIntent {
    pub(in crate::cli::setup) fn for_shell(
        shell: ShellKind,
        unchanged_inputs: Vec<SetupVerificationDocument>,
    ) -> Result<Self, String> {
        let result = Self {
            schema_version: VERIFICATION_SCHEMA,
            scope: VerificationScope::FreshTerminalActivation,
            shell,
            unchanged_inputs,
            planned_postconditions: Vec::new(),
        };
        result.validate_documents()?;
        Ok(result)
    }

    pub(in crate::cli::setup) fn add_unchanged_inputs(
        &mut self,
        inputs: Vec<SetupVerificationDocument>,
    ) -> Result<(), String> {
        self.unchanged_inputs.extend(inputs);
        self.validate_documents()
    }

    fn validate_documents(&self) -> Result<(), String> {
        if self.schema_version != VERIFICATION_SCHEMA
            || !matches!(
                self.shell,
                ShellKind::Bash | ShellKind::Zsh | ShellKind::Fish
            )
            || self.unchanged_inputs.len() + self.planned_postconditions.len()
                > MAX_UNCHANGED_INPUTS
        {
            return Err(refresh("unsupported setup verification intent"));
        }
        let mut seen = BTreeSet::new();
        let mut total = 0u64;
        for input in self
            .unchanged_inputs
            .iter()
            .chain(&self.planned_postconditions)
        {
            input.validate()?;
            if !seen.insert(&input.path) {
                return Err(refresh("duplicate setup verification input"));
            }
            total = total
                .checked_add(input.bytes)
                .ok_or_else(|| refresh("setup verification input size overflow"))?;
        }
        if total > MAX_UNCHANGED_INPUT_BYTES {
            return Err(refresh("setup verification inputs exceed the 8 MiB limit"));
        }
        Ok(())
    }

    pub(super) fn validate_for(
        &self,
        kind: OperationKind,
        shell: Option<&ShellPrecondition>,
        targets: impl Iterator<Item = PathBuf>,
    ) -> Result<(), String> {
        self.validate_documents()?;
        if kind != OperationKind::RecommendedSetup
            || shell.map(ShellPrecondition::selected_shell) != Some(self.shell)
        {
            return Err(refresh(
                "verification intent requires its exact recommended shell setup",
            ));
        }
        let targets = targets.collect::<BTreeSet<_>>();
        if self
            .unchanged_inputs
            .iter()
            .any(|input| targets.contains(&input.path))
        {
            return Err(refresh(
                "unchanged verification input overlaps a mutation target",
            ));
        }
        if self
            .planned_postconditions
            .iter()
            .any(|input| !targets.contains(&input.path))
        {
            return Err(refresh(
                "verification postcondition is not a planned target",
            ));
        }
        Ok(())
    }

    pub(crate) fn request(&self) -> SetupVerificationRequest {
        SetupVerificationRequest {
            schema_version: self.schema_version,
            scope: self.scope,
            shell: self.shell,
        }
    }

    pub(super) fn retain_unchanged(&self) -> Result<Vec<RetainedSetupDocument>, String> {
        self.validate_documents()?;
        self.unchanged_inputs
            .iter()
            .map(RetainedSetupDocument::capture)
            .collect()
    }

    pub(super) fn bind_planned_postconditions(
        &mut self,
        steps: &[Step],
        preimages: &std::collections::BTreeMap<PathBuf, Option<String>>,
    ) -> Result<(), String> {
        if !self.planned_postconditions.is_empty() {
            return Err("verification postconditions were already bound".into());
        }
        for step in steps {
            let before = preimages
                .get(&step.target)
                .ok_or("verification requires the exact caller preimage for every setup target")?;
            let after = transform(&step.edit, before.as_deref(), false)?.or(before.clone());
            self.planned_postconditions
                .push(SetupVerificationDocument::observed(
                    &step.target,
                    &step.scope_root,
                    after.as_deref(),
                )?);
        }
        self.validate_documents()
    }

    fn retain_completed(&self) -> Result<Vec<RetainedSetupDocument>, String> {
        self.validate_documents()?;
        self.unchanged_inputs
            .iter()
            .chain(&self.planned_postconditions)
            .map(RetainedSetupDocument::capture)
            .collect()
    }
}

/// The native file remains held, including an empty file. An absent input keeps
/// its nearest existing parent and every ancestor held and is checked again.
pub(super) struct RetainedSetupDocument {
    expected: SetupVerificationDocument,
    directory: DirectoryIdentity,
    file: Option<BinaryIdentity>,
}

impl RetainedSetupDocument {
    fn capture(expected: &SetupVerificationDocument) -> Result<Self, String> {
        expected.validate()?;
        let mut parent = expected
            .path
            .parent()
            .ok_or("setup input has no parent")?
            .to_path_buf();
        while !parent.exists() {
            if !parent.pop() {
                return Err(refresh("setup input parent is unavailable"));
            }
        }
        let directory = DirectoryIdentity::capture_trusted(&parent)?;
        let snapshot = fs_helpers::read_snapshot_scoped(&expected.path, &expected.scope)?;
        if !expected.matches(snapshot.bytes.as_deref()) {
            return Err(refresh("unchanged setup input content changed"));
        }
        let file = expected
            .sha256
            .as_ref()
            .map(|sha| {
                let held = BinaryIdentity::capture_input(&expected.path)?;
                if held.sha256() != sha {
                    return Err(refresh("setup input changed during retention"));
                }
                Ok(held)
            })
            .transpose()?;
        let result = Self {
            expected: expected.clone(),
            directory,
            file,
        };
        result.revalidate()?;
        Ok(result)
    }

    pub(super) fn revalidate(&self) -> Result<(), String> {
        self.directory.revalidate()?;
        if let Some(file) = &self.file {
            file.revalidate()?;
        }
        let current = fs_helpers::read_snapshot_scoped(&self.expected.path, &self.expected.scope)?;
        if !self.expected.matches(current.bytes.as_deref()) {
            return Err(refresh("retained setup input changed"));
        }
        Ok(())
    }
}

pub(super) fn bind_verification_digest(
    original: String,
    verification: &Option<SetupVerificationIntent>,
) -> Result<String, String> {
    match verification {
        Some(verification) => digest(&(
            "tirith-setup-verification-intent-v1",
            original,
            verification,
        )),
        None => Ok(original), // Preserve the exact historical file-only digest.
    }
}

fn expected_payload_digest(record: &Journal) -> Result<String, String> {
    let mut initial_steps = record.steps.clone();
    for step in &mut initial_steps {
        step.state = StepState::Pending;
        step.undo_document = None;
    }
    let original = digest(&(
        record.kind,
        &record.operator,
        &record.client_version,
        &initial_steps,
        &record.shell_precondition,
    ))?;
    let original = if record.no_op {
        digest(&("tirith-noop-v1", original, record.resolution_cwd.as_deref()))?
    } else {
        original
    };
    bind_verification_digest(
        bind_agent_digest(
            bind_review_digest(original, &record.impact_review)?,
            &record.agent_precondition,
        )?,
        &record.setup_verification,
    )
}

fn completion_fingerprint(record: &Journal) -> Result<String, String> {
    digest(&(
        "tirith-completed-setup-binding-v1",
        &record.operation_id,
        &record.payload_digest,
        &record.request_digest,
        &record.caller_intent_digest,
        &record.resolution_cwd,
        &record.policy_identity,
        &record.authorization,
        &record.external_authorization,
        record.created_at,
        record.state,
    ))
}

fn validate_completed_record(record: &Journal) -> Result<(), String> {
    if record.kind != OperationKind::RecommendedSetup
        || record.client_version != env!("CARGO_PKG_VERSION")
        || !uuid::Uuid::parse_str(&record.operation_id)
            .is_ok_and(|id| id.to_string() == record.operation_id)
        || !matches!(
            record.state,
            JobState::Completed | JobState::CompletedWithRecovery
        )
        || record.active_action == Some(JobAction::Undo)
        || record.undo_external_authorization.is_some()
        || record.setup_verification_cancelled
        || record.caller_intent_digest.is_none()
        || record.steps.iter().any(|step| {
            !matches!(
                step.state,
                StepState::Applied | StepState::AppliedWithRecovery
            )
        })
        || record.steps.len() > MAX_STEPS
        || (record.no_op && !record.steps.is_empty())
        || (!record.no_op && record.steps.is_empty())
    {
        return Err(refresh(
            "setup is not an unchanged completed verification request",
        ));
    }
    let verification = record
        .setup_verification
        .as_ref()
        .ok_or_else(|| refresh("setup verification was not requested"))?;
    verification.validate_for(
        record.kind,
        record.shell_precondition.as_ref(),
        record.steps.iter().map(|step| step.target.clone()),
    )?;
    if verification.planned_postconditions.len() != record.steps.len() {
        return Err(refresh(
            "setup verification is missing a planned file postcondition",
        ));
    }
    if record.payload_digest != expected_payload_digest(record)? {
        return Err(refresh("completed setup immutable payload changed"));
    }
    Ok(())
}

/// This is not a shell-verification proof. It binds only completed file setup.
/// It cannot be cloned, deserialized, serialized, or moved to another thread:
/// native Windows mutexes must be released by the thread that acquired them.
#[allow(dead_code)] // Consumed by the separately reviewed activation coordinator.
pub(crate) struct CompletedSetupLease {
    service: MutationService,
    operation_id: String,
    fingerprint: String,
    policy: EffectivePolicySnapshot,
    shell_inputs: RetainedShellInputs,
    agent_inputs: Option<super::super::claude_service::RetainedAgentInputs>,
    documents: Vec<RetainedSetupDocument>,
    journal_directory: DirectoryIdentity,
    journal_file: BinaryIdentity,
    verification: SetupVerificationIntent,
    _execution_lock: fs_helpers::PlatformLock,
    _permit: WorkerPermit,
    _same_thread: PhantomData<Rc<()>>,
}

#[allow(dead_code)] // No coordinator or process launch is enabled by this patch.
impl CompletedSetupLease {
    pub(crate) fn request(&self) -> SetupVerificationRequest {
        self.verification.request()
    }
    pub(crate) fn operation_id(&self) -> &str {
        &self.operation_id
    }

    pub(crate) fn selected_shell(&self) -> ShellKind {
        self.verification.shell
    }

    pub(crate) fn resolution_cwd(&self) -> Option<&str> {
        self.policy.resolution_cwd()
    }

    pub(crate) fn revalidate(&self) -> Result<(), String> {
        self.journal_directory.revalidate()?;
        self.journal_file.revalidate()?;
        let record = self.service.read(&self.operation_id)?;
        validate_completed_record(&record)?;
        if completion_fingerprint(&record)? != self.fingerprint {
            return Err(refresh("completed setup binding changed"));
        }
        self.policy.revalidate_for_mutation().map_err(refresh)?;
        self.service.authorize(
            &record,
            &self.policy,
            Some(&self.shell_inputs),
            self.agent_inputs.as_ref(),
        )?;
        if !self.service.all_postconditions(&record)? {
            return Err(refresh("completed setup postconditions changed"));
        }
        for document in &self.documents {
            document.revalidate()?;
        }
        Ok(())
    }
}

impl MutationService {
    pub(crate) fn setup_verification_request(
        &self,
        id: &str,
    ) -> Result<Option<SetupVerificationRequest>, String> {
        let record = self.read(id)?;
        if record.kind != OperationKind::RecommendedSetup {
            return Err("verification requests belong only to recommended setup".into());
        }
        record
            .setup_verification
            .as_ref()
            .map(|intent| {
                intent.validate_for(
                    record.kind,
                    record.shell_precondition.as_ref(),
                    record.steps.iter().map(|step| step.target.clone()),
                )?;
                Ok(intent.request())
            })
            .transpose()
    }

    pub(super) fn invalidate_setup_verification(&self, id: &str) -> Result<(), String> {
        let record = self.read(id)?;
        if record.setup_verification.is_some() && !record.setup_verification_cancelled {
            self.update(id, |record| {
                record.setup_verification_cancelled = true;
                Ok(())
            })?;
        }
        Ok(())
    }

    /// Acquire on the future coordinator's worker thread, after file apply has
    /// returned. The global setup writer lock is never held by this lease.
    /// Missing intent is a historical file-only operation, never upgraded here.
    #[allow(dead_code)]
    pub(crate) fn completed_setup_lease(
        &self,
        id: &str,
        policy: EffectivePolicySnapshot,
    ) -> Result<Option<CompletedSetupLease>, String> {
        let initial = self.read(id)?;
        if initial.kind != OperationKind::RecommendedSetup {
            return Err(refresh("operation is not recommended setup"));
        }
        if initial.setup_verification.is_none() {
            return Ok(None);
        }
        validate_completed_record(&initial)?;
        let path = self.path(id)?;
        let permit = {
            let mut reservations = worker_reservations()
                .lock()
                .unwrap_or_else(|error| error.into_inner());
            if reservations.contains_key(&path) {
                return Err("operation already has active work".into());
            }
            if ACTIVE_JOBS.load(Ordering::Acquire) >= MAX_ACTIVE_JOBS {
                return Err("operation worker capacity reached".into());
            }
            reservations.insert(path.clone(), JobAction::Apply);
            ACTIVE_JOBS.fetch_add(1, Ordering::AcqRel);
            WorkerPermit { path: path.clone() }
        };
        let journal_directory = DirectoryIdentity::capture(&self.root)?;
        let execution_lock =
            fs_helpers::try_lock_operation(&path.with_extension("execution-lock"), &self.scope)?
                .ok_or("operation already has an execution owner")?;
        let journal_file = BinaryIdentity::capture_input(&path)?;
        let record = self.read(id)?;
        validate_completed_record(&record)?;
        if completion_fingerprint(&record)? != completion_fingerprint(&initial)? {
            return Err(refresh(
                "setup changed while acquiring its completion lease",
            ));
        }
        let verification = record
            .setup_verification
            .clone()
            .ok_or("verification intent disappeared")?;
        let shell_inputs = record
            .shell_precondition
            .as_ref()
            .ok_or("shell precondition disappeared")?
            .retain()?;
        let agent_inputs = record
            .agent_precondition
            .as_ref()
            .map(|input| input.retain())
            .transpose()?;
        self.authorize(&record, &policy, Some(&shell_inputs), agent_inputs.as_ref())?;
        if !self.all_postconditions(&record)? {
            return Err(refresh("completed setup postconditions changed"));
        }
        // These hashes were derived from the original caller preimages and
        // immutable transformations before apply. Reacquisition cannot bless
        // an unrelated startup edit merely because our owned block still matches.
        let documents = verification.retain_completed()?;
        let lease = CompletedSetupLease {
            service: self.clone(),
            operation_id: id.into(),
            fingerprint: completion_fingerprint(&record)?,
            policy,
            shell_inputs,
            agent_inputs,
            documents,
            journal_directory,
            journal_file,
            verification,
            _execution_lock: execution_lock,
            _permit: permit,
            _same_thread: PhantomData,
        };
        lease.revalidate()?;
        Ok(Some(lease))
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use crate::cli::setup::shell_service::{PreparedShell, ShellChange};
    use crate::cli::test_harness::{with_fake_env, EnvGuard};
    use std::os::unix::fs::PermissionsExt;
    use tirith_core::policy_snapshot::ResolutionMode;

    fn with_setup_env(test: impl FnOnce(&Path, Option<&Path>) + std::panic::UnwindSafe) {
        with_fake_env(true, |home, cwd| {
            let _zdotdir = EnvGuard::remove("ZDOTDIR");
            test(home, cwd);
        });
    }

    fn prepared(home: &Path, manual: bool) -> PreparedShell {
        let binary = home.join("fixture-tirith");
        if !binary.exists() {
            std::fs::write(&binary, b"#!/bin/sh\nexit 0\n").unwrap();
            std::fs::set_permissions(&binary, std::fs::Permissions::from_mode(0o700)).unwrap();
        }
        if manual {
            std::fs::write(
                home.join(".zshrc"),
                "# retained manual startup\neval \"$(tirith init --shell zsh)\"\n",
            )
            .unwrap();
        }
        PreparedShell::capture_with_binary(
            ShellChange::Install {
                shell: ShellKind::Zsh,
                force: false,
            },
            None,
            binary.to_str(),
        )
        .unwrap()
    }

    fn save(service: &MutationService, id: &str, prepared: &PreparedShell) -> OperationStatus {
        let (requests, preimages, shell) = prepared.setup_parts().unwrap();
        service
            .plan_recommended_with_verification_intent(
                id,
                PlanChanges {
                    requests,
                    preimages: &preimages,
                },
                &prepared.snapshot,
                &"fixed-recommended-request",
                IntegrationPreconditions {
                    shell: Some(shell),
                    agent: None,
                },
                prepared.verification_intent().unwrap(),
            )
            .unwrap()
    }

    fn fresh(service: &MutationService, id: &str) -> EffectivePolicySnapshot {
        let record = service.read(id).unwrap();
        EffectivePolicySnapshot::resolve(record.resolution_cwd.as_deref(), ResolutionMode::Runtime)
    }

    fn plan(home: &Path, manual: bool) -> (MutationService, String) {
        let prepared = prepared(home, manual);
        let service = MutationService::current().unwrap();
        let id = uuid::Uuid::new_v4().to_string();
        save(&service, &id, &prepared);
        (service, id)
    }

    fn complete(service: &MutationService, id: &str) {
        assert_eq!(
            service.apply(id, &fresh(service, id)).unwrap().state,
            JobState::Completed
        );
    }

    fn rewrite_record(service: &MutationService, id: &str, edit: impl FnOnce(&mut Journal)) {
        let mut record = service.read(id).unwrap();
        edit(&mut record);
        let text = serde_json::to_string(&record).unwrap();
        fs_helpers::transactional_update(&service.path(id).unwrap(), &service.scope, false, |_| {
            Ok(FileUpdate::write_text(text.clone(), 0o600))
        })
        .unwrap();
    }

    #[test]
    fn noop_retains_versioned_intent_shell_inputs_and_exact_manual_startup() {
        with_setup_env(|home, _| {
            let (service, id) = plan(home, true);
            let record = service.read(&id).unwrap();
            assert!(record.no_op);
            assert_eq!(record.state, JobState::Completed);
            assert!(record.steps.is_empty());
            assert!(record.shell_precondition.is_some());
            let intent = record.setup_verification.as_ref().unwrap();
            assert_eq!(intent.schema_version, 1);
            assert!(intent.shell == ShellKind::Zsh);
            assert_eq!(intent.unchanged_inputs.len(), 1);
            let request =
                serde_json::to_value(service.setup_verification_request(&id).unwrap()).unwrap();
            assert_eq!(
                request,
                serde_json::json!({"schema_version":1,"scope":"fresh_terminal_activation","shell":"zsh"})
            );
            let baseline = active_job_count();
            let lease = service
                .completed_setup_lease(&id, fresh(&service, &id))
                .unwrap()
                .unwrap();
            assert_eq!(lease.operation_id(), id);
            lease.revalidate().unwrap();
            assert_eq!(active_job_count(), baseline + 1);
            drop(lease);
            assert_eq!(active_job_count(), baseline);
        });
    }

    #[test]
    fn old_file_only_uuid_replay_does_not_gain_verification_or_startup_inputs() {
        with_setup_env(|home, _| {
            let prepared = prepared(home, true);
            let service = MutationService::current().unwrap();
            let id = uuid::Uuid::new_v4().to_string();
            service
                .complete_noop_with_intent(
                    &id,
                    OperationKind::RecommendedSetup,
                    &prepared.snapshot,
                    &"fixed-recommended-request",
                )
                .unwrap();
            let old_bytes = std::fs::read(service.path(&id).unwrap()).unwrap();
            assert!(!String::from_utf8_lossy(&old_bytes).contains("setup_verification"));
            let replay = save(&service, &id, &prepared);
            assert!(replay.no_op);
            assert_eq!(
                std::fs::read(service.path(&id).unwrap()).unwrap(),
                old_bytes
            );
            assert!(service.setup_verification_request(&id).unwrap().is_none());
            assert!(service
                .completed_setup_lease(&id, fresh(&service, &id))
                .unwrap()
                .is_none());
            assert!(!service
                .path(&id)
                .unwrap()
                .with_extension("execution-lock")
                .exists());
        });
    }

    #[test]
    fn lease_requires_applied_owned_postconditions_and_does_not_hold_global_writer() {
        with_setup_env(|home, _| {
            let (service, id) = plan(home, false);
            assert!(service
                .completed_setup_lease(&id, fresh(&service, &id))
                .is_err());
            complete(&service, &id);
            let baseline = active_job_count();
            let lease = service
                .completed_setup_lease(&id, fresh(&service, &id))
                .unwrap()
                .unwrap();
            let lock = service.path(&id).unwrap().with_extension("execution-lock");
            assert!(fs_helpers::try_lock_operation(&lock, &service.scope)
                .unwrap()
                .is_none());
            assert!(service
                .completed_setup_lease(&id, fresh(&service, &id))
                .is_err());
            assert_eq!(active_job_count(), baseline + 1);
            let unrelated = home.join("unrelated-owned-setting");
            fs_helpers::transactional_update(&unrelated, home, false, |_| {
                Ok(FileUpdate::write_text("independent".into(), 0o600))
            })
            .unwrap();
            assert_eq!(std::fs::read_to_string(unrelated).unwrap(), "independent");
            assert_eq!(
                service.apply(&id, &fresh(&service, &id)).unwrap().state,
                JobState::Completed
            );
            lease.revalidate().unwrap();
            drop(lease);
            assert!(fs_helpers::try_lock_operation(&lock, &service.scope)
                .unwrap()
                .is_some());
            assert_eq!(active_job_count(), baseline);
        });
    }

    #[test]
    fn noop_startup_drift_refuses_binding_without_repurposing_the_saved_apply() {
        with_setup_env(|home, _| {
            let (service, id) = plan(home, true);
            let original = std::fs::read(service.path(&id).unwrap()).unwrap();
            std::fs::write(home.join(".zshrc"), "# the selected init was removed\n").unwrap();
            assert!(service
                .completed_setup_lease(&id, fresh(&service, &id))
                .is_err());
            assert_eq!(std::fs::read(service.path(&id).unwrap()).unwrap(), original);
            assert_eq!(
                service.apply(&id, &fresh(&service, &id)).unwrap().state,
                JobState::Completed
            );
            assert_eq!(
                std::fs::read_to_string(home.join(".zshrc")).unwrap(),
                "# the selected init was removed\n"
            );
        });
    }

    #[test]
    fn changed_binary_or_shell_selection_cannot_reacquire_a_noop_binding() {
        with_setup_env(|home, _| {
            let (service, id) = plan(home, true);
            let baseline = active_job_count();
            std::fs::write(home.join("fixture-tirith"), "#!/bin/sh\nexit 1\n").unwrap();
            assert!(service
                .completed_setup_lease(&id, fresh(&service, &id))
                .is_err());
            assert_eq!(active_job_count(), baseline);
        });
        with_setup_env(|home, _| {
            let (service, id) = plan(home, true);
            let alternate = home.join("alternate-zdotdir");
            std::fs::create_dir(&alternate).unwrap();
            let _zdotdir = EnvGuard::set("ZDOTDIR", &alternate);
            assert!(service
                .completed_setup_lease(&id, fresh(&service, &id))
                .is_err());
        });
    }

    #[test]
    fn retained_postcondition_rejects_identical_replacement_and_policy_drift() {
        with_setup_env(|home, _| {
            let (service, id) = plan(home, false);
            complete(&service, &id);
            let lease = service
                .completed_setup_lease(&id, fresh(&service, &id))
                .unwrap()
                .unwrap();
            let target = home.join(".zshrc");
            let replacement = home.join("replacement");
            std::fs::write(&replacement, std::fs::read(&target).unwrap()).unwrap();
            std::fs::rename(&replacement, &target).unwrap();
            assert!(
                lease.revalidate().is_err(),
                "equal bytes do not preserve an open native generation"
            );
        });
        with_setup_env(|home, _| {
            let (service, id) = plan(home, true);
            let lease = service
                .completed_setup_lease(&id, fresh(&service, &id))
                .unwrap()
                .unwrap();
            let config = tirith_core::policy::config_dir().unwrap();
            std::fs::create_dir_all(&config).unwrap();
            std::fs::write(config.join("policy.yaml"), "fail_mode: closed\n").unwrap();
            assert!(lease.revalidate().is_err());
        });
    }

    #[test]
    fn cancel_invalidates_completed_verification_without_changing_file_completion() {
        with_setup_env(|home, _| {
            let (service, id) = plan(home, true);
            let before = std::fs::read(home.join(".zshrc")).unwrap();
            let lease = service
                .completed_setup_lease(&id, fresh(&service, &id))
                .unwrap()
                .unwrap();
            let status = service.cancel(&id).unwrap();
            assert_eq!(status.state, JobState::Completed);
            assert!(status.no_op);
            assert!(lease.revalidate().is_err());
            drop(lease);
            assert!(service
                .completed_setup_lease(&id, fresh(&service, &id))
                .is_err());
            assert_eq!(std::fs::read(home.join(".zshrc")).unwrap(), before);
        });
    }

    #[test]
    fn undo_invalidates_then_waits_for_the_owned_completion_lease() {
        with_setup_env(|home, _| {
            let (service, id) = plan(home, false);
            complete(&service, &id);
            let before = std::fs::read(home.join(".zshrc")).unwrap();
            let lease = service
                .completed_setup_lease(&id, fresh(&service, &id))
                .unwrap()
                .unwrap();
            assert!(service.undo(&id, &fresh(&service, &id)).is_err());
            assert_eq!(std::fs::read(home.join(".zshrc")).unwrap(), before);
            assert!(lease.revalidate().is_err());
            drop(lease);
            assert_eq!(
                service.undo(&id, &fresh(&service, &id)).unwrap().state,
                JobState::Undone
            );
            assert!(!std::fs::read_to_string(home.join(".zshrc"))
                .unwrap()
                .contains("tirith-hook"));
            assert!(service
                .completed_setup_lease(&id, fresh(&service, &id))
                .is_err());
        });
    }

    #[test]
    fn mutated_kind_operator_digest_intent_or_terminal_step_cannot_issue_a_lease() {
        for tamper in 0..7 {
            with_setup_env(|home, _| {
                let (service, id) = plan(home, false);
                complete(&service, &id);
                rewrite_record(&service, &id, |record| match tamper {
                    0 => record.kind = OperationKind::SetupShell,
                    1 => record.operator.push_str("-another-operator"),
                    2 => record.payload_digest = "0".repeat(64),
                    3 => record.setup_verification.as_mut().unwrap().schema_version = 2,
                    4 => record.setup_verification.as_mut().unwrap().shell = ShellKind::Bash,
                    5 => record.steps[0].state = StepState::Pending,
                    6 => record.steps[0]
                        .description
                        .push_str(" changed immutable payload"),
                    _ => unreachable!(),
                });
                // Do not use the mutated journal as a source of policy authority.
                let cwd = std::env::current_dir().unwrap().display().to_string();
                let policy = EffectivePolicySnapshot::resolve(Some(&cwd), ResolutionMode::Runtime);
                let baseline = active_job_count();
                assert!(
                    service.completed_setup_lease(&id, policy).is_err(),
                    "tamper {tamper}"
                );
                assert_eq!(active_job_count(), baseline);
            });
        }
    }

    #[test]
    fn completed_label_does_not_override_missing_owned_postconditions() {
        with_setup_env(|home, _| {
            let (service, id) = plan(home, false);
            complete(&service, &id);
            std::fs::write(home.join(".zshrc"), "# no integration remains\n").unwrap();
            assert_eq!(service.read_status(&id).unwrap().state, JobState::Completed);
            assert!(service
                .completed_setup_lease(&id, fresh(&service, &id))
                .is_err());
        });
    }

    #[test]
    fn an_unowned_startup_edit_is_preserved_by_apply_but_cannot_be_rebound_as_verified_input() {
        for before_apply in [false, true] {
            with_setup_env(|home, _| {
                let (service, id) = plan(home, false);
                if !before_apply {
                    complete(&service, &id);
                }
                let path = home.join(".zshrc");
                let previous = std::fs::read_to_string(&path).unwrap_or_default();
                std::fs::write(
                    &path,
                    format!("# independently added startup content\n{previous}"),
                )
                .unwrap();
                if before_apply {
                    complete(&service, &id);
                }
                assert!(std::fs::read_to_string(&path)
                    .unwrap()
                    .contains("independently added"));
                assert!(
                    service
                        .all_postconditions(&service.read(&id).unwrap())
                        .unwrap(),
                    "the owned hook block still matches"
                );
                assert!(
                    service
                        .completed_setup_lease(&id, fresh(&service, &id))
                        .is_err(),
                    "startup contents differ from the immutable full postimage"
                );
            });
        }
    }

    #[test]
    fn no_op_undo_also_revokes_future_verification_while_preserving_completion_exit() {
        with_setup_env(|home, _| {
            let (service, id) = plan(home, true);
            let status = service.undo(&id, &fresh(&service, &id)).unwrap();
            assert_eq!(status.state, JobState::Completed);
            assert!(status.no_op);
            assert!(service
                .completed_setup_lease(&id, fresh(&service, &id))
                .is_err());
        });
    }

    #[test]
    fn explicit_recovery_completion_requires_the_same_real_postconditions() {
        with_setup_env(|home, _| {
            let (service, id) = plan(home, false);
            complete(&service, &id);
            rewrite_record(&service, &id, |record| {
                record.state = JobState::CompletedWithRecovery;
                for step in &mut record.steps {
                    step.state = StepState::AppliedWithRecovery;
                }
            });
            let lease = service
                .completed_setup_lease(&id, fresh(&service, &id))
                .unwrap()
                .unwrap();
            lease.revalidate().unwrap();
            drop(lease);
            std::fs::write(home.join(".zshrc"), "# postcondition lost\n").unwrap();
            assert!(service
                .completed_setup_lease(&id, fresh(&service, &id))
                .is_err());
        });
    }

    #[test]
    fn exact_unchanged_inputs_distinguish_absence_empty_bytes_and_rebinding() {
        with_setup_env(|home, _| {
            let path = home.join("not-created-yet").join("startup");
            let absent = SetupVerificationDocument::observed(&path, home, None).unwrap();
            let held = RetainedSetupDocument::capture(&absent).unwrap();
            held.revalidate().unwrap();
            std::fs::create_dir(path.parent().unwrap()).unwrap();
            std::fs::write(&path, b"").unwrap();
            assert!(
                held.revalidate().is_err(),
                "creating an empty file changes an absent input"
            );
            drop(held);
            let empty = SetupVerificationDocument::observed(&path, home, Some("")).unwrap();
            let held = RetainedSetupDocument::capture(&empty).unwrap();
            held.revalidate().unwrap();
            let other = home.join("replacement");
            std::fs::write(&other, b"").unwrap();
            std::fs::rename(other, &path).unwrap();
            assert!(
                held.revalidate().is_err(),
                "equal empty contents do not retain a live inode"
            );
        });
    }

    #[test]
    fn verification_document_inventory_rejects_duplicates_and_unbounded_metadata() {
        with_setup_env(|home, _| {
            let first =
                SetupVerificationDocument::observed(&home.join("first"), home, Some("")).unwrap();
            assert!(SetupVerificationIntent::for_shell(
                ShellKind::Zsh,
                vec![first.clone(), first.clone()]
            )
            .is_err());
            assert!(SetupVerificationIntent::for_shell(ShellKind::Powershell, vec![]).is_err());
            let mut malformed = first.clone();
            malformed.sha256 = Some("not-a-hash".into());
            assert!(SetupVerificationIntent::for_shell(ShellKind::Zsh, vec![malformed]).is_err());
            let too_many = (0..=MAX_UNCHANGED_INPUTS)
                .map(|index| {
                    SetupVerificationDocument::observed(
                        &home.join(format!("input-{index}")),
                        home,
                        None,
                    )
                    .unwrap()
                })
                .collect();
            assert!(SetupVerificationIntent::for_shell(ShellKind::Zsh, too_many).is_err());
            let mut too_large = first;
            too_large.bytes = MAX_SETUP_FILE_BYTES as u64 + 1;
            assert!(SetupVerificationIntent::for_shell(ShellKind::Zsh, vec![too_large]).is_err());
        });
    }
}
