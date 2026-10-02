//! Immutable review intents for the closed LocalLeafNoScriptsV1 contract.
//! Saved records are reinspection input and history, never execution authority.
use std::path::PathBuf;

pub(crate) const INTENT_SCHEMA_VERSION: u32 = 1;

#[derive(clap::Subcommand)]
pub(crate) enum Action {
    /// Review exact local leaf archives for a new dedicated npm target.
    Plan {
        #[arg(required = true, value_name = "ARCHIVE")]
        artifacts: Vec<PathBuf>,
        #[arg(long)]
        target: PathBuf,
        #[arg(long)]
        json: bool,
    },
    /// Reinspect a reviewed operation and apply only on a qualified native host.
    Apply {
        operation: String,
        #[arg(long)]
        reviewed: String,
        #[arg(long)]
        json: bool,
    },
    /// Inspect historical observations without granting current authority.
    Status {
        operation: String,
        #[arg(long)]
        json: bool,
    },
    /// Withdraw an unstarted intent. Started objects remain preserved.
    Undo {
        operation: String,
        #[arg(long)]
        reviewed: String,
        #[arg(long)]
        json: bool,
    },
    /// Inspect recovery admission; never replay an interrupted installation.
    Recover {
        operation: String,
        #[arg(long)]
        reviewed: String,
        #[arg(long)]
        json: bool,
    },
}
impl Action {
    fn json(&self) -> bool {
        match self {
            Self::Plan { json, .. }
            | Self::Apply { json, .. }
            | Self::Status { json, .. }
            | Self::Undo { json, .. }
            | Self::Recover { json, .. } => *json,
        }
    }
}
#[derive(Debug)]
struct Failure {
    reason: String,
    // A transaction observation is descriptive, never a saved capability.
    observation: Option<serde_json::Value>,
}
impl From<String> for Failure {
    fn from(reason: String) -> Self {
        Self {
            reason,
            observation: None,
        }
    }
}
impl From<&str> for Failure {
    fn from(reason: &str) -> Self {
        reason.to_owned().into()
    }
}
impl Failure {
    fn output(&self) -> serde_json::Value {
        serde_json::json!({"schema":INTENT_SCHEMA_VERSION,
            "contract":tirith_core::artifact::npm_install::CONTRACT,
            "error":self.reason,"execution_state":"not_observed",
            "transaction_observation":self.observation,
            "execution_authority":false,"current_code_safety":"not_established",
            "ongoing_immutability":false})
    }
}
pub(crate) fn run(action: Action) -> i32 {
    let output = super::npm_operation_output::OutputContext::start();
    let json = action.json();
    #[cfg(target_os = "linux")]
    let result = linux::run(action);
    #[cfg(not(target_os = "linux"))]
    let result: Result<serde_json::Value, Failure> = {
        let _ = action;
        Err("LocalLeafNoScriptsV1 requires Linux retained target binding; execution is unavailable on this host".into())
    };
    let (value, exit) = match result {
        Ok(value) => (value, 0),
        Err(failure) => (failure.output(), 1),
    };
    output.finish(
        &value,
        super::npm_operation_output::OperationKind::Install,
        json,
        exit,
    )
}

#[cfg(target_os = "linux")]
mod linux {
    use super::{Action, Failure};
    use crate::cli::{
        npm_install_recovery::{CommittedNpmObservation, NpmRecoveryStore},
        npm_install_transaction,
        package_checkpoint::{
            materialization_store::{canonical_operation, OperationStore, RecordKind, RECORD_CAP},
            InstallTargetBinding,
        },
    };
    use serde::{Deserialize, Serialize};
    use serde_json::{json, Value};
    use sha2::{Digest, Sha256};
    use std::{
        fs::File,
        os::unix::fs::MetadataExt,
        path::{Path, PathBuf},
    };
    use tirith_core::{
        artifact::{
            npm_archive::NpmLimits,
            npm_install::{self, NewNpmDestination, NpmInstallPlan, VerifiedNpmArtifact, CONTRACT},
        },
        policy::BoundedRuntimePolicyInputs,
        policy_snapshot::{EffectivePolicySnapshot, PrivatePolicyReplayGuard},
        task_boundary::{
            PackageInstallPreparationBoundary, TaskBoundaryEffectLease, TaskBoundaryPermit,
        },
    };
    const SCHEMA: u32 = super::INTENT_SCHEMA_VERSION;
    const PATH_CAP: usize = 4096;

    #[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
    #[serde(deny_unknown_fields)]
    struct ArchiveIntent {
        path: String,
        sha256: String,
        device: u64,
        inode: u64,
        size: u64,
        mode: u32,
        owner: u32,
        links: u64,
        modified_seconds: i64,
        modified_nanos: i64,
        changed_seconds: i64,
        changed_nanos: i64,
    }
    // Exact public summary shape is validated independently from the live plan;
    // deserialization never yields NpmInstallPlan or an execution capability.
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct SummaryObservation {
        schema_version: u32,
        contract: String,
        operation_id: String,
        public_plan_digest: String,
        packages: Vec<PackageObservation>,
        compressed_bytes: usize,
        installed_bytes: u64,
        installed_entries: usize,
        threat_db_sequence: u64,
        signed_build_timestamp: u64,
        node_version: String,
        npm_version: String,
        lifecycle_scripts: String,
        dependency_graph: String,
        code_safety: String,
    }
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct PackageObservation {
        name: String,
        version: String,
        compressed_sha256: String,
    }
    #[derive(Serialize, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Intent {
        schema: u32,
        contract: String,
        operation: String,
        operator: u32,
        cwd: String,
        target: String,
        parent_device: u64,
        parent_inode: u64,
        archives: Vec<ArchiveIntent>,
        policy: PrivatePolicyReplayGuard,
        private_plan_digest: String,
        private_review_nonce: String,
        summary: Value,
        reviewed_sha256: String,
    }
    #[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
    #[serde(rename_all = "snake_case")]
    enum EventPhase {
        Started,
        Finished,
        Withdrawn,
    }
    #[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
    #[serde(rename_all = "snake_case")]
    enum ExecutionObservation {
        NotStarted,
        MayHaveStarted,
        Started,
        Completed,
        Unknown,
    }
    #[derive(Clone, Serialize, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct TerminalObservation {
        phase: String,
        succeeded: bool,
        execution_state: ExecutionObservation,
        target_publication_crossed: Option<bool>,
        // Native-process/private-target cleanup observation from the coordinator;
        // this never promises deletion of all caches or retained quarantine evidence.
        cleanup_confirmed: bool,
        private_receipt_id: Option<String>,
        committed_receipt_id: Option<String>,
    }
    #[derive(Serialize, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Event {
        schema: u32,
        contract: String,
        operation: String,
        reviewed_sha256: String,
        phase: EventPhase,
        at: String,
        outcome: Option<TerminalObservation>,
    }
    #[derive(Clone, Serialize, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct RecoveryObservation {
        schema: u32,
        contract: String,
        operation: String,
        reviewed_sha256: String,
        at: String,
        private_milestone_sha256: String,
        committed_milestone_sha256: String,
        private_receipt_id: String,
        committed_receipt_id: String,
        observed_tree_sha256: String,
    }
    struct History {
        started: bool,
        withdrawn: bool,
        finished: Option<TerminalObservation>,
        recovered: Option<RecoveryObservation>,
    }

    pub(super) fn run(action: Action) -> Result<Value, Failure> {
        match action {
            Action::Plan {
                artifacts, target, ..
            } => plan(&artifacts, &target),
            Action::Apply {
                operation,
                reviewed,
                json,
            } => apply(&operation, &reviewed, json),
            Action::Status { operation, .. } => status(&operation),
            Action::Undo {
                operation,
                reviewed,
                ..
            } => undo(&operation, &reviewed),
            Action::Recover {
                operation,
                reviewed,
                ..
            } => recover(&operation, &reviewed),
        }
    }
    fn plan(paths: &[PathBuf], target: &Path) -> Result<Value, Failure> {
        let _bounded = BoundedRuntimePolicyInputs::enter();
        let cwd = current_cwd()?;
        let policy =
            EffectivePolicySnapshot::resolve_for_local_mutation(Some(&cwd)).map_err(err)?;
        let binding = InstallTargetBinding::bind(target).map_err(err)?;
        let id = uuid::Uuid::new_v4().to_string();
        let (artifacts, archives) = capture_artifacts(paths)?;
        let destination = NewNpmDestination::capture(binding.target()).map_err(install_err)?;
        let plan =
            NpmInstallPlan::prepare(&id, &artifacts, destination, &policy).map_err(install_err)?;
        // Review retains an expiring exact-operation lease for its state effects.
        // This lease never launches code or becomes a saved execution capability.
        let review_lease = authorize_task(&plan, &policy)?
            .into_effect_lease_for_gate_at(
                &plan.operation(),
                &policy.policy.task_gate,
                chrono::Utc::now(),
            )
            .map_err(|_| "fresh review authorization is unavailable for this exact npm action")?;
        let parent = std::fs::symlink_metadata(
            binding
                .target()
                .parent()
                .ok_or("target parent unavailable")?,
        )
        .map_err(err)?;
        let mut intent = Intent {
            schema: SCHEMA,
            contract: CONTRACT.into(),
            operation: id.clone(),
            operator: unsafe { libc::geteuid() },
            cwd,
            target: path_text(binding.target())?,
            parent_device: parent.dev(),
            parent_inode: parent.ino(),
            archives,
            policy: policy.private_replay_guard(),
            private_plan_digest: plan.private_plan_digest().into(),
            private_review_nonce: uuid::Uuid::new_v4().to_string(),
            summary: serde_json::to_value(plan.summary()).map_err(err)?,
            reviewed_sha256: String::new(),
        };
        intent.reviewed_sha256 = review_digest(&intent)?;
        validate_intent(&intent, &id)?;
        authorize_review_effect(&intent, &plan, &policy, &review_lease)?;
        let mut store = OperationStore::open_npm_install(&id, true).map_err(err)?;
        authorize_review_effect(&intent, &plan, &policy, &review_lease)?;
        store
            .append(RecordKind::Intent, encode(&intent)?)
            .map_err(err)?;
        authorize_review_effect(&intent, &plan, &policy, &review_lease)?;
        store.revalidate().map_err(err)?;
        let mut value = public_intent(&intent, "reviewed_intent");
        value["execution_available"] = json!(plan.execution_qualification().is_ok());
        value["execution_availability_scope"] =
            json!("native_contract_gate_only; all current apply checks still required");
        value["execution_state"] = json!("not_started");
        Ok(value)
    }
    fn apply(id: &str, reviewed: &str, json_output: bool) -> Result<Value, Failure> {
        let _bounded = BoundedRuntimePolicyInputs::enter();
        let mut store = OperationStore::open_npm_install(id, false).map_err(err)?;
        let intent = load_intent(&mut store, id)?;
        check_review(&intent, reviewed)?;
        let history = read_history(&mut store, &intent)?;
        require_unstarted(&history)?;
        let (policy, binding, artifacts, plan) = recapture(&intent)?;
        // Qualification precedes Started, quarantine, checkpoint and tool launch.
        plan.execution_qualification().map_err(|_| {
            "npm execution is not qualified on this host; operation remains unstarted"
        })?;
        let permit = authorize_task(&plan, &policy)?;
        store.revalidate().map_err(err)?;
        store
            .append(
                RecordKind::Started,
                event(&intent, EventPhase::Started, None)?,
            )
            .map_err(err)?;
        let result = {
            let mut validate_intent = || revalidate_started_intent(&mut store, &intent);
            npm_install_transaction::execute(
                &plan,
                &artifacts,
                &policy,
                &binding,
                permit,
                json_output,
                &intent.reviewed_sha256,
                &mut validate_intent,
            )
        };
        let (observation, result) = match result {
            Ok(value) => {
                if !valid_success(&value, &intent) {
                    let observation = TerminalObservation {
                        phase: "transaction_result_unrecognized".into(),
                        succeeded: false,
                        execution_state: ExecutionObservation::Unknown,
                        target_publication_crossed: None,
                        cleanup_confirmed: false,
                        private_receipt_id: None,
                        committed_receipt_id: None,
                    };
                    let failure = Failure {
                        reason: "transaction returned an unrecognized result; objects preserved"
                            .into(),
                        observation: Some(serde_json::to_value(&observation).map_err(err)?),
                    };
                    (observation, Err(failure))
                } else {
                    (
                        TerminalObservation {
                            phase: "published_verified".into(),
                            succeeded: true,
                            execution_state: ExecutionObservation::Completed,
                            target_publication_crossed: Some(true),
                            cleanup_confirmed: true,
                            private_receipt_id: value["private_receipt_id"]
                                .as_str()
                                .map(str::to_owned),
                            committed_receipt_id: value["committed_receipt_id"]
                                .as_str()
                                .map(str::to_owned),
                        },
                        Ok(value),
                    )
                }
            }
            Err(failure) => {
                let state = match failure.execution_state {
                    npm_install_transaction::ExecutionState::NotStarted => {
                        ExecutionObservation::NotStarted
                    }
                    npm_install_transaction::ExecutionState::MayHaveStarted => {
                        ExecutionObservation::MayHaveStarted
                    }
                    npm_install_transaction::ExecutionState::Started => {
                        ExecutionObservation::Started
                    }
                    npm_install_transaction::ExecutionState::Completed => {
                        ExecutionObservation::Completed
                    }
                };
                let observation = TerminalObservation {
                    phase: failure.phase.into(),
                    succeeded: false,
                    execution_state: state,
                    target_publication_crossed: Some(failure.target_publication_crossed),
                    cleanup_confirmed: failure.cleanup_confirmed,
                    private_receipt_id: None,
                    committed_receipt_id: None,
                };
                let output = serde_json::to_value(&failure).map_err(err)?;
                (
                    observation,
                    Err(Failure {
                        reason: failure.reason,
                        observation: Some(output),
                    }),
                )
            }
        };
        // A failed durable terminal append cannot turn execution into a no-exec
        // claim, or make replay safe. The immutable Started record is retained.
        let persist = (|| -> Result<(), String> {
            store.revalidate().map_err(err)?;
            store
                .append(
                    RecordKind::Finished,
                    event(&intent, EventPhase::Finished, Some(observation.clone()))?,
                )
                .map_err(err)?;
            store.revalidate().map_err(err)
        })();
        if let Err(error) = persist {
            return Err(Failure { reason: format!("transaction history could not be durably completed: {error}; never replay apply"),
                observation: Some(serde_json::to_value(&observation).map_err(err)?) });
        }
        result
    }
    fn valid_success(value: &Value, intent: &Intent) -> bool {
        value["schema"] == SCHEMA
            && value["contract"] == CONTRACT
            && value["operation"] == intent.operation
            && value["phase"] == "published_verified"
            && value["summary"] == intent.summary
            && value["execution_state"] == "completed"
            && value["lifecycle_scripts_executed"] == false
            && value["code_safety"] == "not_established"
            && value["ongoing_immutability"] == false
            && value["target_publication_crossed"] == true
            && value["cleanup_confirmed"] == true
            && ["private_receipt_id", "committed_receipt_id"]
                .iter()
                .all(|key| value[*key].as_str().is_some_and(is_digest))
            && value["private_receipt_id"] != value["committed_receipt_id"]
    }
    fn recapture(
        intent: &Intent,
    ) -> Result<
        (
            EffectivePolicySnapshot,
            InstallTargetBinding,
            Vec<VerifiedNpmArtifact>,
            NpmInstallPlan,
        ),
        String,
    > {
        if current_cwd()? != intent.cwd {
            return Err("current working directory differs from the reviewed context".into());
        }
        let policy =
            EffectivePolicySnapshot::resolve_for_local_mutation(Some(&intent.cwd)).map_err(err)?;
        if policy.private_replay_guard() != intent.policy {
            return Err("policy inputs changed since review".into());
        }
        let binding = InstallTargetBinding::bind(Path::new(&intent.target)).map_err(err)?;
        let parent = std::fs::symlink_metadata(
            binding
                .target()
                .parent()
                .ok_or("target parent unavailable")?,
        )
        .map_err(err)?;
        if parent.dev() != intent.parent_device
            || parent.ino() != intent.parent_inode
            || path_text(binding.target())? != intent.target
        {
            return Err("reviewed target parent or path changed".into());
        }
        let paths = intent
            .archives
            .iter()
            .map(|a| PathBuf::from(&a.path))
            .collect::<Vec<_>>();
        let (artifacts, actual) = capture_artifacts(&paths)?;
        if actual != intent.archives {
            return Err("reviewed archive identity or bytes changed".into());
        }
        let destination = NewNpmDestination::capture(binding.target()).map_err(install_err)?;
        let plan = NpmInstallPlan::prepare(&intent.operation, &artifacts, destination, &policy)
            .map_err(install_err)?;
        if serde_json::to_value(plan.summary()).map_err(err)? != intent.summary
            || plan.private_plan_digest() != intent.private_plan_digest
        {
            return Err("reviewed npm commitment or private decision changed".into());
        }
        Ok((policy, binding, artifacts, plan))
    }
    fn authorize_task(
        plan: &NpmInstallPlan,
        policy: &EffectivePolicySnapshot,
    ) -> Result<TaskBoundaryPermit<PackageInstallPreparationBoundary>, String> {
        let operation = plan.operation();
        let pending = tirith_core::task_boundary::prepare_locally_derived_boundary_authorization::<
            PackageInstallPreparationBoundary,
        >(
            &operation,
            &policy.policy.task_gate,
            &tirith_core::task_analysis::TaskAnalysisContext::default(),
        );
        let assessment = match &pending {
            Ok(p) => Some(p.assessment()),
            Err(e) => e.assessment(),
        };
        if let Some(assessment) = assessment {
            if let Err(error) = tirith_core::audit::log_task_boundary_assessment(assessment) {
                tirith_core::audit::audit_diagnostic(format!(
                    "npm installation task audit append failed: {error}"
                ));
            }
        }
        pending.map_err(|_| "current task authorization refused; provenance or typed approval cannot be invented")?
            .consume_default_for_operation(&operation, chrono::Utc::now())
            .map_err(|_| "fresh authorization is unavailable for this exact npm action".into())
    }
    fn authorize_review_effect(
        intent: &Intent,
        plan: &NpmInstallPlan,
        policy: &EffectivePolicySnapshot,
        lease: &TaskBoundaryEffectLease<PackageInstallPreparationBoundary>,
    ) -> Result<(), String> {
        // Reinspection can take time. Recheck the retained lease deadline and
        // current policy after it, immediately before the intended state effect.
        drop(recapture(intent)?);
        policy.revalidate_for_mutation().map_err(err)?;
        lease
            .authorize_effect_for_gate_at(
                &plan.operation(),
                &policy.policy.task_gate,
                chrono::Utc::now(),
            )
            .map_err(|_| "review authorization expired or changed before its state effect".into())
    }
    fn revalidate_started_intent(
        store: &mut OperationStore,
        intent: &Intent,
    ) -> Result<(), String> {
        store.revalidate().map_err(err)?;
        // A peer is not required to cooperate with flock. Re-read every event
        // that was previously absent, rather than trusting only retained files.
        let history = read_history(store, intent)?;
        if !history.started
            || history.withdrawn
            || history.finished.is_some()
            || history.recovered.is_some()
        {
            return Err("npm intent is no longer exclusively started; objects preserved".into());
        }
        store.revalidate().map_err(err)
    }
    fn require_unstarted(history: &History) -> Result<(), String> {
        if history.started
            || history.withdrawn
            || history.finished.is_some()
            || history.recovered.is_some()
        {
            Err("operation already started or ended; never replay apply".into())
        } else {
            Ok(())
        }
    }
    fn status(id: &str) -> Result<Value, Failure> {
        let mut store = OperationStore::open_npm_install(id, false).map_err(err)?;
        let intent = load_intent(&mut store, id)?;
        let history = read_history(&mut store, &intent)?;
        let phase = if history.withdrawn {
            "withdrawn"
        } else if history.recovered.is_some() {
            "published_reconfirmed"
        } else if let Some(observation) = &history.finished {
            observation.phase.as_str()
        } else if history.started {
            "interrupted_or_running"
        } else {
            "reviewed_intent"
        };
        let mut value = public_intent(&intent, phase);
        value["historical_only"] = json!(true);
        value["transaction_observation"] = json!(history.finished);
        value["recovery_observation"] = json!(history.recovered);
        value["execution_state"] = json!(if history.started {
            "not_observed_currently"
        } else {
            "not_started"
        });
        store.revalidate().map_err(err)?;
        Ok(value)
    }
    fn undo(id: &str, reviewed: &str) -> Result<Value, Failure> {
        let mut store = OperationStore::open_npm_install(id, false).map_err(err)?;
        let intent = load_intent(&mut store, id)?;
        check_review(&intent, reviewed)?;
        let history = read_history(&mut store, &intent)?;
        if history.started {
            return Err("started npm objects are preserved; automatic undo is unavailable and must not replay installation".into());
        }
        if !history.withdrawn {
            store.revalidate().map_err(err)?;
            store
                .append(
                    RecordKind::Withdrawn,
                    event(&intent, EventPhase::Withdrawn, None)?,
                )
                .map_err(err)?;
            store.revalidate().map_err(err)?;
        }
        let mut value = public_intent(&intent, "withdrawn");
        value["execution_state"] = json!("not_started");
        Ok(value)
    }
    fn recover(id: &str, reviewed: &str) -> Result<Value, Failure> {
        let _bounded = BoundedRuntimePolicyInputs::enter();
        let mut store = OperationStore::open_npm_install(id, false).map_err(err)?;
        let intent = load_intent(&mut store, id)?;
        check_review(&intent, reviewed)?;
        let history = read_history(&mut store, &intent)?;
        if !history.started || history.withdrawn {
            return Err("operation has not started; recovery cannot start or replay it".into());
        }
        if current_cwd()? != intent.cwd {
            return Err("current working directory differs from reviewed recovery context".into());
        }
        let policy =
            EffectivePolicySnapshot::resolve_for_local_mutation(Some(&intent.cwd)).map_err(err)?;
        if policy.private_replay_guard() != intent.policy {
            return Err("policy inputs changed since review; npm objects preserved".into());
        }
        let paths = intent
            .archives
            .iter()
            .map(|a| PathBuf::from(&a.path))
            .collect::<Vec<_>>();
        let (artifacts, actual) = capture_artifacts(&paths)?;
        if actual != intent.archives {
            return Err("reviewed archive identity or bytes changed; npm objects preserved".into());
        }
        let mut milestones = NpmRecoveryStore::open(id, false)?;
        let committed = load_recovery_milestones(&mut milestones, &intent)?;
        let captured = tirith_core::artifact::npm_install::recovery::NpmPublishedRecovery::capture(
            id,
            &artifacts,
            &policy,
            Path::new(&intent.target),
            &committed.tree,
            (intent.parent_device, intent.parent_inode),
        )
        .map_err(err)?;
        let operation = captured.operation();
        let pending = tirith_core::task_boundary::prepare_locally_derived_boundary_authorization::<
            tirith_core::task_boundary::LocalPackageRecoveryBoundary,
        >(
            &operation,
            &policy.policy.task_gate,
            &tirith_core::task_analysis::TaskAnalysisContext::default(),
        );
        let assessment = match &pending {
            Ok(value) => Some(value.assessment()),
            Err(error) => error.assessment(),
        };
        if let Some(assessment) = assessment {
            if let Err(error) = tirith_core::audit::log_task_boundary_assessment(assessment) {
                tirith_core::audit::audit_diagnostic(format!(
                    "npm recovery task audit append failed: {error}"
                ));
            }
        }
        let permit = pending
            .map_err(|_| "current task authorization refused for npm reconfirmation")?
            .consume_default_for_operation(&operation, chrono::Utc::now())
            .map_err(|_| "fresh task authorization unavailable for npm reconfirmation")?;
        let lease = permit
            .into_effect_lease_for_gate_at(&operation, &policy.policy.task_gate, chrono::Utc::now())
            .map_err(|_| "npm recovery task authorization expired or changed")?;
        let validate = |store: &mut OperationStore,
                        milestones: &mut NpmRecoveryStore|
         -> Result<(), String> {
            store.revalidate().map_err(err)?;
            let current_history = read_history(store, &intent)?;
            if !current_history.started
                || current_history.withdrawn
                || serde_json::to_value(&current_history.finished).map_err(err)?
                    != serde_json::to_value(&history.finished).map_err(err)?
            {
                return Err("npm intent terminal history changed during reconfirmation".into());
            }
            if let Some(existing) = current_history.recovered {
                if existing.private_milestone_sha256 != committed.private_milestone_sha256
                    || existing.committed_milestone_sha256 != committed.committed_milestone_sha256
                    || existing.observed_tree_sha256 != committed.tree.sha256
                    || existing.private_receipt_id != committed.private_receipt_id
                    || existing.committed_receipt_id != committed.committed_receipt_id
                {
                    return Err("npm reconfirmation history differs from signed milestones".into());
                }
            }
            let fresh = load_recovery_milestones(milestones, &intent)?;
            if fresh.private_milestone_sha256 != committed.private_milestone_sha256
                || fresh.committed_milestone_sha256 != committed.committed_milestone_sha256
            {
                return Err("npm completion milestones changed during reconfirmation".into());
            }
            captured.revalidate().map_err(err)?;
            lease
                .authorize_effect_for_gate_at(
                    &operation,
                    &policy.policy.task_gate,
                    chrono::Utc::now(),
                )
                .map_err(|_| "npm recovery authorization expired or changed".to_owned())
        };
        validate(&mut store, &mut milestones)?;
        if let Some(existing) = &history.recovered {
            if existing.private_milestone_sha256 != committed.private_milestone_sha256
                || existing.committed_milestone_sha256 != committed.committed_milestone_sha256
                || existing.observed_tree_sha256 != committed.tree.sha256
                || existing.private_receipt_id != committed.private_receipt_id
                || existing.committed_receipt_id != committed.committed_receipt_id
            {
                return Err(
                    "saved reconfirmation differs from exact signed completion milestones".into(),
                );
            }
        } else {
            let observation = RecoveryObservation {
                schema: SCHEMA,
                contract: CONTRACT.into(),
                operation: id.into(),
                reviewed_sha256: reviewed.into(),
                at: chrono::Utc::now().to_rfc3339(),
                private_milestone_sha256: committed.private_milestone_sha256.clone(),
                committed_milestone_sha256: committed.committed_milestone_sha256.clone(),
                private_receipt_id: committed.private_receipt_id.clone(),
                committed_receipt_id: committed.committed_receipt_id.clone(),
                observed_tree_sha256: committed.tree.sha256.clone(),
            };
            store
                .append(RecordKind::Recovered, encode(&observation)?)
                .map_err(err)?;
        }
        validate(&mut store, &mut milestones)?;
        let mut value = public_intent(&intent, "published_reconfirmed");
        value["execution_state"] = json!("historical_completed_run_authenticated");
        value["current_tree"] = json!("matches_signed_committed_observation");
        value["private_receipt_id"] = json!(committed.private_receipt_id);
        value["committed_receipt_id"] = json!(committed.committed_receipt_id);
        value["installation_replayed"] = json!(false);
        value["target_modified"] = json!(false);
        value["inode_continuity_across_interruption"] = json!("not_established");
        value["ongoing_immutability"] = json!(false);
        Ok(value)
    }
    fn load_recovery_milestones(
        store: &mut NpmRecoveryStore,
        intent: &Intent,
    ) -> Result<CommittedNpmObservation, String> {
        let public = intent.summary["public_plan_digest"]
            .as_str()
            .ok_or("public npm commitment unavailable")?;
        store.load_committed(
            &intent.reviewed_sha256,
            &intent.private_plan_digest,
            public,
            Path::new(&intent.target),
            (intent.parent_device, intent.parent_inode),
        )
    }
    fn read_recovery(
        store: &mut OperationStore,
        intent: &Intent,
    ) -> Result<Option<RecoveryObservation>, String> {
        let Some(bytes) = store.read(RecordKind::Recovered).map_err(err)? else {
            return Ok(None);
        };
        let value: RecoveryObservation = decode(&bytes)?;
        if value.schema != SCHEMA
            || value.contract != CONTRACT
            || value.operation != intent.operation
            || value.reviewed_sha256 != intent.reviewed_sha256
            || chrono::DateTime::parse_from_rfc3339(&value.at).is_err()
            || ![
                value.private_milestone_sha256.as_str(),
                &value.committed_milestone_sha256,
                &value.private_receipt_id,
                &value.committed_receipt_id,
                &value.observed_tree_sha256,
            ]
            .iter()
            .all(|v| is_digest(v))
            || value.private_receipt_id == value.committed_receipt_id
        {
            return Err("unsupported npm reconfirmation history; objects preserved".into());
        }
        Ok(Some(value))
    }
    fn read_history(store: &mut OperationStore, intent: &Intent) -> Result<History, String> {
        let started =
            read_event(store, RecordKind::Started, intent, EventPhase::Started)?.is_some();
        let finished = read_event(store, RecordKind::Finished, intent, EventPhase::Finished)?
            .and_then(|e| e.outcome);
        let withdrawn =
            read_event(store, RecordKind::Withdrawn, intent, EventPhase::Withdrawn)?.is_some();
        let recovered = read_recovery(store, intent)?;
        // Complete-only reconfirmation does not implement private undo or any replay.
        for kind in [
            RecordKind::Undone,
            RecordKind::ConfirmStarted,
            RecordKind::UndoStarted,
            RecordKind::ContinueUndoStarted,
            RecordKind::ContinuedUndo,
        ] {
            if store.read(kind).map_err(err)?.is_some() {
                return Err("unsupported npm recovery history; objects preserved".into());
            }
        }
        if (finished.is_some() || recovered.is_some()) && !started || withdrawn && started {
            return Err("inconsistent npm installation history; objects preserved".into());
        }
        Ok(History {
            started,
            withdrawn,
            finished,
            recovered,
        })
    }
    fn event(
        intent: &Intent,
        phase: EventPhase,
        outcome: Option<TerminalObservation>,
    ) -> Result<Vec<u8>, String> {
        encode(&Event {
            schema: SCHEMA,
            contract: CONTRACT.into(),
            operation: intent.operation.clone(),
            reviewed_sha256: intent.reviewed_sha256.clone(),
            phase,
            at: chrono::Utc::now().to_rfc3339(),
            outcome,
        })
    }
    fn read_event(
        store: &mut OperationStore,
        kind: RecordKind,
        intent: &Intent,
        expected: EventPhase,
    ) -> Result<Option<Event>, String> {
        let Some(bytes) = store.read(kind).map_err(err)? else {
            return Ok(None);
        };
        let e: Event = decode(&bytes)?;
        if e.schema != SCHEMA
            || e.contract != CONTRACT
            || e.operation != intent.operation
            || e.reviewed_sha256 != intent.reviewed_sha256
            || e.phase != expected
            || chrono::DateTime::parse_from_rfc3339(&e.at).is_err()
            || (e.phase == EventPhase::Finished) != e.outcome.is_some()
        {
            return Err("npm history binding or phase refused".into());
        }
        if let Some(outcome) = &e.outcome {
            if outcome.phase.is_empty()
                || outcome.phase.len() > 128
                || !outcome
                    .phase
                    .bytes()
                    .all(|b| b.is_ascii_lowercase() || b == b'_')
                || outcome.succeeded
                    && (outcome.phase != "published_verified"
                        || outcome.execution_state != ExecutionObservation::Completed
                        || outcome.target_publication_crossed != Some(true)
                        || !outcome.cleanup_confirmed
                        || !outcome.private_receipt_id.as_deref().is_some_and(is_digest)
                        || !outcome
                            .committed_receipt_id
                            .as_deref()
                            .is_some_and(is_digest)
                        || outcome.private_receipt_id == outcome.committed_receipt_id)
                || !outcome.succeeded
                    && (outcome.phase == "published_verified"
                        || outcome.private_receipt_id.is_some()
                        || outcome.committed_receipt_id.is_some())
                || outcome.execution_state == ExecutionObservation::NotStarted
                    && outcome.target_publication_crossed == Some(true)
            {
                return Err("npm terminal observation is inconsistent".into());
            }
        }
        Ok(Some(e))
    }
    fn load_intent(store: &mut OperationStore, id: &str) -> Result<Intent, String> {
        let bytes = store
            .read(RecordKind::Intent)
            .map_err(err)?
            .ok_or("npm installation operation does not exist")?;
        let intent: Intent = decode(&bytes)?;
        validate_intent(&intent, id)?;
        Ok(intent)
    }
    fn validate_intent(intent: &Intent, id: &str) -> Result<(), String> {
        canonical_operation(id).map_err(err)?;
        if intent.schema != SCHEMA
            || intent.contract != CONTRACT
            || intent.operation != id
            || intent.operator != unsafe { libc::geteuid() }
            || intent.archives.is_empty()
            || intent.archives.len() > npm_install::MAX_ARTIFACTS
        {
            return Err("npm intent schema or operator binding refused".into());
        }
        let summary: SummaryObservation = serde_json::from_value(intent.summary.clone())
            .map_err(|_| "npm summary schema refused")?;
        let compressed = intent.archives.iter().try_fold(0usize, |sum, a| {
            usize::try_from(a.size)
                .ok()
                .and_then(|size| sum.checked_add(size))
        });
        if summary.schema_version != SCHEMA
            || summary.contract != CONTRACT
            || summary.operation_id != id
            || !is_digest(&summary.public_plan_digest)
            || summary.packages.len() != intent.archives.len()
            || compressed != Some(summary.compressed_bytes)
            || summary.compressed_bytes > npm_install::MAX_TOTAL_COMPRESSED_BYTES
            || summary.installed_bytes > npm_install::MAX_TOTAL_INSTALLED_BYTES
            || summary.installed_entries > npm_install::MAX_INSTALLED_ENTRIES
            || summary.threat_db_sequence == 0
            || summary.signed_build_timestamp == 0
            || summary.node_version != npm_install::tools::NODE_VERSION
            || summary.npm_version != npm_install::tools::NPM_VERSION
            || summary.lifecycle_scripts != "disabled"
            || summary.dependency_graph != "local_leaf_only"
            || summary.code_safety != "not_established"
            || summary.packages.iter().zip(&intent.archives).any(|(p, a)| {
                p.name.is_empty()
                    || p.name.len() > 1024
                    || p.version.is_empty()
                    || p.version.len() > 256
                    || p.compressed_sha256 != a.sha256
            })
        {
            return Err("npm summary does not match the exact closed contract".into());
        }
        let paths = [&intent.cwd, &intent.target]
            .into_iter()
            .chain(intent.archives.iter().map(|a| &a.path));
        if paths.into_iter().any(|p| {
            p.len() > PATH_CAP
                || !Path::new(p).is_absolute()
                || Path::new(p)
                    .components()
                    .any(|c| matches!(c, std::path::Component::ParentDir))
        }) || intent.archives.iter().any(|a| !is_digest(&a.sha256))
            || !is_digest(&intent.private_plan_digest)
            || !uuid::Uuid::parse_str(&intent.private_review_nonce).is_ok_and(|nonce| {
                nonce.get_version() == Some(uuid::Version::Random)
                    && nonce.to_string() == intent.private_review_nonce
            })
            || !is_digest(&intent.reviewed_sha256)
            || review_digest(intent)? != intent.reviewed_sha256
        {
            return Err("npm intent commitment is malformed or changed".into());
        }
        Ok(())
    }
    fn public_projection(intent: &Intent) -> Value {
        json!({"schema":SCHEMA,"contract":CONTRACT,"operation":intent.operation,"target":intent.target,
            "archives":intent.archives.iter().map(|a| json!({"path":a.path,"sha256":a.sha256})).collect::<Vec<_>>(),"summary":intent.summary})
    }
    fn public_intent(intent: &Intent, phase: &str) -> Value {
        let mut value = public_projection(intent);
        value["reviewed_sha256"] = json!(intent.reviewed_sha256);
        value["phase"] = json!(phase);
        value["execution_authority"] = json!(false);
        value["current_code_safety"] = json!("not_established");
        value["ongoing_immutability"] = json!(false);
        value
    }
    fn review_digest(intent: &Intent) -> Result<String, String> {
        // Commit every review-time input, including private policy and retained
        // file generations. The private random nonce prevents public digest
        // probes against low-entropy policy contents. Neither it nor this private
        // canonical document is part of the display projection.
        let mut value = serde_json::to_value(intent).map_err(err)?;
        value
            .as_object_mut()
            .ok_or("invalid npm intent shape")?
            .remove("reviewed_sha256");
        let mut hash = Sha256::new();
        hash.update(b"tirith-npm-install-reviewed-intent-v1\0");
        hash.update(tirith_core::audit::canonical_json_for_hash(&value).as_bytes());
        Ok(format!("{:x}", hash.finalize()))
    }
    fn check_review(intent: &Intent, reviewed: &str) -> Result<(), String> {
        if !is_digest(reviewed) || intent.reviewed_sha256 != reviewed {
            return Err("reviewed commitment does not match this exact operation".into());
        }
        Ok(())
    }
    fn is_digest(s: &str) -> bool {
        s.len() == 64
            && s.bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    }
    fn capture_artifacts(
        paths: &[PathBuf],
    ) -> Result<(Vec<VerifiedNpmArtifact>, Vec<ArchiveIntent>), String> {
        if paths.is_empty() || paths.len() > 8 {
            return Err("npm installation requires one through eight exact local archives".into());
        }
        let mut retained = Vec::new();
        let mut records = Vec::new();
        for path in paths {
            let absolute = if path.is_absolute() {
                path.clone()
            } else {
                std::env::current_dir().map_err(err)?.join(path)
            };
            let name = absolute.file_name().ok_or("archive needs a file name")?;
            let parent = absolute
                .parent()
                .ok_or("archive parent unavailable")?
                .canonicalize()
                .map_err(err)?;
            let canonical = parent.join(name);
            let path = path_text(&canonical)?;
            let file = tirith_core::util::open_read_no_follow_capped(
                &canonical,
                NpmLimits::default().compressed_bytes as u64,
            )
            .map_err(|_| "local archive is not a bounded ordinary no-follow file".to_string())?;
            let before = file.metadata().map_err(err)?;
            let artifact = VerifiedNpmArtifact::capture(file.try_clone().map_err(err)?)
                .map_err(install_err)?;
            artifact.revalidate().map_err(install_err)?;
            let sha256 = artifact
                .inspection()
                .artifact
                .sha256
                .clone()
                .ok_or("archive identity unavailable")?;
            let record = archive_record(path, sha256, &file)?;
            if (
                before.dev(),
                before.ino(),
                before.len(),
                before.mtime(),
                before.mtime_nsec(),
                before.ctime(),
                before.ctime_nsec(),
            ) != (
                record.device,
                record.inode,
                record.size,
                record.modified_seconds,
                record.modified_nanos,
                record.changed_seconds,
                record.changed_nanos,
            ) {
                return Err("archive changed during capture".into());
            }
            retained.push(artifact);
            records.push(record);
        }
        Ok((retained, records))
    }
    fn archive_record(path: String, sha256: String, file: &File) -> Result<ArchiveIntent, String> {
        let m = file.metadata().map_err(err)?;
        Ok(ArchiveIntent {
            path,
            sha256,
            device: m.dev(),
            inode: m.ino(),
            size: m.len(),
            mode: m.mode(),
            owner: m.uid(),
            links: m.nlink(),
            modified_seconds: m.mtime(),
            modified_nanos: m.mtime_nsec(),
            changed_seconds: m.ctime(),
            changed_nanos: m.ctime_nsec(),
        })
    }
    fn encode(value: &impl Serialize) -> Result<Vec<u8>, String> {
        let bytes = serde_json::to_vec(value).map_err(err)?;
        if bytes.len() > RECORD_CAP {
            return Err("npm installation record exceeds its bound".into());
        }
        Ok(bytes)
    }
    fn decode<T: serde::de::DeserializeOwned>(bytes: &[u8]) -> Result<T, String> {
        let text = std::str::from_utf8(bytes).map_err(err)?;
        let value = tirith_core::mcp_lock::parse_json_no_duplicates(text)
            .map_err(|_| "npm installation record contains ambiguous or invalid JSON")?;
        serde_json::from_value(value).map_err(|_| "npm installation record schema refused".into())
    }
    fn current_cwd() -> Result<String, String> {
        path_text(
            &std::env::current_dir()
                .map_err(err)?
                .canonicalize()
                .map_err(err)?,
        )
    }
    fn path_text(path: &Path) -> Result<String, String> {
        let s = path
            .to_str()
            .ok_or("npm installation paths must be UTF-8")?;
        if s.len() > PATH_CAP {
            return Err("npm installation path exceeds its bound".into());
        }
        Ok(s.into())
    }
    fn err(e: impl std::fmt::Debug) -> String {
        format!("npm install refused: {e:?}")
    }
    fn install_err(e: npm_install::NpmInstallRefusal) -> String {
        format!("npm install refused ({e:?}): {e}")
    }
    #[cfg(test)]
    mod tests {
        use super::*;
        use tirith_test_support::GlobalStateGuard;

        // Synthetic historical observation, deliberately without an archive.
        // This is never accepted as live package authority by recapture/apply.
        fn intent(scope: &GlobalStateGuard) -> Intent {
            let policy = EffectivePolicySnapshot::resolve(
                scope.roots().cwd.to_str(),
                tirith_core::policy_snapshot::ResolutionMode::LocalOnly,
            );
            let id = uuid::Uuid::new_v4().to_string();
            let mut intent = Intent {
                schema: SCHEMA,
                contract: CONTRACT.into(),
                operation: id.clone(),
                operator: unsafe { libc::geteuid() },
                cwd: scope.roots().cwd.to_str().unwrap().into(),
                target: scope
                    .roots()
                    .cwd
                    .join(format!("new-target-{id}"))
                    .to_str()
                    .unwrap()
                    .into(),
                parent_device: 1,
                parent_inode: 2,
                archives: vec![ArchiveIntent {
                    path: scope
                        .roots()
                        .cwd
                        .join("not-present.tgz")
                        .to_str()
                        .unwrap()
                        .into(),
                    sha256: "a".repeat(64),
                    device: 3,
                    inode: 4,
                    size: 5,
                    mode: 0o100600,
                    owner: unsafe { libc::geteuid() },
                    links: 1,
                    modified_seconds: 1,
                    modified_nanos: 0,
                    changed_seconds: 1,
                    changed_nanos: 0,
                }],
                policy: policy.private_replay_guard(),
                private_plan_digest: "b".repeat(64),
                private_review_nonce: uuid::Uuid::new_v4().to_string(),
                summary: json!({"schema_version":1,"contract":CONTRACT,"operation_id":id,
                    "public_plan_digest":"c".repeat(64),
                    "packages":[{"name":"demo","version":"1.0.0","compressed_sha256":"a".repeat(64)}],
                    "compressed_bytes":5,"installed_bytes":5,"installed_entries":1,
                    "threat_db_sequence":1,"signed_build_timestamp":1,
                    "node_version":npm_install::tools::NODE_VERSION,"npm_version":npm_install::tools::NPM_VERSION,
                    "lifecycle_scripts":"disabled","dependency_graph":"local_leaf_only","code_safety":"not_established"}),
                reviewed_sha256: String::new(),
            };
            intent.reviewed_sha256 = review_digest(&intent).unwrap();
            validate_intent(&intent, &id).unwrap();
            intent
        }
        fn save(scope: &GlobalStateGuard) -> Intent {
            let intent = intent(scope);
            OperationStore::open_npm_install(&intent.operation, true)
                .unwrap()
                .append(RecordKind::Intent, encode(&intent).unwrap())
                .unwrap();
            intent
        }
        fn append(
            intent: &Intent,
            kind: RecordKind,
            phase: EventPhase,
            outcome: Option<TerminalObservation>,
        ) {
            OperationStore::open_npm_install(&intent.operation, false)
                .unwrap()
                .append(kind, event(intent, phase, outcome).unwrap())
                .unwrap();
        }
        fn failed_after_execution() -> TerminalObservation {
            TerminalObservation {
                phase: "committed_receipt".into(),
                succeeded: false,
                execution_state: ExecutionObservation::Completed,
                target_publication_crossed: Some(true),
                cleanup_confirmed: false,
                private_receipt_id: None,
                committed_receipt_id: None,
            }
        }
        fn success(intent: &Intent) -> Value {
            json!({"schema":1,"contract":CONTRACT,"operation":intent.operation,
                "phase":"published_verified","summary":intent.summary,"execution_state":"completed",
                "lifecycle_scripts_executed":false,"code_safety":"not_established","ongoing_immutability":false,
                "target_publication_crossed":true,"cleanup_confirmed":true,
                "private_receipt_id":"1".repeat(64),"committed_receipt_id":"2".repeat(64)})
        }
        #[test]
        fn npm_public_review_never_serializes_private_decision_or_policy_guard() {
            let scope = GlobalStateGuard::new().unwrap();
            let intent = intent(&scope);
            let public = public_intent(&intent, "reviewed_intent");
            let encoded = serde_json::to_string(&public).unwrap();
            assert!(!encoded.contains(&intent.private_plan_digest));
            assert!(!encoded.contains(&intent.private_review_nonce));
            for key in [
                "private_plan_digest",
                "private_review_nonce",
                "policy",
                "parent_inode",
                "operator",
                "cwd",
            ] {
                assert!(public.get(key).is_none());
            }
            assert_eq!(public["execution_authority"], false);
            assert_eq!(public["current_code_safety"], "not_established");
        }
        #[test]
        fn npm_summary_unknown_authority_and_contract_changes_refuse_even_with_new_review_hash() {
            let scope = GlobalStateGuard::new().unwrap();
            for (field, value) in [
                ("private_plan_digest", json!("hidden")),
                ("execution_authority", json!(true)),
                ("contract", json!("LocalLeafMaterializeV1")),
                ("lifecycle_scripts", json!("enabled")),
                ("dependency_graph", json!("registry")),
                ("code_safety", json!("safe")),
                ("compressed_bytes", json!(6)),
                ("node_version", json!("ambient")),
            ] {
                let mut intent = intent(&scope);
                intent.summary[field] = value;
                intent.reviewed_sha256 = review_digest(&intent).unwrap();
                assert!(
                    validate_intent(&intent, &intent.operation).is_err(),
                    "{field}"
                );
            }
        }
        #[test]
        fn reviewed_digest_binds_private_inputs_even_when_the_public_view_is_unchanged() {
            let scope = GlobalStateGuard::new().unwrap();
            let original = intent(&scope);
            let original_public = public_projection(&original);
            for field in ["policy", "cwd", "parent", "archive", "plan", "nonce"] {
                let mut changed: Intent =
                    serde_json::from_value(serde_json::to_value(&original).unwrap()).unwrap();
                match field {
                    "policy" => {
                        let mut policy = serde_json::to_value(&changed.policy).unwrap();
                        // Preserve the DTO shape while changing its private commitment.
                        let first = policy["digest"][0].as_u64().unwrap();
                        policy["digest"][0] = json!(first ^ 1);
                        changed.policy = serde_json::from_value(policy).unwrap();
                    }
                    "cwd" => changed.cwd.push_str("/changed"),
                    "parent" => changed.parent_inode += 1,
                    "archive" => changed.archives[0].changed_nanos += 1,
                    "plan" => changed.private_plan_digest = "f".repeat(64),
                    _ => changed.private_review_nonce = uuid::Uuid::new_v4().to_string(),
                }
                assert_eq!(public_projection(&changed), original_public, "{field}");
                assert_ne!(
                    review_digest(&changed).unwrap(),
                    original.reviewed_sha256,
                    "{field}"
                );
                assert!(
                    validate_intent(&changed, &changed.operation).is_err(),
                    "{field}"
                );
                changed.reviewed_sha256 = review_digest(&changed).unwrap();
                assert!(
                    check_review(&changed, &original.reviewed_sha256).is_err(),
                    "{field}"
                );
            }
            let mut invalid: Intent =
                serde_json::from_value(serde_json::to_value(&original).unwrap()).unwrap();
            for nonce in [
                String::new(),
                uuid::Uuid::nil().to_string(),
                "secret".into(),
            ] {
                invalid.private_review_nonce = nonce;
                invalid.reviewed_sha256 = review_digest(&invalid).unwrap();
                assert!(validate_intent(&invalid, &invalid.operation).is_err());
            }
        }
        #[test]
        fn npm_review_binds_target_archive_and_operation_but_never_authorizes_missing_inputs() {
            let scope = GlobalStateGuard::new().unwrap();
            let mut intent = save(&scope);
            let reviewed = intent.reviewed_sha256.clone();
            intent.target.push_str("-changed");
            assert_ne!(review_digest(&intent).unwrap(), reviewed);
            intent.archives[0].sha256 = "e".repeat(64);
            assert!(validate_intent(&intent, &intent.operation).is_err());
            assert!(apply(&intent.operation, &reviewed, true).is_err());
            let mut store = OperationStore::open_npm_install(&intent.operation, false).unwrap();
            assert!(store.read(RecordKind::Started).unwrap().is_none());
            assert!(store.read(RecordKind::Finished).unwrap().is_none());
            assert!(!Path::new(&intent.target).exists());
        }
        #[test]
        fn npm_withdrawal_is_idempotent_without_archive_and_does_not_start_or_recover() {
            let scope = GlobalStateGuard::new().unwrap();
            let intent = save(&scope);
            assert!(!Path::new(&intent.archives[0].path).exists());
            assert!(undo(&intent.operation, &"0".repeat(64)).is_err());
            let first = undo(&intent.operation, &intent.reviewed_sha256).unwrap();
            assert_eq!(first["phase"], "withdrawn");
            assert_eq!(first["execution_state"], "not_started");
            assert_eq!(
                undo(&intent.operation, &intent.reviewed_sha256).unwrap(),
                first
            );
            assert!(apply(&intent.operation, &intent.reviewed_sha256, true)
                .unwrap_err()
                .reason
                .contains("never replay"));
            assert!(recover(&intent.operation, &intent.reviewed_sha256).is_err());
            let mut store = OperationStore::open_npm_install(&intent.operation, false).unwrap();
            assert!(store.read(RecordKind::Started).unwrap().is_none());
            assert!(store.read(RecordKind::Finished).unwrap().is_none());
            assert!(!Path::new(&intent.target).exists());
        }
        #[test]
        fn npm_started_and_failed_execution_history_never_becomes_no_execution_or_replay() {
            let scope = GlobalStateGuard::new().unwrap();
            let intent = save(&scope);
            append(&intent, RecordKind::Started, EventPhase::Started, None);
            let pending = status(&intent.operation).unwrap();
            assert_eq!(pending["phase"], "interrupted_or_running");
            assert_eq!(pending["execution_state"], "not_observed_currently");
            assert!(pending.get("package_code_executed").is_none());
            assert!(apply(&intent.operation, &intent.reviewed_sha256, true)
                .unwrap_err()
                .reason
                .contains("never replay"));
            assert!(undo(&intent.operation, &intent.reviewed_sha256).is_err());
            assert!(recover(&intent.operation, &intent.reviewed_sha256).is_err());
            append(
                &intent,
                RecordKind::Finished,
                EventPhase::Finished,
                Some(failed_after_execution()),
            );
            let done = status(&intent.operation).unwrap();
            assert_eq!(done["historical_only"], true);
            assert_eq!(
                done["transaction_observation"]["execution_state"],
                "completed"
            );
            assert_eq!(
                done["transaction_observation"]["target_publication_crossed"],
                true
            );
            assert_eq!(done["transaction_observation"]["cleanup_confirmed"], false);
            assert_eq!(done["transaction_observation"]["succeeded"], false);
            let mut store = OperationStore::open_npm_install(&intent.operation, false).unwrap();
            assert!(store.read(RecordKind::Withdrawn).unwrap().is_none());
        }
        #[test]
        fn npm_orphan_cross_contract_and_unknown_recovery_history_is_preserved_and_refused() {
            let scope = GlobalStateGuard::new().unwrap();
            for variant in 0..4 {
                let intent = save(&scope);
                let (kind, bytes) = match variant {
                    0 => (
                        RecordKind::Finished,
                        event(
                            &intent,
                            EventPhase::Finished,
                            Some(failed_after_execution()),
                        )
                        .unwrap(),
                    ),
                    1 => {
                        let mut value: Value = serde_json::from_slice(
                            &event(&intent, EventPhase::Started, None).unwrap(),
                        )
                        .unwrap();
                        value["contract"] = json!("LocalLeafMaterializeV1");
                        (RecordKind::Started, serde_json::to_vec(&value).unwrap())
                    }
                    2 => (RecordKind::Started, b"{partial".to_vec()),
                    _ => (RecordKind::Recovered, b"{}".to_vec()),
                };
                OperationStore::open_npm_install(&intent.operation, false)
                    .unwrap()
                    .append(kind, bytes.clone())
                    .unwrap();
                assert!(status(&intent.operation).is_err());
                assert!(undo(&intent.operation, &intent.reviewed_sha256).is_err());
                assert!(apply(&intent.operation, &intent.reviewed_sha256, true).is_err());
                assert_eq!(
                    OperationStore::open_npm_install(&intent.operation, false)
                        .unwrap()
                        .read(kind)
                        .unwrap(),
                    Some(bytes)
                );
            }
        }
        #[test]
        fn npm_effect_callback_rejects_peer_added_terminal_or_recovery_records() {
            use std::io::Write as _;
            use std::os::unix::fs::OpenOptionsExt as _;
            let scope = GlobalStateGuard::new().unwrap();
            for suffix in ["finished", "withdrawn", "recovered"] {
                let intent = save(&scope);
                append(&intent, RecordKind::Started, EventPhase::Started, None);
                let mut store = OperationStore::open_npm_install(&intent.operation, false).unwrap();
                revalidate_started_intent(&mut store, &intent).unwrap();
                // Deliberately bypass the cooperative store lock, just as a
                // same-UID peer could. No separate process or timing assumption.
                let path = tirith_core::policy::state_dir()
                    .unwrap()
                    .join("npm-install-intents")
                    .join(format!("{}.{}.json", intent.operation, suffix));
                let bytes = if suffix == "finished" {
                    event(
                        &intent,
                        EventPhase::Finished,
                        Some(failed_after_execution()),
                    )
                    .unwrap()
                } else if suffix == "withdrawn" {
                    event(&intent, EventPhase::Withdrawn, None).unwrap()
                } else {
                    b"{}".to_vec()
                };
                let mut peer = std::fs::OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .mode(0o600)
                    .open(&path)
                    .unwrap();
                peer.write_all(&bytes).unwrap();
                peer.sync_all().unwrap();
                drop(peer);
                // Retained-record checks alone accept the new known filename.
                store.revalidate().unwrap();
                assert!(
                    revalidate_started_intent(&mut store, &intent).is_err(),
                    "{suffix}"
                );
                assert_eq!(std::fs::read(&path).unwrap(), bytes);
                assert!(!Path::new(&intent.target).exists());
            }
        }
        #[test]
        fn npm_success_requires_exact_plan_and_distinct_content_hash_receipts() {
            let scope = GlobalStateGuard::new().unwrap();
            let intent = intent(&scope);
            let valid = success(&intent);
            assert!(valid_success(&valid, &intent));
            for (field, value) in [
                ("cleanup_confirmed", json!(false)),
                ("lifecycle_scripts_executed", json!(true)),
                ("execution_state", json!("not_started")),
                ("target_publication_crossed", json!(false)),
                (
                    "private_receipt_id",
                    json!(uuid::Uuid::new_v4().to_string()),
                ),
                ("committed_receipt_id", json!("1".repeat(64))),
                ("summary", json!({})),
            ] {
                let mut changed = valid.clone();
                changed[field] = value;
                assert!(!valid_success(&changed, &intent), "{field}");
            }
        }
        #[test]
        fn npm_duplicate_fields_and_unknown_intent_fields_never_parse() {
            let scope = GlobalStateGuard::new().unwrap();
            let intent = intent(&scope);
            let bytes = encode(&intent).unwrap();
            let text = String::from_utf8(bytes).unwrap();
            let duplicate = text.replacen('{', "{\"schema\":1,", 1);
            assert!(decode::<Intent>(duplicate.as_bytes()).is_err());
            let mut value: Value = serde_json::from_str(&text).unwrap();
            value["execution_authority"] = json!(true);
            assert!(decode::<Intent>(&serde_json::to_vec(&value).unwrap()).is_err());
        }
        #[test]
        fn completed_history_never_authorizes_restart_undo_of_private_or_public_bytes() {
            let scope = GlobalStateGuard::new().unwrap();
            let intent = save(&scope);
            append(&intent, RecordKind::Started, EventPhase::Started, None);
            // History fields are descriptive and can never manufacture a native
            // completion proof or recover the original private kernel handles.
            append(
                &intent,
                RecordKind::Finished,
                EventPhase::Finished,
                Some(TerminalObservation {
                    phase: "published_verified".into(),
                    succeeded: true,
                    execution_state: ExecutionObservation::Completed,
                    target_publication_crossed: Some(true),
                    cleanup_confirmed: true,
                    private_receipt_id: Some("c".repeat(64)),
                    committed_receipt_id: Some("d".repeat(64)),
                }),
            );
            let private = scope.roots().cwd.join("unclaimed-private-interruption");
            std::fs::create_dir(&private).unwrap();
            std::fs::write(private.join("payload"), b"preserve private data").unwrap();
            assert!(undo(&intent.operation, &intent.reviewed_sha256)
                .unwrap_err()
                .reason
                .contains("preserved"));
            assert_eq!(
                std::fs::read(private.join("payload")).unwrap(),
                b"preserve private data"
            );
            // Reparenting to the reviewed public path never widens undo authority.
            std::fs::rename(&private, &intent.target).unwrap();
            std::fs::write(
                Path::new(&intent.target).join("new-public-file"),
                b"preserve public data",
            )
            .unwrap();
            assert!(undo(&intent.operation, &intent.reviewed_sha256).is_err());
            assert_eq!(
                std::fs::read(Path::new(&intent.target).join("payload")).unwrap(),
                b"preserve private data"
            );
            assert_eq!(
                std::fs::read(Path::new(&intent.target).join("new-public-file")).unwrap(),
                b"preserve public data"
            );
            let mut store = OperationStore::open_npm_install(&intent.operation, false).unwrap();
            assert!(store.read(RecordKind::Recovered).unwrap().is_none());
            assert!(store.read(RecordKind::Withdrawn).unwrap().is_none());
        }
    }
}

#[cfg(test)]
mod route_tests {
    use super::*;
    use clap::Parser;
    #[derive(Parser)]
    struct Route {
        #[command(subcommand)]
        action: Action,
    }
    #[test]
    fn npm_mutation_routes_require_exact_review_without_execution_overrides() {
        let id = "11111111-1111-4111-8111-111111111111";
        let digest = "a".repeat(64);
        for action in ["apply", "undo", "recover"] {
            assert!(Route::try_parse_from(["install-npm", action, id]).is_err());
            assert!(Route::try_parse_from([
                "install-npm",
                action,
                id,
                "--reviewed",
                &digest,
                "--json"
            ])
            .is_ok());
            for flag in ["--force", "--run-scripts", "--allow-untrusted-tool"] {
                assert!(Route::try_parse_from([
                    "install-npm",
                    action,
                    id,
                    "--reviewed",
                    &digest,
                    flag
                ])
                .is_err());
            }
        }
        assert!(Route::try_parse_from(["install-npm", "status", id, "--json"]).is_ok());
        assert!(Route::try_parse_from(["install-npm", "plan", "--target", "new"]).is_err());
    }
    #[test]
    fn npm_generic_failure_does_not_invent_nonexecution_or_cleanup() {
        let value = Failure::from("unreadable history").output();
        assert_eq!(value["execution_state"], "not_observed");
        assert!(value["transaction_observation"].is_null());
        assert!(value.get("package_code_executed").is_none());
        assert!(value.get("cleanup_confirmed").is_none());
    }
}
