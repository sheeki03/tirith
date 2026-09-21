//! Reviewed local data materialization, separate from disabled package execution.
//! A saved intent is reinspection input, never authority. No runtime is launched.
use std::path::PathBuf;

#[derive(clap::Subcommand)]
pub(crate) enum Action {
    /// Review exact local leaf archives and save an immutable operation intent.
    Plan {
        #[arg(required = true, value_name = "ARCHIVE")]
        artifacts: Vec<PathBuf>,
        #[arg(long)]
        target: PathBuf,
        #[arg(long)]
        json: bool,
    },
    /// Reinspect a reviewed intent and publish to its still-absent target.
    Apply {
        operation: String,
        /// Exact public commitment printed by plan. This is explicit review,
        /// not a substitute for current artifact, policy and task authorization.
        #[arg(long)]
        reviewed: String,
        #[arg(long)]
        json: bool,
    },
    /// Inspect bounded historical records; does not assert current code safety.
    Status {
        operation: String,
        #[arg(long)]
        json: bool,
    },
    /// Withdraw an unstarted operation, or request exact private-tree recovery.
    Undo {
        operation: String,
        #[arg(long)]
        reviewed: String,
        #[arg(long)]
        json: bool,
    },
    /// Revalidate a completed inventory milestone without replaying installation.
    Recover {
        operation: String,
        #[arg(long)]
        reviewed: String,
        #[arg(long)]
        json: bool,
    },
    /// Explicitly inspect and remove exact remaining private contents after interrupted undo.
    ContinueUndo {
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
            | Self::Recover { json, .. }
            | Self::ContinueUndo { json, .. } => *json,
        }
    }
}
pub(crate) fn run(action: Action) -> i32 {
    let json = action.json();
    #[cfg(target_os = "linux")]
    let result = linux::run(action);
    #[cfg(not(target_os = "linux"))]
    let result: Result<serde_json::Value, String> = {
        let _ = action;
        Err("LocalLeafMaterializeV1 publication is supported only on Linux".into())
    };
    match result {
        Ok(value) => {
            let printed = if json {
                serde_json::to_writer(std::io::stdout().lock(), &value).map_err(|e| e.to_string())
            } else {
                print_human(&value)
            };
            if printed.is_err() {
                return 1;
            }
            println!();
            0
        }
        Err(reason) => {
            if json {
                let _ = serde_json::to_writer(
                    std::io::stdout().lock(),
                    &serde_json::json!({"schema":1,"contract":"LocalLeafMaterializeV1","error":reason,"package_code_executed":false,"execution_authority":false}),
                );
                println!();
            } else {
                eprintln!(
                    "tirith pkg materialize: {}",
                    super::sanitize_for_human_output(&reason, false)
                );
            }
            1
        }
    }
}
fn print_human(value: &serde_json::Value) -> Result<(), String> {
    use std::io::Write;
    let rendered = serde_json::to_string_pretty(value).map_err(|e| e.to_string())?;
    // JSON escaping avoids terminal controls in local paths. Private intent
    // fields are never passed to this renderer.
    std::io::stdout()
        .lock()
        .write_all(rendered.as_bytes())
        .map_err(|e| e.to_string())
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
    fn continue_undo_route_requires_review_and_rejects_execution_overrides() {
        let id = "11111111-1111-4111-8111-111111111111";
        let reviewed = "a".repeat(64);
        assert!(Route::try_parse_from(["materialize", "continue-undo", id]).is_err());
        let parsed = Route::try_parse_from([
            "materialize",
            "continue-undo",
            id,
            "--reviewed",
            reviewed.as_str(),
            "--json",
        ])
        .unwrap();
        assert!(
            matches!(parsed.action, Action::ContinueUndo { operation, reviewed: digest, json: true }
            if operation == id && digest == reviewed)
        );
        for unsupported in ["--run-scripts", "--allow-untrusted-tool", "--force"] {
            assert!(Route::try_parse_from([
                "materialize",
                "continue-undo",
                id,
                "--reviewed",
                reviewed.as_str(),
                unsupported,
            ])
            .is_err());
        }
    }
}

#[cfg(target_os = "linux")]
mod linux {
    use super::Action;
    use crate::cli::package_checkpoint::{
        materialization::{MaterializationCheckpoint, State},
        materialization_recovery_checkpoint::RecoveryCheckpoint,
        materialization_store::{canonical_operation, OperationStore, RecordKind, RECORD_CAP},
        InstallTargetBinding,
    };
    use serde::{Deserialize, Serialize};
    use serde_json::{json, Value};
    use sha2::{Digest, Sha256};
    use std::{
        fs::File,
        os::unix::fs::MetadataExt,
        path::{Path, PathBuf},
        sync::atomic::AtomicBool,
    };
    use tirith_core::{
        artifact::{
            npm_archive::NpmLimits,
            npm_install::{
                materialize::{
                    MaterializationPlan, MaterializationRecovery, MaterializationRecoveryAction,
                    CONTRACT,
                },
                NewNpmDestination, VerifiedNpmArtifact,
            },
        },
        policy::BoundedRuntimePolicyInputs,
        policy_snapshot::{EffectivePolicySnapshot, PrivatePolicyReplayGuard},
        task_boundary::{
            BoundaryMarker, BoundaryOperation, LocalPackageMaterializationBoundary,
            LocalPackageRecoveryBoundary, PendingBoundaryAuthorization, TaskBoundaryPermit,
        },
    };
    const SCHEMA: u32 = 1;
    const PATH_CAP: usize = 4096;
    const CONTINUED_UNDO_PHASES: [&str; 2] = [
        "private_contents_continued_undo_empty_root_retained",
        "private_tree_observed_already_empty_root_retained",
    ];

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
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct SummaryObservation {
        schema: u32,
        contract: String,
        operation_id: String,
        public_plan_digest: String,
        inventory_digest: String,
        artifacts: Vec<String>,
        packages: Vec<PackageObservation>,
        files: usize,
        directories: usize,
        bytes: u64,
        threat_db_sequence: u64,
        signed_build_timestamp: u64,
        package_code_executed: bool,
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
        summary: Value,
        reviewed_sha256: String,
    }
    #[derive(Serialize, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Event {
        schema: u32,
        operation: String,
        reviewed_sha256: String,
        phase: String,
        at: String,
    }

    pub(super) fn run(action: Action) -> Result<Value, String> {
        match action {
            Action::Plan {
                artifacts, target, ..
            } => plan(&artifacts, &target),
            Action::Apply {
                operation,
                reviewed,
                ..
            } => apply(&operation, &reviewed),
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
            Action::ContinueUndo {
                operation,
                reviewed,
                ..
            } => {
                let mut store = OperationStore::open(&operation, false).map_err(err)?;
                let intent = load_intent(&mut store, &operation)?;
                check_review(&intent, &reviewed)?;
                recover_started(
                    &mut store,
                    &intent,
                    MaterializationRecoveryAction::ContinueUndoPrivate,
                )
            }
        }
    }
    fn plan(paths: &[PathBuf], target: &Path) -> Result<Value, String> {
        let _bounded = BoundedRuntimePolicyInputs::enter();
        let cwd = current_cwd()?;
        let policy =
            EffectivePolicySnapshot::resolve_for_local_mutation(Some(&cwd)).map_err(err)?;
        let binding = InstallTargetBinding::bind(target).map_err(err)?;
        let id = uuid::Uuid::new_v4().to_string();
        let (artifacts, archives) = capture_artifacts(paths)?;
        let destination = NewNpmDestination::capture(binding.target()).map_err(err)?;
        let plan =
            MaterializationPlan::prepare(&id, artifacts, destination, &policy).map_err(err)?;
        let permit = authorize_task(&plan, &policy)?;
        let mut authorized = plan.authorize(&policy, permit).map_err(err)?;
        let authority = authorized.checkpoint_authorization().map_err(err)?;
        authority.revalidate().map_err(err)?;
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
            private_plan_digest: authority.private_plan_digest().into(),
            summary: serde_json::to_value(plan.summary()).map_err(err)?,
            reviewed_sha256: String::new(),
        };
        intent.reviewed_sha256 = review_digest(&intent)?;
        validate_intent(&intent, &id)?;
        let mut store = OperationStore::open(&id, true).map_err(err)?;
        authority.revalidate().map_err(err)?;
        store
            .append(RecordKind::Intent, encode(&intent)?)
            .map_err(err)?;
        authority.revalidate().map_err(err)?;
        Ok(public_intent(&intent, "reviewed_intent"))
    }
    fn apply(id: &str, reviewed: &str) -> Result<Value, String> {
        let _bounded = BoundedRuntimePolicyInputs::enter();
        let mut store = OperationStore::open(id, false).map_err(err)?;
        let intent = load_intent(&mut store, id)?;
        check_review(&intent, reviewed)?;
        if store.read(RecordKind::Started).map_err(err)?.is_some()
            || store.read(RecordKind::Finished).map_err(err)?.is_some()
            || store.read(RecordKind::Withdrawn).map_err(err)?.is_some()
            || store.read(RecordKind::Recovered).map_err(err)?.is_some()
            || store.read(RecordKind::Undone).map_err(err)?.is_some()
            || store
                .read(RecordKind::ConfirmStarted)
                .map_err(err)?
                .is_some()
            || store.read(RecordKind::UndoStarted).map_err(err)?.is_some()
            || store
                .read(RecordKind::ContinueUndoStarted)
                .map_err(err)?
                .is_some()
            || store
                .read(RecordKind::ContinuedUndo)
                .map_err(err)?
                .is_some()
        {
            return Err("operation has already started or ended; use explicit recover/undo, never replay apply".into());
        }
        let (policy, binding, plan) = recapture(&intent)?;
        let permit = authorize_task(&plan, &policy)?;
        let mut authorized = plan.authorize(&policy, permit).map_err(err)?;
        let authority = authorized.checkpoint_authorization().map_err(err)?;
        if authority.private_plan_digest() != intent.private_plan_digest {
            return Err(
                "private artifact or policy decision changed; create a new reviewed plan".into(),
            );
        }
        authority.revalidate().map_err(err)?;
        // Once the durable start record exists, a later process may inspect or
        // explicitly recover. It never automatically replays this apply.
        store
            .append(RecordKind::Started, event(&intent, "started")?)
            .map_err(err)?;
        let mut checkpoint = MaterializationCheckpoint::begin(&binding, authority).map_err(err)?;
        let (journal, target) = checkpoint.writer_handles().map_err(err)?;
        let mut writer = authorized.writer(journal, target).map_err(err)?;
        let cancelled = AtomicBool::new(false);
        if writer.populate(&cancelled).is_err() {
            let clean = writer.cleanup().is_ok() && checkpoint.record_private_empty().is_ok();
            let phase = if clean {
                "failed_private_empty_retained"
            } else {
                "failed_private_objects_preserved"
            };
            store
                .append(RecordKind::Finished, event(&intent, phase)?)
                .map_err(err)?;
            return Err(format!(
                "materialization failed; {phase}; no package code executed"
            ));
        }
        store.revalidate().map_err(err)?;
        let summary = match checkpoint.publish(&mut writer) {
            Ok(summary) => summary,
            Err(_) => {
                let phase = if checkpoint.state() == State::Private {
                    if writer.cleanup().is_ok() && checkpoint.record_private_empty().is_ok() {
                        "failed_private_empty_retained"
                    } else {
                        "failed_private_objects_preserved"
                    }
                } else {
                    "publication_uncertain_objects_preserved"
                };
                store
                    .append(RecordKind::Finished, event(&intent, phase)?)
                    .map_err(err)?;
                return Err(format!(
                    "materialization publication failed; {phase}; use explicit recovery"
                ));
            }
        };
        store.revalidate().map_err(err)?;
        store
            .append(RecordKind::Finished, event(&intent, "published_verified")?)
            .map_err(err)?;
        Ok(
            json!({"schema":SCHEMA,"contract":CONTRACT,"operation":id,"phase":"published_verified","summary":summary,"package_code_executed":false,"execution_authority":false,"current_code_safety":"not_established","ongoing_immutability":false}),
        )
    }
    fn recapture(
        intent: &Intent,
    ) -> Result<
        (
            EffectivePolicySnapshot,
            InstallTargetBinding,
            MaterializationPlan,
        ),
        String,
    > {
        if current_cwd() != Ok(intent.cwd.clone()) {
            return Err(
                "current working directory differs from the reviewed resolution context".into(),
            );
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
        let destination = NewNpmDestination::capture(binding.target()).map_err(err)?;
        let plan = MaterializationPlan::prepare(&intent.operation, artifacts, destination, &policy)
            .map_err(err)?;
        if serde_json::to_value(plan.summary()).map_err(err)? != intent.summary {
            return Err("reviewed materialization commitment changed".into());
        }
        Ok((policy, binding, plan))
    }
    fn authorize_task(
        plan: &MaterializationPlan,
        policy: &EffectivePolicySnapshot,
    ) -> Result<TaskBoundaryPermit<LocalPackageMaterializationBoundary>, String> {
        let operation = plan.operation();
        let pending = prepare_task::<LocalPackageMaterializationBoundary>(&operation, policy)?;
        // The exact fresh live plan instance supplies the operation. A DTO and
        // the public review digest can never stand in for this typed permit.
        pending
            .consume_default_for_operation(&operation, chrono::Utc::now())
            .map_err(|_| {
                "fresh task authorization is unavailable for this exact action".to_string()
            })
    }
    fn prepare_task<B: BoundaryMarker>(
        operation: &BoundaryOperation<'_>,
        policy: &EffectivePolicySnapshot,
    ) -> Result<PendingBoundaryAuthorization<B>, String> {
        let result = tirith_core::task_boundary::prepare_locally_derived_boundary_authorization::<B>(
            operation,
            &policy.policy.task_gate,
            &tirith_core::task_analysis::TaskAnalysisContext::default(),
        );
        let assessment = match &result {
            Ok(pending) => Some(pending.assessment()),
            Err(error) => error.assessment(),
        };
        if let Some(assessment) = assessment {
            if let Err(error) = tirith_core::audit::log_task_boundary_assessment(assessment) {
                tirith_core::audit::audit_diagnostic(format!(
                    "materialization task audit append failed: {error}"
                ));
            }
        }
        result.map_err(|_|"current task authorization refused; this route cannot invent provenance or typed approval".into())
    }
    fn status(id: &str) -> Result<Value, String> {
        let mut store = OperationStore::open(id, false).map_err(err)?;
        let intent = load_intent(&mut store, id)?;
        let started = read_event(&mut store, RecordKind::Started, &intent, &["started"])?;
        let finished = read_event(
            &mut store,
            RecordKind::Finished,
            &intent,
            &[
                "published_verified",
                "failed_private_empty_retained",
                "failed_private_objects_preserved",
                "publication_uncertain_objects_preserved",
            ],
        )?;
        let withdrawn = read_event(&mut store, RecordKind::Withdrawn, &intent, &["withdrawn"])?;
        let recovered = read_event(
            &mut store,
            RecordKind::Recovered,
            &intent,
            &["published_recovered_verified"],
        )?;
        let undone = read_event(
            &mut store,
            RecordKind::Undone,
            &intent,
            &["private_contents_undone_empty_root_retained"],
        )?;
        let confirm_started = read_event(
            &mut store,
            RecordKind::ConfirmStarted,
            &intent,
            &["confirm_started"],
        )?;
        let undo_started = read_event(
            &mut store,
            RecordKind::UndoStarted,
            &intent,
            &["undo_started"],
        )?;
        let (continue_undo_started, continued_undo) =
            read_continuation_history(&mut store, &intent, started.is_some())?;
        if (recovered.is_some()
            || undone.is_some()
            || confirm_started.is_some()
            || undo_started.is_some())
            && started.is_none()
        {
            return Err("recovery history lacks an original start; objects preserved".into());
        }

        if finished.is_some() && started.is_none() || withdrawn.is_some() && started.is_some() {
            return Err(
                "materialization history contains inconsistent states; objects preserved".into(),
            );
        }
        let phase = if let Some(continued) = &continued_undo {
            continued.phase.as_str()
        } else if continue_undo_started.is_some() {
            "continue_undo_incomplete_or_running"
        } else if undone.is_some() {
            "private_contents_undone_empty_root_retained"
        } else if undo_started.is_some() {
            "undo_incomplete_or_running"
        } else if recovered.is_some() {
            "published_recovered_verified"
        } else if confirm_started.is_some() {
            "confirmation_incomplete_or_running"
        } else {
            finished
                .as_ref()
                .or(withdrawn.as_ref())
                .map(|e| e.phase.as_str())
                .unwrap_or(if started.is_some() {
                    "interrupted_or_running"
                } else {
                    "reviewed_intent"
                })
        };
        let mut output = public_intent(&intent, phase);
        output["current_target_observation"] = json!(path_observation(Path::new(&intent.target)));
        let parent = Path::new(&intent.target)
            .parent()
            .ok_or("target parent unavailable")?;
        output["private_journal_observation"] = json!(path_observation(
            &parent.join(format!(".tirith-materialize-{}", intent.operation))
        ));
        output["historical_only"] = json!(true);
        store.revalidate().map_err(err)?;
        Ok(output)
    }
    fn read_continuation_history(
        store: &mut OperationStore,
        intent: &Intent,
        started: bool,
    ) -> Result<(Option<Event>, Option<Event>), String> {
        let attempt = read_event(
            store,
            RecordKind::ContinueUndoStarted,
            intent,
            &["continue_undo_started"],
        )?;
        let completed = read_event(
            store,
            RecordKind::ContinuedUndo,
            intent,
            &CONTINUED_UNDO_PHASES,
        )?;
        if (attempt.is_some() || completed.is_some()) && !started {
            return Err("continuation history lacks an original start; objects preserved".into());
        }
        if completed.is_some() && attempt.is_none() {
            return Err("continuation outcome lacks its attempt record; objects preserved".into());
        }
        Ok((attempt, completed))
    }
    fn undo(id: &str, reviewed: &str) -> Result<Value, String> {
        let mut store = OperationStore::open(id, false).map_err(err)?;
        let intent = load_intent(&mut store, id)?;
        check_review(&intent, reviewed)?;
        if store.read(RecordKind::Started).map_err(err)?.is_some() {
            return recover_started(
                &mut store,
                &intent,
                MaterializationRecoveryAction::UndoPrivate,
            );
        }
        if store.read(RecordKind::Finished).map_err(err)?.is_some()
            || store.read(RecordKind::Recovered).map_err(err)?.is_some()
            || store.read(RecordKind::Undone).map_err(err)?.is_some()
            || store
                .read(RecordKind::ConfirmStarted)
                .map_err(err)?
                .is_some()
            || store.read(RecordKind::UndoStarted).map_err(err)?.is_some()
            || store
                .read(RecordKind::ContinueUndoStarted)
                .map_err(err)?
                .is_some()
            || store
                .read(RecordKind::ContinuedUndo)
                .map_err(err)?
                .is_some()
        {
            return Err("ended history lacks a start record; objects preserved".into());
        }
        // Every package effect follows the durable Started record while holding
        // this same store lock. Withdrawing only an unstarted intent grants no
        // filesystem-tree effect, and must remain possible after admission is lost.
        if read_event(&mut store, RecordKind::Withdrawn, &intent, &["withdrawn"])?.is_none() {
            store.revalidate().map_err(err)?;
            store
                .append(RecordKind::Withdrawn, event(&intent, "withdrawn")?)
                .map_err(err)?;
            store.revalidate().map_err(err)?;
        }
        Ok(public_intent(&intent, "withdrawn"))
    }
    fn recover(id: &str, reviewed: &str) -> Result<Value, String> {
        let mut store = OperationStore::open(id, false).map_err(err)?;
        let intent = load_intent(&mut store, id)?;
        check_review(&intent, reviewed)?;
        if read_event(&mut store, RecordKind::Started, &intent, &["started"])?.is_none() {
            return Err("operation has not started; recovery cannot start or replay it".into());
        }
        recover_started(
            &mut store,
            &intent,
            MaterializationRecoveryAction::ConfirmPublished,
        )
    }
    fn recover_started(
        store: &mut OperationStore,
        intent: &Intent,
        action: MaterializationRecoveryAction,
    ) -> Result<Value, String> {
        let undo = action != MaterializationRecoveryAction::ConfirmPublished;
        let _bounded = BoundedRuntimePolicyInputs::enter();
        if read_event(store, RecordKind::Started, intent, &["started"])?.is_none() {
            return Err("recovery cannot create or replay an unstarted operation".into());
        }
        let (_, continued_undo) = read_continuation_history(store, intent, true)?;
        if action == MaterializationRecoveryAction::ContinueUndoPrivate && continued_undo.is_some()
        {
            return Err("continuation already has a recorded outcome; inspect status".into());
        }
        if store.read(RecordKind::Withdrawn).map_err(err)?.is_some() {
            return Err(
                "started operation conflicts with withdrawal history; objects preserved".into(),
            );
        }
        if current_cwd() != Ok(intent.cwd.clone()) {
            return Err(
                "current working directory differs from the reviewed recovery context".into(),
            );
        }
        let policy =
            EffectivePolicySnapshot::resolve_for_local_mutation(Some(&intent.cwd)).map_err(err)?;
        let paths = intent
            .archives
            .iter()
            .map(|a| PathBuf::from(&a.path))
            .collect::<Vec<_>>();
        let (artifacts, actual) = capture_artifacts(&paths)?;
        if actual != intent.archives {
            return Err(
                "recovery archive identity or bytes differ from the reviewed intent".into(),
            );
        }
        let mut checkpoint = RecoveryCheckpoint::open(
            Path::new(&intent.target),
            &intent.operation,
            (intent.parent_device, intent.parent_inode),
            &intent.private_plan_digest,
        )
        .map_err(err)?;
        let recovery = MaterializationRecovery::capture(
            &intent.operation,
            Path::new(&intent.target),
            artifacts,
            checkpoint.inventory(),
            action,
            &policy,
        )
        .map_err(err)?;
        let operation = recovery.operation();
        let pending = prepare_task::<LocalPackageRecoveryBoundary>(&operation, &policy)?;
        let permit = pending
            .consume_default_for_operation(&operation, chrono::Utc::now())
            .map_err(|_| {
                "fresh task authorization is unavailable for this exact action".to_string()
            })?;
        let mut authority = recovery.authorize(&policy, permit).map_err(err)?;
        store.revalidate().map_err(err)?;
        checkpoint.revalidate().map_err(err)?;
        let (attempt_kind, attempt_phase) = match action {
            MaterializationRecoveryAction::UndoPrivate => (RecordKind::UndoStarted, "undo_started"),
            MaterializationRecoveryAction::ContinueUndoPrivate => {
                (RecordKind::ContinueUndoStarted, "continue_undo_started")
            }
            MaterializationRecoveryAction::ConfirmPublished => {
                (RecordKind::ConfirmStarted, "confirm_started")
            }
        };
        if read_event(store, attempt_kind, intent, &[attempt_phase])?.is_none() {
            store
                .append(attempt_kind, event(intent, attempt_phase)?)
                .map_err(err)?;
        }
        let cancelled = AtomicBool::new(false);
        if undo {
            authority.relocate_for_undo().map_err(|_|"undo relocation refused or uncertain; inspect status; all remaining objects are preserved".to_string())?;
        }
        let observation = if undo {
            authority.undo_private(&cancelled)
        } else {
            authority.confirm_published()
        }
        .map_err(err)?;
        observation.revalidate().map_err(err)?;
        if undo {
            checkpoint.observe_private_transition().map_err(err)?;
        }
        checkpoint.revalidate().map_err(err)?;
        store.revalidate().map_err(err)?;
        let (kind, phase) = match action {
            MaterializationRecoveryAction::UndoPrivate => (
                RecordKind::Undone,
                "private_contents_undone_empty_root_retained",
            ),
            MaterializationRecoveryAction::ContinueUndoPrivate => (
                RecordKind::ContinuedUndo,
                match observation.summary().outcome.as_str() {
                    "removed_exact_remaining_private_contents" => CONTINUED_UNDO_PHASES[0],
                    "observed_private_tree_already_empty" => CONTINUED_UNDO_PHASES[1],
                    _ => {
                        return Err(
                            "unexpected continuation outcome; preserve recovery history".into()
                        )
                    }
                },
            ),
            MaterializationRecoveryAction::ConfirmPublished => {
                (RecordKind::Recovered, "published_recovered_verified")
            }
        };
        if read_event(store, kind, intent, &[phase])?.is_none() {
            store.append(kind, event(intent, phase)?).map_err(err)?;
        }
        observation.revalidate().map_err(err)?;
        checkpoint.revalidate().map_err(err)?;
        store.revalidate().map_err(err)?;
        Ok(
            json!({"schema":SCHEMA,"contract":CONTRACT,"operation":intent.operation,"phase":phase,"observation":observation.summary(),"package_code_executed":false,"execution_authority":false,"current_code_safety":"not_established","ongoing_immutability":false}),
        )
    }
    fn capture_artifacts(
        paths: &[PathBuf],
    ) -> Result<(Vec<VerifiedNpmArtifact>, Vec<ArchiveIntent>), String> {
        if paths.is_empty() || paths.len() > 8 {
            return Err("materialization requires one through eight exact local archives".into());
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
            let artifact =
                VerifiedNpmArtifact::capture(file.try_clone().map_err(err)?).map_err(err)?;
            artifact.revalidate().map_err(err)?;
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
    fn load_intent(store: &mut OperationStore, id: &str) -> Result<Intent, String> {
        let bytes = store
            .read(RecordKind::Intent)
            .map_err(err)?
            .ok_or("materialization operation does not exist")?;
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
            || intent.archives.len() > 8
        {
            return Err("materialization intent schema or operator binding refused".into());
        }
        let summary: SummaryObservation = serde_json::from_value(intent.summary.clone())
            .map_err(|_| "materialization summary schema refused")?;
        let artifact_hashes = intent
            .archives
            .iter()
            .map(|a| a.sha256.clone())
            .collect::<Vec<_>>();
        if summary.schema != SCHEMA
            || summary.contract != CONTRACT
            || summary.operation_id != id
            || !is_digest(&summary.public_plan_digest)
            || !is_digest(&summary.inventory_digest)
            || summary.artifacts != artifact_hashes
            || summary.packages.len() != intent.archives.len()
            || summary
                .files
                .checked_add(summary.directories)
                .is_none_or(|n| n > tirith_core::artifact::npm_install::materialize::MAX_ENTRIES)
            || summary.bytes > 128 * 1024 * 1024 * 8
            || summary.threat_db_sequence == 0
            || summary.signed_build_timestamp == 0
            || summary.package_code_executed
            || summary.code_safety != "not_established"
            || summary
                .packages
                .iter()
                .zip(&intent.archives)
                .any(|(package, archive)| {
                    package.name.is_empty()
                        || package.name.len() > 1024
                        || package.version.is_empty()
                        || package.version.len() > 1024
                        || package.compressed_sha256 != archive.sha256
                })
        {
            return Err("materialization summary binding or safety claims refused".into());
        }
        for path in std::iter::once(&intent.cwd)
            .chain(std::iter::once(&intent.target))
            .chain(intent.archives.iter().map(|a| &a.path))
        {
            if path.len() > PATH_CAP
                || !Path::new(path).is_absolute()
                || Path::new(path)
                    .components()
                    .any(|p| matches!(p, std::path::Component::ParentDir))
            {
                return Err("materialization intent path is not canonical and bounded".into());
            }
        }
        if intent.archives.iter().any(|a| !is_digest(&a.sha256))
            || !is_digest(&intent.private_plan_digest)
            || !is_digest(&intent.reviewed_sha256)
            || review_digest(intent)? != intent.reviewed_sha256
        {
            return Err("materialization intent commitment is malformed or changed".into());
        }
        Ok(())
    }
    fn public_projection(intent: &Intent) -> Value {
        json!({"schema":SCHEMA,"contract":CONTRACT,"operation":intent.operation,"target":intent.target,"archives":intent.archives.iter().map(|a|json!({"path":a.path,"sha256":a.sha256})).collect::<Vec<_>>(),"summary":intent.summary})
    }
    fn public_intent(intent: &Intent, phase: &str) -> Value {
        let mut v = public_projection(intent);
        v["reviewed_sha256"] = json!(intent.reviewed_sha256);
        v["phase"] = json!(phase);
        v["package_code_executed"] = json!(false);
        v["execution_authority"] = json!(false);
        v["current_code_safety"] = json!("not_established");
        v["ongoing_immutability"] = json!(false);
        v
    }
    fn review_digest(intent: &Intent) -> Result<String, String> {
        Ok(format!(
            "{:x}",
            Sha256::digest(
                tirith_core::audit::canonical_json_for_hash(&public_projection(intent)).as_bytes()
            )
        ))
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
    fn event(intent: &Intent, phase: &str) -> Result<Vec<u8>, String> {
        encode(&Event {
            schema: SCHEMA,
            operation: intent.operation.clone(),
            reviewed_sha256: intent.reviewed_sha256.clone(),
            phase: phase.into(),
            at: chrono::Utc::now().to_rfc3339(),
        })
    }
    fn read_event(
        store: &mut OperationStore,
        kind: RecordKind,
        intent: &Intent,
        phases: &[&str],
    ) -> Result<Option<Event>, String> {
        let Some(bytes) = store.read(kind).map_err(err)? else {
            return Ok(None);
        };
        let e: Event = decode(&bytes)?;
        if e.schema != SCHEMA
            || e.operation != intent.operation
            || e.reviewed_sha256 != intent.reviewed_sha256
            || !phases.contains(&e.phase.as_str())
            || chrono::DateTime::parse_from_rfc3339(&e.at).is_err()
        {
            return Err("materialization history binding or phase refused".into());
        }
        Ok(Some(e))
    }
    fn encode(value: &impl Serialize) -> Result<Vec<u8>, String> {
        let bytes = serde_json::to_vec(value).map_err(err)?;
        if bytes.len() > RECORD_CAP {
            return Err("materialization record exceeds its bound".into());
        }
        Ok(bytes)
    }
    fn decode<T: serde::de::DeserializeOwned>(bytes: &[u8]) -> Result<T, String> {
        let text = std::str::from_utf8(bytes).map_err(err)?;
        let value = tirith_core::mcp_lock::parse_json_no_duplicates(text)
            .map_err(|_| "materialization record contains ambiguous or invalid JSON")?;
        serde_json::from_value(value).map_err(|_| "materialization record schema refused".into())
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
        let s = path.to_str().ok_or("materialization paths must be UTF-8")?;
        if s.len() > PATH_CAP {
            return Err("materialization path exceeds its bound".into());
        }
        Ok(s.into())
    }
    fn path_observation(path: &Path) -> &'static str {
        match std::fs::symlink_metadata(path) {
            Ok(m) if m.is_dir() && !m.file_type().is_symlink() => {
                "present_directory_unverified_preserved"
            }
            Ok(_) => "present_non_directory_preserved",
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => "absent",
            Err(_) => "unavailable_preserved",
        }
    }
    fn err(e: impl std::fmt::Debug) -> String {
        format!("materialization refused: {e:?}")
    }
    #[cfg(test)]
    mod tests {
        use super::*;
        use tirith_test_support::GlobalStateGuard;
        fn intent(scope: &GlobalStateGuard) -> Intent {
            let policy = EffectivePolicySnapshot::resolve(
                scope.roots().cwd.to_str(),
                tirith_core::policy_snapshot::ResolutionMode::LocalOnly,
            );
            let id = uuid::Uuid::new_v4().to_string();
            let mut result = Intent {
                schema: SCHEMA,
                contract: CONTRACT.into(),
                operation: id.clone(),
                operator: unsafe { libc::geteuid() },
                cwd: scope.roots().cwd.to_str().unwrap().into(),
                target: scope
                    .roots()
                    .cwd
                    .join("new-target")
                    .to_str()
                    .unwrap()
                    .into(),
                parent_device: 1,
                parent_inode: 2,
                archives: vec![ArchiveIntent {
                    path: scope
                        .roots()
                        .cwd
                        .join("package.tgz")
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
                summary: json!({"schema":1,"contract":CONTRACT,"operation_id":id,"public_plan_digest":"c".repeat(64),"inventory_digest":"d".repeat(64),"artifacts":["a".repeat(64)],"packages":[{"name":"demo","version":"1.0.0","compressed_sha256":"a".repeat(64)}],"files":1,"directories":1,"bytes":5,"threat_db_sequence":1,"signed_build_timestamp":1,"package_code_executed":false,"code_safety":"not_established"}),
                reviewed_sha256: String::new(),
            };
            result.reviewed_sha256 = review_digest(&result).unwrap();
            result
        }
        fn save_intent(scope: &GlobalStateGuard) -> Intent {
            let intent = intent(scope);
            let mut store = OperationStore::open(&intent.operation, true).unwrap();
            store
                .append(RecordKind::Intent, encode(&intent).unwrap())
                .unwrap();
            intent
        }
        fn append_history(intent: &Intent, kind: RecordKind, phase: &str) {
            OperationStore::open(&intent.operation, false)
                .unwrap()
                .append(kind, event(intent, phase).unwrap())
                .unwrap();
        }
        fn continue_action(intent: &Intent, reviewed: &str) -> Action {
            Action::ContinueUndo {
                operation: intent.operation.clone(),
                reviewed: reviewed.into(),
                json: true,
            }
        }

        #[test]
        fn continuation_route_cannot_start_an_intent_or_bypass_its_review() {
            let scope = GlobalStateGuard::new().unwrap();
            let intent = save_intent(&scope);
            let rejected = run(continue_action(&intent, &"0".repeat(64))).unwrap_err();
            assert!(rejected.contains("reviewed commitment"));
            let rejected = run(continue_action(&intent, &intent.reviewed_sha256)).unwrap_err();
            assert!(rejected.contains("unstarted operation"));
            let mut store = OperationStore::open(&intent.operation, false).unwrap();
            for kind in [
                RecordKind::Started,
                RecordKind::ContinueUndoStarted,
                RecordKind::ContinuedUndo,
                RecordKind::Withdrawn,
            ] {
                assert!(store.read(kind).unwrap().is_none());
            }
            assert!(!Path::new(&intent.target).exists());
        }

        #[test]
        fn continuation_status_preserves_distinct_attempt_removed_and_already_empty_history() {
            let scope = GlobalStateGuard::new().unwrap();
            for completed_phase in CONTINUED_UNDO_PHASES {
                let intent = save_intent(&scope);
                append_history(&intent, RecordKind::Started, "started");
                append_history(&intent, RecordKind::UndoStarted, "undo_started");
                append_history(
                    &intent,
                    RecordKind::ContinueUndoStarted,
                    "continue_undo_started",
                );
                let pending = status(&intent.operation).unwrap();
                assert_eq!(pending["phase"], "continue_undo_incomplete_or_running");
                assert_eq!(pending["historical_only"], true);
                append_history(&intent, RecordKind::ContinuedUndo, completed_phase);
                let completed = status(&intent.operation).unwrap();
                assert_eq!(completed["phase"], completed_phase);
                assert_eq!(completed["historical_only"], true);
                assert_eq!(completed["execution_authority"], false);
                assert_eq!(completed["current_target_observation"], "absent");
                assert!(!Path::new(&intent.target).exists());
            }
        }

        #[test]
        fn continuation_history_refuses_orphans_bad_phases_and_cross_operation_records() {
            let scope = GlobalStateGuard::new().unwrap();
            for case in 0..5 {
                let intent = save_intent(&scope);
                if case != 0 {
                    append_history(&intent, RecordKind::Started, "started");
                }
                if case != 1 {
                    append_history(
                        &intent,
                        RecordKind::ContinueUndoStarted,
                        "continue_undo_started",
                    );
                }
                if case != 0 {
                    let mut bytes = event(&intent, CONTINUED_UNDO_PHASES[0]).unwrap();
                    if case == 2 || case == 3 {
                        let mut record: Event = decode(&bytes).unwrap();
                        if case == 2 {
                            record.phase = "published_recovered_verified".into();
                        } else {
                            record.operation = uuid::Uuid::new_v4().to_string();
                        }
                        bytes = encode(&record).unwrap();
                    } else if case == 4 {
                        bytes = b"{incomplete".to_vec();
                    }
                    OperationStore::open(&intent.operation, false)
                        .unwrap()
                        .append(RecordKind::ContinuedUndo, bytes.clone())
                        .unwrap();
                    assert!(status(&intent.operation).is_err());
                    assert!(run(continue_action(&intent, &intent.reviewed_sha256)).is_err());
                    let mut store = OperationStore::open(&intent.operation, false).unwrap();
                    assert_eq!(
                        store.read(RecordKind::ContinuedUndo).unwrap().unwrap(),
                        bytes
                    );
                } else {
                    assert!(status(&intent.operation).is_err());
                    assert!(run(continue_action(&intent, &intent.reviewed_sha256)).is_err());
                }
                assert!(!Path::new(&intent.target).exists());
            }
        }

        #[test]
        fn completed_continuation_cannot_repeat_effects_or_rewrite_its_outcome() {
            let scope = GlobalStateGuard::new().unwrap();
            let intent = save_intent(&scope);
            append_history(&intent, RecordKind::Started, "started");
            append_history(
                &intent,
                RecordKind::ContinueUndoStarted,
                "continue_undo_started",
            );
            append_history(&intent, RecordKind::ContinuedUndo, CONTINUED_UNDO_PHASES[0]);
            let mut store = OperationStore::open(&intent.operation, false).unwrap();
            let before = store.read(RecordKind::ContinuedUndo).unwrap().unwrap();
            drop(store);
            let rejected = run(continue_action(&intent, &intent.reviewed_sha256)).unwrap_err();
            assert!(rejected.contains("already has a recorded outcome"));
            assert!(apply(&intent.operation, &intent.reviewed_sha256).is_err());
            let mut store = OperationStore::open(&intent.operation, false).unwrap();
            assert_eq!(
                store.read(RecordKind::ContinuedUndo).unwrap().unwrap(),
                before
            );
            assert!(!Path::new(&intent.target).exists());
        }
        #[test]
        fn public_review_never_serializes_private_policy_or_native_recovery_material() {
            let scope = GlobalStateGuard::new().unwrap();
            let intent = intent(&scope);
            let public = public_intent(&intent, "reviewed_intent");
            let text = serde_json::to_string(&public).unwrap();
            for private in [
                "private_plan_digest",
                "modified_seconds",
                "parent_inode",
                "policy",
                "bbbbbbbbbbbbbbbb",
            ] {
                assert!(!text.contains(private), "{private}");
            }
            assert_eq!(public["execution_authority"], false);
            assert_eq!(public["package_code_executed"], false);
            assert_eq!(public["current_code_safety"], "not_established");
            assert_eq!(public["ongoing_immutability"], false);
        }
        #[test]
        fn explicit_review_binds_operation_target_archive_order_and_summary() {
            let scope = GlobalStateGuard::new().unwrap();
            let mut intent = intent(&scope);
            let original = intent.reviewed_sha256.clone();
            assert!(check_review(&intent, &original).is_ok());
            intent.target.push_str("-other");
            assert!(validate_intent(&intent, &intent.operation).is_err());
            intent.reviewed_sha256 = review_digest(&intent).unwrap();
            assert!(check_review(&intent, &original).is_err());
            let before = intent.reviewed_sha256.clone();
            intent.archives[0].sha256 = "d".repeat(64);
            assert_ne!(review_digest(&intent).unwrap(), before);
            let before = review_digest(&intent).unwrap();
            intent.summary["public_plan_digest"] = json!("e".repeat(64));
            assert_ne!(review_digest(&intent).unwrap(), before);
        }
        #[test]
        fn duplicate_and_unknown_intent_fields_cannot_supply_restart_authority() {
            let scope = GlobalStateGuard::new().unwrap();
            let intent = intent(&scope);
            let bytes = encode(&intent).unwrap();
            let mut value: Value = serde_json::from_slice(&bytes).unwrap();
            value["execution_authority"] = json!(true);
            assert!(decode::<Intent>(&serde_json::to_vec(&value).unwrap()).is_err());
            let mut text = String::from_utf8(bytes).unwrap();
            text.insert_str(1, "\"schema\":1,");
            assert!(decode::<Intent>(text.as_bytes()).is_err());
        }
        #[test]
        fn forged_summary_authority_or_private_fields_refuse_even_with_recomputed_review() {
            let scope = GlobalStateGuard::new().unwrap();
            let mut intent = intent(&scope);
            intent.summary["package_code_executed"] = json!(true);
            intent.reviewed_sha256 = review_digest(&intent).unwrap();
            assert!(validate_intent(&intent, &intent.operation).is_err());
            intent.summary["package_code_executed"] = json!(false);
            intent.summary["private_plan_digest"] = json!("never-public");
            intent.reviewed_sha256 = review_digest(&intent).unwrap();
            assert!(validate_intent(&intent, &intent.operation).is_err());
        }
        #[test]
        fn unstarted_withdrawal_survives_lost_artifact_and_changed_policy() {
            let mut scope = GlobalStateGuard::new().unwrap();
            let intent = intent(&scope);
            assert!(!Path::new(&intent.archives[0].path).exists());
            let mut store = OperationStore::open(&intent.operation, true).unwrap();
            store
                .append(RecordKind::Intent, encode(&intent).unwrap())
                .unwrap();
            drop(store);
            scope.set_env("TIRITH_SERVER_URL", "https://127.0.0.1:1");
            scope.set_env("TIRITH_API_KEY", "withdrawal-does-not-fetch-policy");
            let first = undo(&intent.operation, &intent.reviewed_sha256).unwrap();
            assert_eq!(first["phase"], "withdrawn");
            assert_eq!(
                undo(&intent.operation, &intent.reviewed_sha256).unwrap(),
                first
            );
            assert!(apply(&intent.operation, &intent.reviewed_sha256).is_err());
            assert!(!Path::new(&intent.target).exists());
        }

        #[test]
        fn unstarted_withdrawal_cannot_hide_or_erase_incomplete_start_evidence() {
            let scope = GlobalStateGuard::new().unwrap();
            let intent = intent(&scope);
            let mut store = OperationStore::open(&intent.operation, true).unwrap();
            store
                .append(RecordKind::Intent, encode(&intent).unwrap())
                .unwrap();
            store
                .append(RecordKind::Started, b"{incomplete".to_vec())
                .unwrap();
            drop(store);
            assert!(undo(&intent.operation, &intent.reviewed_sha256).is_err());
            let mut store = OperationStore::open(&intent.operation, false).unwrap();
            assert!(store.read(RecordKind::Withdrawn).unwrap().is_none());
            assert_eq!(
                store.read(RecordKind::Started).unwrap().unwrap(),
                b"{incomplete"
            );
        }

        #[test]
        fn malformed_or_cross_operation_start_record_refuses_and_is_preserved() {
            let scope = GlobalStateGuard::new().unwrap();
            let intent = intent(&scope);
            let mut store = OperationStore::open(&intent.operation, true).unwrap();
            let mut wrong = Event {
                schema: SCHEMA,
                operation: uuid::Uuid::new_v4().to_string(),
                reviewed_sha256: intent.reviewed_sha256.clone(),
                phase: "started".into(),
                at: chrono::Utc::now().to_rfc3339(),
            };
            store
                .append(RecordKind::Started, encode(&wrong).unwrap())
                .unwrap();
            assert!(read_event(&mut store, RecordKind::Started, &intent, &["started"]).is_err());
            wrong.operation = intent.operation.clone();
            assert!(store
                .append(RecordKind::Started, encode(&wrong).unwrap())
                .is_err());
            assert!(store.read(RecordKind::Started).unwrap().is_some());
        }
    }
}
