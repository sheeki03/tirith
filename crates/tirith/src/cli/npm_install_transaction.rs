//! One closed npm transaction. A saved intent never enters this interface.
//! Callers supply freshly retained evidence and a one-use task permit.

use serde::Serialize;
use serde_json::{json, Value};
use tirith_core::{
    artifact::{
        npm_install::{
            tools::QualifiedNpmToolClosure, NpmInstallPlan, PreparedNpmExecution,
            VerifiedNpmArtifact,
        },
        quarantine::QuarantineStore,
    },
    capsule::CapsuleSpec,
    policy_snapshot::EffectivePolicySnapshot,
    receipt::{ArtifactScanReceipt, CapsuleReceipt},
    task_boundary::{PackageInstallPreparationBoundary, TaskBoundaryPermit},
};

use super::{
    capsule::{self, BoundOutputPresentation, CapsuleExecutionError},
    npm_install_recovery::{preflight_milestone_signing, NpmRecoveryStore},
    package_checkpoint::{EnvironmentCheckpoint, InstallTargetBinding},
};

#[derive(Clone, Copy, Debug, Serialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum ExecutionState {
    NotStarted,
    MayHaveStarted,
    Started,
    Completed,
}

#[derive(Debug, Serialize)]
pub(super) struct TransactionFailure {
    pub phase: &'static str,
    pub reason: String,
    pub target_publication_crossed: bool,
    pub execution_state: ExecutionState,
    pub cleanup_confirmed: bool,
}

impl TransactionFailure {
    fn before(phase: &'static str, reason: impl Into<String>) -> Self {
        Self {
            phase,
            reason: reason.into(),
            target_publication_crossed: false,
            execution_state: ExecutionState::NotStarted,
            cleanup_confirmed: true,
        }
    }
}

/// A durable Started record must already exclude replay of this operation.
/// Every effect below also rechecks fresh retained policy/task/source authority.
#[allow(clippy::too_many_arguments)]
pub(super) fn execute(
    plan: &NpmInstallPlan,
    artifacts: &[VerifiedNpmArtifact],
    policy: &EffectivePolicySnapshot,
    binding: &InstallTargetBinding,
    permit: TaskBoundaryPermit<PackageInstallPreparationBoundary>,
    json_output: bool,
    reviewed_sha256: &str,
    validate_intent: &mut dyn FnMut() -> Result<(), String>,
) -> Result<Value, TransactionFailure> {
    // The caller must also check platform qualification before creating intent
    // state. Keep this guard at the transaction seam for direct callers.
    plan.execution_qualification().map_err(|_| {
        TransactionFailure::before(
            "qualification",
            "npm execution is not qualified on this host",
        )
    })?;
    preflight_milestone_signing()
        .map_err(|reason| TransactionFailure::before("signed_receipt_preflight", reason))?;
    validate_intent()
        .map_err(|reason| TransactionFailure::before("intent_revalidation", reason))?;
    let mut recovery = NpmRecoveryStore::open(&plan.summary().operation_id, true)
        .map_err(|reason| TransactionFailure::before("recovery_store", reason))?;
    let tools = QualifiedNpmToolClosure::capture().map_err(|error| {
        TransactionFailure::before("tool_closure", format!("tool closure refused: {error:?}"))
    })?;
    let store = QuarantineStore::open().map_err(|_| {
        TransactionFailure::before("quarantine", "cannot retain private quarantine state")
    })?;
    validate_intent()
        .map_err(|reason| TransactionFailure::before("intent_revalidation", reason))?;
    let staged = plan
        .stage(artifacts, policy, &store, permit)
        .map_err(|error| {
            TransactionFailure::before("staging", format!("artifact staging refused: {error:?}"))
        })?;
    let mut prepared = PreparedNpmExecution::capture(plan, artifacts, policy, staged, tools)
        .map_err(|error| {
            TransactionFailure::before("preparation", format!("npm preparation refused: {error:?}"))
        })?;
    let authorization = prepared.checkpoint_authorization().map_err(|error| {
        TransactionFailure::before("authorization", format!("authorization refused: {error:?}"))
    })?;
    let mut checkpoint = EnvironmentCheckpoint::begin_npm_authorized(binding, authorization)
        .map_err(|_| TransactionFailure {
            phase: "checkpoint",
            reason:
                "private checkpoint initialization failed; any retained objects require recovery"
                    .into(),
            target_publication_crossed: false,
            execution_state: ExecutionState::NotStarted,
            // The constructor can preserve partial initialization when its
            // identity-bound cleanup fails. Absence of a returned handle is
            // not proof that those objects were removed.
            cleanup_confirmed: false,
        })?;
    let launch = match checkpoint.take_authorized_launch() {
        Ok(launch) => launch,
        Err(_) => {
            return Err(fail_checkpoint(
                &mut checkpoint,
                "launch_capability",
                "cannot retain the exact one-use launch capability".into(),
                ExecutionState::NotStarted,
                true,
            ));
        }
    };
    let presentation = if json_output {
        BoundOutputPresentation::Suppress
    } else {
        BoundOutputPresentation::ForwardSanitized
    };
    let completed = match capsule::run_to_completion_npm_local_leaf(
        &mut prepared,
        launch,
        presentation,
        validate_intent,
    ) {
        Ok(completed) => completed,
        Err(error) => {
            let (reason, state, clean) = match error {
                CapsuleExecutionError::RefusedBeforeExec(refused) => {
                    (refused.reason, ExecutionState::NotStarted, true)
                }
                CapsuleExecutionError::ExecutedTerminated { termination, .. } => (
                    termination.reason,
                    // The native adapter also uses this variant when cleanup
                    // failed before it could prove whether ACK reached Node.
                    ExecutionState::MayHaveStarted,
                    termination.cleanup_confirmed,
                ),
            };
            return Err(fail_checkpoint(
                &mut checkpoint,
                "native_launch",
                reason,
                state,
                clean,
            ));
        }
    };
    let outcome = completed.outcome();
    if let Some(termination) = &outcome.termination {
        return Err(fail_checkpoint(
            &mut checkpoint,
            "supervision",
            termination.reason.clone(),
            ExecutionState::Started,
            termination.cleanup_confirmed,
        ));
    }
    if outcome.ephemeral_home_cleanup_confirmed != Some(true) {
        return Err(fail_checkpoint(
            &mut checkpoint,
            "native_cleanup",
            "native cleanup was not completely observed; private objects preserved".into(),
            ExecutionState::Started,
            false,
        ));
    }
    if outcome.exit_code != 0
        || outcome.degraded
        || outcome
            .coverage
            .is_degraded_against(&CapsuleSpec::locked_down().required_coverage())
        || !outcome.coverage.egress_claim_is_coherent()
    {
        return Err(fail_checkpoint(
            &mut checkpoint,
            "contained_outcome",
            "npm did not finish successfully with every required containment capability".into(),
            ExecutionState::Completed,
            true,
        ));
    }

    let finish = (|| -> Result<Value, (&'static str, String)> {
        validate_intent().map_err(|reason| ("intent_revalidation", reason))?;
        let verified = prepared.verify_output().map_err(|error| {
            (
                "output_verification",
                format!("installed output refused: {error:?}"),
            )
        })?;
        // Capture this opaque witness while its private pathname still exists.
        let evidence = verified.receipt_evidence().map_err(|error| {
            (
                "receipt_evidence",
                format!("receipt evidence refused: {error:?}"),
            )
        })?;
        prepared
            .revalidate_for_publication(&verified)
            .map_err(|error| {
                (
                    "private_authority",
                    format!("private authority changed: {error:?}"),
                )
            })?;
        let receipt = ArtifactScanReceipt::new_npm(
            policy.policy.enforcement_projection_hash(),
            plan.summary().threat_db_sequence,
            CapsuleReceipt {
                backend_id: outcome.backend_id.into(),
                coverage: outcome.coverage.clone(),
            },
            evidence,
            plan.verdict_summary().clone(),
        )
        .map_err(|_| {
            (
                "private_receipt",
                "cannot construct the exact npm receipt".into(),
            )
        })?;
        let private_id = receipt.receipt_id.clone();
        validate_intent().map_err(|reason| ("intent_revalidation", reason))?;
        let recorded = receipt.record_private_signed().map_err(|_| {
            (
                "private_receipt",
                "cannot durably sign the private npm receipt".into(),
            )
        })?;
        let private_milestone = recovery
            .record_private(reviewed_sha256, &completed, &prepared, &verified, &recorded)
            .map_err(|reason| ("private_completion_milestone", reason))?;
        // Prepare and bind the opaque committed receipt before publication.
        let committed = recorded.prepare_committed().map_err(|_| {
            (
                "receipt_binding",
                "cannot derive the linked committed receipt".into(),
            )
        })?;
        let committed_id = committed.receipt_id().to_owned();
        checkpoint
            .bind_npm_committed_receipt(&committed)
            .map_err(|_| {
                (
                    "receipt_binding",
                    "checkpoint refused the exact receipt binding".into(),
                )
            })?;
        prepared
            .revalidate_for_publication(&verified)
            .map_err(|error| {
                (
                    "publication_authority",
                    format!("publication authority changed: {error:?}"),
                )
            })?;
        validate_intent().map_err(|reason| ("intent_revalidation", reason))?;
        checkpoint.publish_verified().map_err(|_| {
            (
                "publication",
                "no-replace publication did not complete; inspect recovery state".into(),
            )
        })?;
        prepared.revalidate_published(&verified).map_err(|error| {
            (
                "published_verification",
                format!("published authority or tree changed: {error:?}"),
            )
        })?;
        validate_intent().map_err(|reason| ("intent_revalidation", reason))?;
        let proof = committed.record_signed().map_err(|_| {
            (
                "committed_receipt",
                "cannot durably sign the committed npm receipt".into(),
            )
        })?;
        prepared.revalidate_published(&verified).map_err(|error| {
            (
                "commit_authority",
                format!("commit authority or tree changed: {error:?}"),
            )
        })?;
        validate_intent().map_err(|reason| ("intent_revalidation", reason))?;
        recovery
            .record_committed(&private_milestone, &prepared, &verified, &proof)
            .map_err(|reason| ("committed_completion_milestone", reason))?;
        checkpoint.confirm_committed(proof).map_err(|_| {
            (
                "commit_confirmation",
                "committed receipt exists but checkpoint confirmation is incomplete".into(),
            )
        })?;
        prepared.record_published(&verified).map_err(|error| {
            (
                "preparation_journal",
                format!("published target retained; preparation journal incomplete: {error:?}"),
            )
        })?;
        Ok(json!({
            "schema":1,"contract":"LocalLeafNoScriptsV1",
            "operation":plan.summary().operation_id,"phase":"published_verified",
            "summary":plan.summary(),"execution_state":"completed",
            "lifecycle_scripts_executed":false,"code_safety":"not_established",
            "ongoing_immutability":false,"target_publication_crossed":true,
            "cleanup_confirmed":true,"private_receipt_id":private_id,
            "committed_receipt_id":committed_id,"backend_id":outcome.backend_id,
            "coverage":outcome.coverage,
        }))
    })();
    finish.map_err(|(phase, reason)| {
        fail_checkpoint(
            &mut checkpoint,
            phase,
            reason,
            ExecutionState::Completed,
            true,
        )
    })
}

fn fail_checkpoint(
    checkpoint: &mut EnvironmentCheckpoint,
    phase: &'static str,
    mut reason: String,
    execution_state: ExecutionState,
    process_cleanup_confirmed: bool,
) -> TransactionFailure {
    let crossed = checkpoint.publication_crossed();
    let cleanup_confirmed = if !process_cleanup_confirmed {
        checkpoint.preserve_for_recovery();
        false
    } else if crossed {
        // Published objects may have been used or changed by the operator.
        // Never claim rollback or recursively delete that public environment.
        true
    } else {
        let clean = checkpoint.rollback().is_ok();
        if !clean {
            checkpoint.preserve_for_recovery();
            reason.push_str("; private rollback incomplete, remaining objects preserved");
        }
        clean
    };
    TransactionFailure {
        phase,
        reason,
        target_publication_crossed: crossed,
        execution_state,
        cleanup_confirmed,
    }
}
