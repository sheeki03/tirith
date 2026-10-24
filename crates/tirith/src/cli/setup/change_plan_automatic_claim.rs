//! One private claim per explicit completed setup. This module starts no child,
//! opens no transport, and is not reachable from CLI dispatch. Durable state is
//! correlation/replay coordination, never a replacement for a live file lease,
//! authenticated shell context, or core execution proof.

use super::*;
use crate::cli::control::identity::{BinaryIdentity, DirectoryIdentity};
use crate::cli::setup::shell_service::ShellKind;
use setup_binding::{CompletedSetupLease, SetupCompletionEvidence};
use tirith_core::execution_state::{
    self, AuthenticatedShellContext, AutomaticShellVerification, AutomaticVerificationStage,
    ShellVerificationObservation,
};
use tirith_core::policy_snapshot::ResolutionMode;

use super::activation_history::{
    canonical_id, fingerprint, ClaimPhase, ClaimRecord, StoredActivationOutcome,
    TerminalObservation, MAX_CLAIM_BYTES,
};

const MAX_DISCOVERY_ENTRIES: usize = 256;
const MAX_DISCOVERY_BYTES: usize = 16 * 1024 * 1024;
const DISCOVERY_READ_BUDGET: Duration = Duration::from_millis(250);

impl MutationService {
    /// A complete bounded inventory, not recent_statuses and not recency order.
    /// Potentially eligible but drifted records are not silently skipped in
    /// favor of another intent; the selected lease performs full validation.
    pub(super) fn unique_activation_candidate(&self) -> Result<Option<Journal>, String> {
        let started = Instant::now();
        let (names, truncated) =
            fs_helpers::private_directory_names(&self.root, &self.scope, MAX_DISCOVERY_ENTRIES)?;
        if truncated {
            return Err("automatic activation journal inventory is incomplete".into());
        }
        let mut total_bytes = 0usize;
        let mut selected = None;
        for name in names {
            if started.elapsed() >= DISCOVERY_READ_BUDGET {
                return Err("automatic activation discovery exceeded its read budget".into());
            }
            let name = name
                .to_str()
                .ok_or("automatic activation journal inventory has an invalid name")?;
            let Some(id) = name.strip_suffix(".json") else {
                // Execution locks and contained transaction artifacts are not
                // journals. They still count against the directory entry cap.
                continue;
            };
            if !canonical_id(id) {
                return Err("automatic activation journal inventory has a noncanonical ID".into());
            }
            let remaining = MAX_DISCOVERY_BYTES
                .checked_sub(total_bytes)
                .filter(|remaining| *remaining > 0)
                .ok_or("automatic activation discovery exceeds its byte limit")?;
            let snapshot = fs_helpers::read_snapshot_scoped_capped(
                &self.path(id)?,
                &self.scope,
                remaining.min(MAX_SETUP_FILE_BYTES),
            )?;
            snapshot.require_private()?;
            let bytes = snapshot
                .bytes
                .as_deref()
                .ok_or("automatic activation journal disappeared during discovery")?;
            total_bytes += bytes.len();
            let record: Journal = serde_json::from_slice(bytes).map_err(|_| {
                "automatic activation journal inventory contains a malformed record"
            })?;
            if record.schema_version != SCHEMA
                || record.operation_id != id
                || record.operator != self.operator
            {
                return Err("automatic activation journal identity is ambiguous".into());
            }
            if record.kind != OperationKind::RecommendedSetup
                || record.client_version != env!("CARGO_PKG_VERSION")
                || !matches!(
                    record.state,
                    JobState::Completed | JobState::CompletedWithRecovery
                )
                || record.setup_verification.is_none()
                || record.setup_verification_cancelled
                || record.caller_intent_digest.is_none()
                || record.active_action == Some(JobAction::Undo)
                || record.undo_external_authorization.is_some()
                || record
                    .shell_precondition
                    .as_ref()
                    .map(|shell| shell.selected_shell())
                    != Some(ShellKind::Zsh)
                || !matches!(
                    record.setup_completion,
                    Some(SetupCompletionEvidence::Available { .. })
                )
            {
                continue;
            }
            if total_bytes > MAX_DISCOVERY_BYTES - MAX_CLAIM_BYTES {
                return Err("automatic activation discovery exceeds its byte limit".into());
            }
            let claim = self.read_claim(id)?;
            total_bytes = total_bytes
                .checked_add(claim.as_ref().map_or(0, |_| MAX_CLAIM_BYTES))
                .filter(|total| *total <= MAX_DISCOVERY_BYTES)
                .ok_or("automatic activation discovery exceeds its byte limit")?;
            if claim
                .as_ref()
                .is_some_and(|claim| claim.phase != ClaimPhase::Pending)
            {
                // Running survives crashes as an at-most-once tombstone. Ended
                // says only that an attempt was spent; neither means verified.
                continue;
            }
            if selected.is_some() {
                return Err("multiple completed setup intents require explicit resolution".into());
            }
            selected = Some(record);
        }
        if started.elapsed() >= DISCOVERY_READ_BUDGET {
            return Err("automatic activation discovery exceeded its read budget".into());
        }
        Ok(selected)
    }

    fn require_unique_operation(&self, id: &str) -> Result<(), String> {
        match self.unique_activation_candidate()? {
            Some(record) if record.operation_id == id => Ok(()),
            _ => Err("automatic activation's unique completed intent changed".into()),
        }
    }

    /// Acquire in the actual broker process/thread. The caller must already
    /// have authenticated the actual native shell; no PID or DTO substitutes.
    /// Repeated pending discovery can reuse an attempt after the earlier owner
    /// dropped its lease. A concurrently held lease refuses even the same shell.
    #[allow(dead_code)] // No CLI, transport, scheduler, or main wiring in this patch.
    pub(crate) fn claim_automatic_activation<'shell>(
        &self,
        shell: &'shell AuthenticatedShellContext,
        loaded: &str,
    ) -> Result<Option<PendingActivationClaim<'shell>>, String> {
        shell.revalidate()?;
        if !fingerprint(loaded) {
            return Err("automatic activation requires a bounded loaded-state fingerprint".into());
        }
        let Some(candidate) = self.unique_activation_candidate()? else {
            return Ok(None);
        };
        let policy = EffectivePolicySnapshot::resolve(
            candidate.resolution_cwd.as_deref(),
            ResolutionMode::Runtime,
        );
        let lease = self
            .completed_setup_lease(&candidate.operation_id, policy)?
            .ok_or("automatic activation requires explicit setup verification intent")?;
        if lease.selected_shell() != ShellKind::Zsh {
            return Err("automatic activation requires the selected Zsh setup".into());
        }
        let requested = ClaimRecord {
            schema_version: activation_history::CLAIM_SCHEMA,
            operation_id: lease.operation_id().into(),
            attempt_id: uuid::Uuid::new_v4().to_string(),
            setup_binding: lease.automatic_claim_binding_for_shell(shell)?,
            shell_binding: shell.automatic_claim_binding(lease.operation_id())?,
            loaded: loaded.into(),
            phase: ClaimPhase::Pending,
        };
        let state_directory = DirectoryIdentity::capture_trusted(&self.scope)?;
        let path = self.claim_path(lease.operation_id())?;
        let outcome = super::super::fs_transaction::update_private_activation_claim(
            &path,
            &self.scope,
            |snapshot| pending_update(snapshot, &requested),
            || {
                state_directory.revalidate()?;
                lease.require_fresh_shell(shell)?;
                self.require_unique_operation(lease.operation_id())
            },
        )?;
        require_clean(outcome)?;
        let record = self
            .read_claim(lease.operation_id())?
            .ok_or("published automatic claim is unavailable")?;
        if !record.reusable_by(&requested) {
            return Err("published automatic claim changed".into());
        }
        let owner = ClaimOwner {
            service: self.clone(),
            lease,
            shell,
            state_directory,
            claim_directory: DirectoryIdentity::capture(&self.claim_directory())?,
            file: BinaryIdentity::capture_input_capped(&path, MAX_CLAIM_BYTES as u64)?,
            record,
        };
        owner.revalidate()?;
        Ok(Some(PendingActivationClaim { owner }))
    }
}

fn require_clean(outcome: TransactionOutcome) -> Result<(), String> {
    if matches!(
        outcome,
        TransactionOutcome::Written | TransactionOutcome::Unchanged
    ) {
        Ok(())
    } else {
        Err("automatic claim publication was not cleanly durable; retain it without retry".into())
    }
}

fn pending_update(
    snapshot: &super::super::fs_transaction::FileSnapshot,
    requested: &ClaimRecord,
) -> Result<FileUpdate, String> {
    snapshot.require_private()?;
    if requested.phase != ClaimPhase::Pending {
        return Err("only a pending automatic claim can be created or reused".into());
    }
    match snapshot.bytes() {
        Some(bytes)
            if ClaimRecord::decode(bytes, &requested.operation_id)?.reusable_by(requested) =>
        {
            Ok(FileUpdate::unchanged())
        }
        Some(_) => Err("completed setup was already claimed by another shell or spent".into()),
        None => Ok(FileUpdate::write_text(requested.encoded()?, 0o600).with_exact_mode()),
    }
}

struct ClaimOwner<'shell> {
    service: MutationService,
    lease: CompletedSetupLease,
    shell: &'shell AuthenticatedShellContext,
    state_directory: DirectoryIdentity,
    claim_directory: DirectoryIdentity,
    file: BinaryIdentity,
    record: ClaimRecord,
}

impl ClaimOwner<'_> {
    fn record_terminal(&self, terminal: TerminalObservation) -> Result<(), String> {
        self.revalidate()?;
        let journal = self.service.read(&self.record.operation_id)?;
        let outcome =
            StoredActivationOutcome::new(&self.service, &journal, self.record.clone(), terminal)?;
        self.service
            .publish_activation_outcome(&outcome, || self.revalidate())?;
        self.revalidate()
    }

    fn revalidate(&self) -> Result<(), String> {
        self.state_directory.revalidate()?;
        self.claim_directory.revalidate()?;
        self.file.revalidate()?;
        if self.lease.automatic_claim_binding_for_shell(self.shell)? != self.record.setup_binding
            || self
                .shell
                .automatic_claim_binding(&self.record.operation_id)?
                != self.record.shell_binding
            || self.service.read_claim(&self.record.operation_id)?.as_ref() != Some(&self.record)
        {
            return Err("automatic claim lost its live setup/shell binding".into());
        }
        self.file.revalidate()
    }

    fn advance(&mut self, phase: ClaimPhase) -> Result<(), String> {
        if !matches!(
            (self.record.phase, phase),
            (ClaimPhase::Pending, ClaimPhase::Running) | (ClaimPhase::Running, ClaimPhase::Ended)
        ) {
            return Err("automatic claim transition cannot be retried".into());
        }
        self.revalidate()?;
        let mut next = self.record.clone();
        next.phase = phase;
        let path = self.service.claim_path(&self.record.operation_id)?;
        let outcome = super::super::fs_transaction::update_private_activation_claim(
            &path,
            &self.service.scope,
            |snapshot| exact_transition(snapshot, &self.record, &next),
            || {
                self.revalidate()?;
                if phase == ClaimPhase::Running {
                    self.service
                        .require_unique_operation(&self.record.operation_id)?;
                }
                Ok(())
            },
        )?;
        require_clean(outcome)?;
        // Keep the previous generation held until its durable successor has
        // been captured. No journal bytes are changed during either operation.
        let successor = BinaryIdentity::capture_input_capped(&path, MAX_CLAIM_BYTES as u64)?;
        if self.service.read_claim(&self.record.operation_id)?.as_ref() != Some(&next) {
            return Err("automatic claim successor changed".into());
        }
        self.file = successor;
        self.record = next;
        self.revalidate()
    }
}

fn exact_transition(
    snapshot: &super::super::fs_transaction::FileSnapshot,
    expected: &ClaimRecord,
    next: &ClaimRecord,
) -> Result<FileUpdate, String> {
    let mut immutable = expected.clone();
    immutable.phase = next.phase;
    if immutable != *next
        || !matches!(
            (expected.phase, next.phase),
            (ClaimPhase::Pending, ClaimPhase::Running) | (ClaimPhase::Running, ClaimPhase::Ended)
        )
    {
        return Err("automatic claim transition cannot reset or change its binding".into());
    }
    snapshot.require_private()?;
    let existing = snapshot.bytes().ok_or("automatic claim disappeared")?;
    if ClaimRecord::decode(existing, &expected.operation_id)? != *expected {
        return Err("automatic claim generation was already changed".into());
    }
    Ok(FileUpdate::write_text(next.encoded()?, 0o600).with_exact_mode())
}

/// Live non-Clone/non-Serialize owner. Disk bytes cannot construct this value.
pub(crate) struct PendingActivationClaim<'shell> {
    owner: ClaimOwner<'shell>,
}

impl<'shell> PendingActivationClaim<'shell> {
    pub(crate) fn operation_id(&self) -> &str {
        &self.owner.record.operation_id
    }

    pub(crate) fn attempt_id(&self) -> &str {
        &self.owner.record.attempt_id
    }

    pub(crate) fn cancel(mut self) -> Result<(), String> {
        self.owner.advance(ClaimPhase::Running)?;
        self.owner.advance(ClaimPhase::Ended)?;
        self.owner.record_terminal(TerminalObservation::Cancelled)
    }

    /// Actual-terminal inputs are separate from the saved setup resolution.
    /// Persist Running before core start: any error or lost result spends this
    /// operation. Callers never reacquire a Running record or reset it Pending.
    pub(crate) fn start(
        mut self,
        actual_config_paths: &[PathBuf],
        actual_loaded: &str,
    ) -> Result<RunningActivationClaim<'shell>, String> {
        self.owner.advance(ClaimPhase::Running)?;
        let started: Result<AutomaticShellVerification<'shell>, String> = (|| {
            if actual_loaded != self.owner.record.loaded {
                return Err("automatic loaded state changed before start".into());
            }
            let verification = execution_state::start_automatic_shell_verification(
                self.owner.shell,
                &self.owner.record.operation_id,
                &self.owner.record.attempt_id,
                actual_config_paths,
                actual_loaded,
            )?;
            self.owner.revalidate()?;
            Ok(verification)
        })();
        let verification = match started {
            Ok(verification) => verification,
            Err(error) => {
                self.owner.advance(ClaimPhase::Ended)?;
                self.owner.record_terminal(TerminalObservation::Refused)?;
                return Err(error);
            }
        };
        Ok(RunningActivationClaim {
            owner: self.owner,
            verification: Some(verification),
        })
    }
}

/// Drop/crash leaves Running durable. It cannot grant another attempt. The
/// original completion lease and native shell context remain held throughout.
pub(crate) struct RunningActivationClaim<'shell> {
    owner: ClaimOwner<'shell>,
    verification: Option<AutomaticShellVerification<'shell>>,
}

impl<'shell> RunningActivationClaim<'shell> {
    pub(crate) fn operation_id(&self) -> &str {
        &self.owner.record.operation_id
    }

    pub(crate) fn attempt_id(&self) -> &str {
        &self.owner.record.attempt_id
    }

    pub(crate) fn issue_next(&mut self) -> Result<AutomaticVerificationStage, String> {
        self.owner.revalidate()?;
        let stage = self
            .verification
            .as_mut()
            .ok_or("automatic owner was consumed")?
            .issue_next()?;
        self.owner.revalidate()?;
        Ok(stage)
    }

    pub(crate) fn finish_restored(
        mut self,
        actual_loaded: &str,
    ) -> Result<FinishedActivationClaim<'shell>, String> {
        let observed: Result<ShellVerificationObservation, String> = (|| {
            self.owner.revalidate()?;
            let report = self
                .verification
                .take()
                .ok_or("automatic owner was consumed")?
                .finish_restored(actual_loaded)?;
            self.owner.revalidate()?;
            Ok(report)
        })();
        // Failure to record Ended leaves the stronger no-retry Running state.
        self.owner.advance(ClaimPhase::Ended)?;
        // Publication failure leaves Ended spent and must not yield Complete.
        // The returned lease still survives the terminal acknowledgement; this
        // stored observation does not assert successful transport delivery.
        match observed {
            Ok(report) => self.owner.record_terminal(TerminalObservation::from_core(
                report,
                &self.owner.record.attempt_id,
            )?)?,
            Err(error) => {
                self.owner.record_terminal(TerminalObservation::Refused)?;
                return Err(error);
            }
        }
        Ok(FinishedActivationClaim { owner: self.owner })
    }

    pub(crate) fn abort(mut self) -> Result<(), String> {
        self.owner.advance(ClaimPhase::Ended)?;
        self.owner.record_terminal(TerminalObservation::Cancelled)
    }
}

/// Hold completed setup inputs and its operation lock through the terminal
/// transport handshake. This owner cannot finalize again, issue a stage, or
/// grant protection evidence. Losing delivery never resets the spent claim.
pub(crate) struct FinishedActivationClaim<'shell> {
    owner: ClaimOwner<'shell>,
}

impl FinishedActivationClaim<'_> {
    pub(crate) fn revalidate(&self) -> Result<(), String> {
        if self.owner.record.phase != ClaimPhase::Ended {
            return Err("automatic completion claim is not terminal".into());
        }
        self.owner.revalidate()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    const OPERATION: &str = "12345678-9abc-4def-8123-456789abcdef";
    const ATTEMPT: &str = "22345678-9abc-4def-8123-456789abcdef";

    fn record() -> ClaimRecord {
        ClaimRecord {
            schema_version: activation_history::CLAIM_SCHEMA,
            operation_id: OPERATION.into(),
            attempt_id: ATTEMPT.into(),
            setup_binding: "a".repeat(64),
            shell_binding: "b".repeat(64),
            loaded: "c".repeat(64),
            phase: ClaimPhase::Pending,
        }
    }

    fn publish(scope: &Path, request: &ClaimRecord) -> Result<TransactionOutcome, String> {
        let path = scope
            .join("claims")
            .join(format!("{}.json", request.operation_id));
        super::super::super::fs_transaction::update_private_activation_claim(
            &path,
            scope,
            |snapshot| pending_update(snapshot, request),
            || Ok(()),
        )
    }

    fn transition_file(
        scope: &Path,
        previous: &ClaimRecord,
        next: &ClaimRecord,
    ) -> Result<TransactionOutcome, String> {
        let path = scope
            .join("claims")
            .join(format!("{}.json", previous.operation_id));
        super::super::super::fs_transaction::update_private_activation_claim(
            &path,
            scope,
            |snapshot| exact_transition(snapshot, previous, next),
            || Ok(()),
        )
    }

    #[test]
    fn pending_reuse_preserves_original_attempt_and_full_binding() {
        let existing = record();
        let mut request = existing.clone();
        request.attempt_id = uuid::Uuid::new_v4().to_string();
        assert!(existing.reusable_by(&request));
        for field in ["operation", "setup", "shell", "loaded"] {
            let mut changed = request.clone();
            match field {
                "operation" => changed.operation_id = uuid::Uuid::new_v4().to_string(),
                "setup" => changed.setup_binding = "d".repeat(64),
                "shell" => changed.shell_binding = "d".repeat(64),
                _ => changed.loaded = "d".repeat(64),
            }
            assert!(!existing.reusable_by(&changed), "{field}");
        }
        for phase in [ClaimPhase::Running, ClaimPhase::Ended] {
            let mut spent = existing.clone();
            spent.phase = phase;
            assert!(!spent.reusable_by(&request));
        }
    }

    #[test]
    fn claim_decoder_refuses_unknown_fields_versions_ids_and_states() {
        let value = serde_json::to_value(record()).unwrap();
        for (field, replacement) in [
            ("schema_version", serde_json::json!(2)),
            (
                "operation_id",
                serde_json::json!("00000000-0000-0000-0000-000000000000"),
            ),
            (
                "attempt_id",
                serde_json::json!("22345678-9ABC-4DEF-8123-456789ABCDEF"),
            ),
            ("phase", serde_json::json!("retry")),
            ("shell_binding", serde_json::json!("b".repeat(63))),
            ("setup_binding", serde_json::json!("A".repeat(64))),
            ("loaded", serde_json::json!("c".repeat(65))),
            ("shell_pid", serde_json::json!(42)),
        ] {
            let mut invalid = value.clone();
            invalid[field] = replacement;
            assert!(
                ClaimRecord::decode(&serde_json::to_vec(&invalid).unwrap(), OPERATION).is_err(),
                "{field}"
            );
        }
        assert!(ClaimRecord::decode(&vec![b' '; MAX_CLAIM_BYTES + 1], OPERATION).is_err());
        assert!(ClaimRecord::decode(record().encoded().unwrap().as_bytes(), ATTEMPT).is_err());
    }

    #[test]
    fn durable_repeated_pending_discovery_reuses_identical_original_generation() {
        let _guard = crate::cli::test_harness::ENV_LOCK.lock().unwrap();
        let temporary = tempfile::tempdir().unwrap();
        let scope = temporary.path();
        let original = record();
        assert_eq!(
            publish(scope, &original).unwrap(),
            TransactionOutcome::Written
        );
        let path = scope.join("claims").join(format!("{OPERATION}.json"));
        let held = BinaryIdentity::capture_input(&path).unwrap();
        let bytes = std::fs::read(&path).unwrap();
        let mut repeat = original.clone();
        repeat.attempt_id = uuid::Uuid::new_v4().to_string();
        assert_eq!(
            publish(scope, &repeat).unwrap(),
            TransactionOutcome::Unchanged
        );
        held.revalidate().unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), bytes);
        assert_eq!(
            ClaimRecord::decode(&bytes, OPERATION).unwrap().attempt_id,
            ATTEMPT
        );
    }

    #[test]
    fn competing_process_contexts_have_only_one_durable_winner() {
        let _guard = crate::cli::test_harness::ENV_LOCK.lock().unwrap();
        // Threads exercise the cross-process filesystem rendezvous with no
        // shared Rust mutex. No authenticated context is fabricated by this
        // store fixture; full native broker authorization remains separate.
        let temporary = tempfile::tempdir().unwrap();
        let barrier = std::sync::Arc::new(std::sync::Barrier::new(2));
        let mut tasks = Vec::new();
        for letter in ['d', 'e'] {
            let barrier = barrier.clone();
            let scope = temporary.path().to_path_buf();
            let mut competing = record();
            competing.shell_binding = letter.to_string().repeat(64);
            tasks.push(std::thread::spawn(move || {
                barrier.wait();
                publish(&scope, &competing).is_ok()
            }));
        }
        let winners = tasks
            .into_iter()
            .map(|task| usize::from(task.join().unwrap()))
            .sum::<usize>();
        assert_eq!(winners, 1);
        let bytes = std::fs::read(
            temporary
                .path()
                .join("claims")
                .join(format!("{OPERATION}.json")),
        )
        .unwrap();
        let winner = ClaimRecord::decode(&bytes, OPERATION).unwrap();
        assert!(winner.shell_binding == "d".repeat(64) || winner.shell_binding == "e".repeat(64));
    }

    #[test]
    fn running_crash_tombstone_and_ended_record_never_reset_to_pending() {
        let _guard = crate::cli::test_harness::ENV_LOCK.lock().unwrap();
        let temporary = tempfile::tempdir().unwrap();
        let scope = temporary.path();
        let pending = record();
        publish(scope, &pending).unwrap();
        let mut running = pending.clone();
        running.phase = ClaimPhase::Running;
        transition_file(scope, &pending, &running).unwrap();
        assert!(publish(scope, &pending).is_err());
        assert!(transition_file(scope, &pending, &running).is_err());
        let mut ended = running.clone();
        ended.phase = ClaimPhase::Ended;
        transition_file(scope, &running, &ended).unwrap();
        assert!(publish(scope, &pending).is_err());
        assert!(transition_file(scope, &running, &ended).is_err());
        assert!(transition_file(scope, &ended, &pending).is_err());
        let bytes = std::fs::read(scope.join("claims").join(format!("{OPERATION}.json"))).unwrap();
        assert_eq!(ClaimRecord::decode(&bytes, OPERATION).unwrap(), ended);
    }

    #[test]
    fn malformed_oversized_public_linked_and_symlink_claims_are_not_replaced() {
        let _guard = crate::cli::test_harness::ENV_LOCK.lock().unwrap();
        for case in ["malformed", "oversized", "public", "linked", "symlink"] {
            let temporary = tempfile::tempdir().unwrap();
            let scope = temporary.path();
            let request = record();
            publish(scope, &request).unwrap();
            let path = scope.join("claims").join(format!("{OPERATION}.json"));
            match case {
                "malformed" => std::fs::write(&path, b"{}").unwrap(),
                "oversized" => std::fs::write(&path, vec![b'x'; MAX_CLAIM_BYTES + 1]).unwrap(),
                "public" => {
                    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap()
                }
                "linked" => std::fs::hard_link(&path, scope.join("other-link")).unwrap(),
                _ => {
                    let destination = scope.join("outside-claim");
                    std::fs::rename(&path, &destination).unwrap();
                    std::os::unix::fs::symlink(destination, &path).unwrap();
                }
            }
            let before = std::fs::read(&path).unwrap();
            assert!(publish(scope, &request).is_err(), "{case}");
            assert_eq!(std::fs::read(&path).unwrap(), before, "{case}");
        }
    }

    #[test]
    fn held_claim_identity_rejects_same_bytes_in_a_replacement_file() {
        let _guard = crate::cli::test_harness::ENV_LOCK.lock().unwrap();
        let temporary = tempfile::tempdir().unwrap();
        let scope = temporary.path();
        publish(scope, &record()).unwrap();
        let path = scope.join("claims").join(format!("{OPERATION}.json"));
        let held = BinaryIdentity::capture_input(&path).unwrap();
        let replacement = scope.join("replacement");
        std::fs::write(&replacement, std::fs::read(&path).unwrap()).unwrap();
        std::fs::set_permissions(&replacement, std::fs::Permissions::from_mode(0o600)).unwrap();
        std::fs::rename(replacement, path).unwrap();
        assert!(held.revalidate().is_err());
    }

    #[test]
    fn state_transition_cannot_replace_attempt_or_authenticated_shell_binding() {
        let _guard = crate::cli::test_harness::ENV_LOCK.lock().unwrap();
        let temporary = tempfile::tempdir().unwrap();
        let pending = record();
        publish(temporary.path(), &pending).unwrap();
        for changed_field in ["attempt", "shell", "setup", "loaded"] {
            let mut running = pending.clone();
            running.phase = ClaimPhase::Running;
            match changed_field {
                "attempt" => running.attempt_id = uuid::Uuid::new_v4().to_string(),
                "shell" => running.shell_binding = "d".repeat(64),
                "setup" => running.setup_binding = "d".repeat(64),
                _ => running.loaded = "d".repeat(64),
            }
            assert!(transition_file(temporary.path(), &pending, &running).is_err());
        }
        let bytes = std::fs::read(
            temporary
                .path()
                .join("claims")
                .join(format!("{OPERATION}.json")),
        )
        .unwrap();
        assert_eq!(ClaimRecord::decode(&bytes, OPERATION).unwrap(), pending);
    }

    #[test]
    fn lost_authority_or_over_limit_output_creates_no_claim_directory() {
        let _guard = crate::cli::test_harness::ENV_LOCK.lock().unwrap();
        let temporary = tempfile::tempdir().unwrap();
        let scope = temporary.path();
        let path = scope.join("claims").join(format!("{OPERATION}.json"));
        let request = record();
        assert!(
            super::super::super::fs_transaction::update_private_activation_claim(
                &path,
                scope,
                |snapshot| pending_update(snapshot, &request),
                || Err("lease revoked".into()),
            )
            .is_err()
        );
        assert!(!scope.join("claims").exists());
        assert!(
            super::super::super::fs_transaction::update_private_activation_claim(
                &path,
                scope,
                |_| Ok(FileUpdate::write_text(
                    "x".repeat(MAX_CLAIM_BYTES + 1),
                    0o600
                )),
                || Ok(()),
            )
            .is_err()
        );
        assert!(!scope.join("claims").exists());
    }

    fn service_for_inventory(scope: &Path) -> MutationService {
        let root = scope.join("operations");
        std::fs::create_dir(&root).unwrap();
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).unwrap();
        MutationService {
            root,
            scope: scope.into(),
            operator: "fixture".into(),
        }
    }

    #[test]
    fn discovery_refuses_truncated_inventory_and_malformed_or_noncanonical_journals() {
        let _guard = crate::cli::test_harness::ENV_LOCK.lock().unwrap();
        for case in ["truncated", "malformed", "noncanonical", "oversized"] {
            let temporary = tempfile::tempdir().unwrap();
            let service = service_for_inventory(temporary.path());
            match case {
                "truncated" => {
                    for index in 0..=MAX_DISCOVERY_ENTRIES {
                        std::fs::write(
                            service.root.join(format!("entry-{index}.execution-lock")),
                            [],
                        )
                        .unwrap();
                    }
                }
                "malformed" => {
                    std::fs::write(service.root.join(format!("{OPERATION}.json")), b"{}").unwrap()
                }
                "oversized" => {
                    let path = service.root.join(format!("{OPERATION}.json"));
                    std::fs::File::create(path)
                        .unwrap()
                        .set_len(MAX_SETUP_FILE_BYTES as u64 + 1)
                        .unwrap();
                }
                _ => std::fs::write(service.root.join("old-short-id.json"), b"{}").unwrap(),
            }
            for entry in std::fs::read_dir(&service.root).unwrap() {
                let path = entry.unwrap().path();
                if path.extension().is_some_and(|value| value == "json") {
                    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).unwrap();
                }
            }
            assert!(service.unique_activation_candidate().is_err(), "{case}");
        }
    }

    #[test]
    fn discovery_has_no_reconciliation_or_ordering_fallback() {
        let _guard = crate::cli::test_harness::ENV_LOCK.lock().unwrap();
        let temporary = tempfile::tempdir().unwrap();
        let service = service_for_inventory(temporary.path());
        assert!(service.unique_activation_candidate().unwrap().is_none());
        std::fs::write(service.root.join("unrelated.execution-lock"), []).unwrap();
        assert!(service.unique_activation_candidate().unwrap().is_none());
        assert_eq!(std::fs::read_dir(service.root).unwrap().count(), 1);
        assert!(!temporary
            .path()
            .join("automatic-activation-claims")
            .exists());
    }
}
