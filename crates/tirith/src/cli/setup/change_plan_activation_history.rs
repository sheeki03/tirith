//! Bounded private history, not persisted execution authority. A live claim
//! owner is the only production writer. Readers trust ordinary operator-owned
//! private records, never a durable signature or a live shell-verification bit.

use super::*;

pub(super) const CLAIM_SCHEMA: u32 = 1;
pub(super) const MAX_CLAIM_BYTES: usize = 4096;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum ClaimPhase {
    Pending,
    Running,
    Ended,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ClaimRecord {
    pub(super) schema_version: u32,
    pub(super) operation_id: String,
    pub(super) attempt_id: String,
    pub(super) setup_binding: String,
    pub(super) shell_binding: String,
    pub(super) loaded: String,
    pub(super) phase: ClaimPhase,
}

pub(super) fn canonical_id(value: &str) -> bool {
    value.len() == 36
        && uuid::Uuid::parse_str(value).is_ok_and(|id| !id.is_nil() && id.to_string() == value)
}

pub(super) fn fingerprint(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

impl ClaimRecord {
    pub(super) fn decode(bytes: &[u8], operation: &str) -> Result<Self, String> {
        if bytes.len() > MAX_CLAIM_BYTES {
            return Err("automatic claim exceeds its fixed bound".into());
        }
        let result: Self = serde_json::from_slice(bytes)
            .map_err(|_| "automatic claim is malformed; retain it and use a new setup intent")?;
        if result.schema_version != CLAIM_SCHEMA
            || !canonical_id(operation)
            || result.operation_id != operation
            || !canonical_id(&result.attempt_id)
            || !fingerprint(&result.setup_binding)
            || !fingerprint(&result.shell_binding)
            || !fingerprint(&result.loaded)
        {
            return Err("automatic claim identity or schema does not match".into());
        }
        Ok(result)
    }

    #[cfg(unix)]
    pub(super) fn encoded(&self) -> Result<String, String> {
        let text = serde_json::to_string(self).map_err(|_| "cannot encode automatic claim")?;
        Self::decode(text.as_bytes(), &self.operation_id)?;
        Ok(text)
    }

    #[cfg(unix)]
    pub(super) fn reusable_by(&self, requested: &Self) -> bool {
        self.phase == ClaimPhase::Pending
            && requested.phase == ClaimPhase::Pending
            && self.operation_id == requested.operation_id
            && self.setup_binding == requested.setup_binding
            && self.shell_binding == requested.shell_binding
            && self.loaded == requested.loaded
    }
}

impl MutationService {
    pub(super) fn claim_directory(&self) -> PathBuf {
        self.scope.join("automatic-activation-claims")
    }

    pub(super) fn claim_path(&self, id: &str) -> Result<PathBuf, String> {
        if !canonical_id(id) {
            return Err("automatic activation requires a canonical non-nil operation ID".into());
        }
        Ok(self.claim_directory().join(format!("{id}.json")))
    }

    pub(super) fn read_claim(&self, id: &str) -> Result<Option<ClaimRecord>, String> {
        let snapshot = fs_helpers::read_snapshot_scoped_capped(
            &self.claim_path(id)?,
            &self.scope,
            MAX_CLAIM_BYTES,
        )?;
        snapshot.require_private()?;
        snapshot
            .bytes
            .as_deref()
            .map(|bytes| ClaimRecord::decode(bytes, id))
            .transpose()
    }
}

const HISTORY_SCHEMA: u32 = 1;
const MAX_HISTORY_BYTES: usize = 4096;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "outcome", rename_all = "snake_case", deny_unknown_fields)]
pub(super) enum TerminalObservation {
    ObservedBlocking {
        observed_unix_ms: u64,
        expires_unix_ms: u64,
    },
    Cancelled,
    Refused,
}

impl TerminalObservation {
    #[cfg(unix)]
    pub(super) fn from_core(
        report: tirith_core::execution_state::ShellVerificationObservation,
        attempt_id: &str,
    ) -> Result<Self, String> {
        use tirith_core::execution_state::{ShellHookFamily, ShellVerificationStatus};
        if report.schema_version != 1
            || report.challenge_id != attempt_id
            || report.family != ShellHookFamily::Zsh
            || report.status != ShellVerificationStatus::ObservedBlocking
            || report.source != "fresh_terminal_activation"
            || report.scope != "completed_setup_shell_observation"
        {
            return Err("automatic terminal observation does not match its live claim".into());
        }
        let observed_unix_ms = report
            .observed_unix_ms
            .ok_or("automatic terminal observation has no observation time")?;
        let result = Self::ObservedBlocking {
            observed_unix_ms,
            expires_unix_ms: report.expires_unix_ms,
        };
        result.validate(u64::MAX)?;
        Ok(result)
    }

    fn validate(&self, recorded_unix_ms: u64) -> Result<(), String> {
        if let Self::ObservedBlocking {
            observed_unix_ms,
            expires_unix_ms,
        } = self
        {
            if *observed_unix_ms == 0
                || observed_unix_ms > expires_unix_ms
                || *observed_unix_ms > recorded_unix_ms
            {
                return Err("automatic historical observation times are invalid".into());
            }
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct StoredActivationOutcome {
    schema_version: u32,
    storage_binding: String,
    client_version: String,
    channel: HistoricalChannel,
    completed_state: JobState,
    claim: ClaimRecord,
    recorded_unix_ms: u64,
    observation: TerminalObservation,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum HistoricalChannel {
    Zsh,
}

impl StoredActivationOutcome {
    #[cfg(unix)]
    pub(super) fn new(
        service: &MutationService,
        journal: &Journal,
        claim: ClaimRecord,
        observation: TerminalObservation,
    ) -> Result<Self, String> {
        let recorded_unix_ms = u64::try_from(
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_err(|_| "historical observation clock is unavailable")?
                .as_millis(),
        )
        .map_err(|_| "historical observation clock overflow")?;
        let result = Self {
            schema_version: HISTORY_SCHEMA,
            storage_binding: service.activation_storage_binding()?,
            client_version: journal.client_version.clone(),
            channel: HistoricalChannel::Zsh,
            completed_state: journal.state,
            claim,
            recorded_unix_ms,
            observation,
        };
        result.validate_for(service, journal)?;
        Ok(result)
    }

    fn decode(bytes: &[u8]) -> Result<Self, String> {
        if bytes.len() > MAX_HISTORY_BYTES {
            return Err("automatic historical outcome exceeds its fixed bound".into());
        }
        let record: Self = serde_json::from_slice(bytes)
            .map_err(|_| "automatic historical outcome is malformed")?;
        if record.schema_version != HISTORY_SCHEMA
            || !fingerprint(&record.storage_binding)
            || record.recorded_unix_ms == 0
            || record.client_version.is_empty()
            || record.client_version.len() > 64
            || !record
                .client_version
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b".-+".contains(&b))
            || !matches!(
                record.completed_state,
                JobState::Completed | JobState::CompletedWithRecovery
            )
            || record.claim.phase != ClaimPhase::Ended
        {
            return Err("automatic historical outcome schema or binding is invalid".into());
        }
        ClaimRecord::decode(
            &serde_json::to_vec(&record.claim).map_err(|_| "cannot inspect claim")?,
            &record.claim.operation_id,
        )?;
        record.observation.validate(record.recorded_unix_ms)?;
        Ok(record)
    }

    #[cfg(unix)]
    fn encoded(&self) -> Result<String, String> {
        let bytes = serde_json::to_string(self).map_err(|_| "cannot encode automatic history")?;
        Self::decode(bytes.as_bytes())?;
        Ok(bytes)
    }

    fn validate_for(&self, service: &MutationService, journal: &Journal) -> Result<(), String> {
        if self.storage_binding != service.activation_storage_binding()?
            || journal.operator != service.operator
            || self.client_version != journal.client_version
            || self.claim.operation_id != journal.operation_id
            || self.claim.phase != ClaimPhase::Ended
            || !matches!(
                self.completed_state,
                JobState::Completed | JobState::CompletedWithRecovery
            )
            || self.claim.setup_binding
                != setup_binding::historical_completion_binding(journal, self.completed_state)?
        {
            return Err("automatic history does not match its stored setup and operator".into());
        }
        self.observation.validate(self.recorded_unix_ms)
    }
}

#[derive(Clone, Copy, Debug, Serialize)]
#[serde(rename_all = "snake_case")]
enum Availability {
    Missing,
    Incomplete,
    Invalid,
    Recorded,
}

#[derive(Clone, Copy, Debug, Serialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum SetupRelation {
    Changed,
    RecordedInputsMatch,
    Unknown,
    NotChecked,
}

#[derive(Clone, Copy, Debug, Serialize)]
#[serde(rename_all = "snake_case")]
enum CurrentProtection {
    Unknown,
}

/// This additive DTO has no current verification boolean or execution token.
/// It records a terminal observation under the ordinary private-record model.
#[derive(Clone, Debug, Serialize)]
pub(crate) struct SetupActivationHistory {
    schema_version: u32,
    scope: &'static str,
    storage_integrity: &'static str,
    current_protection: CurrentProtection,
    availability: Availability,
    setup_state: SetupRelation,
    claim_phase: Option<ClaimPhase>,
    observation: Option<HistoricalTerminalObservation>,
}

#[derive(Clone, Debug, Serialize)]
struct HistoricalTerminalObservation {
    channel: HistoricalChannel,
    client_version: String,
    attempt_id: String,
    recorded_unix_ms: u64,
    // Expiry describes the former live proof, never a freshness entitlement.
    terminal: TerminalObservation,
}

impl SetupActivationHistory {
    fn new(availability: Availability) -> Self {
        Self {
            schema_version: 1,
            scope: "stored_historical_terminal_observation",
            storage_integrity: "operator_owned_private_record",
            current_protection: CurrentProtection::Unknown,
            availability,
            setup_state: SetupRelation::Unknown,
            claim_phase: None,
            observation: None,
        }
    }
}

impl MutationService {
    fn activation_storage_binding(&self) -> Result<String, String> {
        digest(&(
            "tirith-automatic-history-storage-v1",
            &self.scope,
            &self.operator,
        ))
    }

    fn activation_history_path(&self, operation: &str) -> Result<PathBuf, String> {
        if !canonical_id(operation) {
            return Err("automatic history requires its canonical operation ID".into());
        }
        Ok(self
            .scope
            .join("automatic-activation-outcomes")
            .join(format!("{operation}.json")))
    }

    fn read_activation_outcome(
        &self,
        operation: &str,
    ) -> Result<Option<StoredActivationOutcome>, String> {
        let snapshot = fs_helpers::read_snapshot_scoped_capped(
            &self.activation_history_path(operation)?,
            &self.scope,
            MAX_HISTORY_BYTES,
        )?;
        snapshot.require_private()?;
        snapshot
            .bytes
            .as_deref()
            .map(StoredActivationOutcome::decode)
            .transpose()
    }

    #[cfg(unix)]
    pub(super) fn publish_activation_outcome(
        &self,
        outcome: &StoredActivationOutcome,
        revalidate: impl FnMut() -> Result<(), String>,
    ) -> Result<(), String> {
        let path = self.activation_history_path(&outcome.claim.operation_id)?;
        let result = super::super::fs_transaction::update_private_activation_claim(
            &path,
            &self.scope,
            |snapshot| immutable_outcome_update(snapshot, outcome),
            revalidate,
        )?;
        if !matches!(
            result,
            TransactionOutcome::Written | TransactionOutcome::Unchanged
        ) || self
            .read_activation_outcome(&outcome.claim.operation_id)?
            .as_ref()
            != Some(outcome)
        {
            return Err("automatic historical outcome was not cleanly published".into());
        }
        Ok(())
    }

    /// The inventory reads at most two 4 KiB private records per retained row.
    /// Only explicit status reads compare at most 16 recorded setup documents,
    /// sharing one 8 MiB content budget. Neither route reacquires execution proof.
    fn activation_history(
        &self,
        journal: &Journal,
        compare_inputs: bool,
    ) -> SetupActivationHistory {
        if !canonical_id(&journal.operation_id) {
            return SetupActivationHistory::new(Availability::Missing);
        }
        let read = (|| {
            let claim = self.read_claim(&journal.operation_id)?;
            let outcome = self.read_activation_outcome(&journal.operation_id)?;
            match outcome {
                Some(outcome) => {
                    outcome.validate_for(self, journal)?;
                    if claim.as_ref() != Some(&outcome.claim) {
                        return Err("automatic historical claim changed".into());
                    }
                    let mut view = SetupActivationHistory::new(Availability::Recorded);
                    view.claim_phase = Some(ClaimPhase::Ended);
                    view.setup_state =
                        setup_binding::historical_setup_relation(journal, compare_inputs);
                    view.observation = Some(HistoricalTerminalObservation {
                        channel: outcome.channel,
                        client_version: outcome.client_version,
                        attempt_id: outcome.claim.attempt_id,
                        recorded_unix_ms: outcome.recorded_unix_ms,
                        terminal: outcome.observation,
                    });
                    Ok(view)
                }
                None => {
                    if let Some(claim) = &claim {
                        let binding_matches =
                            [JobState::Completed, JobState::CompletedWithRecovery]
                                .into_iter()
                                .any(|state| {
                                    setup_binding::historical_completion_binding(journal, state)
                                        .is_ok_and(|binding| binding == claim.setup_binding)
                                });
                        if !binding_matches {
                            return Err(
                                "automatic incomplete claim does not match its setup".into()
                            );
                        }
                    }
                    let mut view = SetupActivationHistory::new(if claim.is_some() {
                        Availability::Incomplete
                    } else {
                        Availability::Missing
                    });
                    view.claim_phase = claim.map(|claim| claim.phase);
                    view.setup_state = setup_binding::historical_setup_relation(journal, false);
                    Ok(view)
                }
            }
        })();
        read.unwrap_or_else(|_: String| SetupActivationHistory::new(Availability::Invalid))
    }

    pub(super) fn public_with_activation_history(
        &self,
        journal: &Journal,
        compare_inputs: bool,
    ) -> OperationStatus {
        let mut view = journal.public();
        if journal.kind == OperationKind::RecommendedSetup {
            view.setup_activation = Some(self.activation_history(journal, compare_inputs));
        }
        view
    }
}

#[cfg(unix)]
fn immutable_outcome_update(
    snapshot: &super::super::fs_transaction::FileSnapshot,
    requested: &StoredActivationOutcome,
) -> Result<FileUpdate, String> {
    snapshot.require_private()?;
    let encoded = requested.encoded()?;
    match snapshot.bytes() {
        Some(bytes) if StoredActivationOutcome::decode(bytes)? == *requested => {
            Ok(FileUpdate::unchanged())
        }
        Some(_) => Err("automatic historical outcome is already recorded differently".into()),
        None => Ok(FileUpdate::write_text(encoded, 0o600).with_exact_mode()),
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use crate::cli::setup::shell_service::{PreparedShell, ShellChange, ShellKind};
    use crate::cli::test_harness::{with_fake_env, EnvGuard};
    use std::os::unix::fs::PermissionsExt;
    use tirith_core::policy_snapshot::ResolutionMode;

    // These create private-record fixtures, not authenticated shell proofs.
    // Product outcome construction remains inside the retained live ClaimOwner.
    fn fixture(home: &Path) -> (MutationService, Journal, StoredActivationOutcome) {
        let binary = home.join("inert-history-fixture");
        std::fs::write(&binary, b"#!/bin/sh\nexit 0\n").unwrap();
        std::fs::set_permissions(&binary, std::fs::Permissions::from_mode(0o700)).unwrap();
        let prepared = PreparedShell::capture_with_binary(
            ShellChange::Install {
                shell: ShellKind::Zsh,
                force: false,
            },
            None,
            binary.to_str(),
        )
        .unwrap();
        let service = MutationService::current().unwrap();
        let operation = uuid::Uuid::new_v4().to_string();
        let (requests, preimages, shell) = prepared.setup_parts().unwrap();
        service
            .plan_recommended_with_verification_intent(
                &operation,
                PlanChanges {
                    requests,
                    preimages: &preimages,
                },
                &prepared.snapshot,
                &"historical-result-fixture",
                IntegrationPreconditions {
                    shell: Some(shell),
                    agent: None,
                },
                prepared.verification_intent().unwrap(),
            )
            .unwrap();
        let journal = service.read(&operation).unwrap();
        let policy = EffectivePolicySnapshot::resolve(
            journal.resolution_cwd.as_deref(),
            ResolutionMode::Runtime,
        );
        assert_eq!(
            service.apply(&operation, &policy).unwrap().state,
            JobState::Completed
        );
        let journal = service.read(&operation).unwrap();
        let claim = ClaimRecord {
            schema_version: CLAIM_SCHEMA,
            operation_id: operation,
            attempt_id: uuid::Uuid::new_v4().to_string(),
            setup_binding: setup_binding::historical_completion_binding(&journal, journal.state)
                .unwrap(),
            shell_binding: "b".repeat(64),
            loaded: "c".repeat(64),
            phase: ClaimPhase::Ended,
        };
        let outcome = StoredActivationOutcome::new(
            &service,
            &journal,
            claim,
            TerminalObservation::ObservedBlocking {
                observed_unix_ms: 1,
                expires_unix_ms: 2,
            },
        )
        .unwrap();
        (service, journal, outcome)
    }

    fn write_claim(service: &MutationService, claim: &ClaimRecord) {
        super::super::super::fs_transaction::update_private_activation_claim(
            &service.claim_path(&claim.operation_id).unwrap(),
            &service.scope,
            |_| Ok(FileUpdate::write_text(claim.encoded().unwrap(), 0o600).with_exact_mode()),
            || Ok(()),
        )
        .unwrap();
    }

    fn publish(service: &MutationService, outcome: &StoredActivationOutcome) {
        write_claim(service, &outcome.claim);
        service
            .publish_activation_outcome(outcome, || Ok(()))
            .unwrap();
    }

    fn view(service: &MutationService, operation: &str) -> Value {
        serde_json::to_value(service.read_status(operation).unwrap()).unwrap()["setup_activation"]
            .clone()
    }

    fn with_fixture(
        test: impl FnOnce(&Path, MutationService, Journal, StoredActivationOutcome)
            + std::panic::UnwindSafe,
    ) {
        with_fake_env(true, |home, _| {
            let _zdotdir = EnvGuard::remove("ZDOTDIR");
            let (service, journal, outcome) = fixture(home);
            test(home, service, journal, outcome);
        });
    }

    #[test]
    fn activation_parents_are_private_under_actual_ordinary_umasks() {
        // umask is process-global. Reexecute only this fixture in a fresh native
        // test process instead of changing unrelated parallel tests' masks.
        let _environment = crate::cli::test_harness::ENV_LOCK
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        let child_test = format!(
            "{}::activation_parent_umask_child",
            module_path!().split_once("::").unwrap().1,
        );
        for mask in ["022", "027"] {
            let output = std::process::Command::new(std::env::current_exe().unwrap())
                .args(["--exact", &child_test, "--nocapture", "--test-threads=1"])
                .env("TIRITH_TEST_ACTIVATION_PARENT_UMASK", mask)
                .output()
                .unwrap();
            assert!(
                output.status.success(),
                "{}",
                String::from_utf8_lossy(&output.stderr)
            );
            assert!(
                String::from_utf8_lossy(&output.stdout)
                    .contains(&format!("activation-private-parent-fixture:{mask}")),
                "the exact native fixture must actually execute: {}",
                String::from_utf8_lossy(&output.stdout),
            );
        }
    }

    #[test]
    fn activation_parent_umask_child() {
        let Ok(mask) = std::env::var("TIRITH_TEST_ACTIVATION_PARENT_UMASK") else {
            return;
        };
        let (native_mask, ordinary_mode) = match mask.as_str() {
            "022" => (0o022, 0o755),
            "027" => (0o027, 0o750),
            _ => panic!("unsupported isolated fixture umask"),
        };
        struct RestoreMask(libc::mode_t);
        impl Drop for RestoreMask {
            fn drop(&mut self) {
                unsafe {
                    libc::umask(self.0);
                }
            }
        }
        let _mask = RestoreMask(unsafe { libc::umask(native_mask) });
        with_fixture(|_, service, journal, outcome| {
            use crate::cli::control::identity::{BinaryIdentity, DirectoryIdentity};
            use std::os::unix::fs::MetadataExt;
            let parents = [
                service.claim_directory(),
                service
                    .activation_history_path(&journal.operation_id)
                    .unwrap()
                    .parent()
                    .unwrap()
                    .to_path_buf(),
            ];
            assert!(parents.iter().all(|path| !path.exists()));
            publish(&service, &outcome);
            for parent in &parents {
                let metadata = parent.metadata().unwrap();
                assert_eq!(metadata.mode() & 0o777, 0o700);
                assert_eq!(metadata.uid(), unsafe { libc::geteuid() });
                DirectoryIdentity::capture(parent)
                    .unwrap()
                    .revalidate()
                    .unwrap();
            }
            for path in [
                service.claim_path(&journal.operation_id).unwrap(),
                service
                    .activation_history_path(&journal.operation_id)
                    .unwrap(),
            ] {
                assert_eq!(path.metadata().unwrap().mode() & 0o777, 0o600);
                BinaryIdentity::capture_input(&path)
                    .unwrap()
                    .revalidate()
                    .unwrap();
            }
            let status = view(&service, &journal.operation_id);
            assert_eq!(status["availability"], "recorded");
            assert_eq!(status["current_protection"], "unknown");

            // Tighten a pre-fix, operator-owned parent without replacing the
            // immutable historical record or pretending it is live proof.
            let path = service
                .activation_history_path(&journal.operation_id)
                .unwrap();
            let retained = BinaryIdentity::capture_input(&path).unwrap();
            std::fs::set_permissions(&parents[1], std::fs::Permissions::from_mode(0o755)).unwrap();
            assert!(DirectoryIdentity::capture(&parents[1]).is_err());
            service
                .publish_activation_outcome(&outcome, || Ok(()))
                .unwrap();
            retained.revalidate().unwrap();
            DirectoryIdentity::capture(&parents[1])
                .unwrap()
                .revalidate()
                .unwrap();
            assert_eq!(
                view(&service, &journal.operation_id)["availability"],
                "recorded"
            );

            // The ordinary setup parent rule must not become private globally.
            let ordinary = service.scope.join("ordinary-control").join("file");
            super::super::super::fs_transaction::transactional_update(
                &ordinary,
                &service.scope,
                false,
                |_| Ok(FileUpdate::write_text("ordinary".into(), 0o600)),
            )
            .unwrap();
            assert_eq!(
                ordinary.parent().unwrap().metadata().unwrap().mode() & 0o777,
                ordinary_mode
            );
        });
        println!("activation-private-parent-fixture:{mask}");
    }

    #[test]
    fn legacy_missing_and_incomplete_claims_never_become_current_protection() {
        with_fixture(|_, service, journal, outcome| {
            let before = std::fs::read(service.path(&journal.operation_id).unwrap()).unwrap();
            let missing = view(&service, &journal.operation_id);
            assert_eq!(missing["availability"], "missing");
            assert_eq!(missing["current_protection"], "unknown");
            assert!(!service
                .activation_history_path(&journal.operation_id)
                .unwrap()
                .exists());
            for phase in [ClaimPhase::Pending, ClaimPhase::Running, ClaimPhase::Ended] {
                let mut claim = outcome.claim.clone();
                claim.phase = phase;
                write_claim(&service, &claim);
                let result = view(&service, &journal.operation_id);
                assert_eq!(result["availability"], "incomplete");
                assert_eq!(result["current_protection"], "unknown");
                assert!(result["observation"].is_null());
            }
            assert_eq!(
                before,
                std::fs::read(service.path(&journal.operation_id).unwrap()).unwrap()
            );
            assert!(!String::from_utf8(before)
                .unwrap()
                .contains("setup_activation"));
        });
    }

    #[test]
    fn historical_outcome_is_additive_bounded_and_keeps_private_bindings_out_of_dto() {
        with_fixture(|_, service, journal, outcome| {
            publish(&service, &outcome);
            let result = view(&service, &journal.operation_id);
            assert_eq!(result["availability"], "recorded");
            assert_eq!(result["current_protection"], "unknown");
            assert_eq!(result["setup_state"], "recorded_inputs_match");
            assert_eq!(result["scope"], "stored_historical_terminal_observation");
            assert_eq!(
                result["observation"]["terminal"]["outcome"],
                "observed_blocking"
            );
            assert_eq!(
                result["observation"]["attempt_id"],
                outcome.claim.attempt_id
            );
            let serialized = result.to_string();
            for private in [
                &outcome.storage_binding,
                &outcome.claim.setup_binding,
                &outcome.claim.shell_binding,
                &outcome.claim.loaded,
            ] {
                assert!(!serialized.contains(private));
            }
            let recent = serde_json::to_value(service.recent_statuses(1).unwrap()).unwrap();
            assert_eq!(
                recent["operations"][0]["setup_activation"]["setup_state"],
                "not_checked"
            );
            assert!(outcome.encoded().unwrap().len() <= MAX_HISTORY_BYTES);
        });
    }

    #[test]
    fn changed_startup_and_actual_undo_retain_only_historical_result() {
        with_fixture(|home, service, journal, outcome| {
            publish(&service, &outcome);
            let startup = home.join(".zshrc");
            let original = std::fs::read(&startup).unwrap();
            let mut edited = original.clone();
            edited.extend_from_slice(b"\n# user edit after observation\n");
            std::fs::write(&startup, edited).unwrap();
            let changed = view(&service, &journal.operation_id);
            assert_eq!(changed["availability"], "recorded");
            assert_eq!(changed["setup_state"], "changed");
            assert_eq!(changed["current_protection"], "unknown");
            std::fs::write(&startup, original).unwrap();
            let policy = EffectivePolicySnapshot::resolve(
                journal.resolution_cwd.as_deref(),
                ResolutionMode::Runtime,
            );
            assert_eq!(
                service.undo(&journal.operation_id, &policy).unwrap().state,
                JobState::Undone
            );
            let undone = view(&service, &journal.operation_id);
            assert_eq!(undone["availability"], "recorded");
            assert_eq!(undone["setup_state"], "changed");
            assert_eq!(undone["observation"], changed["observation"]);
            assert_eq!(undone["current_protection"], "unknown");
        });
    }

    #[test]
    fn immutable_outcome_cas_never_overwrites_a_different_terminal_result() {
        with_fixture(|_, service, journal, outcome| {
            publish(&service, &outcome);
            let path = service
                .activation_history_path(&journal.operation_id)
                .unwrap();
            let bytes = std::fs::read(&path).unwrap();
            service
                .publish_activation_outcome(&outcome, || Ok(()))
                .unwrap();
            let mut other = outcome.clone();
            other.observation = TerminalObservation::Refused;
            assert!(service
                .publish_activation_outcome(&other, || Ok(()))
                .is_err());
            assert_eq!(bytes, std::fs::read(path).unwrap());
            assert_eq!(
                service
                    .read_claim(&journal.operation_id)
                    .unwrap()
                    .unwrap()
                    .phase,
                ClaimPhase::Ended
            );
        });
    }

    #[test]
    fn publication_guard_failure_preserves_spent_claim_and_reports_incomplete() {
        with_fixture(|_, service, journal, outcome| {
            write_claim(&service, &outcome.claim);
            assert!(service
                .publish_activation_outcome(&outcome, || Err("fixture lost live ownership".into()))
                .is_err());
            assert!(!service
                .activation_history_path(&journal.operation_id)
                .unwrap()
                .exists());
            assert_eq!(
                service
                    .read_claim(&journal.operation_id)
                    .unwrap()
                    .unwrap()
                    .phase,
                ClaimPhase::Ended
            );
            assert_eq!(
                view(&service, &journal.operation_id)["availability"],
                "incomplete"
            );
        });
    }

    #[test]
    fn forged_sidecar_identity_and_claim_replacement_are_invalid() {
        with_fixture(|_, service, journal, outcome| {
            publish(&service, &outcome);
            let path = service
                .activation_history_path(&journal.operation_id)
                .unwrap();
            let original = serde_json::to_value(&outcome).unwrap();
            for (pointer, replacement) in [
                ("/schema_version", serde_json::json!(2)),
                ("/storage_binding", serde_json::json!("d".repeat(64))),
                ("/client_version", serde_json::json!("0.0.1")),
                ("/channel", serde_json::json!("bash")),
                (
                    "/completed_state",
                    serde_json::json!("completed-with-recovery"),
                ),
                (
                    "/claim/operation_id",
                    serde_json::json!(uuid::Uuid::new_v4().to_string()),
                ),
                (
                    "/claim/attempt_id",
                    serde_json::json!(uuid::Uuid::new_v4().to_string()),
                ),
                ("/claim/setup_binding", serde_json::json!("e".repeat(64))),
                ("/claim/shell_binding", serde_json::json!("f".repeat(64))),
                ("/claim/loaded", serde_json::json!("d".repeat(64))),
                ("/claim/phase", serde_json::json!("running")),
                ("/observation/outcome", serde_json::json!("active")),
            ] {
                let mut altered = original.clone();
                *altered.pointer_mut(pointer).unwrap() = replacement;
                std::fs::write(&path, serde_json::to_vec(&altered).unwrap()).unwrap();
                assert_eq!(
                    view(&service, &journal.operation_id)["availability"],
                    "invalid",
                    "{pointer}"
                );
            }
            std::fs::write(&path, outcome.encoded().unwrap()).unwrap();
            let mut other = outcome.claim.clone();
            other.attempt_id = uuid::Uuid::new_v4().to_string();
            write_claim(&service, &other);
            assert_eq!(
                view(&service, &journal.operation_id)["availability"],
                "invalid"
            );
            std::fs::remove_file(&path).unwrap();
            other.setup_binding = "d".repeat(64);
            write_claim(&service, &other);
            assert_eq!(
                view(&service, &journal.operation_id)["availability"],
                "invalid"
            );
        });
    }

    #[test]
    fn private_history_cannot_move_between_operator_or_state_scopes() {
        with_fixture(|_, service, journal, outcome| {
            let mut other_operator = service.clone();
            other_operator.operator.push_str("-other");
            assert!(outcome.validate_for(&other_operator, &journal).is_err());
            let mut other_scope = service.clone();
            other_scope.scope = service.scope.join("different-state-scope");
            assert!(outcome.validate_for(&other_scope, &journal).is_err());
            let mut other_journal = journal.clone();
            other_journal.operation_id = uuid::Uuid::new_v4().to_string();
            assert!(outcome.validate_for(&service, &other_journal).is_err());
            other_journal = journal.clone();
            other_journal.request_digest = "d".repeat(64);
            assert!(outcome.validate_for(&service, &other_journal).is_err());
        });
    }

    #[test]
    fn inaccessible_current_input_preserves_history_but_cannot_claim_input_match() {
        with_fixture(|home, service, journal, outcome| {
            publish(&service, &outcome);
            let startup = home.join(".zshrc");
            std::fs::remove_file(&startup).unwrap();
            let cpath = std::ffi::CString::new(startup.to_str().unwrap()).unwrap();
            assert_eq!(unsafe { libc::mkfifo(cpath.as_ptr(), 0o600) }, 0);
            let result = view(&service, &journal.operation_id);
            assert_eq!(result["availability"], "recorded");
            assert_eq!(result["setup_state"], "unknown");
            assert_eq!(result["current_protection"], "unknown");
        });
    }

    #[test]
    fn malformed_oversized_and_nonprivate_sidecars_refuse_read_and_republication() {
        with_fixture(|_, service, journal, outcome| {
            publish(&service, &outcome);
            let path = service
                .activation_history_path(&journal.operation_id)
                .unwrap();
            for bytes in [b"{".to_vec(), vec![b' '; MAX_HISTORY_BYTES + 1]] {
                std::fs::write(&path, bytes).unwrap();
                assert_eq!(
                    view(&service, &journal.operation_id)["availability"],
                    "invalid"
                );
                assert!(service
                    .publish_activation_outcome(&outcome, || Ok(()))
                    .is_err());
            }
            std::fs::write(&path, outcome.encoded().unwrap()).unwrap();
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
            assert_eq!(
                view(&service, &journal.operation_id)["availability"],
                "invalid"
            );
            assert!(service
                .publish_activation_outcome(&outcome, || Ok(()))
                .is_err());
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
            let linked = path.with_extension("retained-fixture");
            std::fs::hard_link(&path, &linked).unwrap();
            assert_eq!(
                view(&service, &journal.operation_id)["availability"],
                "invalid"
            );
            std::fs::remove_file(&path).unwrap();
            std::os::unix::fs::symlink(&linked, &path).unwrap();
            assert_eq!(
                view(&service, &journal.operation_id)["availability"],
                "invalid"
            );
            assert!(service
                .publish_activation_outcome(&outcome, || Ok(()))
                .is_err());
            std::fs::remove_file(&path).unwrap();
            let cpath = std::ffi::CString::new(path.to_str().unwrap()).unwrap();
            assert_eq!(unsafe { libc::mkfifo(cpath.as_ptr(), 0o600) }, 0);
            assert_eq!(
                view(&service, &journal.operation_id)["availability"],
                "invalid"
            );
        });
    }

    #[test]
    fn core_observation_requires_exact_attempt_channel_scope_status_and_times() {
        use tirith_core::execution_state::{
            ShellHookFamily, ShellVerificationObservation, ShellVerificationStatus,
        };
        let attempt = uuid::Uuid::new_v4().to_string();
        let report = || ShellVerificationObservation {
            schema_version: 1,
            challenge_id: attempt.clone(),
            family: ShellHookFamily::Zsh,
            status: ShellVerificationStatus::ObservedBlocking,
            observed_unix_ms: Some(1),
            expires_unix_ms: 2,
            source: "fresh_terminal_activation",
            scope: "completed_setup_shell_observation",
        };
        assert!(TerminalObservation::from_core(report(), &attempt).is_ok());
        for field in 0..9 {
            let mut other = report();
            match field {
                0 => other.schema_version = 2,
                1 => other.challenge_id = uuid::Uuid::new_v4().to_string(),
                2 => other.family = ShellHookFamily::Bash,
                3 => other.status = ShellVerificationStatus::Stale,
                4 => other.source = "manual",
                5 => other.scope = "current",
                6 => other.observed_unix_ms = None,
                7 => other.observed_unix_ms = Some(0),
                _ => other.observed_unix_ms = Some(3),
            }
            assert!(
                TerminalObservation::from_core(other, &attempt).is_err(),
                "field {field}"
            );
        }
    }
}
