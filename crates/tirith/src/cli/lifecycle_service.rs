//! Typed lifecycle commands shared by local clients. Browser requests supply
//! actions/opaque IDs; all executable, policy and network inputs are private.
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, OnceLock};

use serde::{Deserialize, Serialize};
use tirith_core::policy_snapshot::{
    EffectivePolicySnapshot, PrivatePolicyReplayGuard, ResolutionMode,
};
use tirith_core::task_boundary::SelfUpdateBoundary;

use super::lifecycle_operations::{Action, Operation, OperationView, Phase, Preview, Store};
use super::release_compatibility::{VerifiedCandidate, VerifiedRollback};
use super::{SelfEffectAuthorization, SemVer};
use crate::cli::control::identity::{BinaryIdentity, DirectoryIdentity};

const MAX_RETAINED: usize = 16;
type BinaryAuthorization = super::RetainedSelfAuthorization<SelfUpdateBoundary>;

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SignedProof {
    tag: String,
    target: String,
    compatibility: Vec<u8>,
    checksums: String,
    signature: Vec<u8>,
    certificate: Vec<u8>,
    archive_sha256: String,
    candidate_sha256: String,
    verifier_path: PathBuf,
    verifier_sha256: String,
}

#[derive(Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
enum Candidate {
    Update { proof: Box<SignedProof> },
    Rollback { receipt_sha256: String },
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct BinaryPlan {
    cwd: PathBuf,
    binary: PathBuf,
    old_sha256: String,
    backup_sha256: Option<String>,
    candidate_sha256: String,
    channel: String,
    archiver_path: Option<PathBuf>,
    archiver_sha256: Option<String>,
    policy: PrivatePolicyReplayGuard,
    observed_formats: serde_json::Value,
    candidate: Candidate,
}

struct Retained {
    store: Store,
    binary: BinaryIdentity,
    backup: Option<BinaryIdentity>,
    binary_directory: DirectoryIdentity,
    verifier: Option<BinaryIdentity>,
    archiver: Option<BinaryIdentity>,
    cwd: PathBuf,
}

impl Retained {
    fn capture(store: Store, plan: &BinaryPlan) -> Result<Self, String> {
        let binary = BinaryIdentity::capture(&plan.binary)?;
        if binary.sha256() != plan.old_sha256 {
            return Err("the running executable changed after preparation".into());
        }
        let backup_path = super::previous_backup_path(&plan.binary);
        super::verify_exact_regular_preimage(&backup_path, plan.backup_sha256.as_deref())?;
        let backup = plan
            .backup_sha256
            .as_ref()
            .map(|_| BinaryIdentity::capture(&backup_path))
            .transpose()?;
        let verifier = match &plan.candidate {
            Candidate::Update { proof } => {
                let verifier = BinaryIdentity::capture(&proof.verifier_path)?;
                if verifier.sha256() != proof.verifier_sha256 {
                    return Err("the release signature verifier changed after preparation".into());
                }
                Some(verifier)
            }
            Candidate::Rollback { .. } => None,
        };
        let archiver = match (&plan.archiver_path, &plan.archiver_sha256) {
            (Some(path), Some(expected)) => {
                let guard = BinaryIdentity::capture(path)?;
                if guard.sha256() != expected {
                    return Err("archive extractor changed after preparation".into());
                }
                Some(guard)
            }
            (None, None) => None,
            _ => return Err("archive extractor binding is malformed".into()),
        };
        let binary_directory = DirectoryIdentity::capture_trusted(
            plan.binary
                .parent()
                .ok_or("cannot locate binary directory")?,
        )?;
        let retained = Self {
            store,
            binary,
            backup,
            binary_directory,
            verifier,
            archiver,
            cwd: plan.cwd.clone(),
        };
        retained.revalidate(plan)?;
        Ok(retained)
    }

    fn revalidate(&self, plan: &BinaryPlan) -> Result<(), String> {
        self.store.revalidate()?;
        self.binary_directory.revalidate()?;
        self.binary.revalidate()?;
        if let Some(backup) = &self.backup {
            backup.revalidate()?;
        }
        super::verify_exact_regular_preimage(
            &super::previous_backup_path(&plan.binary),
            plan.backup_sha256.as_deref(),
        )?;
        if let Some(verifier) = &self.verifier {
            verifier.revalidate()?;
        }
        if let Some(archiver) = &self.archiver {
            archiver.revalidate()?;
            #[cfg(unix)]
            if super::resolve_trusted_tar()?.path() != archiver.path() {
                return Err("archive extractor selection changed after preparation".into());
            }
        }
        if current_cwd()? != self.cwd {
            return Err("lifecycle working directory changed; prepare a fresh operation".into());
        }
        let provenance = eligible_binary()?;
        if provenance.binary_path.as_ref() != Some(&plan.binary)
            || super::install_method_token(&provenance) != plan.channel
        {
            return Err(
                "installation identity or owning channel changed; prepare a fresh operation".into(),
            );
        }
        if serde_json::to_value(
            super::lifecycle::gather(&provenance, None)
                .compatibility
                .observed_formats,
        )
        .map_err(|_| "cannot compare local formats")?
            != plan.observed_formats
        {
            return Err(
                "local compatibility formats changed after preparation; prepare a fresh preview"
                    .into(),
            );
        }
        Ok(())
    }

    fn handoff_identity(
        &self,
        operation: &Operation<BinaryPlan>,
    ) -> Result<serde_json::Value, String> {
        self.revalidate(operation.payload())?;
        Ok(serde_json::json!({
            "protocol": 1,
            "operation_id": operation.id(),
            "plan_sha256": operation.plan_sha256(),
            "cwd": self.cwd,
            "state": self.store.handoff_identity()?,
            "binary_directory": self.binary_directory.private_handoff_identity()?,
            "binary": self.binary.private_handoff_identity()?,
            "backup": self.backup.as_ref().map(BinaryIdentity::private_handoff_identity).transpose()?,
            "verifier": self.verifier.as_ref().map(BinaryIdentity::private_handoff_identity).transpose()?,
            "archiver": self.archiver.as_ref().map(BinaryIdentity::private_handoff_identity).transpose()?,
        }))
    }
}

fn retained_plans() -> &'static Mutex<BTreeMap<String, Arc<Retained>>> {
    static PLANS: OnceLock<Mutex<BTreeMap<String, Arc<Retained>>>> = OnceLock::new();
    PLANS.get_or_init(|| Mutex::new(BTreeMap::new()))
}

fn current_cwd() -> Result<PathBuf, String> {
    std::env::current_dir()
        .and_then(|cwd| cwd.canonicalize())
        .map_err(|_| "cannot retain lifecycle working directory".into())
}

fn eligible_binary() -> Result<super::CliProvenance, String> {
    if !cfg!(unix) {
        return Err("browser binary replacement is not qualified on this platform; use `tirith update` or the owning installer in a terminal".into());
    }
    let provenance = super::gather_cli_provenance();
    if provenance.path_resolution_failed || !provenance.install_method.is_self_replaceable() {
        return Err(format!(
            "this installation is managed by {}; {}",
            super::install_method_token(&provenance),
            provenance
                .install_method
                .upgrade_command()
                .unwrap_or("inspect `tirith version --provenance` and use the owning installer")
        ));
    }
    super::ensure_hermes_install_still_proven(&provenance)?;
    // Browser workers never invoke the helper, including a helper retained by
    // a former installation channel. Unknown/inaccessible state is present.
    if super::managed_helper_state_present() {
        return Err("a protected package-approval helper or rollback state exists; run `tirith update` in a terminal so its required administrator confirmation can be handled explicitly".into());
    }
    let path = provenance
        .binary_path
        .as_deref()
        .ok_or("cannot resolve running executable")?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let metadata =
            std::fs::symlink_metadata(path).map_err(|_| "cannot inspect installation ownership")?;
        let uid = unsafe { libc::geteuid() };
        if uid == 0 || !metadata.is_file() || metadata.uid() != uid || metadata.mode() & 0o6022 != 0
        {
            return Err("browser updates require an operator-owned ordinary executable; use its owning administrator or installation channel".into());
        }
    }
    if !super::dir_is_writable(path.parent().ok_or("cannot locate binary directory")?) {
        return Err("installation directory requires administrator access; run the owning installer or `tirith update` from an appropriate terminal".into());
    }
    Ok(provenance)
}

fn authorization(
    kind: &str,
    projection: serde_json::Value,
    destination: Option<&Path>,
) -> Result<BinaryAuthorization, String> {
    super::prepare_self_authorization::<SelfUpdateBoundary>(
        super::self_boundary_envelope(kind, projection, destination)?,
        super::update_effects(false, false),
    )
}

fn policy_snapshot(cwd: &Path) -> Result<EffectivePolicySnapshot, String> {
    let snapshot = EffectivePolicySnapshot::resolve(cwd.to_str(), ResolutionMode::Runtime);
    snapshot
        .revalidate_for_mutation()
        .map_err(|error| error.to_string())?;
    Ok(snapshot)
}

fn check_policy(plan: &BinaryPlan) -> Result<EffectivePolicySnapshot, String> {
    let snapshot = policy_snapshot(&plan.cwd)?;
    if snapshot.private_replay_guard() != plan.policy {
        return Err("policy, trust, incident, environment or project inputs changed; prepare a fresh lifecycle operation".into());
    }
    Ok(snapshot)
}

fn operation_preview(current: &str, preview: super::release_compatibility::Preview) -> Preview {
    Preview {
        current_version: current.into(),
        candidate_version: Some(preview.candidate_version),
        candidate_sequence: None,
        candidate_format: None,
        evidence: preview.evidence.into(),
        compatible: preview.compatible,
        issues: preview.issues,
        configuration_changed: false,
        integration_reload_required: true,
        service_restart_required: true,
    }
}

/// Explicit network action for an update; rollback preparation is local.
/// Refusals happen before release resolution for managed/admin installations.
pub(crate) fn prepare(id: &str, action: Action) -> Result<OperationView, String> {
    if action == Action::RefreshThreatDb {
        return crate::cli::threatdb_cmd::lifecycle::prepare(id);
    }
    let store = Store::current()?;
    if store.reserve(id, action)?.is_some() {
        return status(id);
    }
    let result = prepare_binary_reserved(id, action, store);
    if result.is_err() {
        let _ = Store::current().and_then(|store| store.fail_preparation(id));
    }
    result
}

fn prepare_binary_reserved(
    id: &str,
    action: Action,
    store: Store,
) -> Result<OperationView, String> {
    let provenance = eligible_binary()?;
    let binary = provenance
        .binary_path
        .clone()
        .ok_or("cannot resolve executable")?;
    let auth = authorization(
        "browser-lifecycle-prepare",
        serde_json::json!({"action":action,"binary":binary,"old_sha256":provenance.binary_sha256}),
        None,
    )?;
    auth.authorize_effect()?;
    let cwd = current_cwd()?;
    let snapshot = policy_snapshot(&cwd)?;
    let old = BinaryIdentity::capture(&binary)?;
    let backup_path = super::previous_backup_path(&binary);
    let backup_sha256 = super::hash_file_opt(&backup_path);
    super::verify_exact_regular_preimage(&backup_path, backup_sha256.as_deref())?;
    let (candidate, preview, candidate_sha256) = match action {
        Action::Update => {
            let latest = super::fetch_latest_version(&auth).map_err(|error| error.message())?;
            let current =
                SemVer::parse(&provenance.version).ok_or("current binary version is invalid")?;
            if latest <= current {
                return Err(format!(
                    "already current: installed {current}, latest published {latest}"
                ));
            }
            let target = provenance
                .target
                .as_deref()
                .ok_or("no published artifact exists for this platform")?;
            let proof = SignedProof::download(&format!("v{latest}"), target, &auth)?;
            let staged = proof.stage(&auth)?;
            let verified = proof.verify(&staged)?;
            let preview = verified.preview(&provenance);
            preview.require_compatible()?;
            let sha256 = verified.binary_sha256().to_string();
            (
                Candidate::Update {
                    proof: Box::new(proof),
                },
                operation_preview(&provenance.version, preview),
                sha256,
            )
        }
        Action::Rollback => {
            let sha256 = backup_sha256
                .as_deref()
                .ok_or("no saved binary is available for rollback")?;
            let verified = VerifiedRollback::load(&binary, sha256)?;
            let preview = verified.preview(&provenance);
            preview.require_compatible()?;
            (
                Candidate::Rollback {
                    receipt_sha256: verified.receipt_sha256().into(),
                },
                operation_preview(&provenance.version, preview),
                sha256.into(),
            )
        }
        Action::RefreshThreatDb => unreachable!(),
    };
    old.revalidate()?;
    snapshot
        .revalidate_for_mutation()
        .map_err(|error| error.to_string())?;
    #[cfg(unix)]
    let archiver = if action == Action::Update {
        Some(BinaryIdentity::capture(
            super::resolve_trusted_tar()?.path(),
        )?)
    } else {
        None
    };
    #[cfg(not(unix))]
    let archiver: Option<BinaryIdentity> = None;
    let plan = BinaryPlan {
        cwd,
        binary,
        old_sha256: old.sha256().into(),
        backup_sha256,
        candidate_sha256,
        channel: super::install_method_token(&provenance).into(),
        archiver_path: archiver.as_ref().map(|guard| guard.path().to_path_buf()),
        archiver_sha256: archiver.as_ref().map(|guard| guard.sha256().to_string()),
        policy: snapshot.private_replay_guard(),
        observed_formats: serde_json::to_value(
            super::lifecycle::gather(&provenance, None)
                .compatibility
                .observed_formats,
        )
        .map_err(|_| "cannot bind local formats")?,
        candidate,
    };
    let retained = Arc::new(Retained::capture(store, &plan)?);
    let mut registry = retained_plans()
        .lock()
        .map_err(|_| "lifecycle registry unavailable")?;
    registry.retain(|id, held| {
        held.store
            .load::<BinaryPlan>(id)
            .map(|operation| operation.phase() != Phase::Prepared || !operation.is_expired())
            .unwrap_or(false)
    });
    if registry.len() >= MAX_RETAINED {
        return Err(
            "too many retained lifecycle previews; cancel unused previews before preparing another"
                .into(),
        );
    }
    auth.authorize_effect()?;
    let operation = retained.store.create(id, action, preview, plan)?;
    registry.insert(operation.id().into(), retained);
    Ok(operation.view())
}

struct StagedProof {
    _directory: tempfile::TempDir,
    release: super::ReleaseSet,
}

impl SignedProof {
    fn download(
        tag: &str,
        target: &str,
        auth: &impl SelfEffectAuthorization,
    ) -> Result<Self, String> {
        let verifier_path = super::cosign_program().ok_or("signed browser updates require a trusted cosign executable; install cosign and prepare again")?;
        let verifier = BinaryIdentity::capture(&verifier_path)?;
        let client = super::http_client(super::API_TIMEOUT_SECS)
            .map_err(|_| "cannot initialize release verification")?;
        let base = format!("https://github.com/{}/releases/download/{tag}", super::REPO);
        let fetch = |name: &str| {
            super::fetch_bytes(
                &client,
                &format!("{base}/{name}"),
                super::MAX_METADATA_SIZE,
                auth,
            )
            .map_err(|error| error.message())
        };
        let checksums = String::from_utf8(fetch("checksums.txt")?)
            .map_err(|_| "release checksums are not UTF-8")?;
        let mut proof = Self {
            tag: tag.into(),
            target: target.into(),
            compatibility: fetch(super::release_compatibility::ASSET)?,
            checksums,
            signature: fetch("checksums.txt.sig")?,
            certificate: fetch("checksums.txt.pem")?,
            archive_sha256: String::new(),
            candidate_sha256: String::new(),
            verifier_path,
            verifier_sha256: verifier.sha256().into(),
        };
        let staged = proof.stage(auth)?;
        let candidate = VerifiedCandidate::verify_with_program(
            &staged.release,
            &proof.compatibility,
            target,
            false,
            Some(verifier.path()),
        )?;
        proof.archive_sha256 = candidate.archive_sha256().into();
        proof.candidate_sha256 = candidate.binary_sha256().into();
        verifier.revalidate()?;
        Ok(proof)
    }

    fn stage(&self, auth: &impl SelfEffectAuthorization) -> Result<StagedProof, String> {
        auth.authorize_effect()?;
        let directory = tempfile::Builder::new()
            .prefix("tirith-lifecycle-proof-")
            .tempdir()
            .map_err(|_| "cannot stage release proof")?;
        let path = directory.path();
        for (name, bytes) in [
            ("checksums.txt", self.checksums.as_bytes()),
            ("checksums.txt.sig", self.signature.as_slice()),
            ("checksums.txt.pem", self.certificate.as_slice()),
        ] {
            super::write_file(&path.join(name), bytes, auth)
                .map_err(|_| "cannot stage signed release evidence")?;
        }
        let release = super::ReleaseSet {
            tag: self.tag.clone(),
            archive_path: path.join(tirith_core::selfupdate::release_archive_name(&self.target)),
            checksums_txt: self.checksums.clone(),
            sig_path: Some(path.join("checksums.txt.sig")),
            cert_path: Some(path.join("checksums.txt.pem")),
            checksums_path: path.join("checksums.txt"),
        };
        Ok(StagedProof {
            _directory: directory,
            release,
        })
    }

    fn verify(&self, staged: &StagedProof) -> Result<VerifiedCandidate, String> {
        let verifier = BinaryIdentity::capture(&self.verifier_path)?;
        if verifier.sha256() != self.verifier_sha256 {
            return Err("signature verifier identity changed; prepare again".into());
        }
        let candidate = VerifiedCandidate::verify_with_program(
            &staged.release,
            &self.compatibility,
            &self.target,
            false,
            Some(verifier.path()),
        )?;
        if candidate.archive_sha256() != self.archive_sha256
            || candidate.binary_sha256() != self.candidate_sha256
        {
            return Err(
                "stored candidate identity differs from its authenticated release proof".into(),
            );
        }
        verifier.revalidate()?;
        Ok(candidate)
    }
}

pub(crate) fn status(id: &str) -> Result<OperationView, String> {
    let store = Store::current()?;
    let view = store.view_any(id)?;
    if matches!(view.phase, Phase::Preparing | Phase::RefreshRequired) {
        return Ok(view);
    }
    let Some(_lock) = store.lock(id)? else {
        return store
            .load::<serde_json::Value>(id)
            .map(|operation| operation.view());
    };
    let mut operation = store.load::<serde_json::Value>(id)?;
    let live = if operation.action() == Action::RefreshThreatDb {
        crate::cli::threatdb_cmd::lifecycle::has_preview(id)
    } else {
        retained_plans()
            .lock()
            .map_err(|_| "lifecycle registry unavailable")?
            .contains_key(id)
    };
    if operation.phase() == Phase::Prepared && (!live || operation.is_expired()) {
        store.transition(&mut operation, Phase::RefreshRequired, false, Some("retained_context_unavailable"), "Original preview context expired or its service ended. Prepare a fresh preview; no publication was authorized.")?;
        retained_plans()
            .lock()
            .map_err(|_| "lifecycle registry unavailable")?
            .remove(id);
        crate::cli::threatdb_cmd::lifecycle::release_preview(id)?;
    } else if matches!(operation.phase(), Phase::Accepted | Phase::Verifying) && !live {
        store.transition(&mut operation, Phase::RefreshRequired, false, Some("worker_stopped_before_publication"), "The worker stopped before publication intent. This operation cannot resume; prepare a fresh preview.")?;
    } else if matches!(
        operation.phase(),
        Phase::PublicationIntent | Phase::Published
    ) {
        let published = operation.view().published;
        store.transition(&mut operation, Phase::RecoveryRequired, published, Some("worker_stopped_during_publication"), "The worker stopped around publication. Inspect the recorded identities and current installation; do not replay this operation or choose another candidate.")?;
    }
    Ok(operation.view())
}

pub(crate) fn cancel(id: &str) -> Result<OperationView, String> {
    let store = Store::current()?;
    let _lock = store
        .lock(id)?
        .ok_or("operation is active; cancellation is unavailable")?;
    let mut operation = store.load::<serde_json::Value>(id)?;
    if operation.phase() != Phase::Prepared {
        return Err(
            "only an unapplied preview can be cancelled; inspect the durable operation status"
                .into(),
        );
    }
    store.transition(
        &mut operation,
        Phase::Cancelled,
        false,
        None,
        "Preview cancelled. Prepare another operation when ready.",
    )?;
    retained_plans()
        .lock()
        .map_err(|_| "lifecycle registry unavailable")?
        .remove(id);
    crate::cli::threatdb_cmd::lifecycle::release_preview(id)?;
    Ok(operation.view())
}

/// Contains retained handles. Never serialize this object into an HTTP reply.
pub(crate) struct AcceptedOperation {
    id: String,
    retained: Arc<Retained>,
}

impl AcceptedOperation {
    pub(crate) fn operation_id(&self) -> &str {
        &self.id
    }
    pub(crate) fn executable(&self) -> &Path {
        self.retained.binary.path()
    }
    pub(crate) fn cwd(&self) -> &Path {
        &self.retained.cwd
    }
    /// Anonymous-pipe only, while this object and its original handles live.
    pub(crate) fn handoff_identity(&self) -> Result<serde_json::Value, String> {
        let operation = self.retained.store.load::<BinaryPlan>(&self.id)?;
        self.retained.handoff_identity(&operation)
    }
    /// Call after the worker returns its independently captured identity and
    /// before sending the final GO message. Parent handles remain alive here.
    pub(crate) fn confirm_worker(&self, evidence: &serde_json::Value) -> Result<(), String> {
        if &self.handoff_identity()? != evidence {
            return Err("worker did not capture the original retained lifecycle objects".into());
        }
        retained_plans()
            .lock()
            .map_err(|_| "lifecycle registry unavailable")?
            .remove(&self.id);
        Ok(())
    }
    /// After a failed child is killed and reaped, retire its unapplied grant.
    pub(crate) fn fail_handoff(&self) -> Result<OperationView, String> {
        let _lock = self
            .retained
            .store
            .lock(&self.id)?
            .ok_or("worker is still active; wait for it before retiring the handoff")?;
        let mut operation = self.retained.store.load::<BinaryPlan>(&self.id)?;
        if operation.phase() != Phase::Accepted {
            return Err("handoff phase changed; inspect its durable status".into());
        }
        self.retained.store.transition(&mut operation, Phase::RefreshRequired, false, Some("worker_handoff_failed"), "The worker did not receive a complete retained-context handoff. No publication was authorized; prepare a fresh preview.")?;
        retained_plans()
            .lock()
            .map_err(|_| "lifecycle registry unavailable")?
            .remove(&self.id);
        Ok(operation.view())
    }
    pub(crate) fn view(&self) -> Result<OperationView, String> {
        Ok(self.retained.store.load::<BinaryPlan>(&self.id)?.view())
    }
}

pub(crate) fn begin_apply(id: &str) -> Result<AcceptedOperation, String> {
    let retained = retained_plans()
        .lock()
        .map_err(|_| "lifecycle registry unavailable")?
        .get(id)
        .cloned()
        .ok_or("the original live preview context is unavailable; prepare a fresh operation")?;
    let _lock = retained
        .store
        .lock(id)?
        .ok_or("this operation already has an active worker")?;
    let mut operation = retained.store.load::<BinaryPlan>(id)?;
    retained.store.require_original_client(&operation)?;
    if operation.phase() != Phase::Prepared || operation.is_expired() {
        return Err("this operation is expired or already accepted; inspect status or prepare a fresh preview".into());
    }
    retained.revalidate(operation.payload())?;
    check_policy(operation.payload())?;
    retained.store.transition(&mut operation, Phase::Accepted, false, None, "Update worker accepted. Keep this operation ID to inspect the result after reopening the dashboard.")?;
    Ok(AcceptedOperation {
        id: id.into(),
        retained,
    })
}

/// Captures its own handles before acknowledging the parent. This object has
/// no mutation method until a final matching parent GO message is consumed.
pub(crate) struct WorkerCapture {
    retained: Retained,
    operation: Operation<BinaryPlan>,
    _lock: crate::cli::setup::fs_helpers::PlatformLock,
}

pub(crate) fn capture_worker(id: &str) -> Result<WorkerCapture, String> {
    let store = Store::current()?;
    let lock = store
        .lock(id)?
        .ok_or("another worker already owns this operation")?;
    let operation = store.load::<BinaryPlan>(id)?;
    store.require_original_client(&operation)?;
    if operation.phase() != Phase::Accepted || operation.is_expired() {
        return Err(
            "worker requires a fresh accepted operation; recorded publication is never replayed"
                .into(),
        );
    }
    let retained = Retained::capture(store, operation.payload())?;
    check_policy(operation.payload())?;
    Ok(WorkerCapture {
        retained,
        operation,
        _lock: lock,
    })
}

impl WorkerCapture {
    pub(crate) fn handoff_identity(&self) -> Result<serde_json::Value, String> {
        self.retained.handoff_identity(&self.operation)
    }
    pub(crate) fn confirm_handoff(
        self,
        parent_evidence: &serde_json::Value,
    ) -> Result<ReadyWorker, String> {
        if &self.handoff_identity()? != parent_evidence {
            return Err("parent lifecycle identity does not match retained worker context".into());
        }
        Ok(ReadyWorker(self))
    }
}

pub(crate) struct ReadyWorker(WorkerCapture);

impl ReadyWorker {
    /// No latest lookup, browser parameter, elevation or candidate execution.
    /// The caller may reopen the dashboard only using resulting_binary after
    /// this method verifies publication and releases the service update guard.
    pub(crate) fn run(mut self) -> Result<WorkerResult, String> {
        let work = &mut self.0;
        work.retained.store.transition(
            &mut work.operation,
            Phase::Verifying,
            false,
            None,
            "Revalidating the exact prepared candidate and local context.",
        )?;
        let result = apply_binary(&work.retained, &mut work.operation);
        match result {
            Ok(result) => Ok(result),
            Err(error) => {
                let _ = work
                    .retained
                    .store
                    .record_failure(work.operation.id(), &error);
                let publication_started = matches!(
                    work.operation.phase(),
                    Phase::PublicationIntent | Phase::Published
                );
                let phase = if publication_started {
                    Phase::RecoveryRequired
                } else {
                    Phase::Failed
                };
                let published = work.operation.view().published;
                work.retained.store.transition(&mut work.operation, phase, published, Some(if publication_started { "publication_requires_inspection" } else { "verification_failed" }), if publication_started { "Inspect the retained binary and operation journal with the originating client. Do not replay this operation; no compensating overwrite was attempted." } else { "The prepared operation stopped before publication. Its private lifecycle record retains a bounded failure diagnostic; prepare a fresh preview after resolving the cause." })?;
                Err(error)
            }
        }
    }
}

/// Trusted local caller only. The path is never a browser response field.
pub(crate) struct WorkerResult {
    pub(crate) view: OperationView,
    pub(crate) resulting_binary: PathBuf,
    pub(crate) resulting_sha256: String,
}

fn apply_binary(
    retained: &Retained,
    operation: &mut Operation<BinaryPlan>,
) -> Result<WorkerResult, String> {
    retained.revalidate(operation.payload())?;
    let policy = check_policy(operation.payload())?;
    let plan = operation.payload();
    let envelope = super::self_boundary_envelope(
        "browser-lifecycle-apply",
        serde_json::json!({"operation_id":operation.id(),"plan_sha256":operation.plan_sha256(),"binary":plan.binary,"old_sha256":plan.old_sha256,"candidate_sha256":plan.candidate_sha256,"backup_sha256":plan.backup_sha256,"updates_privileged_helper":false}),
        Some(&plan.binary),
    )?;
    let provenance = eligible_binary()?;
    // Keep both generic boundary authorizations separate: rollback never gains
    // network effects merely because update uses the same journal backend.
    let update_auth;
    let rollback_auth;
    let auth: &dyn SelfEffectAuthorization = match &plan.candidate {
        Candidate::Update { .. } => {
            update_auth = super::prepare_self_authorization_with_policy::<SelfUpdateBoundary>(
                envelope,
                super::update_effects(false, false),
                &policy.policy.task_gate,
            )?;
            &update_auth
        }
        Candidate::Rollback { .. } => {
            rollback_auth = super::prepare_self_authorization_with_policy::<SelfUpdateBoundary>(
                envelope,
                super::rollback_effects(false),
                &policy.policy.task_gate,
            )?;
            &rollback_auth
        }
    };
    // Adapter gives existing publication primitives a sized authorization while
    // preserving the typed boundary lease selected above.
    struct Auth<'a>(&'a dyn SelfEffectAuthorization);
    impl SelfEffectAuthorization for Auth<'_> {
        fn authorize_effect(&self) -> Result<(), String> {
            self.0.authorize_effect()
        }
    }
    let auth = Auth(auth);
    auth.authorize_effect()?;
    let temp = tempfile::Builder::new()
        .prefix("tirith-lifecycle-update-")
        .tempdir()
        .map_err(|_| "cannot stage prepared update")?;
    let source = match &plan.candidate {
        Candidate::Update { proof } => {
            let staged = proof.stage(&auth)?;
            let verified = proof.verify(&staged)?;
            verified.preview(&provenance).require_compatible()?;
            let name = tirith_core::selfupdate::release_archive_name(&proof.target);
            let url = format!(
                "https://github.com/{}/releases/download/{}/{}",
                super::REPO,
                proof.tag,
                name
            );
            let client = super::http_client(super::DOWNLOAD_TIMEOUT_SECS)
                .map_err(|_| "cannot initialize archive download")?;
            let bytes = super::fetch_bytes(&client, &url, super::MAX_ARCHIVE_SIZE, &auth)
                .map_err(|error| error.message())?;
            if super::hex_sha256(&bytes) != proof.archive_sha256 {
                return Err("downloaded archive differs from the exact signed preview".into());
            }
            let archive = temp.path().join(name);
            super::write_file(&archive, &bytes, &auth)
                .map_err(|_| "cannot stage prepared archive")?;
            let source = super::extract_tirith_binary(&archive, &proof.target, temp.path(), &auth)?;
            super::verify_exact_regular_preimage(&source, Some(&plan.candidate_sha256))?;
            source
        }
        Candidate::Rollback { receipt_sha256 } => {
            let verified = VerifiedRollback::load(&plan.binary, &plan.candidate_sha256)?;
            if verified.receipt_sha256() != receipt_sha256 {
                return Err("rollback compatibility receipt changed after preparation".into());
            }
            verified.preview(&provenance).require_compatible()?;
            super::previous_backup_path(&plan.binary)
        }
    };
    retained.revalidate(plan)?;
    check_policy(plan)?;
    let control = crate::cli::control::quiesce_for_update()?;
    control.revalidate()?;
    retained.revalidate(plan)?;
    check_policy(plan)?;
    auth.authorize_effect()?;
    if matches!(plan.candidate, Candidate::Update { .. }) {
        super::release_compatibility::preserve_current_for_rollback(&provenance, &auth)?;
    }
    let binary = plan.binary.clone();
    let old_sha256 = plan.old_sha256.clone();
    let backup_sha256 = plan.backup_sha256.clone();
    let candidate_sha256 = plan.candidate_sha256.clone();
    let update = matches!(plan.candidate, Candidate::Update { .. });
    retained.store.transition(operation, Phase::PublicationIntent, false, None, "The exact candidate is verified; atomic publication is starting. This operation cannot be replayed.")?;
    control.revalidate()?;
    retained.revalidate(operation.payload())?;
    check_policy(operation.payload())?;
    if update {
        super::atomic_self_replace(
            &binary,
            &source,
            &candidate_sha256,
            &old_sha256,
            backup_sha256.as_deref(),
            &auth,
        )?;
    } else {
        super::atomic_restore_from(&binary, &source, &old_sha256, &candidate_sha256, &auth)?;
    }
    super::verify_exact_regular_preimage(&binary, Some(&candidate_sha256))?;
    retained.store.transition(operation, Phase::Published, true, None, "Verified binary installed. Starting a fresh dashboard is a separate step; shell and host integrations must be reloaded.")?;
    retained.store.transition(operation, Phase::Completed, true, None, "Open the dashboard with the verified installed binary, then open a fresh shell or reload the host and verify protection behavior.")?;
    drop(control);
    Ok(WorkerResult {
        view: operation.view(),
        resulting_binary: binary,
        resulting_sha256: candidate_sha256,
    })
}

/// Internal effect lease for the same personal lifecycle backend's cache work.
/// No browser flags can add resource escalation or bypass this assessment.
pub(crate) struct ThreatDbAuthorization(BinaryAuthorization);
impl ThreatDbAuthorization {
    pub(crate) fn revalidate(&self) -> Result<(), String> {
        self.0.authorize_effect()
    }
}
pub(crate) fn authorize_threatdb(
    kind: &str,
    projection: serde_json::Value,
) -> Result<ThreatDbAuthorization, String> {
    authorization(kind, projection, None).map(ThreatDbAuthorization)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn invalid_browser_operation_ids_never_become_write_paths() {
        assert!(begin_apply("../arbitrary").is_err());
        assert!(begin_apply("00000000-0000-0000-0000-000000000000").is_err());
    }

    #[test]
    fn prepared_candidate_deserialization_forbids_unknown_modes() {
        assert!(serde_json::from_value::<Candidate>(serde_json::json!({"kind":"update","allow_unsigned":true,"url":"https://example.invalid"})).is_err());
        assert!(serde_json::from_value::<Candidate>(
            serde_json::json!({"kind":"command","command":"sudo arbitrary"})
        )
        .is_err());
    }
}
