//! Retained inputs and exact generated-metadata binding for the closed launcher.
//! There is no process launch or generic argv constructor in this module.

use std::ffi::{OsStr, OsString};
use std::sync::Arc;

use base64::Engine as _;
use sha2::Sha512;

use super::*;

pub(super) const USER_CONFIG: &str = "npm-user.npmrc";
pub(super) const GLOBAL_CONFIG: &str = "npm-global.npmrc";

/// A clone of an already-validated retained input. The closed CLI adapter still
/// validates its grammar and seals these exact bytes before target execution.
pub struct NpmExecutionInput {
    pub name: String,
    pub sha256: String,
    pub file: File,
}

struct PinnedInput {
    name: String,
    sha256: String,
    file: File,
    generation: FileGeneration,
}

/// Shared authorization for the effects of one compound preparation. Only the
/// retained constructor creates it; it is not serializable or independently
/// renewable. The checkpoint must compare `target_identity` before creating its
/// private target and retain the lease through the one-shot launch boundary.
pub struct NpmPreparationAuthorization {
    operation_id: String,
    target: PackageTargetIdentity,
    envelope: TaskEnvelopeInput,
    lease: Arc<TaskBoundaryEffectLease<PackageInstallPreparationBoundary>>,
}

impl NpmPreparationAuthorization {
    pub fn operation_id(&self) -> &str {
        &self.operation_id
    }

    pub fn target_identity(&self) -> &PackageTargetIdentity {
        &self.target
    }

    pub fn into_parts(
        self,
    ) -> (
        TaskEnvelopeInput,
        Arc<TaskBoundaryEffectLease<PackageInstallPreparationBoundary>>,
    ) {
        (self.envelope, self.lease)
    }
}

/// All inspection inputs remain retained until the blocking launch and output
/// verification finish. A backend must independently establish full native
/// sealed-input coverage; constructing this value never authorizes execution.
pub struct PreparedNpmExecution<'a> {
    plan: &'a NpmInstallPlan,
    artifacts: &'a [VerifiedNpmArtifact],
    policy: &'a EffectivePolicySnapshot,
    staged: StagedNpmInputs,
    tools: tools::QualifiedNpmToolClosure,
    pins: Vec<PinnedInput>,
    layout: Option<BoundLayout>,
    checkpoint_authorization_issued: bool,
    resume_authorized: bool,
}

struct BoundLayout {
    staging: DirCapability,
    staging_identity: (u64, u64),
    target: DirCapability,
    target_file: File,
    target_identity: (u64, u64),
    target_operand: OsString,
    expected_lock: Value,
}

impl<'a> PreparedNpmExecution<'a> {
    pub fn capture(
        plan: &'a NpmInstallPlan,
        artifacts: &'a [VerifiedNpmArtifact],
        policy: &'a EffectivePolicySnapshot,
        staged: StagedNpmInputs,
        tools: tools::QualifiedNpmToolClosure,
    ) -> Result<Self> {
        plan.revalidate(artifacts, policy)?;
        tools.revalidate()?;
        if staged.transaction.id() != plan.id {
            return Err(NpmInstallRefusal::JournalConflict);
        }
        staged
            .lease
            .authorize_effect_at(&plan.operation(), Utc::now())
            .map_err(|_| NpmInstallRefusal::AuthorizationRefused)?;
        staged.revalidate_identity()?;
        let pack = tools.runtime_pack()?;
        staged
            .transaction
            .write_control_file_atomic_0600(runtime_pack::FILE_NAME, pack)
            .map_err(|_| NpmInstallRefusal::QuarantineUnavailable)?;
        let mut specs: Vec<_> = artifacts
            .iter()
            .map(|artifact| {
                (
                    format!("npm-{}.tgz", artifact.sha256()),
                    artifact.sha256().to_owned(),
                    artifact.compressed.len() as u64,
                )
            })
            .collect();
        for name in [USER_CONFIG, GLOBAL_CONFIG] {
            specs.push((name.into(), digest(b""), 0));
        }
        specs.push((
            runtime_pack::FILE_NAME.into(),
            digest(pack),
            pack.len() as u64,
        ));
        let files = staged
            .transaction
            .pin_files_for_launch(specs.iter().map(|(name, _, _)| name.as_str()))
            .map_err(|_| NpmInstallRefusal::InputUnavailable)?;
        if files.len() != specs.len() {
            return Err(NpmInstallRefusal::NativeExecutionUnqualified);
        }
        let mut pins = Vec::with_capacity(files.len());
        for (file, (name, sha256, size)) in files.into_iter().zip(specs) {
            let generation = file_generation(&file).map_err(|_| NpmInstallRefusal::InputChanged)?;
            if generation.links != 1 || generation.size != size {
                return Err(NpmInstallRefusal::InputChanged);
            }
            let input = PinnedInput {
                name,
                sha256,
                file,
                generation,
            };
            input.revalidate()?;
            pins.push(input);
        }
        let prepared = Self {
            plan,
            artifacts,
            policy,
            staged,
            tools,
            pins,
            layout: None,
            checkpoint_authorization_issued: false,
            resume_authorized: false,
        };
        prepared.revalidate()?;
        Ok(prepared)
    }

    pub fn program(&self) -> Result<&crate::trusted_child::TrustedExecutable> {
        self.tools.program()
    }

    pub fn entrypoint(&self) -> &Path {
        self.tools.entrypoint()
    }

    pub fn read_roots(&self) -> Vec<PathBuf> {
        self.tools.read_roots()
    }

    pub fn target_policy_path(&self) -> PathBuf {
        self.plan
            .destination
            .parent
            .path()
            .join(&self.plan.destination.component)
    }

    pub fn clone_inputs(&self) -> Result<Vec<NpmExecutionInput>> {
        self.revalidate()?;
        self.pins
            .iter()
            .map(|input| {
                Ok(NpmExecutionInput {
                    name: input.name.clone(),
                    sha256: input.sha256.clone(),
                    file: input
                        .file
                        .try_clone()
                        .map_err(|_| NpmInstallRefusal::InputChanged)?,
                })
            })
            .collect()
    }

    pub fn checkpoint_authorization(&mut self) -> Result<NpmPreparationAuthorization> {
        if self.checkpoint_authorization_issued {
            return Err(NpmInstallRefusal::ExecutionStateConflict);
        }
        self.revalidate()?;
        self.checkpoint_authorization_issued = true;
        Ok(NpmPreparationAuthorization {
            operation_id: self.plan.id.clone(),
            target: self.plan.destination.task_identity(),
            envelope: self.plan.envelope.clone(),
            lease: Arc::clone(&self.staged.lease),
        })
    }

    /// Called before staging and again at the guarded target-resume boundary.
    /// No network or subprocess is used to recapture unavailable evidence.
    pub fn revalidate(&self) -> Result<()> {
        self.revalidate_sources()?;
        if let Some(layout) = &self.layout {
            layout.revalidate()?;
        }
        Ok(())
    }

    fn revalidate_sources(&self) -> Result<()> {
        self.plan.revalidate(self.artifacts, self.policy)?;
        self.tools.revalidate()?;
        self.staged.revalidate_identity()?;
        self.staged
            .lease
            .authorize_effect_at(&self.plan.operation(), Utc::now())
            .map_err(|_| NpmInstallRefusal::AuthorizationRefused)?;
        for input in &self.pins {
            input.revalidate()?;
        }
        Ok(())
    }

    /// The closed launcher supplies its actual retained directory identities
    /// and reserved FD operand after final descriptor allocation. Exact metadata
    /// is derived from these values, not from a saved report or browser path.
    pub fn bind_layout(
        &mut self,
        staging_root: &Path,
        target_operand: &OsStr,
        target_visible_root: &Path,
        target_identity: (u64, u64),
    ) -> Result<()> {
        if self.layout.is_some() || self.resume_authorized {
            return Err(NpmInstallRefusal::ExecutionStateConflict);
        }
        self.revalidate()?;
        validate_target_operand(target_operand)?;
        let staging = canonical_directory(staging_root)?;
        let target = canonical_directory(target_visible_root)?;
        if target.identity().map_err(layout_error)? != target_identity {
            return Err(NpmInstallRefusal::DestinationChanged);
        }
        let staging_identity = staging.identity().map_err(layout_error)?;
        let target_file = File::open(Path::new(target_operand)).map_err(layout_error)?;
        if file_identity(&target_file).map_err(layout_error)? != target_identity {
            return Err(NpmInstallRefusal::DestinationChanged);
        }
        let expected_lock = expected_hidden_lock(
            self.artifacts,
            staging_root,
            Path::new(target_operand),
            target_visible_root,
        )?;
        let layout = BoundLayout {
            staging,
            staging_identity,
            target,
            target_file,
            target_identity,
            target_operand: target_operand.to_owned(),
            expected_lock,
        };
        layout.revalidate()?;
        self.write_phase(PreparationPhase::LayoutBound)?;
        self.layout = Some(layout);
        Ok(())
    }

    /// Must run after TARGET_EXEC_OBSERVED and before ACK_RESUME. Even a rejected
    /// attempt leaves durable recovery evidence and cannot silently retry npm.
    pub fn before_target_resume(&mut self) -> Result<()> {
        if self.layout.is_none() || self.resume_authorized {
            return Err(NpmInstallRefusal::ExecutionStateConflict);
        }
        self.revalidate()?;
        self.write_phase(PreparationPhase::LaunchAccepted)?;
        self.resume_authorized = true;
        Ok(())
    }

    /// The CLI must first establish a successful, quiescent contained outcome.
    /// This checks every installed byte and the complete generated lock value;
    /// its result still has to be revalidated at checkpoint publication.
    pub fn verify_output(&self) -> Result<VerifiedNpmTree> {
        if !self.resume_authorized {
            return Err(NpmInstallRefusal::ExecutionStateConflict);
        }
        self.revalidate_sources()?;
        let layout = self.layout.as_ref().expect("resume requires layout");
        layout.revalidate_target()?;
        let modules = layout
            .target
            .open_child_directory("node_modules")
            .map_err(|_| NpmInstallRefusal::InstalledContentChanged)?;
        let mut file = modules
            .open_child_file(".package-lock.json", metadata::MAX_HIDDEN_LOCK_BYTES as u64)
            .map_err(|_| NpmInstallRefusal::InstalledContentChanged)?;
        let before =
            file_generation(&file).map_err(|_| NpmInstallRefusal::InstalledContentChanged)?;
        let mut bytes = Vec::new();
        (&mut file)
            .take(metadata::MAX_HIDDEN_LOCK_BYTES as u64 + 1)
            .read_to_end(&mut bytes)
            .map_err(|_| NpmInstallRefusal::InstalledContentChanged)?;
        metadata::verify_hidden_lock(&bytes, &layout.expected_lock)?;
        if file_generation(&file).map_err(|_| NpmInstallRefusal::InstalledContentChanged)? != before
        {
            return Err(NpmInstallRefusal::InstalledContentChanged);
        }
        let mut expected = self.plan.expected.clone();
        expected.insert(
            "node_modules/.package-lock.json".into(),
            NpmFile {
                path: "node_modules/.package-lock.json".into(),
                size: bytes.len() as u64,
                sha256: digest(&bytes),
                executable: false,
                kind: NpmFileKind::Metadata,
            },
        );
        let retained = layout.target_file.try_clone().map_err(layout_error)?;
        verify_tree(layout.target.path(), &retained, &expected)?;
        self.write_phase(PreparationPhase::Verified)?;
        let runtime_pack = self
            .pins
            .iter()
            .find(|pin| pin.name == runtime_pack::FILE_NAME)
            .ok_or(NpmInstallRefusal::ToolClosureChanged)?;
        let npm_receipt = receipt_evidence::NpmVerificationSummary::from_verified(
            self.plan,
            &runtime_pack.sha256,
            &expected,
        )?;
        Ok(VerifiedNpmTree {
            visible: layout.target.path().into(),
            retained,
            expected,
            npm_receipt: Some(npm_receipt),
        })
    }

    /// Recheck the exact verified tree immediately before the shared checkpoint
    /// publishes it. The launcher may already have removed its sealed staging
    /// namespace and reserved numeric FD; neither is re-opened after execution.
    pub fn revalidate_for_publication(&self, verified: &VerifiedNpmTree) -> Result<()> {
        if !self.resume_authorized {
            return Err(NpmInstallRefusal::ExecutionStateConflict);
        }
        self.revalidate_sources()?;
        let layout = self
            .layout
            .as_ref()
            .ok_or(NpmInstallRefusal::ExecutionStateConflict)?;
        layout.revalidate_target()?;
        if verified.visible != layout.target.path()
            || file_identity(&verified.retained).map_err(layout_error)? != layout.target_identity
        {
            return Err(NpmInstallRefusal::DestinationChanged);
        }
        let pack = self
            .pins
            .iter()
            .find(|pin| pin.name == runtime_pack::FILE_NAME)
            .ok_or(NpmInstallRefusal::ToolClosureChanged)?;
        let expected_summary = receipt_evidence::NpmVerificationSummary::from_verified(
            self.plan,
            &pack.sha256,
            &verified.expected,
        )?;
        if verified.npm_receipt.as_ref() != Some(&expected_summary) {
            return Err(NpmInstallRefusal::ExecutionStateConflict);
        }
        verified.revalidate()
    }

    fn write_phase(&self, phase: PreparationPhase) -> Result<()> {
        self.revalidate_sources()?;
        let record = PreparationRecord {
            schema: 1,
            contract: CONTRACT.into(),
            operation_id: self.plan.id.clone(),
            plan_digest: self.plan.digest.clone(),
            phase,
        };
        self.staged
            .transaction
            .write_control_file_atomic_0600(
                JOURNAL_NAME,
                &serde_json::to_vec(&record).map_err(|_| NpmInstallRefusal::RecoveryRequired)?,
            )
            .map(|_| ())
            .map_err(|_| NpmInstallRefusal::QuarantineUnavailable)
    }
}

fn layout_error<T>(_: T) -> NpmInstallRefusal {
    NpmInstallRefusal::ExecutionLayoutUnsupported
}

fn canonical_directory(path: &Path) -> Result<DirCapability> {
    if !path.is_absolute() || path.to_str().is_none() || path.as_os_str().len() > 4096 {
        return Err(NpmInstallRefusal::ExecutionLayoutUnsupported);
    }
    if path.canonicalize().map_err(layout_error)? != path {
        return Err(NpmInstallRefusal::ExecutionLayoutUnsupported);
    }
    DirCapability::open_root(path).map_err(layout_error)
}

fn validate_target_operand(operand: &OsStr) -> Result<()> {
    let descriptor = operand
        .to_str()
        .and_then(|path| path.strip_prefix("/proc/self/fd/"))
        .ok_or(NpmInstallRefusal::ExecutionLayoutUnsupported)?;
    if descriptor.is_empty()
        || descriptor.starts_with('0')
        || !descriptor.bytes().all(|byte| byte.is_ascii_digit())
        || !descriptor
            .parse::<u32>()
            .is_ok_and(|fd| (3..=1_048_575).contains(&fd))
    {
        return Err(NpmInstallRefusal::ExecutionLayoutUnsupported);
    }
    Ok(())
}

impl BoundLayout {
    fn revalidate_target(&self) -> Result<()> {
        if canonical_directory(self.target.path())?
            .identity()
            .map_err(layout_error)?
            != self.target_identity
            || self.target.identity().map_err(layout_error)? != self.target_identity
            || file_identity(&self.target_file).map_err(layout_error)? != self.target_identity
        {
            return Err(NpmInstallRefusal::DestinationChanged);
        }
        Ok(())
    }

    fn revalidate(&self) -> Result<()> {
        for (directory, expected) in [
            (&self.staging, self.staging_identity),
            (&self.target, self.target_identity),
        ] {
            if canonical_directory(directory.path())?
                .identity()
                .map_err(layout_error)?
                != expected
                || directory.identity().map_err(layout_error)? != expected
            {
                return Err(NpmInstallRefusal::DestinationChanged);
            }
        }
        // Reserved descriptors are retained in the calling launcher process;
        // the visible /proc alias must still identify its held target as well.
        let target = File::open(Path::new(&self.target_operand)).map_err(layout_error)?;
        if file_identity(&target).map_err(layout_error)? != self.target_identity {
            return Err(NpmInstallRefusal::DestinationChanged);
        }
        Ok(())
    }
}

impl PinnedInput {
    fn revalidate(&self) -> Result<()> {
        if file_generation(&self.file).map_err(|_| NpmInstallRefusal::InputChanged)?
            != self.generation
        {
            return Err(NpmInstallRefusal::InputChanged);
        }
        let mut file = self
            .file
            .try_clone()
            .map_err(|_| NpmInstallRefusal::InputChanged)?;
        file.seek(SeekFrom::Start(0))
            .map_err(|_| NpmInstallRefusal::InputChanged)?;
        let (size, hash) = hash_reader(file.take(self.generation.size + 1))
            .map_err(|_| NpmInstallRefusal::InputChanged)?;
        if size != self.generation.size
            || hash != self.sha256
            || file_generation(&self.file).map_err(|_| NpmInstallRefusal::InputChanged)?
                != self.generation
        {
            return Err(NpmInstallRefusal::InputChanged);
        }
        Ok(())
    }
}

fn expected_hidden_lock(
    artifacts: &[VerifiedNpmArtifact],
    staging: &Path,
    target_operand: &Path,
    target: &Path,
) -> Result<Value> {
    let mut packages = serde_json::Map::new();
    for artifact in artifacts {
        let installed = target.join("node_modules").join(&artifact.leaf.name);
        let source = staging.join(format!("npm-{}.tgz", artifact.sha256()));
        let integrity = format!(
            "sha512-{}",
            base64::engine::general_purpose::STANDARD.encode(Sha512::digest(&artifact.compressed))
        );
        packages.insert(
            relative_posix(target_operand, &installed)?,
            metadata::leaf_row(
                &artifact.leaf.version,
                &integrity,
                &format!("file:{}", relative_posix(target_operand, &source)?),
                &artifact.leaf.manager_metadata,
            ),
        );
    }
    let lock = serde_json::json!({"lockfileVersion":3,"requires":true,"packages":packages});
    if serde_json::to_vec(&lock).map_err(layout_error)?.len() > metadata::MAX_HIDDEN_LOCK_BYTES {
        return Err(NpmInstallRefusal::ResourceLimit);
    }
    Ok(lock)
}

// Node path.relative is lexical; npm's FD prefix remains the lockfile base even
// though installed package realpaths name the retained private target. All
// inputs here are absolute canonical POSIX paths or the exact validated FD path.
fn relative_posix(from: &Path, to: &Path) -> Result<String> {
    let from = from
        .to_str()
        .filter(|p| p.starts_with('/'))
        .ok_or(NpmInstallRefusal::ExecutionLayoutUnsupported)?;
    let to = to
        .to_str()
        .filter(|p| p.starts_with('/'))
        .ok_or(NpmInstallRefusal::ExecutionLayoutUnsupported)?;
    let from: Vec<_> = from.split('/').filter(|p| !p.is_empty()).collect();
    let to: Vec<_> = to.split('/').filter(|p| !p.is_empty()).collect();
    if from
        .iter()
        .chain(&to)
        .any(|part| matches!(*part, "." | ".."))
    {
        return Err(NpmInstallRefusal::ExecutionLayoutUnsupported);
    }
    let common = from.iter().zip(&to).take_while(|(a, b)| a == b).count();
    Ok(std::iter::repeat_n("..", from.len() - common)
        .chain(to[common..].iter().copied())
        .collect::<Vec<_>>()
        .join("/"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exact_fd_layout_matches_characterized_npm_1119_paths() {
        let prefix = Path::new("/proc/self/fd/17");
        assert_eq!(
            relative_posix(
                prefix,
                Path::new("/tmp/fixture/staging/target/node_modules/leaf")
            )
            .unwrap(),
            "../../../../tmp/fixture/staging/target/node_modules/leaf"
        );
        assert_eq!(
            relative_posix(prefix, Path::new("/tmp/fixture/staging/npm-a.tgz")).unwrap(),
            "../../../../tmp/fixture/staging/npm-a.tgz"
        );
        assert_ne!(
            relative_posix(prefix, Path::new("/tmp/fixture/staging/npm-a.tgz")).unwrap(),
            "../npm-a.tgz"
        );
    }

    #[test]
    fn target_operand_refuses_wrappers_aliases_and_unreserved_standard_fds() {
        for value in [
            "/proc/self/fd/0",
            "/proc/self/fd/02",
            "/proc/self/fd/3/",
            "/proc/self/fd/3/..",
            "/dev/fd/3",
            "/proc/self/fd/999999999999",
        ] {
            assert!(
                validate_target_operand(OsStr::new(value)).is_err(),
                "{value}"
            );
        }
        assert!(validate_target_operand(OsStr::new("/proc/self/fd/17")).is_ok());
    }
}
