//! LocalLeafNoScriptsV1 preparation and verification foundations.
//!
//! This module never launches npm. A retained artifact and a successful static
//! review cannot stand in for a qualified tool closure, a native capsule, or a
//! PackageInstallPreparation permit. The execution qualification table remains
//! closed until the complete launcher contract has native acceptance evidence.

use std::collections::{BTreeMap, BTreeSet};
use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::path::{Component, Path, PathBuf};

use chrono::Utc;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};

use super::npm_archive::{self, NpmArchiveState, NpmFile, NpmFileKind, NpmInspection, NpmLimits};
use super::quarantine::{QuarantineStore, QuarantineTransaction};
use super::resolver::ResolverRequest;
use crate::policy_snapshot::{EffectivePolicySnapshot, PrivatePolicyReplayGuard};
use crate::task::{IngressAdapter, TaskEnvelopeInput};
use crate::task_boundary::{
    self, BoundaryOperation, OwnedBoundary, PackageInstallPreparationBoundary,
    PackageOperationBinding, PackageTargetIdentity, TaskBoundaryEffectLease, TaskBoundaryPermit,
};
use crate::util::dirfd::{
    file_generation, file_identity, DirCapability, EntryKind, FileGeneration,
};

#[path = "npm_install_execution.rs"]
mod execution;
#[path = "npm_install_metadata.rs"]
mod metadata;
#[path = "npm_install_receipt.rs"]
pub mod receipt_evidence;
#[path = "npm_install_runtime_pack.rs"]
pub mod runtime_pack;
#[path = "npm_install_tools.rs"]
pub mod tools;
pub use execution::{NpmExecutionInput, NpmPreparationAuthorization, PreparedNpmExecution};

pub const CONTRACT: &str = "LocalLeafNoScriptsV1";
pub const MAX_ARTIFACTS: usize = 8;
pub const MAX_TOTAL_COMPRESSED_BYTES: usize = 64 * 1024 * 1024;
pub const MAX_TOTAL_INSTALLED_BYTES: u64 = 128 * 1024 * 1024;
pub const MAX_INSTALLED_ENTRIES: usize = 20_000;
const JOURNAL_NAME: &str = "npm-preparation.json";
const JOURNAL_CAP: u64 = 64 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum NpmInstallRefusal {
    InputUnavailable,
    InputChanged,
    ArchiveUnsupported,
    ManifestUnsupported,
    DependencyGraphUnsupported,
    EmbeddedDependencies,
    EmbeddedResolutionMetadata,
    PackageIdentityUnsupported,
    ResourceLimit,
    DuplicatePackage,
    DestinationUnavailable,
    DestinationChanged,
    PolicyChanged,
    AuthorizationRefused,
    QuarantineUnavailable,
    RecoveryRequired,
    JournalConflict,
    InvalidOperationId,
    UnexpectedInstalledEntry,
    InstalledContentChanged,
    NativeExecutionUnqualified,
    ToolClosureUnsupported,
    ToolClosureChanged,
    ExecutionLayoutUnsupported,
    ExecutionStateConflict,
}

type Result<T> = std::result::Result<T, NpmInstallRefusal>;

fn digest(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

fn hash_reader(mut reader: impl Read) -> std::io::Result<(u64, String)> {
    let mut hasher = Sha256::new();
    let mut bytes = 0u64;
    let mut buffer = [0u8; 64 * 1024];
    loop {
        let read = reader.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        bytes += read as u64;
        hasher.update(&buffer[..read]);
    }
    Ok((bytes, hex::encode(hasher.finalize())))
}

/// Private retained bytes, complete manifest capture and native generation.
/// There is deliberately no serde constructor, Clone or public field setter.
pub struct VerifiedNpmArtifact {
    source: File,
    generation: FileGeneration,
    compressed: Vec<u8>,
    inspection: NpmInspection,
    leaf: LeafManifest,
}

#[derive(Clone, Serialize)]
struct LeafManifest {
    name: String,
    version: String,
    manifest_sha256: String,
    /// Presence is preserved, even when the supported value is empty/false.
    dependency_fields: BTreeMap<String, Value>,
    manager_metadata: BTreeMap<String, Value>,
}

impl VerifiedNpmArtifact {
    pub fn open(path: &Path) -> Result<Self> {
        let file = crate::util::open_read_no_follow_capped(
            path,
            NpmLimits::default().compressed_bytes as u64,
        )
        .map_err(|_| NpmInstallRefusal::InputUnavailable)?;
        Self::capture(file)
    }

    /// The caller transfers ownership of the exact regular-file handle. The
    /// source pathname is never reopened to compute an identity or stage bytes.
    pub fn capture(mut source: File) -> Result<Self> {
        if !source
            .metadata()
            .map_err(|_| NpmInstallRefusal::InputUnavailable)?
            .is_file()
        {
            return Err(NpmInstallRefusal::InputUnavailable);
        }
        let generation =
            file_generation(&source).map_err(|_| NpmInstallRefusal::InputUnavailable)?;
        let cap = NpmLimits::default().compressed_bytes;
        if generation.size > cap as u64 {
            return Err(NpmInstallRefusal::ResourceLimit);
        }
        source
            .seek(SeekFrom::Start(0))
            .map_err(|_| NpmInstallRefusal::InputUnavailable)?;
        let mut compressed = Vec::new();
        (&mut source)
            .take(cap as u64 + 1)
            .read_to_end(&mut compressed)
            .map_err(|_| NpmInstallRefusal::InputUnavailable)?;
        if compressed.len() > cap {
            return Err(NpmInstallRefusal::ResourceLimit);
        }
        if file_generation(&source).map_err(|_| NpmInstallRefusal::InputChanged)? != generation {
            return Err(NpmInstallRefusal::InputChanged);
        }
        // Narrow parser seam: the manifest comes from the SAME validated tar
        // member traversal. A public/deserialized inspection is never authority.
        let (inspection, manifest) = npm_archive::read_npm_tarball_with_manifest(
            compressed.as_slice(),
            "retained-local-artifact.tgz",
            &NpmLimits::default(),
        );
        if inspection.archive_state != NpmArchiveState::Accepted
            || !inspection.coverage.archive_complete
            || !inspection.coverage.metadata_complete
            || inspection.artifact.sha256.as_deref() != Some(digest(&compressed).as_str())
        {
            return Err(NpmInstallRefusal::ArchiveUnsupported);
        }
        let leaf = LeafManifest::capture(
            &manifest.ok_or(NpmInstallRefusal::ManifestUnsupported)?,
            &inspection,
        )?;
        Ok(Self {
            source,
            generation,
            compressed,
            inspection,
            leaf,
        })
    }

    pub fn inspection(&self) -> &NpmInspection {
        &self.inspection
    }

    pub fn revalidate(&self) -> Result<()> {
        if file_generation(&self.source).map_err(|_| NpmInstallRefusal::InputChanged)?
            != self.generation
        {
            return Err(NpmInstallRefusal::InputChanged);
        }
        let mut source = self
            .source
            .try_clone()
            .map_err(|_| NpmInstallRefusal::InputChanged)?;
        source
            .seek(SeekFrom::Start(0))
            .map_err(|_| NpmInstallRefusal::InputChanged)?;
        let (copied, actual) = hash_reader(source.take(self.compressed.len() as u64 + 1))
            .map_err(|_| NpmInstallRefusal::InputChanged)?;
        if copied != self.compressed.len() as u64
            || actual != self.sha256()
            || file_generation(&self.source).map_err(|_| NpmInstallRefusal::InputChanged)?
                != self.generation
        {
            return Err(NpmInstallRefusal::InputChanged);
        }
        Ok(())
    }

    fn sha256(&self) -> &str {
        self.inspection
            .artifact
            .sha256
            .as_deref()
            .expect("validated capture")
    }
}

impl LeafManifest {
    fn capture(bytes: &[u8], inspection: &NpmInspection) -> Result<Self> {
        let text =
            std::str::from_utf8(bytes).map_err(|_| NpmInstallRefusal::ManifestUnsupported)?;
        let value = crate::mcp_lock::parse_json_no_duplicates(text)
            .map_err(|_| NpmInstallRefusal::ManifestUnsupported)?;
        let object = value
            .as_object()
            .ok_or(NpmInstallRefusal::ManifestUnsupported)?;
        let name = object
            .get("name")
            .and_then(Value::as_str)
            .ok_or(NpmInstallRefusal::PackageIdentityUnsupported)?;
        let version = object
            .get("version")
            .and_then(Value::as_str)
            .ok_or(NpmInstallRefusal::PackageIdentityUnsupported)?;
        if !valid_package_name(name)
            || !valid_version(version)
            || inspection.artifact.name.as_deref() != Some(name)
            || inspection.artifact.version.as_deref() != Some(version)
        {
            return Err(NpmInstallRefusal::PackageIdentityUnsupported);
        }
        let mut dependency_fields = BTreeMap::new();
        for field in [
            "dependencies",
            "optionalDependencies",
            "peerDependencies",
            "peerDependenciesMeta",
            "acceptDependencies",
            "overrides",
            "resolutions",
        ] {
            if let Some(value) = object.get(field) {
                if !value.as_object().is_some_and(|map| map.is_empty()) {
                    return Err(NpmInstallRefusal::DependencyGraphUnsupported);
                }
                dependency_fields.insert(field.into(), value.clone());
            }
        }
        for field in ["bundledDependencies", "bundleDependencies", "workspaces"] {
            if let Some(value) = object.get(field) {
                let empty = value.as_array().is_some_and(Vec::is_empty)
                    || (field != "workspaces" && value == &Value::Bool(false));
                if !empty {
                    return Err(NpmInstallRefusal::DependencyGraphUnsupported);
                }
                dependency_fields.insert(field.into(), value.clone());
            }
        }
        // Development dependencies are captured as exact bytes by the manifest
        // digest, but never selected by this contract's generated root manifest.
        if object
            .get("devDependencies")
            .is_some_and(|value| !value.is_object())
        {
            return Err(NpmInstallRefusal::ManifestUnsupported);
        }
        for field in object.keys() {
            if field.starts_with('_') || field == "hasInstallScript" {
                return Err(NpmInstallRefusal::ManifestUnsupported);
            }
        }
        if inspection
            .files
            .iter()
            .any(|file| file.path.split('/').any(|part| part == "node_modules"))
        {
            return Err(NpmInstallRefusal::EmbeddedDependencies);
        }
        if inspection.files.iter().any(|file| {
            matches!(
                file.path.rsplit('/').next(),
                Some("npm-shrinkwrap.json" | "package-lock.json" | ".npmrc")
            )
        }) {
            return Err(NpmInstallRefusal::EmbeddedResolutionMetadata);
        }
        Ok(Self {
            name: name.into(),
            version: version.into(),
            manifest_sha256: digest(bytes),
            dependency_fields,
            manager_metadata: metadata::capture_leaf_metadata(object, name)?,
        })
    }
}

fn valid_package_name(name: &str) -> bool {
    fn component(value: &str) -> bool {
        !value.is_empty()
            && value != "node_modules"
            && value != "favicon.ico"
            && value.as_bytes()[0].is_ascii_alphanumeric()
            && value.bytes().all(|byte| {
                byte.is_ascii_lowercase() || byte.is_ascii_digit() || b"._-".contains(&byte)
            })
    }
    if name.len() > 214 {
        return false;
    }
    if let Some(scoped) = name.strip_prefix('@') {
        scoped
            .split_once('/')
            .is_some_and(|(scope, name)| component(scope) && component(name))
    } else {
        component(name)
    }
}

fn valid_version(version: &str) -> bool {
    if version.is_empty() || version.len() > 128 || !version.is_ascii() {
        return false;
    }
    let (without_build, build) = version
        .split_once('+')
        .map_or((version, None), |(left, right)| (left, Some(right)));
    let (core, pre) = without_build
        .split_once('-')
        .map_or((without_build, None), |(left, right)| (left, Some(right)));
    let number = |part: &str| {
        !part.is_empty()
            && part.bytes().all(|byte| byte.is_ascii_digit())
            && (part.len() == 1 || !part.starts_with('0'))
    };
    let components: Vec<_> = core.split('.').collect();
    if components.len() != 3 || !components.iter().all(|part| number(part)) {
        return false;
    }
    for (part, prerelease) in [(pre, true), (build, false)] {
        if let Some(part) = part {
            if !part.split('.').all(|id| {
                !id.is_empty()
                    && id
                        .bytes()
                        .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
                    && (!prerelease || !id.bytes().all(|byte| byte.is_ascii_digit()) || number(id))
            }) {
                return false;
            }
        }
    }
    true
}

/// A new destination reserved by a retained parent handle. This does not create
/// the destination and is not a path-based overwrite capability.
pub struct NewNpmDestination {
    parent: DirCapability,
    identity: (u64, u64),
    component: String,
}

impl NewNpmDestination {
    pub fn capture(path: &Path) -> Result<Self> {
        if !path.is_absolute()
            || path
                .components()
                .any(|part| matches!(part, Component::ParentDir))
        {
            return Err(NpmInstallRefusal::DestinationUnavailable);
        }
        let component = path
            .file_name()
            .and_then(|name| name.to_str())
            .filter(|name| {
                !name.is_empty()
                    && name.len() <= 200
                    && !name.contains(['/', '\\', ':'])
                    && *name != "."
                    && *name != ".."
            })
            .ok_or(NpmInstallRefusal::DestinationUnavailable)?
            .to_owned();
        let parent_path = path
            .parent()
            .ok_or(NpmInstallRefusal::DestinationUnavailable)?
            .canonicalize()
            .map_err(|_| NpmInstallRefusal::DestinationUnavailable)?;
        // The shared checkpoint binds this same canonical parent. The original
        // alias never becomes a later publication or authorization operand.
        let parent = DirCapability::open_root(&parent_path)
            .map_err(|_| NpmInstallRefusal::DestinationUnavailable)?;
        let identity = parent
            .identity()
            .map_err(|_| NpmInstallRefusal::DestinationUnavailable)?;
        let result = Self {
            parent,
            identity,
            component,
        };
        result.revalidate()?;
        Ok(result)
    }

    pub fn revalidate(&self) -> Result<()> {
        let visible = DirCapability::open_root(self.parent.path())
            .map_err(|_| NpmInstallRefusal::DestinationChanged)?;
        if visible
            .identity()
            .map_err(|_| NpmInstallRefusal::DestinationChanged)?
            != self.identity
        {
            return Err(NpmInstallRefusal::DestinationChanged);
        }
        let (entries, truncated) = self
            .parent
            .read_entries(MAX_INSTALLED_ENTRIES)
            .map_err(|_| NpmInstallRefusal::DestinationChanged)?;
        if truncated
            || entries
                .iter()
                .any(|entry| entry.name.as_deref() == Some(self.component.as_str()))
        {
            return Err(NpmInstallRefusal::DestinationChanged);
        }
        Ok(())
    }

    fn task_identity(&self) -> PackageTargetIdentity {
        let path = self.parent.path().join(&self.component);
        #[cfg(target_os = "linux")]
        let parent_identity = format!("linux-devino-v1:{}:{}", self.identity.0, self.identity.1);
        #[cfg(not(target_os = "linux"))]
        let parent_identity = "unsupported".to_owned();
        PackageTargetIdentity::new(
            digest(path.as_os_str().as_encoded_bytes()),
            parent_identity,
            &self.component,
        )
    }
}

/// A private, immutable preparation binding. It is intentionally not a saved
/// inspection report and does not claim native execution qualification.
pub struct NpmInstallPlan {
    id: String,
    policy_guard: PrivatePolicyReplayGuard,
    digest: String,
    envelope: TaskEnvelopeInput,
    artifacts: Vec<(String, LeafManifest)>,
    expected: BTreeMap<String, NpmFile>,
    destination: NewNpmDestination,
}

impl NpmInstallPlan {
    pub fn prepare(
        id: &str,
        artifacts: &[VerifiedNpmArtifact],
        destination: NewNpmDestination,
        policy: &EffectivePolicySnapshot,
        threat_generation: &str,
    ) -> Result<Self> {
        let id = uuid::Uuid::parse_str(id)
            .map_err(|_| NpmInstallRefusal::InvalidOperationId)?
            .to_string();
        if artifacts.is_empty() || artifacts.len() > MAX_ARTIFACTS || threat_generation.len() > 256
        {
            return Err(NpmInstallRefusal::ResourceLimit);
        }
        policy
            .revalidate_for_mutation()
            .map_err(|_| NpmInstallRefusal::PolicyChanged)?;
        destination.revalidate()?;
        let mut names = BTreeSet::new();
        let mut compressed = 0usize;
        let mut total = 0u64;
        let mut expected = BTreeMap::new();
        for artifact in artifacts {
            artifact.revalidate()?;
            if !names.insert(&artifact.leaf.name) {
                return Err(NpmInstallRefusal::DuplicatePackage);
            }
            compressed = compressed.saturating_add(artifact.compressed.len());
            for file in &artifact.inspection.files {
                if file.path == "package" && file.kind == NpmFileKind::Directory {
                    continue;
                }
                let Some(relative) = file.path.strip_prefix("package/") else {
                    return Err(NpmInstallRefusal::ArchiveUnsupported);
                };
                if relative.is_empty() {
                    continue;
                }
                let path = format!("node_modules/{}/{relative}", artifact.leaf.name);
                total = total.saturating_add(file.size);
                if expected.insert(path, file.clone()).is_some() {
                    return Err(NpmInstallRefusal::DuplicatePackage);
                }
            }
        }
        if compressed > MAX_TOTAL_COMPRESSED_BYTES
            || total > MAX_TOTAL_INSTALLED_BYTES
            || expected.len() > MAX_INSTALLED_ENTRIES
        {
            return Err(NpmInstallRefusal::ResourceLimit);
        }
        let bindings: Vec<_> = artifacts
            .iter()
            .map(|artifact| (artifact.sha256().to_owned(), artifact.leaf.clone()))
            .collect();
        let policy_guard = policy.private_replay_guard();
        let target = destination.task_identity();
        let request = ResolverRequest {
            requirements: artifacts
                .iter()
                .map(|artifact| format!("{}@{}", artifact.leaf.name, artifact.leaf.version))
                .collect(),
            index_urls: Vec::new(),
            allowances: Default::default(),
        };
        let origins: Vec<_> = artifacts
            .iter()
            .map(|artifact| format!("sha256:{}", artifact.sha256()))
            .collect();
        let mut envelope = task_boundary::package_envelope(&PackageOperationBinding::new(
            "npm", &request, &origins, &target,
        ))
        .map_err(|_| NpmInstallRefusal::ResourceLimit)?;
        let public_binding = serde_json::json!({"contract":CONTRACT,"operation_id":id,"artifacts":bindings,
            "tool_closure":{"node_sha256":tools::NODE_SHA256,"npm_tree_sha256":tools::NPM_TREE_SHA256},
            "threat_generation":threat_generation,"package_envelope":envelope});
        let public_digest =
            digest(crate::audit::canonical_json_for_hash(&public_binding).as_bytes());
        let private_binding = serde_json::json!({"operation":public_binding,"policy":policy_guard});
        let plan_digest =
            digest(crate::audit::canonical_json_for_hash(&private_binding).as_bytes());
        // Boundary projections may be public. They bind the complete leaf
        // contract, while the secret-bearing replay guard stays exclusively in
        // the private journal comparison and mandatory pre-effect revalidation.
        envelope.sources[0].content =
            format!("tirith-npm-leaf-preparation:v1:sha256:{public_digest}");
        Ok(Self {
            id,
            policy_guard,
            digest: plan_digest,
            envelope,
            artifacts: bindings,
            expected,
            destination,
        })
    }

    pub fn operation(&self) -> BoundaryOperation<'_> {
        BoundaryOperation {
            boundary: OwnedBoundary::PackageInstallPreparation,
            envelope: &self.envelope,
            adapter: IngressAdapter::Unattributed,
            boundary_effects: BTreeSet::new(),
        }
    }

    pub fn execution_qualification(&self) -> Result<()> {
        Err(NpmInstallRefusal::NativeExecutionUnqualified)
    }

    fn revalidate(
        &self,
        artifacts: &[VerifiedNpmArtifact],
        policy: &EffectivePolicySnapshot,
    ) -> Result<()> {
        policy
            .revalidate_for_mutation()
            .map_err(|_| NpmInstallRefusal::PolicyChanged)?;
        if policy.private_replay_guard() != self.policy_guard
            || artifacts.len() != self.artifacts.len()
        {
            return Err(NpmInstallRefusal::PolicyChanged);
        }
        self.destination.revalidate()?;
        for (artifact, (hash, manifest)) in artifacts.iter().zip(&self.artifacts) {
            artifact.revalidate()?;
            if artifact.sha256() != hash
                || artifact.leaf.manifest_sha256 != manifest.manifest_sha256
            {
                return Err(NpmInstallRefusal::InputChanged);
            }
        }
        Ok(())
    }

    /// Only inert bytes enter quarantine. The exact typed task permit is checked
    /// before creating a journal or each subsequent filesystem effect.
    pub fn stage(
        &self,
        artifacts: &[VerifiedNpmArtifact],
        policy: &EffectivePolicySnapshot,
        store: &QuarantineStore,
        permit: TaskBoundaryPermit<PackageInstallPreparationBoundary>,
    ) -> Result<StagedNpmInputs> {
        self.revalidate(artifacts, policy)?;
        let lease = permit
            .into_effect_lease_at(&self.operation(), Utc::now())
            .map_err(|_| NpmInstallRefusal::AuthorizationRefused)?;
        let transaction = store
            .begin_transaction(&self.id)
            .map_err(|_| NpmInstallRefusal::QuarantineUnavailable)?;
        let mut record = PreparationRecord {
            schema: 1,
            contract: CONTRACT.into(),
            operation_id: self.id.clone(),
            plan_digest: self.digest.clone(),
            phase: PreparationPhase::Preparing,
        };
        let directory = DirCapability::open_root(transaction.dir())
            .map_err(|_| NpmInstallRefusal::QuarantineUnavailable)?;
        if directory
            .identity()
            .map_err(|_| NpmInstallRefusal::QuarantineUnavailable)?
            != file_identity(
                &transaction
                    .try_clone_dir_handle()
                    .map_err(|_| NpmInstallRefusal::QuarantineUnavailable)?,
            )
            .map_err(|_| NpmInstallRefusal::QuarantineUnavailable)?
        {
            return Err(NpmInstallRefusal::QuarantineUnavailable);
        }
        match directory.open_child_file(JOURNAL_NAME, JOURNAL_CAP) {
            Ok(file) => {
                let mut bytes = Vec::new();
                file.take(JOURNAL_CAP + 1)
                    .read_to_end(&mut bytes)
                    .map_err(|_| NpmInstallRefusal::RecoveryRequired)?;
                if bytes.len() > JOURNAL_CAP as usize {
                    return Err(NpmInstallRefusal::RecoveryRequired);
                }
                let prior: PreparationRecord = serde_json::from_slice(&bytes)
                    .map_err(|_| NpmInstallRefusal::RecoveryRequired)?;
                if prior.schema != 1
                    || prior.contract != CONTRACT
                    || prior.operation_id != self.id
                    || prior.plan_digest != self.digest
                {
                    return Err(NpmInstallRefusal::JournalConflict);
                }
                if !matches!(
                    prior.phase,
                    PreparationPhase::Preparing | PreparationPhase::InputsReady
                ) {
                    return Err(NpmInstallRefusal::RecoveryRequired);
                }
                record = prior;
            }
            Err(crate::util::OpenRegularError::NotFound) => (),
            Err(_) => return Err(NpmInstallRefusal::RecoveryRequired),
        }
        let effect = || -> Result<()> {
            self.revalidate(artifacts, policy)?;
            lease
                .authorize_effect_at(&self.operation(), Utc::now())
                .map_err(|_| NpmInstallRefusal::AuthorizationRefused)?;
            transaction
                .verify_visible_identity()
                .map_err(|_| NpmInstallRefusal::QuarantineUnavailable)
        };
        effect()?;
        transaction
            .write_control_file_atomic_0600(
                JOURNAL_NAME,
                &serde_json::to_vec(&record).map_err(|_| NpmInstallRefusal::RecoveryRequired)?,
            )
            .map_err(|_| NpmInstallRefusal::QuarantineUnavailable)?;
        for artifact in artifacts {
            effect()?;
            store
                .ingest_bytes(&artifact.compressed, artifact.sha256())
                .map_err(|_| NpmInstallRefusal::QuarantineUnavailable)?;
            effect()?;
            transaction
                .materialize_npm_blob(artifact.sha256())
                .map_err(|_| NpmInstallRefusal::QuarantineUnavailable)?;
        }
        for name in [execution::USER_CONFIG, execution::GLOBAL_CONFIG] {
            effect()?;
            transaction
                .write_control_file_atomic_0600(name, b"")
                .map_err(|_| NpmInstallRefusal::QuarantineUnavailable)?;
        }
        record.phase = PreparationPhase::InputsReady;
        effect()?;
        transaction
            .write_control_file_atomic_0600(
                JOURNAL_NAME,
                &serde_json::to_vec(&record).map_err(|_| NpmInstallRefusal::RecoveryRequired)?,
            )
            .map_err(|_| NpmInstallRefusal::QuarantineUnavailable)?;
        Ok(StagedNpmInputs {
            transaction,
            lease: std::sync::Arc::new(lease),
        })
    }

    /// Verify an already quiescent, privately owned staging tree. No npm output,
    /// hidden lockfile, link or generated package metadata is implicitly trusted.
    pub fn verify_staged_tree(&self, visible: &Path, retained: File) -> Result<VerifiedNpmTree> {
        verify_tree(visible, &retained, &self.expected)?;
        Ok(VerifiedNpmTree {
            visible: visible.into(),
            retained,
            expected: self.expected.clone(),
            npm_receipt: None,
        })
    }
}

pub struct StagedNpmInputs {
    transaction: QuarantineTransaction,
    lease: std::sync::Arc<TaskBoundaryEffectLease<PackageInstallPreparationBoundary>>,
}

impl StagedNpmInputs {
    pub fn transaction_id(&self) -> &str {
        self.transaction.id()
    }
    pub fn revalidate_identity(&self) -> Result<()> {
        self.transaction
            .verify_visible_identity()
            .map_err(|_| NpmInstallRefusal::QuarantineUnavailable)
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum PreparationPhase {
    Preparing,
    InputsReady,
    LayoutBound,
    LaunchAccepted,
    ChildFinished,
    Verified,
    Published,
    RecoveryRequired,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PreparationRecord {
    schema: u32,
    contract: String,
    operation_id: String,
    plan_digest: String,
    phase: PreparationPhase,
}

/// A retained verification witness, not an install approval. The future
/// publication boundary must revalidate this after quiescing every child.
pub struct VerifiedNpmTree {
    visible: PathBuf,
    retained: File,
    expected: BTreeMap<String, NpmFile>,
    npm_receipt: Option<receipt_evidence::NpmVerificationSummary>,
}

impl VerifiedNpmTree {
    pub fn revalidate(&self) -> Result<()> {
        verify_tree(&self.visible, &self.retained, &self.expected)
    }

    pub fn receipt_evidence(&self) -> Result<receipt_evidence::VerifiedNpmReceiptEvidence> {
        self.revalidate()?;
        let summary = self
            .npm_receipt
            .clone()
            .ok_or(NpmInstallRefusal::ExecutionStateConflict)?;
        summary
            .validate_stored()
            .map_err(|_| NpmInstallRefusal::InstalledContentChanged)?;
        Ok(receipt_evidence::VerifiedNpmReceiptEvidence { summary })
    }
}

fn verify_tree(
    visible: &Path,
    retained: &File,
    expected: &BTreeMap<String, NpmFile>,
) -> Result<()> {
    let root = DirCapability::open_root(visible)
        .map_err(|_| NpmInstallRefusal::InstalledContentChanged)?;
    if root
        .identity()
        .map_err(|_| NpmInstallRefusal::InstalledContentChanged)?
        != file_identity(retained).map_err(|_| NpmInstallRefusal::InstalledContentChanged)?
    {
        return Err(NpmInstallRefusal::InstalledContentChanged);
    }
    let mut directories = BTreeSet::new();
    for (path, file) in expected {
        let mut parent = Path::new(path).parent();
        while let Some(path) = parent {
            if !path.as_os_str().is_empty() {
                directories.insert(path.to_string_lossy().replace('\\', "/"));
            }
            parent = path.parent();
        }
        if file.kind == NpmFileKind::Directory {
            directories.insert(path.trim_end_matches('/').into());
        }
    }
    let mut seen_files = BTreeSet::new();
    let mut seen_directories = BTreeSet::new();
    let mut count = 0usize;
    let mut bytes = 0u64;
    let mut directory_witnesses = Vec::new();
    let mut file_witnesses = Vec::new();
    let mut stack = vec![(String::new(), root)];
    while let Some((prefix, directory)) = stack.pop() {
        if !prefix.is_empty() {
            directory_witnesses.push((
                prefix.clone(),
                directory
                    .identity()
                    .map_err(|_| NpmInstallRefusal::InstalledContentChanged)?,
            ));
        }
        let generation = directory
            .metadata()
            .map_err(|_| NpmInstallRefusal::InstalledContentChanged)?;
        let (entries, truncated) = directory
            .read_entries(MAX_INSTALLED_ENTRIES.saturating_sub(count))
            .map_err(|_| NpmInstallRefusal::InstalledContentChanged)?;
        if truncated {
            return Err(NpmInstallRefusal::ResourceLimit);
        }
        let mut before = Vec::new();
        for entry in entries {
            count += 1;
            if count > MAX_INSTALLED_ENTRIES {
                return Err(NpmInstallRefusal::ResourceLimit);
            }
            let name = entry
                .name
                .ok_or(NpmInstallRefusal::UnexpectedInstalledEntry)?;
            let path = if prefix.is_empty() {
                name.clone()
            } else {
                format!("{prefix}/{name}")
            };
            if path.len() > 4096 || path.split('/').count() > 68 {
                return Err(NpmInstallRefusal::ResourceLimit);
            }
            before.push((name.clone(), entry.kind));
            match entry.kind {
                EntryKind::Directory => {
                    if !directories.contains(&path) {
                        return Err(NpmInstallRefusal::UnexpectedInstalledEntry);
                    }
                    seen_directories.insert(path.clone());
                    let child = directory
                        .open_child_directory(&name)
                        .map_err(|_| NpmInstallRefusal::InstalledContentChanged)?;
                    stack.push((path, child));
                }
                EntryKind::RegularFile => {
                    let expected = expected
                        .get(&path)
                        .filter(|file| file.kind != NpmFileKind::Directory)
                        .ok_or(NpmInstallRefusal::UnexpectedInstalledEntry)?;
                    let mut file = directory
                        .open_child_file(&name, expected.size)
                        .map_err(|_| NpmInstallRefusal::InstalledContentChanged)?;
                    let generation = file_generation(&file)
                        .map_err(|_| NpmInstallRefusal::InstalledContentChanged)?;
                    if generation.links != 1 || generation.size != expected.size {
                        return Err(NpmInstallRefusal::InstalledContentChanged);
                    }
                    #[cfg(unix)]
                    {
                        use std::os::unix::fs::PermissionsExt;
                        let mode = file
                            .metadata()
                            .map_err(|_| NpmInstallRefusal::InstalledContentChanged)?
                            .permissions()
                            .mode();
                        if mode & 0o7000 != 0 || (mode & 0o111 != 0) != expected.executable {
                            return Err(NpmInstallRefusal::InstalledContentChanged);
                        }
                    }
                    let (copied, actual) = hash_reader((&mut file).take(expected.size + 1))
                        .map_err(|_| NpmInstallRefusal::InstalledContentChanged)?;
                    bytes = bytes.saturating_add(copied);
                    if bytes > MAX_TOTAL_INSTALLED_BYTES {
                        return Err(NpmInstallRefusal::ResourceLimit);
                    }
                    if copied != expected.size
                        || actual != expected.sha256
                        || file_generation(&file)
                            .map_err(|_| NpmInstallRefusal::InstalledContentChanged)?
                            != generation
                    {
                        return Err(NpmInstallRefusal::InstalledContentChanged);
                    }
                    let rebound = directory
                        .open_child_file(&name, expected.size)
                        .map_err(|_| NpmInstallRefusal::InstalledContentChanged)?;
                    if file_identity(&rebound)
                        .map_err(|_| NpmInstallRefusal::InstalledContentChanged)?
                        != generation.identity
                    {
                        return Err(NpmInstallRefusal::InstalledContentChanged);
                    }
                    file_witnesses.push((path.clone(), generation));
                    seen_files.insert(path);
                }
                EntryKind::Symlink | EntryKind::Other => {
                    return Err(NpmInstallRefusal::UnexpectedInstalledEntry)
                }
            }
        }
        let (after, truncated) = directory
            .read_entries(MAX_INSTALLED_ENTRIES)
            .map_err(|_| NpmInstallRefusal::InstalledContentChanged)?;
        let mut after: Vec<_> = after
            .into_iter()
            .map(|entry| (entry.name.unwrap_or_default(), entry.kind))
            .collect();
        before.sort();
        after.sort();
        let metadata_after = directory
            .metadata()
            .map_err(|_| NpmInstallRefusal::InstalledContentChanged)?;
        if truncated
            || before != after
            || generation.modified().ok() != metadata_after.modified().ok()
        {
            return Err(NpmInstallRefusal::InstalledContentChanged);
        }
    }
    if seen_files.len()
        != expected
            .values()
            .filter(|file| file.kind != NpmFileKind::Directory)
            .count()
        || seen_directories != directories
    {
        return Err(NpmInstallRefusal::InstalledContentChanged);
    }
    let visible = DirCapability::open_root(visible)
        .map_err(|_| NpmInstallRefusal::InstalledContentChanged)?;
    if visible
        .identity()
        .map_err(|_| NpmInstallRefusal::InstalledContentChanged)?
        != file_identity(retained).map_err(|_| NpmInstallRefusal::InstalledContentChanged)?
    {
        return Err(NpmInstallRefusal::InstalledContentChanged);
    }
    // A held child directory is not proof that the same name still reaches it.
    // Rebind every observed relative name beneath the retained root at the end.
    for (path, identity) in directory_witnesses {
        let directory = visible
            .open_descendant_directory(&path)
            .map_err(|_| NpmInstallRefusal::InstalledContentChanged)?;
        if directory
            .identity()
            .map_err(|_| NpmInstallRefusal::InstalledContentChanged)?
            != identity
        {
            return Err(NpmInstallRefusal::InstalledContentChanged);
        }
    }
    for (path, generation) in file_witnesses {
        let file = visible
            .open_descendant_file(&path, generation.size)
            .map_err(|_| NpmInstallRefusal::InstalledContentChanged)?;
        if file_generation(&file).map_err(|_| NpmInstallRefusal::InstalledContentChanged)?
            != generation
        {
            return Err(NpmInstallRefusal::InstalledContentChanged);
        }
    }
    Ok(())
}

#[cfg(test)]
#[path = "npm_install_tests.rs"]
mod tests;
