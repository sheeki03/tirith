//! LocalLeafMaterializeV1: retained local archive data, never package execution.
//!
//! This is a separate authority path from the still-unqualified npm execution
//! contract. Public previews are observations, not constructors for write proof.
//! Linux writes use only held directory descriptors. Publication belongs to the
//! distinct CLI checkpoint; no subprocess, network or automatic Drop cleanup
//! occurs here. Outside same-UID writers are not locked out: verified generations
//! describe observed bytes and never authorize their later execution.

use super::*;
use crate::task::{LocalPackageTreeAction, ProposedAction};
use crate::task_boundary::{LocalPackageMaterializationBoundary, LocalPackageRecoveryBoundary};
use std::sync::{atomic::AtomicBool, Arc};

#[path = "npm_materialize_namespace.rs"]
mod namespace;
use namespace::ProtectedNamespace;

#[path = "npm_materialize_decision.rs"]
mod decision;
use crate::threatdb::materialization_source::MaterializationThreatSource;
use decision::MaterializationDecision;

#[path = "npm_materialize_recovery.rs"]
mod recovery;
pub use recovery::{
    AuthorizedMaterializationRecovery, MaterializationRecovery, MaterializationRecoveryAction,
    MaterializationRecoveryObservation, MaterializationRecoverySummary,
};

#[path = "npm_materialize_writer.rs"]
mod writer;
pub use writer::{
    MaterializationRecoveryInventory, MaterializationWriter, VerifiedMaterializedTree,
};

pub const CONTRACT: &str = "LocalLeafMaterializeV1";
pub const WRITER_VERSION: u32 = 1;
/// Exact persisted inventory reader/writer schema, separately bound at release.
pub const RECOVERY_INVENTORY_VERSION: u32 = 1;
pub const MAX_ENTRIES: usize = 512;
pub const STAGING_COMPONENT: &str = "pending-target";
const MAX_OUTPUT_PATH_BYTES: usize = 1024 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MaterializationRefusal {
    InputChanged,
    ArchiveUnsupported,
    ManifestUnsupported,
    ExecutionDeclaration,
    NativePayload,
    ResourceLimit,
    InvalidOperationId,
    DuplicatePackage,
    PolicyChanged,
    AuthorizationRefused,
    DestinationChanged,
    StagingChanged,
    UnexpectedEntry,
    ContentChanged,
    Io,
    Cancelled,
    RecoveryRequired,
    UnsupportedPlatform,
    StateConflict,
    AnalysisIncomplete,
    ArtifactPolicyRefused,
    ThreatDataUnavailable,
    ThreatDataChanged,
    ThreatDataStale,
}
pub type MaterializationResult<T> = std::result::Result<T, MaterializationRefusal>;
use MaterializationRefusal as Refusal;

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ExpectedEntry {
    directory: bool,
    size: u64,
    sha256: String,
    mode: u32,
}

/// Descriptive output only. No API accepts this as write or commit authority.
#[derive(Clone, Serialize)]
pub struct MaterializationSummary {
    pub schema: u32,
    pub contract: String,
    pub operation_id: String,
    pub public_plan_digest: String,
    pub inventory_digest: String,
    pub artifacts: Vec<String>,
    pub packages: Vec<MaterializationPackageSummary>,
    pub files: usize,
    pub directories: usize,
    pub bytes: u64,
    pub threat_db_sequence: u64,
    pub signed_build_timestamp: u64,
    pub package_code_executed: bool,
    pub code_safety: String,
}

/// Bounded descriptive package identities from the accepted root manifests.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MaterializationPackageSummary {
    pub name: String,
    pub version: String,
    pub compressed_sha256: String,
}

/// Immutable owned inputs. Capture neither creates output nor launches tools.
/// Its inspection sources remain retained until the operation is abandoned.
pub struct MaterializationPlan {
    id: String,
    operator: String,
    artifacts: Vec<VerifiedNpmArtifact>,
    destination: NewNpmDestination,
    namespace: ProtectedNamespace,
    policy_guard: PrivatePolicyReplayGuard,
    private_digest: String,
    decision: MaterializationDecision,
    envelope: TaskEnvelopeInput,
    expected: BTreeMap<String, ExpectedEntry>,
    summary: MaterializationSummary,
}
impl MaterializationPlan {
    pub fn prepare(
        id: &str,
        artifacts: Vec<VerifiedNpmArtifact>,
        destination: NewNpmDestination,
        policy: &EffectivePolicySnapshot,
    ) -> MaterializationResult<Self> {
        let uuid = uuid::Uuid::parse_str(id).map_err(|_| Refusal::InvalidOperationId)?;
        if uuid.is_nil() || uuid.to_string() != id {
            return Err(Refusal::InvalidOperationId);
        }
        if artifacts.is_empty() || artifacts.len() > MAX_ARTIFACTS {
            return Err(Refusal::ResourceLimit);
        }
        let source = MaterializationThreatSource::capture().map_err(decision::source_error)?;
        Self::prepare_with_source(id, artifacts, destination, policy, source)
    }
    fn prepare_with_source(
        id: &str,
        artifacts: Vec<VerifiedNpmArtifact>,
        destination: NewNpmDestination,
        policy: &EffectivePolicySnapshot,
        source: MaterializationThreatSource,
    ) -> MaterializationResult<Self> {
        let uuid = uuid::Uuid::parse_str(id).map_err(|_| Refusal::InvalidOperationId)?;
        if uuid.is_nil() || uuid.to_string() != id {
            return Err(Refusal::InvalidOperationId);
        }
        if artifacts.is_empty() || artifacts.len() > MAX_ARTIFACTS {
            return Err(Refusal::ResourceLimit);
        }
        policy
            .revalidate_for_mutation()
            .map_err(|_| Refusal::PolicyChanged)?;
        destination
            .revalidate()
            .map_err(|_| Refusal::DestinationChanged)?;
        let namespace =
            ProtectedNamespace::capture(destination.parent.path(), destination.identity)?;
        let (expected, bytes) = capture_expected(&artifacts)?;
        let decision = MaterializationDecision::capture(&artifacts, policy, source)?;
        let (threat_db_sequence, signed_build_timestamp) = decision.publication();
        let inventory_digest =
            digest(&serde_json::to_vec(&expected).map_err(|_| Refusal::ResourceLimit)?);
        let policy_guard = policy.private_replay_guard();
        let requirements = artifacts
            .iter()
            .map(|a| format!("{}@{}", a.leaf.name, a.leaf.version))
            .collect();
        let origins: Vec<_> = artifacts
            .iter()
            .map(|a| format!("sha256:{}", a.sha256()))
            .collect();
        let request = ResolverRequest {
            requirements,
            index_urls: Vec::new(),
            allowances: Default::default(),
        };
        let mut envelope = task_boundary::package_envelope(&PackageOperationBinding::new(
            "npm",
            &request,
            &origins,
            &destination.task_identity(),
        ))
        .map_err(|_| Refusal::ResourceLimit)?;
        envelope.actions = vec![ProposedAction::LocalPackageMaterialize {
            binding: LocalPackageTreeAction::new(
                id,
                artifacts
                    .iter()
                    .map(|a| format!("{}@{}", a.leaf.name, a.leaf.version))
                    .collect(),
                destination
                    .parent
                    .path()
                    .join(&destination.component)
                    .to_str()
                    .ok_or(Refusal::DestinationChanged)?
                    .into(),
                inventory_digest.clone(),
            ),
        }];
        let commitments: Vec<_> = artifacts.iter().map(|a| serde_json::json!({
            "compressed_sha256": a.sha256(), "manifest_sha256": a.leaf.manifest_sha256,
            "name": a.leaf.name, "version": a.leaf.version, "analyzer": a.inspection.analyzer_version,
            "limits": a.inspection.limits,
        })).collect();
        let public = serde_json::json!({
            "contract": CONTRACT, "writer": WRITER_VERSION, "resolver":"explicit-local-selection-v1",
            "operation_id": id, "operator": current_operator(), "artifacts":commitments,
            "inventory":inventory_digest, "max_entries":MAX_ENTRIES, "policy_posture":policy.policy_posture_sha256,
            "threat_db_sequence":threat_db_sequence, "signed_build_timestamp":signed_build_timestamp, "envelope":envelope,
            "files_mode":420,"directories_mode":448,
        });
        let public_digest = digest(crate::audit::canonical_json_for_hash(&public).as_bytes());
        let plan_digest = digest(
            crate::audit::canonical_json_for_hash(&serde_json::json!({
                "public":public, "policy":policy_guard, "artifact_decision":decision.private_commitment(),
            }))
            .as_bytes(),
        );
        envelope.sources[0].content = format!(
            "tirith-npm-materialization:v1:sha256:{public_digest}:instance:{}",
            uuid::Uuid::new_v4()
        );
        let summary = MaterializationSummary {
            schema: 1,
            contract: CONTRACT.into(),
            operation_id: id.into(),
            public_plan_digest: public_digest,
            inventory_digest,
            artifacts: artifacts.iter().map(|a| a.sha256().into()).collect(),
            packages: artifacts
                .iter()
                .map(|a| MaterializationPackageSummary {
                    name: a.leaf.name.clone(),
                    version: a.leaf.version.clone(),
                    compressed_sha256: a.sha256().into(),
                })
                .collect(),
            files: expected.values().filter(|e| !e.directory).count(),
            directories: expected.values().filter(|e| e.directory).count(),
            bytes,
            threat_db_sequence,
            signed_build_timestamp,
            package_code_executed: false,
            code_safety: "not_established".into(),
        };
        Ok(Self {
            id: id.into(),
            operator: current_operator(),
            artifacts,
            destination,
            namespace,
            policy_guard,
            private_digest: plan_digest,
            decision,
            envelope,
            expected,
            summary,
        })
    }
    pub fn operation(&self) -> BoundaryOperation<'_> {
        BoundaryOperation {
            boundary: OwnedBoundary::LocalPackageMaterialization,
            envelope: &self.envelope,
            adapter: IngressAdapter::Unattributed,
            boundary_effects: BTreeSet::new(),
        }
    }
    pub fn summary(&self) -> &MaterializationSummary {
        &self.summary
    }
    pub fn target_identity(&self) -> PackageTargetIdentity {
        self.destination.task_identity()
    }
    pub fn journal_component(&self) -> String {
        format!(".tirith-materialize-{}", self.id)
    }
    pub fn target_path(&self) -> PathBuf {
        self.destination
            .parent
            .path()
            .join(&self.destination.component)
    }
    /// Apply-time exact byte/policy revalidation precedes acquiring the lease.
    /// The inert writer cannot consume a legacy execution preparation permit.
    /// ```compile_fail
    /// use tirith_core::artifact::npm_install::materialize::MaterializationPlan;
    /// use tirith_core::policy_snapshot::EffectivePolicySnapshot;
    /// use tirith_core::task_boundary::{TaskBoundaryPermit, PackageInstallPreparationBoundary};
    /// fn wrong(plan: &MaterializationPlan, policy: &EffectivePolicySnapshot,
    ///          permit: TaskBoundaryPermit<PackageInstallPreparationBoundary>) {
    ///     let _ = plan.authorize(policy, permit);
    /// }
    /// ```
    pub fn authorize<'a>(
        &'a self,
        policy: &'a EffectivePolicySnapshot,
        permit: TaskBoundaryPermit<LocalPackageMaterializationBoundary>,
    ) -> MaterializationResult<AuthorizedMaterialization<'a>> {
        self.revalidate(policy, true, true)?;
        let lease = permit
            .into_effect_lease_for_gate_at(&self.operation(), &policy.policy.task_gate, Utc::now())
            .map_err(|_| Refusal::AuthorizationRefused)?;
        Ok(AuthorizedMaterialization {
            plan: self,
            policy,
            lease: Arc::new(lease),
            checkpoint_issued: false,
            writer_issued: false,
        })
    }
    fn revalidate(
        &self,
        policy: &EffectivePolicySnapshot,
        full: bool,
        absent: bool,
    ) -> MaterializationResult<()> {
        self.namespace.revalidate()?;
        if self.operator != current_operator() {
            return Err(Refusal::AuthorizationRefused);
        }
        policy
            .revalidate_for_mutation()
            .map_err(|_| Refusal::PolicyChanged)?;
        if policy.private_replay_guard() != self.policy_guard {
            return Err(Refusal::PolicyChanged);
        }
        if absent {
            self.destination
                .revalidate()
                .map_err(|_| Refusal::DestinationChanged)?;
        }
        self.decision.revalidate(full)?;
        for artifact in &self.artifacts {
            if full {
                artifact.revalidate().map_err(|_| Refusal::InputChanged)?;
            } else if file_generation(&artifact.source).map_err(|_| Refusal::InputChanged)?
                != artifact.generation
            {
                return Err(Refusal::InputChanged);
            }
        }
        Ok(())
    }
}

#[cfg(unix)]
fn current_operator() -> String {
    format!("uid:{}", unsafe { libc::geteuid() })
}
#[cfg(not(unix))]
fn current_operator() -> String {
    "unsupported-materialization-operator".into()
}

fn add_expected(
    map: &mut BTreeMap<String, ExpectedEntry>,
    path: &str,
    entry: ExpectedEntry,
) -> MaterializationResult<()> {
    let mut parent = path;
    let mut directories = Vec::new();
    while let Some((prefix, _)) = parent.rsplit_once('/') {
        directories.push(prefix.to_owned());
        parent = prefix;
    }
    for directory in directories.into_iter().rev() {
        let expected = ExpectedEntry {
            directory: true,
            size: 0,
            sha256: digest(b""),
            mode: 0o700,
        };
        if let Some(prior) = map.get(&directory) {
            if prior != &expected {
                return Err(Refusal::ArchiveUnsupported);
            }
        } else {
            reject_alias(map, &directory)?;
            map.insert(directory, expected);
        }
    }
    if let Some(prior) = map.get(path) {
        // Explicit directory entries may name an already implied directory.
        if !entry.directory || prior != &entry {
            return Err(Refusal::ArchiveUnsupported);
        }
    } else {
        reject_alias(map, path)?;
        map.insert(path.into(), entry);
    }
    if map.len() > MAX_ENTRIES || map.keys().map(String::len).sum::<usize>() > MAX_OUTPUT_PATH_BYTES
    {
        return Err(Refusal::ResourceLimit);
    }
    Ok(())
}

fn reject_alias(map: &BTreeMap<String, ExpectedEntry>, path: &str) -> MaterializationResult<()> {
    let key = npm_archive::collision_key(path);
    if map
        .keys()
        .any(|old| old != path && npm_archive::collision_key(old) == key)
    {
        return Err(Refusal::ArchiveUnsupported);
    }
    Ok(())
}

fn validated_payload(
    artifact: &VerifiedNpmArtifact,
) -> MaterializationResult<npm_archive::ValidatedNpmPayload> {
    let (inspection, payload) =
        npm_archive::capture_npm_payload(&artifact.compressed, &artifact.inspection.limits);
    if inspection.archive_state != NpmArchiveState::Accepted
        || !inspection.coverage.archive_complete
        || !inspection.coverage.metadata_complete
        || inspection.artifact.sha256.as_deref() != Some(artifact.sha256())
        || serde_json::to_vec(&inspection.files).map_err(|_| Refusal::ArchiveUnsupported)?
            != serde_json::to_vec(&artifact.inspection.files)
                .map_err(|_| Refusal::ArchiveUnsupported)?
    {
        return Err(Refusal::ArchiveUnsupported);
    }
    payload.ok_or(Refusal::ArchiveUnsupported)
}
fn admit_contract(
    artifact: &VerifiedNpmArtifact,
    payload: &npm_archive::ValidatedNpmPayload,
) -> MaterializationResult<()> {
    let manifest = payload
        .members()
        .find(|m| m.path == "package/package.json")
        .ok_or(Refusal::ManifestUnsupported)?;
    if digest(manifest.bytes) != artifact.leaf.manifest_sha256 {
        return Err(Refusal::InputChanged);
    }
    let value = crate::mcp_lock::parse_json_no_duplicates(
        std::str::from_utf8(manifest.bytes).map_err(|_| Refusal::ManifestUnsupported)?,
    )
    .map_err(|_| Refusal::ManifestUnsupported)?;
    let object = value.as_object().ok_or(Refusal::ManifestUnsupported)?;
    // Absent or exactly empty declarations only; malformed shapes never become
    // harmless through JavaScript truthiness or npm metadata normalization.
    if object
        .get("scripts")
        .is_some_and(|v| !v.as_object().is_some_and(|m| m.is_empty()))
    {
        return Err(Refusal::ExecutionDeclaration);
    }
    for name in ["bin", "man"] {
        if object.get(name).is_some_and(|v| match v {
            Value::Object(m) => !m.is_empty(),
            Value::Array(a) => !a.is_empty(),
            _ => true,
        }) {
            return Err(Refusal::ExecutionDeclaration);
        }
    }
    if let Some(value) = object.get("directories") {
        let dirs = value.as_object().ok_or(Refusal::ExecutionDeclaration)?;
        if dirs.contains_key("bin") || dirs.contains_key("man") {
            return Err(Refusal::ExecutionDeclaration);
        }
    }
    if object
        .get("gypfile")
        .is_some_and(|v| v != &Value::Bool(false))
    {
        return Err(Refusal::ExecutionDeclaration);
    }
    for member in payload.members() {
        if member.path.eq_ignore_ascii_case("package/binding.gyp") {
            return Err(Refusal::ExecutionDeclaration);
        }
        if matches!(member.kind, NpmFileKind::Native | NpmFileKind::WebAssembly) {
            return Err(Refusal::NativePayload);
        }
    }
    Ok(())
}

/// One compound task lease, with separately consumed checkpoint/writer issues.
/// Dropping any of these values closes handles only and never deletes a path.
pub struct AuthorizedMaterialization<'a> {
    plan: &'a MaterializationPlan,
    policy: &'a EffectivePolicySnapshot,
    lease: Arc<TaskBoundaryEffectLease<LocalPackageMaterializationBoundary>>,
    checkpoint_issued: bool,
    writer_issued: bool,
}
/// An opaque exact-target lease for the distinct checkpoint. There is no raw
/// permit extraction and no executable/launch authorization accessor.
pub struct MaterializationCheckpointAuthorization<'a> {
    plan: &'a MaterializationPlan,
    policy: &'a EffectivePolicySnapshot,
    lease: Arc<TaskBoundaryEffectLease<LocalPackageMaterializationBoundary>>,
}
impl MaterializationCheckpointAuthorization<'_> {
    pub fn target_path(&self) -> PathBuf {
        self.plan.target_path()
    }
    pub fn revalidate_tree(
        &self,
        tree: &VerifiedMaterializedTree<'_, '_>,
    ) -> MaterializationResult<()> {
        if !tree.belongs_to(self.plan) {
            return Err(Refusal::AuthorizationRefused);
        }
        tree.revalidate()?;
        self.lease
            .authorize_effect_for_gate_at(
                &self.plan.operation(),
                &self.policy.policy.task_gate,
                Utc::now(),
            )
            .map_err(|_| Refusal::AuthorizationRefused)
    }
    pub fn operation_id(&self) -> &str {
        &self.plan.id
    }
    /// Private journal/CAS only; never include this in a public projection.
    pub fn private_plan_digest(&self) -> &str {
        &self.plan.private_digest
    }
    pub fn target_identity(&self) -> PackageTargetIdentity {
        self.plan.target_identity()
    }
    pub fn journal_component(&self) -> String {
        self.plan.journal_component()
    }
    pub fn revalidate(&self) -> MaterializationResult<()> {
        self.plan.revalidate(self.policy, false, true)?;
        self.lease
            .authorize_effect_for_gate_at(
                &self.plan.operation(),
                &self.policy.policy.task_gate,
                Utc::now(),
            )
            .map_err(|_| Refusal::AuthorizationRefused)
    }
}
impl<'a> AuthorizedMaterialization<'a> {
    pub fn checkpoint_authorization(
        &mut self,
    ) -> MaterializationResult<MaterializationCheckpointAuthorization<'a>> {
        if self.checkpoint_issued {
            return Err(Refusal::StateConflict);
        }
        self.plan.revalidate(self.policy, false, true)?;
        self.lease
            .authorize_effect_for_gate_at(
                &self.plan.operation(),
                &self.policy.policy.task_gate,
                Utc::now(),
            )
            .map_err(|_| Refusal::AuthorizationRefused)?;
        self.checkpoint_issued = true;
        Ok(MaterializationCheckpointAuthorization {
            plan: self.plan,
            policy: self.policy,
            lease: Arc::clone(&self.lease),
        })
    }
    pub fn writer(
        &mut self,
        journal: File,
        target: File,
    ) -> MaterializationResult<MaterializationWriter<'a>> {
        if !self.checkpoint_issued || self.writer_issued {
            return Err(Refusal::StateConflict);
        }
        // Consume before admission: a failed attempt cannot be silently redirected.
        self.writer_issued = true;
        writer::begin(
            self.plan,
            self.policy,
            Arc::clone(&self.lease),
            journal,
            target,
        )
    }
}

#[cfg(test)]
#[path = "npm_materialize_tests.rs"]
mod tests;

fn capture_expected(
    artifacts: &[VerifiedNpmArtifact],
) -> MaterializationResult<(BTreeMap<String, ExpectedEntry>, u64)> {
    if artifacts.is_empty() || artifacts.len() > MAX_ARTIFACTS {
        return Err(Refusal::ResourceLimit);
    }
    let mut expected = BTreeMap::new();
    let mut names = BTreeSet::new();
    let mut compressed = 0usize;
    let mut bytes = 0u64;
    for artifact in artifacts {
        artifact.revalidate().map_err(|_| Refusal::InputChanged)?;
        if !names.insert(artifact.leaf.name.clone()) {
            return Err(Refusal::DuplicatePackage);
        }
        compressed = compressed
            .checked_add(artifact.compressed.len())
            .ok_or(Refusal::ResourceLimit)?;
        if compressed > MAX_TOTAL_COMPRESSED_BYTES {
            return Err(Refusal::ResourceLimit);
        }
        // Validate the complete payload through the same parser now, before
        // any caller can obtain a task-authorized output writer.
        let payload = validated_payload(artifact)?;
        admit_contract(artifact, &payload)?;
        for member in payload.members() {
            if member.path == "package" {
                continue;
            }
            let relative = member
                .path
                .strip_prefix("package/")
                .ok_or(Refusal::ArchiveUnsupported)?;
            let path = format!("node_modules/{}/{relative}", artifact.leaf.name);
            let directory = member.kind == NpmFileKind::Directory;
            let entry = ExpectedEntry {
                directory,
                size: member.bytes.len() as u64,
                sha256: digest(member.bytes),
                mode: if directory { 0o700 } else { 0o644 },
            };
            bytes = bytes
                .checked_add(entry.size)
                .ok_or(Refusal::ResourceLimit)?;
            if bytes > MAX_TOTAL_INSTALLED_BYTES {
                return Err(Refusal::ResourceLimit);
            }
            add_expected(&mut expected, &path, entry)?;
        }
    }
    Ok((expected, bytes))
}
