//! Complete current-tree observations for signed npm recovery milestones.
//!
//! These read-only witnesses never authorize execution or deletion. An identity
//! equality after a crash is a fresh observation, not proof of inode continuity.
use super::*;
use std::os::unix::fs::MetadataExt;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NpmRecoveryTreeObservation {
    pub sha256: String,
    pub root_device: u64,
    pub root_inode: u64,
    pub files: usize,
    pub directories: usize,
    pub bytes: u64,
}

/// Only a complete bounded descriptor walk creates this value. Its serialized
/// projection is descriptive and cannot be promoted back into this witness.
pub struct NpmRecoverySnapshot {
    observation: NpmRecoveryTreeObservation,
}
impl NpmRecoverySnapshot {
    pub fn observation(&self) -> &NpmRecoveryTreeObservation {
        &self.observation
    }
}

/// Private context for the signed milestone. This contains a private policy
/// commitment and must never be printed or copied to a public receipt.
pub struct NpmRecoveryPlanBinding {
    pub operation_id: String,
    pub private_plan_digest: String,
    pub public_plan_digest: String,
    pub target: PathBuf,
    pub parent_identity: (u64, u64),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
struct Generation {
    device: u64,
    inode: u64,
    size: u64,
    links: u64,
    mode: u32,
    owner: u32,
    group: u32,
    modified_seconds: i64,
    modified_nanos: i64,
    changed_seconds: i64,
    changed_nanos: i64,
}
impl Generation {
    fn of(metadata: &std::fs::Metadata) -> Self {
        Self {
            device: metadata.dev(),
            inode: metadata.ino(),
            size: metadata.size(),
            links: metadata.nlink(),
            mode: metadata.mode(),
            owner: metadata.uid(),
            group: metadata.gid(),
            modified_seconds: metadata.mtime(),
            modified_nanos: metadata.mtime_nsec(),
            changed_seconds: metadata.ctime(),
            changed_nanos: metadata.ctime_nsec(),
        }
    }
}
#[derive(Serialize)]
struct EntryObservation {
    directory: bool,
    generation: Generation,
    sha256: Option<String>,
}
fn changed<T>(_: T) -> NpmInstallRefusal {
    NpmInstallRefusal::InstalledContentChanged
}

/// Observe every current regular file and directory through retained directory
/// handles, reject links/special entries, then rebind every generation by name.
/// Limits are identical to the closed npm output contract.
pub fn observe_npm_recovery_tree(path: &Path) -> Result<NpmRecoverySnapshot> {
    if !path.is_absolute()
        || path.as_os_str().len() > 4096
        || path.canonicalize().map_err(changed)? != path
    {
        return Err(NpmInstallRefusal::DestinationChanged);
    }
    // Keep the original root open through every read and final name rebind.
    // The traversal descriptor alone would be dropped after its children were queued.
    let anchor = DirCapability::open_root(path).map_err(changed)?;
    let root_generation = Generation::of(&anchor.metadata().map_err(changed)?);
    let root = DirCapability::open_root(path).map_err(changed)?;
    if Generation::of(&root.metadata().map_err(changed)?) != root_generation {
        return Err(NpmInstallRefusal::DestinationChanged);
    }
    let mut entries = BTreeMap::new();
    let mut stack = vec![(String::new(), root)];
    let mut files = 0usize;
    let mut directories = 0usize;
    let mut bytes = 0u64;
    while let Some((prefix, directory)) = stack.pop() {
        let before_generation = Generation::of(&directory.metadata().map_err(changed)?);
        let (children, truncated) = directory
            .read_entries(MAX_INSTALLED_ENTRIES.saturating_sub(entries.len()))
            .map_err(changed)?;
        if truncated {
            return Err(NpmInstallRefusal::ResourceLimit);
        }
        let mut names = Vec::new();
        for child in children {
            let name = child
                .name
                .ok_or(NpmInstallRefusal::UnexpectedInstalledEntry)?;
            let relative = if prefix.is_empty() {
                name.clone()
            } else {
                format!("{prefix}/{name}")
            };
            if relative.len() > 4096
                || relative.split('/').count() > 68
                || entries.len() >= MAX_INSTALLED_ENTRIES
            {
                return Err(NpmInstallRefusal::ResourceLimit);
            }
            names.push((name.clone(), child.kind));
            let observed = match child.kind {
                EntryKind::Directory => {
                    let held = directory.open_child_directory(&name).map_err(changed)?;
                    let generation = Generation::of(&held.metadata().map_err(changed)?);
                    if generation.mode & 0o7000 != 0 {
                        return Err(NpmInstallRefusal::InstalledContentChanged);
                    }
                    directories += 1;
                    stack.push((relative.clone(), held));
                    EntryObservation {
                        directory: true,
                        generation,
                        sha256: None,
                    }
                }
                EntryKind::RegularFile => {
                    let mut held = directory
                        .open_child_file(&name, MAX_TOTAL_INSTALLED_BYTES.saturating_sub(bytes))
                        .map_err(changed)?;
                    let generation = Generation::of(&held.metadata().map_err(changed)?);
                    if generation.links != 1 || generation.mode & 0o7000 != 0 {
                        return Err(NpmInstallRefusal::InstalledContentChanged);
                    }
                    let (size, sha256) =
                        hash_reader((&mut held).take(generation.size.saturating_add(1)))
                            .map_err(changed)?;
                    bytes = bytes
                        .checked_add(size)
                        .ok_or(NpmInstallRefusal::ResourceLimit)?;
                    if bytes > MAX_TOTAL_INSTALLED_BYTES {
                        return Err(NpmInstallRefusal::ResourceLimit);
                    }
                    if size != generation.size
                        || Generation::of(&held.metadata().map_err(changed)?) != generation
                    {
                        return Err(NpmInstallRefusal::InstalledContentChanged);
                    }
                    files += 1;
                    EntryObservation {
                        directory: false,
                        generation,
                        sha256: Some(sha256),
                    }
                }
                EntryKind::Symlink | EntryKind::Other => {
                    return Err(NpmInstallRefusal::UnexpectedInstalledEntry)
                }
            };
            if entries.insert(relative, observed).is_some() {
                return Err(NpmInstallRefusal::InstalledContentChanged);
            }
        }
        let (after, truncated) = directory
            .read_entries(MAX_INSTALLED_ENTRIES)
            .map_err(changed)?;
        let mut after: Vec<_> = after
            .into_iter()
            .map(|entry| (entry.name.unwrap_or_default(), entry.kind))
            .collect();
        names.sort();
        after.sort();
        if truncated
            || names != after
            || before_generation != Generation::of(&directory.metadata().map_err(changed)?)
        {
            return Err(NpmInstallRefusal::InstalledContentChanged);
        }
    }
    let root = DirCapability::open_root(path).map_err(changed)?;
    if Generation::of(&root.metadata().map_err(changed)?) != root_generation {
        return Err(NpmInstallRefusal::DestinationChanged);
    }
    for (relative, entry) in &entries {
        let actual = if entry.directory {
            Generation::of(
                &root
                    .open_descendant_directory(relative)
                    .map_err(changed)?
                    .metadata()
                    .map_err(changed)?,
            )
        } else {
            Generation::of(
                &root
                    .open_descendant_file(relative, entry.generation.size)
                    .map_err(changed)?
                    .metadata()
                    .map_err(changed)?,
            )
        };
        if actual != entry.generation {
            return Err(NpmInstallRefusal::InstalledContentChanged);
        }
    }
    let rebound = DirCapability::open_root(path).map_err(changed)?;
    if Generation::of(&rebound.metadata().map_err(changed)?) != root_generation {
        return Err(NpmInstallRefusal::DestinationChanged);
    }
    if Generation::of(&anchor.metadata().map_err(changed)?) != root_generation {
        return Err(NpmInstallRefusal::DestinationChanged);
    }
    // Fixed-width metadata and length-prefixed UTF-8 paths form one unambiguous
    // ordered stream without allocating a second whole-tree JSON document.
    let mut hash = Sha256::new();
    hash.update(b"tirith-npm-recovery-tree-v1\0");
    hash_generation(&mut hash, &root_generation);
    hash.update((entries.len() as u64).to_le_bytes());
    for (path, entry) in &entries {
        hash.update((path.len() as u64).to_le_bytes());
        hash.update(path.as_bytes());
        hash.update([u8::from(entry.directory)]);
        hash_generation(&mut hash, &entry.generation);
        if let Some(content) = &entry.sha256 {
            hash.update(content.as_bytes());
        }
    }
    let sha256 = format!("{:x}", hash.finalize());
    Ok(NpmRecoverySnapshot {
        observation: NpmRecoveryTreeObservation {
            sha256,
            root_device: root_generation.device,
            root_inode: root_generation.inode,
            files,
            directories,
            bytes,
        },
    })
}

fn hash_generation(hash: &mut Sha256, generation: &Generation) {
    hash.update(generation.device.to_le_bytes());
    hash.update(generation.inode.to_le_bytes());
    hash.update(generation.size.to_le_bytes());
    hash.update(generation.links.to_le_bytes());
    hash.update(generation.mode.to_le_bytes());
    hash.update(generation.owner.to_le_bytes());
    hash.update(generation.group.to_le_bytes());
    hash.update(generation.modified_seconds.to_le_bytes());
    hash.update(generation.modified_nanos.to_le_bytes());
    hash.update(generation.changed_seconds.to_le_bytes());
    hash.update(generation.changed_nanos.to_le_bytes());
}

impl VerifiedNpmTree {
    pub fn receipt_summary(&self) -> Result<receipt_evidence::NpmVerificationSummary> {
        self.revalidate()?;
        self.npm_receipt
            .clone()
            .ok_or(NpmInstallRefusal::ExecutionStateConflict)
    }
    pub fn clone_retained_root(&self) -> Result<File> {
        self.retained.try_clone().map_err(changed)
    }
    /// The public pathname may differ after publication; the retained exact
    /// inode and complete expected output are checked at both observation ends.
    pub fn recovery_snapshot_at(&self, path: &Path) -> Result<NpmRecoverySnapshot> {
        verify_tree(path, &self.retained, &self.expected)?;
        let snapshot = observe_npm_recovery_tree(path)?;
        if (
            snapshot.observation.root_device,
            snapshot.observation.root_inode,
        ) != file_identity(&self.retained).map_err(changed)?
        {
            return Err(NpmInstallRefusal::DestinationChanged);
        }
        verify_tree(path, &self.retained, &self.expected)?;
        Ok(snapshot)
    }
    pub fn private_recovery_snapshot(&self) -> Result<NpmRecoverySnapshot> {
        self.recovery_snapshot_at(&self.visible)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::{symlink, PermissionsExt};
    #[test]
    fn complete_observation_changes_for_bytes_metadata_extra_and_replaced_inode() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("root");
        std::fs::create_dir(&root).unwrap();
        let file = root.join("package.json");
        std::fs::write(&file, b"aaaa").unwrap();
        let first = observe_npm_recovery_tree(&root).unwrap();
        assert_eq!(
            first.observation(),
            observe_npm_recovery_tree(&root).unwrap().observation()
        );
        std::fs::write(&file, b"bbbb").unwrap();
        assert_ne!(
            first.observation(),
            observe_npm_recovery_tree(&root).unwrap().observation()
        );
        let second = observe_npm_recovery_tree(&root).unwrap();
        std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o400)).unwrap();
        assert_ne!(
            second.observation(),
            observe_npm_recovery_tree(&root).unwrap().observation()
        );
        let third = observe_npm_recovery_tree(&root).unwrap();
        std::fs::write(root.join("extra"), b"x").unwrap();
        assert_ne!(
            third.observation(),
            observe_npm_recovery_tree(&root).unwrap().observation()
        );
        std::fs::rename(&file, root.join("old")).unwrap();
        std::fs::write(&file, b"bbbb").unwrap();
        assert_ne!(
            third.observation(),
            observe_npm_recovery_tree(&root).unwrap().observation()
        );
    }
    #[test]
    fn links_special_entries_and_alias_roots_are_refused() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("root");
        std::fs::create_dir(&root).unwrap();
        std::fs::write(root.join("a"), b"x").unwrap();
        symlink("a", root.join("b")).unwrap();
        assert!(observe_npm_recovery_tree(&root).is_err());
        std::fs::remove_file(root.join("b")).unwrap();
        std::fs::hard_link(root.join("a"), root.join("b")).unwrap();
        assert!(observe_npm_recovery_tree(&root).is_err());
        symlink(&root, temp.path().join("alias")).unwrap();
        assert!(observe_npm_recovery_tree(&temp.path().join("alias")).is_err());
    }
}

/// Fresh policy/static/source assessment of an already published exact tree.
/// It has no install, mutation, deletion, or replay method.
pub struct NpmPublishedRecovery<'a> {
    artifacts: &'a [VerifiedNpmArtifact],
    policy: &'a EffectivePolicySnapshot,
    decision: ArtifactDecision,
    path: PathBuf,
    parent: DirCapability,
    parent_identity: (u64, u64),
    snapshot: NpmRecoverySnapshot,
    envelope: TaskEnvelopeInput,
}
impl<'a> NpmPublishedRecovery<'a> {
    pub fn capture(
        operation: &str,
        artifacts: &'a [VerifiedNpmArtifact],
        policy: &'a EffectivePolicySnapshot,
        path: &Path,
        signed_observation: &NpmRecoveryTreeObservation,
        parent_identity: (u64, u64),
    ) -> Result<Self> {
        NpmInstallPlan::validate_request(operation, artifacts)?;
        policy
            .revalidate_for_mutation()
            .map_err(|_| NpmInstallRefusal::PolicyChanged)?;
        for artifact in artifacts {
            artifact.revalidate()?;
        }
        let source = MaterializationThreatSource::capture().map_err(install_source_refusal)?;
        let decision = ArtifactDecision::capture(artifacts, policy, source)
            .map_err(install_decision_refusal)?;
        let parent =
            DirCapability::open_root(path.parent().ok_or(NpmInstallRefusal::DestinationChanged)?)
                .map_err(changed)?;
        if parent.identity().map_err(changed)? != parent_identity {
            return Err(NpmInstallRefusal::DestinationChanged);
        }
        let snapshot = observe_npm_recovery_tree(path)?;
        if snapshot.observation() != signed_observation {
            return Err(NpmInstallRefusal::InstalledContentChanged);
        }
        let binding = crate::task::LocalPackageTreeAction::new(
            operation,
            artifacts
                .iter()
                .map(|artifact| format!("{}@{}", artifact.leaf.name, artifact.leaf.version))
                .collect(),
            path.to_str()
                .ok_or(NpmInstallRefusal::DestinationChanged)?
                .into(),
            snapshot.observation.sha256.clone(),
        );
        let observation = serde_json::json!({"schema":1,"contract":CONTRACT,"operation":operation,
            "current_tree":snapshot.observation(),"instance":uuid::Uuid::new_v4().to_string(),
            "action":"reconfirm_already_published"});
        let envelope = TaskEnvelopeInput {
            task_id: None,
            sources: vec![crate::task::TaskSourceInput {
                claimed_source: crate::task::SourceKind::Unknown,
                content: format!(
                    "tirith-npm-published-reconfirmation:v1:sha256:{}",
                    digest(crate::audit::canonical_json_for_hash(&observation).as_bytes())
                ),
                locator: None,
                receipt: None,
            }],
            actions: vec![crate::task::ProposedAction::LocalPackageReconfirm { binding }],
            requested_effects: BTreeSet::new(),
        };
        let value = Self {
            artifacts,
            policy,
            decision,
            path: path.into(),
            parent,
            parent_identity,
            snapshot,
            envelope,
        };
        value.revalidate()?;
        Ok(value)
    }
    pub fn operation(&self) -> BoundaryOperation<'_> {
        BoundaryOperation {
            boundary: OwnedBoundary::LocalPackageRecovery,
            envelope: &self.envelope,
            adapter: IngressAdapter::Unattributed,
            boundary_effects: BTreeSet::new(),
        }
    }
    pub fn revalidate(&self) -> Result<()> {
        let visible_parent = DirCapability::open_root(self.parent.path()).map_err(changed)?;
        if self.parent.identity().map_err(changed)? != self.parent_identity
            || visible_parent.identity().map_err(changed)? != self.parent_identity
        {
            return Err(NpmInstallRefusal::DestinationChanged);
        }
        self.policy
            .revalidate_for_mutation()
            .map_err(|_| NpmInstallRefusal::PolicyChanged)?;
        self.decision
            .revalidate(true)
            .map_err(install_decision_refusal)?;
        for artifact in self.artifacts {
            artifact.revalidate()?;
        }
        if observe_npm_recovery_tree(&self.path)?.observation() != self.snapshot.observation() {
            return Err(NpmInstallRefusal::InstalledContentChanged);
        }
        Ok(())
    }
}
