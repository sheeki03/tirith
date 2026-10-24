//! Linux-only exclusive native data writer. Retained descriptors are bounded by
//! MAX_ENTRIES + journal/root + one temporary directory enumeration descriptor.
//! No path-based recursive deletion, implicit rollback, launch or network API.
#![cfg_attr(not(target_os = "linux"), allow(dead_code))]
use super::*;
#[cfg(target_os = "linux")]
use std::sync::atomic::Ordering;

#[derive(Clone, Copy, PartialEq, Eq)]
enum State {
    Empty,
    Writing,
    Complete,
    PublicationPossible,
    Published,
    Cleaned,
}
pub(super) struct OwnedEntry {
    pub(super) file: File,
    pub(super) generation: FileGeneration,
    pub(super) expected: ExpectedEntry,
}

pub struct MaterializationWriter<'a> {
    plan: &'a MaterializationPlan,
    policy: &'a EffectivePolicySnapshot,
    lease: Arc<TaskBoundaryEffectLease<LocalPackageMaterializationBoundary>>,
    journal: File,
    root: File,
    root_generation: FileGeneration,
    entries: BTreeMap<String, OwnedEntry>,
    state: State,
    uncertain: bool,
}
/// Non-serializable, non-cloneable evidence borrowing the live owned tree.
/// Public summary serialization cannot reconstruct this witness.
pub struct VerifiedMaterializedTree<'w, 'p> {
    writer: &'w MaterializationWriter<'p>,
}
/// Private journal observation only. This includes private CAS material and
/// must never be sent to a browser, ordinary status or support export. It is
/// serializable evidence, NOT a constructor for cleanup/publication authority.
#[derive(Serialize)]
pub struct MaterializationRecoveryInventory {
    schema: u32,
    contract: String,
    operation_id: String,
    public_plan_digest: String,
    private_plan_digest: String,
    operator: String,
    target_component: String,
    target_path_sha256: String,
    inventory_digest: String,
    packages: Vec<MaterializationPackageSummary>,
    phase: &'static str,
    parent: (u64, u64),
    journal: (u64, u64),
    root: RecoveryGeneration,
    entries: BTreeMap<String, RecoveryEntry>,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct RecoveryEntry {
    pub(super) generation: RecoveryGeneration,
    pub(super) expected: ExpectedEntry,
}
#[derive(Clone, Copy, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct RecoveryGeneration {
    identity: (u64, u64),
    size: u64,
    links: u64,
    modified_seconds: i64,
    modified_nanos: i64,
    changed_seconds: i64,
    changed_nanos: i64,
}
impl From<RecoveryGeneration> for FileGeneration {
    fn from(value: RecoveryGeneration) -> Self {
        Self {
            identity: value.identity,
            size: value.size,
            links: value.links,
            modified_seconds: value.modified_seconds,
            modified_nanos: value.modified_nanos,
            changed_seconds: value.changed_seconds,
            changed_nanos: value.changed_nanos,
        }
    }
}
impl From<FileGeneration> for RecoveryGeneration {
    fn from(value: FileGeneration) -> Self {
        Self {
            identity: value.identity,
            size: value.size,
            links: value.links,
            modified_seconds: value.modified_seconds,
            modified_nanos: value.modified_nanos,
            changed_seconds: value.changed_seconds,
            changed_nanos: value.changed_nanos,
        }
    }
}
impl VerifiedMaterializedTree<'_, '_> {
    pub(crate) fn belongs_to(&self, plan: &MaterializationPlan) -> bool {
        std::ptr::eq(self.writer.plan, plan)
    }
    pub fn summary(&self) -> &MaterializationSummary {
        &self.writer.plan.summary
    }
    pub fn revalidate(&self) -> MaterializationResult<()> {
        self.writer.verify_complete()
    }
    pub fn recovery_inventory(&self) -> MaterializationResult<MaterializationRecoveryInventory> {
        self.revalidate()?;
        let writer = self.writer;
        Ok(MaterializationRecoveryInventory {
            schema: RECOVERY_INVENTORY_VERSION,
            contract: CONTRACT.into(),
            operation_id: writer.plan.id.clone(),
            public_plan_digest: writer.plan.summary.public_plan_digest.clone(),
            private_plan_digest: writer.plan.private_digest.clone(),
            operator: writer.plan.operator.clone(),
            target_component: writer.plan.destination.component.clone(),
            target_path_sha256: digest(writer.plan.target_path().as_os_str().as_encoded_bytes()),
            inventory_digest: writer.plan.summary.inventory_digest.clone(),
            packages: writer.plan.summary.packages.clone(),
            phase: if writer.state == State::Published {
                "published"
            } else {
                "private"
            },
            parent: writer.plan.destination.identity,
            journal: file_identity(&writer.journal).map_err(|_| Refusal::StagingChanged)?,
            root: writer.root_generation.into(),
            entries: writer
                .entries
                .iter()
                .map(|(path, entry)| {
                    (
                        path.clone(),
                        RecoveryEntry {
                            generation: entry.generation.into(),
                            expected: entry.expected.clone(),
                        },
                    )
                })
                .collect(),
        })
    }
    pub fn published(&self) -> bool {
        self.writer.state == State::Published
    }
}

pub(super) fn begin<'a>(
    plan: &'a MaterializationPlan,
    policy: &'a EffectivePolicySnapshot,
    lease: Arc<TaskBoundaryEffectLease<LocalPackageMaterializationBoundary>>,
    journal: File,
    root: File,
) -> MaterializationResult<MaterializationWriter<'a>> {
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (plan, policy, lease, journal, root);
        Err(Refusal::UnsupportedPlatform)
    }
    #[cfg(target_os = "linux")]
    {
        plan.revalidate(policy, true, true)?;
        lease
            .authorize_effect_for_gate_at(&plan.operation(), &policy.policy.task_gate, Utc::now())
            .map_err(|_| Refusal::AuthorizationRefused)?;
        native::directory(&journal)?;
        native::directory(&root)?;
        let generation = file_generation(&root).map_err(|_| Refusal::StagingChanged)?;
        let result = MaterializationWriter {
            plan,
            policy,
            lease,
            journal,
            root,
            root_generation: generation,
            entries: BTreeMap::new(),
            state: State::Empty,
            uncertain: false,
        };
        result.layout()?;
        if !native::names(&result.root)?.is_empty() {
            return Err(Refusal::UnexpectedEntry);
        }
        result.inventory(false)?;
        Ok(result)
    }
}

impl<'a> MaterializationWriter<'a> {
    /// Populate once. Failures retain the writer and all admitted handles for
    /// explicit inventory-checked cleanup; retry never repeats a partial write.
    pub fn populate(&mut self, cancelled: &AtomicBool) -> MaterializationResult<()> {
        #[cfg(not(target_os = "linux"))]
        {
            let _ = cancelled;
            Err(Refusal::UnsupportedPlatform)
        }
        #[cfg(target_os = "linux")]
        {
            if self.state != State::Empty {
                return Err(Refusal::StateConflict);
            }
            self.state = State::Writing;
            self.effect(cancelled)?;
            // All artifacts were completely accepted at plan creation. Reparse
            // only those immutable retained Vecs, one decoded image at a time.
            for index in 0..self.plan.artifacts.len() {
                let artifact = &self.plan.artifacts[index];
                let payload = validated_payload(artifact)?;
                admit_contract(artifact, &payload)?;
                let package_name = artifact.leaf.name.clone();
                for member in payload.members() {
                    if member.path == "package" {
                        continue;
                    }
                    let relative = member
                        .path
                        .strip_prefix("package/")
                        .ok_or(Refusal::ArchiveUnsupported)?;
                    let path = format!("node_modules/{package_name}/{relative}");
                    let expected = self
                        .plan
                        .expected
                        .get(&path)
                        .ok_or(Refusal::ArchiveUnsupported)?
                        .clone();
                    if expected.directory != (member.kind == NpmFileKind::Directory)
                        || expected.size != member.bytes.len() as u64
                        || expected.sha256 != digest(member.bytes)
                    {
                        return Err(Refusal::InputChanged);
                    }
                    self.ensure_parents(&path, cancelled)?;
                    if expected.directory {
                        self.ensure_directory(&path, cancelled)?;
                    } else {
                        self.create_file(&path, member.bytes, &expected, cancelled)?;
                    }
                }
            }
            self.effect(cancelled)?;
            self.root.sync_all().map_err(|_| Refusal::Io)?;
            self.state = State::Complete;
            self.verify_complete()
        }
    }
    pub fn verify(&self) -> MaterializationResult<VerifiedMaterializedTree<'_, 'a>> {
        self.verify_complete()?;
        Ok(VerifiedMaterializedTree { writer: self })
    }
    /// Call immediately before the checkpoint's no-replace rename. Once a
    /// publication syscall may run, neither errors nor cleanup can remove data.
    pub fn begin_publication(&mut self) -> MaterializationResult<()> {
        if self.state != State::Complete {
            return Err(Refusal::StateConflict);
        }
        self.verify_complete()?;
        self.state = State::PublicationPossible;
        Ok(())
    }
    /// Only actual visible target identity plus complete content observation can
    /// move the witness from publication-possible to published.
    pub fn confirm_published(&mut self) -> MaterializationResult<()> {
        if self.state != State::PublicationPossible {
            return Err(Refusal::StateConflict);
        }
        self.layout()?;
        // rename changes the root directory's ctime. No other root generation
        // field is permitted to drift, and the full inventory remains checked.
        let after = file_generation(&self.root).map_err(|_| Refusal::StagingChanged)?;
        let before = self.root_generation;
        if after.identity != before.identity
            || after.size != before.size
            || after.links != before.links
            || after.modified_seconds != before.modified_seconds
            || after.modified_nanos != before.modified_nanos
        {
            return Err(Refusal::StagingChanged);
        }
        self.root_generation = after;
        self.plan.revalidate(self.policy, true, false)?;
        self.lease
            .authorize_effect_for_gate_at(
                &self.plan.operation(),
                &self.policy.policy.task_gate,
                Utc::now(),
            )
            .map_err(|_| Refusal::AuthorizationRefused)?;
        self.inventory(true)?;
        self.state = State::Published;
        Ok(())
    }
    /// Explicit cancellation of a live private tree. First validate the ENTIRE
    /// known inventory, including bytes and absence of unknown names. Any edit,
    /// replacement or uncertain write preserves every remaining object. Removal
    /// is descriptor-relative and never visits a public target or unexpected name.
    pub fn cleanup(&mut self) -> MaterializationResult<()> {
        #[cfg(not(target_os = "linux"))]
        {
            Err(Refusal::UnsupportedPlatform)
        }
        #[cfg(target_os = "linux")]
        {
            if self.state == State::Cleaned {
                return Ok(());
            }
            if matches!(self.state, State::PublicationPossible | State::Published) || self.uncertain
            {
                return Err(Refusal::RecoveryRequired);
            }
            self.layout()?;
            self.inventory(true)?;
            let mut paths: Vec<_> = self.entries.keys().cloned().collect();
            paths.sort_by_key(|p| std::cmp::Reverse(p.matches('/').count()));
            for path in paths {
                // Recheck the remaining inventory and this exact held generation
                // before each unlink; cancellation does not authorize new writes.
                self.plan.revalidate(self.policy, false, true)?;
                self.lease
                    .authorize_effect_for_gate_at(
                        &self.plan.operation(),
                        &self.policy.policy.task_gate,
                        Utc::now(),
                    )
                    .map_err(|_| Refusal::AuthorizationRefused)?;
                self.layout()?;
                self.inventory(false)?;
                let (parent, name) = split(&path)?;
                let entry = self.entries.get(&path).ok_or(Refusal::StateConflict)?;
                if entry.expected.directory && !native::names(&entry.file)?.is_empty() {
                    return Err(Refusal::UnexpectedEntry);
                }
                native::same_child(
                    self.directory(parent)?,
                    name,
                    &entry.file,
                    entry.expected.directory,
                )?;
                native::unlink(self.directory(parent)?, name, entry.expected.directory)?;
                // Once unlink has succeeded this retained object is no longer
                // cleanup authority. Parent sync failure retains all other data.
                self.entries.remove(&path);
                self.refresh_parent(parent)?;
                self.directory(parent)?
                    .sync_all()
                    .map_err(|_| Refusal::Io)?;
            }
            self.inventory(false)?;
            self.state = State::Cleaned;
            Ok(())
        }
    }
    fn verify_complete(&self) -> MaterializationResult<()> {
        if !matches!(self.state, State::Complete | State::Published) {
            return Err(Refusal::StateConflict);
        }
        self.plan
            .revalidate(self.policy, true, self.state == State::Complete)?;
        self.lease
            .authorize_effect_for_gate_at(
                &self.plan.operation(),
                &self.policy.policy.task_gate,
                Utc::now(),
            )
            .map_err(|_| Refusal::AuthorizationRefused)?;
        self.layout()?;
        if self.entries.len() != self.plan.expected.len()
            || self
                .entries
                .iter()
                .any(|(path, entry)| self.plan.expected.get(path) != Some(&entry.expected))
        {
            return Err(Refusal::ContentChanged);
        }
        self.inventory(true)
    }
    fn layout(&self) -> MaterializationResult<()> {
        #[cfg(not(target_os = "linux"))]
        {
            Err(Refusal::UnsupportedPlatform)
        }
        #[cfg(target_os = "linux")]
        {
            let visible = DirCapability::open_root(self.plan.destination.parent.path())
                .map_err(|_| Refusal::DestinationChanged)?;
            if visible
                .identity()
                .map_err(|_| Refusal::DestinationChanged)?
                != self.plan.destination.identity
            {
                return Err(Refusal::DestinationChanged);
            }
            let journal = self
                .plan
                .destination
                .parent
                .open_child_directory(&self.plan.journal_component())
                .map_err(|_| Refusal::StagingChanged)?;
            if journal.identity().map_err(|_| Refusal::StagingChanged)?
                != file_identity(&self.journal).map_err(|_| Refusal::StagingChanged)?
            {
                return Err(Refusal::StagingChanged);
            }
            native::directory(&self.journal)?;
            native::directory(&self.root)?;
            if matches!(self.state, State::PublicationPossible | State::Published) {
                let target = self
                    .plan
                    .destination
                    .parent
                    .open_child_directory(&self.plan.destination.component)
                    .map_err(|_| Refusal::DestinationChanged)?;
                if target.identity().map_err(|_| Refusal::DestinationChanged)?
                    != self.root_generation.identity
                {
                    return Err(Refusal::DestinationChanged);
                }
            } else {
                native::same_child(&self.journal, STAGING_COMPONENT, &self.root, true)?;
                self.plan
                    .destination
                    .revalidate()
                    .map_err(|_| Refusal::DestinationChanged)?;
            }
            Ok(())
        }
    }
    fn inventory(&self, hashes: bool) -> MaterializationResult<()> {
        #[cfg(not(target_os = "linux"))]
        {
            let _ = hashes;
            Err(Refusal::UnsupportedPlatform)
        }
        #[cfg(target_os = "linux")]
        {
            if self.uncertain {
                return Err(Refusal::RecoveryRequired);
            }
            validate_inventory(&self.root, self.root_generation, &self.entries, hashes)
        }
    }
    #[cfg(target_os = "linux")]
    fn directory(&self, path: &str) -> MaterializationResult<&File> {
        if path.is_empty() {
            return Ok(&self.root);
        }
        self.entries
            .get(path)
            .filter(|e| e.expected.directory)
            .map(|e| &e.file)
            .ok_or(Refusal::StagingChanged)
    }
    #[cfg(target_os = "linux")]
    fn refresh_parent(&mut self, path: &str) -> MaterializationResult<()> {
        let generation =
            file_generation(self.directory(path)?).map_err(|_| Refusal::StagingChanged)?;
        if path.is_empty() {
            self.root_generation = generation;
        } else {
            self.entries
                .get_mut(path)
                .ok_or(Refusal::StagingChanged)?
                .generation = generation;
        }
        Ok(())
    }
    #[cfg(target_os = "linux")]
    fn effect(&self, cancelled: &AtomicBool) -> MaterializationResult<()> {
        if cancelled.load(Ordering::Acquire) {
            return Err(Refusal::Cancelled);
        }
        self.plan.revalidate(self.policy, false, true)?;
        self.lease
            .authorize_effect_for_gate_at(
                &self.plan.operation(),
                &self.policy.policy.task_gate,
                Utc::now(),
            )
            .map_err(|_| Refusal::AuthorizationRefused)?;
        self.layout()?;
        self.inventory(false)
    }
    #[cfg(target_os = "linux")]
    fn ensure_parents(&mut self, path: &str, cancelled: &AtomicBool) -> MaterializationResult<()> {
        let mut parents = Vec::new();
        let mut current = path;
        while let Some((parent, _)) = current.rsplit_once('/') {
            parents.push(parent);
            current = parent;
        }
        for parent in parents.into_iter().rev() {
            self.ensure_directory(parent, cancelled)?;
        }
        Ok(())
    }
    #[cfg(target_os = "linux")]
    fn ensure_directory(
        &mut self,
        path: &str,
        cancelled: &AtomicBool,
    ) -> MaterializationResult<()> {
        if self.entries.contains_key(path) {
            return Ok(());
        }
        self.effect(cancelled)?;
        let expected = self
            .plan
            .expected
            .get(path)
            .filter(|e| e.directory)
            .ok_or(Refusal::ArchiveUnsupported)?
            .clone();
        let (parent, name) = split(path)?;
        // If creation succeeds but immediate admission fails, there is no exact
        // held witness for cleanup. Retain everything, including the new name.
        self.uncertain = true;
        let file = native::create_directory(self.directory(parent)?, name)?;
        let generation = file_generation(&file).map_err(|_| Refusal::Io)?;
        self.entries.insert(
            path.into(),
            OwnedEntry {
                file,
                generation,
                expected,
            },
        );
        self.refresh_parent(parent)?;
        self.directory(parent)?
            .sync_all()
            .map_err(|_| Refusal::Io)?;
        self.uncertain = false;
        Ok(())
    }
    #[cfg(target_os = "linux")]
    fn create_file(
        &mut self,
        path: &str,
        bytes: &[u8],
        expected: &ExpectedEntry,
        cancelled: &AtomicBool,
    ) -> MaterializationResult<()> {
        use std::io::Write as _;
        self.effect(cancelled)?;
        if self.entries.contains_key(path) {
            return Err(Refusal::UnexpectedEntry);
        }
        let (parent, name) = split(path)?;
        self.uncertain = true;
        let file = native::create_file(self.directory(parent)?, name)?;
        let generation = file_generation(&file).map_err(|_| Refusal::Io)?;
        let empty = ExpectedEntry {
            directory: false,
            size: 0,
            sha256: digest(b""),
            mode: 0o644,
        };
        self.entries.insert(
            path.into(),
            OwnedEntry {
                file,
                generation,
                expected: empty,
            },
        );
        self.refresh_parent(parent)?;
        self.uncertain = false;
        let mut offset = 0;
        let mut hasher = Sha256::new();
        while offset < bytes.len() {
            self.effect(cancelled)?;
            let entry = self.entries.get_mut(path).ok_or(Refusal::StateConflict)?;
            let end = bytes.len().min(offset + 64 * 1024);
            let count = entry
                .file
                .write(&bytes[offset..end])
                .map_err(|_| Refusal::Io)?;
            if count == 0 {
                return Err(Refusal::Io);
            }
            hasher.update(&bytes[offset..offset + count]);
            offset += count;
            entry.expected.size = offset as u64;
            entry.expected.sha256 = hex::encode(hasher.clone().finalize());
            // Failure to capture the post-write generation makes cleanup
            // uncertain instead of treating old metadata as deletion authority.
            self.uncertain = true;
            entry.generation = file_generation(&entry.file).map_err(|_| Refusal::Io)?;
            self.uncertain = false;
        }
        let entry = self.entries.get_mut(path).ok_or(Refusal::StateConflict)?;
        entry.file.sync_all().map_err(|_| Refusal::Io)?;
        if &entry.expected != expected {
            return Err(Refusal::ContentChanged);
        }
        self.directory(parent)?
            .sync_all()
            .map_err(|_| Refusal::Io)?;
        self.inventory(false)
    }
}
#[cfg(target_os = "linux")]
pub(super) fn directory_for<'a>(
    root: &'a File,
    entries: &'a BTreeMap<String, OwnedEntry>,
    path: &str,
) -> MaterializationResult<&'a File> {
    if path.is_empty() {
        return Ok(root);
    }
    entries
        .get(path)
        .filter(|e| e.expected.directory)
        .map(|e| &e.file)
        .ok_or(Refusal::StagingChanged)
}
#[cfg(target_os = "linux")]
pub(super) fn validate_inventory(
    root: &File,
    root_generation: FileGeneration,
    entries: &BTreeMap<String, OwnedEntry>,
    hashes: bool,
) -> MaterializationResult<()> {
    if file_generation(root).map_err(|_| Refusal::StagingChanged)? != root_generation {
        return Err(Refusal::StagingChanged);
    }
    let mut expected_names: BTreeMap<&str, BTreeSet<&str>> = BTreeMap::new();
    expected_names.insert("", BTreeSet::new());
    for (path, entry) in entries {
        let (parent, name) = split(path)?;
        expected_names.entry(parent).or_default().insert(name);
        if entry.expected.directory {
            expected_names.entry(path).or_default();
        }
        native::same_child(
            directory_for(root, entries, parent)?,
            name,
            &entry.file,
            entry.expected.directory,
        )?;
        native::validate_entry(entry, hashes)?;
    }
    for (path, names) in expected_names {
        let actual = native::names(directory_for(root, entries, path)?)?;
        if actual.iter().map(String::as_str).collect::<BTreeSet<_>>() != names {
            return Err(Refusal::UnexpectedEntry);
        }
    }
    // Retained handles exclude inode reuse while all observed identities
    // and generations are checked again after enumeration/hashing.
    if file_generation(root).map_err(|_| Refusal::StagingChanged)? != root_generation {
        return Err(Refusal::StagingChanged);
    }
    for (path, entry) in entries {
        let (parent, name) = split(path)?;
        native::same_child(
            directory_for(root, entries, parent)?,
            name,
            &entry.file,
            entry.expected.directory,
        )?;
        native::validate_entry(entry, false)?;
    }
    Ok(())
}

pub(super) fn split(path: &str) -> MaterializationResult<(&str, &str)> {
    let (parent, name) = path.rsplit_once('/').unwrap_or(("", path));
    if name.is_empty() || matches!(name, "." | "..") || name.as_bytes().contains(&0) {
        return Err(Refusal::ArchiveUnsupported);
    }
    Ok((parent, name))
}

#[cfg(target_os = "linux")]
pub(super) mod native {
    use super::*;
    use std::ffi::{CStr, CString};
    use std::os::fd::{AsRawFd, FromRawFd};
    use std::os::unix::fs::MetadataExt;
    fn name(value: &str) -> MaterializationResult<CString> {
        if value.is_empty() || matches!(value, "." | "..") || value.contains('/') {
            return Err(Refusal::ArchiveUnsupported);
        }
        CString::new(value).map_err(|_| Refusal::ArchiveUnsupported)
    }
    fn metadata(file: &File) -> MaterializationResult<std::fs::Metadata> {
        file.metadata().map_err(|_| Refusal::Io)
    }
    pub(crate) fn directory(file: &File) -> MaterializationResult<()> {
        namespace::check_object_acl(file, true)?;
        let m = metadata(file)?;
        if !m.is_dir() || m.uid() != unsafe { libc::geteuid() } || m.mode() & 0o7777 != 0o700 {
            return Err(Refusal::StagingChanged);
        }
        Ok(())
    }
    pub(crate) fn same_child(
        parent: &File,
        child: &str,
        held: &File,
        directory: bool,
    ) -> MaterializationResult<()> {
        let child = name(child)?;
        let mut status: libc::stat = unsafe { std::mem::zeroed() };
        // SAFETY: retained parent and validated single component; no following.
        if unsafe {
            libc::fstatat(
                parent.as_raw_fd(),
                child.as_ptr(),
                &mut status,
                libc::AT_SYMLINK_NOFOLLOW,
            )
        } != 0
        {
            return Err(Refusal::StagingChanged);
        }
        let id = file_identity(held).map_err(|_| Refusal::StagingChanged)?;
        if (status.st_dev, status.st_ino) != id
            || status.st_mode & libc::S_IFMT
                != if directory {
                    libc::S_IFDIR
                } else {
                    libc::S_IFREG
                }
        {
            return Err(Refusal::StagingChanged);
        }
        Ok(())
    }
    pub(crate) fn open_root(path: &Path) -> MaterializationResult<File> {
        use std::os::unix::fs::OpenOptionsExt;
        std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_DIRECTORY | libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK)
            .open(path)
            .map_err(|_| Refusal::DestinationChanged)
    }
    pub(crate) fn open_child(
        parent: &File,
        child: &str,
        directory: bool,
    ) -> MaterializationResult<File> {
        let child_name = name(child)?;
        let raw = unsafe {
            libc::openat(
                parent.as_raw_fd(),
                child_name.as_ptr(),
                libc::O_RDONLY
                    | libc::O_CLOEXEC
                    | libc::O_NOFOLLOW
                    | libc::O_NONBLOCK
                    | if directory { libc::O_DIRECTORY } else { 0 },
            )
        };
        if raw < 0 {
            return Err(Refusal::StagingChanged);
        }
        let file = unsafe { File::from_raw_fd(raw) };
        same_child(parent, child, &file, directory)?;
        Ok(file)
    }
    pub(crate) fn present(parent: &File, child: &str) -> MaterializationResult<bool> {
        let child = name(child)?;
        let mut status: libc::stat = unsafe { std::mem::zeroed() };
        if unsafe {
            libc::fstatat(
                parent.as_raw_fd(),
                child.as_ptr(),
                &mut status,
                libc::AT_SYMLINK_NOFOLLOW,
            )
        } == 0
        {
            return Ok(true);
        }
        if std::io::Error::last_os_error().raw_os_error() == Some(libc::ENOENT) {
            Ok(false)
        } else {
            Err(Refusal::StagingChanged)
        }
    }
    pub(crate) fn relocate_no_replace(
        parent: &File,
        component: &str,
        journal: &File,
    ) -> MaterializationResult<()> {
        let component = name(component)?;
        let destination = name(STAGING_COMPONENT)?;
        // Use the kernel syscall on GNU and musl alike. Some libc targets do
        // not expose the wrapper; failure still refuses without a replacing
        // rename fallback.
        if unsafe {
            libc::syscall(
                libc::SYS_renameat2,
                parent.as_raw_fd(),
                component.as_ptr(),
                journal.as_raw_fd(),
                destination.as_ptr(),
                libc::RENAME_NOREPLACE,
            )
        } != 0
        {
            return Err(Refusal::RecoveryRequired);
        }
        Ok(())
    }
    pub(crate) fn create_directory(parent: &File, child: &str) -> MaterializationResult<File> {
        let child_name = name(child)?;
        // SAFETY: exclusive creation under a held directory; EEXIST refuses.
        if unsafe { libc::mkdirat(parent.as_raw_fd(), child_name.as_ptr(), 0o700) } != 0 {
            return Err(Refusal::Io);
        }
        let raw = unsafe {
            libc::openat(
                parent.as_raw_fd(),
                child_name.as_ptr(),
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC | libc::O_NOFOLLOW,
            )
        };
        if raw < 0 {
            return Err(Refusal::Io);
        }
        let file = unsafe { File::from_raw_fd(raw) };
        let created = metadata(&file)?;
        if !created.is_dir()
            || created.uid() != unsafe { libc::geteuid() }
            || created.mode() & 0o077 != 0
        {
            return Err(Refusal::StagingChanged);
        }
        same_child(parent, child, &file, true)?;
        if unsafe { libc::fchmod(file.as_raw_fd(), 0o700) } != 0 {
            return Err(Refusal::Io);
        }
        directory(&file)?;
        same_child(parent, child, &file, true)?;
        file.sync_all().map_err(|_| Refusal::Io)?;
        Ok(file)
    }
    pub(crate) fn create_file(parent: &File, child: &str) -> MaterializationResult<File> {
        let child_name = name(child)?;
        let raw = unsafe {
            libc::openat(
                parent.as_raw_fd(),
                child_name.as_ptr(),
                libc::O_RDWR | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                0o644,
            )
        };
        if raw < 0 {
            return Err(Refusal::Io);
        }
        let file = unsafe { File::from_raw_fd(raw) };
        if unsafe { libc::fchmod(file.as_raw_fd(), 0o644) } != 0 {
            return Err(Refusal::Io);
        }
        let m = metadata(&file)?;
        if !m.is_file()
            || m.nlink() != 1
            || m.uid() != unsafe { libc::geteuid() }
            || m.mode() & 0o7777 != 0o644
        {
            return Err(Refusal::StagingChanged);
        }
        same_child(parent, child, &file, false)?;
        Ok(file)
    }
    pub(crate) fn validate_entry(entry: &OwnedEntry, hash: bool) -> MaterializationResult<()> {
        namespace::check_object_acl(&entry.file, entry.expected.directory)?;
        let before = file_generation(&entry.file).map_err(|_| Refusal::ContentChanged)?;
        let m = metadata(&entry.file)?;
        if before != entry.generation
            || m.uid() != unsafe { libc::geteuid() }
            || m.mode() & 0o7777 != entry.expected.mode
            || m.is_dir() != entry.expected.directory
            || (!entry.expected.directory && (!m.is_file() || m.nlink() != 1))
        {
            return Err(Refusal::ContentChanged);
        }
        if hash && !entry.expected.directory {
            let mut reader = entry.file.try_clone().map_err(|_| Refusal::Io)?;
            reader.seek(SeekFrom::Start(0)).map_err(|_| Refusal::Io)?;
            let (size, sha) =
                hash_reader(reader.take(entry.expected.size + 1)).map_err(|_| Refusal::Io)?;
            if size != entry.expected.size || sha != entry.expected.sha256 {
                return Err(Refusal::ContentChanged);
            }
        }
        if file_generation(&entry.file).map_err(|_| Refusal::ContentChanged)? != before {
            return Err(Refusal::ContentChanged);
        }
        Ok(())
    }
    pub(crate) fn names(directory: &File) -> MaterializationResult<BTreeSet<String>> {
        let raw = unsafe {
            libc::openat(
                directory.as_raw_fd(),
                c".".as_ptr(),
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC | libc::O_NOFOLLOW,
            )
        };
        if raw < 0 {
            return Err(Refusal::Io);
        }
        let stream = unsafe { libc::fdopendir(raw) };
        if stream.is_null() {
            unsafe { libc::close(raw) };
            return Err(Refusal::Io);
        }
        struct Directory(*mut libc::DIR);
        impl Drop for Directory {
            fn drop(&mut self) {
                unsafe { libc::closedir(self.0) };
            }
        }
        let stream = Directory(stream);
        let mut result = BTreeSet::new();
        loop {
            unsafe { *libc::__errno_location() = 0 };
            let entry = unsafe { libc::readdir(stream.0) };
            if entry.is_null() {
                if unsafe { *libc::__errno_location() } != 0 {
                    return Err(Refusal::Io);
                }
                break;
            }
            let bytes = unsafe { CStr::from_ptr((*entry).d_name.as_ptr()) }.to_bytes();
            if bytes == b"." || bytes == b".." {
                continue;
            }
            if result.len() >= MAX_ENTRIES {
                return Err(Refusal::ResourceLimit);
            }
            let value = std::str::from_utf8(bytes).map_err(|_| Refusal::UnexpectedEntry)?;
            if !result.insert(value.to_owned()) {
                return Err(Refusal::UnexpectedEntry);
            }
        }
        Ok(result)
    }
    pub(crate) fn unlink(parent: &File, child: &str, directory: bool) -> MaterializationResult<()> {
        let child = name(child)?;
        if unsafe {
            libc::unlinkat(
                parent.as_raw_fd(),
                child.as_ptr(),
                if directory { libc::AT_REMOVEDIR } else { 0 },
            )
        } != 0
        {
            return Err(Refusal::Io);
        }
        Ok(())
    }
}
