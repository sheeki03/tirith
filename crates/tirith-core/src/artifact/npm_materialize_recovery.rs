//! Fresh, explicit recovery of a complete recorded materialization milestone.
//!
//! A journal is evidence, not retained authority. Capture reopens every current
//! object and checks the fixed layout, complete expected bytes, generations and
//! absence of extras. Fresh task authorization binds that CURRENT observation.
//! This does not claim inode continuity through a crash or exclude an outside
//! same-UID writer. Incomplete unrecorded writes remain preserved. Explicit
//! continuation admits only the exact currently remaining private inventory.
#![cfg_attr(not(target_os = "linux"), allow(dead_code))]
use super::*;
#[cfg(target_os = "linux")]
use writer::{directory_for, native, split, validate_inventory};
use writer::{OwnedEntry, RecoveryEntry, RecoveryGeneration};

const INVENTORY_BYTES: usize = 2 * 1024 * 1024;

#[derive(Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MaterializationRecoveryAction {
    /// Observe only an already-public exact tree. Never replay a rename/install.
    ConfirmPublished,
    /// Remove only exact private contents; public trees must first undergo the
    /// same lease's fixed no-replace relocation under the private journal.
    UndoPrivate,
    /// Explicit fresh delete-only authorization for a residual private tree.
    /// Recorded missing entries are absence observations, never prior success.
    ContinueUndoPrivate,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct StoredInventory {
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
    phase: String,
    parent: (u64, u64),
    journal: (u64, u64),
    root: RecoveryGeneration,
    entries: BTreeMap<String, RecoveryEntry>,
}
#[derive(Clone, Copy, PartialEq, Eq)]
enum Location {
    Private,
    Public,
}
#[derive(Clone, Copy, PartialEq, Eq)]
enum Progress {
    Captured,
    Relocating,
    Private,
    Removing,
    Empty,
    Confirmed,
}

/// Fresh native handles and inputs, never a deserialized capability.
pub struct MaterializationRecovery {
    id: String,
    action: MaterializationRecoveryAction,
    operator: String,
    policy_guard: PrivatePolicyReplayGuard,
    artifacts: Vec<VerifiedNpmArtifact>,
    decision: Option<ArtifactDecision>,
    destination: NewNpmDestination,
    namespace: ProtectedNamespace,
    parent: File,
    journal: File,
    root: File,
    root_generation: FileGeneration,
    entries: BTreeMap<String, OwnedEntry>,
    location: Location,
    envelope: TaskEnvelopeInput,
    summary: MaterializationRecoverySummary,
}
/// Public, bounded descriptive history only. No private replay digest, native
/// inventory, raw policy, journal bytes or capability is projected.
#[derive(Clone, Serialize)]
pub struct MaterializationRecoverySummary {
    pub schema: u32,
    pub contract: String,
    pub operation_id: String,
    pub action: MaterializationRecoveryAction,
    pub original_public_plan_digest: String,
    pub packages: Vec<MaterializationPackageSummary>,
    pub outcome: String,
    pub root_relocated_since_observation: bool,
    pub recorded_entries: usize,
    pub remaining_entries_at_capture: usize,
    pub missing_recorded_entries: usize,
    pub package_code_executed: bool,
    pub code_safety: String,
}

impl MaterializationRecovery {
    pub fn capture(
        id: &str,
        target: &Path,
        artifacts: Vec<VerifiedNpmArtifact>,
        inventory_json: &[u8],
        action: MaterializationRecoveryAction,
        policy: &EffectivePolicySnapshot,
    ) -> MaterializationResult<Self> {
        #[cfg(not(target_os = "linux"))]
        {
            let _ = (id, target, artifacts, inventory_json, action, policy);
            Err(Refusal::UnsupportedPlatform)
        }
        #[cfg(target_os = "linux")]
        {
            Self::capture_inner(id, target, artifacts, inventory_json, action, policy, None)
        }
    }
    #[cfg(target_os = "linux")]
    fn capture_inner(
        id: &str,
        target: &Path,
        artifacts: Vec<VerifiedNpmArtifact>,
        inventory_json: &[u8],
        action: MaterializationRecoveryAction,
        policy: &EffectivePolicySnapshot,
        #[allow(unused_variables)] fixture_source: Option<MaterializationThreatSource>,
    ) -> MaterializationResult<Self> {
        validate_id(id)?;
        policy
            .revalidate_for_mutation()
            .map_err(|_| Refusal::PolicyChanged)?;
        let record = decode(inventory_json)?;
        if record.operation_id != id || record.operator != current_operator() {
            return Err(Refusal::AuthorizationRefused);
        }
        // Build only the exact expected raw bytes; Undo deliberately does not
        // ask a malware verdict for permission to remove those unchanged bytes.
        let (expected, _) = capture_expected(&artifacts)?;
        let packages = artifacts
            .iter()
            .map(|a| MaterializationPackageSummary {
                name: a.leaf.name.clone(),
                version: a.leaf.version.clone(),
                compressed_sha256: a.sha256().into(),
            })
            .collect::<Vec<_>>();
        if packages != record.packages
            || record.entries.len() != expected.len()
            || record
                .entries
                .iter()
                .any(|(path, e)| expected.get(path) != Some(&e.expected))
            || digest(&serde_json::to_vec(&expected).map_err(|_| Refusal::ResourceLimit)?)
                != record.inventory_digest
        {
            return Err(Refusal::InputChanged);
        }
        let destination = capture_destination(target)?;
        let namespace =
            ProtectedNamespace::capture(destination.parent.path(), destination.identity)?;
        if destination.component != record.target_component
            || destination.identity != record.parent
            || digest(
                destination
                    .parent
                    .path()
                    .join(&destination.component)
                    .as_os_str()
                    .as_encoded_bytes(),
            ) != record.target_path_sha256
        {
            return Err(Refusal::DestinationChanged);
        }
        let parent = native::open_root(destination.parent.path())?;
        if file_identity(&parent).map_err(|_| Refusal::DestinationChanged)? != destination.identity
        {
            return Err(Refusal::DestinationChanged);
        }
        let journal_name = format!(".tirith-materialize-{id}");
        let journal = native::open_child(&parent, &journal_name, true)?;
        native::directory(&journal)?;
        if file_identity(&journal).map_err(|_| Refusal::StagingChanged)? != record.journal {
            return Err(Refusal::StagingChanged);
        }
        let public = native::present(&parent, &destination.component)?;
        let private = native::present(&journal, STAGING_COMPONENT)?;
        if public == private {
            return Err(Refusal::StateConflict);
        }
        let location = if public {
            Location::Public
        } else {
            Location::Private
        };
        if (action == MaterializationRecoveryAction::ConfirmPublished
            && location != Location::Public)
            || (action == MaterializationRecoveryAction::ContinueUndoPrivate
                && location != Location::Private)
        {
            return Err(Refusal::StateConflict);
        }
        let root = if public {
            native::open_child(&parent, &destination.component, true)?
        } else {
            native::open_child(&journal, STAGING_COMPONENT, true)?
        };
        native::directory(&root)?;
        let root_generation = file_generation(&root).map_err(|_| Refusal::StagingChanged)?;
        let recorded_root: FileGeneration = record.root.into();
        let moved = (record.phase == "private") != (location == Location::Private);
        let continuation = action == MaterializationRecoveryAction::ContinueUndoPrivate;
        if if continuation {
            root_generation.identity != recorded_root.identity
        } else {
            (!moved && root_generation != recorded_root)
                || (moved && !rename_generation(recorded_root, root_generation))
        } {
            return Err(Refusal::StagingChanged);
        }
        // Every ancestor must already be in the complete accepted inventory.
        // Open only one safe name relative to its freshly retained parent.
        let mut entries = BTreeMap::new();
        for (path, entry) in &record.entries {
            let (parent_path, name) = split(path)?;
            if continuation && !parent_path.is_empty() && !entries.contains_key(parent_path) {
                // An absent ancestor proves only that this recorded descendant
                // is not reachable at its fixed path; no removed inode is owned.
                continue;
            }
            let parent_file = directory_for(&root, &entries, parent_path)?;
            if continuation && !native::present(parent_file, name)? {
                continue;
            }
            let held = native::open_child(parent_file, name, entry.expected.directory)?;
            let recorded: FileGeneration = entry.generation.into();
            let generation = if continuation && entry.expected.directory {
                let current = file_generation(&held).map_err(|_| Refusal::StagingChanged)?;
                if current.identity != recorded.identity {
                    return Err(Refusal::StagingChanged);
                }
                // Directory generation legitimately changes as children are
                // removed. Fresh current identity/mode/ACL/no-extra checks and
                // the new task lease authorize this observed remaining tree.
                current
            } else {
                recorded
            };
            let owned = OwnedEntry {
                file: held,
                generation,
                expected: entry.expected.clone(),
            };
            native::validate_entry(&owned, true)?;
            entries.insert(path.clone(), owned);
        }
        validate_inventory(&root, root_generation, &entries, true)?;
        let decision = match action {
            MaterializationRecoveryAction::UndoPrivate
            | MaterializationRecoveryAction::ContinueUndoPrivate => None,
            MaterializationRecoveryAction::ConfirmPublished => {
                #[cfg(test)]
                let source = fixture_source
                    .map(Ok)
                    .unwrap_or_else(MaterializationThreatSource::capture)
                    .map_err(decision::source_error)?;
                #[cfg(not(test))]
                let source =
                    MaterializationThreatSource::capture().map_err(decision::source_error)?;
                Some(ArtifactDecision::capture(&artifacts, policy, source)?)
            }
        };
        let remaining_entries = entries.len();
        let residual=entries.iter().map(|(path,entry)|(path,serde_json::json!({"generation":RecoveryGeneration::from(entry.generation),"expected":entry.expected}))).collect::<BTreeMap<_,_>>();
        let residual_digest = digest(
            crate::audit::canonical_json_for_hash(
                &serde_json::to_value(&residual).map_err(|_| Refusal::ResourceLimit)?,
            )
            .as_bytes(),
        );
        let binding = LocalPackageTreeAction::new(
            id,
            packages
                .iter()
                .map(|p| format!("{}@{}", p.name, p.version))
                .collect(),
            destination
                .parent
                .path()
                .join(&destination.component)
                .to_str()
                .ok_or(Refusal::DestinationChanged)?
                .into(),
            residual_digest.clone(),
        );
        let action_input = match action {
            MaterializationRecoveryAction::ConfirmPublished => {
                ProposedAction::LocalPackageMaterialize { binding }
            }
            MaterializationRecoveryAction::UndoPrivate
            | MaterializationRecoveryAction::ContinueUndoPrivate => {
                ProposedAction::LocalPackageUndo { binding }
            }
        };
        // Bind a fresh complete observed generation and action, rather than
        // treating dev/inode from a closed historical handle as live ownership.
        let observation = serde_json::json!({
            "schema":1,"contract":CONTRACT,"operation_id":id,"action":action,
            "historical_record":digest(inventory_json),"current_root":RecoveryGeneration::from(root_generation),
            "public":public,"operator":current_operator(),"residual_inventory":residual_digest,
            "missing_entries":record.entries.len()-remaining_entries,"instance":uuid::Uuid::new_v4().to_string(),
        });
        let mut source = crate::task::TaskSourceInput {
            claimed_source: crate::task::SourceKind::Unknown,
            content: String::new(),
            locator: None,
            receipt: None,
        };
        source.content = format!(
            "tirith-local-materialization-recovery:v1:sha256:{}",
            digest(crate::audit::canonical_json_for_hash(&observation).as_bytes())
        );
        let envelope = TaskEnvelopeInput {
            task_id: None,
            sources: vec![source],
            actions: vec![action_input],
            requested_effects: BTreeSet::new(),
        };
        let value = Self {
            id: id.into(),
            action,
            operator: current_operator(),
            policy_guard: policy.private_replay_guard(),
            artifacts,
            decision,
            destination,
            namespace,
            parent,
            journal,
            root,
            root_generation,
            entries,
            location,
            envelope,
            summary: MaterializationRecoverySummary {
                schema: 1,
                contract: CONTRACT.into(),
                operation_id: id.into(),
                action,
                original_public_plan_digest: record.public_plan_digest,
                packages,
                outcome: "captured_current_inventory".into(),
                root_relocated_since_observation: moved,
                recorded_entries: record.entries.len(),
                remaining_entries_at_capture: remaining_entries,
                missing_recorded_entries: record.entries.len() - remaining_entries,
                package_code_executed: false,
                code_safety: "not_established".into(),
            },
        };
        value.revalidate(policy, true)?;
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
    pub fn authorize<'a>(
        self,
        policy: &'a EffectivePolicySnapshot,
        permit: TaskBoundaryPermit<LocalPackageRecoveryBoundary>,
    ) -> MaterializationResult<AuthorizedMaterializationRecovery<'a>> {
        self.revalidate(policy, true)?;
        let lease = permit
            .into_effect_lease_for_gate_at(&self.operation(), &policy.policy.task_gate, Utc::now())
            .map_err(|_| Refusal::AuthorizationRefused)?;
        Ok(AuthorizedMaterializationRecovery {
            captured: self,
            policy,
            lease,
            progress: Progress::Captured,
        })
    }
    fn inputs(&self, policy: &EffectivePolicySnapshot, full: bool) -> MaterializationResult<()> {
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
        if let Some(decision) = &self.decision {
            decision.revalidate(full)?;
        }
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
    fn layout(&self) -> MaterializationResult<()> {
        #[cfg(not(target_os = "linux"))]
        {
            Err(Refusal::UnsupportedPlatform)
        }
        #[cfg(target_os = "linux")]
        {
            let visible = DirCapability::open_root(self.destination.parent.path())
                .map_err(|_| Refusal::DestinationChanged)?;
            if visible
                .identity()
                .map_err(|_| Refusal::DestinationChanged)?
                != self.destination.identity
                || file_identity(&self.parent).map_err(|_| Refusal::DestinationChanged)?
                    != self.destination.identity
            {
                return Err(Refusal::DestinationChanged);
            }
            native::directory(&self.journal)?;
            native::directory(&self.root)?;
            native::same_child(
                &self.parent,
                &format!(".tirith-materialize-{}", self.id),
                &self.journal,
                true,
            )?;
            match self.location {
                Location::Private => {
                    if native::present(&self.parent, &self.destination.component)? {
                        return Err(Refusal::DestinationChanged);
                    }
                    native::same_child(&self.journal, STAGING_COMPONENT, &self.root, true)?;
                }
                Location::Public => {
                    if native::present(&self.journal, STAGING_COMPONENT)? {
                        return Err(Refusal::StagingChanged);
                    }
                    native::same_child(
                        &self.parent,
                        &self.destination.component,
                        &self.root,
                        true,
                    )?;
                }
            }
            Ok(())
        }
    }
    fn revalidate(
        &self,
        policy: &EffectivePolicySnapshot,
        full: bool,
    ) -> MaterializationResult<()> {
        self.inputs(policy, full)?;
        self.layout()?;
        #[cfg(not(target_os = "linux"))]
        {
            Err(Refusal::UnsupportedPlatform)
        }
        #[cfg(target_os = "linux")]
        {
            validate_inventory(&self.root, self.root_generation, &self.entries, full)
        }
    }
}

/// Consumes one current exact action permit. No raw lease or path-only delete
/// accessor, and no Drop cleanup. Errors preserve all remaining objects.
pub struct AuthorizedMaterializationRecovery<'a> {
    captured: MaterializationRecovery,
    policy: &'a EffectivePolicySnapshot,
    lease: TaskBoundaryEffectLease<LocalPackageRecoveryBoundary>,
    progress: Progress,
}
/// Borrows the authorized owner until its final observation is durably recorded.
pub struct MaterializationRecoveryObservation<'w, 'p> {
    owner: &'w AuthorizedMaterializationRecovery<'p>,
}
impl MaterializationRecoveryObservation<'_, '_> {
    pub fn summary(&self) -> &MaterializationRecoverySummary {
        &self.owner.captured.summary
    }
    pub fn revalidate(&self) -> MaterializationResult<()> {
        if !matches!(self.owner.progress, Progress::Empty | Progress::Confirmed) {
            return Err(Refusal::StateConflict);
        }
        self.owner.check(true)
    }
}
impl<'a> AuthorizedMaterializationRecovery<'a> {
    fn check(&self, full: bool) -> MaterializationResult<()> {
        if self.progress == Progress::Relocating {
            return Err(Refusal::RecoveryRequired);
        }
        self.lease
            .authorize_effect_for_gate_at(
                &self.captured.operation(),
                &self.policy.policy.task_gate,
                Utc::now(),
            )
            .map_err(|_| Refusal::AuthorizationRefused)?;
        self.captured.revalidate(self.policy, full)
    }
    /// Idempotent private-layout validation; a public tree is relocated at most
    /// once by a NOREPLACE syscall under this exact fresh delete-only lease.
    pub fn relocate_for_undo(&mut self) -> MaterializationResult<()> {
        #[cfg(not(target_os = "linux"))]
        {
            Err(Refusal::UnsupportedPlatform)
        }
        #[cfg(target_os = "linux")]
        {
            if !matches!(
                self.captured.action,
                MaterializationRecoveryAction::UndoPrivate
                    | MaterializationRecoveryAction::ContinueUndoPrivate
            ) || !matches!(self.progress, Progress::Captured | Progress::Private)
            {
                return Err(Refusal::StateConflict);
            }
            self.check(true)?;
            if self.captured.location == Location::Private {
                self.progress = Progress::Private;
                return Ok(());
            }
            self.progress = Progress::Relocating; // uncertainty permanently bans this owner's cleanup
            native::relocate_no_replace(
                &self.captured.parent,
                &self.captured.destination.component,
                &self.captured.journal,
            )?;
            let after =
                file_generation(&self.captured.root).map_err(|_| Refusal::RecoveryRequired)?;
            if !rename_generation(self.captured.root_generation, after) {
                return Err(Refusal::RecoveryRequired);
            }
            self.captured.root_generation = after;
            self.captured.location = Location::Private;
            self.captured.layout()?;
            validate_inventory(&self.captured.root, after, &self.captured.entries, true)?;
            self.captured
                .parent
                .sync_all()
                .map_err(|_| Refusal::RecoveryRequired)?;
            self.captured
                .journal
                .sync_all()
                .map_err(|_| Refusal::RecoveryRequired)?;
            self.progress = Progress::Private;
            self.check(true)
        }
    }
    pub fn confirm_published(
        &mut self,
    ) -> MaterializationResult<MaterializationRecoveryObservation<'_, 'a>> {
        if self.captured.action != MaterializationRecoveryAction::ConfirmPublished
            || self.captured.location != Location::Public
            || self.progress != Progress::Captured
            || self.captured.decision.is_none()
        {
            return Err(Refusal::StateConflict);
        }
        self.check(true)?;
        self.progress = Progress::Confirmed;
        self.captured.summary.outcome = "confirmed_current_public_tree".into();
        Ok(MaterializationRecoveryObservation { owner: self })
    }
    /// Removes only complete, exactly observed private entries, deepest first.
    /// A partial interruption is retained and requires separate fresh recovery;
    /// this owner cannot silently retry a partially committed sequence.
    pub fn undo_private(
        &mut self,
        cancelled: &AtomicBool,
    ) -> MaterializationResult<MaterializationRecoveryObservation<'_, 'a>> {
        #[cfg(not(target_os = "linux"))]
        {
            let _ = cancelled;
            Err(Refusal::UnsupportedPlatform)
        }
        #[cfg(target_os = "linux")]
        {
            use std::sync::atomic::Ordering;
            if !matches!(
                self.captured.action,
                MaterializationRecoveryAction::UndoPrivate
                    | MaterializationRecoveryAction::ContinueUndoPrivate
            ) || self.captured.location != Location::Private
                || !matches!(self.progress, Progress::Captured | Progress::Private)
            {
                return Err(Refusal::StateConflict);
            }
            self.check(true)?;
            self.progress = Progress::Removing;
            let mut paths = self.captured.entries.keys().cloned().collect::<Vec<_>>();
            paths.sort_by_key(|path| std::cmp::Reverse(path.matches('/').count()));
            for path in paths {
                if cancelled.load(Ordering::Acquire) {
                    return Err(Refusal::Cancelled);
                }
                self.check(false)?;
                let (parent_path, name) = split(&path)?;
                let entry = self
                    .captured
                    .entries
                    .get(&path)
                    .ok_or(Refusal::StateConflict)?;
                if entry.expected.directory && !native::names(&entry.file)?.is_empty() {
                    return Err(Refusal::UnexpectedEntry);
                }
                let parent =
                    directory_for(&self.captured.root, &self.captured.entries, parent_path)?;
                native::same_child(parent, name, &entry.file, entry.expected.directory)?;
                native::unlink(parent, name, entry.expected.directory)?;
                self.captured.entries.remove(&path);
                let parent =
                    directory_for(&self.captured.root, &self.captured.entries, parent_path)?;
                let after = file_generation(parent).map_err(|_| Refusal::RecoveryRequired)?;
                parent.sync_all().map_err(|_| Refusal::RecoveryRequired)?;
                if parent_path.is_empty() {
                    self.captured.root_generation = after;
                } else {
                    self.captured
                        .entries
                        .get_mut(parent_path)
                        .ok_or(Refusal::StateConflict)?
                        .generation = after;
                }
            }
            self.check(true)?;
            self.progress = Progress::Empty;
            self.captured.summary.outcome =
                if self.captured.action == MaterializationRecoveryAction::ContinueUndoPrivate {
                    if self.captured.summary.remaining_entries_at_capture == 0 {
                        "observed_private_tree_already_empty"
                    } else {
                        "removed_exact_remaining_private_contents"
                    }
                } else {
                    "removed_exact_private_contents"
                }
                .into();
            Ok(MaterializationRecoveryObservation { owner: self })
        }
    }
}
fn validate_id(id: &str) -> MaterializationResult<()> {
    if !uuid::Uuid::parse_str(id).is_ok_and(|u| !u.is_nil() && u.to_string() == id) {
        return Err(Refusal::InvalidOperationId);
    }
    Ok(())
}
fn sha(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
fn decode(bytes: &[u8]) -> MaterializationResult<StoredInventory> {
    if bytes.is_empty() || bytes.len() > INVENTORY_BYTES {
        return Err(Refusal::ResourceLimit);
    }
    let json = crate::mcp_lock::parse_json_no_duplicates(
        std::str::from_utf8(bytes).map_err(|_| Refusal::RecoveryRequired)?,
    )
    .map_err(|_| Refusal::RecoveryRequired)?;
    let value: StoredInventory =
        serde_json::from_value(json).map_err(|_| Refusal::RecoveryRequired)?;
    validate_id(&value.operation_id)?;
    if value.schema != RECOVERY_INVENTORY_VERSION
        || value.contract != CONTRACT
        || !matches!(value.phase.as_str(), "private" | "published")
        || !sha(&value.private_plan_digest)
        || !sha(&value.public_plan_digest)
        || !sha(&value.target_path_sha256)
        || !sha(&value.inventory_digest)
        || value.entries.is_empty()
        || value.entries.len() > MAX_ENTRIES
        || value.entries.keys().map(String::len).sum::<usize>() > MAX_OUTPUT_PATH_BYTES
        || value.packages.is_empty()
        || value.packages.len() > MAX_ARTIFACTS
    {
        return Err(Refusal::RecoveryRequired);
    }
    Ok(value)
}
#[cfg(target_os = "linux")]
fn capture_destination(path: &Path) -> MaterializationResult<NewNpmDestination> {
    if !path.is_absolute()
        || path
            .components()
            .any(|part| matches!(part, Component::ParentDir))
    {
        return Err(Refusal::DestinationChanged);
    }
    let component = path
        .file_name()
        .and_then(|n| n.to_str())
        .filter(|n| {
            !n.is_empty()
                && n.len() <= 200
                && !n.contains(['/', '\\', ':'])
                && *n != "."
                && *n != ".."
        })
        .ok_or(Refusal::DestinationChanged)?
        .to_owned();
    let parent_path = path
        .parent()
        .ok_or(Refusal::DestinationChanged)?
        .canonicalize()
        .map_err(|_| Refusal::DestinationChanged)?;
    let parent = DirCapability::open_root(&parent_path).map_err(|_| Refusal::DestinationChanged)?;
    let identity = parent.identity().map_err(|_| Refusal::DestinationChanged)?;
    Ok(NewNpmDestination {
        parent,
        identity,
        component,
    })
}
fn rename_generation(before: FileGeneration, after: FileGeneration) -> bool {
    before.identity == after.identity
        && before.size == after.size
        && before.links == after.links
        && before.modified_seconds == after.modified_seconds
        && before.modified_nanos == after.modified_nanos
}

#[cfg(test)]
#[path = "npm_materialize_recovery_tests.rs"]
mod tests;
