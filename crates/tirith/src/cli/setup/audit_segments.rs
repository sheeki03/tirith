//! Explicit immutable segment export and irreversible retention deletion.
//! Only server-derived UUID paths are accepted. No active log is modified.
use super::change_plan::{Edit, MutationService, OperationKind, RequestedChange};
use super::fs_helpers;
use super::fs_transaction::{FileUpdate, TransactionOutcome};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use tirith_core::audit::retention::RotationPlan;
use tirith_core::policy_snapshot::{EffectivePolicySnapshot, ResolutionMode};

const CHUNK_BYTES: usize = 8 * 1024 * 1024;
const MAX_CHUNKS: usize = 32;

#[derive(Clone, Serialize, Deserialize)]
#[serde(tag = "action", rename_all = "snake_case", deny_unknown_fields)]
pub(crate) enum SegmentChange {
    Export {
        segment_id: String,
    },
    Delete {
        segment_id: String,
        acknowledge_irreversible: bool,
    },
}
impl SegmentChange {
    fn source(&self) -> &str {
        match self {
            Self::Export { segment_id } | Self::Delete { segment_id, .. } => segment_id,
        }
    }
    fn kind(&self) -> OperationKind {
        match self {
            Self::Export { .. } => OperationKind::ExportAudit,
            Self::Delete { .. } => OperationKind::DeleteAuditSegment,
        }
    }
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct SegmentPlan {
    schema_version: u32,
    operation_id: String,
    change: SegmentChange,
    root: PathBuf,
    records: usize,
    archive_bytes: u64,
    archive_sha256: String,
    files: Vec<FileRevision>,
    checkpoint: Vec<u8>,
    tombstone: Vec<u8>,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct FileRevision {
    name: String,
    bytes: usize,
    sha256: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Manifest {
    schema_version: u32,
    operation_id: String,
    bytes: u64,
    sha256: String,
    checkpoint_sha256: String,
    original_head_sha256: Option<String>,
    chunks: Vec<Chunk>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Chunk {
    bytes: usize,
    sha256: String,
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum SegmentState {
    Original,
    Partial,
    Applied,
}

pub(crate) fn prepare(
    id: &str,
    change: SegmentChange,
    cwd: Option<&str>,
) -> Result<serde_json::Value, String> {
    canonical_id(id)?;
    canonical_id(change.source())?;
    if matches!(
        change,
        SegmentChange::Delete {
            acknowledge_irreversible: false,
            ..
        }
    ) {
        return Err("deletion requires explicit acknowledgement that retained segment records cannot be restored".into());
    }
    let service = MutationService::current()?;
    let kind = change.kind();
    let intent = (cwd, &change);
    if let Some(status) = service.status_for_intent(id, kind, &intent)? {
        return display(status, None, cwd);
    }
    let snapshot = EffectivePolicySnapshot::resolve(cwd, ResolutionMode::Runtime);
    snapshot
        .revalidate_for_mutation()
        .map_err(|e| e.to_string())?;
    let original = service.rotation_plan(change.source())?;
    let plan = SegmentPlan::capture(id, change.clone(), &original)?;
    let preview = plan.projection();
    let status = service.plan_with_preimages_and_intent(id, kind, vec![RequestedChange {
        target: plan.target(), scope_root: plan.root.clone(), edit: Edit::AuditSegment(plan),
        activation: true, description: if matches!(change, SegmentChange::Delete { .. }) {
            "Irreversibly delete the selected retained records; preserve their checkpoint and a deletion record".into()
        } else { "Export the selected exact audit segment into a separate private bundle".into() },
    }], &snapshot, &BTreeMap::new(), &intent)?;
    display(status, Some(preview), cwd)
}
fn display(
    status: super::change_plan::OperationStatus,
    preview: Option<serde_json::Value>,
    cwd: Option<&str>,
) -> Result<serde_json::Value, String> {
    let snapshot = EffectivePolicySnapshot::resolve(cwd, ResolutionMode::LocalOnly);
    let compiled = tirith_core::redact::CompiledCustomPatterns::new_silent(
        &tirith_core::policy::captured_policy_dlp_patterns_or(&snapshot.policy.dlp_custom_patterns),
    );
    Ok(
        serde_json::json!({"schema_version":1,"kind":"audit_segment_plan","preview":preview,
        "operation":crate::cli::profile::status_projection(&status,&compiled)?,"executed":false}),
    )
}
fn canonical_id(id: &str) -> Result<(), String> {
    if uuid::Uuid::parse_str(id).is_ok_and(|value| value.to_string() == id) {
        Ok(())
    } else {
        Err("audit segment and operation IDs must be canonical UUIDs".into())
    }
}
fn hash(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}
fn private_read(path: &Path, root: &Path) -> Result<Option<Vec<u8>>, String> {
    let snapshot = fs_helpers::read_snapshot_scoped(path, root)?;
    snapshot.require_private()?;
    Ok(snapshot.bytes)
}

impl SegmentPlan {
    fn capture(id: &str, change: SegmentChange, original: &RotationPlan) -> Result<Self, String> {
        let root = tirith_core::policy::data_dir().ok_or("operator data directory unavailable")?;
        if !root.is_absolute() || change.source() != original.operation_id() {
            return Err("segment identity differs from its rotation journal".into());
        }
        let source = root.join("audit-segments").join(change.source());
        if private_read(&source.join("deleted.json"), &root)?.is_some() {
            return Err(
                "retained records were already deleted; their checkpoint remains available".into(),
            );
        }
        let manifest_bytes = private_read(&source.join("manifest.json"), &root)?
            .ok_or("retained segment has no complete manifest")?;
        if manifest_bytes.len() > 64 * 1024 {
            return Err("segment manifest exceeds its limit".into());
        }
        let manifest: Manifest =
            serde_json::from_slice(&manifest_bytes).map_err(|_| "segment manifest is invalid")?;
        if manifest.schema_version != 1
            || manifest.operation_id != original.operation_id()
            || manifest.sha256 != original.archive_sha256()
            || manifest.bytes != original.archive_bytes()
            || manifest.checkpoint_sha256 != hash(original.checkpoint())
            || manifest.original_head_sha256 != original.original_head().map(hash)
            || manifest.chunks.is_empty()
            || manifest.chunks.len() > MAX_CHUNKS
            || manifest
                .chunks
                .iter()
                .any(|c| c.bytes == 0 || c.bytes > CHUNK_BYTES)
            || manifest.chunks.iter().map(|c| c.bytes as u64).sum::<u64>() != manifest.bytes
        {
            return Err("retained manifest does not match its verified rotation".into());
        }
        let mut files = Vec::new();
        let mut combined = Sha256::new();
        for (index, chunk) in manifest.chunks.iter().enumerate() {
            let name = format!("{index:04}.chunk");
            let bytes =
                private_read(&source.join(&name), &root)?.ok_or("retained chunk unavailable")?;
            if bytes.len() != chunk.bytes || hash(&bytes) != chunk.sha256 {
                return Err("retained chunk changed".into());
            }
            combined.update(&bytes);
            files.push(FileRevision {
                name,
                bytes: chunk.bytes,
                sha256: chunk.sha256.clone(),
            });
        }
        if format!("{:x}", combined.finalize()) != manifest.sha256 {
            return Err("retained archive digest differs".into());
        }
        let checkpoint = private_read(&source.join("checkpoint.json"), &root)?
            .ok_or("retained checkpoint unavailable")?;
        if checkpoint != original.checkpoint() {
            return Err("retained checkpoint changed".into());
        }
        files.push(FileRevision {
            name: "checkpoint.json".into(),
            bytes: checkpoint.len(),
            sha256: hash(&checkpoint),
        });
        if let Some(head) = original.original_head() {
            if private_read(&source.join("original.head"), &root)?.as_deref() != Some(head) {
                return Err("retained head changed".into());
            }
            files.push(FileRevision {
                name: "original.head".into(),
                bytes: head.len(),
                sha256: hash(head),
            });
        }
        files.push(FileRevision {
            name: "manifest.json".into(),
            bytes: manifest_bytes.len(),
            sha256: hash(&manifest_bytes),
        });
        let records = original.projection()["retained_records"]
            .as_u64()
            .ok_or("rotation record count unavailable")? as usize;
        let tombstone = serde_json::to_vec(&serde_json::json!({"schema_version":1,"kind":"audit-segment-deletion",
            "operation_id":id,"segment_id":change.source(),"record_count":records,"archive_bytes":manifest.bytes,
            "archive_sha256":manifest.sha256,"checkpoint_sha256":hash(&checkpoint),
            "record_availability":"operator_deleted","active_chain_modified":false,
            "irreversible":true,"recorded_at":chrono::Utc::now().to_rfc3339()})).map_err(|e| e.to_string())?;
        let plan = Self {
            schema_version: 1,
            operation_id: id.into(),
            change,
            root,
            records,
            archive_bytes: manifest.bytes,
            archive_sha256: manifest.sha256,
            files,
            checkpoint,
            tombstone,
        };
        if plan.observe()? != SegmentState::Original {
            return Err("segment destination changed before planning".into());
        }
        Ok(plan)
    }
    pub(super) fn operation_id(&self) -> &str {
        &self.operation_id
    }
    pub(super) fn kind(&self) -> OperationKind {
        self.change.kind()
    }
    pub(super) fn irreversible(&self) -> bool {
        matches!(self.change, SegmentChange::Delete { .. })
    }
    pub(super) fn target(&self) -> PathBuf {
        self.destination().join(if self.irreversible() {
            "deleted.json"
        } else {
            "manifest.json"
        })
    }
    pub(super) fn validate_target(&self, target: &Path, root: &Path) -> Result<(), String> {
        self.validate()?;
        if root != self.root || target != self.target() {
            return Err("segment mutation target changed".into());
        }
        Ok(())
    }
    fn source(&self) -> PathBuf {
        self.root.join("audit-segments").join(self.change.source())
    }
    fn destination(&self) -> PathBuf {
        if self.irreversible() {
            self.source()
        } else {
            self.root.join("audit-exports").join(&self.operation_id)
        }
    }
    fn validate(&self) -> Result<(), String> {
        canonical_id(&self.operation_id)?;
        canonical_id(self.change.source())?;
        if matches!(
            self.change,
            SegmentChange::Delete {
                acknowledge_irreversible: false,
                ..
            }
        ) || self.schema_version != 1
            || tirith_core::policy::data_dir().as_deref() != Some(self.root.as_path())
            || self.files.is_empty()
            || self.files.len() > MAX_CHUNKS + 3
            || self.files.iter().any(|file| {
                file.bytes > CHUNK_BYTES
                    || !(file.name == "checkpoint.json"
                        || file.name == "manifest.json"
                        || file.name == "original.head"
                        || (file.name.len() == 10
                            && file.name.ends_with(".chunk")
                            && file.name[..4].bytes().all(|c| c.is_ascii_digit())))
            })
        {
            return Err("segment plan shape or operator data directory changed".into());
        }
        Ok(())
    }
    fn read_revision(
        &self,
        base: &Path,
        revision: &FileRevision,
    ) -> Result<Option<Vec<u8>>, String> {
        let bytes = private_read(&base.join(&revision.name), &self.root)?;
        if bytes
            .as_ref()
            .is_some_and(|bytes| bytes.len() != revision.bytes || hash(bytes) != revision.sha256)
        {
            return Err("owned retained segment file changed; preserve it for review".into());
        }
        Ok(bytes)
    }
    pub(super) fn observe(&self) -> Result<SegmentState, String> {
        self.validate()?;
        let destination = self.destination();
        let marker = if self.irreversible() {
            private_read(&destination.join("deleted.json"), &self.root)?
        } else {
            None
        };
        if marker
            .as_ref()
            .is_some_and(|bytes| bytes != &self.tombstone)
        {
            return Err("segment deletion marker belongs to another generation".into());
        }
        let mut present = 0;
        let mut total = 0;
        for file in &self.files {
            if self.irreversible() && file.name == "checkpoint.json" {
                if self.read_revision(&destination, file)?.is_none() {
                    return Err("retained checkpoint is unavailable".into());
                }
                continue;
            }
            total += 1;
            present += usize::from(self.read_revision(&destination, file)?.is_some());
        }
        if self.irreversible() {
            if marker.is_none() {
                if present == total {
                    Ok(SegmentState::Original)
                } else {
                    Err("segment disappeared before deletion intent was recorded".into())
                }
            } else if present == 0 {
                Ok(SegmentState::Applied)
            } else {
                Ok(SegmentState::Partial)
            }
        } else if present == 0 {
            Ok(SegmentState::Original)
        } else if present == total {
            Ok(SegmentState::Applied)
        } else {
            Ok(SegmentState::Partial)
        }
    }
    pub(super) fn projection(&self) -> serde_json::Value {
        serde_json::json!({"schema_version":1,"kind":"audit_segment_preview","segment_id":self.change.source(),
            "operation_id":self.operation_id,"action":if self.irreversible(){"delete"}else{"export"},
            "retained_records":self.records,"retained_bytes":self.archive_bytes,
            "archive_sha256":self.archive_sha256,"irreversible":self.irreversible(),
            "active_log_modified":false,"checkpoint_retained":true,"executed":false})
    }
    pub(super) fn mutate(
        &self,
        policy: &EffectivePolicySnapshot,
        undo: bool,
        mut guard: impl FnMut() -> Result<(), String>,
    ) -> Result<TransactionOutcome, String> {
        self.validate()?;
        if undo && self.irreversible() {
            return Err("retained record deletion is irreversible; its checkpoint and deletion record remain".into());
        }
        guard()?;
        let destination = self.destination();
        let mut recovery = false;
        if self.irreversible() {
            self.observe()?;
            publish(
                &destination.join("deleted.json"),
                &self.root,
                &self.tombstone,
                policy,
                self.kind(),
                &mut guard,
                &mut recovery,
            )?;
        }
        if self.irreversible() || undo {
            // Marker/checkpoint outlive every deleted chunk. For export undo,
            // delete the complete manifest first so a partial bundle is never
            // advertised as a finished export.
            let files: Vec<_> = if undo {
                self.files.iter().rev().collect()
            } else {
                self.files.iter().collect()
            };
            for revision in files {
                if self.irreversible() && revision.name == "checkpoint.json" {
                    continue;
                }
                guard()?;
                self.validate()?;
                self.observe()?;
                if let Some(bytes) = self.read_revision(&destination, revision)? {
                    let path = destination.join(&revision.name);
                    let retained = crate::cli::prepare_config_destination_permitted(
                        &self.root,
                        &path,
                        true,
                        &policy.policy,
                        false,
                        false,
                    )
                    .map_err(|e| e.to_string())?;
                    let actual = retained
                        .read_capped(CHUNK_BYTES as u64)
                        .map_err(|e| format!("cannot capture retained delete preimage: {e:?}"))?;
                    if actual != bytes {
                        return Err("retained delete generation changed".into());
                    }
                    guard()?;
                    policy
                        .revalidate_for_mutation()
                        .map_err(|e| e.to_string())?;
                    crate::cli::delete_prepared_config_file_permitted(
                        &self.root,
                        &path,
                        retained,
                        &actual,
                        &policy.policy,
                        false,
                    )
                    .map_err(|e| e.to_string())?;
                }
            }
        } else {
            // Check the entire immutable source before the first export write.
            // Recheck each retained chunk again at its own publication.
            for revision in &self.files {
                self.read_revision(&self.source(), revision)
                    .map_err(|error| format!("refresh-required: {error}"))?
                    .ok_or("refresh-required: source segment is unavailable")?;
            }
            for revision in &self.files {
                guard()?;
                self.validate()?;
                let bytes = self
                    .read_revision(&self.source(), revision)?
                    .ok_or("source segment is no longer available for export")?;
                publish(
                    &destination.join(&revision.name),
                    &self.root,
                    &bytes,
                    policy,
                    self.kind(),
                    &mut guard,
                    &mut recovery,
                )?;
            }
        }
        let observed = self.observe()?;
        if (!undo && observed != SegmentState::Applied)
            || (undo && observed != SegmentState::Original)
        {
            return Err("segment operation has not reached its intended postconditions".into());
        }
        Ok(if recovery {
            TransactionOutcome::WrittenWithRecovery
        } else {
            TransactionOutcome::Written
        })
    }
}

fn publish(
    path: &Path,
    root: &Path,
    bytes: &[u8],
    policy: &EffectivePolicySnapshot,
    kind: OperationKind,
    guard: &mut impl FnMut() -> Result<(), String>,
    recovery: &mut bool,
) -> Result<(), String> {
    guard()?;
    policy
        .revalidate_for_mutation()
        .map_err(|e| e.to_string())?;
    super::change_plan::preflight_target(kind, root, path, policy)?;
    let result = super::fs_transaction::transactional_update_authorized(
        path,
        root,
        false,
        |snapshot| {
            snapshot.require_private()?;
            if let Some(current) = snapshot.bytes() {
                if current == bytes {
                    return Ok(FileUpdate::unchanged());
                }
                return Err("immutable segment publication destination changed".into());
            }
            Ok(FileUpdate::Write {
                bytes: bytes.to_vec(),
                mode: 0o600,
                preserve_existing_mode: false,
                backup: false,
            })
        },
        || {
            guard()?;
            policy.revalidate_for_mutation().map_err(|e| e.to_string())
        },
        |payload| super::change_plan::authorize_publication(kind, root, path, payload, policy),
    )?;
    *recovery |= result == TransactionOutcome::WrittenWithRecovery;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::super::change_plan::JobState;
    use super::*;
    use crate::cli::test_harness::with_fake_env;

    fn retained() -> (String, PathBuf, Vec<u8>) {
        tirith_core::audit::log_hook_event("test", "retention", "source", None, None);
        let active = tirith_core::audit::audit_log_path().unwrap();
        let original = std::fs::read(&active).unwrap();
        let id = uuid::Uuid::new_v4().to_string();
        super::super::audit_service::prepare(
            &id,
            super::super::audit_service::AuditChange::Rotate,
            None,
        )
        .unwrap();
        let state = MutationService::current()
            .unwrap()
            .apply(
                &id,
                &EffectivePolicySnapshot::resolve(None, ResolutionMode::Runtime),
            )
            .unwrap();
        assert!(matches!(
            state.state,
            JobState::Completed | JobState::CompletedWithRecovery
        ));
        (id, active, original)
    }
    #[test]
    fn exported_segment_contains_exact_records_and_undo_leaves_source_and_active_chain() {
        with_fake_env(true, |_, _| {
            let (source_id, active, original) = retained();
            let active_bytes = std::fs::read(&active).unwrap();
            let id = uuid::Uuid::new_v4().to_string();
            prepare(
                &id,
                SegmentChange::Export {
                    segment_id: source_id.clone(),
                },
                None,
            )
            .unwrap();
            let service = MutationService::current().unwrap();
            let policy = EffectivePolicySnapshot::resolve(None, ResolutionMode::Runtime);
            service.apply(&id, &policy).unwrap();
            let data = tirith_core::policy::data_dir().unwrap();
            let destination = data.join("audit-exports").join(&id);
            assert_eq!(
                std::fs::read(destination.join("0000.chunk")).unwrap(),
                original
            );
            assert!(destination.join("manifest.json").exists());
            service.undo(&id, &policy).unwrap();
            assert!(!destination.join("manifest.json").exists());
            assert!(!destination.join("0000.chunk").exists());
            assert_eq!(
                std::fs::read(
                    data.join("audit-segments")
                        .join(source_id)
                        .join("0000.chunk")
                )
                .unwrap(),
                original
            );
            assert_eq!(std::fs::read(&active).unwrap(), active_bytes);
        });
    }
    #[test]
    fn explicit_delete_is_irreversible_and_retains_checkpoint_and_deletion_record() {
        with_fake_env(true, |_, _| {
            let (source_id, active, _) = retained();
            let active_bytes = std::fs::read(&active).unwrap();
            let id = uuid::Uuid::new_v4().to_string();
            assert!(prepare(
                &id,
                SegmentChange::Delete {
                    segment_id: source_id.clone(),
                    acknowledge_irreversible: false
                },
                None
            )
            .is_err());
            prepare(
                &id,
                SegmentChange::Delete {
                    segment_id: source_id.clone(),
                    acknowledge_irreversible: true,
                },
                None,
            )
            .unwrap();
            let service = MutationService::current().unwrap();
            let policy = EffectivePolicySnapshot::resolve(None, ResolutionMode::Runtime);
            service.apply(&id, &policy).unwrap();
            let source = tirith_core::policy::data_dir()
                .unwrap()
                .join("audit-segments")
                .join(&source_id);
            assert!(source.join("deleted.json").exists());
            assert!(source.join("checkpoint.json").exists());
            assert!(!source.join("0000.chunk").exists());
            assert!(!source.join("manifest.json").exists());
            assert!(service.undo(&id, &policy).is_err());
            assert_eq!(std::fs::read(&active).unwrap(), active_bytes);
            assert!(tirith_core::audit::verify_audit_log(&active, None).ok);
            assert!(prepare(
                &uuid::Uuid::new_v4().to_string(),
                SegmentChange::Export {
                    segment_id: source_id
                },
                None
            )
            .is_err());
        });
    }
    #[test]
    fn changed_owned_archive_bytes_refuse_deletion_before_tombstone_or_data_loss() {
        with_fake_env(true, |_, _| {
            let (source_id, _, _) = retained();
            let id = uuid::Uuid::new_v4().to_string();
            prepare(
                &id,
                SegmentChange::Delete {
                    segment_id: source_id.clone(),
                    acknowledge_irreversible: true,
                },
                None,
            )
            .unwrap();
            let source = tirith_core::policy::data_dir()
                .unwrap()
                .join("audit-segments")
                .join(&source_id);
            std::fs::write(source.join("0000.chunk"), b"intervening data").unwrap();
            let result = MutationService::current().unwrap().apply(
                &id,
                &EffectivePolicySnapshot::resolve(None, ResolutionMode::Runtime),
            );
            assert!(result.is_err() || result.unwrap().state == JobState::RefreshRequired);
            assert!(!source.join("deleted.json").exists());
            assert_eq!(
                std::fs::read(source.join("0000.chunk")).unwrap(),
                b"intervening data"
            );
        });
    }
}
