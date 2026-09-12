//! Typed same-inode audit retention. Archives are private bounded chunks; the
//! operation journal owns the immutable plan and all crash/undo state.
use std::fs::File;
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tirith_core::audit::retention::{LockedAuditLog, RotationPlan, RotationState, RotationStore};
use tirith_core::policy_snapshot::{EffectivePolicySnapshot, ResolutionMode};

use super::change_plan::{Edit, MutationService, OperationKind, OperationStatus, RequestedChange};
use super::fs_helpers;
use super::fs_transaction::{FileUpdate, TransactionOutcome};

const CHUNK_BYTES: usize = 8 * 1024 * 1024;
const MAX_CHUNKS: usize = 32;

#[derive(Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum AuditChange {
    Rotate,
}

pub(crate) fn prepare(
    id: &str,
    change: AuditChange,
    cwd: Option<&str>,
) -> Result<serde_json::Value, String> {
    uuid::Uuid::parse_str(id).map_err(|_| "operation ID must be a UUID")?;
    let service = MutationService::current()?;
    let intent = (cwd, change);
    if let Some(status) = service.status_for_intent(id, OperationKind::RotateAudit, &intent)? {
        return projection(status, None);
    }
    let snapshot = EffectivePolicySnapshot::resolve(cwd, ResolutionMode::Runtime);
    snapshot
        .revalidate_for_mutation()
        .map_err(|e| e.to_string())?;
    let root = tirith_core::policy::data_dir().ok_or("operator data directory unavailable")?;
    let target = tirith_core::audit::audit_log_path().ok_or("audit log path unavailable")?;
    check_paths(&target, &root, id)?;
    super::change_plan::preflight_target(OperationKind::RotateAudit, &root, &target, &snapshot)?;
    let plan = capture(id, &target, &root, &snapshot)?;
    let preview = plan.projection();
    let status = service.plan_with_preimages_and_intent(
        id,
        OperationKind::RotateAudit,
        vec![RequestedChange {
            target,
            scope_root: root,
            edit: Edit::AuditRotation(plan),
            activation: true,
            description: "Rotate verified audit history to a private retained segment".into(),
        }],
        &snapshot,
        &Default::default(),
        &intent,
    )?;
    projection(status, Some(preview))
}

fn projection(
    status: OperationStatus,
    preview: Option<serde_json::Value>,
) -> Result<serde_json::Value, String> {
    let policy = EffectivePolicySnapshot::resolve(None, ResolutionMode::LocalOnly);
    let compiled = tirith_core::redact::CompiledCustomPatterns::new_silent(
        &tirith_core::policy::captured_policy_dlp_patterns_or(&policy.policy.dlp_custom_patterns),
    );
    let status = crate::cli::profile::status_projection(&status, &compiled)?;
    Ok(
        serde_json::json!({"schema_version":1,"kind":"audit_rotation_plan", "operation":status,
        "preview":preview,"executed":false}),
    )
}

fn check_paths(target: &Path, root: &Path, id: &str) -> Result<(), String> {
    uuid::Uuid::parse_str(id).map_err(|_| "rotation ID must be a UUID")?;
    if !root.is_absolute() || target != root.join("log.jsonl") {
        return Err("retention requires the operator's fixed active audit log".into());
    }
    Ok(())
}

fn open<'a>(
    target: &Path,
    root: &Path,
    id: &str,
    policy: Option<&'a EffectivePolicySnapshot>,
    guard: &'a mut dyn FnMut() -> Result<(), String>,
) -> Result<(LockedAuditLog, Store<'a>), String> {
    check_paths(target, root, id)?;
    let (file, lease) = fs_helpers::open_existing_in_place(target, root)?;
    let log = LockedAuditLog::acquire(file)?;
    let store = Store {
        lease,
        identity: log.identity(),
        root: root.into(),
        target: target.into(),
        archive: root.join("audit-segments").join(id),
        policy,
        guard,
        head_generation: None,
        recovery: false,
    };
    Ok((log, store))
}

fn capture(
    id: &str,
    target: &Path,
    root: &Path,
    policy: &EffectivePolicySnapshot,
) -> Result<RotationPlan, String> {
    let mut guard = || policy.revalidate_for_mutation().map_err(|e| e.to_string());
    let (mut log, mut store) = open(target, root, id, Some(policy), &mut guard)?;
    RotationPlan::capture(id, &mut log, &mut store)
}

pub(super) fn observe(
    plan: &RotationPlan,
    target: &Path,
    root: &Path,
) -> Result<RotationState, String> {
    let mut guard = || Err("read-only retention observation cannot publish".into());
    let (mut log, mut store) = open(target, root, plan.operation_id(), None, &mut guard)?;
    plan.observe(&mut log, &mut store)
}

pub(super) fn mutate(
    plan: &RotationPlan,
    target: &Path,
    root: &Path,
    policy: &EffectivePolicySnapshot,
    undo: bool,
    mut guard: impl FnMut() -> Result<(), String>,
) -> Result<TransactionOutcome, String> {
    let (mut log, mut store) = open(target, root, plan.operation_id(), Some(policy), &mut guard)?;
    if undo {
        plan.undo(&mut log, &mut store)?;
    } else {
        plan.apply(&mut log, &mut store)?;
    }
    Ok(if store.recovery {
        TransactionOutcome::WrittenWithRecovery
    } else {
        TransactionOutcome::Written
    })
}

#[derive(Serialize, Deserialize)]
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
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Chunk {
    bytes: usize,
    sha256: String,
}

struct Store<'a> {
    lease: fs_helpers::InPlaceLease,
    identity: (u64, u64),
    root: PathBuf,
    target: PathBuf,
    archive: PathBuf,
    policy: Option<&'a EffectivePolicySnapshot>,
    guard: &'a mut dyn FnMut() -> Result<(), String>,
    head_generation: Option<Option<Vec<u8>>>,
    recovery: bool,
}

fn hash(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}
impl Store<'_> {
    fn read_private(&self, path: &Path) -> Result<Option<Vec<u8>>, String> {
        let snapshot = fs_helpers::read_snapshot_scoped(path, &self.root)?;
        snapshot.require_private()?;
        Ok(snapshot.bytes)
    }
    fn publish(
        &mut self,
        path: &Path,
        bytes: &[u8],
        expected: Option<&Option<Vec<u8>>>,
    ) -> Result<(), String> {
        self.before_mutation()?;
        let policy = self.policy.ok_or("retention observer cannot write")?;
        super::change_plan::preflight_target(OperationKind::RotateAudit, &self.root, path, policy)?;
        let check = std::cell::RefCell::new(&mut *self.guard);
        let outcome = super::fs_transaction::transactional_update_authorized(
            path,
            &self.root,
            false,
            |snapshot| {
                snapshot.require_private()?;
                if let Some(expected) = expected {
                    if snapshot.bytes() != expected.as_deref() {
                        return Err("audit head changed before publication".into());
                    }
                } else if let Some(current) = snapshot.bytes() {
                    if current == bytes {
                        return Ok(FileUpdate::unchanged());
                    }
                    return Err(
                        "immutable audit archive entry changed; retain it for recovery".into(),
                    );
                }
                Ok(FileUpdate::Write {
                    bytes: bytes.to_vec(),
                    mode: 0o600,
                    preserve_existing_mode: false,
                    backup: false,
                })
            },
            || {
                self.lease.validate(self.identity)?;
                (**check.borrow_mut())()
            },
            |payload| {
                super::change_plan::authorize_publication(
                    OperationKind::RotateAudit,
                    &self.root,
                    path,
                    payload,
                    policy,
                )
            },
        )?;
        self.recovery |= outcome == TransactionOutcome::WrittenWithRecovery;
        Ok(())
    }
    fn manifest(&self, plan: &RotationPlan) -> Result<Manifest, String> {
        let bytes = self
            .read_private(&self.archive.join("manifest.json"))?
            .ok_or("audit archive is incomplete")?;
        if bytes.len() > 64 * 1024 {
            return Err("audit manifest exceeds limit".into());
        }
        let manifest: Manifest =
            serde_json::from_slice(&bytes).map_err(|_| "audit archive manifest is invalid")?;
        if manifest.schema_version != 1
            || manifest.operation_id != plan.operation_id()
            || manifest.bytes != plan.archive_bytes()
            || manifest.sha256 != plan.archive_sha256()
            || manifest.checkpoint_sha256 != hash(plan.checkpoint())
            || manifest.original_head_sha256 != plan.original_head().map(hash)
            || manifest.chunks.is_empty()
            || manifest.chunks.len() > MAX_CHUNKS
            || manifest
                .chunks
                .iter()
                .any(|chunk| chunk.bytes == 0 || chunk.bytes > CHUNK_BYTES)
            || manifest
                .chunks
                .iter()
                .map(|chunk| chunk.bytes as u64)
                .sum::<u64>()
                != manifest.bytes
        {
            return Err("audit manifest does not match immutable rotation plan".into());
        }
        Ok(manifest)
    }
    fn chunks(
        &mut self,
        plan: &RotationPlan,
        mut consume: impl FnMut(&[u8]) -> Result<(), String>,
    ) -> Result<(), String> {
        self.lease.validate(self.identity)?;
        let manifest = self.manifest(plan)?;
        let checkpoint = self
            .read_private(&self.archive.join("checkpoint.json"))?
            .ok_or("archive checkpoint missing")?;
        if checkpoint != plan.checkpoint() {
            return Err("archive checkpoint changed".into());
        }
        if let Some(expected) = plan.original_head() {
            if self
                .read_private(&self.archive.join("original.head"))?
                .as_deref()
                != Some(expected)
            {
                return Err("archive original head changed".into());
            }
        }
        let mut combined = Sha256::new();
        for (index, chunk) in manifest.chunks.iter().enumerate() {
            self.lease.validate(self.identity)?;
            let bytes = self
                .read_private(&self.archive.join(format!("{index:04}.chunk")))?
                .ok_or("archive chunk missing")?;
            if bytes.len() != chunk.bytes || hash(&bytes) != chunk.sha256 {
                return Err("audit archive chunk changed".into());
            }
            combined.update(&bytes);
            consume(&bytes)?;
        }
        if format!("{:x}", combined.finalize()) != manifest.sha256 {
            return Err("audit archive hash differs".into());
        }
        Ok(())
    }
}

impl RotationStore for Store<'_> {
    fn validate_bindings(&mut self, identity: (u64, u64)) -> Result<(), String> {
        self.lease.validate(identity)
    }
    fn read_head(&mut self) -> Result<Option<Vec<u8>>, String> {
        let head = self.read_private(&self.root.join("log.jsonl.head"))?;
        if head.as_ref().is_some_and(|bytes| bytes.len() > 64 * 1024) {
            return Err("audit head exceeds limit".into());
        }
        self.head_generation = Some(head.clone());
        Ok(head)
    }
    fn before_mutation(&mut self) -> Result<(), String> {
        self.lease.validate(self.identity)?;
        (self.guard)()?;
        let policy = self.policy.ok_or("retention observer cannot mutate")?;
        super::change_plan::preflight_target(
            OperationKind::RotateAudit,
            &self.root,
            &self.target,
            policy,
        )
    }
    fn authorize_log_mutation(
        &mut self,
        plan: &RotationPlan,
        mutation: tirith_core::audit::retention::LogMutation,
    ) -> Result<(), String> {
        self.before_mutation()?;
        super::change_plan::authorize_publication(
            OperationKind::RotateAudit,
            &self.root,
            &self.target,
            &plan.mutation_binding(mutation)?,
            self.policy.ok_or("retention observer cannot mutate")?,
        )
    }
    fn publish_head(&mut self, bytes: &[u8]) -> Result<(), String> {
        let expected = self
            .head_generation
            .clone()
            .ok_or("head generation was not captured")?;
        self.publish(&self.root.join("log.jsonl.head"), bytes, Some(&expected))?;
        self.head_generation = Some(Some(bytes.to_vec()));
        Ok(())
    }
    fn ensure_archive(&mut self, source: &mut File, plan: &RotationPlan) -> Result<(), String> {
        self.before_mutation()?;
        let policy = self.policy.ok_or("retention observer cannot archive")?;
        super::change_plan::preflight_target(
            OperationKind::RotateAudit,
            &self.root,
            &self.archive.join("manifest.json"),
            policy,
        )?;
        fs_helpers::ensure_private_directory(&self.archive, &self.root)?;
        source.seek(SeekFrom::Start(0)).map_err(|e| e.to_string())?;
        let mut remaining = plan.archive_bytes();
        let mut chunks = Vec::new();
        let mut combined = Sha256::new();
        while remaining != 0 {
            if chunks.len() >= MAX_CHUNKS {
                return Err("audit archive exceeds chunk limit".into());
            }
            let mut bytes = vec![0; remaining.min(CHUNK_BYTES as u64) as usize];
            source.read_exact(&mut bytes).map_err(|e| e.to_string())?;
            combined.update(&bytes);
            self.publish(
                &self.archive.join(format!("{:04}.chunk", chunks.len())),
                &bytes,
                None,
            )?;
            remaining -= bytes.len() as u64;
            chunks.push(Chunk {
                bytes: bytes.len(),
                sha256: hash(&bytes),
            });
        }
        if format!("{:x}", combined.finalize()) != plan.archive_sha256() {
            return Err("audit source changed while archiving".into());
        }
        self.publish(
            &self.archive.join("checkpoint.json"),
            plan.checkpoint(),
            None,
        )?;
        if let Some(head) = plan.original_head() {
            self.publish(&self.archive.join("original.head"), head, None)?;
        }
        let manifest = Manifest {
            schema_version: 1,
            operation_id: plan.operation_id().into(),
            bytes: plan.archive_bytes(),
            sha256: plan.archive_sha256().into(),
            checkpoint_sha256: hash(plan.checkpoint()),
            original_head_sha256: plan.original_head().map(hash),
            chunks,
        };
        self.publish(
            &self.archive.join("manifest.json"),
            &serde_json::to_vec(&manifest).map_err(|e| e.to_string())?,
            None,
        )
    }
    fn verify_archive(&mut self, plan: &RotationPlan) -> Result<(), String> {
        self.chunks(plan, |_| Ok(()))
    }
    fn matches_archive_prefix(
        &mut self,
        source: &mut File,
        plan: &RotationPlan,
    ) -> Result<bool, String> {
        source.seek(SeekFrom::Start(0)).map_err(|e| e.to_string())?;
        let mut remaining = source.metadata().map_err(|e| e.to_string())?.len();
        let mut matches = remaining < plan.archive_bytes();
        self.chunks(plan, |bytes| {
            let length = remaining.min(bytes.len() as u64) as usize;
            if length != 0 {
                let mut current = vec![0; length];
                source.read_exact(&mut current).map_err(|e| e.to_string())?;
                matches &= current == bytes[..length];
                remaining -= length as u64;
            }
            Ok(())
        })?;
        Ok(matches && remaining == 0)
    }
    fn restore_archive(
        &mut self,
        destination: &mut File,
        plan: &RotationPlan,
    ) -> Result<(), String> {
        self.chunks(plan, |bytes| {
            destination.write_all(bytes).map_err(|e| e.to_string())
        })
    }
}

#[cfg(test)]
mod tests {
    use super::super::change_plan::JobState;
    use super::*;
    use crate::cli::test_harness::with_fake_env;

    fn seed() -> (PathBuf, Vec<u8>) {
        tirith_core::audit::log_hook_event("test", "retention", "before", None, None);
        let path = tirith_core::audit::audit_log_path().unwrap();
        let bytes = std::fs::read(&path).unwrap();
        assert!(tirith_core::audit::verify_audit_log(&path, None).ok);
        (path, bytes)
    }

    #[test]
    fn shared_rotation_plan_applies_and_compensates_exact_bytes_without_replacing_log() {
        with_fake_env(true, |_, _| {
            let (path, before) = seed();
            let root = path.parent().unwrap();
            let id = uuid::Uuid::new_v4().to_string();
            let preview = prepare(&id, AuditChange::Rotate, None).unwrap();
            assert_eq!(preview["preview"]["retained_bytes"], before.len());
            assert_eq!(std::fs::read(&path).unwrap(), before);
            assert!(!root.join("audit-segments").exists());
            let service = MutationService::current().unwrap();
            let policy = EffectivePolicySnapshot::resolve(None, ResolutionMode::Runtime);
            let (old, _lease) = fs_helpers::open_existing_in_place(&path, root).unwrap();
            let completed = service.apply(&id, &policy).unwrap();
            assert!(matches!(
                completed.state,
                JobState::Completed | JobState::CompletedWithRecovery
            ));
            assert_eq!(
                old.metadata().unwrap().len(),
                std::fs::metadata(&path).unwrap().len()
            );
            assert!(tirith_core::audit::verify_audit_log(&path, None).ok);
            assert_eq!(
                std::fs::read(root.join("audit-segments").join(&id).join("0000.chunk")).unwrap(),
                before
            );
            let undone = service.undo(&id, &policy).unwrap();
            assert!(matches!(
                undone.state,
                JobState::Undone | JobState::UndoneWithRecovery
            ));
            assert_eq!(std::fs::read(&path).unwrap(), before);
            assert!(tirith_core::audit::verify_audit_log(&path, None).ok);
        });
    }

    #[test]
    fn new_records_after_rotation_are_preserved_and_prevent_undo() {
        with_fake_env(true, |_, _| {
            let (path, _) = seed();
            let id = uuid::Uuid::new_v4().to_string();
            prepare(&id, AuditChange::Rotate, None).unwrap();
            let service = MutationService::current().unwrap();
            let snapshot = EffectivePolicySnapshot::resolve(None, ResolutionMode::Runtime);
            service.apply(&id, &snapshot).unwrap();
            tirith_core::audit::log_hook_event("test", "retention", "later", None, None);
            let later = std::fs::read(&path).unwrap();
            assert!(service.undo(&id, &snapshot).is_err());
            assert_eq!(std::fs::read(&path).unwrap(), later);
            assert!(tirith_core::audit::verify_audit_log(&path, None).ok);
            let replay = prepare(&id, AuditChange::Rotate, None).unwrap();
            assert_eq!(replay["operation"]["operation_id"], id);
        });
    }

    #[test]
    fn intervening_append_and_task_gate_denial_prevent_any_archive_or_active_write() {
        with_fake_env(true, |_, _| {
            let (path, _) = seed();
            let root = path.parent().unwrap();
            let id = uuid::Uuid::new_v4().to_string();
            prepare(&id, AuditChange::Rotate, None).unwrap();
            tirith_core::audit::log_hook_event("test", "retention", "intervening", None, None);
            let intervening = std::fs::read(&path).unwrap();
            let service = MutationService::current().unwrap();
            let snapshot = EffectivePolicySnapshot::resolve(None, ResolutionMode::Runtime);
            let result = service.apply(&id, &snapshot);
            assert!(result.is_err() || result.unwrap().state == JobState::RefreshRequired);
            assert_eq!(std::fs::read(&path).unwrap(), intervening);
            assert!(!root.join("audit-segments").exists());
            let id = uuid::Uuid::new_v4().to_string();
            prepare(&id, AuditChange::Rotate, None).unwrap();
            let mut denied = EffectivePolicySnapshot::resolve(None, ResolutionMode::Runtime);
            denied.policy.task_gate.mode = tirith_core::web3_policy::TaskGateMode::Enforce;
            denied
                .policy
                .task_gate
                .effects_denied_for_untrusted_sources
                .insert(tirith_core::effects::CommandEffectKind::FilesystemWrite);
            let result = service.apply(&id, &denied);
            assert!(result.is_err() || result.unwrap().state == JobState::RefreshRequired);
            assert_eq!(std::fs::read(&path).unwrap(), intervening);
            assert!(!root.join("audit-segments").exists());
        });
    }
}
