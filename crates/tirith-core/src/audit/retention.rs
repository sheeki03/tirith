//! Same-inode audit rotation protocol. Publication and private archive ownership
//! belong to a retained-capability store supplied by the typed mutation service.
//! Old writers share the existing log lock and reject the invalid-head barrier.
use std::fs::File;
use std::io::{Read, Seek, SeekFrom, Write};
use std::time::{Duration, Instant};

use fs2::FileExt;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

const LOCK_WAIT: Duration = Duration::from_secs(30);
const MAX_BYTES: u64 = 256 * 1024 * 1024;
const MAX_HEAD: usize = 64 * 1024;

/// Retains the actual log inode and its exclusive native lock. The caller must
/// retain its directory capability too; `RotationStore::validate_bindings`
/// verifies that capability at every destructive boundary.
pub struct LockedAuditLog {
    file: File,
    identity: (u64, u64),
}

impl LockedAuditLog {
    pub fn acquire(file: File) -> Result<Self, String> {
        let metadata = file.metadata().map_err(err)?;
        if !metadata.is_file() || crate::util::dirfd::hard_link_count(&file) != Some(1) {
            return Err("audit rotation requires a regular single-link log".into());
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            if metadata.uid() != unsafe { libc::geteuid() } || metadata.mode() & 0o077 != 0 {
                return Err("audit rotation requires a private current-user-owned log".into());
            }
        }
        let start = Instant::now();
        loop {
            match file.try_lock_exclusive() {
                Ok(()) => break,
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    if start.elapsed() >= LOCK_WAIT {
                        return Err("audit writer lock deadline reached".into());
                    }
                    std::thread::sleep(Duration::from_millis(10));
                }
                Err(error) => return Err(err(error)),
            }
        }
        let identity = match crate::util::dirfd::file_identity(&file) {
            Ok(identity) => identity,
            Err(error) => {
                let _ = FileExt::unlock(&file);
                return Err(err(error));
            }
        };
        Ok(Self { file, identity })
    }

    pub fn identity(&self) -> (u64, u64) {
        self.identity
    }
}

impl Drop for LockedAuditLog {
    fn drop(&mut self) {
        let _ = FileExt::unlock(&self.file);
    }
}

/// Private, restartable immutable payload. Its serialized form belongs only in
/// the protected operation journal; public consumers receive `projection()`.
#[derive(Clone, Serialize, Deserialize)]
pub struct RotationPlan {
    schema_version: u32,
    operation_id: String,
    log_identity: (u64, u64),
    original_bytes: u64,
    original_sha256: String,
    original_head: Option<Vec<u8>>,
    original_lines: usize,
    original_signed: bool,
    original_restore_head: Vec<u8>,
    checkpoint: Vec<u8>,
    genesis: Vec<u8>,
    genesis_head: Vec<u8>,
    barrier: Vec<u8>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    signing_inputs: Option<SigningInputs>,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
struct SigningInputs {
    configured: bool,
    signer_public: Option<[u8; 32]>,
    verifier_public: Option<[u8; 32]>,
}
impl SigningInputs {
    fn capture() -> Self {
        Self {
            configured: super::audit_signing_configured(),
            signer_public: super::audit_signing_secret().map(|bytes| {
                ed25519_dalek::SigningKey::from_bytes(&bytes)
                    .verifying_key()
                    .to_bytes()
            }),
            verifier_public: super::audit_verify_key().map(|key| key.to_bytes()),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RotationState {
    Original,
    BarrierBeforeTruncate,
    EmptyAfterTruncate,
    PartialGenesis,
    PartialRestore,
    GenesisBeforeHead,
    Applied,
    AppliedWithAdditionalRecords,
    Restored,
}

/// Exact typed in-place write intent. The retained backend binds a local
/// ConfigWrite permit to this closed intent and the immutable plan hashes.
#[derive(Clone, Copy, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum LogMutation {
    Truncate,
    WriteGenesis,
    RestoreArchive,
}

/// Implementations derive fixed archive paths from the operation UUID, retain
/// native parent capabilities, require private files, and validate publication
/// generations. No method accepts a browser-supplied path or arbitrary command.
#[doc(hidden)]
pub trait RotationStore {
    fn validate_bindings(&mut self, log_identity: (u64, u64)) -> Result<(), String>;
    fn read_head(&mut self) -> Result<Option<Vec<u8>>, String>;
    fn before_mutation(&mut self) -> Result<(), String>;
    fn authorize_log_mutation(
        &mut self,
        plan: &RotationPlan,
        mutation: LogMutation,
    ) -> Result<(), String>;
    fn publish_head(&mut self, bytes: &[u8]) -> Result<(), String>;
    /// Stream exact log bytes plus original head and checkpoint to immutable
    /// private files; sync all files and directory entries before returning.
    fn ensure_archive(&mut self, source: &mut File, plan: &RotationPlan) -> Result<(), String>;
    fn verify_archive(&mut self, plan: &RotationPlan) -> Result<(), String>;
    /// Compare every existing byte with the corresponding immutable archive
    /// prefix. Called only behind this operation's invalid-head barrier.
    fn matches_archive_prefix(
        &mut self,
        source: &mut File,
        plan: &RotationPlan,
    ) -> Result<bool, String>;
    /// Copy only the verified archived log into the already-truncated handle.
    fn restore_archive(
        &mut self,
        destination: &mut File,
        plan: &RotationPlan,
    ) -> Result<(), String>;
}

impl RotationPlan {
    /// Capture under the same lock used by old and new audit writers. Whole-log
    /// verification is reused from audit.rs, without opening a second Windows
    /// handle or recursively taking a file lock.
    pub fn capture(
        operation_id: &str,
        log: &mut LockedAuditLog,
        store: &mut impl RotationStore,
    ) -> Result<Self, String> {
        uuid::Uuid::parse_str(operation_id).map_err(|_| "rotation ID must be a UUID")?;
        store.validate_bindings(log.identity)?;
        let signing_inputs = SigningInputs::capture();
        let head = store.read_head()?;
        if head.as_ref().is_some_and(|bytes| bytes.len() > MAX_HEAD) {
            return Err("audit head exceeds rotation limit".into());
        }
        let parsed_head = parse_head(head.as_deref())?;
        log.file.seek(SeekFrom::Start(0)).map_err(err)?;
        let report = super::verify_open_audit_log(&log.file, parsed_head.clone(), None);
        if !report.ok {
            return Err(
                "audit integrity must verify before retention; inspect audit verify".into(),
            );
        }
        let (bytes, sha256) = hash_log(&mut log.file)?;
        if bytes == 0 || report.total_lines == 0 {
            return Err("empty audit history does not require rotation".into());
        }
        let tail = super::read_last_line_from(&mut log.file)?
            .as_deref()
            .and_then(super::line_hash)
            .ok_or("audit tail cannot be bound to a rotation checkpoint")?;
        let original_signed = report.signing_expected;
        let restore_head = match &head {
            Some(bytes) => bytes.clone(),
            None => head_bytes(&tail, report.total_lines as u64, original_signed)?,
        };
        let checkpoint = signed_json(
            serde_json::json!({
                "schema_version":1,"kind":"audit-segment-checkpoint","operation_id":operation_id,
                "log_sha256":sha256,"log_bytes":bytes,"head_sha256":head.as_ref().map(|value| hex(value)),
                "tail_hash":tail,"lines":report.total_lines,"signing_expected":original_signed,
                "verification":"verified-before-rotation","created_at":chrono::Utc::now().to_rfc3339()
            }),
            original_signed || super::audit_signing_configured(),
        )?;
        let mut genesis = signed_json(
            serde_json::json!({
                "schema_version":1,"entry_type":"audit_rotation","event":"segment_rotated",
                "timestamp":chrono::Utc::now().to_rfc3339(),"session_id":"retention",
                "action":"recorded","command_redacted":"","rule_ids":[],
                "prev_hash":null,"checkpoint_id":operation_id,"checkpoint_sha256":hex(&checkpoint),
                "archived_log_sha256":sha256,"archived_lines":report.total_lines
            }),
            original_signed || super::audit_signing_configured(),
        )?;
        let genesis_hash = super::line_hash(std::str::from_utf8(&genesis).map_err(err)?)
            .ok_or("cannot hash rotation genesis")?;
        genesis.push(b'\n');
        let genesis_head = head_bytes(
            &genesis_hash,
            1,
            original_signed || super::audit_signing_configured(),
        )?;
        // This is intentionally not a HeadReceipt. Every compatible old writer
        // rejects it instead of appending during a crash-recovery window.
        let barrier = serde_json::to_vec(&serde_json::json!({
            "schema_version":1,"rotation_in_progress":operation_id,"checkpoint_sha256":hex(&checkpoint)
        })).map_err(err)?;
        if SigningInputs::capture() != signing_inputs {
            return Err("audit signing inputs changed while planning".into());
        }
        Ok(Self {
            schema_version: 1,
            operation_id: operation_id.into(),
            log_identity: log.identity,
            original_bytes: bytes,
            original_sha256: sha256,
            original_head: head,
            original_lines: report.total_lines,
            original_signed,
            original_restore_head: restore_head,
            checkpoint,
            genesis,
            genesis_head,
            barrier,
            signing_inputs: Some(signing_inputs),
        })
    }

    pub fn mutation_binding(&self, mutation: LogMutation) -> Result<Vec<u8>, String> {
        serde_json::to_vec(&serde_json::json!({"kind":"retained-audit-write-v1",
            "operation_id":self.operation_id,"mutation":mutation,
            "original_sha256":self.original_sha256,"original_bytes":self.original_bytes,
            "genesis_sha256":hex(&self.genesis),"genesis_bytes":self.genesis.len(),
            "checkpoint_sha256":hex(&self.checkpoint)}))
        .map_err(err)
    }

    pub fn projection(&self) -> serde_json::Value {
        serde_json::json!({"schema_version":1,"kind":"audit_rotation_preview",
            "operation_id":self.operation_id,"retained_records":self.original_lines,
            "retained_bytes":self.original_bytes,"signed_segment":self.original_signed,
            "active_log":"new-checkpointed-segment","archive":"private-exact-bytes",
            "undo":"available-only-before-additional-active-records","executed":false})
    }

    pub fn archive_bytes(&self) -> u64 {
        self.original_bytes
    }
    pub fn archive_sha256(&self) -> &str {
        &self.original_sha256
    }
    pub fn original_head(&self) -> Option<&[u8]> {
        self.original_head.as_deref()
    }
    pub fn checkpoint(&self) -> &[u8] {
        &self.checkpoint
    }
    pub fn operation_id(&self) -> &str {
        &self.operation_id
    }

    pub fn observe(
        &self,
        log: &mut LockedAuditLog,
        store: &mut impl RotationStore,
    ) -> Result<RotationState, String> {
        self.validate(log, store)?;
        let head = store.read_head()?;
        let (length, hash) = hash_log(&mut log.file)?;
        if length == self.original_bytes && hash == self.original_sha256 {
            return if head == self.original_head {
                Ok(RotationState::Original)
            } else if head.as_deref() == Some(self.original_restore_head.as_slice()) {
                Ok(RotationState::Restored)
            } else if head.as_deref() == Some(self.barrier.as_slice()) {
                Ok(RotationState::BarrierBeforeTruncate)
            } else {
                Err("audit head changed since retention planning".into())
            };
        }
        if length == 0 && head.as_deref() == Some(self.barrier.as_slice()) {
            return Ok(RotationState::EmptyAfterTruncate);
        }
        if head.as_deref() == Some(self.barrier.as_slice()) && length < self.genesis.len() as u64 {
            log.file.seek(SeekFrom::Start(0)).map_err(err)?;
            let mut prefix = vec![0; length as usize];
            log.file.read_exact(&mut prefix).map_err(err)?;
            if self.genesis.starts_with(&prefix) {
                return Ok(RotationState::PartialGenesis);
            }
        }
        if length >= self.genesis.len() as u64 {
            log.file.seek(SeekFrom::Start(0)).map_err(err)?;
            let mut prefix = vec![0; self.genesis.len()];
            log.file.read_exact(&mut prefix).map_err(err)?;
            if prefix == self.genesis {
                if length == self.genesis.len() as u64 {
                    if head.as_deref() == Some(self.barrier.as_slice()) {
                        return Ok(RotationState::GenesisBeforeHead);
                    }
                    if head.as_deref() == Some(self.genesis_head.as_slice()) {
                        store.verify_archive(self)?;
                        return Ok(RotationState::Applied);
                    }
                } else {
                    log.file.seek(SeekFrom::Start(0)).map_err(err)?;
                    if super::verify_open_audit_log(&log.file, parse_head(head.as_deref())?, None)
                        .ok
                    {
                        store.verify_archive(self)?;
                        return Ok(RotationState::AppliedWithAdditionalRecords);
                    }
                }
            }
        }
        if head.as_deref() == Some(self.barrier.as_slice()) && length < self.original_bytes {
            log.file.seek(SeekFrom::Start(0)).map_err(err)?;
            if store.matches_archive_prefix(&mut log.file, self)? {
                return Ok(RotationState::PartialRestore);
            }
        }
        Err("audit bytes changed outside the retained operation; recovery must preserve current records".into())
    }

    pub fn apply(
        &self,
        log: &mut LockedAuditLog,
        store: &mut impl RotationStore,
    ) -> Result<RotationState, String> {
        let mut state = self.observe(log, store)?;
        if matches!(
            state,
            RotationState::Applied | RotationState::AppliedWithAdditionalRecords
        ) {
            store.verify_archive(self)?;
            return Ok(state);
        }
        if matches!(
            state,
            RotationState::Restored | RotationState::PartialRestore
        ) {
            return Err("rotation was undone; create a new operation".into());
        }
        if state == RotationState::Original {
            self.before_mutation(log, store)?;
            log.file.seek(SeekFrom::Start(0)).map_err(err)?;
            store.ensure_archive(&mut log.file, self)?;
            store.verify_archive(self)?;
            self.before_mutation(log, store)?;
            self.require_state(log, store, RotationState::Original)?;
            store.publish_head(&self.barrier)?;
            state = RotationState::BarrierBeforeTruncate;
        } else {
            store.verify_archive(self)?;
        }
        if state == RotationState::BarrierBeforeTruncate {
            self.before_mutation(log, store)?;
            self.require_state(log, store, RotationState::BarrierBeforeTruncate)?;
            store.authorize_log_mutation(self, LogMutation::Truncate)?;
            log.file.set_len(0).map_err(err)?;
            log.file.sync_all().map_err(err)?;
            state = RotationState::EmptyAfterTruncate;
        }
        if state == RotationState::PartialGenesis {
            self.before_mutation(log, store)?;
            self.require_state(log, store, RotationState::PartialGenesis)?;
            store.authorize_log_mutation(self, LogMutation::Truncate)?;
            log.file.set_len(0).map_err(err)?;
            log.file.sync_all().map_err(err)?;
            state = RotationState::EmptyAfterTruncate;
        }
        if state == RotationState::EmptyAfterTruncate {
            self.before_mutation(log, store)?;
            self.require_state(log, store, RotationState::EmptyAfterTruncate)?;
            log.file.seek(SeekFrom::Start(0)).map_err(err)?;
            store.authorize_log_mutation(self, LogMutation::WriteGenesis)?;
            log.file.write_all(&self.genesis).map_err(err)?;
            log.file.sync_all().map_err(err)?;
            state = RotationState::GenesisBeforeHead;
        }
        if state == RotationState::GenesisBeforeHead {
            self.before_mutation(log, store)?;
            self.require_state(log, store, RotationState::GenesisBeforeHead)?;
            store.publish_head(&self.genesis_head)?;
        }
        self.observe(log, store)
    }

    /// Compensation refuses even one later append. Archives remain retained;
    /// undo is restoration of active bytes, never deletion of recovery evidence.
    pub fn undo(
        &self,
        log: &mut LockedAuditLog,
        store: &mut impl RotationStore,
    ) -> Result<RotationState, String> {
        let state = self.observe(log, store)?;
        if matches!(state, RotationState::Original | RotationState::Restored) {
            return Ok(state);
        }
        if state == RotationState::AppliedWithAdditionalRecords {
            return Err("new audit records exist; undo would overwrite them".into());
        }
        store.verify_archive(self)?;
        self.before_mutation(log, store)?;
        self.require_state(log, store, state)?;
        store.publish_head(&self.barrier)?;
        self.before_mutation(log, store)?;
        let barrier_state = if state == RotationState::Applied {
            RotationState::GenesisBeforeHead
        } else {
            state
        };
        self.require_state(log, store, barrier_state)?;
        store.authorize_log_mutation(self, LogMutation::Truncate)?;
        log.file.set_len(0).map_err(err)?;
        log.file.seek(SeekFrom::Start(0)).map_err(err)?;
        log.file.sync_all().map_err(err)?;
        store.authorize_log_mutation(self, LogMutation::RestoreArchive)?;
        store.restore_archive(&mut log.file, self)?;
        log.file.sync_all().map_err(err)?;
        let (length, hash) = hash_log(&mut log.file)?;
        if length != self.original_bytes || hash != self.original_sha256 {
            return Err(
                "restored archive bytes differ; audit remains behind recovery barrier".into(),
            );
        }
        self.before_mutation(log, store)?;
        store.publish_head(&self.original_restore_head)?;
        self.observe(log, store)
    }

    fn require_state(
        &self,
        log: &mut LockedAuditLog,
        store: &mut impl RotationStore,
        expected: RotationState,
    ) -> Result<(), String> {
        if self.observe(log, store)? != expected {
            return Err("audit generation changed immediately before retention publication".into());
        }
        Ok(())
    }

    fn validate(&self, log: &LockedAuditLog, store: &mut impl RotationStore) -> Result<(), String> {
        if self.schema_version != 1 || log.identity != self.log_identity {
            return Err("audit log identity changed since retention planning".into());
        }
        let expected = self.signing_inputs.as_ref().ok_or(
            "rotation predates signing-input binding; retain it for compatible-client recovery",
        )?;
        if &SigningInputs::capture() != expected {
            return Err("audit signing inputs changed since retention planning".into());
        }
        store.validate_bindings(log.identity)
    }

    fn before_mutation(
        &self,
        log: &LockedAuditLog,
        store: &mut impl RotationStore,
    ) -> Result<(), String> {
        self.validate(log, store)?;
        store.before_mutation()
    }
}

fn parse_head(bytes: Option<&[u8]>) -> Result<Option<super::HeadReceipt>, String> {
    bytes
        .map(|bytes| {
            if bytes.len() > MAX_HEAD {
                return Err("audit head exceeds rotation limit".into());
            }
            serde_json::from_slice(bytes)
                .map_err(|_| "audit head is malformed or rotation recovery is required".into())
        })
        .transpose()
}

fn head_bytes(hash: &str, count: u64, signed: bool) -> Result<Vec<u8>, String> {
    signed_json(
        serde_json::json!({"head_hash":hash,"count":count,"signing_enabled":signed}),
        signed,
    )
}

fn signed_json(mut value: serde_json::Value, signed: bool) -> Result<Vec<u8>, String> {
    if signed {
        let canonical = super::canonical_json_string(&value);
        let signature = super::sign_canonical(canonical.as_bytes())
            .ok_or("signing key unavailable; signed retention cannot proceed")?;
        use base64::Engine as _;
        use ed25519_dalek::Verifier as _;
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(&signature)
            .map_err(err)?;
        let parsed = ed25519_dalek::Signature::from_slice(&bytes).map_err(err)?;
        let verifier = super::audit_verify_key()
            .ok_or("audit verifying key unavailable for signed retention")?;
        verifier
            .verify(canonical.as_bytes(), &parsed)
            .map_err(|_| "audit signing and verification keys disagree")?;
        value
            .as_object_mut()
            .ok_or("retention record must be an object")?
            .insert("sig".into(), signature.into());
    }
    serde_json::to_vec(&value).map_err(err)
}

fn hash_log(file: &mut File) -> Result<(u64, String), String> {
    let before = crate::util::dirfd::file_generation(file).map_err(err)?;
    if before.links != 1 || before.size > MAX_BYTES {
        return Err("audit log is linked or exceeds retention byte limit".into());
    }
    file.seek(SeekFrom::Start(0)).map_err(err)?;
    let mut hash = Sha256::new();
    let mut total = 0u64;
    let mut buffer = [0u8; 64 * 1024];
    loop {
        let length = file.read(&mut buffer).map_err(err)?;
        if length == 0 {
            break;
        }
        total += length as u64;
        if total > MAX_BYTES {
            return Err("audit grew beyond retention byte limit".into());
        }
        hash.update(&buffer[..length]);
    }
    if crate::util::dirfd::file_generation(file).map_err(err)? != before || total != before.size {
        return Err("audit changed during the bounded snapshot".into());
    }
    Ok((total, format!("{:x}", hash.finalize())))
}

fn hex(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}
fn err(error: impl std::fmt::Display) -> String {
    error.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;
    use tirith_test_support::GlobalStateGuard;

    type ArchivedFixture = (Vec<u8>, Option<Vec<u8>>, Vec<u8>);
    struct TestStore {
        head: PathBuf,
        archive: Option<ArchivedFixture>,
        mutations: usize,
        refuse_at: Option<usize>,
    }

    impl RotationStore for TestStore {
        fn validate_bindings(&mut self, _: (u64, u64)) -> Result<(), String> {
            Ok(())
        }
        fn read_head(&mut self) -> Result<Option<Vec<u8>>, String> {
            match std::fs::read(&self.head) {
                Ok(bytes) => Ok(Some(bytes)),
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
                Err(error) => Err(err(error)),
            }
        }
        fn before_mutation(&mut self) -> Result<(), String> {
            self.mutations += 1;
            if self.refuse_at == Some(self.mutations) {
                return Err("injected publication refusal".into());
            }
            Ok(())
        }
        fn authorize_log_mutation(
            &mut self,
            _: &RotationPlan,
            _: LogMutation,
        ) -> Result<(), String> {
            Ok(())
        }
        fn publish_head(&mut self, bytes: &[u8]) -> Result<(), String> {
            std::fs::write(&self.head, bytes).map_err(err)
        }
        fn ensure_archive(&mut self, source: &mut File, plan: &RotationPlan) -> Result<(), String> {
            let mut bytes = Vec::new();
            source
                .take(plan.archive_bytes() + 1)
                .read_to_end(&mut bytes)
                .map_err(err)?;
            self.archive = Some((bytes, plan.original_head.clone(), plan.checkpoint.clone()));
            self.verify_archive(plan)
        }
        fn verify_archive(&mut self, plan: &RotationPlan) -> Result<(), String> {
            let (bytes, head, checkpoint) = self.archive.as_ref().ok_or("archive unavailable")?;
            if bytes.len() as u64 != plan.original_bytes
                || hex(bytes) != plan.original_sha256
                || head != &plan.original_head
                || checkpoint != &plan.checkpoint
            {
                return Err("archive changed".into());
            }
            Ok(())
        }
        fn matches_archive_prefix(
            &mut self,
            source: &mut File,
            plan: &RotationPlan,
        ) -> Result<bool, String> {
            self.verify_archive(plan)?;
            let mut bytes = Vec::new();
            source.read_to_end(&mut bytes).map_err(err)?;
            Ok(self.archive.as_ref().unwrap().0.starts_with(&bytes))
        }
        fn restore_archive(
            &mut self,
            destination: &mut File,
            plan: &RotationPlan,
        ) -> Result<(), String> {
            self.verify_archive(plan)?;
            destination
                .write_all(&self.archive.as_ref().unwrap().0)
                .map_err(err)
        }
    }

    fn entry() -> super::super::AuditEntry {
        super::super::AuditEntry {
            timestamp: "2026-09-12T00:00:00Z".into(),
            session_id: "retention-test".into(),
            action: "Allow".into(),
            rule_ids: Vec::new(),
            command_redacted: "inert marker".into(),
            bypass_requested: false,
            bypass_honored: false,
            interactive: false,
            policy_path: None,
            event_id: None,
            tier_reached: 1,
            entry_type: "verdict".into(),
            event: None,
            integration: None,
            hook_type: None,
            detail: None,
            elapsed_ms: None,
            raw_action: None,
            raw_rule_ids: None,
            trust_pattern: None,
            trust_rule_id: None,
            trust_action: None,
            trust_ttl_expires: None,
            trust_scope: None,
            agent_origin: None,
            manifest_allowed_match: None,
            prev_hash: None,
            sig: None,
        }
    }

    fn lock(path: &std::path::Path) -> LockedAuditLog {
        LockedAuditLog::acquire(
            std::fs::OpenOptions::new()
                .read(true)
                .write(true)
                .open(path)
                .unwrap(),
        )
        .unwrap()
    }

    fn read_locked(log: &mut LockedAuditLog) -> Vec<u8> {
        log.file.seek(SeekFrom::Start(0)).unwrap();
        let mut bytes = Vec::new();
        log.file.read_to_end(&mut bytes).unwrap();
        bytes
    }

    #[test]
    fn exact_partial_genesis_and_restore_resume_but_unknown_bytes_are_preserved() {
        let mut global = GlobalStateGuard::new().unwrap();
        let root = tempfile::tempdir().unwrap();
        global.set_env("XDG_CONFIG_HOME", root.path().join("config"));
        global.set_env("TIRITH_LOG", "1");
        let path = root.path().join("audit.jsonl");
        let _ = super::super::append_to_audit_log(&entry(), Some(path.clone()));
        let original = std::fs::read(&path).unwrap();
        let mut store = TestStore {
            head: super::super::head_path(&path),
            archive: None,
            mutations: 0,
            refuse_at: None,
        };
        let mut log = lock(&path);
        let plan =
            RotationPlan::capture(&uuid::Uuid::new_v4().to_string(), &mut log, &mut store).unwrap();
        log.file.seek(SeekFrom::Start(0)).unwrap();
        store.ensure_archive(&mut log.file, &plan).unwrap();
        store.publish_head(&plan.barrier).unwrap();
        log.file.set_len(0).unwrap();
        log.file.seek(SeekFrom::Start(0)).unwrap();
        log.file.write_all(&plan.genesis[..17]).unwrap();
        assert_eq!(
            plan.observe(&mut log, &mut store).unwrap(),
            RotationState::PartialGenesis
        );
        assert_eq!(
            plan.apply(&mut log, &mut store).unwrap(),
            RotationState::Applied
        );
        store.publish_head(&plan.barrier).unwrap();
        log.file.set_len(0).unwrap();
        log.file.seek(SeekFrom::Start(0)).unwrap();
        log.file.write_all(&original[..original.len() / 2]).unwrap();
        assert_eq!(
            plan.observe(&mut log, &mut store).unwrap(),
            RotationState::PartialRestore
        );
        assert!(plan.apply(&mut log, &mut store).is_err());
        assert!(matches!(
            plan.undo(&mut log, &mut store).unwrap(),
            RotationState::Original | RotationState::Restored
        ));
        assert_eq!(read_locked(&mut log), original);
        store.publish_head(&plan.barrier).unwrap();
        log.file.set_len(0).unwrap();
        log.file.seek(SeekFrom::Start(0)).unwrap();
        log.file.write_all(b"unknown concurrent bytes").unwrap();
        assert!(plan.undo(&mut log, &mut store).is_err());
        assert_eq!(read_locked(&mut log), b"unknown concurrent bytes");
    }

    #[test]
    fn signed_rotation_preserves_checkpoint_signatures_and_missing_key_refuses() {
        let mut global = GlobalStateGuard::new().unwrap();
        let root = tempfile::tempdir().unwrap();
        global.set_env("XDG_CONFIG_HOME", root.path().join("config"));
        global.set_env("TIRITH_LOG", "1");
        let config = crate::policy::config_dir().unwrap();
        std::fs::create_dir_all(&config).unwrap();
        let key = ed25519_dalek::SigningKey::from_bytes(&[29; 32]);
        let key_path = config.join("audit-signing.key");
        std::fs::write(&key_path, key.to_bytes()).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&key_path, std::fs::Permissions::from_mode(0o600)).unwrap();
        }
        std::fs::write(
            config.join("audit-signing.pub"),
            key.verifying_key().to_bytes(),
        )
        .unwrap();
        let path = root.path().join("audit.jsonl");
        assert!(matches!(
            super::super::append_to_audit_log(&entry(), Some(path.clone())),
            super::super::AuditWrite::Written(_)
        ));
        let mut store = TestStore {
            head: super::super::head_path(&path),
            archive: None,
            mutations: 0,
            refuse_at: None,
        };
        let mut log = lock(&path);
        let plan =
            RotationPlan::capture(&uuid::Uuid::new_v4().to_string(), &mut log, &mut store).unwrap();
        assert!(
            serde_json::from_slice::<serde_json::Value>(plan.checkpoint()).unwrap()["sig"]
                .is_string()
        );
        std::fs::write(&key_path, [31; 32]).unwrap();
        assert!(plan.apply(&mut log, &mut store).is_err());
        assert!(store.archive.is_none());
        assert!(
            RotationPlan::capture(&uuid::Uuid::new_v4().to_string(), &mut log, &mut store).is_err()
        );
        std::fs::write(&key_path, key.to_bytes()).unwrap();
        plan.apply(&mut log, &mut store).unwrap();
        plan.undo(&mut log, &mut store).unwrap();
        std::fs::remove_file(&key_path).unwrap();
        let original = read_locked(&mut log);
        assert!(
            RotationPlan::capture(&uuid::Uuid::new_v4().to_string(), &mut log, &mut store).is_err()
        );
        assert_eq!(read_locked(&mut log), original);
    }

    #[test]
    fn rotation_keeps_inode_and_exact_archive_and_undo_preserves_verification() {
        let mut global = GlobalStateGuard::new().unwrap();
        let root = tempfile::tempdir().unwrap();
        global.set_env("XDG_CONFIG_HOME", root.path().join("config"));
        global.set_env("TIRITH_LOG", "1");
        let path = root.path().join("audit.jsonl");
        assert!(matches!(
            super::super::append_to_audit_log(&entry(), Some(path.clone())),
            super::super::AuditWrite::Written(_)
        ));
        let original = std::fs::read(&path).unwrap();
        let mut store = TestStore {
            head: super::super::head_path(&path),
            archive: None,
            mutations: 0,
            refuse_at: None,
        };
        let mut locked = lock(&path);
        let identity = locked.identity();
        let plan =
            RotationPlan::capture(&uuid::Uuid::new_v4().to_string(), &mut locked, &mut store)
                .unwrap();
        assert_eq!(
            plan.apply(&mut locked, &mut store).unwrap(),
            RotationState::Applied
        );
        assert_eq!(locked.identity(), identity);
        assert_eq!(store.archive.as_ref().unwrap().0, original);
        assert_eq!(
            plan.apply(&mut locked, &mut store).unwrap(),
            RotationState::Applied
        );
        assert!(matches!(
            plan.undo(&mut locked, &mut store).unwrap(),
            RotationState::Original | RotationState::Restored
        ));
        drop(locked);
        assert_eq!(std::fs::read(&path).unwrap(), original);
        assert!(super::super::verify_audit_log(&path, None).ok);
    }

    #[test]
    fn barrier_blocks_existing_writer_after_interruption_and_resume_preserves_records() {
        let mut global = GlobalStateGuard::new().unwrap();
        let root = tempfile::tempdir().unwrap();
        global.set_env("XDG_CONFIG_HOME", root.path().join("config"));
        global.set_env("TIRITH_LOG", "1");
        let path = root.path().join("audit.jsonl");
        assert!(matches!(
            super::super::append_to_audit_log(&entry(), Some(path.clone())),
            super::super::AuditWrite::Written(_)
        ));
        let mut store = TestStore {
            head: super::super::head_path(&path),
            archive: None,
            mutations: 0,
            refuse_at: Some(4),
        };
        let mut locked = lock(&path);
        let plan =
            RotationPlan::capture(&uuid::Uuid::new_v4().to_string(), &mut locked, &mut store)
                .unwrap();
        assert!(plan.apply(&mut locked, &mut store).is_err());
        assert_eq!(
            plan.observe(&mut locked, &mut store).unwrap(),
            RotationState::EmptyAfterTruncate
        );
        drop(locked);
        assert!(matches!(
            super::super::append_to_audit_log(&entry(), Some(path.clone())),
            super::super::AuditWrite::Failed(_)
        ));
        assert_eq!(std::fs::metadata(&path).unwrap().len(), 0);
        store.refuse_at = None;
        let mut locked = lock(&path);
        assert_eq!(
            plan.apply(&mut locked, &mut store).unwrap(),
            RotationState::Applied
        );
        drop(locked);
        assert!(matches!(
            super::super::append_to_audit_log(&entry(), Some(path.clone())),
            super::super::AuditWrite::Written(_)
        ));
        let after_append = std::fs::read(&path).unwrap();
        let mut locked = lock(&path);
        assert_eq!(
            plan.apply(&mut locked, &mut store).unwrap(),
            RotationState::AppliedWithAdditionalRecords
        );
        assert!(plan.undo(&mut locked, &mut store).is_err());
        drop(locked);
        assert_eq!(std::fs::read(&path).unwrap(), after_append);
        assert!(super::super::verify_audit_log(&path, None).ok);
    }

    #[test]
    fn archive_corruption_cannot_authorize_truncation_or_restore() {
        let mut global = GlobalStateGuard::new().unwrap();
        let root = tempfile::tempdir().unwrap();
        global.set_env("XDG_CONFIG_HOME", root.path().join("config"));
        global.set_env("TIRITH_LOG", "1");
        let path = root.path().join("audit.jsonl");
        assert!(matches!(
            super::super::append_to_audit_log(&entry(), Some(path.clone())),
            super::super::AuditWrite::Written(_)
        ));
        let mut store = TestStore {
            head: super::super::head_path(&path),
            archive: None,
            mutations: 0,
            refuse_at: Some(3),
        };
        let mut locked = lock(&path);
        let plan =
            RotationPlan::capture(&uuid::Uuid::new_v4().to_string(), &mut locked, &mut store)
                .unwrap();
        assert!(plan.apply(&mut locked, &mut store).is_err());
        store.archive.as_mut().unwrap().0.push(b'x');
        store.refuse_at = None;
        let before = hash_log(&mut locked.file).unwrap();
        assert!(plan.apply(&mut locked, &mut store).is_err());
        assert!(plan.undo(&mut locked, &mut store).is_err());
        assert_eq!(hash_log(&mut locked.file).unwrap(), before);
    }
}
