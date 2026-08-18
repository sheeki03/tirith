//! Signed, content-addressed receipt for one contained preset run (C14).
//!
//! `tirith capsule run --preset untrusted-project` promises containment. A
//! promise with no record is not a control, so every invocation of that command
//! produces exactly one receipt: on a successful contained run, on a
//! parent-terminated run, and on a pre-launch refusal.
//!
//! # Why this type lives in `tirith-core`
//!
//! The audit hash chain is the tamper-evidence anchor, and its receipt-anchor
//! entry point ([`crate::audit::log_capsule_run_receipt`]) is `pub(crate)`. A
//! receipt defined in the CLI crate could therefore not anchor itself and would
//! be an unchained file with no tamper evidence at all. The CLI is a thin
//! renderer over this type.
//!
//! # Relationship to the other receipts
//!
//! [`crate::receipt::ArtifactScanReceipt`] is install-shaped: it mandates a
//! resolver command, a threat-DB sequence, a post-install RECORD summary, and
//! artifact hashes, none of which a contained project run has. It is deliberately
//! NOT generalized in place. What IS shared is the discipline: canonical JSON
//! through [`crate::audit::canonical_json_for_hash`], a content-addressed id
//! computed with the id field blanked, an atomic `0600` save, and an audit-chain
//! anchor. The field names here (`schema`, `receipt_type`, `receipt_id`,
//! `created_at`, `tirith_version`, `engine_build_sha`, `policy_projection_hash`,
//! `status`, `subject`, `evidence`, `coverage`, `signature`) follow the shared
//! envelope shape so a later unified receipt type can absorb this one
//! mechanically.
//!
//! # Honesty rules this type enforces
//!
//! - [`CapsuleRunStatus::Contained`] may be recorded ONLY when the backend
//!   delivered every requested control, the parent proved cleanup, and the
//!   output inventory was complete. [`CapsuleRunReceipt::validate`] rejects a
//!   receipt that claims otherwise, so a false contained result cannot be saved,
//!   signed, or anchored.
//! - The child's exit status and Tirith's own decision are separate fields. A
//!   child that exited 0 inside a run Tirith terminated is not a clean run, and
//!   a child that exited 1 inside a fully contained run is not a Tirith refusal.
//! - The argv is recorded as a DIGEST. Arguments routinely carry secrets, and a
//!   receipt is a durable artifact.
//!
//! # What `policy_projection_hash` does and does not bind
//!
//! [`crate::policy::Policy::security_projection`] omits `web3_guard` and
//! `task_gate` entirely, so the projection hash does NOT bind the task-gate
//! ceiling that tightened this run. Rather than silently under-binding (or
//! re-freezing the frozen legacy projection contract for an unrelated slice),
//! the receipt records [`crate::task_boundary::ceiling_binding`] separately in
//! `task_gate_binding`. Both are needed to reproduce the effective ceiling.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::capsule::{CapsuleCoverage, ResourceLimits};
use crate::capsule_project::ProjectDiff;

/// Schema version of [`CapsuleRunReceipt`]. Bumped when a field is added or its
/// meaning changes.
pub const CAPSULE_RUN_RECEIPT_SCHEMA: u32 = 1;

/// Stable discriminator so a reader can tell this envelope from any other
/// receipt sharing the same directory or chain.
pub const CAPSULE_RUN_RECEIPT_TYPE: &str = "capsule_run";

/// Maximum bytes of a saved capsule receipt that will be re-read for chain
/// anchoring. A receipt is a small bounded record.
pub const MAX_CAPSULE_RECEIPT_BYTES: usize = 512 * 1024;

/// What the preset actually achieved.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CapsuleRunStatus {
    /// The backend delivered every requested control, the target ran to its own
    /// exit, cleanup was confirmed, and the output inventory was complete.
    Contained,
    /// The target ran contained but something about the record is incomplete:
    /// the parent terminated it, cleanup was not confirmed, or an inventory hit
    /// a cap. Never a claim of a clean contained run.
    Partial,
    /// The target never ran: the host could not deliver a required control, or
    /// the input was refused. This says nothing about whether an ephemeral copy
    /// of the project was made first; some refusals happen only once the copy
    /// exists, and [`CapsuleRunEvidence::project_copy_materialized`] is the field
    /// that records which kind this was.
    Refused,
}

impl CapsuleRunStatus {
    /// Stable wire token, matching the serde spelling.
    pub fn token(self) -> &'static str {
        match self {
            Self::Contained => "contained",
            Self::Partial => "partial",
            Self::Refused => "refused",
        }
    }
}

/// Tirith's own decision about the run, kept separate from the child's exit
/// status so neither can be read as the other.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CapsuleRunDecision {
    /// Tirith let the target run and it reached its own exit status.
    TargetCompleted,
    /// Tirith's parent supervisor terminated the target after it started.
    TerminatedByTirith,
    /// Tirith refused before any target code ran.
    RefusedBeforeLaunch,
}

impl CapsuleRunDecision {
    /// Stable wire token, matching the serde spelling.
    pub fn token(self) -> &'static str {
        match self {
            Self::TargetCompleted => "target_completed",
            Self::TerminatedByTirith => "terminated_by_tirith",
            Self::RefusedBeforeLaunch => "refused_before_launch",
        }
    }
}

/// A tree digest as recorded in the receipt. `complete` false means the digest
/// covers less than the whole tree.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CapsuleTreeDigest {
    pub digest: String,
    pub file_count: usize,
    pub total_bytes: u64,
    pub complete: bool,
}

/// The requested-versus-achieved coverage ledger, plus which dimensions the
/// PARENT owns rather than the OS backend.
///
/// No OS backend enforces `max_output_bytes` or `wall_clock_seconds`; the parent
/// supervisor does. Recording them as backend-enforced would over-claim exactly
/// what [`CapsuleCoverage`]'s honesty contract exists to prevent, so they are
/// listed here by name.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CapsuleRunCoverage {
    pub requested: CapsuleCoverage,
    pub achieved: CapsuleCoverage,
    pub parent_enforced_dimensions: Vec<String>,
}

/// Everything about the target that is safe to record durably.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CapsuleRunSubject {
    /// The preset name (`untrusted-project`).
    pub preset: String,
    /// Digest of the EXACT argv. The argument strings themselves are never
    /// recorded.
    pub argv_digest: String,
    /// Number of argv elements, so a digest can be reproduced deliberately.
    pub argv_len: usize,
    /// Digest of the held project copy as it was handed to the child.
    pub project_input: Option<CapsuleTreeDigest>,
    /// Digest of the held project copy after the child exited.
    pub project_output: Option<CapsuleTreeDigest>,
}

/// Everything about the run itself.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CapsuleRunEvidence {
    /// The capsule backend identifier, or `"none"` for a refusal that never
    /// selected one.
    pub backend_id: String,
    /// `<os>/<arch>`, so a refusal receipt states which host produced it.
    pub platform: String,
    /// The effective resource ceilings the run requested.
    pub limits: ResourceLimits,
    /// The child's own exit code, when a child ran.
    pub child_exit_code: Option<i32>,
    /// Tirith's decision, always present and never conflated with the above.
    pub decision: CapsuleRunDecision,
    /// The typed parent termination reason, when the parent terminated it.
    pub termination_kind: Option<String>,
    /// Bounded, secret-free parent text describing the refusal or termination.
    /// Absolute host paths are replaced by [`CapsuleRunReceipt::new`]; see
    /// [`redact_host_paths`].
    pub reason: Option<String>,
    /// Whether an ephemeral copy of the project was created on the operator's
    /// disk during this run. A refusal that happened after the copy existed is
    /// not the same event as one that happened before it, and only this field
    /// tells them apart.
    pub project_copy_materialized: bool,
    /// Whether every ephemeral artifact this run created was PROVEN gone: the
    /// held project copy, the contained process tree, and the launcher's
    /// temporary HOME. Each of the three is observed; none is assumed.
    pub cleanup_confirmed: bool,
    /// Bounded difference between the input and output inventories.
    pub diff: ProjectDiff,
}

/// One contained preset run, content-addressed and optionally ed25519-signed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CapsuleRunReceipt {
    pub schema: u32,
    pub receipt_type: String,
    /// Content-addressed id: sha256 over the canonical JSON with `receipt_id`
    /// and `signature` blanked.
    pub receipt_id: String,
    pub created_at: String,
    pub tirith_version: String,
    pub engine_build_sha: String,
    /// [`crate::policy::Policy::security_projection_hash`]. See the module note
    /// on what it does not bind.
    pub policy_projection_hash: String,
    /// [`crate::task_boundary::ceiling_binding`] for the decision that tightened
    /// this run, which the security projection does not cover.
    pub task_gate_binding: String,
    pub status: CapsuleRunStatus,
    pub subject: CapsuleRunSubject,
    pub evidence: CapsuleRunEvidence,
    pub coverage: CapsuleRunCoverage,
    /// Base64 ed25519 signature over the canonical JSON with `signature`
    /// blanked, produced by the SAME key and routine as the audit chain
    /// ([`crate::audit::sign_canonical_bytes`]). `None` when no signing key is
    /// configured; the receipt is then hash-chained only.
    pub signature: Option<String>,
}

/// Why a receipt could not be assembled, validated, saved, or anchored.
#[derive(Debug)]
pub enum CapsuleReceiptError {
    /// The receipt is not internally consistent. Raised before any write.
    Invalid(String),
    /// Writing the receipt file failed.
    Io(std::io::Error),
}

impl std::fmt::Display for CapsuleReceiptError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Invalid(reason) => write!(f, "refusing an invalid capsule receipt: {reason}"),
            Self::Io(error) => write!(f, "capsule receipt I/O failed: {error}"),
        }
    }
}

impl std::error::Error for CapsuleReceiptError {}

/// The saved and anchored outcome of [`CapsuleRunReceipt::record`].
#[derive(Debug, Clone)]
pub struct RecordedCapsuleReceipt {
    /// The content-addressed copy under `data_dir()/capsule-receipts/`, when a
    /// data directory exists.
    pub store_path: Option<PathBuf>,
    /// The operator-requested `--receipt <path>` copy, when one was requested.
    pub requested_path: Option<PathBuf>,
    /// Whether the receipt carries an ed25519 signature.
    pub signed: bool,
    /// Whether the content hash was anchored in the audit chain.
    pub anchored: bool,
    /// Present when the receipt was saved but could not be anchored. Never
    /// silently dropped: an unanchored receipt is not tamper-evident.
    pub anchor_warning: Option<String>,
}

/// A receipt destination bound to its retained parent before the project scan.
/// If it is inside the source tree, [`Self::project_exclusion`] names exactly
/// that one relative file so the receipt cannot become part of its own subject.
pub struct PreparedCapsuleReceipt {
    requested: Option<PreparedRequestedReceipt>,
}

struct PreparedRequestedReceipt {
    path: PathBuf,
    reported_path: PathBuf,
    destination: crate::util::ContainedAtomicFile,
    project_exclusion: Option<PathBuf>,
}

impl PreparedCapsuleReceipt {
    /// Retain the requested destination parent, creating missing parents
    /// capability-relatively, before any tree bytes are scanned.
    pub fn prepare(
        requested_path: Option<&Path>,
        project_root: Option<&Path>,
    ) -> Result<Self, CapsuleReceiptError> {
        let requested = requested_path
            .map(|path| {
                let reported_path = path.to_path_buf();
                let path = crate::capsule_project::trusted_platform_root_alias(
                    &absolute_path(path).map_err(CapsuleReceiptError::Io)?,
                );
                let project_root = project_root
                    .map(absolute_path)
                    .transpose()
                    .map_err(CapsuleReceiptError::Io)?
                    .map(|root| crate::capsule_project::trusted_platform_root_alias(&root));
                let anchor = project_root
                    .as_ref()
                    .filter(|root| path.strip_prefix(root).is_ok())
                    .cloned()
                    .or_else(|| filesystem_anchor(&path))
                    .ok_or_else(|| {
                        CapsuleReceiptError::Io(std::io::Error::new(
                            std::io::ErrorKind::InvalidInput,
                            "receipt path has no filesystem root",
                        ))
                    })?;
                let destination = crate::util::ContainedAtomicFile::prepare(&anchor, &path, true)
                    .map_err(CapsuleReceiptError::Io)?;
                match destination.read_capped(0) {
                    Ok(_) | Err(crate::util::OpenRegularError::TooLarge) => {}
                    Err(crate::util::OpenRegularError::NotFound) => {}
                    Err(crate::util::OpenRegularError::NotRegularFile) => {
                        return Err(CapsuleReceiptError::Io(std::io::Error::new(
                            std::io::ErrorKind::InvalidInput,
                            "receipt destination exists but is not a regular file",
                        )))
                    }
                    Err(crate::util::OpenRegularError::Io(error)) => {
                        return Err(CapsuleReceiptError::Io(error))
                    }
                }
                let project_exclusion = project_root
                    .as_deref()
                    .and_then(|root| path.strip_prefix(root).ok())
                    .filter(|relative| {
                        !relative.as_os_str().is_empty()
                            && relative.components().all(|component| {
                                matches!(component, std::path::Component::Normal(_))
                            })
                    })
                    .map(Path::to_path_buf);
                Ok(PreparedRequestedReceipt {
                    path,
                    reported_path,
                    destination,
                    project_exclusion,
                })
            })
            .transpose()?;
        Ok(Self { requested })
    }

    /// The one project-relative file omitted from the capsule copy.
    pub fn project_exclusion(&self) -> Option<&Path> {
        self.requested
            .as_ref()
            .and_then(|requested| requested.project_exclusion.as_deref())
    }
}

fn absolute_path(path: &Path) -> std::io::Result<PathBuf> {
    if path.is_absolute() {
        Ok(path.to_path_buf())
    } else {
        Ok(std::env::current_dir()?.join(path))
    }
}

fn filesystem_anchor(path: &Path) -> Option<PathBuf> {
    let mut anchor = PathBuf::new();
    for component in path.components() {
        match component {
            std::path::Component::Prefix(prefix) => anchor.push(prefix.as_os_str()),
            std::path::Component::RootDir => {
                anchor.push(component.as_os_str());
                return Some(anchor);
            }
            _ => return None,
        }
    }
    None
}

/// Everything the constructor needs. Grouped so the assembly site reads as one
/// record rather than a fourteen-argument call.
#[derive(Debug, Clone)]
pub struct CapsuleRunFacts {
    pub status: CapsuleRunStatus,
    pub policy_projection_hash: String,
    pub task_gate_binding: String,
    pub subject: CapsuleRunSubject,
    pub evidence: CapsuleRunEvidence,
    pub coverage: CapsuleRunCoverage,
}

impl CapsuleRunReceipt {
    /// Assemble, stamp the content address, and sign when a key is available.
    ///
    /// Signing uses the audit chain's own key and routine, so there is exactly
    /// one signing key path in the product and a receipt cannot be signed by a
    /// key the chain does not use.
    pub fn new(facts: CapsuleRunFacts) -> Self {
        let mut facts = facts;
        // Applied here rather than at the assembly site so no future caller can
        // route a filesystem-policy error into a durable, shareable artifact
        // with the operator's home layout still in it.
        facts.evidence.reason = facts
            .evidence
            .reason
            .as_deref()
            .map(redact_host_paths)
            .filter(|reason| !reason.is_empty());
        let mut receipt = CapsuleRunReceipt {
            schema: CAPSULE_RUN_RECEIPT_SCHEMA,
            receipt_type: CAPSULE_RUN_RECEIPT_TYPE.to_string(),
            receipt_id: String::new(),
            created_at: chrono::Utc::now().to_rfc3339(),
            tirith_version: env!("CARGO_PKG_VERSION").to_string(),
            engine_build_sha: crate::receipt::engine_build_sha().to_string(),
            policy_projection_hash: facts.policy_projection_hash,
            task_gate_binding: facts.task_gate_binding,
            status: facts.status,
            subject: facts.subject,
            evidence: facts.evidence,
            coverage: facts.coverage,
            signature: None,
        };
        receipt.receipt_id = receipt.compute_content_hash();
        receipt.signature =
            crate::audit::sign_canonical_bytes(receipt.signing_payload().as_bytes());
        receipt
    }

    /// The canonical JSON signed by [`Self::signature`]: the whole receipt with
    /// the signature field blanked and the content id PRESENT, so the signature
    /// binds the content address rather than floating free of it.
    pub fn signing_payload(&self) -> String {
        self.canonical_json(false)
    }

    /// The lowercase-hex sha256 of the canonical JSON with `receipt_id` and
    /// `signature` blanked, through the same canonicalizer the audit chain uses.
    pub fn compute_content_hash(&self) -> String {
        crate::command_card::sha256_hex(self.canonical_json(true).as_bytes())
    }

    fn canonical_json(&self, blank_receipt_id: bool) -> String {
        let serialized = serde_json::to_value(self);
        debug_assert!(
            serialized.is_ok(),
            "capsule receipt failed to serialize; a field is not serializable"
        );
        let mut value = serialized.unwrap_or(serde_json::Value::Null);
        if let Some(object) = value.as_object_mut() {
            if blank_receipt_id {
                object.insert(
                    "receipt_id".to_string(),
                    serde_json::Value::String(String::new()),
                );
            }
            object.insert("signature".to_string(), serde_json::Value::Null);
        }
        crate::audit::canonical_json_for_hash(&value)
    }

    /// Whether the stored id still matches a recomputation over the content.
    pub fn content_hash_matches(&self) -> bool {
        self.receipt_id == self.compute_content_hash()
    }

    /// Verify the detached signature against an ed25519 public key. Returns
    /// `false` for an absent, malformed, or non-verifying signature, so a caller
    /// cannot read "unsigned" as "verified".
    pub fn signature_verifies(&self, public_key: &[u8; 32]) -> bool {
        use ed25519_dalek::Verifier as _;

        let Some(encoded) = self.signature.as_deref() else {
            return false;
        };
        use base64::Engine as _;
        let Ok(bytes) = base64::engine::general_purpose::STANDARD.decode(encoded) else {
            return false;
        };
        let Ok(signature) = ed25519_dalek::Signature::from_slice(&bytes) else {
            return false;
        };
        let Ok(key) = ed25519_dalek::VerifyingKey::from_bytes(public_key) else {
            return false;
        };
        key.verify(self.signing_payload().as_bytes(), &signature)
            .is_ok()
    }

    /// Every honesty invariant, checked before the receipt can reach the
    /// filesystem or the signed audit chain.
    ///
    /// The load-bearing rule is the [`CapsuleRunStatus::Contained`] gate: a
    /// receipt may only claim a contained run when the backend delivered the
    /// requested coverage, Tirith did not terminate the target, cleanup was
    /// confirmed, and both tree inventories were complete. Anything less must be
    /// `Partial` or `Refused`.
    pub fn validate(&self) -> Result<(), CapsuleReceiptError> {
        if self.schema != CAPSULE_RUN_RECEIPT_SCHEMA {
            return Err(CapsuleReceiptError::Invalid(format!(
                "unsupported capsule receipt schema {}",
                self.schema
            )));
        }
        if self.receipt_type != CAPSULE_RUN_RECEIPT_TYPE {
            return Err(CapsuleReceiptError::Invalid(
                "receipt_type is not a capsule run".to_string(),
            ));
        }
        if !self.content_hash_matches() {
            return Err(CapsuleReceiptError::Invalid(
                "receipt_id does not match the canonical receipt content".to_string(),
            ));
        }
        match self.status {
            CapsuleRunStatus::Refused => {
                if self.evidence.decision != CapsuleRunDecision::RefusedBeforeLaunch {
                    return Err(CapsuleReceiptError::Invalid(
                        "a refused receipt must record a pre-launch refusal decision".to_string(),
                    ));
                }
                if self.evidence.child_exit_code.is_some() {
                    return Err(CapsuleReceiptError::Invalid(
                        "a refused receipt cannot carry a child exit status".to_string(),
                    ));
                }
                if self.evidence.reason.is_none() {
                    return Err(CapsuleReceiptError::Invalid(
                        "a refused receipt must name the control that could not be achieved"
                            .to_string(),
                    ));
                }
                // A refusal that left an untrusted repository on the operator's
                // disk is not a clean refusal, so it may not be recorded as one.
                if self.evidence.project_copy_materialized && !self.evidence.cleanup_confirmed {
                    return Err(CapsuleReceiptError::Invalid(
                        "a refused receipt that copied the project must record confirmed cleanup"
                            .to_string(),
                    ));
                }
            }
            CapsuleRunStatus::Contained => {
                if self
                    .coverage
                    .achieved
                    .is_degraded_against(&self.coverage.requested)
                {
                    return Err(CapsuleReceiptError::Invalid(
                        "a contained receipt cannot record achieved coverage below what it requested"
                            .to_string(),
                    ));
                }
                if !self.coverage.achieved.egress_claim_is_coherent() {
                    return Err(CapsuleReceiptError::Invalid(
                        "a contained receipt cannot claim domain egress without raw-socket denial"
                            .to_string(),
                    ));
                }
                if self.evidence.decision != CapsuleRunDecision::TargetCompleted {
                    return Err(CapsuleReceiptError::Invalid(
                        "a contained receipt requires the target to have reached its own exit"
                            .to_string(),
                    ));
                }
                if !self.evidence.cleanup_confirmed {
                    return Err(CapsuleReceiptError::Invalid(
                        "a contained receipt requires confirmed cleanup".to_string(),
                    ));
                }
                if self.evidence.child_exit_code.is_none() {
                    return Err(CapsuleReceiptError::Invalid(
                        "a contained receipt must record the child's exit status".to_string(),
                    ));
                }
                let complete = self
                    .subject
                    .project_input
                    .as_ref()
                    .is_some_and(|tree| tree.complete)
                    && self
                        .subject
                        .project_output
                        .as_ref()
                        .is_some_and(|tree| tree.complete);
                if !complete {
                    return Err(CapsuleReceiptError::Invalid(
                        "a contained receipt requires complete input and output tree digests"
                            .to_string(),
                    ));
                }
            }
            CapsuleRunStatus::Partial => {
                if self.evidence.decision == CapsuleRunDecision::RefusedBeforeLaunch
                    && self.evidence.reason.is_none()
                {
                    return Err(CapsuleReceiptError::Invalid(
                        "a partial receipt that refused must carry a reason".to_string(),
                    ));
                }
            }
        }
        Ok(())
    }

    /// Save the receipt and anchor its content hash in the audit chain.
    ///
    /// Order: validate (side-effect free), write the content-addressed store
    /// copy, ANCHOR it, then write the operator's `--receipt` copy. Anchoring
    /// before the operator copy is deliberate: the anchor re-reads the stored
    /// bytes to mint its digest capability, and a failed operator-path write
    /// (an unwritable directory, say) must not leave the store copy orphaned
    /// and unanchored. The operator copy is still written when no data
    /// directory exists, because they explicitly asked for that file.
    pub fn record(
        &self,
        requested_path: Option<&Path>,
    ) -> Result<RecordedCapsuleReceipt, CapsuleReceiptError> {
        self.validate()?;
        let prepared = PreparedCapsuleReceipt::prepare(requested_path, None)?;
        self.record_prepared(&prepared)
    }

    /// Save using a destination retained since before the project scan. Every
    /// publication is immediately re-read through that same parent capability
    /// and compared byte-for-byte before success can be reported.
    pub fn record_prepared(
        &self,
        prepared: &PreparedCapsuleReceipt,
    ) -> Result<RecordedCapsuleReceipt, CapsuleReceiptError> {
        self.validate()?;
        let json = serde_json::to_string_pretty(self).map_err(|error| {
            CapsuleReceiptError::Io(std::io::Error::new(std::io::ErrorKind::InvalidData, error))
        })?;
        if json.len() > MAX_CAPSULE_RECEIPT_BYTES {
            return Err(CapsuleReceiptError::Invalid(format!(
                "serialized receipt exceeds the {MAX_CAPSULE_RECEIPT_BYTES}-byte limit"
            )));
        }

        let mut store_path = None;
        if let Some(directory) = capsule_receipts_dir() {
            let path = absolute_path(&directory.join(format!("{}.json", self.receipt_id)))
                .map_err(CapsuleReceiptError::Io)?;
            let anchor = filesystem_anchor(&path).ok_or_else(|| {
                CapsuleReceiptError::Io(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "receipt store path has no filesystem root",
                ))
            })?;
            let destination = crate::util::ContainedAtomicFile::prepare(&anchor, &path, true)
                .map_err(CapsuleReceiptError::Io)?;
            publish_and_verify(&destination, &path, json.as_bytes())?;
            store_path = Some(path);
        }

        let (anchored, anchor_warning) = match crate::audit::log_capsule_run_receipt(
            &self.receipt_id,
            &self.receipt_id,
            self.status.token(),
        ) {
            crate::audit::ReceiptAnchor::Recorded { .. } => (true, None),
            crate::audit::ReceiptAnchor::Skipped => (false, None),
            crate::audit::ReceiptAnchor::Failed(reason) => (false, Some(reason)),
        };

        let mut written_requested = None;
        if let Some(requested) = &prepared.requested {
            publish_and_verify(&requested.destination, &requested.path, json.as_bytes())?;
            written_requested = Some(requested.reported_path.clone());
        }

        Ok(RecordedCapsuleReceipt {
            store_path,
            requested_path: written_requested,
            signed: self.signature.is_some(),
            anchored,
            anchor_warning,
        })
    }
}

fn publish_and_verify(
    destination: &crate::util::ContainedAtomicFile,
    visible_path: &Path,
    bytes: &[u8],
) -> Result<(), CapsuleReceiptError> {
    destination
        .write_atomic(bytes, true)
        .map_err(CapsuleReceiptError::Io)?;
    let cap = u64::try_from(MAX_CAPSULE_RECEIPT_BYTES).unwrap_or(u64::MAX);
    let visible = destination.read_capped(cap).map_err(|error| {
        CapsuleReceiptError::Io(std::io::Error::other(format!(
            "verify published capsule receipt: {error:?}"
        )))
    })?;
    if visible != bytes {
        return Err(CapsuleReceiptError::Io(std::io::Error::other(
            "published capsule receipt did not read back byte-for-byte",
        )));
    }
    let mut visible_file =
        crate::util::open_read_no_follow_capped(visible_path, cap).map_err(|error| {
            CapsuleReceiptError::Io(std::io::Error::other(format!(
                "verify visible capsule receipt: {error:?}"
            )))
        })?;
    use std::io::Read as _;
    let mut visible_bytes = Vec::new();
    (&mut visible_file)
        .take(cap.saturating_add(1))
        .read_to_end(&mut visible_bytes)
        .map_err(CapsuleReceiptError::Io)?;
    if visible_bytes != bytes {
        return Err(CapsuleReceiptError::Io(std::io::Error::other(
            "visible capsule receipt did not read back byte-for-byte",
        )));
    }
    Ok(())
}

/// What an absolute host path becomes in a durable receipt.
pub const REDACTED_PATH_MARKER: &str = "<path>";

/// Trailing punctuation that belongs to the sentence rather than to the path.
const PATH_TRAILING_PUNCTUATION: &[char] = &[';', ',', ':', '.', '"', '\'', ')', ']', '}'];

/// Leading punctuation that belongs to the sentence rather than to the path. A
/// quoted path is still a path, and this is a privacy invariant, so the quoting
/// style a message happens to use must not decide whether it holds.
const PATH_LEADING_PUNCTUATION: &[char] = &['"', '\'', '(', '[', '{', '`'];

/// Replace every absolute host path in parent-generated text with
/// [`REDACTED_PATH_MARKER`].
///
/// A receipt is durable and shareable, and the refusal reasons that reach it are
/// built from filesystem-policy errors that `.display()` both roots. Those name
/// the operator's account, their home layout, and which credential stores exist
/// on the machine. The terminal rendering keeps the paths, because the operator
/// needs them to act; the artifact they hand to a counterparty does not.
pub fn redact_host_paths(text: &str) -> String {
    let mut redacted = String::with_capacity(text.len());
    for chunk in text.split_inclusive(char::is_whitespace) {
        let word = chunk.trim_end();
        let trailing_whitespace = &chunk[word.len()..];
        let quoted = word.trim_start_matches(PATH_LEADING_PUNCTUATION);
        let leading_punctuation = &word[..word.len() - quoted.len()];
        let body = quoted.trim_end_matches(PATH_TRAILING_PUNCTUATION);
        let trailing_punctuation = &quoted[body.len()..];
        if is_absolute_host_path(body) {
            redacted.push_str(leading_punctuation);
            redacted.push_str(REDACTED_PATH_MARKER);
            redacted.push_str(trailing_punctuation);
        } else {
            redacted.push_str(word);
        }
        redacted.push_str(trailing_whitespace);
    }
    redacted
}

/// Whether one whitespace-delimited token names an absolute path on any host
/// this receipt can be written on. A bare `/` is a separator in prose, not a
/// location, so it is left alone.
fn is_absolute_host_path(token: &str) -> bool {
    if token.len() < 2 {
        return false;
    }
    if token.starts_with('/') {
        return true;
    }
    let bytes = token.as_bytes();
    // `C:\...` and `\\server\share`, so a Windows refusal receipt is covered by
    // the same rule as a unix one.
    (bytes[0].is_ascii_alphabetic() && bytes.get(1) == Some(&b':') && bytes.get(2) == Some(&b'\\'))
        || token.starts_with("\\\\")
}

/// Where content-addressed capsule receipts are stored. Deliberately its own
/// directory: the install receipts under `receipts/` have a different schema and
/// a different chain entry type, and mixing them would let a reader deserialize
/// one as the other.
pub fn capsule_receipts_dir() -> Option<PathBuf> {
    crate::policy::data_dir().map(|dir| dir.join("capsule-receipts"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn coverage(all: bool) -> CapsuleCoverage {
        CapsuleCoverage {
            fs_read_enforced: all,
            fs_write_enforced: all,
            exec_limited: all,
            network_raw_denied: all,
            domain_proxy_enforced: false,
            resource_limits_enforced: all,
            env_isolated: all,
            handles_isolated: all,
        }
    }

    fn tree(complete: bool, digest: &str) -> CapsuleTreeDigest {
        CapsuleTreeDigest {
            digest: digest.to_string(),
            file_count: 2,
            total_bytes: 12,
            complete,
        }
    }

    fn contained_facts() -> CapsuleRunFacts {
        CapsuleRunFacts {
            status: CapsuleRunStatus::Contained,
            policy_projection_hash: "a".repeat(64),
            task_gate_binding: "task_gate:v1:mode=off;denied=".to_string(),
            subject: CapsuleRunSubject {
                preset: "untrusted-project".to_string(),
                argv_digest: "b".repeat(64),
                argv_len: 2,
                project_input: Some(tree(true, &"c".repeat(64))),
                project_output: Some(tree(true, &"d".repeat(64))),
            },
            evidence: CapsuleRunEvidence {
                backend_id: "landlock-seccomp".to_string(),
                platform: "linux/x86_64".to_string(),
                limits: ResourceLimits::conservative(),
                child_exit_code: Some(0),
                decision: CapsuleRunDecision::TargetCompleted,
                termination_kind: None,
                reason: None,
                project_copy_materialized: true,
                cleanup_confirmed: true,
                diff: ProjectDiff::default(),
            },
            coverage: CapsuleRunCoverage {
                requested: coverage(true),
                achieved: coverage(true),
                parent_enforced_dimensions: vec![
                    "max_output_bytes".to_string(),
                    "wall_clock_seconds".to_string(),
                ],
            },
        }
    }

    #[test]
    fn a_fresh_receipt_is_content_addressed_and_valid() {
        let receipt = CapsuleRunReceipt::new(contained_facts());
        assert_eq!(receipt.receipt_id.len(), 64);
        assert!(receipt.content_hash_matches());
        receipt.validate().expect("a coherent receipt validates");
    }

    #[test]
    fn in_project_receipt_parent_is_prepared_and_exclusion_is_exact() {
        let base = tempfile::tempdir().expect("tempdir");
        let project = base.path().join("project");
        std::fs::create_dir(&project).expect("project");
        let requested = project.join("receipts/run.json");
        let prepared = PreparedCapsuleReceipt::prepare(Some(&requested), Some(&project))
            .expect("prepare retained parent");

        assert_eq!(
            prepared.project_exclusion(),
            Some(Path::new("receipts/run.json"))
        );
        assert!(project.join("receipts").is_dir());
    }

    #[test]
    fn a_directory_cannot_become_a_broad_receipt_exclusion() {
        let base = tempfile::tempdir().expect("tempdir");
        let project = base.path().join("project");
        let requested = project.join("receipts/run.json");
        std::fs::create_dir_all(&requested).expect("directory at requested leaf");

        let error = match PreparedCapsuleReceipt::prepare(Some(&requested), Some(&project)) {
            Err(error) => error,
            Ok(_) => panic!("non-file receipt leaf must refuse"),
        };
        assert!(error.to_string().contains("not a regular file"));
    }

    #[test]
    fn publication_requires_immediate_retained_and_visible_readback() {
        let base = tempfile::tempdir().expect("tempdir");
        let project = base.path().join("project");
        std::fs::create_dir_all(project.join("receipts")).expect("receipt parent");
        let requested = project.join("receipts/run.json");
        let prepared = PreparedCapsuleReceipt::prepare(Some(&requested), Some(&project))
            .expect("prepare retained parent");
        let requested_capability = prepared.requested.as_ref().expect("requested capability");
        publish_and_verify(
            &requested_capability.destination,
            &requested_capability.path,
            b"receipt-one",
        )
        .expect("matching readback succeeds");

        let retained_parent = project.join("receipts-retained");
        std::fs::rename(project.join("receipts"), &retained_parent).expect("swap parent");
        std::fs::create_dir(project.join("receipts")).expect("visible replacement");
        let error = publish_and_verify(
            &requested_capability.destination,
            &requested_capability.path,
            b"receipt-two",
        )
        .expect_err("hidden publication cannot report success");
        assert!(error.to_string().contains("visible capsule receipt"));
        assert_eq!(
            std::fs::read(retained_parent.join("run.json")).expect("retained publication"),
            b"receipt-two"
        );
        assert!(!requested.exists());
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn retained_receipt_accepts_the_approved_macos_var_alias() {
        let base = tempfile::tempdir().expect("tempdir");
        let canonical_base = std::fs::canonicalize(base.path()).expect("canonical tempdir");
        let suffix = canonical_base
            .strip_prefix("/private/var")
            .expect("macOS tempdir lives beneath /private/var");
        let aliased_base = Path::new("/var").join(suffix);
        let project = canonical_base.join("project");
        std::fs::create_dir(&project).expect("project");
        let aliased_project = aliased_base.join("project");
        let requested = aliased_project.join("receipts/run.json");

        let prepared = PreparedCapsuleReceipt::prepare(Some(&requested), Some(&aliased_project))
            .expect("the fixed system alias is accepted");

        assert_eq!(
            prepared.project_exclusion(),
            Some(Path::new("receipts/run.json"))
        );
        assert!(project.join("receipts").is_dir());
    }

    #[cfg(unix)]
    #[test]
    fn retained_receipt_rejects_a_symlink_below_the_project_root() {
        let base = tempfile::tempdir().expect("tempdir");
        let project = base.path().join("project");
        let outside = base.path().join("outside");
        std::fs::create_dir(&project).expect("project");
        std::fs::create_dir(&outside).expect("outside");
        std::os::unix::fs::symlink(&outside, project.join("receipts")).expect("symlink");
        let requested = project.join("receipts/run.json");

        let error = match PreparedCapsuleReceipt::prepare(Some(&requested), Some(&project)) {
            Err(error) => error,
            Ok(_) => panic!("a symlink below the trusted project root must be refused"),
        };
        assert!(
            error
                .to_string()
                .contains("symlinked contained directory component receipts"),
            "{error}"
        );
    }

    #[test]
    fn tampering_with_any_field_breaks_the_content_address() {
        let baseline = CapsuleRunReceipt::new(contained_facts());
        for mutate in [
            (|r: &mut CapsuleRunReceipt| r.evidence.child_exit_code = Some(1)) as fn(&mut _),
            |r: &mut CapsuleRunReceipt| r.evidence.cleanup_confirmed = false,
            |r: &mut CapsuleRunReceipt| r.subject.argv_digest = "e".repeat(64),
            |r: &mut CapsuleRunReceipt| r.status = CapsuleRunStatus::Partial,
            |r: &mut CapsuleRunReceipt| r.coverage.achieved.network_raw_denied = false,
        ] {
            let mut tampered = baseline.clone();
            mutate(&mut tampered);
            assert!(
                !tampered.content_hash_matches(),
                "an edited receipt must not still match its content address"
            );
            assert!(tampered.validate().is_err());
        }
    }

    #[test]
    fn the_content_address_ignores_the_signature_field() {
        let mut receipt = CapsuleRunReceipt::new(contained_facts());
        let before = receipt.compute_content_hash();
        receipt.signature = Some("not-a-real-signature".to_string());
        assert_eq!(receipt.compute_content_hash(), before);
        assert!(receipt.content_hash_matches());
    }

    #[test]
    fn a_contained_claim_requires_full_coverage_cleanup_and_complete_digests() {
        let degraded = {
            let mut facts = contained_facts();
            facts.coverage.achieved.network_raw_denied = false;
            CapsuleRunReceipt::new(facts)
        };
        assert!(degraded.validate().is_err());

        let unconfirmed = {
            let mut facts = contained_facts();
            facts.evidence.cleanup_confirmed = false;
            CapsuleRunReceipt::new(facts)
        };
        assert!(unconfirmed.validate().is_err());

        let terminated = {
            let mut facts = contained_facts();
            facts.evidence.decision = CapsuleRunDecision::TerminatedByTirith;
            CapsuleRunReceipt::new(facts)
        };
        assert!(terminated.validate().is_err());

        let incomplete = {
            let mut facts = contained_facts();
            facts.subject.project_output = Some(tree(false, &"d".repeat(64)));
            CapsuleRunReceipt::new(facts)
        };
        assert!(incomplete.validate().is_err());
    }

    #[test]
    fn a_refusal_records_a_reason_and_never_a_child_exit() {
        let mut facts = contained_facts();
        facts.status = CapsuleRunStatus::Refused;
        facts.evidence.decision = CapsuleRunDecision::RefusedBeforeLaunch;
        facts.evidence.child_exit_code = None;
        facts.evidence.reason = Some("missing: network_raw_denied".to_string());
        facts.subject.project_input = None;
        facts.subject.project_output = None;
        CapsuleRunReceipt::new(facts.clone())
            .validate()
            .expect("a coherent refusal validates");

        let mut with_exit = facts.clone();
        with_exit.evidence.child_exit_code = Some(0);
        assert!(CapsuleRunReceipt::new(with_exit).validate().is_err());

        let mut without_reason = facts;
        without_reason.evidence.reason = None;
        assert!(CapsuleRunReceipt::new(without_reason).validate().is_err());
    }

    #[test]
    fn the_signature_binds_the_signing_payload() {
        use ed25519_dalek::{Signer as _, SigningKey};

        let mut receipt = CapsuleRunReceipt::new(contained_facts());
        let key = SigningKey::from_bytes(&[7u8; 32]);
        use base64::Engine as _;
        receipt.signature = Some(
            base64::engine::general_purpose::STANDARD
                .encode(key.sign(receipt.signing_payload().as_bytes()).to_bytes()),
        );
        let public = key.verifying_key().to_bytes();
        assert!(receipt.signature_verifies(&public));

        // Any edit after signing invalidates the signature, because the payload
        // carries the content address.
        let mut edited = receipt.clone();
        edited.receipt_id = "f".repeat(64);
        assert!(!edited.signature_verifies(&public));

        let mut unsigned = receipt;
        unsigned.signature = None;
        assert!(!unsigned.signature_verifies(&public));
    }

    #[test]
    fn the_serialized_receipt_carries_no_argv_and_no_host_path() {
        let receipt = CapsuleRunReceipt::new(contained_facts());
        let json = serde_json::to_string(&receipt).expect("serialize");
        assert!(!json.contains("\"argv\""));
        assert!(!json.contains("/Users/"));
        assert!(!json.contains("/home/"));
        assert!(!json.contains("/tmp/"));
        assert!(json.contains("argv_digest"));
    }

    #[test]
    fn a_path_bearing_refusal_reason_is_redacted_before_it_becomes_durable() {
        // The real shape: the deny-root refusal reason, which `.display()`s both
        // roots and so names the operator's account and their credential stores.
        let mut facts = contained_facts();
        facts.status = CapsuleRunStatus::Refused;
        facts.evidence.decision = CapsuleRunDecision::RefusedBeforeLaunch;
        facts.evidence.child_exit_code = None;
        facts.subject.project_input = None;
        facts.subject.project_output = None;
        facts.evidence.reason = Some(
            "--project names a path the untrusted-project preset denies by default: write allow \
             root /Users/home/.ssh overlaps deny root /Users/home/.ssh; this backend cannot prove \
             an explicit deny carve-out"
                .to_string(),
        );
        let receipt = CapsuleRunReceipt::new(facts);
        receipt
            .validate()
            .expect("a redacted refusal still validates");
        let json = serde_json::to_string(&receipt).expect("serialize");
        assert!(!json.contains("/Users/"), "{json}");
        assert!(json.contains(REDACTED_PATH_MARKER));
        let reason = receipt.evidence.reason.expect("the refusal keeps a reason");
        assert!(
            reason.contains("overlaps deny root") && reason.ends_with("carve-out"),
            "the sentence must survive the redaction: {reason}"
        );
    }

    #[test]
    fn host_path_redaction_keeps_prose_and_covers_every_host_spelling() {
        assert_eq!(
            redact_host_paths("resolve the held project copy /tmp/tirith-capsule-project-ab12: no"),
            format!("resolve the held project copy {REDACTED_PATH_MARKER}: no")
        );
        assert_eq!(
            redact_host_paths("open grant C:\\Users\\dev\\.ssh failed"),
            format!("open grant {REDACTED_PATH_MARKER} failed")
        );
        assert_eq!(
            redact_host_paths("read/write ratio is 3/4 and a / separates them"),
            "read/write ratio is 3/4 and a / separates them"
        );
        // A quoted path is still a path.
        assert_eq!(
            redact_host_paths("cannot canonicalize '/Users/home/.aws': denied"),
            format!("cannot canonicalize '{REDACTED_PATH_MARKER}': denied")
        );
        assert_eq!(
            redact_host_paths("missing: network_raw_denied"),
            "missing: network_raw_denied"
        );
    }

    #[test]
    fn a_refusal_that_copied_the_project_must_have_cleaned_it_up() {
        let mut facts = contained_facts();
        facts.status = CapsuleRunStatus::Refused;
        facts.evidence.decision = CapsuleRunDecision::RefusedBeforeLaunch;
        facts.evidence.child_exit_code = None;
        facts.evidence.reason = Some("the project copy could not be inventoried".to_string());
        facts.subject.project_input = None;
        facts.subject.project_output = None;
        facts.evidence.project_copy_materialized = true;
        facts.evidence.cleanup_confirmed = false;
        assert!(
            CapsuleRunReceipt::new(facts.clone()).validate().is_err(),
            "a refusal that left the copy on disk must not record as a clean refusal"
        );

        facts.evidence.project_copy_materialized = false;
        CapsuleRunReceipt::new(facts)
            .validate()
            .expect("a refusal before any copy is clean whatever cleanup reports");
    }
}
