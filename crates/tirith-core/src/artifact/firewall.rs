//! The package firewall's inspect-and-verdict layer (PR D3).
//!
//! D2 resolved a set of requirements into a fully hash-pinned lock and landed the
//! pinned wheels in the D1 quarantine as content-addressed blobs. This module is
//! the step between that and D4's install-from-digest: it takes the resolver's
//! [`ResolvedSet`], RE-MATERIALISES each approved blob into the install
//! transaction under its validated `*.whl` filename, runs the wheel-set inspection
//! over the verified bytes, and finalises ONE [`Verdict`] the install gates on.
//!
//! # The TOCTOU re-bind (firewall invariant)
//!
//! The firewall operates only on content-addressed quarantine files, and it
//! RE-HASHES each one immediately before evaluation. The re-hash is not a separate
//! pre-flight stat: [`QuarantineTransaction::materialize_blob`] streams the blob
//! from a single no-follow handle, re-hashes the copied bytes, and publishes the
//! `*.whl` copy ONLY when the re-hash equals the digest the resolver pinned. So a
//! blob that was swapped, truncated, or removed between D2's ingest and this
//! evaluation cannot pass: `materialize_blob` returns a
//! [`QuarantineError::DigestMismatch`] / [`QuarantineError::BlobNotFound`], which
//! this module turns into the Critical
//! [`crate::verdict::RuleId::ArtifactDownloadIntegrityMismatch`] for that artifact.
//! The bytes the firewall inspects are therefore exactly the bytes that hashed to
//! the approved digest at materialisation time, and the bytes D4 installs are the
//! same immutable `0o400` copies this step produced.
//!
//! # Two distinct hash verdicts
//!
//! A download-vs-expected hash mismatch and a known-malicious hash match are
//! different failures and carry different RuleIds:
//!
//! * [`crate::verdict::RuleId::ArtifactDownloadIntegrityMismatch`] (here): the
//!   bytes are NOT the bytes that were approved (the blob no longer hashes to the
//!   resolver-pinned digest). An integrity failure; the enforcing surface fails
//!   closed regardless of whether the substituted content is itself flagged.
//! * [`crate::verdict::RuleId::ArtifactKnownMalicious`] (the threat-DB lookup the
//!   inspection's [`crate::artifact::correlate`] applies): the bytes ARE a
//!   confirmed bad artifact (their SHA-256 matches a known-malicious record). A
//!   reputation hit, gated behind the `artifact-hash-lookup` feature.
//!
//! The firewall never conflates the two: an integrity mismatch is decided here
//! before the bytes are even inspected, and a known-malicious match is decided by
//! the inspection's correlator over the verified bytes.
//!
//! # Failing closed
//!
//! This module produces findings and a verdict; it does not by itself decide the
//! degraded-coverage policy gate (that is the capsule/E-stack and D4's concern). A
//! Critical integrity finding makes the verdict's action `Block`, so an install
//! surface that respects the verdict cannot proceed on substituted bytes.

use std::path::PathBuf;

use crate::artifact::inspect::{inspect_artifact_set, ArtifactSetInspection};
use crate::artifact::quarantine::{QuarantineError, QuarantineTransaction};
use crate::artifact::resolver::{ResolvedArtifact, ResolvedSet};
use crate::policy::Policy;
use crate::threatdb::ThreatDb;
use crate::verdict::{Evidence, Finding, RuleId, Severity, Timings, Verdict};

/// The outcome of firewalling a resolved set: the verdict the install gates on,
/// the integrity-mismatch findings decided BEFORE inspection (kept separate so a
/// caller can distinguish "the approved bytes are gone" from a content finding),
/// the underlying wheel-set inspection over the artifacts that materialised
/// cleanly, and the validated `*.whl` paths that did materialise (the immutable
/// copies D4 installs from).
pub struct FirewallOutcome {
    /// The single finalised verdict over the whole set (integrity findings +
    /// every inspection finding + the threat-DB hash lookup), via
    /// [`crate::escalation::finalize_static_verdict`].
    pub verdict: Verdict,
    /// The Critical [`RuleId::ArtifactDownloadIntegrityMismatch`] findings, one per
    /// artifact whose quarantine blob did not re-hash to its approved digest (a
    /// swap, truncation, or missing blob). Empty when every blob was intact.
    pub integrity_findings: Vec<Finding>,
    /// The wheel-set inspection over the artifacts that materialised intact. An
    /// artifact with an integrity mismatch is NOT inspected (its bytes are not the
    /// approved bytes), so it is absent from this inspection.
    pub set_inspection: ArtifactSetInspection,
    /// The validated `*.whl` paths that materialised cleanly into the transaction
    /// (parallel to `set_inspection.members` by input order). D4 installs from
    /// exactly these immutable copies.
    pub materialized: Vec<PathBuf>,
}

impl FirewallOutcome {
    /// Whether the firewall verdict blocks the install (any Critical/blocking
    /// finding, including an integrity mismatch). A convenience over
    /// `self.verdict.action`.
    pub fn is_block(&self) -> bool {
        matches!(self.verdict.action, crate::verdict::Action::Block)
    }

    /// Whether any artifact failed the integrity re-bind (its blob did not re-hash
    /// to the approved digest). When true, the approved bytes are gone for at least
    /// one artifact and the install must not proceed.
    pub fn has_integrity_mismatch(&self) -> bool {
        !self.integrity_findings.is_empty()
    }
}

/// Firewall a resolved set into a single verdict.
///
/// For each [`ResolvedArtifact`] in `resolved`, materialise its content-addressed
/// blob into `txn` under the artifact's validated wheel filename. The
/// materialisation re-hashes the blob (the TOCTOU re-bind); a mismatch / missing
/// blob becomes a Critical [`RuleId::ArtifactDownloadIntegrityMismatch`] for that
/// artifact and the artifact is excluded from inspection. The artifacts that
/// materialise intact are inspected as a SET (so a cross-distribution
/// loader/payload split across two approved wheels is caught), and every finding
/// (integrity + inspection signal/native/cross + the threat-DB hash lookup) is
/// finalised through [`crate::escalation::finalize_static_verdict`] so per-rule
/// severity / action overrides and paranoia filtering apply at this verdict site
/// (cross-cutting invariant 5).
///
/// `threat_db` is threaded into [`ArtifactSetInspection::all_findings`] so the
/// `artifact-hash-lookup` known-malicious check resolves without re-reading bytes.
/// Passing `None` simply skips that lookup; it never causes a false positive.
pub fn firewall_resolved_set(
    resolved: &ResolvedSet,
    txn: &QuarantineTransaction,
    policy: &Policy,
    threat_db: Option<&ThreatDb>,
) -> FirewallOutcome {
    let mut integrity_findings: Vec<Finding> = Vec::new();
    let mut materialized: Vec<PathBuf> = Vec::new();

    for artifact in &resolved.artifacts {
        match materialize_one(txn, artifact) {
            Ok(path) => materialized.push(path),
            Err(err) => integrity_findings.push(integrity_mismatch_finding(artifact, &err)),
        }
    }

    // Inspect only the artifacts that materialised intact: the others are not the
    // approved bytes, so inspecting them would describe content we are about to
    // refuse to install anyway.
    let set_inspection = inspect_artifact_set(&materialized);

    let mut findings = integrity_findings.clone();
    findings.extend(set_inspection.all_findings(threat_db));

    // Artifact/firewall verdicts are tier-3 by construction (they never run the
    // tier-1 command gate); timings are not measured on this seam, matching
    // `crate::artifact::evaluate_artifact`.
    let verdict =
        crate::escalation::finalize_static_verdict(findings, policy, 3, Timings::default());

    FirewallOutcome {
        verdict,
        integrity_findings,
        set_inspection,
        materialized,
    }
}

/// Materialise one resolved artifact's blob into the transaction under its
/// validated wheel filename, re-hashing on the way (the integrity re-bind).
/// Returns the published `*.whl` path, or the quarantine error explaining why the
/// approved bytes could not be reproduced.
fn materialize_one(
    txn: &QuarantineTransaction,
    artifact: &ResolvedArtifact,
) -> Result<PathBuf, QuarantineError> {
    txn.materialize_blob(&artifact.sha256, &artifact.wheel_filename)
}

/// Build the Critical [`RuleId::ArtifactDownloadIntegrityMismatch`] finding for an
/// artifact whose blob did not re-hash to its approved digest. The evidence names
/// the artifact and the failure, never any secret or registry credential.
fn integrity_mismatch_finding(artifact: &ResolvedArtifact, err: &QuarantineError) -> Finding {
    let detail = match err {
        QuarantineError::DigestMismatch { expected, actual } => format!(
            "quarantined wheel {} no longer hashes to its approved digest: expected sha256 {}, \
             re-hashed to {} at firewall time. The approved bytes were substituted or corrupted; \
             installing would run unapproved content.",
            artifact.wheel_filename, expected, actual
        ),
        QuarantineError::BlobNotFound(digest) => format!(
            "the approved blob for wheel {} (sha256 {}) is missing from the quarantine at firewall \
             time, so its bytes cannot be reproduced for inspection or install.",
            artifact.wheel_filename, digest
        ),
        other => format!(
            "the approved blob for wheel {} (sha256 {}) could not be re-materialised for the \
             firewall: {}. The approved bytes cannot be confirmed, so the install must not \
             proceed.",
            artifact.wheel_filename, artifact.sha256, other
        ),
    };

    Finding {
        rule_id: RuleId::ArtifactDownloadIntegrityMismatch,
        severity: Severity::Critical,
        title: "A quarantined artifact no longer hashes to its approved digest".to_string(),
        description: "The package firewall re-hashes each content-addressed quarantine blob \
             immediately before evaluation. This artifact's blob did not reproduce the digest the \
             resolver pinned, so the bytes that would be installed are not the bytes that were \
             approved. This is an integrity failure, distinct from a known-malicious hash match; \
             the install fails closed."
            .to_string(),
        evidence: vec![Evidence::Text { detail }],
        human_view: None,
        agent_view: None,
        mitre_id: Some("T1565".to_string()),
        custom_rule_id: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::artifact::quarantine::QuarantineStore;
    use crate::artifact::resolver::{ResolvedArtifact, ResolvedSet};
    use crate::verdict::Action;
    use base64::Engine as _;
    use sha2::{Digest, Sha256};
    use std::io::Write as _;
    use zip::write::SimpleFileOptions;
    use zip::ZipWriter;

    /// Lowercase-hex SHA-256 of `bytes`, the digest the resolver would pin.
    fn sha256_hex(bytes: &[u8]) -> String {
        let mut h = Sha256::new();
        h.update(bytes);
        let out = h.finalize();
        let mut s = String::with_capacity(64);
        for b in out {
            s.push_str(&format!("{b:02x}"));
        }
        s
    }

    /// The RECORD `sha256=<base64url-no-pad>` cell for a member body, the exact
    /// form `crate::artifact::wheel::parse_record` decodes and `verify_wheel_record`
    /// compares against the member's actual hash.
    fn record_sha256_cell(body: &[u8]) -> String {
        let mut h = Sha256::new();
        h.update(body);
        let digest = h.finalize();
        let b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(digest);
        format!("sha256={b64}")
    }

    /// Build an in-memory wheel zip from (member, body) pairs (the proven
    /// `inspect.rs` test helper).
    fn build_wheel(members: &[(&str, &[u8])]) -> Vec<u8> {
        let mut zw = ZipWriter::new(std::io::Cursor::new(Vec::new()));
        for (name, body) in members {
            zw.start_file(*name, SimpleFileOptions::default()).unwrap();
            zw.write_all(body).unwrap();
        }
        zw.finish().unwrap().into_inner()
    }

    /// A benign wheel for distribution `name` version `1.0` whose RECORD CORRECTLY
    /// lists and hashes every non-RECORD member (METADATA + WHEEL), so the wheel
    /// inspection yields no integrity, startup, or native findings. `salt` lets the
    /// caller produce two byte-distinct wheels (distinct outer digests) without
    /// changing the clean-inspection property. Returns the wheel bytes.
    fn benign_wheel(name: &str, salt: &str) -> Vec<u8> {
        let metadata =
            format!("Metadata-Version: 2.1\nName: {name}\nVersion: 1.0\nSummary: {salt}\n\n");
        let wheel =
            b"Wheel-Version: 1.0\nGenerator: test\nRoot-Is-Purelib: true\nTag: py3-none-any\n";
        let metadata_bytes = metadata.into_bytes();
        let record = format!(
            "{name}-1.0.dist-info/METADATA,{},{}\n\
             {name}-1.0.dist-info/WHEEL,{},{}\n\
             {name}-1.0.dist-info/RECORD,,\n",
            record_sha256_cell(&metadata_bytes),
            metadata_bytes.len(),
            record_sha256_cell(wheel),
            wheel.len(),
        );
        build_wheel(&[
            (
                &format!("{name}-1.0.dist-info/METADATA"),
                metadata_bytes.as_slice(),
            ),
            (&format!("{name}-1.0.dist-info/WHEEL"), wheel.as_slice()),
            (&format!("{name}-1.0.dist-info/RECORD"), record.as_bytes()),
        ])
    }

    /// The default benign wheel used where one clean wheel is enough.
    fn benign_wheel_bytes() -> Vec<u8> {
        benign_wheel("demo", "a")
    }

    /// A store + open transaction over a fresh temp root.
    fn store_with_txn(id: &str) -> (tempfile::TempDir, QuarantineStore, QuarantineTransaction) {
        let root = tempfile::tempdir().unwrap();
        let store = QuarantineStore::with_root(root.path().join("q")).unwrap();
        let txn = store.begin_transaction(id).unwrap();
        (root, store, txn)
    }

    /// Happy path: a benign wheel ingested as a blob, then firewalled, yields an
    /// Allow with no findings and one materialised `*.whl`. Proves the
    /// materialise -> inspect -> finalize pipeline and that a clean set is clean.
    #[test]
    fn firewall_allows_clean_resolved_set() {
        let bytes = benign_wheel_bytes();
        let digest = sha256_hex(&bytes);
        let filename = "demo-1.0-py3-none-any.whl";

        let (_root, store, txn) = store_with_txn("fw-clean");
        store.ingest_bytes(&bytes, &digest).unwrap();

        let resolved = ResolvedSet {
            locked_requirements: format!("demo==1.0 \\\n    --hash=sha256:{digest}\n"),
            artifacts: vec![ResolvedArtifact {
                wheel_filename: filename.to_string(),
                sha256: digest.clone(),
            }],
        };

        let outcome = firewall_resolved_set(&resolved, &txn, &Policy::default(), None);

        assert!(
            !outcome.has_integrity_mismatch(),
            "an intact blob must not produce an integrity mismatch"
        );
        assert_eq!(outcome.materialized.len(), 1, "the one wheel materialises");
        assert_eq!(
            outcome.verdict.action,
            Action::Allow,
            "a clean benign wheel is allowed: {:?}",
            outcome.verdict.findings
        );
        assert!(outcome.verdict.findings.is_empty());
        assert_eq!(outcome.verdict.tier_reached, 3);
        // The materialised copy is the validated wheel name, inside the txn dir.
        assert!(outcome.materialized[0].ends_with(filename));
        assert!(outcome.materialized[0].starts_with(txn.dir()));
    }

    /// The integrity re-bind: if the quarantine blob is swapped (different bytes
    /// landed under the approved digest's path) between ingest and firewall, the
    /// re-hash at materialise time differs and the firewall raises
    /// `ArtifactDownloadIntegrityMismatch` (Critical -> Block), NOT
    /// `ArtifactKnownMalicious`. The swapped artifact is excluded from inspection.
    #[test]
    fn firewall_blocks_on_blob_swap_with_integrity_mismatch() {
        let approved = benign_wheel_bytes();
        let approved_digest = sha256_hex(&approved);
        let filename = "demo-1.0-py3-none-any.whl";

        let (_root, store, txn) = store_with_txn("fw-swap");
        // Ingest the approved bytes legitimately (verifies on the way in).
        store.ingest_bytes(&approved, &approved_digest).unwrap();

        // Now SWAP the blob's bytes underneath the approved-digest path, as a
        // tamper between D2 ingest and D3 firewall would. The blob file is
        // immutable (0o400) on unix; loosen perms first so the test can overwrite.
        let blob_path = store.blob_path(&approved_digest);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            std::fs::set_permissions(&blob_path, std::fs::Permissions::from_mode(0o600)).unwrap();
        }
        std::fs::write(
            &blob_path,
            b"totally different bytes that do not match the digest",
        )
        .unwrap();

        let resolved = ResolvedSet {
            locked_requirements: format!("demo==1.0 \\\n    --hash=sha256:{approved_digest}\n"),
            artifacts: vec![ResolvedArtifact {
                wheel_filename: filename.to_string(),
                sha256: approved_digest.clone(),
            }],
        };

        let outcome = firewall_resolved_set(&resolved, &txn, &Policy::default(), None);

        assert!(
            outcome.has_integrity_mismatch(),
            "a swapped blob must fail the integrity re-bind"
        );
        assert_eq!(outcome.integrity_findings.len(), 1);
        assert_eq!(
            outcome.integrity_findings[0].rule_id,
            RuleId::ArtifactDownloadIntegrityMismatch,
            "a download-vs-expected mismatch is ArtifactDownloadIntegrityMismatch, \
             not ArtifactKnownMalicious"
        );
        assert_eq!(outcome.integrity_findings[0].severity, Severity::Critical);
        assert_eq!(outcome.verdict.action, Action::Block);
        assert!(outcome.is_block());
        // The swapped artifact is NOT inspected (its bytes are not the approved bytes).
        assert!(outcome.materialized.is_empty());
        assert!(outcome.set_inspection.members.is_empty());
        // No ArtifactKnownMalicious is fabricated for an integrity failure.
        assert!(!outcome
            .verdict
            .findings
            .iter()
            .any(|f| f.rule_id == RuleId::ArtifactKnownMalicious));
    }

    /// A missing blob (the approved digest's blob was removed) also fails closed
    /// with the integrity-mismatch RuleId, never silently producing an empty Allow.
    #[test]
    fn firewall_blocks_when_approved_blob_is_missing() {
        let bytes = benign_wheel_bytes();
        let digest = sha256_hex(&bytes);
        let filename = "demo-1.0-py3-none-any.whl";

        let (_root, _store, txn) = store_with_txn("fw-missing");
        // Deliberately do NOT ingest the blob.

        let resolved = ResolvedSet {
            locked_requirements: format!("demo==1.0 \\\n    --hash=sha256:{digest}\n"),
            artifacts: vec![ResolvedArtifact {
                wheel_filename: filename.to_string(),
                sha256: digest.clone(),
            }],
        };

        let outcome = firewall_resolved_set(&resolved, &txn, &Policy::default(), None);

        assert!(outcome.has_integrity_mismatch());
        assert_eq!(
            outcome.integrity_findings[0].rule_id,
            RuleId::ArtifactDownloadIntegrityMismatch
        );
        assert_eq!(outcome.verdict.action, Action::Block);
        assert!(outcome.materialized.is_empty());
    }

    /// A mixed set: one intact wheel and one swapped wheel. The intact one
    /// materialises and is inspected (clean); the swapped one raises the integrity
    /// mismatch. The whole-set verdict blocks (one Critical finding), and exactly
    /// one artifact materialised.
    #[test]
    fn firewall_mixed_set_blocks_only_on_the_tampered_member() {
        let good = benign_wheel("good", "g");
        let good_digest = sha256_hex(&good);
        // A second, byte-distinct benign wheel (distinct outer digest). Its blob is
        // swapped after ingest below, so the inspection never sees these bytes; only
        // its approved digest matters.
        let bad_source = benign_wheel("bad", "b");
        let bad_digest = sha256_hex(&bad_source);

        let (_root, store, txn) = store_with_txn("fw-mixed");
        store.ingest_bytes(&good, &good_digest).unwrap();
        store.ingest_bytes(&bad_source, &bad_digest).unwrap();

        // Swap the SECOND blob's bytes after ingest.
        let bad_blob = store.blob_path(&bad_digest);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            std::fs::set_permissions(&bad_blob, std::fs::Permissions::from_mode(0o600)).unwrap();
        }
        std::fs::write(&bad_blob, b"swapped second-wheel bytes").unwrap();

        let resolved = ResolvedSet {
            locked_requirements: String::new(),
            artifacts: vec![
                ResolvedArtifact {
                    wheel_filename: "good-1.0-py3-none-any.whl".to_string(),
                    sha256: good_digest.clone(),
                },
                ResolvedArtifact {
                    wheel_filename: "bad-1.0-py3-none-any.whl".to_string(),
                    sha256: bad_digest.clone(),
                },
            ],
        };

        let outcome = firewall_resolved_set(&resolved, &txn, &Policy::default(), None);

        assert_eq!(
            outcome.integrity_findings.len(),
            1,
            "only the tampered member fails the re-bind"
        );
        assert_eq!(
            outcome.materialized.len(),
            1,
            "only the intact member materialises"
        );
        assert_eq!(outcome.verdict.action, Action::Block);
    }

    /// The finding's evidence never leaks bytes/secrets: it names the wheel and the
    /// expected/actual digests only. Guards cross-cutting invariant 7 (no secrets in
    /// output) for this rule's evidence text.
    #[test]
    fn integrity_finding_evidence_is_redaction_safe() {
        let artifact = ResolvedArtifact {
            wheel_filename: "demo-1.0-py3-none-any.whl".to_string(),
            sha256: "a".repeat(64),
        };
        let finding = integrity_mismatch_finding(
            &artifact,
            &QuarantineError::DigestMismatch {
                expected: "a".repeat(64),
                actual: "b".repeat(64),
            },
        );
        assert_eq!(finding.rule_id, RuleId::ArtifactDownloadIntegrityMismatch);
        let Evidence::Text { detail } = &finding.evidence[0] else {
            panic!("expected text evidence");
        };
        assert!(detail.contains("demo-1.0-py3-none-any.whl"));
        assert!(detail.contains(&"a".repeat(64)));
        assert!(detail.contains(&"b".repeat(64)));
    }

    /// CR3 fail-closed: a wheel whose blob hash-matches its lock (so it
    /// materialises INTACT, no integrity mismatch) but which is STRUCTURALLY
    /// REJECTED by the hardened reader (a `..` path-traversal member) must Block.
    /// Before the chokepoint fix, `all_findings` ignored `inspected.rejected`, so
    /// `firewall_resolved_set` returned Allow and the install proceeded to extract
    /// the traversal member. Now the synthesized `WheelStructurallyRejected` finding
    /// makes the verdict Block by construction.
    #[test]
    fn firewall_blocks_structurally_rejected_wheel_that_matches_its_lock() {
        // A wheel with a `../etc/passwd` member: read_wheel REJECTS it, but its bytes
        // hash fine, so the quarantine blob materialises intact (no integrity miss).
        let bytes = build_wheel(&[
            ("../etc/passwd", b"root:x:0:0\n"),
            (
                "demo-1.0.dist-info/METADATA",
                b"Metadata-Version: 2.1\nName: demo\nVersion: 1.0\n\n",
            ),
        ]);
        let digest = sha256_hex(&bytes);
        let filename = "demo-1.0-py3-none-any.whl";

        let (_root, store, txn) = store_with_txn("fw-rejected");
        store.ingest_bytes(&bytes, &digest).unwrap();

        let resolved = ResolvedSet {
            locked_requirements: format!("demo==1.0 \\\n    --hash=sha256:{digest}\n"),
            artifacts: vec![ResolvedArtifact {
                wheel_filename: filename.to_string(),
                sha256: digest.clone(),
            }],
        };

        let outcome = firewall_resolved_set(&resolved, &txn, &Policy::default(), None);

        // The blob materialised intact (the rejection is structural, not an integrity
        // mismatch), so the ONLY thing forcing Block is the structural-rejection finding.
        assert!(
            !outcome.has_integrity_mismatch(),
            "a structurally-rejected wheel still hashes to its approved digest"
        );
        assert_eq!(
            outcome.materialized.len(),
            1,
            "the wheel materialises intact"
        );
        assert_eq!(
            outcome.verdict.action,
            Action::Block,
            "a structurally-rejected wheel must Block, not Allow: {:?}",
            outcome.verdict.findings
        );
        assert!(
            outcome
                .verdict
                .findings
                .iter()
                .any(|f| f.rule_id == RuleId::WheelStructurallyRejected),
            "the Block is carried by a WheelStructurallyRejected finding: {:?}",
            outcome
                .verdict
                .findings
                .iter()
                .map(|f| f.rule_id)
                .collect::<Vec<_>>()
        );
    }
}
