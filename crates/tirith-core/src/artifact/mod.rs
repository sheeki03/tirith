//! The artifact inspection model: a reusable, policy-independent description of
//! WHAT a package artifact is, WHICH files it carries, WHAT execution it can
//! trigger, and HOW completely it was inspected. Policy evaluation is a separate
//! seam ([`evaluate_artifact`]) so the same inspection can be re-evaluated under
//! different policies without re-reading the bytes.
//!
//! This module (PR A3) holds only the data model and the evaluation seam; the
//! analyzers that POPULATE it (archive reader, RECORD verifier, `.pth`/startup
//! analysis, native triage) land in later PRs (A4, B5 to B8). It is deliberately
//! free of any I/O.
//!
//! # Subject vs identity vs signal vs finding
//!
//! The model keeps four concerns separate, because conflating them is what the
//! current command-string gate cannot do:
//!
//! * An [`InspectionSubject`] names WHAT was inspected (a wheel with a known
//!   sha256, an installed distribution with no source-wheel hash to invent, a
//!   generic archive, or a single installed file). The subject does not invent a
//!   hash it does not have.
//! * An [`ArtifactSignal`] is a granular, policy-independent OBSERVATION (a
//!   `.pth` line spawns a subprocess; a RECORD hash does not match). Many signals
//!   correlate (in B5 to B8) into one user-facing finding; the signals are the
//!   evidence, not findings themselves, and carry no [`crate::verdict::RuleId`].
//! * An [`ExecutionEdge`] records a "this triggers that" relationship (a startup
//!   hook imports a module owned by another distribution), the mechanism by which
//!   one location can cause code in another to run.
//! * A [`crate::verdict::Verdict`] is the POLICY decision, produced only by
//!   [`evaluate_artifact`], never stored on the inspection.
//!
//! All locations use [`SubjectLocation`] (introduced in A2), so a coverage gap,
//! an artifact file, a signal, and an execution edge all render the same
//! `foo.whl!/pkg/file` archive-member notation.
//!
//! # Coverage is one concept
//!
//! [`InspectionCoverage`] reuses A2's [`crate::scan::CoverageGap`] rather than
//! forking a parallel "artifact gap" type, so "what did we not look at" has a
//! single representation across the scanner and the artifact model. A4 may extend
//! [`crate::scan::CoverageGapKind`] for archive specifics; this module does not
//! introduce a competing gap kind.
//!
//! # Serialization
//!
//! The whole model is serde-round-trippable and schema-versioned
//! ([`ArtifactInspection::schema_version`], [`ARTIFACT_SCHEMA_VERSION`]) so a
//! persisted or transported inspection can be validated against the version that
//! wrote it. [`crate::threatdb::Ecosystem`] has no serde derive (its
//! discriminants are an on-disk DB format, deliberately decoupled from JSON), so
//! [`ArtifactIdentity`] serializes its ecosystem through the same small helper
//! `ecosystem_scan` uses for its dependency model.

use serde::{Deserialize, Serialize};

use crate::location::SubjectLocation;
use crate::policy::Policy;
use crate::scan::CoverageGap;
use crate::threatdb::{Ecosystem, ThreatDb};
use crate::verdict::{Finding, Timings, Verdict};

/// The hardened, streaming, wheel-only ZIP reader (PR A4). Separates hard
/// structural violations from coverage limits and hands native members to B7.
pub mod archive;

/// Pure parsers for a distribution's `.dist-info` metadata files (PR B5):
/// METADATA, WHEEL, entry_points.txt, direct_url.json, and RECORD. No I/O.
pub mod wheel;

/// Wheel-RECORD (strict) and installed-RECORD (lax) integrity verification plus
/// the duplicate-aware cross-distribution ownership index (PR B5).
pub mod record;

/// Schema version for the serialized [`ArtifactInspection`]. Bump when the wire
/// shape changes incompatibly; a consumer calls
/// [`ArtifactInspection::check_schema`] before trusting a deserialized value.
pub const ARTIFACT_SCHEMA_VERSION: u32 = 1;

/// WHAT was inspected. The subject is separated from per-file detail and from
/// any policy decision: it identifies the thing, nothing more.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
// `tag = "kind"` (not "subject"): this enum is itself the value of the `subject`
// field on `ArtifactInspection`, so tagging it "subject" produced a confusing
// `{"subject":{"subject":...}}` wire shape. `kind` matches the house convention used
// by the other tagged enums in this crate.
#[serde(rename_all = "snake_case", tag = "kind", content = "identity")]
pub enum InspectionSubject {
    /// A distributable artifact (a wheel or sdist) with a known content hash.
    Artifact(ArtifactIdentity),
    /// An installed distribution discovered in a site-packages tree. No source
    /// wheel hash is invented, because the installed bytes are not the artifact
    /// bytes.
    InstalledDistribution(DistributionIdentity),
    /// An archive that is not a recognized package artifact (a plain `.zip`).
    GenericArchive(GenericArchiveIdentity),
    /// A single installed file inspected on its own (a `.pth`, a
    /// `sitecustomize.py`), not owned through a distribution's RECORD.
    InstalledFile(InstalledFileIdentity),
}

/// Identity of a distributable artifact: the ecosystem, the distribution
/// name/version, the filename, and the content hash that makes it exact.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ArtifactIdentity {
    /// The packaging ecosystem the artifact belongs to. Serialized through a
    /// helper because [`Ecosystem`] has no serde derive.
    #[serde(
        serialize_with = "serialize_ecosystem",
        deserialize_with = "deserialize_ecosystem"
    )]
    pub ecosystem: Ecosystem,
    /// The distribution (project) name as the artifact declares it.
    pub name: String,
    /// The version string, if the artifact names one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    /// The on-disk artifact filename (e.g. `foo-1.0-py3-none-any.whl`).
    pub filename: String,
    /// The whole-artifact SHA-256 (lowercase hex). Present because an artifact,
    /// unlike an installed distribution, has exact bytes.
    pub sha256: String,
}

/// Identity of an INSTALLED distribution. Distinct from [`ArtifactIdentity`] in
/// that it carries no source-artifact hash: the installed files are not the
/// distributed artifact, so no hash is fabricated.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DistributionIdentity {
    /// The packaging ecosystem.
    #[serde(
        serialize_with = "serialize_ecosystem",
        deserialize_with = "deserialize_ecosystem"
    )]
    pub ecosystem: Ecosystem,
    /// The distribution (project) name.
    pub name: String,
    /// The installed version, if resolvable from `.dist-info`/metadata.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    /// The on-disk `.dist-info` (or equivalent) directory backing this install.
    pub dist_info_path: SubjectLocation,
}

/// Identity of a generic (non-package) archive, identified only by its filename
/// and content hash.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GenericArchiveIdentity {
    /// The on-disk archive filename.
    pub filename: String,
    /// The whole-archive SHA-256 (lowercase hex).
    pub sha256: String,
}

/// Identity of a single installed file inspected on its own.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InstalledFileIdentity {
    /// Where the file lives.
    pub location: SubjectLocation,
    /// The file's SHA-256 (lowercase hex), when it was hashed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sha256: Option<String>,
}

/// A complete inspection of one subject: its files, the policy-independent
/// signals observed, the execution edges between locations, and how completely
/// it was covered.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ArtifactInspection {
    /// The wire schema version. Defaults to [`ARTIFACT_SCHEMA_VERSION`] when
    /// constructed via [`ArtifactInspection::new`] and on deserialization of an
    /// older value that omitted it.
    #[serde(default = "default_schema_version")]
    pub schema_version: u32,
    /// WHAT was inspected.
    pub subject: InspectionSubject,
    /// The files the subject carries (members, installed files).
    #[serde(default)]
    pub files: Vec<ArtifactFile>,
    /// Granular, policy-independent observations. The analyzers (B5 to B8)
    /// populate these; A3 ships the model empty.
    #[serde(default)]
    pub signals: Vec<ArtifactSignal>,
    /// "This triggers that" relationships between locations.
    #[serde(default)]
    pub execution_edges: Vec<ExecutionEdge>,
    /// How completely the subject was inspected.
    #[serde(default)]
    pub coverage: InspectionCoverage,
}

impl ArtifactInspection {
    /// A new inspection of `subject` with no files/signals/edges and full
    /// coverage, stamped with the current [`ARTIFACT_SCHEMA_VERSION`].
    pub fn new(subject: InspectionSubject) -> Self {
        Self {
            schema_version: ARTIFACT_SCHEMA_VERSION,
            subject,
            files: Vec::new(),
            signals: Vec::new(),
            execution_edges: Vec::new(),
            coverage: InspectionCoverage::default(),
        }
    }

    /// Validate the deserialized schema version against what this build can read.
    /// A consumer MUST call this before trusting a transported or persisted
    /// inspection: a value stamped newer than [`ARTIFACT_SCHEMA_VERSION`] may carry
    /// fields this build cannot interpret, so it is rejected rather than trusted.
    ///
    /// No load path deserializes an inspection from an untrusted source in this
    /// milestone (every deserialize site is a test), so this guard has no caller
    /// yet; it is the contract a future transport or persistence boundary must use.
    pub fn check_schema(&self) -> Result<(), String> {
        if self.schema_version > ARTIFACT_SCHEMA_VERSION {
            return Err(format!(
                "artifact inspection schema_version {} is newer than supported {}",
                self.schema_version, ARTIFACT_SCHEMA_VERSION
            ));
        }
        Ok(())
    }
}

/// A granular, policy-independent observation about a subject. Correlation (in
/// B5 to B8) maps a SET of these into one user-facing finding; on its own a
/// signal carries no [`crate::verdict::RuleId`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ArtifactSignal {
    /// What was observed.
    pub kind: ArtifactSignalKind,
    /// Where it was observed.
    pub location: SubjectLocation,
    /// Human-readable supporting detail (the offending `.pth` line, the
    /// mismatching hash pair). Carried into a correlated finding's evidence.
    pub evidence: String,
    /// How strongly the observation supports the inference it feeds.
    pub confidence: EdgeConfidence,
}

/// A "this can cause code in that to run" relationship between two locations.
/// The analyzers emit these; B5 to B8 correlate them (cross-distribution loads,
/// native-import chains) into findings, attaching a finding to the loader while
/// naming the payload.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExecutionEdge {
    /// The location whose execution begins the edge (the loader/trigger site).
    pub from: SubjectLocation,
    /// The mechanism class by which `from` triggers `to`.
    pub trigger: ExecutionTrigger,
    /// The location that gets executed as a result (the payload site).
    pub to: SubjectLocation,
    /// Human-readable detail of the concrete mechanism (the import line, the
    /// resolved module name, the launched runtime).
    pub mechanism: String,
    /// How strongly the evidence supports the edge actually executing.
    pub confidence: EdgeConfidence,
}

/// How strongly a signal or edge is supported. DISTINCT from
/// [`crate::threatdb::Confidence`]: that grades threat-intel match certainty
/// (Low/Medium/Confirmed) for the threat DB, while this grades the strength of a
/// LOCAL structural inference and is not interchangeable with it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EdgeConfidence {
    /// Weak: the observation is suggestive but easily benign.
    Low,
    /// Moderate: the observation is unusual and warrants correlation.
    Medium,
    /// Strong: the observation is hard to explain benignly.
    High,
}

/// The class of mechanism by which one location triggers execution in another.
/// Generic on purpose (the rules must not over-fit to specific payload
/// filenames), with the concrete detail carried in [`ExecutionEdge::mechanism`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExecutionTrigger {
    /// A packaging install script (`setup.py`, a postinstall hook) runs at
    /// install time.
    InstallScript,
    /// A `.pth` `import` line runs at interpreter start.
    PythonStartupPth,
    /// A Python 3.15 `.start` entry-point file runs at interpreter start.
    PythonStartupEntryPoint,
    /// `sitecustomize.py` / `usercustomize.py` runs at interpreter start.
    PythonSiteCustomize,
    /// A normal `import` runs the imported module's top-level code.
    PythonImport,
    /// A native module's initializer (`PyInit_*`, a constructor, TLS/DllMain)
    /// runs on load.
    NativeModuleInit,
    /// A console-script entry point runs when invoked.
    ConsoleEntryPoint,
    /// A shell command is invoked.
    ShellInvocation,
    /// Code downloads further payload at runtime.
    RuntimeDownload,
    /// One runtime launches a different runtime (Python launching Bun/Node/Deno).
    CrossRuntimeInvocation,
}

/// The granular observation an [`ArtifactSignal`] records. Each variant is one
/// thing an analyzer can notice; correlation upstream decides which combinations
/// become a finding. These are NOT [`crate::verdict::RuleId`]s.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ArtifactSignalKind {
    /// A `.pth` line begins with `import ` and so executes at startup.
    PthExecutableLine,
    /// A `.pth`/startup line performs a network download.
    PthNetworkDownload,
    /// A `.pth`/startup line spawns a subprocess.
    PthSubprocessSpawn,
    /// A `.pth`/startup line manipulates `sys.path` search order.
    PthSysPathSearch,
    /// A `.pth` line inserts an untrusted (world/user-writable, `/tmp`,
    /// relative-traversal, network) path ahead of trusted imports.
    PthUntrustedPathAddition,
    /// A startup hook's executable content is obfuscated.
    StartupHookObfuscated,
    /// A RECORD entry's recorded hash does not match the file on disk.
    RecordHashMismatch,
    /// A file RECORD lists is missing from the install.
    RecordMissingFile,
    /// An installed file is not listed in any owning distribution's RECORD.
    UnlistedInstalledFile,
    /// A single normalized installed path is owned by more than one
    /// distribution.
    DuplicateOwnedFile,
    /// A `sitecustomize.py`/`usercustomize.py` is present but owned by no
    /// distribution's RECORD.
    SitecustomizeUnowned,
    /// An editable install could not be verified against its target.
    EditableInstallUnverified,
    /// A native module exposes a direct execution entry (`PyInit_*`, a
    /// constructor, TLS/DllMain).
    NativeExecutionEntry,
    /// A native module exhibits a danger capability (process spawn, runtime
    /// loader, downloader/network, dynamic code loading).
    NativeDangerCapability,
    /// Corroborating evidence for a native chain (an external runtime name, a
    /// sibling script/payload reference, a sensitive path, a known indicator).
    NativeCorroboration,
}

/// A file the subject carries, with its location, size, content hash, and a
/// coarse kind used by correlation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ArtifactFile {
    /// Where the file lives (an archive member or an installed path).
    pub location: SubjectLocation,
    /// The file's uncompressed size in bytes.
    pub size: u64,
    /// The file's SHA-256 (lowercase hex).
    pub sha256: String,
    /// A coarse classification driving correlation.
    pub kind: ArtifactFileKind,
}

/// A coarse classification of an [`ArtifactFile`], enough for correlation to
/// reason about ("is this a startup hook?", "is this native code?") without
/// re-sniffing. A `.pth` is its OWN kind ([`ArtifactFileKind::PthFile`]) and is
/// never folded into a binary-blob bucket.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ArtifactFileKind {
    /// `.dist-info`/`.egg-info` metadata (METADATA, WHEEL, RECORD, entry_points).
    DistInfoMetadata,
    /// A `.pth` startup-path file.
    PthFile,
    /// A Python 3.15 `.start` entry-point file.
    StartFile,
    /// A `sitecustomize.py`/`usercustomize.py` startup hook.
    SiteCustomize,
    /// A Python source file (`.py`).
    PythonSource,
    /// A native extension/shared object (`.so`/`.dylib`/`.pyd`/`.node`).
    NativeModule,
    /// A WebAssembly module (`.wasm`).
    WasmModule,
    /// A script (shell, batch, PowerShell) bundled in the artifact.
    Script,
    /// Anything else (data, docs, media).
    Other,
}

/// How completely a subject was inspected. Reuses A2's [`CoverageGap`] so there
/// is one coverage concept across the scanner and the artifact model.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct InspectionCoverage {
    /// How many archive members / installed files were actually inspected.
    pub members_inspected: usize,
    /// How many were present in total (so `members_inspected < members_total`
    /// means the inspection is incomplete even before reading `gaps`).
    pub members_total: usize,
    /// The specific members/files that were not fully analyzed, each with its
    /// reason. Empty means full coverage.
    #[serde(default)]
    pub gaps: Vec<CoverageGap>,
}

impl InspectionCoverage {
    /// Whether every member was inspected and no gap was recorded.
    ///
    /// A default (`0`/`0`) coverage reports complete BY CONSTRUCTION: an unmeasured
    /// skeleton has no gaps and `0 == 0`, matching `new()`'s "full coverage until an
    /// analyzer records otherwise" contract. Analyzers set real totals before relying
    /// on this, so it is not "vacuously true" in any path that actually consults it.
    pub fn is_complete(&self) -> bool {
        debug_assert!(
            self.members_inspected <= self.members_total,
            "InspectionCoverage inconsistent: members_inspected {} > members_total {}",
            self.members_inspected,
            self.members_total
        );
        // `==` rather than `>=`: members_inspected can never legitimately exceed
        // members_total, so an inconsistent (forged) count returns not-complete in
        // release builds instead of silently passing, while the debug_assert above
        // surfaces it loudly in tests.
        self.gaps.is_empty() && self.members_inspected == self.members_total
    }
}

/// Evaluate an inspection under a policy, producing a [`Verdict`]. This is the
/// policy seam: it is separate from inspection so the same (cacheable)
/// [`ArtifactInspection`] can be re-evaluated under a permissive vs a strict
/// policy without re-reading bytes.
///
/// It routes through [`crate::escalation::finalize_static_verdict`] so per-rule
/// severity overrides and `action_overrides` are honored at this verdict site,
/// exactly like `ecosystem_scan` (cross-cutting invariant 5).
///
/// In A3 there are no analyzers and no artifact-specific
/// [`crate::verdict::RuleId`]s yet, so the signal-to-finding correlation is a
/// skeleton: it produces no findings. The real correlation (and the
/// artifact RuleIds it emits) lands with the analyzers in B5 to B8. The
/// `threat_db` is threaded now so later PRs can resolve hashes/names without a
/// signature change.
pub fn evaluate_artifact(
    inspection: &ArtifactInspection,
    policy: &Policy,
    threat_db: Option<&ThreatDb>,
) -> Verdict {
    let findings = correlate_findings(inspection, threat_db);
    // Artifact/scan-path verdicts are tier-3 by construction (they never run the
    // tier-1 command gate); timings are not measured on this seam.
    crate::escalation::finalize_static_verdict(findings, policy, 3, Timings::default())
}

/// Correlate the inspection's signals/edges into user-facing findings.
///
/// A3 skeleton: returns no findings. B5 to B8 replace this with the real
/// correlation that maps signal sets to the artifact RuleIds. Kept as a named
/// seam (rather than inlined into [`evaluate_artifact`]) so the analyzers extend
/// one place and `evaluate_artifact` stays the stable policy boundary.
fn correlate_findings(
    _inspection: &ArtifactInspection,
    _threat_db: Option<&ThreatDb>,
) -> Vec<Finding> {
    Vec::new()
}

/// Serialize an [`Ecosystem`] as its lowercase name, mirroring
/// `ecosystem_scan::serialize_ecosystem` so the two models agree on the wire
/// string (and because [`Ecosystem`] has no serde derive of its own).
fn serialize_ecosystem<S: serde::Serializer>(eco: &Ecosystem, s: S) -> Result<S::Ok, S::Error> {
    s.serialize_str(&eco.to_string())
}

/// Deserialize an [`Ecosystem`] from the name produced by [`serialize_ecosystem`]
/// (case-insensitive, with the same aliases [`Ecosystem::from_name`] accepts).
fn deserialize_ecosystem<'de, D: serde::Deserializer<'de>>(d: D) -> Result<Ecosystem, D::Error> {
    let s = String::deserialize(d)?;
    Ecosystem::from_name(&s)
        .ok_or_else(|| serde::de::Error::custom(format!("unknown ecosystem: {s}")))
}

/// The default schema version for serde, so a value written before
/// `schema_version` existed (or one that omits it) deserializes as v1.
fn default_schema_version() -> u32 {
    // Hardcoded to 1 (the version when `schema_version` was introduced), NOT
    // `ARTIFACT_SCHEMA_VERSION`: additive versioning means a JSON value that OMITS the
    // field is legacy v1 data and must default to 1 even after the constant is bumped.
    // Returning the live constant would silently relabel old data as the new version.
    1
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::Policy;
    use crate::verdict::{Action, Evidence, RuleId, Severity};

    /// A subject of each variant, round-tripping through serde, to lock the
    /// tagged-enum wire shape and the ecosystem serde helpers.
    fn artifact_subject() -> InspectionSubject {
        InspectionSubject::Artifact(ArtifactIdentity {
            ecosystem: Ecosystem::PyPI,
            name: "demo".to_string(),
            version: Some("1.2.3".to_string()),
            filename: "demo-1.2.3-py3-none-any.whl".to_string(),
            sha256: "a".repeat(64),
        })
    }

    #[test]
    fn round_trips_artifact_subject() {
        let inspection = ArtifactInspection::new(artifact_subject());
        let json = serde_json::to_string(&inspection).unwrap();
        let back: ArtifactInspection = serde_json::from_str(&json).unwrap();
        assert_eq!(back, inspection);
        assert_eq!(back.schema_version, ARTIFACT_SCHEMA_VERSION);
    }

    #[test]
    fn round_trips_installed_distribution_subject() {
        let subject = InspectionSubject::InstalledDistribution(DistributionIdentity {
            ecosystem: Ecosystem::PyPI,
            name: "demo".to_string(),
            version: Some("1.2.3".to_string()),
            dist_info_path: SubjectLocation::installed(
                "/venv/lib/site-packages/demo-1.2.3.dist-info",
            ),
        });
        let inspection = ArtifactInspection::new(subject);
        let json = serde_json::to_string(&inspection).unwrap();
        let back: ArtifactInspection = serde_json::from_str(&json).unwrap();
        assert_eq!(back, inspection);
    }

    #[test]
    fn round_trips_generic_archive_subject() {
        let subject = InspectionSubject::GenericArchive(GenericArchiveIdentity {
            filename: "bundle.zip".to_string(),
            sha256: "b".repeat(64),
        });
        let inspection = ArtifactInspection::new(subject);
        let json = serde_json::to_string(&inspection).unwrap();
        let back: ArtifactInspection = serde_json::from_str(&json).unwrap();
        assert_eq!(back, inspection);
    }

    #[test]
    fn round_trips_installed_file_subject() {
        let subject = InspectionSubject::InstalledFile(InstalledFileIdentity {
            location: SubjectLocation::installed("/venv/lib/site-packages/__editable__.pth"),
            sha256: None,
        });
        let inspection = ArtifactInspection::new(subject);
        let json = serde_json::to_string(&inspection).unwrap();
        let back: ArtifactInspection = serde_json::from_str(&json).unwrap();
        assert_eq!(back, inspection);
    }

    /// A fully populated inspection (files, signals, edges, coverage gaps)
    /// round-trips, exercising every nested type's serde including the reused
    /// `CoverageGap`.
    #[test]
    fn round_trips_fully_populated_inspection() {
        let mut inspection = ArtifactInspection::new(artifact_subject());
        inspection.files.push(ArtifactFile {
            location: SubjectLocation::member("demo-1.2.3-py3-none-any.whl", "demo/bootstrap.pth"),
            size: 42,
            sha256: "c".repeat(64),
            kind: ArtifactFileKind::PthFile,
        });
        inspection.signals.push(ArtifactSignal {
            kind: ArtifactSignalKind::PthSubprocessSpawn,
            location: SubjectLocation::member("demo-1.2.3-py3-none-any.whl", "demo/bootstrap.pth"),
            evidence: "import os; os.system('curl evil')".to_string(),
            confidence: EdgeConfidence::High,
        });
        inspection.execution_edges.push(ExecutionEdge {
            from: SubjectLocation::member("demo-1.2.3-py3-none-any.whl", "demo/bootstrap.pth"),
            trigger: ExecutionTrigger::PythonStartupPth,
            to: SubjectLocation::member("other-2.0.whl", "payload/run.js"),
            mechanism: "sys.path search then import".to_string(),
            confidence: EdgeConfidence::Medium,
        });
        inspection.coverage = InspectionCoverage {
            members_inspected: 3,
            members_total: 4,
            gaps: vec![CoverageGap {
                location: SubjectLocation::member("demo-1.2.3-py3-none-any.whl", "big.bin"),
                kind: crate::scan::CoverageGapKind::Oversized,
                sha256: Some("d".repeat(64)),
            }],
        };

        let json = serde_json::to_string(&inspection).unwrap();
        let back: ArtifactInspection = serde_json::from_str(&json).unwrap();
        assert_eq!(back, inspection);
        assert!(!back.coverage.is_complete());
    }

    /// The reused location renders an archive member as `foo.whl!/pkg/file`,
    /// confirming A3 inherits A2's render contract rather than inventing one.
    #[test]
    fn subject_location_renders_archive_member() {
        let loc = SubjectLocation::member("foo.whl", "pkg/file");
        assert_eq!(loc.to_string(), "foo.whl!/pkg/file");
    }

    /// An unknown ecosystem name is a deserialization error, not a silent
    /// wrong-ecosystem fallback.
    #[test]
    fn unknown_ecosystem_fails_to_deserialize() {
        let json = r#"{"kind":"artifact","identity":{"ecosystem":"not-a-real-ecosystem","name":"x","filename":"x.whl","sha256":"00"}}"#;
        assert!(serde_json::from_str::<InspectionSubject>(json).is_err());
    }

    /// The `InspectionSubject` tag serializes as `kind` (not `subject`), so the wire
    /// shape is `{"subject":{"kind":...}}`, not the confusing `{"subject":{"subject"`.
    #[test]
    fn serialized_subject_uses_kind_tag() {
        let json = r#"{"kind":"generic_archive","identity":{"filename":"x.zip","sha256":"00"}}"#;
        let subject: InspectionSubject = serde_json::from_str(json).unwrap();
        let back = serde_json::to_string(&subject).unwrap();
        assert!(
            back.contains(r#""kind":"generic_archive""#),
            "tag must serialize as `kind`: {back}"
        );
        assert!(
            !back.contains(r#""subject""#),
            "the enum tag must not be `subject`: {back}"
        );
    }

    /// A default (0/0) coverage is complete BY CONSTRUCTION (the documented contract,
    /// so the 0/0 case is not later mistaken for a bug).
    #[test]
    fn default_coverage_is_complete_by_construction() {
        let cov = InspectionCoverage {
            members_inspected: 0,
            members_total: 0,
            gaps: Vec::new(),
        };
        assert!(cov.is_complete());
    }

    /// A value written before `schema_version` existed (it is absent from the
    /// JSON) deserializes with the default version, so the field is additive.
    #[test]
    fn missing_schema_version_defaults() {
        // The `subject` field wraps the adjacently-tagged `InspectionSubject`,
        // and `schema_version` is omitted entirely so the serde default fills it.
        let json = r#"{"subject":{"kind":"generic_archive","identity":{"filename":"x.zip","sha256":"00"}}}"#;
        let back: ArtifactInspection = serde_json::from_str(json).unwrap();
        // Must be the hardcoded baseline 1, NOT ARTIFACT_SCHEMA_VERSION: this locks the
        // default so a future schema bump cannot silently relabel legacy JSON as new.
        assert_eq!(back.schema_version, 1);
    }

    /// A schema_version newer than this build understands is rejected by
    /// check_schema (the guard the module doc promises), so a forward-incompatible
    /// inspection is not silently trusted; the current version validates.
    #[test]
    fn inspection_rejects_unknown_schema_version() {
        let newer = r#"{"schema_version":999,"subject":{"kind":"generic_archive","identity":{"filename":"x.zip","sha256":"00"}}}"#;
        let bad: ArtifactInspection = serde_json::from_str(newer).unwrap();
        assert!(bad.check_schema().is_err());

        let current = r#"{"subject":{"kind":"generic_archive","identity":{"filename":"x.zip","sha256":"00"}}}"#;
        let good: ArtifactInspection = serde_json::from_str(current).unwrap();
        assert!(good.check_schema().is_ok());
    }

    /// An inspection claiming more inspected members than exist is internally
    /// inconsistent; is_complete debug-asserts that invariant. Gated to debug builds:
    /// `debug_assert!` is a no-op under `--release`, so without this the
    /// `#[should_panic]` test would fail (no panic) in a release test run.
    #[test]
    #[cfg(debug_assertions)]
    #[should_panic(expected = "inconsistent")]
    fn inspection_coverage_rejects_inconsistent_counters() {
        let cov = InspectionCoverage {
            members_inspected: 5,
            members_total: 4,
            gaps: Vec::new(),
        };
        let _ = cov.is_complete();
    }

    /// A synthetic Medium finding (the kind the analyzers will emit) is a Warn
    /// under a permissive policy but a Block under a policy whose
    /// `action_overrides` upgrade it. Drives the `evaluate_artifact` ->
    /// `finalize_static_verdict` seam with a real (non-artifact) RuleId so A3
    /// adds none of its own.
    #[test]
    fn identical_signals_differ_by_policy() {
        // The skeleton correlator produces no findings, so to exercise the policy
        // seam we feed `finalize_static_verdict` (the same helper
        // `evaluate_artifact` calls) a synthetic finding directly. This keeps A3
        // from inventing an artifact RuleId solely for a test.
        let finding = Finding {
            // A pre-existing Medium-severity RuleId; not an artifact rule.
            rule_id: RuleId::ThreatUnresolvedMaliciousPackage,
            severity: Severity::Medium,
            title: "synthetic".to_string(),
            description: "synthetic medium finding".to_string(),
            evidence: vec![Evidence::Text {
                detail: "for policy-sensitivity test".to_string(),
            }],
            human_view: None,
            agent_view: None,
            mitre_id: None,
            custom_rule_id: None,
        };

        // Permissive: default action derivation. Medium -> Warn.
        let permissive = Policy::default();
        let permissive_verdict = crate::escalation::finalize_static_verdict(
            vec![finding.clone()],
            &permissive,
            3,
            Timings::default(),
        );
        assert_eq!(permissive_verdict.action, Action::Warn);

        // Strict: an action override forces this rule to Block. The override map
        // is keyed by the rule's `Display` form (its snake_case serde name) with
        // a `"block"` string value, matching `apply_action_overrides`.
        let mut strict = Policy::default();
        strict.action_overrides.insert(
            RuleId::ThreatUnresolvedMaliciousPackage.to_string(),
            "block".to_string(),
        );
        let strict_verdict = crate::escalation::finalize_static_verdict(
            vec![finding],
            &strict,
            3,
            Timings::default(),
        );
        assert_eq!(strict_verdict.action, Action::Block);

        // Same finding set, different policy, different verdict: the seam works.
        assert_ne!(permissive_verdict.action, strict_verdict.action);
    }

    /// `evaluate_artifact` itself produces an Allow on the A3 skeleton (no
    /// analyzers, no findings) and routes through the policy helper.
    #[test]
    fn evaluate_artifact_skeleton_is_allow() {
        let inspection = ArtifactInspection::new(artifact_subject());
        let verdict = evaluate_artifact(&inspection, &Policy::default(), None);
        assert_eq!(verdict.action, Action::Allow);
        assert!(verdict.findings.is_empty());
        assert_eq!(verdict.tier_reached, 3);
    }
}
