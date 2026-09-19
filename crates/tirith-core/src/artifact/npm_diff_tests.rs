use super::*;
use crate::artifact::npm_archive::{
    read_npm_tarball, NpmIssue, NpmIssueKind, NpmLimits, NpmSignalKind,
};

fn base() -> NpmInspection {
    let bytes = include_bytes!("../../tests/fixtures/npm/npm-11.19.0-portable-pax.tgz");
    let inspection = read_npm_tarball(bytes.as_slice(), "fixture.tgz", &NpmLimits::default());
    assert!(inspection.coverage.static_analysis_complete);
    inspection
}

fn changed(old: &NpmInspection) -> NpmInspection {
    let mut new = old.clone();
    new.artifact.sha256 = Some("a".repeat(64));
    new
}

#[test]
fn identical_artifact_is_not_a_release_change_even_when_filename_changes() {
    let old = base();
    let mut new = old.clone();
    new.artifact.filename = "copied-fixture.tgz".to_owned();
    let result = compare_npm_releases(&old, &new).unwrap();
    assert_eq!(result.same_artifact, Some(true));
    assert_eq!(result.state, NpmComparisonState::Comparable);
    assert!(result.deltas.is_empty());
    assert!(result.notes.is_empty());
    assert_eq!(result.old_artifact.sha256, result.new_artifact.sha256);
}

#[test]
fn benign_rebuild_and_minification_preserve_identity_without_inventing_risk() {
    let old = base();
    let mut new = changed(&old);
    let member = new
        .files
        .iter_mut()
        .find(|f| f.path == "package/index.js")
        .unwrap();
    member.sha256 = "b".repeat(64);
    member.size = 25;
    let result = compare_npm_releases(&old, &new).unwrap();
    assert_eq!(result.same_artifact, Some(false));
    assert!(result.capability_comparison_available);
    assert!(
        matches!(result.deltas.as_slice(), [NpmDelta::MemberChanged { path, .. }] if path == "package/index.js")
    );
    assert!(result.current_review_signals.is_empty());
    let repacked = compare_npm_releases(&old, &changed(&old)).unwrap();
    assert_eq!(repacked.same_artifact, Some(false));
    assert!(repacked.deltas.is_empty());
}

#[test]
fn newly_observed_capability_requires_compatible_complete_analysis() {
    let old = base();
    let mut new = changed(&old);
    new.files
        .iter_mut()
        .find(|f| f.path == "package/index.js")
        .unwrap()
        .sha256 = "b".repeat(64);
    new.signals.push(NpmSignal {
        kind: NpmSignalKind::CodeCapabilities,
        level: NpmSignalLevel::Observation,
        member: "package/index.js".to_owned(),
        capabilities: vec![NpmCapability::NetworkAccess],
        lifecycle_events: Vec::new(),
        evidence: "A fetch call pattern is present.".to_owned(),
    });
    let result = compare_npm_releases(&old, &new).unwrap();
    assert!(result.capability_comparison_available);
    assert!(result.deltas.iter().any(|d| matches!(
        d,
        NpmDelta::CapabilityObservationAdded {
            capability: NpmCapability::NetworkAccess,
            ..
        }
    )));
    new.analyzer_version = "npm-static-2".to_owned();
    let result = compare_npm_releases(&old, &new).unwrap();
    assert!(!result.capability_comparison_available);
    assert!(result.notes.contains(&NpmComparisonNote::AnalyzerChanged));
    assert!(!result
        .deltas
        .iter()
        .any(|d| matches!(d, NpmDelta::CapabilityObservationAdded { .. })));
    assert!(result
        .deltas
        .iter()
        .any(|d| matches!(d, NpmDelta::MemberChanged { .. })));
}

#[test]
fn coverage_or_limit_changes_cannot_be_reported_as_new_execution_behavior() {
    let old = base();
    let mut new = changed(&old);
    new.coverage.static_analysis_complete = false;
    new.coverage.issues.push(NpmIssue {
        kind: NpmIssueKind::DynamicCode,
        member: Some("package/index.js".to_owned()),
        detail: "Dynamic code is unresolved.".to_owned(),
    });
    new.signals.push(NpmSignal {
        kind: NpmSignalKind::EncodedDynamicExecution,
        level: NpmSignalLevel::Review,
        member: "package/index.js".to_owned(),
        capabilities: vec![NpmCapability::DynamicEvaluation],
        lifecycle_events: vec!["postinstall".to_owned()],
        evidence: "Encoded dynamic evaluation is observed.".to_owned(),
    });
    let result = compare_npm_releases(&old, &new).unwrap();
    assert!(!result.capability_comparison_available);
    assert!(result.notes.contains(&NpmComparisonNote::CoverageChanged));
    assert!(result
        .notes
        .contains(&NpmComparisonNote::StaticCoverageIncomplete));
    assert_eq!(result.current_review_signals.len(), 1);
    assert!(!result
        .deltas
        .iter()
        .any(|d| matches!(d, NpmDelta::CapabilityObservationAdded { .. })));
    let mut new = changed(&old);
    new.limits.code_member_bytes /= 2;
    let result = compare_npm_releases(&old, &new).unwrap();
    assert!(!result.capability_comparison_available);
    assert!(result.notes.contains(&NpmComparisonNote::LimitsChanged));
}

#[test]
fn scripts_native_members_and_command_entry_changes_remain_direct_byte_evidence() {
    let old = base();
    let mut new = changed(&old);
    let metadata = new.metadata.as_mut().unwrap();
    metadata
        .scripts
        .insert("postinstall".to_owned(), "node changed.js".to_owned());
    metadata
        .scripts
        .insert("preinstall".to_owned(), "node before.js".to_owned());
    metadata
        .bin
        .insert("fixture".to_owned(), "bin/main.js".to_owned());
    metadata.main = Some("new-entry.js".to_owned());
    metadata.implicit_node_gyp_install = true;
    new.files.push(NpmFile {
        path: "package/addon.node".to_owned(),
        size: 64,
        sha256: "b".repeat(64),
        executable: false,
        kind: NpmFileKind::Native,
    });
    let result = compare_npm_releases(&old, &new).unwrap();
    assert!(result.deltas.iter().any(
        |d| matches!(d, NpmDelta::DeclaredScriptChanged { event, .. } if event == "postinstall")
    ));
    assert!(result.deltas.iter().any(
        |d| matches!(d, NpmDelta::DeclaredScriptAdded { event, .. } if event == "preinstall")
    ));
    assert!(result
        .deltas
        .iter()
        .any(|d| matches!(d, NpmDelta::MemberAdded { file } if file.kind == NpmFileKind::Native)));
    assert!(result
        .deltas
        .iter()
        .any(|d| matches!(d, NpmDelta::CommandLineEntryChanged { .. })));
    assert!(result
        .deltas
        .iter()
        .any(|d| matches!(d, NpmDelta::MainEntryChanged { .. })));
    assert!(result
        .deltas
        .iter()
        .any(|d| matches!(d, NpmDelta::ImplicitNativeBuildChanged { .. })));
}

#[test]
fn unchanged_transport_with_changed_analysis_never_emits_package_deltas() {
    let old = base();
    let mut new = old.clone();
    new.analyzer_version = "npm-static-next".to_owned();
    new.files[0].kind = NpmFileKind::OtherCode;
    let result = compare_npm_releases(&old, &new).unwrap();
    assert_eq!(result.same_artifact, Some(true));
    assert!(result.deltas.is_empty());
    assert!(!result.capability_comparison_available);
    assert!(result
        .notes
        .contains(&NpmComparisonNote::SameArtifactDifferentEvidence));
    assert!(result.notes.contains(&NpmComparisonNote::AnalyzerChanged));
}

#[test]
fn incomplete_or_unknown_schema_inputs_cannot_claim_a_complete_release_comparison() {
    let old = base();
    let mut new = changed(&old);
    new.schema_version += 1;
    let result = compare_npm_releases(&old, &new).unwrap();
    assert_eq!(result.state, NpmComparisonState::Unavailable);
    assert!(result.notes.contains(&NpmComparisonNote::UnsupportedSchema));
    assert!(result.deltas.is_empty());
    let mut new = changed(&old);
    new.artifact.sha256 = None;
    let result = compare_npm_releases(&old, &new).unwrap();
    assert_eq!(result.same_artifact, None);
    assert_eq!(result.state, NpmComparisonState::Unavailable);
    let mut new = changed(&old);
    new.archive_state = NpmArchiveState::Refused;
    new.coverage.archive_complete = false;
    new.coverage.metadata_complete = false;
    new.coverage.static_analysis_complete = false;
    let result = compare_npm_releases(&old, &new).unwrap();
    assert_eq!(result.state, NpmComparisonState::Unavailable);
    assert!(result
        .notes
        .contains(&NpmComparisonNote::ArchiveCoverageIncomplete));
}

#[test]
fn name_changes_are_labelled_and_delta_outputs_are_bounded() {
    let old = base();
    let mut new = changed(&old);
    new.artifact.name = Some("another-package".to_owned());
    new.metadata.as_mut().unwrap().name = "another-package".to_owned();
    for index in 0..250 {
        new.files.push(NpmFile {
            path: format!("package/generated-{index}.js"),
            size: 0,
            sha256: "b".repeat(64),
            executable: false,
            kind: NpmFileKind::JavaScript,
        });
    }
    let result = compare_npm_releases(&old, &new).unwrap();
    assert!(result
        .notes
        .contains(&NpmComparisonNote::DeclaredPackageNameChanged));
    assert!(!result.capability_comparison_available);
    assert_eq!(result.deltas.len(), NPM_COMPARISON_MAX_DELTAS);
    assert!(result.omitted_deltas > 0);
    assert!(result.notes.contains(&NpmComparisonNote::DeltaOutputLimit));
    assert!(matches!(
        result.deltas[0],
        NpmDelta::DeclaredIdentityChanged { .. }
    ));
    let json = serde_json::to_string(&result).unwrap();
    let parsed: NpmComparison = serde_json::from_str(&json).unwrap();
    assert_eq!(parsed, result);
    new.files[0].path = "x".repeat(8192);
    assert!(compare_npm_releases(&old, &new).is_err());
}
