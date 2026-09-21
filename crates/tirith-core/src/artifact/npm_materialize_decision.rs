//! Non-serializable artifact decision over exact retained input and source bytes.
//! Task authorization is an additional boundary, never a substitute for this
//! policy/static/hash decision. No caller report or generation string is accepted.
use super::*;
use crate::threatdb::materialization_source::{MaterializationThreatSource, SourceRefusal};
use crate::threatdb::{Confidence, Ecosystem, PackageThreatAssessment};
use crate::verdict::{Action, Evidence, Finding, RuleId, Severity, Timings};

pub(super) struct MaterializationDecision {
    source: MaterializationThreatSource,
    decision_digest: String,
}
impl MaterializationDecision {
    pub(super) fn capture(
        artifacts: &[VerifiedNpmArtifact],
        policy: &EffectivePolicySnapshot,
        source: MaterializationThreatSource,
    ) -> MaterializationResult<Self> {
        source.revalidate(true).map_err(source_error)?;
        let findings = findings(artifacts, source.db())?;
        let verdict = crate::escalation::finalize_static_verdict(
            findings,
            &policy.policy,
            3,
            Timings::default(),
        );
        // This initial contract does not mint an implicit acknowledgement for
        // warnings. The caller may inspect evidence separately; no filesystem
        // authority is issued unless the effective policy finalizes Allow.
        if verdict.action != Action::Allow {
            return Err(Refusal::ArtifactPolicyRefused);
        }
        let decision_digest = digest(
            crate::audit::canonical_json_for_hash(&serde_json::json!({
                "schema":1,"verdict":verdict,"source":source.private_commitment(),
                "policy":policy.private_replay_guard(),
            }))
            .as_bytes(),
        );
        source.revalidate(false).map_err(source_error)?;
        Ok(Self {
            source,
            decision_digest,
        })
    }
    pub(super) fn revalidate(&self, full: bool) -> MaterializationResult<()> {
        self.source.revalidate(full).map_err(source_error)
    }
    pub(super) fn private_commitment(&self) -> &str {
        &self.decision_digest
    }
    pub(super) fn publication(&self) -> (u64, u64) {
        self.source.publication()
    }
}
pub(super) fn source_error(error: SourceRefusal) -> Refusal {
    match error {
        SourceRefusal::Stale => Refusal::ThreatDataStale,
        SourceRefusal::Changed | SourceRefusal::Rollback => Refusal::ThreatDataChanged,
        SourceRefusal::ResourceLimit => Refusal::ResourceLimit,
        _ => Refusal::ThreatDataUnavailable,
    }
}
fn hash(value: &str) -> MaterializationResult<[u8; 32]> {
    let bytes = hex::decode(value).map_err(|_| Refusal::ArchiveUnsupported)?;
    bytes.try_into().map_err(|_| Refusal::ArchiveUnsupported)
}
fn finding(rule: RuleId, severity: Severity, title: &str, detail: String) -> Finding {
    Finding {
        rule_id: rule,
        severity,
        title: title.into(),
        description: detail.clone(),
        evidence: vec![Evidence::Text { detail }],
        human_view: None,
        agent_view: None,
        mitre_id: None,
        custom_rule_id: None,
    }
}
fn grade(confidence: Confidence) -> Severity {
    match confidence {
        Confidence::Confirmed => Severity::High,
        _ => Severity::Medium,
    }
}
fn findings(
    artifacts: &[VerifiedNpmArtifact],
    db: &crate::threatdb::ThreatDb,
) -> MaterializationResult<Vec<Finding>> {
    let mut findings = Vec::new();
    for artifact in artifacts {
        let inspection = &artifact.inspection;
        // Enforcing artifact installation has the same mandatory completeness
        // floor as the wheel firewall. "Ignore" cannot invent missing analysis.
        if !inspection.coverage.archive_complete
            || !inspection.coverage.metadata_complete
            || !inspection.coverage.static_analysis_complete
            || !inspection.coverage.issues.is_empty()
        {
            return Err(Refusal::AnalysisIncomplete);
        }
        if let Some(hit) = db.check_artifact_sha256(&hash(artifact.sha256())?) {
            findings.push(finding(
                RuleId::ArtifactKnownMalicious,
                grade(hit.confidence),
                "Artifact matches threat intelligence",
                format!(
                    "Retained artifact sha256:{} matches a {}-confidence record.",
                    artifact.sha256(),
                    hit.confidence.as_str()
                ),
            ));
        }
        match db.assess_package(
            Ecosystem::Npm,
            &artifact.leaf.name,
            &crate::version_intent::VersionIntent::Resolved(artifact.leaf.version.clone()),
        ) {
            PackageThreatAssessment::NoRecord
            | PackageThreatAssessment::ConstraintExcludesAffected => {}
            PackageThreatAssessment::ExactMatch(hit) => findings.push(finding(
                RuleId::ThreatMaliciousPackage,
                grade(hit.confidence),
                "Selected package identity matches threat intelligence",
                format!(
                    "{}@{} matches a {}-confidence record.",
                    artifact.leaf.name,
                    artifact.leaf.version,
                    hit.confidence.as_str()
                ),
            )),
            _ => return Err(Refusal::AnalysisIncomplete),
        }
        if db
            .check_typosquat(Ecosystem::Npm, &artifact.leaf.name)
            .is_some()
        {
            findings.push(finding(
                RuleId::ThreatPackageTyposquat,
                Severity::Medium,
                "Selected name matches a known typosquat",
                artifact.leaf.name.clone(),
            ));
        }
        for member in &inspection.files {
            if member.kind == NpmFileKind::Directory {
                continue;
            }
            if let Some(hit) = db.check_file_sha256(&hash(&member.sha256)?) {
                findings.push(finding(
                    RuleId::ArtifactKnownMalicious,
                    grade(hit.confidence),
                    "Retained member matches threat intelligence",
                    format!(
                        "{} sha256:{} matches a {}-confidence file record.",
                        member.path,
                        member.sha256,
                        hit.confidence.as_str()
                    ),
                ));
            }
        }
        for signal in &inspection.signals {
            if signal.level == npm_archive::NpmSignalLevel::Review {
                findings.push(finding(
                    RuleId::PackageScriptDangerous,
                    Severity::Medium,
                    "Static npm behavior requires review",
                    format!("{}: {}", signal.member, signal.evidence),
                ));
            }
        }
        if findings.len() > MAX_ENTRIES {
            return Err(Refusal::ResourceLimit);
        }
    }
    Ok(findings)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn coverage_gap_cannot_be_approved_by_permissive_task_or_scan_policy() {
        let root = tempfile::tempdir().unwrap();
        let mut artifact =
            super::super::tests::artifact(root.path(), super::super::tests::MANIFEST, &[]);
        artifact.inspection.coverage.static_analysis_complete = false;
        let source = MaterializationThreatSource::fixture_empty();
        assert!(matches!(
            findings(&[artifact], source.db()),
            Err(Refusal::AnalysisIncomplete)
        ));
    }
    #[test]
    fn actual_v2_artifact_and_member_hash_records_produce_policy_block_findings() {
        let root = tempfile::tempdir().unwrap();
        let artifact =
            super::super::tests::artifact(root.path(), super::super::tests::MANIFEST, &[]);
        let mut writer = crate::threatdb::ThreatDbWriter::new(1, 1);
        writer.add_artifact_sha256(
            hash(artifact.sha256()).unwrap(),
            crate::threatdb::ThreatSource::OssfMalicious,
            Confidence::Confirmed,
            false,
            None,
        );
        writer.add_file_sha256(
            hash(&artifact.inspection.files[0].sha256).unwrap(),
            crate::threatdb::ThreatSource::DatadogMalicious,
            Confidence::Confirmed,
            &[],
            None,
        );
        let key = ed25519_dalek::SigningKey::from_bytes(&[7u8; 32]);
        let bytes = writer
            .build_format(crate::threatdb::ThreatDbFormat::V2, &key)
            .unwrap();
        let db = crate::threatdb::ThreatDb::from_bytes(bytes, 0).unwrap();
        let found = findings(&[artifact], &db).unwrap();
        assert_eq!(found.len(), 2);
        assert!(found
            .iter()
            .all(|f| f.rule_id == RuleId::ArtifactKnownMalicious));
        let verdict = crate::escalation::finalize_static_verdict(
            found,
            &crate::policy::Policy::default(),
            3,
            Timings::default(),
        );
        assert_eq!(verdict.action, Action::Block);
    }
    #[test]
    fn review_signal_is_a_real_policy_input_not_an_observation_only_label() {
        let root = tempfile::tempdir().unwrap();
        let mut artifact =
            super::super::tests::artifact(root.path(), super::super::tests::MANIFEST, &[]);
        artifact.inspection.signals.push(npm_archive::NpmSignal {
            kind: npm_archive::NpmSignalKind::DownloadToShell,
            level: npm_archive::NpmSignalLevel::Review,
            member: "package/index.js".into(),
            capabilities: Vec::new(),
            lifecycle_events: Vec::new(),
            evidence: "bounded parser test observation".into(),
        });
        let source = MaterializationThreatSource::fixture_empty();
        let found = findings(&[artifact], source.db()).unwrap();
        assert_eq!(found.len(), 1);
        let verdict = crate::escalation::finalize_static_verdict(
            found,
            &crate::policy::Policy::default(),
            3,
            Timings::default(),
        );
        assert_ne!(verdict.action, Action::Allow);
    }
}
