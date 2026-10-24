//! Pure comparison of exact npm artifact inspections. Changes to the analyzer,
//! its limits or coverage are separated from changes to package bytes. No new
//! reads, resolution or execution are performed by this module.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

use super::npm_archive::{
    NpmArchiveState, NpmArtifactIdentity, NpmCapability, NpmCoverage, NpmFile, NpmFileKind,
    NpmInspection, NpmMetadata, NpmSignal, NpmSignalLevel, NPM_ANALYZER_VERSION,
    NPM_INSPECTION_SCHEMA_VERSION,
};

pub const NPM_COMPARISON_SCHEMA_VERSION: u32 = 1;
pub const NPM_COMPARISON_MAX_DELTAS: usize = 200;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NpmComparisonState {
    Comparable,
    Qualified,
    Unavailable,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NpmComparisonNote {
    UnsupportedSchema,
    MissingExactIdentity,
    ArchiveCoverageIncomplete,
    MetadataCoverageIncomplete,
    StaticCoverageIncomplete,
    AnalyzerChanged,
    UnsupportedAnalyzer,
    LimitsChanged,
    CoverageChanged,
    DeclaredPackageNameChanged,
    SameArtifactDifferentEvidence,
    DeltaOutputLimit,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum NpmDelta {
    DeclaredIdentityChanged {
        old_name: Option<String>,
        new_name: Option<String>,
        old_version: Option<String>,
        new_version: Option<String>,
    },
    MemberAdded {
        file: NpmFile,
    },
    MemberRemoved {
        file: NpmFile,
    },
    MemberChanged {
        path: String,
        old_sha256: String,
        new_sha256: String,
        old_kind: NpmFileKind,
        new_kind: NpmFileKind,
        old_executable: bool,
        new_executable: bool,
    },
    DeclaredScriptAdded {
        event: String,
        command: String,
    },
    DeclaredScriptRemoved {
        event: String,
        command: String,
    },
    DeclaredScriptChanged {
        event: String,
        old_command: String,
        new_command: String,
    },
    CommandLineEntryChanged {
        name: String,
        old_target: Option<String>,
        new_target: Option<String>,
    },
    MainEntryChanged {
        old_target: Option<String>,
        new_target: Option<String>,
    },
    ImplicitNativeBuildChanged {
        old_enabled: bool,
        new_enabled: bool,
    },
    /// Emitted only with identical analyzer/limits and complete, equivalent
    /// coverage. This compares observations, not execution or malware verdicts.
    CapabilityObservationAdded {
        member: String,
        capability: NpmCapability,
    },
    CapabilityObservationRemoved {
        member: String,
        capability: NpmCapability,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NpmComparison {
    pub schema_version: u32,
    pub state: NpmComparisonState,
    pub old_artifact: NpmArtifactIdentity,
    pub new_artifact: NpmArtifactIdentity,
    pub same_artifact: Option<bool>,
    /// True only when a capability observation delta can be attributed to the
    /// byte change under this comparison's explicitly supported static scope.
    pub capability_comparison_available: bool,
    pub old_coverage: NpmCoverage,
    pub new_coverage: NpmCoverage,
    pub notes: Vec<NpmComparisonNote>,
    pub deltas: Vec<NpmDelta>,
    pub omitted_deltas: usize,
    /// Current evidence is preserved even when differing coverage forbids a
    /// defensible "newly introduced" claim. It is never counted as a delta.
    pub current_review_signals: Vec<NpmSignal>,
}

impl NpmComparison {
    fn note(&mut self, note: NpmComparisonNote) {
        if !self.notes.contains(&note) {
            self.notes.push(note);
        }
        if self.state == NpmComparisonState::Comparable {
            self.state = NpmComparisonState::Qualified;
        }
    }

    fn delta(&mut self, delta: NpmDelta) {
        if self.deltas.len() < NPM_COMPARISON_MAX_DELTAS {
            self.deltas.push(delta);
        } else {
            self.omitted_deltas = self.omitted_deltas.saturating_add(1);
            self.note(NpmComparisonNote::DeltaOutputLimit);
        }
    }
}

/// Compare two captured inspections. Inputs normally come directly from the
/// bounded reader; persisted inputs must also pass their output schema/privacy
/// boundary before display. This entry refuses out-of-contract collection and
/// string sizes before allocating maps or cloning the input into a report.
pub fn compare_npm_releases(
    old: &NpmInspection,
    new: &NpmInspection,
) -> Result<NpmComparison, &'static str> {
    if !valid_bounds(old) || !valid_bounds(new) {
        return Err("npm inspection exceeds the supported comparison bounds");
    }
    let same_artifact = match (&old.artifact.sha256, &new.artifact.sha256) {
        (Some(old), Some(new)) if valid_sha(old) && valid_sha(new) => Some(old == new),
        _ => None,
    };
    let mut result = NpmComparison {
        schema_version: NPM_COMPARISON_SCHEMA_VERSION,
        state: NpmComparisonState::Comparable,
        old_artifact: old.artifact.clone(),
        new_artifact: new.artifact.clone(),
        same_artifact,
        capability_comparison_available: false,
        old_coverage: old.coverage.clone(),
        new_coverage: new.coverage.clone(),
        notes: Vec::new(),
        deltas: Vec::new(),
        omitted_deltas: 0,
        current_review_signals: new
            .signals
            .iter()
            .filter(|s| s.level == NpmSignalLevel::Review)
            .cloned()
            .collect(),
    };
    if old.schema_version != NPM_INSPECTION_SCHEMA_VERSION
        || new.schema_version != NPM_INSPECTION_SCHEMA_VERSION
    {
        result.note(NpmComparisonNote::UnsupportedSchema);
        result.state = NpmComparisonState::Unavailable;
        return Ok(result);
    }
    if same_artifact.is_none() {
        result.note(NpmComparisonNote::MissingExactIdentity);
        result.state = NpmComparisonState::Unavailable;
        return Ok(result);
    }
    let archives_complete = old.archive_state == NpmArchiveState::Accepted
        && new.archive_state == NpmArchiveState::Accepted
        && old.coverage.archive_complete
        && new.coverage.archive_complete;
    if !archives_complete {
        result.note(NpmComparisonNote::ArchiveCoverageIncomplete);
    }
    let metadata_complete = old.coverage.metadata_complete
        && new.coverage.metadata_complete
        && old.metadata.is_some()
        && new.metadata.is_some();
    if !metadata_complete {
        result.note(NpmComparisonNote::MetadataCoverageIncomplete);
    }
    let static_complete =
        old.coverage.static_analysis_complete && new.coverage.static_analysis_complete;
    if !static_complete {
        result.note(NpmComparisonNote::StaticCoverageIncomplete);
    }
    let same_analyzer = old.analyzer_version == new.analyzer_version;
    if !same_analyzer {
        result.note(NpmComparisonNote::AnalyzerChanged);
    }
    let supported_analyzer = old.analyzer_version == NPM_ANALYZER_VERSION
        && new.analyzer_version == NPM_ANALYZER_VERSION;
    if !supported_analyzer {
        result.note(NpmComparisonNote::UnsupportedAnalyzer);
    }
    let same_limits = old.limits == new.limits;
    if !same_limits {
        result.note(NpmComparisonNote::LimitsChanged);
    }
    let same_coverage = old.coverage.archive_complete == new.coverage.archive_complete
        && old.coverage.metadata_complete == new.coverage.metadata_complete
        && old.coverage.static_analysis_complete == new.coverage.static_analysis_complete
        && old.coverage.analysis_scope == new.coverage.analysis_scope
        && old.coverage.issues == new.coverage.issues;
    if !same_coverage {
        result.note(NpmComparisonNote::CoverageChanged);
    }
    let same_name = old.artifact.name.is_some() && old.artifact.name == new.artifact.name;
    if old.artifact.name != new.artifact.name {
        result.note(NpmComparisonNote::DeclaredPackageNameChanged);
    }
    result.capability_comparison_available = archives_complete
        && metadata_complete
        && static_complete
        && same_analyzer
        && supported_analyzer
        && same_limits
        && same_coverage
        && same_name;
    if same_artifact == Some(true) {
        // Same transport bytes cannot introduce a package change. Differing
        // captures are an analysis/evidence difference, even if a producer failed
        // to bump its analyzer version or a persisted capture was inconsistent.
        if old.files != new.files
            || old.metadata != new.metadata
            || old.signals != new.signals
            || old.artifact.name != new.artifact.name
            || old.artifact.version != new.artifact.version
        {
            result.note(NpmComparisonNote::SameArtifactDifferentEvidence);
            result.capability_comparison_available = false;
        }
        return Ok(result);
    }
    if !archives_complete {
        result.state = NpmComparisonState::Unavailable;
        return Ok(result);
    }
    if metadata_complete {
        if old.artifact.name != new.artifact.name || old.artifact.version != new.artifact.version {
            result.delta(NpmDelta::DeclaredIdentityChanged {
                old_name: old.artifact.name.clone(),
                new_name: new.artifact.name.clone(),
                old_version: old.artifact.version.clone(),
                new_version: new.artifact.version.clone(),
            });
        }
        if let (Some(old), Some(new)) = (&old.metadata, &new.metadata) {
            compare_metadata(old, new, &mut result);
        }
    }
    // Direct membership/content identities can be compared even if a static
    // analyzer is incomplete or changed. They do not imply a risk delta.
    let old_files: BTreeMap<_, _> = old
        .files
        .iter()
        .map(|file| (file.path.as_str(), file))
        .collect();
    let new_files: BTreeMap<_, _> = new
        .files
        .iter()
        .map(|file| (file.path.as_str(), file))
        .collect();
    for (path, file) in &new_files {
        match old_files.get(path) {
            None => result.delta(NpmDelta::MemberAdded {
                file: (*file).clone(),
            }),
            Some(prior) if prior.sha256 != file.sha256 || prior.executable != file.executable => {
                result.delta(NpmDelta::MemberChanged {
                    path: (*path).to_owned(),
                    old_sha256: prior.sha256.clone(),
                    new_sha256: file.sha256.clone(),
                    old_kind: prior.kind,
                    new_kind: file.kind,
                    old_executable: prior.executable,
                    new_executable: file.executable,
                });
            }
            _ => {}
        }
    }
    for (path, file) in &old_files {
        if !new_files.contains_key(path) {
            result.delta(NpmDelta::MemberRemoved {
                file: (*file).clone(),
            });
        }
    }
    if result.capability_comparison_available {
        let old_capabilities = capabilities(old);
        let new_capabilities = capabilities(new);
        for (member, capability) in new_capabilities.difference(&old_capabilities) {
            result.delta(NpmDelta::CapabilityObservationAdded {
                member: member.clone(),
                capability: *capability,
            });
        }
        for (member, capability) in old_capabilities.difference(&new_capabilities) {
            result.delta(NpmDelta::CapabilityObservationRemoved {
                member: member.clone(),
                capability: *capability,
            });
        }
    }
    Ok(result)
}

fn compare_metadata(old: &NpmMetadata, new: &NpmMetadata, result: &mut NpmComparison) {
    for (event, command) in &new.scripts {
        match old.scripts.get(event) {
            None => result.delta(NpmDelta::DeclaredScriptAdded {
                event: event.clone(),
                command: command.clone(),
            }),
            Some(prior) if prior != command => result.delta(NpmDelta::DeclaredScriptChanged {
                event: event.clone(),
                old_command: prior.clone(),
                new_command: command.clone(),
            }),
            _ => {}
        }
    }
    for (event, command) in &old.scripts {
        if !new.scripts.contains_key(event) {
            result.delta(NpmDelta::DeclaredScriptRemoved {
                event: event.clone(),
                command: command.clone(),
            });
        }
    }
    for name in old
        .bin
        .keys()
        .chain(new.bin.keys())
        .collect::<BTreeSet<_>>()
    {
        if old.bin.get(name) != new.bin.get(name) {
            result.delta(NpmDelta::CommandLineEntryChanged {
                name: name.clone(),
                old_target: old.bin.get(name).cloned(),
                new_target: new.bin.get(name).cloned(),
            });
        }
    }
    if old.main != new.main {
        result.delta(NpmDelta::MainEntryChanged {
            old_target: old.main.clone(),
            new_target: new.main.clone(),
        });
    }
    if old.implicit_node_gyp_install != new.implicit_node_gyp_install {
        result.delta(NpmDelta::ImplicitNativeBuildChanged {
            old_enabled: old.implicit_node_gyp_install,
            new_enabled: new.implicit_node_gyp_install,
        });
    }
}

fn capabilities(inspection: &NpmInspection) -> BTreeSet<(String, NpmCapability)> {
    inspection
        .signals
        .iter()
        .flat_map(|signal| {
            signal
                .capabilities
                .iter()
                .map(|capability| (signal.member.clone(), *capability))
        })
        .collect()
}

fn valid_sha(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

fn valid_bounds(inspection: &NpmInspection) -> bool {
    let limits = super::npm_archive::NpmLimits::default();
    if inspection.files.len() > limits.headers
        || inspection.signals.len() > limits.signals
        || inspection.coverage.issues.len() > 256
        || inspection.artifact.filename.len() > 4096
        || inspection.analyzer_version.len() > 128
        || inspection.coverage.analysis_scope.len() > 512
        || inspection
            .artifact
            .name
            .as_ref()
            .is_some_and(|s| s.len() > 214)
        || inspection
            .artifact
            .version
            .as_ref()
            .is_some_and(|s| s.len() > 256)
        || inspection
            .artifact
            .sha256
            .as_ref()
            .is_some_and(|s| !valid_sha(s))
    {
        return false;
    }
    let mut names = BTreeSet::new();
    let mut path_bytes = 0usize;
    for file in &inspection.files {
        path_bytes = path_bytes.saturating_add(file.path.len());
        if file.path.len() > limits.path_bytes
            || path_bytes > limits.total_path_bytes
            || !valid_sha(&file.sha256)
            || !names.insert(file.path.as_str())
        {
            return false;
        }
    }
    if inspection.signals.iter().any(|s| {
        s.member.len() > limits.path_bytes
            || s.evidence.len() > 1024
            || s.capabilities.len() > 16
            || s.lifecycle_events.len() > 128
            || s.lifecycle_events.iter().any(|e| e.len() > 128)
    }) || inspection.coverage.issues.iter().any(|i| {
        i.member
            .as_ref()
            .is_some_and(|m| m.len() > limits.path_bytes)
            || i.detail.len() > 1024
    }) {
        return false;
    }
    if let Some(metadata) = &inspection.metadata {
        let map_valid = |map: &BTreeMap<String, String>, count: usize, key: usize, value: usize| {
            map.len() <= count && map.iter().all(|(k, v)| k.len() <= key && v.len() <= value)
        };
        if metadata.name.len() > 214
            || metadata.version.len() > 256
            || !map_valid(&metadata.scripts, 128, 128, 8192)
            || !map_valid(&metadata.bin, 128, 214, 4096)
            || !map_valid(&metadata.dependencies, 2048, 214, 2048)
            || metadata.main.as_ref().is_some_and(|s| s.len() > 4096)
            || metadata.bundled_dependencies.len() > 2048
            || metadata.bundled_dependencies.iter().any(|s| s.len() > 214)
        {
            return false;
        }
    }
    true
}

#[cfg(test)]
#[path = "npm_diff_tests.rs"]
mod tests;
