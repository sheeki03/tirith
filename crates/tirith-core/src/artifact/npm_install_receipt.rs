//! Canonical, path-free npm verification evidence for schema-v3 signed receipts.

use serde::{Deserialize, Serialize};

use super::{digest, tools, NpmFile, NpmFileKind, NpmInstallRefusal, Result};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct NpmArtifactVerification {
    pub artifact_sha256: String,
    pub manifest_sha256: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct NpmVerificationSummary {
    pub schema_version: u32,
    pub contract: String,
    pub operation_id: String,
    pub node_version: String,
    pub node_sha256: String,
    pub npm_version: String,
    pub npm_tree_sha256: String,
    pub runtime_pack_sha256: String,
    pub artifacts: Vec<NpmArtifactVerification>,
    pub output_tree_sha256: String,
    pub files_verified: usize,
    pub directories_verified: usize,
    pub bytes_verified: u64,
    pub lifecycle_scripts: NpmLifecycleMode,
    pub dependency_graph: NpmDependencyGraph,
    pub code_safety: NpmCodeSafety,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum NpmLifecycleMode {
    Disabled,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum NpmDependencyGraph {
    LocalLeafOnly,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum NpmCodeSafety {
    NotEstablished,
}

/// A deserialized summary is evidence to inspect, never a construction permit.
/// Only a current retained verified tree can issue this non-Clone capability.
pub struct VerifiedNpmReceiptEvidence {
    pub(crate) summary: NpmVerificationSummary,
}

impl NpmVerificationSummary {
    pub fn validate_stored(&self) -> std::result::Result<(), &'static str> {
        let sha = |value: &str| {
            value.len() == 64
                && value
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        };
        if self.schema_version != 1
            || self.contract != super::CONTRACT
            || uuid::Uuid::parse_str(&self.operation_id)
                .ok()
                .map(|id| id.to_string())
                .as_deref()
                != Some(self.operation_id.as_str())
            || self.node_version != tools::NODE_VERSION
            || self.node_sha256 != tools::NODE_SHA256
            || self.npm_version != tools::NPM_VERSION
            || self.npm_tree_sha256 != tools::NPM_TREE_SHA256
            || !sha(&self.runtime_pack_sha256)
            || !sha(&self.output_tree_sha256)
            || self.artifacts.is_empty()
            || self.artifacts.len() > super::MAX_ARTIFACTS
            || self.files_verified == 0
            || self.files_verified > super::MAX_INSTALLED_ENTRIES
            || self.directories_verified == 0
            || self.directories_verified > super::MAX_INSTALLED_ENTRIES
            || self
                .files_verified
                .checked_add(self.directories_verified)
                .is_none_or(|total| total > super::MAX_INSTALLED_ENTRIES)
            || self.bytes_verified == 0
            || self.bytes_verified > super::MAX_TOTAL_INSTALLED_BYTES
        {
            return Err("unsupported or incomplete npm verification summary");
        }
        let mut previous: Option<&str> = None;
        for artifact in &self.artifacts {
            if !sha(&artifact.artifact_sha256)
                || !sha(&artifact.manifest_sha256)
                || previous.is_some_and(|value| value >= artifact.artifact_sha256.as_str())
            {
                return Err("invalid or repeated npm artifact verification identity");
            }
            previous = Some(&artifact.artifact_sha256);
        }
        Ok(())
    }

    pub(super) fn from_verified(
        plan: &super::NpmInstallPlan,
        runtime_pack_sha256: &str,
        expected: &std::collections::BTreeMap<String, NpmFile>,
    ) -> Result<Self> {
        let mut artifacts: Vec<_> = plan
            .artifacts
            .iter()
            .map(|(sha, leaf)| NpmArtifactVerification {
                artifact_sha256: sha.clone(),
                manifest_sha256: leaf.manifest_sha256.clone(),
            })
            .collect();
        artifacts.sort_by(|a, b| a.artifact_sha256.cmp(&b.artifact_sha256));
        let mut directories = std::collections::BTreeSet::new();
        let mut bytes = 0;
        let mut files = 0;
        for (path, file) in expected {
            let mut parent = std::path::Path::new(path).parent();
            while let Some(path) = parent {
                if !path.as_os_str().is_empty() {
                    directories.insert(path.to_owned());
                }
                parent = path.parent();
            }
            if file.kind == NpmFileKind::Directory {
                directories.insert(path.into());
            } else {
                files += 1;
                bytes += file.size;
            }
        }
        let facts: Vec<_> = expected
            .iter()
            .map(|(path, file)| (path, file.kind, file.size, &file.sha256, file.executable))
            .collect();
        let canonical = crate::audit::canonical_json_for_hash(
            &serde_json::to_value(facts).map_err(|_| NpmInstallRefusal::InstalledContentChanged)?,
        );
        let summary = Self {
            schema_version: 1,
            contract: super::CONTRACT.into(),
            operation_id: plan.id.clone(),
            node_version: tools::NODE_VERSION.into(),
            node_sha256: tools::NODE_SHA256.into(),
            npm_version: tools::NPM_VERSION.into(),
            npm_tree_sha256: tools::NPM_TREE_SHA256.into(),
            runtime_pack_sha256: runtime_pack_sha256.into(),
            artifacts,
            output_tree_sha256: digest(canonical.as_bytes()),
            files_verified: files,
            directories_verified: directories.len(),
            bytes_verified: bytes,
            lifecycle_scripts: NpmLifecycleMode::Disabled,
            dependency_graph: NpmDependencyGraph::LocalLeafOnly,
            code_safety: NpmCodeSafety::NotEstablished,
        };
        summary
            .validate_stored()
            .map_err(|_| NpmInstallRefusal::InstalledContentChanged)?;
        Ok(summary)
    }
}
