//! Read-only lifecycle facts. Version observations never imply enforcement,
//! release authenticity, ownership of another installation, or write authority.
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use serde::Serialize;
use tirith_core::policy_snapshot::{EffectivePolicySnapshot, ResolutionMode};
use tirith_core::selfupdate::SemVer;

#[derive(Debug, Serialize)]
pub(crate) struct VersionObservation {
    pub version: Option<String>,
    pub evidence: &'static str,
}

#[derive(Debug, Serialize)]
pub(crate) struct LoadedIntegration {
    pub version: Option<String>,
    pub shell: Option<String>,
    pub evidence: &'static str,
    pub reload_status: &'static str,
    pub next_action: &'static str,
}

#[derive(Debug, Serialize)]
pub(crate) struct FormatFact {
    pub surface: &'static str,
    pub declared_version: Option<u32>,
    pub state: &'static str,
}

#[derive(Debug, Serialize)]
pub(crate) struct CompatibilityFacts {
    pub evidence: &'static str,
    pub candidate_evidence: &'static str,
    pub policy_read_versions: Vec<u32>,
    pub mcp_lock_read_versions: Vec<u32>,
    pub legacy_trust_read_versions: Vec<u32>,
    pub scoped_grant_read_versions: Vec<u32>,
    pub operation_journal_version: u32,
    pub operation_journal_client_rule: &'static str,
    pub control_service_protocol: u32,
    pub control_service_reuse_rule: &'static str,
    pub configuration_update_rule: &'static str,
    pub observed_formats: Vec<FormatFact>,
    pub candidate_next_action: &'static str,
}

#[derive(Debug, Serialize)]
pub(crate) struct LifecycleFacts {
    pub schema_version: u32,
    pub kind: &'static str,
    pub installed_binary: VersionObservation,
    pub release: VersionObservation,
    pub channel_available: VersionObservation,
    pub install_method: &'static str,
    pub install_method_resolved: bool,
    pub self_replaceable: bool,
    pub upgrade_guidance: Option<&'static str>,
    pub resolved_path_binary_count: usize,
    pub path_scan_complete: bool,
    pub multiple_binaries: bool,
    pub loaded_integration: LoadedIntegration,
    /// This process only. The control service separately owns its live jobs.
    pub active_jobs_in_this_process: usize,
    pub compatibility: CompatibilityFacts,
}

fn loaded_integration(
    binary_version: &str,
    inherited_version: Option<&str>,
    inherited_shell: Option<&str>,
) -> LoadedIntegration {
    // Do not echo arbitrary inherited bytes into machine/human output.
    let version = inherited_version
        .filter(|raw| raw.len() <= 64)
        .and_then(SemVer::parse)
        .map(|version| version.to_string());
    let shell = inherited_shell
        .filter(|shell| {
            matches!(
                *shell,
                "bash" | "zsh" | "fish" | "powershell" | "pwsh" | "nu" | "nushell"
            )
        })
        .map(str::to_string);
    let reload_status = match version.as_deref() {
        Some(version) if version == binary_version => "matching_version_unverified",
        Some(_) => "reload_required",
        None => "unknown",
    };
    LoadedIntegration {
        version,
        shell,
        evidence: "inherited_environment_unverified",
        reload_status,
        next_action: match reload_status {
            "matching_version_unverified" => "Inspect tirith status --json in the target shell; reported configuration is not a fresh blocking test.",
            "reload_required" => "Open a fresh shell or reload the owning host, then inspect tirith status --json; configuration alone does not prove blocking.",
            _ => "Open the intended shell or host and verify its loaded integration; an absent marker does not prove it is disabled.",
        },
    }
}

fn format_fact(
    path: &Path,
    surface: &'static str,
    field: &str,
    yaml: bool,
    absent_version: Option<u32>,
) -> FormatFact {
    let bytes = match tirith_core::util::read_regular_capped(path, 1024 * 1024) {
        Ok(bytes) => bytes,
        Err(error) => {
            return FormatFact {
                surface,
                declared_version: None,
                state: if matches!(error, tirith_core::util::OpenRegularError::NotFound) {
                    "absent"
                } else {
                    "unreadable"
                },
            }
        }
    };
    let parsed = if yaml {
        serde_yaml::from_slice::<serde_json::Value>(&bytes).ok()
    } else {
        serde_json::from_slice::<serde_json::Value>(&bytes).ok()
    };
    let version = parsed
        .as_ref()
        .filter(|value| value.is_object())
        .and_then(|value| match value.get(field) {
            Some(value) => value
                .as_u64()
                .and_then(|value| u32::try_from(value).ok())
                .filter(|value| *value > 0),
            None => absent_version,
        });
    FormatFact {
        surface,
        declared_version: version,
        state: if version.is_some() {
            "declared_local_unverified"
        } else {
            "invalid"
        },
    }
}

fn observed_formats() -> Vec<FormatFact> {
    let cwd = std::env::current_dir().ok();
    let snapshot = EffectivePolicySnapshot::resolve(
        cwd.as_deref().and_then(Path::to_str),
        ResolutionMode::LocalOnly,
    );
    let mut formats = Vec::new();
    let mut seen = BTreeSet::new();
    for input in snapshot.input_revisions {
        if input.source.kind != "policy" {
            continue;
        }
        if let Some(path) = input.source.path {
            if seen.insert(path.clone()) {
                formats.push(format_fact(
                    Path::new(&path),
                    "policy",
                    "schema_version",
                    true,
                    Some(1),
                ));
            }
        }
    }
    if let Some(config) = tirith_core::policy::config_dir() {
        formats.push(format_fact(
            &config.join("trust.json"),
            "legacy_trust",
            "version",
            false,
            None,
        ));
        formats.push(format_fact(
            &config.join(tirith_core::trust_grants::STORE_FILE),
            "scoped_grants",
            "schema_version",
            false,
            None,
        ));
    } else {
        for surface in ["legacy_trust", "scoped_grants"] {
            formats.push(FormatFact {
                surface,
                declared_version: None,
                state: "configuration_root_unavailable",
            });
        }
    }
    if let Some(project) = crate::cli::mcp::resolve_repo_root() {
        formats.push(format_fact(
            &project.join(".tirith/trust.json"),
            "legacy_trust",
            "version",
            false,
            None,
        ));
        formats.push(format_fact(
            &project.join(".tirith/mcp.lock"),
            "mcp_lock",
            "format_version",
            false,
            None,
        ));
    }
    formats
}

fn path_binary_count(path: Option<std::ffi::OsString>) -> (usize, bool) {
    let Some(path) = path else {
        return (0, false);
    };
    let mut targets = BTreeSet::<PathBuf>::new();
    let mut complete = true;
    for (index, directory) in std::env::split_paths(&path).enumerate() {
        if index >= 128 {
            complete = false;
            break;
        }
        let candidate = directory.join(if cfg!(windows) {
            "tirith.exe"
        } else {
            "tirith"
        });
        match std::fs::symlink_metadata(&candidate) {
            Ok(_) => match crate::cli::resolve_effective_tirith_target(&candidate) {
                Some(target) => {
                    targets.insert(target);
                }
                None => complete = false,
            },
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(_) => complete = false,
        }
    }
    (targets.len(), complete)
}

pub(super) fn gather(
    provenance: &super::CliProvenance,
    observed_release: Option<&str>,
) -> LifecycleFacts {
    let release = observed_release
        .and_then(SemVer::parse)
        .map(|version| version.to_string());
    let self_replaceable =
        provenance.install_method.is_self_replaceable() && !provenance.path_resolution_failed;
    let (resolved_path_binary_count, path_scan_complete) =
        path_binary_count(std::env::var_os("PATH"));
    LifecycleFacts {
        schema_version: 1,
        kind: "lifecycle",
        installed_binary: VersionObservation { version: Some(provenance.version.clone()), evidence: "running_binary_build_metadata" },
        release: VersionObservation { evidence: if release.is_some() { "github_release_api_unverified" } else { "not_queried_offline" }, version: release.clone() },
        channel_available: VersionObservation {
            version: if self_replaceable { release.clone() } else { None },
            evidence: if self_replaceable && release.is_some() { "standalone_release_api_unverified" } else { "owning_channel_not_queried" },
        },
        install_method: super::install_method_token(provenance),
        install_method_resolved: !provenance.path_resolution_failed,
        self_replaceable,
        upgrade_guidance: provenance.install_method.upgrade_command(),
        resolved_path_binary_count,
        path_scan_complete,
        multiple_binaries: resolved_path_binary_count > 1,
        loaded_integration: loaded_integration(&provenance.version, std::env::var("TIRITH_INTEGRATION_VERSION").ok().as_deref(), std::env::var("TIRITH_INTEGRATION_SHELL").ok().as_deref()),
        active_jobs_in_this_process: crate::cli::setup::change_plan::active_job_count(),
        compatibility: CompatibilityFacts {
            evidence: "current_binary_contract_with_local_format_observations",
            candidate_evidence: "not_verified",
            policy_read_versions: (1..=tirith_core::policy_migrations::CURRENT_SCHEMA_VERSION).collect(),
            mcp_lock_read_versions: (4..=tirith_core::mcp_lock::MCP_LOCK_FORMAT_VERSION).collect(),
            legacy_trust_read_versions: vec![1],
            scoped_grant_read_versions: vec![tirith_core::trust_grants::STORE_VERSION],
            operation_journal_version: 1,
            operation_journal_client_rule: "exact_client_version_required",
            control_service_protocol: 1,
            control_service_reuse_rule: "exact_protocol_version_and_binary_sha256_required; quiesce_before_replacement",
            configuration_update_rule: "preserve_existing_bytes; do_not_restore_old_configuration_over_user_edits",
            observed_formats: observed_formats(),
            candidate_next_action: "Verify the candidate compatibility document against its signed release checksums before replacing a binary; unknown or unsupported formats require explicit migration guidance.",
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn inherited_marker_never_claims_verified_activation() {
        let matching = loaded_integration("0.4.2", Some("0.4.2"), Some("bash"));
        assert_eq!(matching.reload_status, "matching_version_unverified");
        assert_eq!(matching.evidence, "inherited_environment_unverified");
        assert_eq!(
            loaded_integration("0.4.2", Some("0.4.1"), Some("zsh")).reload_status,
            "reload_required"
        );
        let unknown = loaded_integration("0.4.2", Some("unknown"), Some("arbitrary-secret"));
        assert_eq!(unknown.reload_status, "unknown");
        assert!(unknown.version.is_none() && unknown.shell.is_none());
    }

    #[test]
    fn format_observations_preserve_unknown_and_future_versions_without_contents() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("policy.yaml");
        assert_eq!(
            format_fact(&file, "policy", "schema_version", true, Some(1)).state,
            "absent"
        );
        std::fs::write(&file, "schema_version: 99\napi_key: hidden\n").unwrap();
        let future = format_fact(&file, "policy", "schema_version", true, Some(1));
        assert_eq!(future.declared_version, Some(99));
        assert!(!serde_json::to_string(&future).unwrap().contains("hidden"));
        std::fs::write(&file, "schema_version: invalid\n").unwrap();
        assert_eq!(
            format_fact(&file, "policy", "schema_version", true, Some(1)).state,
            "invalid"
        );
        std::fs::write(&file, "paranoia: 1\n").unwrap();
        assert_eq!(
            format_fact(&file, "policy", "schema_version", true, Some(1)).declared_version,
            Some(1)
        );
    }
}
