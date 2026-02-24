use etcetera::BaseStrategy;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::{Path, PathBuf};

use crate::verdict::{RuleId, Severity};

/// Try both `.yaml` and `.yml` extensions in a directory.
fn find_policy_in_dir(dir: &Path) -> Option<PathBuf> {
    let yaml = dir.join("policy.yaml");
    if yaml.exists() {
        return Some(yaml);
    }
    let yml = dir.join("policy.yml");
    if yml.exists() {
        return Some(yml);
    }
    None
}

/// Policy configuration loaded from YAML.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct Policy {
    /// Path this policy was loaded from.
    #[serde(skip)]
    pub path: Option<String>,

    /// Fail mode: "open" (default) or "closed".
    pub fail_mode: FailMode,

    /// Allow TIRITH=0 bypass in interactive mode.
    pub allow_bypass_env: bool,

    /// Allow TIRITH=0 bypass in non-interactive mode.
    pub allow_bypass_env_noninteractive: bool,

    /// Paranoia tier (1-4).
    pub paranoia: u8,

    /// Severity overrides per rule.
    #[serde(default)]
    pub severity_overrides: HashMap<String, Severity>,

    /// Additional known domains (extends built-in list).
    #[serde(default)]
    pub additional_known_domains: Vec<String>,

    /// Allowlist: URL patterns that are always allowed.
    #[serde(default)]
    pub allowlist: Vec<String>,

    /// Blocklist: URL patterns that are always blocked.
    #[serde(default)]
    pub blocklist: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
#[derive(Default)]
pub enum FailMode {
    #[default]
    Open,
    Closed,
}

impl Default for Policy {
    fn default() -> Self {
        Self {
            path: None,
            fail_mode: FailMode::Open,
            allow_bypass_env: true,
            allow_bypass_env_noninteractive: false,
            paranoia: 1,
            severity_overrides: HashMap::new(),
            additional_known_domains: Vec::new(),
            allowlist: Vec::new(),
            blocklist: Vec::new(),
        }
    }
}

impl Policy {
    /// Discover and load partial policy (just bypass + fail_mode fields).
    /// Used in Tier 2 for fast bypass resolution.
    pub fn discover_partial(cwd: Option<&str>) -> Self {
        match discover_policy_path(cwd) {
            Some(path) => match std::fs::read_to_string(&path) {
                Ok(content) => match serde_yaml::from_str::<Policy>(&content) {
                    Ok(mut p) => {
                        p.path = Some(path.display().to_string());
                        p
                    }
                    Err(e) => {
                        eprintln!(
                            "tirith: warning: failed to parse policy at {}: {e}",
                            path.display()
                        );
                        // Parse error: use fail_mode default behavior
                        Policy::default()
                    }
                },
                Err(_) => Policy::default(),
            },
            None => Policy::default(),
        }
    }

    /// Discover and load full policy.
    pub fn discover(cwd: Option<&str>) -> Self {
        // Check env override first
        if let Ok(root) = std::env::var("TIRITH_POLICY_ROOT") {
            if let Some(path) = find_policy_in_dir(&PathBuf::from(&root).join(".tirith")) {
                return Self::load_from_path(&path);
            }
        }

        match discover_policy_path(cwd) {
            Some(path) => Self::load_from_path(&path),
            None => {
                // Try user-level policy
                if let Some(user_path) = user_policy_path() {
                    if user_path.exists() {
                        return Self::load_from_path(&user_path);
                    }
                }
                Policy::default()
            }
        }
    }

    fn load_from_path(path: &Path) -> Self {
        match std::fs::read_to_string(path) {
            Ok(content) => match serde_yaml::from_str::<Policy>(&content) {
                Ok(mut p) => {
                    p.path = Some(path.display().to_string());
                    p
                }
                Err(e) => {
                    eprintln!(
                        "tirith: warning: failed to parse policy at {}: {e}",
                        path.display(),
                    );
                    Policy::default()
                }
            },
            Err(_) => Policy::default(),
        }
    }

    /// Get severity override for a rule.
    pub fn severity_override(&self, rule_id: &RuleId) -> Option<Severity> {
        let key = serde_json::to_value(rule_id)
            .ok()
            .and_then(|v| v.as_str().map(String::from))?;
        self.severity_overrides.get(&key).copied()
    }

    /// Check if a URL is in the blocklist.
    pub fn is_blocklisted(&self, url: &str) -> bool {
        let url_lower = url.to_lowercase();
        self.blocklist.iter().any(|pattern| {
            let p = pattern.to_lowercase();
            url_lower.contains(&p)
        })
    }

    /// Check if a URL is in the allowlist.
    pub fn is_allowlisted(&self, url: &str) -> bool {
        let url_lower = url.to_lowercase();
        self.allowlist.iter().any(|pattern| {
            let p = pattern.to_lowercase();
            if p.is_empty() {
                return false;
            }
            if is_domain_pattern(&p) {
                if let Some(host) = extract_host_for_match(url) {
                    return domain_matches(&host, &p);
                }
                return false;
            }
            url_lower.contains(&p)
        })
    }

    /// Load and merge user-level lists (allowlist/blocklist flat text files).
    pub fn load_user_lists(&mut self) {
        if let Some(config) = crate::policy::config_dir() {
            let allowlist_path = config.join("allowlist");
            if let Ok(content) = std::fs::read_to_string(&allowlist_path) {
                for line in content.lines() {
                    let line = line.trim();
                    if !line.is_empty() && !line.starts_with('#') {
                        self.allowlist.push(line.to_string());
                    }
                }
            }
            let blocklist_path = config.join("blocklist");
            if let Ok(content) = std::fs::read_to_string(&blocklist_path) {
                for line in content.lines() {
                    let line = line.trim();
                    if !line.is_empty() && !line.starts_with('#') {
                        self.blocklist.push(line.to_string());
                    }
                }
            }
        }
    }

    /// Load and merge org-level lists from a repo root's .tirith/ dir.
    pub fn load_org_lists(&mut self, cwd: Option<&str>) {
        if let Some(repo_root) = find_repo_root(cwd) {
            let org_dir = repo_root.join(".tirith");
            let allowlist_path = org_dir.join("allowlist");
            if let Ok(content) = std::fs::read_to_string(&allowlist_path) {
                for line in content.lines() {
                    let line = line.trim();
                    if !line.is_empty() && !line.starts_with('#') {
                        self.allowlist.push(line.to_string());
                    }
                }
            }
            let blocklist_path = org_dir.join("blocklist");
            if let Ok(content) = std::fs::read_to_string(&blocklist_path) {
                for line in content.lines() {
                    let line = line.trim();
                    if !line.is_empty() && !line.starts_with('#') {
                        self.blocklist.push(line.to_string());
                    }
                }
            }
        }
    }
}

fn is_domain_pattern(p: &str) -> bool {
    !p.contains("://")
        && !p.contains('/')
        && !p.contains('?')
        && !p.contains('#')
        && !p.contains(':')
}

fn extract_host_for_match(url: &str) -> Option<String> {
    if let Some(host) = crate::parse::parse_url(url).host() {
        return Some(host.trim_end_matches('.').to_lowercase());
    }
    // Fallback for schemeless host/path (e.g., example.com/path)
    let candidate = url.split('/').next().unwrap_or(url).trim();
    if candidate.starts_with('-') || !candidate.contains('.') || candidate.contains(' ') {
        return None;
    }
    let host = if let Some((h, port)) = candidate.rsplit_once(':') {
        if port.chars().all(|c| c.is_ascii_digit()) && !port.is_empty() {
            h
        } else {
            candidate
        }
    } else {
        candidate
    };
    Some(host.trim_end_matches('.').to_lowercase())
}

fn domain_matches(host: &str, pattern: &str) -> bool {
    let host = host.trim_end_matches('.');
    let pattern = pattern.trim_start_matches("*.").trim_end_matches('.');
    host == pattern || host.ends_with(&format!(".{pattern}"))
}

/// Discover policy path by walking up from cwd to .git boundary.
fn discover_policy_path(cwd: Option<&str>) -> Option<PathBuf> {
    let start = cwd
        .map(PathBuf::from)
        .or_else(|| std::env::current_dir().ok())?;

    let mut current = start.as_path();
    loop {
        // Check for .tirith/policy.yaml or .tirith/policy.yml
        if let Some(candidate) = find_policy_in_dir(&current.join(".tirith")) {
            return Some(candidate);
        }

        // Check for .git boundary (directory or file for worktrees)
        let git_dir = current.join(".git");
        if git_dir.exists() {
            return None; // Hit repo root without finding policy
        }

        // Go up
        match current.parent() {
            Some(parent) if parent != current => current = parent,
            _ => break,
        }
    }

    None
}

/// Find the repository root (directory containing .git).
fn find_repo_root(cwd: Option<&str>) -> Option<PathBuf> {
    let start = cwd
        .map(PathBuf::from)
        .or_else(|| std::env::current_dir().ok())?;
    let mut current = start.as_path();
    loop {
        let git = current.join(".git");
        if git.exists() {
            return Some(current.to_path_buf());
        }
        match current.parent() {
            Some(parent) if parent != current => current = parent,
            _ => break,
        }
    }
    None
}

/// Get user-level policy path.
fn user_policy_path() -> Option<PathBuf> {
    let base = etcetera::choose_base_strategy().ok()?;
    find_policy_in_dir(&base.config_dir().join("tirith"))
}

/// Get tirith data directory.
pub fn data_dir() -> Option<PathBuf> {
    let base = etcetera::choose_base_strategy().ok()?;
    Some(base.data_dir().join("tirith"))
}

/// Get tirith config directory.
pub fn config_dir() -> Option<PathBuf> {
    let base = etcetera::choose_base_strategy().ok()?;
    Some(base.config_dir().join("tirith"))
}

/// Get tirith state directory.
/// Must match bash-hook.bash path: ${XDG_STATE_HOME:-$HOME/.local/state}/tirith
pub fn state_dir() -> Option<PathBuf> {
    match std::env::var("XDG_STATE_HOME") {
        Ok(val) if !val.trim().is_empty() => Some(PathBuf::from(val.trim()).join("tirith")),
        _ => home::home_dir().map(|h| h.join(".local/state/tirith")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_allowlist_domain_matches_subdomain() {
        let p = Policy {
            allowlist: vec!["github.com".to_string()],
            ..Default::default()
        };
        assert!(p.is_allowlisted("https://api.github.com/repos"));
        assert!(p.is_allowlisted("git@github.com:owner/repo.git"));
        assert!(!p.is_allowlisted("https://evil-github.com"));
    }

    #[test]
    fn test_allowlist_schemeless_host() {
        let p = Policy {
            allowlist: vec!["raw.githubusercontent.com".to_string()],
            ..Default::default()
        };
        assert!(p.is_allowlisted("raw.githubusercontent.com/path/to/file"));
    }

    #[test]
    fn test_allowlist_schemeless_host_with_port() {
        let p = Policy {
            allowlist: vec!["example.com".to_string()],
            ..Default::default()
        };
        assert!(p.is_allowlisted("example.com:8080/path"));
    }
}
