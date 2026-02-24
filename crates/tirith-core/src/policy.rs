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

    // --- Team features (Phase 18) ---
    /// Approval rules: commands matching these rules require human approval.
    #[serde(default)]
    pub approval_rules: Vec<ApprovalRule>,

    /// Network deny list: block commands targeting these hosts/CIDRs.
    #[serde(default)]
    pub network_deny: Vec<String>,

    /// Network allow list: exempt these hosts/CIDRs from network deny.
    #[serde(default)]
    pub network_allow: Vec<String>,

    /// Webhook endpoints to notify on findings.
    #[serde(default)]
    pub webhooks: Vec<WebhookConfig>,

    /// Checkpoint configuration (Pro+).
    #[serde(default)]
    pub checkpoints: CheckpointPolicyConfig,

    /// Scan configuration overrides.
    #[serde(default)]
    pub scan: ScanPolicyConfig,

    /// Per-rule allowlist scoping (Team).
    #[serde(default)]
    pub allowlist_rules: Vec<AllowlistRule>,

    /// Custom detection rules defined in YAML (Team).
    #[serde(default)]
    pub custom_rules: Vec<CustomRule>,

    /// Custom DLP redaction patterns (Team). Regex patterns applied alongside
    /// built-in patterns when redacting commands in audit logs and webhooks.
    #[serde(default)]
    pub dlp_custom_patterns: Vec<String>,

    // --- Policy server (Phase 27, Team) ---
    /// URL of the centralized policy server (e.g., "https://policy.example.com").
    #[serde(default)]
    pub policy_server_url: Option<String>,
    /// API key for authenticating with the policy server.
    #[serde(default)]
    pub policy_server_api_key: Option<String>,
    /// Fail mode for remote policy fetch: "open" (default), "closed", or "cached".
    #[serde(default)]
    pub policy_fetch_fail_mode: Option<String>,
    /// Whether to enforce the fetch fail mode strictly (ignore local fallback on auth errors).
    #[serde(default)]
    pub enforce_fail_mode: Option<bool>,
}

/// Approval rule: when a command matches, require human approval before execution.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApprovalRule {
    /// Rule IDs that trigger approval (e.g., "pipe_to_interpreter").
    pub rule_ids: Vec<String>,
    /// Timeout in seconds (0 = indefinite).
    #[serde(default)]
    pub timeout_secs: u64,
    /// Fallback when approval times out: "block", "warn", or "allow".
    #[serde(default = "default_approval_fallback")]
    pub fallback: String,
}

fn default_approval_fallback() -> String {
    "block".to_string()
}

/// Webhook configuration for event notification.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebhookConfig {
    /// Webhook URL.
    pub url: String,
    /// Minimum severity to trigger webhook.
    #[serde(default = "default_webhook_severity")]
    pub min_severity: Severity,
    /// Optional headers (supports env var expansion: `$ENV_VAR`).
    #[serde(default)]
    pub headers: HashMap<String, String>,
    /// Payload template (supports `{{rule_id}}`, `{{command_preview}}`).
    #[serde(default)]
    pub payload_template: Option<String>,
}

fn default_webhook_severity() -> Severity {
    Severity::High
}

/// Checkpoint policy configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct CheckpointPolicyConfig {
    /// Max checkpoints to retain.
    pub max_count: usize,
    /// Max age in hours.
    pub max_age_hours: u64,
    /// Max total storage in bytes.
    pub max_storage_bytes: u64,
}

impl Default for CheckpointPolicyConfig {
    fn default() -> Self {
        Self {
            max_count: 100,
            max_age_hours: 168,                   // 1 week
            max_storage_bytes: 500 * 1024 * 1024, // 500 MiB
        }
    }
}

/// Scan policy configuration.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct ScanPolicyConfig {
    /// Additional config file paths to scan as priority files.
    #[serde(default)]
    pub additional_config_files: Vec<String>,
    /// Trusted MCP server URLs (suppress McpUntrustedServer for these).
    #[serde(default)]
    pub trusted_mcp_servers: Vec<String>,
    /// Glob patterns to ignore during scan.
    #[serde(default)]
    pub ignore_patterns: Vec<String>,
    /// Severity threshold for CI failure (default: "critical").
    #[serde(default)]
    pub fail_on: Option<String>,
}

/// Per-rule allowlist scoping.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AllowlistRule {
    /// Rule ID to scope the allowlist entry to.
    pub rule_id: String,
    /// Patterns that suppress this specific rule.
    pub patterns: Vec<String>,
}

/// Custom detection rule defined in policy YAML.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CustomRule {
    /// Unique identifier for this custom rule.
    pub id: String,
    /// Regex pattern to match.
    pub pattern: String,
    /// Contexts this rule applies to: "exec", "paste", "file".
    #[serde(default = "default_custom_rule_contexts")]
    pub context: Vec<String>,
    /// Severity level.
    #[serde(default = "default_custom_rule_severity")]
    pub severity: Severity,
    /// Short title for findings.
    pub title: String,
    /// Description for findings.
    #[serde(default)]
    pub description: String,
}

fn default_custom_rule_contexts() -> Vec<String> {
    vec!["exec".to_string(), "paste".to_string()]
}

fn default_custom_rule_severity() -> Severity {
    Severity::High
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
            approval_rules: Vec::new(),
            network_deny: Vec::new(),
            network_allow: Vec::new(),
            webhooks: Vec::new(),
            checkpoints: CheckpointPolicyConfig::default(),
            scan: ScanPolicyConfig::default(),
            allowlist_rules: Vec::new(),
            custom_rules: Vec::new(),
            dlp_custom_patterns: Vec::new(),
            policy_server_url: None,
            policy_server_api_key: None,
            policy_fetch_fail_mode: None,
            enforce_fail_mode: None,
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
                Err(e) => {
                    eprintln!(
                        "tirith: warning: cannot read policy at {}: {e}",
                        path.display()
                    );
                    Policy::default()
                }
            },
            None => Policy::default(),
        }
    }

    /// Discover and load full policy.
    ///
    /// Resolution order:
    /// 1. Local policy (TIRITH_POLICY_ROOT, walk-up discovery, user-level)
    /// 2. Team+ only: if `TIRITH_SERVER_URL` + `TIRITH_API_KEY` are set (or
    ///    policy has `policy_server_url`), try remote fetch. On success the
    ///    remote policy **replaces** the local one entirely and is cached.
    /// 3. On remote failure, apply `policy_fetch_fail_mode`:
    ///    - `"open"` (default): warn and use local policy
    ///    - `"closed"`: return a fail-closed default (all actions = Block)
    ///    - `"cached"`: try cached remote policy, else fall back to local
    /// 4. Auth errors (401/403) always fail closed regardless of mode.
    pub fn discover(cwd: Option<&str>) -> Self {
        // --- Step 1: resolve local policy ---
        let local = Self::discover_local(cwd);

        // Centralized policy fetch is a Team+ feature.
        if crate::license::current_tier() < crate::license::Tier::Team {
            return local;
        }

        // --- Step 2: determine remote fetch parameters ---
        let server_url = std::env::var("TIRITH_SERVER_URL")
            .ok()
            .filter(|s| !s.is_empty())
            .or_else(|| local.policy_server_url.clone());
        let api_key = std::env::var("TIRITH_API_KEY")
            .ok()
            .filter(|s| !s.is_empty())
            .or_else(|| local.policy_server_api_key.clone());

        let (server_url, api_key) = match (server_url, api_key) {
            (Some(u), Some(k)) => (u, k),
            _ => return local, // no remote configured
        };

        let fail_mode = local.policy_fetch_fail_mode.as_deref().unwrap_or("open");

        // --- Step 3: attempt remote fetch ---
        match crate::policy_client::fetch_remote_policy(&server_url, &api_key) {
            Ok(yaml) => {
                // Cache the fetched policy for offline use
                let _ = cache_remote_policy(&yaml);
                match serde_yaml::from_str::<Policy>(&yaml) {
                    Ok(mut p) => {
                        p.path = Some(format!("remote:{server_url}"));
                        // Carry over server connection info so audit upload can use it
                        if p.policy_server_url.is_none() {
                            p.policy_server_url = Some(server_url);
                        }
                        if p.policy_server_api_key.is_none() {
                            p.policy_server_api_key = Some(api_key);
                        }
                        p
                    }
                    Err(e) => {
                        eprintln!("tirith: warning: remote policy parse error: {e}");
                        local
                    }
                }
            }
            Err(crate::policy_client::PolicyFetchError::AuthError(code)) => {
                // Auth errors always fail closed
                eprintln!("tirith: error: policy server auth failed (HTTP {code}), failing closed");
                Self::fail_closed_policy()
            }
            Err(e) => {
                // Apply fail mode
                match fail_mode {
                    "closed" => {
                        eprintln!(
                            "tirith: error: remote policy fetch failed ({e}), failing closed"
                        );
                        Self::fail_closed_policy()
                    }
                    "cached" => {
                        eprintln!(
                            "tirith: warning: remote policy fetch failed ({e}), trying cache"
                        );
                        match load_cached_remote_policy() {
                            Some(p) => p,
                            None => {
                                eprintln!("tirith: warning: no cached remote policy, using local");
                                local
                            }
                        }
                    }
                    _ => {
                        // "open" (default): warn and use local
                        eprintln!(
                            "tirith: warning: remote policy fetch failed ({e}), using local policy"
                        );
                        local
                    }
                }
            }
        }
    }

    /// Discover local policy only (no remote fetch).
    fn discover_local(cwd: Option<&str>) -> Self {
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

    /// Return a fail-closed policy that blocks everything.
    fn fail_closed_policy() -> Self {
        Policy {
            fail_mode: FailMode::Closed,
            allow_bypass_env: false,
            allow_bypass_env_noninteractive: false,
            path: Some("fail-closed".into()),
            ..Default::default()
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
            Err(e) => {
                eprintln!(
                    "tirith: warning: cannot read policy at {}: {e}",
                    path.display()
                );
                Policy::default()
            }
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

/// Get the path for caching remote policy: ~/.cache/tirith/remote-policy.yaml
fn remote_policy_cache_path() -> Option<PathBuf> {
    let cache_dir = std::env::var("XDG_CACHE_HOME")
        .ok()
        .filter(|s| !s.is_empty())
        .map(PathBuf::from)
        .unwrap_or_else(|| home::home_dir().unwrap_or_default().join(".cache"));
    Some(cache_dir.join("tirith").join("remote-policy.yaml"))
}

/// Cache the raw YAML from a remote policy fetch.
fn cache_remote_policy(yaml: &str) -> std::io::Result<()> {
    if let Some(path) = remote_policy_cache_path() {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        // Write with restricted permissions (owner-only)
        let mut opts = std::fs::OpenOptions::new();
        opts.write(true).create(true).truncate(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o600);
        }
        let mut f = opts.open(&path)?;
        use std::io::Write;
        f.write_all(yaml.as_bytes())?;
    }
    Ok(())
}

/// Load a previously cached remote policy.
fn load_cached_remote_policy() -> Option<Policy> {
    let path = remote_policy_cache_path()?;
    let content = std::fs::read_to_string(&path).ok()?;
    match serde_yaml::from_str::<Policy>(&content) {
        Ok(mut p) => {
            p.path = Some(format!("cached:{}", path.display()));
            Some(p)
        }
        Err(e) => {
            eprintln!("tirith: warning: cached remote policy parse error: {e}");
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Mutex to serialize tests that mutate environment variables.
    /// `std::env::set_var` is not thread-safe — concurrent mutation causes UB.
    static ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

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

    #[test]
    fn test_discover_skips_remote_fetch_below_team_tier() {
        let _guard = ENV_LOCK.lock().unwrap();

        let dir = tempfile::tempdir().unwrap();
        let policy_dir = dir.path().join(".tirith");
        std::fs::create_dir_all(&policy_dir).unwrap();
        std::fs::write(
            policy_dir.join("policy.yaml"),
            "fail_mode: open\npolicy_fetch_fail_mode: closed\nallow_bypass_env_noninteractive: true\n",
        )
        .unwrap();

        // Force Community tier regardless of host machine config.
        unsafe { std::env::set_var("TIRITH_LICENSE", "!") };
        unsafe { std::env::set_var("TIRITH_SERVER_URL", "http://127.0.0.1") };
        unsafe { std::env::set_var("TIRITH_API_KEY", "dummy") };

        let policy = Policy::discover(Some(dir.path().to_str().unwrap()));
        assert_ne!(policy.path.as_deref(), Some("fail-closed"));
        assert_eq!(policy.fail_mode, FailMode::Open);
        assert!(policy.allow_bypass_env_noninteractive);
        assert!(policy
            .path
            .as_deref()
            .unwrap_or_default()
            .contains(".tirith"));

        unsafe { std::env::remove_var("TIRITH_API_KEY") };
        unsafe { std::env::remove_var("TIRITH_SERVER_URL") };
        unsafe { std::env::remove_var("TIRITH_LICENSE") };
    }
}
