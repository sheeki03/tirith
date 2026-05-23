use etcetera::BaseStrategy;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::{Path, PathBuf};

use crate::agent_origin::AgentOrigin;

/// A named scan profile for reusable filter configurations.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ScanProfile {
    #[serde(default)]
    pub include: Vec<String>,
    #[serde(default)]
    pub exclude: Vec<String>,
    #[serde(default)]
    pub fail_on: Option<String>,
    #[serde(default)]
    pub ignore: Vec<String>,
}

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

    /// Require explicit acknowledgement for warn findings in interactive mode.
    #[serde(default)]
    pub strict_warn: bool,

    /// Per-rule action overrides: force action for specific rules (upgrade only: "block").
    #[serde(default)]
    pub action_overrides: HashMap<String, String>,

    /// Escalation rules: upgrade action based on session history or finding count.
    #[serde(default)]
    pub escalation: Vec<crate::escalation::EscalationRule>,

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

    /// Threat intelligence configuration.
    #[serde(default)]
    pub threat_intel: ThreatIntelConfig,

    /// Per-agent governance rules (M4 item 8).
    ///
    /// The engine consults this block via
    /// [`crate::escalation::apply_agent_rules`] inside
    /// [`crate::escalation::post_process_verdict`]: a `deny` match against
    /// [`crate::verdict::Verdict::agent_origin`] forces the action to
    /// [`crate::verdict::Action::Block`] and appends a
    /// [`crate::verdict::RuleId::AgentDeniedByPolicy`] finding. `allow` is
    /// NOT a bypass — a verdict the engine already blocked stays blocked.
    /// See [`agent_decision`] for the matching semantics.
    ///
    /// Known scope limitations (fixed in follow-up commits on this PR): the
    /// `tirith paste` / `install` / `ecosystem scan` paths and the MCP
    /// `tools/call_check_url` / `tools/call_check_paste` handlers stamp
    /// origin for audit but do not yet route through
    /// `post_process_verdict`, so `deny` is currently scoped to `tirith
    /// check`, the gateway, and `tools/call_check_command`. The
    /// `TIRITH=0` interactive bypass also currently skips `apply_agent_rules`.
    ///
    /// See `docs/agent-governance-design.md` for the trust model:
    /// **operator-trust**, never adversary-resistant. The matching strings
    /// are caller-claimed signals (`TIRITH_INTEGRATION`,
    /// `clientInfo.name`, etc.); they are informative, not load-bearing
    /// for security policy alone.
    #[serde(default)]
    pub agent_rules: AgentRules,
}

/// Per-agent governance rules — the policy surface for Milestone 4 item 8.
///
/// The engine consults these rules via
/// [`crate::escalation::apply_agent_rules`] inside
/// [`crate::escalation::post_process_verdict`]. The pure decision helper
/// [`agent_decision`] computes the outcome; the enforcement helper
/// converts a `Denied` outcome into [`crate::verdict::Action::Block`]
/// plus a [`crate::verdict::RuleId::AgentDeniedByPolicy`] finding.
///
/// Two lists, evaluated in this order:
/// 1. **`deny`** — first match wins, returns [`AgentDecision::Denied`]. A
///    deny entry beats any allow entry, mirroring how `blocklist` beats
///    `allowlist` elsewhere in this policy.
/// 2. **`allow`** — first match wins, returns [`AgentDecision::Allowed`].
///    `allow` is NOT a bypass: a verdict the engine already blocked stays
///    blocked even when the caller is on the allow list. Richer
///    "trusted agent" semantics (severity overrides on `allow`, per-origin
///    fail-mode tuning) are deferred pending real telemetry.
///
/// No matcher in either list → [`AgentDecision::Unspecified`], which
/// leaves the verdict unchanged. A verdict with `agent_origin == None`
/// is treated as `Unspecified` for the same reason.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct AgentRules {
    /// Allow entries — when an [`AgentOrigin`] matches one of these and no
    /// deny entry matches first, [`agent_decision`] returns
    /// [`AgentDecision::Allowed`].
    pub allow: Vec<AgentMatcher>,
    /// Deny entries — when an [`AgentOrigin`] matches one of these,
    /// [`agent_decision`] returns [`AgentDecision::Denied`] regardless of
    /// any allow entry.
    pub deny: Vec<AgentMatcher>,
}

/// A single matcher in [`AgentRules`].
///
/// Shape per Q1 of `docs/agent-governance-design.md`: a closed `kind` (the
/// [`AgentOriginKind`] discriminator) plus an optional `name` payload
/// string that, when present, must equal the variant's caller-claimed
/// payload. The kinds-and-payloads structure mirrors [`AgentOrigin`]
/// itself: the operator declares which **category** of caller they care
/// about (closed enum, no smuggling), and optionally pins the specific
/// caller-claimed name (free-form, as the design doc recommends).
///
/// The field is `name` rather than `tool` because the payload string
/// means different things by kind: for `kind: agent` it's an upstream
/// hook tool, for `kind: mcp` it's the client name, for `kind: ci` it's
/// the provider, and for `kind: ide` it's the editor name. `name` is
/// neutral across the closed enum.
///
/// String matching is **case-sensitive exact** — `claude-code` does not
/// match `Claude Code`. The design doc records (Q2) that normalization
/// is intentionally deferred until chunk 3 has a real telemetry sample
/// set; an honest operator declares the same casing the caller emits.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgentMatcher {
    /// The [`AgentOrigin`] category this matcher binds to.
    pub kind: AgentOriginKind,
    /// Optional caller-claimed payload — the `tool` slot on `Agent`, the
    /// `client_name` on `Mcp`, the `provider` on `Ci`, or the `name` on
    /// `Ide`. `Human` and `Gateway` have no payload; a `name` value with
    /// those kinds matches nothing (caught by validation, see
    /// `policy_validate.rs`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
}

/// Closed enum mirroring the [`AgentOrigin`] discriminator.
///
/// A separate type rather than reusing the discriminator inline lets us
/// (a) deserialize a `kind: agent` YAML value cleanly without dragging the
/// whole `AgentOrigin` payload through the matcher schema, and
/// (b) reject an unknown kind at policy-load time rather than silently
/// matching nothing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AgentOriginKind {
    Human,
    Agent,
    Mcp,
    Gateway,
    Ci,
    Ide,
}

impl AgentOriginKind {
    /// The discriminator string used by [`AgentOrigin::kind`]. Kept as a
    /// `match` rather than a `to_lowercase` of `Debug` so it cannot drift
    /// when a future variant lands.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Human => "human",
            Self::Agent => "agent",
            Self::Mcp => "mcp",
            Self::Gateway => "gateway",
            Self::Ci => "ci",
            Self::Ide => "ide",
        }
    }

    /// Parse from the same string [`AgentOrigin::kind`] returns. Used by
    /// `tirith agent allow` to interpret an operator's `--matcher kind=...`
    /// argument.
    pub fn parse(raw: &str) -> Option<Self> {
        match raw.trim() {
            "human" => Some(Self::Human),
            "agent" => Some(Self::Agent),
            "mcp" => Some(Self::Mcp),
            "gateway" => Some(Self::Gateway),
            "ci" => Some(Self::Ci),
            "ide" => Some(Self::Ide),
            _ => None,
        }
    }
}

/// The outcome of consulting [`AgentRules`] against an [`AgentOrigin`].
///
/// Pure data computed by [`agent_decision`]. The engine consumes the value
/// via [`crate::escalation::apply_agent_rules`]: `Denied` forces
/// [`crate::verdict::Action::Block`] and appends a
/// [`crate::verdict::RuleId::AgentDeniedByPolicy`] finding; `Allowed` and
/// `Unspecified` leave the verdict unchanged.
///
/// `Allowed` / `Denied` carry the [`AgentMatcher`] that triggered the
/// decision — the first match wins (deny walked before allow), so the
/// payload is unambiguous. `apply_agent_rules` reads this matcher to
/// name the rule in the injected finding without falling back to
/// `{:?}` formatting on the policy path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AgentDecision {
    /// The origin matched an `allow` matcher and no `deny` matcher (or
    /// `deny` is empty). The carried matcher is the first allow entry
    /// that matched.
    Allowed { matcher: AgentMatcher },
    /// The origin matched a `deny` matcher. Beats any `allow` match.
    /// The carried matcher is the first deny entry that matched.
    Denied { matcher: AgentMatcher },
    /// No matcher in either list applied — the caller falls through.
    Unspecified,
}

/// Pure decision helper. Consulted by the engine via
/// [`crate::escalation::apply_agent_rules`] inside
/// [`crate::escalation::post_process_verdict`].
///
/// Evaluation order:
/// 1. Walk `deny` in declaration order; first match → [`AgentDecision::Denied`].
/// 2. Walk `allow` in declaration order; first match → [`AgentDecision::Allowed`].
/// 3. Fall through → [`AgentDecision::Unspecified`].
///
/// Matching rules per matcher:
/// * `kind` must equal `origin.kind()`.
/// * If `name` is `Some(s)`, the matcher's payload must byte-equal the
///   origin's caller-claimed payload (`Agent::tool`, `Mcp::client_name`,
///   `Ci::provider`, or `Ide::name`). A `name` value applied to
///   `kind: human` or `kind: gateway` is harmless — it simply matches
///   nothing, because those variants carry no caller-claimed payload.
/// * If `name` is `None`, the matcher matches every origin of that
///   `kind` regardless of payload.
///
/// **Caller-trust caveat.** The strings being compared are
/// caller-controlled (see `agent_origin.rs` and `agent-governance-design.md`).
/// A policy author who treats a match as "this came from a trusted
/// caller" is wrong — they would be trusting the same byte an attacker
/// can set. Use `agent_rules` for filtering, dashboarding, and
/// observability; layer real authentication elsewhere if the decision
/// must withstand a hostile environment.
pub fn agent_decision(policy: &Policy, origin: &AgentOrigin) -> AgentDecision {
    if let Some(matcher) = policy
        .agent_rules
        .deny
        .iter()
        .find(|m| matcher_matches(m, origin))
    {
        return AgentDecision::Denied {
            matcher: matcher.clone(),
        };
    }
    if let Some(matcher) = policy
        .agent_rules
        .allow
        .iter()
        .find(|m| matcher_matches(m, origin))
    {
        return AgentDecision::Allowed {
            matcher: matcher.clone(),
        };
    }
    AgentDecision::Unspecified
}

/// True iff the matcher's `kind` equals the origin's kind AND (the
/// matcher has no `name` filter OR the filter byte-equals the origin's
/// caller-claimed payload).
fn matcher_matches(matcher: &AgentMatcher, origin: &AgentOrigin) -> bool {
    if matcher.kind.as_str() != origin.kind() {
        return false;
    }
    let Some(expected) = matcher.name.as_deref() else {
        return true;
    };
    match (matcher.kind, origin) {
        (AgentOriginKind::Agent, AgentOrigin::Agent { tool, .. }) => tool == expected,
        (AgentOriginKind::Mcp, AgentOrigin::Mcp { client_name, .. }) => client_name == expected,
        (AgentOriginKind::Ci, AgentOrigin::Ci { provider }) => {
            provider.as_deref() == Some(expected)
        }
        (AgentOriginKind::Ide, AgentOrigin::Ide { name }) => name == expected,
        // Human / Gateway carry no payload — a `name` filter cannot match.
        _ => false,
    }
}

/// Threat intelligence configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct ThreatIntelConfig {
    /// Auto-update interval in hours. 0 = disabled. Default: 24.
    pub auto_update_hours: u64,
    /// Enable real-time OSV.dev queries. Default: true.
    pub osv_enabled: bool,
    /// Enable real-time deps.dev queries. Default: true.
    pub deps_dev_enabled: bool,
    /// Optional: Google Safe Browsing API key (user gets own free key).
    #[serde(skip_serializing)]
    pub google_safe_browsing_key: Option<String>,
    /// Optional: abuse.ch Auth-Key for URLhaus/ThreatFox feeds.
    #[serde(skip_serializing)]
    pub abusech_auth_key: Option<String>,
    /// Optional: enable Phishing Army feed (CC BY-NC 4.0, non-commercial only).
    pub phishing_army_enabled: bool,
}

impl Default for ThreatIntelConfig {
    fn default() -> Self {
        Self {
            auto_update_hours: 24,
            osv_enabled: true,
            deps_dev_enabled: true,
            google_safe_browsing_key: None,
            abusech_auth_key: None,
            phishing_army_enabled: false,
        }
    }
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
    /// Trusted MCP server NAMES — the keys used in the `mcpServers` /
    /// `servers` object of an MCP config file (e.g. `"github"`, `"fs"`), and
    /// the same names the lockfile stores. A server name listed here:
    ///
    /// * Suppresses `mcp_insecure_server`, `mcp_untrusted_server`,
    ///   `mcp_suspicious_args`, and `mcp_overly_permissive` findings for that
    ///   server (the existing config-file MCP rules in
    ///   `rules/configfile.rs`).
    /// * Filters drift entries with this name out of the
    ///   `mcp_server_drift` finding. If the only drift entries are for
    ///   trusted servers, no drift finding fires; otherwise the trusted
    ///   entries are removed and the rule surfaces only the untrusted ones.
    ///
    /// Names are case-sensitive and matched as literal strings — they are
    /// MCP server identifiers, not URLs. (The field name predates the
    /// per-name semantics; see `mcp_allowed_tools` below for the tighter
    /// per-server tool gate.)
    #[serde(default)]
    pub trusted_mcp_servers: Vec<String>,
    /// Per-server allowed-tools gate. Keys are MCP server names (the same
    /// strings `trusted_mcp_servers` uses); values are the exact tool names
    /// the server may expose.
    ///
    /// Two effects, both via the `mcp_server_drift` rule (no new RuleId —
    /// drift detection is the natural home for "a tool appeared that
    /// policy does not allow"):
    ///
    /// 1. **At drift time, on a newly-added tool.** When `mcp_server_drift`
    ///    detects that the current inventory added a tool to a server whose
    ///    name is a key here, and that tool is NOT in the listed set, the
    ///    drift finding for that server is **upgraded to High severity**
    ///    (the default drift severity is Medium). Drift inside the allowed
    ///    set stays Medium; an `mcp_allowed_tools` entry of `[]` for a
    ///    server therefore forbids ANY tool on that server (every new tool
    ///    is out-of-set).
    /// 2. **At lockfile load, on the lockfile's recorded tools.** When the
    ///    lockfile itself records tools outside the allowed set — for
    ///    example, the lockfile was refreshed against a config that already
    ///    has a tool policy forbids — a `mcp_server_drift` finding fires
    ///    (severity High) naming the disallowed tools. This catches the
    ///    "snuck a tool past `tirith mcp lock`" failure mode.
    ///
    /// A server NOT listed here is unconstrained — `mcp_allowed_tools` is
    /// an opt-in tightening. Combine with `trusted_mcp_servers` to first
    /// declare a server trusted (suppress config-side noise) and then
    /// declare which of its tools are acceptable.
    #[serde(default)]
    pub mcp_allowed_tools: HashMap<String, Vec<String>>,
    /// Glob patterns to ignore during scan.
    #[serde(default)]
    pub ignore_patterns: Vec<String>,
    /// Severity threshold for CI failure (default: "critical").
    #[serde(default)]
    pub fail_on: Option<String>,
    /// Named scan profiles with preset include/exclude/fail_on.
    #[serde(default)]
    pub profiles: HashMap<String, ScanProfile>,
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
            strict_warn: false,
            action_overrides: HashMap::new(),
            escalation: Vec::new(),
            policy_server_url: None,
            policy_server_api_key: None,
            policy_fetch_fail_mode: None,
            enforce_fail_mode: None,
            threat_intel: ThreatIntelConfig::default(),
            agent_rules: AgentRules::default(),
        }
    }
}

impl Policy {
    /// Discover and load partial policy (just bypass + fail_mode fields).
    /// Used in Tier 2 for fast bypass resolution.
    /// Uses the same resolution order as full discovery (TIRITH_POLICY_ROOT,
    /// walk-up, user-level) so bypass settings are consistent.
    pub fn discover_partial(cwd: Option<&str>) -> Self {
        Self::discover_local(cwd)
    }

    /// Discover and load full policy.
    ///
    /// Resolution order:
    /// 1. Local policy (TIRITH_POLICY_ROOT, walk-up discovery, user-level)
    /// 2. If `TIRITH_SERVER_URL` + `TIRITH_API_KEY` are set (or policy has
    ///    `policy_server_url`), try remote fetch. On success the
    ///    remote policy **replaces** the local one entirely and is cached.
    /// 3. On remote failure, apply `policy_fetch_fail_mode`:
    ///    - `"open"` (default): warn and use local policy
    ///    - `"closed"`: return a fail-closed default (all actions = Block)
    ///    - `"cached"`: try cached remote policy, else fall back to local
    /// 4. Auth errors (401/403) always fail closed regardless of mode.
    pub fn discover(cwd: Option<&str>) -> Self {
        let local = Self::discover_local(cwd);

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
            _ => return local,
        };

        let fail_mode = local.policy_fetch_fail_mode.as_deref().unwrap_or("open");

        match crate::policy_client::fetch_remote_policy(&server_url, &api_key) {
            Ok(yaml) => {
                let _ = cache_remote_policy(&yaml);
                match serde_yaml::from_str::<Policy>(&yaml) {
                    Ok(mut p) => {
                        p.path = Some(format!("remote:{server_url}"));
                        // Retain connection details so audit upload can reuse them.
                        if p.policy_server_url.is_none() {
                            p.policy_server_url = Some(server_url);
                        }
                        if p.policy_server_api_key.is_none() {
                            p.policy_server_api_key = Some(api_key);
                        }
                        p
                    }
                    Err(e) => match fail_mode {
                        "closed" => {
                            eprintln!(
                                "tirith: error: remote policy parse error ({e}), failing closed"
                            );
                            Self::fail_closed_policy()
                        }
                        "cached" => {
                            eprintln!(
                                "tirith: warning: remote policy parse error ({e}), trying cache"
                            );
                            match load_cached_remote_policy() {
                                Some(p) => p,
                                None => {
                                    eprintln!(
                                        "tirith: warning: no cached remote policy, using local"
                                    );
                                    local
                                }
                            }
                        }
                        _ => {
                            eprintln!("tirith: warning: remote policy parse error: {e}");
                            local
                        }
                    },
                }
            }
            Err(crate::policy_client::PolicyFetchError::AuthError(code)) => {
                // Auth errors always fail closed, regardless of fail_mode —
                // the server is explicitly saying "no".
                eprintln!("tirith: error: policy server auth failed (HTTP {code}), failing closed");
                Self::fail_closed_policy()
            }
            Err(e) => match fail_mode {
                "closed" => {
                    eprintln!("tirith: error: remote policy fetch failed ({e}), failing closed");
                    Self::fail_closed_policy()
                }
                "cached" => {
                    eprintln!("tirith: warning: remote policy fetch failed ({e}), trying cache");
                    match load_cached_remote_policy() {
                        Some(p) => p,
                        None => {
                            eprintln!("tirith: warning: no cached remote policy, using local");
                            local
                        }
                    }
                }
                _ => {
                    eprintln!(
                        "tirith: warning: remote policy fetch failed ({e}), using local policy"
                    );
                    local
                }
            },
        }
    }

    /// Discover local policy only (no remote fetch).
    fn discover_local(cwd: Option<&str>) -> Self {
        match discover_local_policy_path(cwd) {
            Some(path) => Self::load_from_path(&path),
            None => Policy::default(),
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
        self.allowlist
            .iter()
            .any(|pattern| allowlist_pattern_matches(pattern, url))
    }

    /// Check if a URL is allowlisted for a specific rule or custom rule ID.
    pub fn is_allowlisted_for_rule(&self, rule_id: &str, url: &str) -> bool {
        self.allowlist_rules.iter().any(|rule| {
            rule.rule_id.eq_ignore_ascii_case(rule_id)
                && rule
                    .patterns
                    .iter()
                    .any(|pattern| allowlist_pattern_matches(pattern, url))
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

    /// Load trust entries from trust.json files and merge non-expired entries
    /// into the policy's allowlist and allowlist_rules.
    ///
    /// Called on the analysis hot path — MUST stay read-only (no file mutation).
    pub fn load_trust_entries(&mut self, cwd: Option<&str>) {
        if let Some(config) = config_dir() {
            let user_trust = config.join("trust.json");
            self.merge_trust_store(&user_trust);
        }
        if let Some(repo_root) = find_repo_root(cwd) {
            let repo_trust = repo_root.join(".tirith").join("trust.json");
            self.merge_trust_store(&repo_trust);
        }
    }

    /// Read a trust.json file and merge non-expired entries into the policy.
    fn merge_trust_store(&mut self, path: &Path) {
        let content = match std::fs::read_to_string(path) {
            Ok(c) => c,
            Err(_) => return,
        };

        let store: serde_json::Value = match serde_json::from_str(&content) {
            Ok(v) => v,
            Err(e) => {
                crate::audit::audit_diagnostic(format!(
                    "tirith: trust: corrupt trust store at {} — trust entries skipped: {e}",
                    path.display()
                ));
                return;
            }
        };

        let entries = match store.get("entries").and_then(|v| v.as_array()) {
            Some(arr) => arr,
            None => return,
        };

        let now = chrono::Utc::now();

        for entry in entries {
            // Unparseable or past-expiry timestamps are treated as expired.
            if let Some(exp_str) = entry.get("ttl_expires").and_then(|v| v.as_str()) {
                match chrono::DateTime::parse_from_rfc3339(exp_str) {
                    Ok(expiry) if expiry < now => continue,
                    Ok(_) => {}
                    Err(_) => continue,
                }
            }

            let pattern = match entry.get("pattern").and_then(|v| v.as_str()) {
                Some(p) if !p.is_empty() => p.to_string(),
                _ => continue,
            };

            let rule_id = entry
                .get("rule_id")
                .and_then(|v| v.as_str())
                .map(String::from);

            match rule_id {
                Some(rid) => {
                    if let Some(existing) = self
                        .allowlist_rules
                        .iter_mut()
                        .find(|r| r.rule_id.eq_ignore_ascii_case(&rid))
                    {
                        if !existing.patterns.contains(&pattern) {
                            existing.patterns.push(pattern);
                        }
                    } else {
                        self.allowlist_rules.push(AllowlistRule {
                            rule_id: rid,
                            patterns: vec![pattern],
                        });
                    }
                }
                None => {
                    if !self.allowlist.contains(&pattern) {
                        self.allowlist.push(pattern);
                    }
                }
            }
        }
    }

    /// Load and merge org-level lists from a repo root's .tirith/ dir.
    ///
    /// **Note:** Org-level policies are committed to the repository and may be
    /// controlled by other contributors. A diagnostic is emitted so the user
    /// knows that repo-level policy is active.
    pub fn load_org_lists(&mut self, cwd: Option<&str>) {
        if let Some(repo_root) = find_repo_root(cwd) {
            let org_dir = repo_root.join(".tirith");
            let allowlist_path = org_dir.join("allowlist");
            if let Ok(content) = std::fs::read_to_string(&allowlist_path) {
                eprintln!(
                    "tirith: loading org-level allowlist from {}",
                    allowlist_path.display()
                );
                for line in content.lines() {
                    let line = line.trim();
                    if !line.is_empty() && !line.starts_with('#') {
                        self.allowlist.push(line.to_string());
                    }
                }
            }
            let blocklist_path = org_dir.join("blocklist");
            if let Ok(content) = std::fs::read_to_string(&blocklist_path) {
                eprintln!(
                    "tirith: loading org-level blocklist from {}",
                    blocklist_path.display()
                );
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

pub fn allowlist_pattern_matches(pattern: &str, url: &str) -> bool {
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
    url.to_lowercase().contains(&p)
}

/// Discover policy path by walking up from cwd to .git boundary.
fn discover_policy_path(cwd: Option<&str>) -> Option<PathBuf> {
    let start = cwd
        .map(PathBuf::from)
        .or_else(|| std::env::current_dir().ok())?;

    let mut current = start.as_path();
    loop {
        if let Some(candidate) = find_policy_in_dir(&current.join(".tirith")) {
            return Some(candidate);
        }

        // `.git` may be a directory or a file (worktrees), so `.exists()` handles both.
        let git_dir = current.join(".git");
        if git_dir.exists() {
            return None;
        }

        match current.parent() {
            Some(parent) if parent != current => current = parent,
            _ => break,
        }
    }

    None
}

/// Resolve the path of the local policy that `discover_local` would load, without
/// reading or parsing it. Mirrors `discover_local`'s resolution order exactly:
/// `TIRITH_POLICY_ROOT/.tirith` -> walk-up from cwd to the `.git` boundary -> the
/// user config dir. Returns `None` when no local policy file exists.
///
/// Existence-based: a present-but-unparseable policy file still yields its path
/// here (callers that need a parsed policy use `Policy::discover`).
pub fn discover_local_policy_path(cwd: Option<&str>) -> Option<PathBuf> {
    if let Ok(root) = std::env::var("TIRITH_POLICY_ROOT") {
        if let Some(path) = find_policy_in_dir(&PathBuf::from(&root).join(".tirith")) {
            return Some(path);
        }
    }
    if let Some(path) = discover_policy_path(cwd) {
        return Some(path);
    }
    user_policy_path()
}

/// Find the repository root (directory containing .git).
pub fn find_repo_root(cwd: Option<&str>) -> Option<PathBuf> {
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

/// Find the nearest ancestor directory containing a `.kiro/` subdirectory.
///
/// Mirrors Kiro CLI's own workspace-local agent discovery. Returns the
/// directory that CONTAINS `.kiro/` (not `.kiro/` itself), so callers can
/// `dir.join(".kiro/agents/foo.json")`.
///
/// Excludes `$HOME`: `~/.kiro` is the user-scope agent root, not a project
/// workspace. Without this guard, any project inside `$HOME` would collapse
/// onto the user-scope dir.
pub fn find_workspace_kiro_dir(start: &Path) -> Option<PathBuf> {
    let home = home::home_dir();
    let mut current = start;
    loop {
        let is_home = home.as_deref().map(|h| current == h).unwrap_or(false);
        if !is_home && current.join(".kiro").is_dir() {
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
///
/// MUST match the path computed by bash-hook.bash:
/// `${XDG_STATE_HOME:-$HOME/.local/state}/tirith`. Any divergence here will
/// make the hook and the binary disagree about where session state lives.
/// Treat an empty `XDG_STATE_HOME` as unset to mirror `${VAR:-fallback}`.
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
        .or_else(|| home::home_dir().map(|h| h.join(".cache")))?;
    Some(cache_dir.join("tirith").join("remote-policy.yaml"))
}

/// Cache the raw YAML from a remote policy fetch.
fn cache_remote_policy(yaml: &str) -> std::io::Result<()> {
    if let Some(path) = remote_policy_cache_path() {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
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
    fn test_discover_applies_remote_fetch_fail_mode_when_configured() {
        let _guard = crate::TEST_ENV_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());

        let dir = tempfile::tempdir().unwrap();
        let policy_dir = dir.path().join(".tirith");
        std::fs::create_dir_all(&policy_dir).unwrap();
        std::fs::write(
            policy_dir.join("policy.yaml"),
            "fail_mode: open\npolicy_fetch_fail_mode: closed\nallow_bypass_env_noninteractive: true\n",
        )
        .unwrap();

        unsafe { std::env::set_var("TIRITH_SERVER_URL", "http://127.0.0.1") };
        unsafe { std::env::set_var("TIRITH_API_KEY", "dummy") };

        let policy = Policy::discover(Some(dir.path().to_str().unwrap()));
        assert_eq!(policy.path.as_deref(), Some("fail-closed"));
        assert_eq!(policy.fail_mode, FailMode::Closed);
        assert!(!policy.allow_bypass_env_noninteractive);

        unsafe { std::env::remove_var("TIRITH_API_KEY") };
        unsafe { std::env::remove_var("TIRITH_SERVER_URL") };
    }

    /// Snapshot an env var on construction and restore it on `Drop`.
    /// `TEST_ENV_LOCK` serializes env-mutating tests but does not restore
    /// values; this guard does, so a test cannot leak into another.
    struct EnvVarGuard {
        key: &'static str,
        prev: Option<std::ffi::OsString>,
    }

    impl EnvVarGuard {
        fn set(key: &'static str, value: impl AsRef<std::ffi::OsStr>) -> Self {
            let prev = std::env::var_os(key);
            unsafe { std::env::set_var(key, value) };
            Self { key, prev }
        }

        fn unset(key: &'static str) -> Self {
            let prev = std::env::var_os(key);
            unsafe { std::env::remove_var(key) };
            Self { key, prev }
        }
    }

    impl Drop for EnvVarGuard {
        fn drop(&mut self) {
            match &self.prev {
                Some(v) => unsafe { std::env::set_var(self.key, v) },
                None => unsafe { std::env::remove_var(self.key) },
            }
        }
    }

    #[test]
    fn discover_local_policy_path_prefers_policy_root_over_walkup() {
        let _lock = crate::TEST_ENV_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let isolated_config = tempfile::tempdir().unwrap();
        let _xdg = EnvVarGuard::set("XDG_CONFIG_HOME", isolated_config.path());

        // Both the TIRITH_POLICY_ROOT repo and the cwd carry their own policy.
        let root_repo = tempfile::tempdir().unwrap();
        let cwd_repo = tempfile::tempdir().unwrap();
        for base in [root_repo.path(), cwd_repo.path()] {
            std::fs::create_dir_all(base.join(".tirith")).unwrap();
            std::fs::write(base.join(".tirith/policy.yaml"), "fail_mode: open\n").unwrap();
        }
        let _root = EnvVarGuard::set("TIRITH_POLICY_ROOT", root_repo.path());

        assert_eq!(
            discover_local_policy_path(Some(cwd_repo.path().to_str().unwrap())),
            Some(root_repo.path().join(".tirith/policy.yaml")),
            "TIRITH_POLICY_ROOT must win over cwd walk-up",
        );
    }

    #[test]
    fn discover_local_policy_path_walks_up_to_repo_root() {
        let _lock = crate::TEST_ENV_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let isolated_config = tempfile::tempdir().unwrap();
        let _xdg = EnvVarGuard::set("XDG_CONFIG_HOME", isolated_config.path());
        let _root = EnvVarGuard::unset("TIRITH_POLICY_ROOT");

        let repo = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(repo.path().join(".git")).unwrap();
        std::fs::create_dir_all(repo.path().join(".tirith")).unwrap();
        std::fs::write(repo.path().join(".tirith/policy.yaml"), "fail_mode: open\n").unwrap();
        let subdir = repo.path().join("a/b/c");
        std::fs::create_dir_all(&subdir).unwrap();

        assert_eq!(
            discover_local_policy_path(Some(subdir.to_str().unwrap())),
            Some(repo.path().join(".tirith/policy.yaml")),
            "walk-up from a subdir must find the repo-root policy",
        );
    }

    #[test]
    fn discover_local_policy_path_finds_cwd_policy_without_git() {
        let _lock = crate::TEST_ENV_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let isolated_config = tempfile::tempdir().unwrap();
        let _xdg = EnvVarGuard::set("XDG_CONFIG_HOME", isolated_config.path());
        let _root = EnvVarGuard::unset("TIRITH_POLICY_ROOT");

        // Mimics `tirith policy init` run outside a git repo (e.g. in $HOME):
        // it writes cwd/.tirith/policy.yaml with no .git boundary anywhere.
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(dir.path().join(".tirith")).unwrap();
        std::fs::write(dir.path().join(".tirith/policy.yaml"), "fail_mode: open\n").unwrap();

        assert_eq!(
            discover_local_policy_path(Some(dir.path().to_str().unwrap())),
            Some(dir.path().join(".tirith/policy.yaml")),
            "a cwd-local .tirith/policy.yaml must be found without a .git boundary",
        );
    }

    // -----------------------------------------------------------------------
    // M4 item 8: agent governance schema. These tests cover the data layer
    // — (a) the schema round-trips through YAML, (b) the pure
    // `agent_decision` helper computes Denied/Allowed/Unspecified correctly,
    // and (c) `AgentOriginKind` parses back and forth. The enforcement
    // splice (`apply_agent_rules` inside `post_process_verdict`) is covered
    // by `crates/tirith-core/src/escalation.rs::tests`.
    // -----------------------------------------------------------------------

    #[test]
    fn agent_origin_kind_parses_every_variant() {
        for (raw, expected) in [
            ("human", AgentOriginKind::Human),
            ("agent", AgentOriginKind::Agent),
            ("mcp", AgentOriginKind::Mcp),
            ("gateway", AgentOriginKind::Gateway),
            ("ci", AgentOriginKind::Ci),
            ("ide", AgentOriginKind::Ide),
        ] {
            assert_eq!(AgentOriginKind::parse(raw), Some(expected));
            assert_eq!(expected.as_str(), raw, "as_str must round-trip with parse");
        }
        assert_eq!(AgentOriginKind::parse("telepathy"), None);
        // Whitespace tolerated on the parse side (operator-typed input).
        assert_eq!(
            AgentOriginKind::parse("  agent\t"),
            Some(AgentOriginKind::Agent)
        );
    }

    #[test]
    fn agent_rules_round_trip_through_yaml_is_stable() {
        // Build a policy with a populated agent_rules block, render to YAML,
        // and re-parse: every byte that matters must survive.
        let policy = Policy {
            agent_rules: AgentRules {
                allow: vec![
                    AgentMatcher {
                        kind: AgentOriginKind::Agent,
                        name: Some("claude-code".to_string()),
                    },
                    AgentMatcher {
                        kind: AgentOriginKind::Human,
                        name: None,
                    },
                ],
                deny: vec![AgentMatcher {
                    kind: AgentOriginKind::Mcp,
                    name: Some("untrusted-client".to_string()),
                }],
            },
            ..Default::default()
        };
        let yaml = serde_yaml::to_string(&policy).expect("policy serializes");
        let round: Policy = serde_yaml::from_str(&yaml).expect("policy re-parses");
        assert_eq!(round.agent_rules, policy.agent_rules);
        // The yaml itself must carry the operator-visible keys.
        assert!(yaml.contains("agent_rules"), "missing key: {yaml}");
        assert!(yaml.contains("allow"));
        assert!(yaml.contains("deny"));
        assert!(yaml.contains("claude-code"));
        // `name: None` must NOT serialize as `name: null` — skip_serializing_if
        // keeps it omitted, mirroring chunk-1's AgentOrigin serialization.
        let human_count = yaml.matches("kind: human").count();
        let null_name_count = yaml.matches("name: null").count();
        assert!(
            human_count >= 1,
            "expected at least one kind: human entry in {yaml}",
        );
        assert_eq!(
            null_name_count, 0,
            "name: null leaked into YAML — must be omitted: {yaml}",
        );
    }

    #[test]
    fn agent_rules_empty_block_round_trips() {
        // A policy with the default AgentRules (both lists empty) must
        // round-trip identically.
        let policy = Policy::default();
        let yaml = serde_yaml::to_string(&policy).expect("default policy serializes");
        let round: Policy = serde_yaml::from_str(&yaml).expect("default round-trip parses");
        assert_eq!(round.agent_rules, AgentRules::default());
    }

    #[test]
    fn agent_rules_load_legacy_policy_without_field() {
        // A pre-chunk-2 policy file (no `agent_rules:` key at all) must load
        // cleanly with the default empty AgentRules — additive, never breaking.
        let yaml = "fail_mode: open\nparanoia: 1\n";
        let policy: Policy = serde_yaml::from_str(yaml).expect("legacy parse");
        assert_eq!(policy.agent_rules, AgentRules::default());
        assert!(policy.agent_rules.allow.is_empty());
        assert!(policy.agent_rules.deny.is_empty());
    }

    #[test]
    fn agent_decision_unspecified_when_rules_empty() {
        let policy = Policy::default();
        let origin = AgentOrigin::agent("claude-code", None).unwrap();
        assert_eq!(agent_decision(&policy, &origin), AgentDecision::Unspecified);
    }

    #[test]
    fn agent_decision_allowed_on_kind_match_without_name_filter() {
        let allow_matcher = AgentMatcher {
            kind: AgentOriginKind::Agent,
            name: None,
        };
        let policy = Policy {
            agent_rules: AgentRules {
                allow: vec![allow_matcher.clone()],
                deny: vec![],
            },
            ..Default::default()
        };
        // Any Agent origin matches.
        let claude = AgentOrigin::agent("claude-code", None).unwrap();
        let cursor = AgentOrigin::agent("cursor", None).unwrap();
        assert_eq!(
            agent_decision(&policy, &claude),
            AgentDecision::Allowed {
                matcher: allow_matcher.clone()
            },
        );
        assert_eq!(
            agent_decision(&policy, &cursor),
            AgentDecision::Allowed {
                matcher: allow_matcher
            },
        );
        // A different kind still falls through.
        let human = AgentOrigin::human(true);
        assert_eq!(agent_decision(&policy, &human), AgentDecision::Unspecified);
    }

    #[test]
    fn agent_decision_allowed_on_kind_and_name_exact_match() {
        let allow_matcher = AgentMatcher {
            kind: AgentOriginKind::Agent,
            name: Some("claude-code".to_string()),
        };
        let policy = Policy {
            agent_rules: AgentRules {
                allow: vec![allow_matcher.clone()],
                deny: vec![],
            },
            ..Default::default()
        };
        let claude = AgentOrigin::agent("claude-code", Some("1.2.3")).unwrap();
        // Same kind + exact-payload-match → Allowed (the version slot is
        // ignored by the matcher — only `name` participates).
        assert_eq!(
            agent_decision(&policy, &claude),
            AgentDecision::Allowed {
                matcher: allow_matcher
            },
        );

        // Different payload → falls through.
        let cursor = AgentOrigin::agent("cursor", None).unwrap();
        assert_eq!(agent_decision(&policy, &cursor), AgentDecision::Unspecified);

        // Case mismatch → falls through (case-sensitive exact match, per Q2).
        let upper = AgentOrigin::agent("Claude-Code", None).unwrap();
        assert_eq!(agent_decision(&policy, &upper), AgentDecision::Unspecified);
    }

    #[test]
    fn agent_decision_deny_beats_allow() {
        // A deny entry wins over any allow entry — chunk-2 ordering contract.
        let allow_matcher = AgentMatcher {
            kind: AgentOriginKind::Agent,
            name: None,
        };
        let deny_matcher = AgentMatcher {
            kind: AgentOriginKind::Agent,
            name: Some("bad-actor".to_string()),
        };
        let policy = Policy {
            agent_rules: AgentRules {
                allow: vec![allow_matcher.clone()],
                deny: vec![deny_matcher.clone()],
            },
            ..Default::default()
        };
        let bad = AgentOrigin::agent("bad-actor", None).unwrap();
        // The decision must carry the deny matcher payload — chunk 3 Finding D
        // restored it so `apply_agent_rules` can name the matched rule cleanly.
        assert_eq!(
            agent_decision(&policy, &bad),
            AgentDecision::Denied {
                matcher: deny_matcher
            },
        );
        // But a good actor still gets the broad allow.
        let good = AgentOrigin::agent("claude-code", None).unwrap();
        assert_eq!(
            agent_decision(&policy, &good),
            AgentDecision::Allowed {
                matcher: allow_matcher
            },
        );
    }

    #[test]
    fn agent_decision_payload_filter_on_payloadless_kind_matches_nothing() {
        // Filtering by `name` on Human / Gateway has no payload to match, so
        // the matcher matches nothing. (Validation flags this as a warning;
        // the decision helper must still behave deterministically.)
        let policy = Policy {
            agent_rules: AgentRules {
                allow: vec![
                    AgentMatcher {
                        kind: AgentOriginKind::Human,
                        name: Some("xyz".to_string()),
                    },
                    AgentMatcher {
                        kind: AgentOriginKind::Gateway,
                        name: Some("xyz".to_string()),
                    },
                ],
                deny: vec![],
            },
            ..Default::default()
        };
        // No matcher payload is asserted here — the contract is that NONE of
        // them match, so the variant is Unspecified (no payload to carry).
        assert_eq!(
            agent_decision(&policy, &AgentOrigin::human(true)),
            AgentDecision::Unspecified,
            "name filter on payloadless kind must not match",
        );
        assert_eq!(
            agent_decision(&policy, &AgentOrigin::Gateway),
            AgentDecision::Unspecified,
        );
    }

    #[test]
    fn agent_decision_for_mcp_ci_ide_payloads() {
        let mcp_matcher = AgentMatcher {
            kind: AgentOriginKind::Mcp,
            name: Some("Cursor".to_string()),
        };
        let ci_matcher = AgentMatcher {
            kind: AgentOriginKind::Ci,
            name: Some("github-actions".to_string()),
        };
        let ide_matcher = AgentMatcher {
            kind: AgentOriginKind::Ide,
            name: Some("vscode".to_string()),
        };
        let policy = Policy {
            agent_rules: AgentRules {
                allow: vec![mcp_matcher.clone(), ci_matcher.clone(), ide_matcher.clone()],
                deny: vec![],
            },
            ..Default::default()
        };
        let cursor = AgentOrigin::mcp("Cursor", None).unwrap();
        let gha = AgentOrigin::ci(Some("github-actions"));
        let vsc = AgentOrigin::ide("vscode").unwrap();
        assert_eq!(
            agent_decision(&policy, &cursor),
            AgentDecision::Allowed {
                matcher: mcp_matcher
            },
        );
        assert_eq!(
            agent_decision(&policy, &gha),
            AgentDecision::Allowed {
                matcher: ci_matcher
            },
        );
        assert_eq!(
            agent_decision(&policy, &vsc),
            AgentDecision::Allowed {
                matcher: ide_matcher
            },
        );

        // A generic CI (provider: None) does NOT match a payload filter.
        let generic_ci = AgentOrigin::ci(None);
        assert_eq!(
            agent_decision(&policy, &generic_ci),
            AgentDecision::Unspecified,
            "a payload filter must not match a None provider",
        );
    }

    /// **Chunk-3 retirement note.** The chunk-2 invariant test
    /// `agent_rules_chunk2_loading_changes_no_verdict` asserted that
    /// loading `agent_rules` into a `Policy` did not change any verdict.
    /// That contract was correct *for chunk 2 only* — chunk 3 wires the
    /// `agent_decision` helper into `post_process_verdict`, so a populated
    /// `agent_rules` block CAN now flip a verdict (specifically: a `deny`
    /// match forces Block + injects `RuleId::AgentDeniedByPolicy`).
    ///
    /// The replacement tests live in
    /// `crates/tirith-core/src/escalation.rs::tests` — they exercise the
    /// real splice point (`post_process_verdict`) and pin the four
    /// behavioral arms required by the chunk-3 spec:
    ///
    /// * `agent_rules_deny_forces_block_on_allow_verdict`
    /// * `agent_rules_deny_keeps_block_on_already_blocked_verdict`
    /// * `agent_rules_allow_does_not_bypass_block`
    /// * `agent_rules_unspecified_leaves_verdict_unchanged`
    /// * `agent_rules_unset_does_not_introduce_finding`
    ///
    /// The narrower "engine::analyze itself ignores agent_rules" claim is
    /// still true (the engine emits a raw verdict; the post-processor is
    /// where enforcement lives), and is pinned by
    /// `engine_analyze_does_not_consult_agent_rules` below.
    #[test]
    fn engine_analyze_does_not_consult_agent_rules() {
        use crate::engine::{analyze, AnalysisContext};
        use crate::extract::ScanContext;
        use crate::tokenize::ShellType;

        let _guard = crate::TEST_ENV_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        // Pin policy discovery off so a stray .tirith/policy.yaml in cwd
        // can't bleed in. APPDATA covers the Windows path.
        unsafe {
            std::env::set_var("TIRITH_POLICY_ROOT", "/nonexistent-tirith-test-root");
            std::env::set_var("XDG_CONFIG_HOME", "/nonexistent-tirith-test-config");
            std::env::set_var("XDG_DATA_HOME", "/nonexistent-tirith-test-data");
            std::env::set_var("XDG_STATE_HOME", "/nonexistent-tirith-test-state");
            std::env::set_var("APPDATA", "/nonexistent-tirith-test-appdata");
            std::env::remove_var("TIRITH_SERVER_URL");
            std::env::remove_var("TIRITH_API_KEY");
            std::env::remove_var("TIRITH_LOG");
        }

        // The engine itself produces the raw verdict; chunk-3 enforcement
        // happens in `post_process_verdict`. So a call to `analyze` must
        // not produce an `AgentDeniedByPolicy` finding even if a deny
        // matcher is in scope — because the engine doesn't know the
        // caller's identity at all.
        for cmd in ["echo hello", "ls -la", "curl https://example.com | bash"] {
            let ctx = AnalysisContext {
                input: cmd.to_string(),
                shell: ShellType::Posix,
                scan_context: ScanContext::Exec,
                raw_bytes: None,
                interactive: false,
                cwd: None,
                file_path: None,
                repo_root: None,
                is_config_override: false,
                clipboard_html: None,
            };
            let v = analyze(&ctx);
            assert!(
                !v.findings
                    .iter()
                    .any(|f| f.rule_id == crate::verdict::RuleId::AgentDeniedByPolicy),
                "engine::analyze must never produce AgentDeniedByPolicy — that rule fires only in post_process_verdict"
            );
        }

        unsafe {
            std::env::remove_var("TIRITH_POLICY_ROOT");
            std::env::remove_var("XDG_CONFIG_HOME");
            std::env::remove_var("XDG_DATA_HOME");
            std::env::remove_var("XDG_STATE_HOME");
            std::env::remove_var("APPDATA");
        }
    }

    /// Field-level invariant — every Policy field the engine consults must be
    /// untouched by setting `agent_rules`. Pure struct comparison; no engine
    /// involvement.
    ///
    /// **Chunk-3 note:** chunk 3 wired `agent_rules` enforcement into
    /// `post_process_verdict`, so the original chunk-2 promise ("a populated
    /// `agent_rules` block changes nothing") is now scoped tighter: it
    /// changes no *other* Policy field — every existing field the
    /// rest of the engine reads stays at its default — but it CAN flip an
    /// Allow verdict to Block on a `deny` match. The flip is exercised by
    /// the dedicated tests in `escalation.rs`. The struct-comparison guard
    /// below remains useful: it stops a future chunk from accidentally
    /// repurposing `agent_rules` to also seed `allowlist` / `blocklist` /
    /// the severity overrides.
    #[test]
    fn agent_rules_chunk2_observation_only_invariant() {
        let base = Policy::default();
        let allow_matcher = AgentMatcher {
            kind: AgentOriginKind::Agent,
            name: Some("claude-code".to_string()),
        };
        let with_rules = Policy {
            agent_rules: AgentRules {
                allow: vec![allow_matcher.clone()],
                deny: vec![AgentMatcher {
                    kind: AgentOriginKind::Mcp,
                    name: None,
                }],
            },
            ..Default::default()
        };
        // Every other engine-read field must equal the default policy: chunk
        // 3's `agent_rules` enforcement must not bleed into adjacent
        // mechanisms (allowlist / blocklist / severity overrides / etc.).
        assert_eq!(base.fail_mode, with_rules.fail_mode);
        assert_eq!(base.allow_bypass_env, with_rules.allow_bypass_env);
        assert_eq!(base.paranoia, with_rules.paranoia);
        assert_eq!(base.severity_overrides, with_rules.severity_overrides);
        assert_eq!(base.allowlist, with_rules.allowlist);
        assert_eq!(base.blocklist, with_rules.blocklist);
        assert_eq!(base.approval_rules.len(), with_rules.approval_rules.len());
        assert_eq!(base.action_overrides, with_rules.action_overrides);
        assert_eq!(base.escalation.len(), with_rules.escalation.len());
        assert_eq!(base.strict_warn, with_rules.strict_warn);

        // The decision helper produces sensible answers — and chunk 3 wires
        // these through `post_process_verdict` (see `escalation.rs` tests).
        let origin = AgentOrigin::agent("claude-code", None).unwrap();
        assert_eq!(
            agent_decision(&with_rules, &origin),
            AgentDecision::Allowed {
                matcher: allow_matcher
            },
        );
        assert_eq!(agent_decision(&base, &origin), AgentDecision::Unspecified);
    }
}
