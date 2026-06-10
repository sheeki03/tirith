use etcetera::BaseStrategy;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap};
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

/// Default `schema_version` for serde: shipping policies omit it and are v1
/// (`u32::default()` of 0 would falsely flag them older than any migration).
fn default_schema_version() -> u32 {
    1
}

/// M8 ch1 — `context_guard_enabled` defaults to `true` (fresh/pre-M8 policies
/// opt in to context detection). Set `false` to silence the rule.
fn default_context_guard_enabled() -> bool {
    true
}

/// F8/F9 — provenance of a loaded [`Policy`]: which discovery branch produced
/// it. Stamped by the loader from the branch that MATCHED, never read from the
/// YAML (`#[serde(skip)]` on the `Policy::scope` field), so a repo cannot spoof
/// a wider trust scope by declaring one in its `.tirith/policy.yaml`.
///
/// Only [`PolicyScope::Repo`] is treated as untrusted: a repo checkout is
/// attacker-controllable content, so its policy is neutralized down to
/// tightening-only via [`Policy::sanitize_repo_scoped`]. Org/User/Remote/Default
/// are operator-controlled and honored in full.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum PolicyScope {
    /// Loaded from a repo-local `.tirith/policy.yaml` (walk-up to `.git`).
    /// UNTRUSTED — may only tighten; suppression/bypass/exfil fields are reset.
    Repo,
    /// Loaded from the user config dir (`~/.config/tirith/policy.yaml`). Trusted.
    User,
    /// Loaded from `TIRITH_POLICY_ROOT/.tirith/policy.yaml` (org/CI mount). Trusted.
    Org,
    /// Loaded from a remote policy server fetch. Trusted (operator-configured).
    Remote,
    /// No policy file found anywhere — the built-in defaults. The DEFAULT and a
    /// NON-repo (trusted) value, so a freshly `Policy::default()`-constructed
    /// policy is never mistaken for repo-scoped and accidentally sanitized.
    #[default]
    Default,
}

/// Policy configuration loaded from YAML.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct Policy {
    /// Path this policy was loaded from.
    #[serde(skip)]
    pub path: Option<String>,

    /// F8/F9 — discovery provenance (which branch loaded this policy). NOT
    /// deserialized (`#[serde(skip)]`): a repo YAML can never set it, so it is a
    /// spoof-proof trust signal. Stamped by the loader; drives
    /// [`Self::sanitize_repo_scoped`] (repo policies may only tighten).
    #[serde(skip)]
    pub scope: PolicyScope,

    /// Schema version (M5.5 F3). Omitted shipping policies are v1; forward
    /// migrations in [`crate::policy_migrations`] run on raw YAML pre-deserialize.
    #[serde(default = "default_schema_version")]
    pub schema_version: u32,

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

    /// **M6 ch7** — package-reputation thresholds and actions (replaces the
    /// hard-coded aggregate-score constants). Empty keeps M6 ch6 behavior; see
    /// [`PackagePolicy`] and its `*_effective` helpers.
    #[serde(default)]
    pub package_policy: PackagePolicy,

    /// Per-agent governance rules (M4 item 8). Consulted via
    /// [`crate::escalation::apply_agent_rules`] in `post_process_verdict`: a
    /// `deny` match forces [`crate::verdict::Action::Block`] + an
    /// `AgentDeniedByPolicy` finding; `allow` is NOT a bypass. Enforced on every
    /// analysis path (the `TIRITH=0` interactive bypass currently skips it).
    /// Operator-trust model only — matched strings are caller-claimed, not
    /// adversary-resistant (see `docs/agent-governance-design.md`).
    #[serde(default)]
    pub agent_rules: AgentRules,

    /// **M7 ch2** — repo-specific patterns `tirith share`/`redact` scrub before
    /// sending content out. Customer/tenant/case IDs are repo-specific so they
    /// live here; cross-org signals ship in `share_patterns.toml`. Empty default.
    #[serde(default)]
    pub share: ShareConfig,

    /// **M8 ch1** — operational-context guard switch. When `true` (default),
    /// `rules::context` flags destructive/write/credential commands against
    /// labeled-production contexts. `false` keeps labels readable for status.
    #[serde(default = "default_context_guard_enabled")]
    pub context_guard_enabled: bool,

    /// **M8 ch1** — operator-supplied destructive verbs per provider. Keys are
    /// provider strings; values are verbs that escalate to
    /// `ContextProdDestructiveCommand` (High) when seen in the first three
    /// positions. Widens the shipped `rules::context` tables without code changes.
    #[serde(default)]
    pub context_destructive_verbs: HashMap<String, Vec<String>>,

    /// **M8 ch1** — `provider:context` → criticality map, populated by
    /// [`Policy::load_context_labels`] from user- and repo-scope label files
    /// (repo wins). NOT serialized — labels live in their own file. Values:
    /// `critical`/`production`/`prod`/`live`/`p0`/`p1` (case-insensitive).
    #[serde(skip)]
    pub context_labels: BTreeMap<String, String>,

    /// **M8 ch2** — `host` (or `user@host`) → criticality map for SSH, populated
    /// by [`Policy::load_ssh_host_labels`] (repo wins). Matcher tries exact
    /// `user@host` then bare host; `~/.ssh/config` aliases are resolved at label
    /// time so the file stores the FINAL hostname. Only critical/prod-tier values
    /// fire the rule; others document the inventory without enforcing.
    #[serde(skip)]
    pub ssh_host_labels: BTreeMap<String, String>,

    /// **M8 ch3** — gate `apply` behind a recorded plan hash. When `true`, the
    /// `rules::iac` apply gate fires `IacApplyWithoutPlan` (no plan) /
    /// `IacPlanHashMismatch` (unrecorded plan SHA-256), both High. `false`
    /// (default) leaves `iac` advisory. Toggled by `tirith iac
    /// require-plan-before-apply on|off`.
    #[serde(default)]
    pub iac_require_plan_before_apply: bool,

    /// **M8 ch4** — when `true`, an active `state_dir()/sudo-session.json`
    /// (from `tirith sudo session start --reason`) downgrades the five sudo
    /// rules High→Medium. `false` (default) leaves the session file
    /// status-only — every sudo rule fires at baseline High. Toggled by
    /// `tirith sudo require-reason on|off`.
    #[serde(default)]
    pub sudo_require_reason: bool,

    /// **M8 ch4** — default `tirith sudo session start` TTL in seconds. `None`
    /// falls back to [`crate::sudo_session::DEFAULT_SESSION_TTL_SECS`] (30 min).
    /// CLI-default only; the rule module never reads it.
    #[serde(default)]
    pub sudo_session_ttl: Option<u64>,

    /// **M9 ch4** — env-var lifecycle guard. When `true`, the two
    /// [`crate::env_guard`] exec-path rules fire from `engine::analyze`
    /// (`EnvSensitiveExposedToUnknownScript` High, `EnvPrintenvToNetworkSink`
    /// Medium). `false` (default) leaves only the `tirith env diff|explain`
    /// surfaces. Toggled by `tirith env guard on|off`.
    #[serde(default)]
    pub env_guard_enabled: bool,

    /// **M9 ch4** — user extension of the sensitive env-var name list, merged
    /// with the built-in `assets/data/sensitive_env.toml` (which is always
    /// included). See [`crate::env_guard::effective_sensitive_vars`].
    #[serde(default)]
    pub env_guard_sensitive_vars: Vec<String>,

    /// **M9 ch5** — exec-provenance/PATH-shadowing hot-path guard. When `true`,
    /// the three CHEAP (stat-free) [`crate::path_audit`] rules fire from
    /// `engine::analyze` in Exec context: `ExecInTmp`/`ExecInRepoBin` (Medium)
    /// and `PathWritableDirBeforeSystem` (High). The seven EXPENSIVE provenance
    /// signals NEVER fire on the hot path (only under `tirith exec`/`path`).
    /// `false` (default) fires nothing here. Toggled by `tirith path guard on|off`.
    #[serde(default)]
    pub exec_guard_enabled: bool,

    /// **M9 ch6** — repo-hook/automation guard. When `true`, the exec hot path
    /// scans git/husky/lefthook/pre-commit hooks (+ `package.json` scripts,
    /// `.envrc`) when the leader is a hook-triggering command, surfacing
    /// `RepoHookNetworkCall`/`RepoHookCredentialRead`/`RepoHookSudo` for only the
    /// hook types that leader triggers. Per-repo mtime-cached 60s. `false`
    /// (default) fires nothing here. Toggled by `tirith hooks guard on|off`.
    #[serde(default)]
    pub hooks_guard_enabled: bool,

    /// **M10 ch5** — opt-in anomaly baseline (D2). When `true`, the exec/paste
    /// hot path records privacy-hashed observations to `state_dir()/baseline.jsonl`
    /// and appends Info-severity `AnomalyFirstTimeInThisRepo`/`AnomalyRareInBaseline`
    /// findings (never changing the action). `false` (default) does NO baseline
    /// I/O on the hot path. Toggled by `tirith baseline learn`.
    #[serde(default)]
    pub baseline_enabled: bool,

    /// **M12 ch1** — trusted install-source hosts for paste provenance.
    /// Consulted only by the `paste_provenance` rule (`PasteSourceMismatch`): a
    /// destination host NOT listed is a risk signal escalating a mismatch to
    /// High; a listed one keeps it at Info. Empty default (backward-compatible).
    /// Case-insensitive, exact-or-dot-suffix subdomain match (so `github.com`
    /// allows `objects.github.com` but not `evilgithub.com`).
    #[serde(default)]
    pub allowed_install_domains: Vec<String>,

    /// Presentation bookkeeping (NOT a policy knob). When this policy is repo-
    /// scoped, [`Self::sanitize_repo_scoped`] records here the YAML key name of
    /// every field whose hostile value it neutralized, so the UX layer can show
    /// the operator exactly which repo settings were ignored. Never serialized
    /// (`#[serde(skip)]`): a repo YAML can neither set nor read it. Empty unless
    /// `sanitize_repo_scoped` ran and found a non-default to reset.
    #[serde(skip)]
    pub neutralized_fields: Vec<&'static str>,
}

/// **M7 ch2** — `tirith share` policy configuration. Empty-default is the
/// supported forward-compat surface.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct ShareConfig {
    /// Repo-specific regex patterns matched against `tirith share`/`redact`
    /// content; each match becomes `[REDACTED:customer_id]`. Patterns over 1024
    /// chars are skipped with a warning. No shipped default (e.g. `CUST-\d{4,6}`).
    pub customer_id_patterns: Vec<String>,
}

/// Per-agent governance rules (M4 item 8). [`agent_decision`] walks `deny`
/// first (first match wins, beats any `allow`), then `allow`; `allow` is NOT a
/// bypass. No match → [`AgentDecision::Unspecified`] (verdict unchanged), as is
/// an `agent_origin == None`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct AgentRules {
    /// Allow entries — matched (with no prior deny) → [`AgentDecision::Allowed`].
    pub allow: Vec<AgentMatcher>,
    /// Deny entries — matched → [`AgentDecision::Denied`] regardless of allow.
    pub deny: Vec<AgentMatcher>,
}

/// A single matcher in [`AgentRules`]: a closed `kind` plus an optional `name`
/// payload that, when present, must equal the variant's caller-claimed payload
/// (the `tool`/`client_name`/`provider`/`name` slot by kind). Matching is
/// case-sensitive exact (normalization deferred). See
/// `docs/agent-governance-design.md`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgentMatcher {
    /// The [`AgentOrigin`] category this matcher binds to.
    pub kind: AgentOriginKind,
    /// Optional caller-claimed payload (the kind-specific slot). `Human`/`Gateway`
    /// have none, so a `name` with those kinds matches nothing (validation flags it).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// M13 ch5 — OPTIONAL advisory predicate: expected filesystem-write scope.
    /// Does NOT affect matching (stays on `kind` + `name`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub filesystem_write: Option<FilesystemWriteScope>,
    /// M13 ch5 — OPTIONAL advisory predicate: network-access treatment. Does not
    /// affect matching.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub network: Option<NetworkPredicate>,
    /// M13 ch5 — OPTIONAL advisory predicate: whether the agent may read secrets.
    /// Does not affect matching.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub secrets_access: Option<SecretsAccessPredicate>,
}

impl Default for AgentMatcher {
    /// `kind: human`, no name, no predicates. Exists for `..Default::default()`
    /// over the M13 predicate fields; every real site sets `kind`, so the
    /// `Human` default is never load-bearing.
    fn default() -> Self {
        Self {
            kind: AgentOriginKind::Human,
            name: None,
            filesystem_write: None,
            network: None,
            secrets_access: None,
        }
    }
}

impl AgentMatcher {
    /// Construct a matcher with `kind` + optional `name` and no M13 predicates
    /// (the pre-M13 shape); the predicate fields default to `None`.
    pub fn new(kind: AgentOriginKind, name: Option<String>) -> Self {
        Self {
            kind,
            name,
            filesystem_write: None,
            network: None,
            secrets_access: None,
        }
    }

    /// Construct a matcher carrying the M13 ch5 semantic predicates.
    pub fn with_predicates(
        kind: AgentOriginKind,
        name: Option<String>,
        filesystem_write: Option<FilesystemWriteScope>,
        network: Option<NetworkPredicate>,
        secrets_access: Option<SecretsAccessPredicate>,
    ) -> Self {
        Self {
            kind,
            name,
            filesystem_write,
            network,
            secrets_access,
        }
    }
}

/// M13 ch5 — filesystem-write scope predicate on an [`AgentMatcher`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FilesystemWriteScope {
    /// Writes confined to the current repository working tree.
    RepoOnly,
    /// Writes allowed anywhere under the user's home directory.
    Home,
    /// Writes allowed anywhere on the filesystem.
    Everywhere,
}

/// M13 ch5 — network-access predicate on an [`AgentMatcher`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NetworkPredicate {
    /// Network access is permitted.
    Allow,
    /// Network access should be surfaced (warned) but not blocked.
    Warn,
    /// Network access should be blocked.
    Block,
}

/// M13 ch5 — secrets-access predicate on an [`AgentMatcher`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SecretsAccessPredicate {
    /// Reading secrets is permitted.
    Allow,
    /// Reading secrets should be blocked.
    Block,
}

impl FilesystemWriteScope {
    /// Parse from the CLI `--filesystem-write <v>` argument value.
    pub fn parse(raw: &str) -> Option<Self> {
        match raw.trim().to_ascii_lowercase().as_str() {
            "repo_only" | "repo-only" | "repo" => Some(Self::RepoOnly),
            "home" => Some(Self::Home),
            "everywhere" | "all" => Some(Self::Everywhere),
            _ => None,
        }
    }
    /// The canonical snake_case string (matches the serde representation).
    pub fn as_str(self) -> &'static str {
        match self {
            Self::RepoOnly => "repo_only",
            Self::Home => "home",
            Self::Everywhere => "everywhere",
        }
    }
}

impl NetworkPredicate {
    /// Parse from the CLI `--network <v>` argument value.
    pub fn parse(raw: &str) -> Option<Self> {
        match raw.trim().to_ascii_lowercase().as_str() {
            "allow" => Some(Self::Allow),
            "warn" => Some(Self::Warn),
            "block" => Some(Self::Block),
            _ => None,
        }
    }
    /// The canonical snake_case string.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Allow => "allow",
            Self::Warn => "warn",
            Self::Block => "block",
        }
    }
}

impl SecretsAccessPredicate {
    /// Parse from the CLI `--secrets-access <v>` argument value.
    pub fn parse(raw: &str) -> Option<Self> {
        match raw.trim().to_ascii_lowercase().as_str() {
            "allow" => Some(Self::Allow),
            "block" => Some(Self::Block),
            _ => None,
        }
    }
    /// The canonical snake_case string.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Allow => "allow",
            Self::Block => "block",
        }
    }
}

/// Closed enum mirroring the [`AgentOrigin`] discriminator (a separate type so
/// a `kind:` value deserializes without the payload, and an unknown kind is
/// rejected at load time rather than silently matching nothing).
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
    /// The discriminator string used by [`AgentOrigin::kind`] (explicit `match`
    /// so it cannot drift when a future variant lands).
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

    /// Parse from the string [`AgentOrigin::kind`] returns (used by `tirith
    /// agent allow`).
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

/// The outcome of consulting [`AgentRules`] against an [`AgentOrigin`] (pure
/// data from [`agent_decision`]). `Denied` forces
/// [`crate::verdict::Action::Block`] + an `AgentDeniedByPolicy` finding;
/// `Allowed`/`Unspecified` leave the verdict unchanged. `Allowed`/`Denied`
/// carry the matched matcher so `apply_agent_rules` can name the rule.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AgentDecision {
    /// Matched an `allow` matcher with no prior `deny`. Carries that matcher.
    Allowed { matcher: AgentMatcher },
    /// Matched a `deny` matcher (beats any allow). Carries that matcher.
    Denied { matcher: AgentMatcher },
    /// No matcher in either list applied — the caller falls through.
    Unspecified,
}

/// Pure decision helper (consulted via `apply_agent_rules` in
/// `post_process_verdict`). Walks `deny` then `allow` in declaration order,
/// first match wins, else `Unspecified`. Per matcher: `kind` must equal
/// `origin.kind()`; a `Some(name)` must byte-equal the origin's caller-claimed
/// payload (a `name` on payloadless `human`/`gateway` matches nothing); `None`
/// matches every origin of that kind.
///
/// **Caller-trust caveat.** The compared strings are caller-controlled, so a
/// match is NOT proof of a trusted caller — use this for filtering/observability,
/// not as a security boundary. See `agent-governance-design.md`.
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

/// True iff `kind` matches AND (no `name` filter OR the filter byte-equals the
/// origin's caller-claimed payload).
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
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
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
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
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
    /// Trusted MCP server NAMES (the `mcpServers`/`servers` keys, also stored in
    /// the lockfile). A listed name suppresses `mcp_insecure_server` /
    /// `mcp_untrusted_server` / `mcp_suspicious_args` / `mcp_overly_permissive`
    /// for that server and filters its entries out of `mcp_server_drift`.
    /// Case-sensitive literal identifiers, not URLs.
    #[serde(default)]
    pub trusted_mcp_servers: Vec<String>,
    /// Per-server allowed-tools gate (keys are server names; values the exact
    /// permitted tool names). Both effects flow through `mcp_server_drift`
    /// (no new RuleId): a newly-added or lockfile-recorded tool outside the set
    /// upgrades/fires the drift finding at High (an `[]` entry forbids any tool).
    /// An unlisted server is unconstrained — this is an opt-in tightening.
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
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AllowlistRule {
    /// Rule ID to scope the allowlist entry to.
    pub rule_id: String,
    /// Patterns that suppress this specific rule.
    pub patterns: Vec<String>,
}

/// Custom detection rule defined in policy YAML. Carries EXACTLY ONE of
/// `pattern` (regex, [`crate::rules::custom`]) or `when` (M13 ch4 DSL,
/// [`crate::custom_rule_dsl`]); [`Self::validate_shape`] enforces the XOR.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CustomRule {
    /// Unique identifier for this custom rule.
    pub id: String,
    /// Regex pattern. Mutually exclusive with `when`; `None` for a DSL rule.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pattern: Option<String>,
    /// M13 ch4 semantic-predicate clause. Mutually exclusive with `pattern`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub when: Option<crate::custom_rule_dsl::WhenClause>,
    /// Contexts this rule applies to: "exec", "paste", "file".
    #[serde(default = "default_custom_rule_contexts")]
    pub context: Vec<String>,
    /// Severity level.
    #[serde(default = "default_custom_rule_severity")]
    pub severity: Severity,
    /// Short title for findings (`message:` is an alias for the DSL example shape).
    #[serde(alias = "message")]
    pub title: String,
    /// Description for findings.
    #[serde(default)]
    pub description: String,
    /// M13 ch4 — optional declared action. RECORDED metadata only in v1: the
    /// effective action still derives from `severity` via `action_from_findings`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub action: Option<crate::verdict::Action>,
}

/// Why a [`CustomRule`]'s shape is invalid (neither or both of pattern/when).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CustomRuleShapeError {
    /// Neither `pattern` nor `when` was supplied.
    Neither,
    /// Both `pattern` and `when` were supplied.
    Both,
}

impl std::fmt::Display for CustomRuleShapeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CustomRuleShapeError::Neither => {
                write!(
                    f,
                    "must have exactly one of `pattern:` or `when:` (has neither)"
                )
            }
            CustomRuleShapeError::Both => {
                write!(
                    f,
                    "must have exactly one of `pattern:` or `when:` (has both)"
                )
            }
        }
    }
}

impl CustomRule {
    /// Validate the pattern-XOR-when invariant (EXACTLY ONE).
    pub fn validate_shape(&self) -> Result<(), CustomRuleShapeError> {
        match (self.pattern.is_some(), self.when.is_some()) {
            (true, false) | (false, true) => Ok(()),
            (false, false) => Err(CustomRuleShapeError::Neither),
            (true, true) => Err(CustomRuleShapeError::Both),
        }
    }
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
            scope: PolicyScope::default(),
            schema_version: default_schema_version(),
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
            package_policy: PackagePolicy::default(),
            agent_rules: AgentRules::default(),
            share: ShareConfig::default(),
            context_guard_enabled: default_context_guard_enabled(),
            context_destructive_verbs: HashMap::new(),
            context_labels: BTreeMap::new(),
            ssh_host_labels: BTreeMap::new(),
            iac_require_plan_before_apply: false,
            sudo_require_reason: false,
            sudo_session_ttl: None,
            env_guard_enabled: false,
            env_guard_sensitive_vars: Vec::new(),
            exec_guard_enabled: false,
            hooks_guard_enabled: false,
            baseline_enabled: false,
            allowed_install_domains: Vec::new(),
            neutralized_fields: Vec::new(),
        }
    }
}

/// M6 ch7 — operator-supplied internal-name pattern for the dependency-confusion
/// heuristic. `name` is a package-name pattern with an optional trailing `*`
/// wildcard; `ecosystem` (npm/pypi/crates.io/...) scopes it, `None` = all.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct InternalPackageSpec {
    /// Optional ecosystem scope (npm / pypi / crates.io / ...). `None`
    /// matches every ecosystem — the M6 ch6 behavior.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ecosystem: Option<String>,
    /// The pattern. A trailing `*` is wildcard.
    pub name: String,
}

impl InternalPackageSpec {
    /// Build a spec from a bare-string pattern (M6 ch6 shape) — used by the
    /// migration to lift the legacy top-level list.
    pub fn from_pattern(name: impl Into<String>) -> Self {
        Self {
            ecosystem: None,
            name: name.into(),
        }
    }
}

/// M6 ch7 — package-reputation thresholds and actions. Every field defaults to
/// the M6 ch6 shipping behavior (the section can be omitted). Threshold fields
/// are read via `*_effective` helpers that fold in the baseline.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct PackagePolicy {
    /// Block when the registry positively reports the package does not
    /// exist (`PackageExistence::NotFound`). Requires `--online`; offline
    /// runs report `Unknown` and this rule never fires.
    pub block_not_found: bool,
    /// Block when the package was first published within this many days
    /// (registry-API age). `None` disables the block path; `Some(N)`
    /// blocks when `package_age_days <= N`.
    pub block_newer_than_days: Option<u32>,
    /// Warn when the package was first published within this many days.
    /// `None` falls back to the M6 ch6 baseline (the
    /// `VERY_NEW_PACKAGE_DAYS` constant in `package_risk`).
    pub warn_newer_than_days: Option<u32>,
    /// Warn when the registry-reported recent downloads fall at or below
    /// this number. `None` disables the warn path.
    pub warn_low_downloads_below: Option<u32>,
    /// Block when `name_vs_popular == Unknown` AND install-script analysis
    /// flagged a network call or shell spawn. Requires the install-script signal
    /// (only available on `--online` install / scan paths, not bare offline).
    pub block_install_scripts_for_unknown_packages: bool,
    /// Block when the package name is within this edit distance of a
    /// known-popular package. `None` disables; `Some(1)` is the strictest
    /// useful setting (one-character typosquats only). Read by
    /// `install_txn`'s `PackagePolicyTyposquatDistance` rule.
    pub block_typosquat_distance: Option<u32>,
    /// Override the aggregate-score block threshold. `None` falls back to
    /// the M6 ch6 baseline of 76 (`risk_level == "critical"`).
    pub block_aggregate_score: Option<u32>,
    /// Override the aggregate-score warn threshold. `None` falls back to
    /// the M6 ch6 baseline of 51 (`risk_level == "high"`).
    pub warn_aggregate_score: Option<u32>,
    /// Block when any OSV advisory's CVSS is at or above this value.
    /// `None` falls back to the M6 ch6 baseline of `7.0`.
    pub block_osv_min_cvss: Option<f32>,
    /// Elevate `PackageRepoMismatch` from its Medium baseline to Block.
    /// Default `false` — the M6 ch6 behavior is "Medium finding only".
    pub block_repo_mismatch: bool,
    /// Whether `PackageInstallScriptNetworkCall` produces a Warn-baseline
    /// finding. Default `true` — the M6 ch6 behavior. Set to `false` to
    /// silence the signal entirely (paranoia-1 / noisy-CI environments).
    pub warn_install_script_network_call: bool,
    /// Whether a `PackageDependencyConfusion` finding blocks. Default
    /// `true` — the rule's M6 ch6 severity is `High` so the Block is the
    /// natural action mapping. Set to `false` to demote to Warn.
    pub block_dependency_confusion: bool,
    /// Operator-supplied internal-name patterns the dependency-confusion
    /// heuristic consumes. Replaces the M6 ch6 top-level
    /// `internal_package_names: Vec<String>` (migrated forward by
    /// [`crate::policy_migrations`] v1→v2).
    pub internal_package_names: Vec<InternalPackageSpec>,
    /// Cap on how many packages the `--online` repo-mismatch check
    /// verifies (ordered by score, highest first). `None` falls back to
    /// the M6 ch6 baseline of 50. Set to `0` via `Some(0)` to disable.
    pub repo_mismatch_check_max_packages: Option<u32>,
}

impl PackagePolicy {
    /// Aggregate-score Block threshold (override or baseline 76).
    pub fn block_aggregate_score_effective(&self) -> u32 {
        self.block_aggregate_score
            .unwrap_or(DEFAULT_BLOCK_AGGREGATE_SCORE)
    }
    /// Aggregate-score Warn threshold (override or baseline 51).
    pub fn warn_aggregate_score_effective(&self) -> u32 {
        self.warn_aggregate_score
            .unwrap_or(DEFAULT_WARN_AGGREGATE_SCORE)
    }
    /// OSV CVSS block threshold (override or baseline 7.0).
    pub fn block_osv_min_cvss_effective(&self) -> f32 {
        self.block_osv_min_cvss
            .unwrap_or(DEFAULT_BLOCK_OSV_MIN_CVSS)
    }
    /// Repo-mismatch verification cap (override or baseline 50).
    pub fn repo_mismatch_check_max_packages_effective(&self) -> u32 {
        self.repo_mismatch_check_max_packages
            .unwrap_or(DEFAULT_REPO_MISMATCH_CHECK_MAX_PACKAGES)
    }
}

/// M6 ch7 baseline thresholds (the previously hard-coded M6 ch6 constants),
/// the single source of truth for the `*_effective` helpers and `policy init`.
pub const DEFAULT_BLOCK_AGGREGATE_SCORE: u32 = 76;
pub const DEFAULT_WARN_AGGREGATE_SCORE: u32 = 51;
pub const DEFAULT_BLOCK_OSV_MIN_CVSS: f32 = 7.0;
pub const DEFAULT_REPO_MISMATCH_CHECK_MAX_PACKAGES: u32 = 50;

impl Default for PackagePolicy {
    fn default() -> Self {
        Self {
            block_not_found: false,
            block_newer_than_days: None,
            warn_newer_than_days: None,
            warn_low_downloads_below: None,
            block_install_scripts_for_unknown_packages: false,
            block_typosquat_distance: None,
            block_aggregate_score: None,
            warn_aggregate_score: None,
            block_osv_min_cvss: None,
            block_repo_mismatch: false,
            // Keep the M6 ch6 Warn-baseline install-script signal on by default.
            warn_install_script_network_call: true,
            // M6 ch6 dep-confusion is High → Block; `true` preserves that.
            block_dependency_confusion: true,
            internal_package_names: Vec::new(),
            repo_mismatch_check_max_packages: None,
        }
    }
}

impl Policy {
    /// Discover and load partial policy (bypass + fail_mode), for the tier-2
    /// fast bypass path. Same resolution order as full discovery, and M11 ch5
    /// incident overrides are applied here too so a `TIRITH=0` bypass honors an
    /// active incident.
    pub fn discover_partial(cwd: Option<&str>) -> Self {
        let mut p = Self::discover_local(cwd);
        p.apply_runtime_overrides();
        p
    }

    /// Discover and load full policy. Resolution order: local
    /// (TIRITH_POLICY_ROOT / walk-up / user) then, if a server is configured,
    /// remote fetch (which fully replaces local on success and is cached). On
    /// remote failure `policy_fetch_fail_mode` decides open/closed/cached; auth
    /// errors (401/403) always fail closed. M11 ch5 incident overrides are then
    /// merged via [`Self::apply_runtime_overrides`].
    pub fn discover(cwd: Option<&str>) -> Self {
        let mut p = Self::discover_resolved(cwd);
        p.apply_runtime_overrides();
        p
    }

    /// Discover the EFFECTIVE policy OFFLINE — local resolution
    /// ([`Self::discover_local`]) + the incident override merge, but
    /// DELIBERATELY skipping the entire remote branch (no env probe, no
    /// `policy_server_url`, no fetch), so it can never hang or leak. For local
    /// reporting surfaces (e.g. `tirith dashboard`'s "no network calls"
    /// promise); the hot enforcement path uses [`Self::discover`]. Returns the
    /// bare local policy — the read-only overlay helpers are NOT applied here.
    pub fn discover_local_only(cwd: Option<&str>) -> Self {
        let mut p = Self::discover_local(cwd);
        p.apply_runtime_overrides();
        p
    }

    /// The local/remote resolution body for [`Self::discover`], WITHOUT the
    /// incident-override merge (split out so the override applies exactly once
    /// regardless of which remote-fetch branch produced the policy).
    fn discover_resolved(cwd: Option<&str>) -> Self {
        let local = Self::discover_local(cwd);

        // F8 — track the ORIGIN of each connection field so an ambient
        // (env-sourced) key is never paired with a server URL that came from a
        // REPO-scoped policy. After F9 a repo's `policy_server_url` is already
        // `None`, so the fallback below cannot select a repo URL; this is the
        // explicit belt-and-suspenders guard. `true` = ambient env origin.
        let url_from_env = std::env::var("TIRITH_SERVER_URL")
            .ok()
            .filter(|s| !s.is_empty());
        let server_url_is_env = url_from_env.is_some();
        let server_url = url_from_env.or_else(|| local.policy_server_url.clone());

        let key_from_env = std::env::var("TIRITH_API_KEY")
            .ok()
            .filter(|s| !s.is_empty());
        let api_key_is_env = key_from_env.is_some();
        let api_key = key_from_env.or_else(|| local.policy_server_api_key.clone());

        let (server_url, api_key) = match (server_url, api_key) {
            (Some(u), Some(k)) => (u, k),
            _ => return local,
        };

        // F8 guard: an AMBIENT env key must only authenticate to a server URL
        // that is itself operator-controlled — env-sourced, OR a non-repo local
        // scope. A URL drawn from a repo-scoped policy paired with an ambient
        // key would leak that key to repo-controlled infrastructure; refuse and
        // fall back to the local policy (no fetch).
        if api_key_is_env && !server_url_is_env && local.scope == PolicyScope::Repo {
            eprintln!(
                "tirith: warning: refusing to send ambient TIRITH_API_KEY to a repo-scoped policy_server_url; using local policy"
            );
            return local;
        }

        let fail_mode = local.policy_fetch_fail_mode.as_deref().unwrap_or("open");

        match crate::policy_client::fetch_remote_policy(&server_url, &api_key) {
            Ok(yaml) => {
                let _ = cache_remote_policy(&yaml);
                // Migrations run on remote YAML the same as local (M5.5 F3).
                match Self::try_parse_yaml(&yaml) {
                    Ok(mut p) => {
                        p.path = Some(format!("remote:{server_url}"));
                        // F8/F9 — a remote-server policy is operator-controlled
                        // (trusted); stamp Remote so it is never sanitized as a repo.
                        p.scope = PolicyScope::Remote;
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
                // Auth errors always fail closed regardless of fail_mode.
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

    /// Discover local policy only (no remote fetch). Stamps [`Self::scope`] from
    /// the discovery BRANCH (F8/F9) and, when that branch is
    /// [`PolicyScope::Repo`], neutralizes the loaded policy down to
    /// tightening-only via [`Self::sanitize_repo_scoped`] — a repo checkout is
    /// attacker-controllable, so it may add restrictions but never relax,
    /// suppress, or exfil.
    fn discover_local(cwd: Option<&str>) -> Self {
        match discover_local_policy_path_scoped(cwd) {
            Some((path, scope)) => {
                let mut p = Self::load_from_path(&path);
                p.scope = scope;
                // F9 — default-deny on the untrusted (repo) branch ONLY. Org/User
                // are operator-controlled and honored in full. Runs right after
                // load so the policy.yaml suppression/bypass/exfil fields are
                // neutralized before any caller sees the policy. (The parallel
                // repo flat-file suppression channel is closed in
                // [`Self::load_org_lists`]; the repo `.tirith/trust.json` overlay
                // is no longer auto-honored by [`Self::load_trust_entries`] — only
                // the user-scope trust store is merged.)
                if scope == PolicyScope::Repo {
                    p.sanitize_repo_scoped();
                }
                p
            }
            None => Policy::default(),
        }
    }

    /// F9 — neutralize a REPO-scoped policy down to tightening-only. A repo
    /// checkout is attacker-controllable content, so its `.tirith/policy.yaml`
    /// must never be able to WEAKEN, SUPPRESS, or EXFIL. This resets every field
    /// a hostile repo could use for those ends back to the
    /// [`Policy::default()`] value.
    ///
    /// RESET (a repo could WEAKEN/SUPPRESS/EXFIL through these):
    /// * `allowlist`, `allowlist_rules`, `network_allow`,
    ///   `additional_known_domains`, `severity_overrides` — drop or downgrade a
    ///   finding (engine.rs `findings.retain` + the severity-override path).
    /// * `allow_bypass_env`, `allow_bypass_env_noninteractive` — re-enable the
    ///   `TIRITH=0` bypass.
    /// * `policy_fetch_fail_mode`, `enforce_fail_mode` — steer a remote-fetch
    ///   failure toward open/cached.
    /// * `webhooks`, `policy_server_url`, `policy_server_api_key`,
    ///   `dlp_custom_patterns` — exfil findings / redirect discovery to a
    ///   repo-controlled sink.
    /// * `context_guard_enabled` — `false` disables the M8 operational-context
    ///   destructive-command guard (`rules::context`/`container`/`iac`
    ///   early-return). Pure suppression.
    /// * `package_policy` — demote/silence supply-chain findings
    ///   (`install_txn`): `block_dependency_confusion`/
    ///   `warn_install_script_network_call` flips, raised
    ///   `block_aggregate_score`/`warn_aggregate_score`/`block_osv_min_cvss`.
    ///   Several fire OFFLINE (typosquat distance, aggregate score).
    /// * `threat_intel` — `osv_enabled`/`deps_dev_enabled: false` disable
    ///   advisory lookups (`threatdb_api`); also a home for planted API keys.
    /// * `allowed_install_domains` — listing the attacker's host DOWNGRADES
    ///   `PasteSourceMismatch` from High to Info (`rules::paste_provenance`).
    /// * `scan.trusted_mcp_servers` — listing a server NAME silences
    ///   `mcp_insecure_server`/`mcp_untrusted_server`/`mcp_suspicious_args`/
    ///   `mcp_overly_permissive` and filters drift (`rules::configfile`/
    ///   `mcpdrift`). `scan.ignore_patterns`/`fail_on`/`profiles` suppress the
    ///   `tirith scan` walk / relax its CI gate. All reset.
    ///
    /// LEFT INTACT (tightening-only or inert at repo scope, each verified):
    /// * `blocklist`, `network_deny` — only ADD blocks.
    /// * `approval_rules` — only ADD an approval gate.
    /// * `action_overrides` — upgrade-only ("block"), validated at load.
    /// * `escalation` — `EscalationAction` is Block-only (never a downgrade).
    /// * `custom_rules` — only ADD detections.
    /// * `paranoia` — `retain_by_paranoia` keeps Medium+ at any tier; raising it
    ///   keeps MORE Info/Low. A lower value is never weaker than the default 1.
    /// * `strict_warn`, the M8/M9 guard toggles (`iac_require_plan_before_apply`,
    ///   `sudo_require_reason`, `env_guard_enabled`, `exec_guard_enabled`,
    ///   `hooks_guard_enabled`, `baseline_enabled`) — default `false`/off; a repo
    ///   can only turn them ON, which adds rules. `context_destructive_verbs`,
    ///   `env_guard_sensitive_vars` only WIDEN the destructive/sensitive sets.
    /// * `agent_rules` — `deny` tightens; `allow` is NOT a bypass (escalation.rs).
    /// * `checkpoints`, `sudo_session_ttl`, `scan.additional_config_files`/
    ///   `mcp_allowed_tools` — retention/coverage/tightening, never a guard relax.
    /// * `share` (`customer_id_patterns`) — only ADDS redactions (more scrubbing).
    /// * `schema_version`, `fail_mode`, `webhooks` `min_severity` — inert here
    ///   (`fail_mode: open` is already the default; a repo `closed` only tightens).
    /// * `context_labels`/`ssh_host_labels` — `#[serde(skip)]`, loaded separately.
    ///
    /// Whenever a new [`Policy`] field is added, classify it here AND in the
    /// `f9_sanitize_classification_is_exhaustive` tripwire test (which fails to
    /// compile until the field is accounted for).
    ///
    /// Only called for [`PolicyScope::Repo`] (see [`Self::discover_local`]).
    fn sanitize_repo_scoped(&mut self) {
        let defaults = Policy::default();

        // Presentation bookkeeping (design C): record the YAML key of every field
        // we neutralize so the UX layer can tell the operator exactly which repo
        // settings were ignored. `record` pushes a key only when the field is
        // about to actually change; the reset that follows is byte-for-byte the
        // historical behavior — recording NEVER alters a final field value.
        // `neutralized_fields` is reset first so a re-sanitize is idempotent.
        self.neutralized_fields.clear();
        let mut neutralized: Vec<&'static str> = Vec::new();
        macro_rules! record {
            // Field-equality form: reset target is the default's value for the
            // field, so "changed" == "differs from default".
            ($key:expr, $field:ident) => {
                if self.$field != defaults.$field {
                    neutralized.push($key);
                }
            };
            // Explicit-predicate form: the reset target is a literal (false /
            // None) that may NOT be the Default (e.g. `allow_bypass_env` defaults
            // to true but is forced false). `$changed` is a bool that is true iff
            // the current value differs from that reset target.
            ($key:expr, $changed:expr) => {
                if $changed {
                    neutralized.push($key);
                }
            };
        }

        // Suppression vectors — a repo must not be able to DROP a finding. The
        // engine's allowlist/allowlist_rules path (engine.rs `findings.retain`)
        // and severity downgrades are the documented suppression surfaces.
        record!("allowlist", allowlist);
        record!("allowlist_rules", allowlist_rules);
        record!("network_allow", network_allow);
        record!("additional_known_domains", additional_known_domains);
        record!("severity_overrides", severity_overrides);
        self.allowlist = defaults.allowlist;
        self.allowlist_rules = defaults.allowlist_rules;
        self.network_allow = defaults.network_allow;
        self.additional_known_domains = defaults.additional_known_domains;
        self.severity_overrides = defaults.severity_overrides;

        // Bypass / remote-fail relaxation — a repo must not be able to re-enable
        // the `TIRITH=0` bypass or steer remote-fetch failure toward open/cached.
        // NOTE: `allow_bypass_env` defaults to TRUE (permissive), so leaving/omitting
        // it (the common case for ANY repo policy) is NOT a weakening attempt — it is
        // forced false for safety regardless. We deliberately do NOT record it, so the
        // operator-facing "ignored weakening fields" notice never fires for a
        // tightening-only repo. `allow_bypass_env_noninteractive` defaults FALSE, so a
        // `true` there IS an explicit weakening and is recorded. The resets below are
        // unchanged.
        record!(
            "allow_bypass_env_noninteractive",
            self.allow_bypass_env_noninteractive
        );
        record!(
            "policy_fetch_fail_mode",
            self.policy_fetch_fail_mode.is_some()
        );
        record!("enforce_fail_mode", self.enforce_fail_mode.is_some());
        self.allow_bypass_env = false;
        self.allow_bypass_env_noninteractive = false;
        self.policy_fetch_fail_mode = None;
        self.enforce_fail_mode = None;

        // Exfil / remote redirection — a repo must not be able to ship findings
        // to its own webhook or point discovery at its own policy server.
        record!("webhooks", webhooks);
        record!("policy_server_url", self.policy_server_url.is_some());
        record!(
            "policy_server_api_key",
            self.policy_server_api_key.is_some()
        );
        record!("dlp_custom_patterns", dlp_custom_patterns);
        self.webhooks = defaults.webhooks;
        self.policy_server_url = None;
        self.policy_server_api_key = None;
        self.dlp_custom_patterns = defaults.dlp_custom_patterns;

        // Guard-disable suppression — a repo must not be able to turn OFF a guard
        // that defaults ON, demote/silence supply-chain findings, disable threat
        // lookups, or downgrade a paste-source mismatch by self-listing its host.
        record!("context_guard_enabled", context_guard_enabled);
        record!("package_policy", package_policy);
        record!("threat_intel", threat_intel);
        record!("allowed_install_domains", allowed_install_domains);
        self.context_guard_enabled = defaults.context_guard_enabled;
        self.package_policy = defaults.package_policy.clone();
        self.threat_intel = defaults.threat_intel.clone();
        self.allowed_install_domains = defaults.allowed_install_domains.clone();

        // MCP / scan suppression — a `trusted_mcp_servers` NAME silences the four
        // MCP config rules + drift; `ignore_patterns`/`fail_on`/`profiles` suppress
        // the `tirith scan` walk or relax its CI gate. Reset the weakening scan
        // sub-fields; `additional_config_files` and `mcp_allowed_tools` are
        // tightening (more coverage / an opt-in tool allow-list) and stay.
        if self.scan.trusted_mcp_servers != defaults.scan.trusted_mcp_servers {
            neutralized.push("scan.trusted_mcp_servers");
        }
        if self.scan.ignore_patterns != defaults.scan.ignore_patterns {
            neutralized.push("scan.ignore_patterns");
        }
        if self.scan.fail_on != defaults.scan.fail_on {
            neutralized.push("scan.fail_on");
        }
        // `scan.profiles` (HashMap<String, ScanProfile>) has no PartialEq; its
        // default is empty, so a non-empty map is an author-set (weakening) value.
        if !self.scan.profiles.is_empty() {
            neutralized.push("scan.profiles");
        }
        self.scan.trusted_mcp_servers = defaults.scan.trusted_mcp_servers.clone();
        self.scan.ignore_patterns = defaults.scan.ignore_patterns.clone();
        self.scan.fail_on = defaults.scan.fail_on.clone();
        self.scan.profiles = defaults.scan.profiles.clone();

        self.neutralized_fields = neutralized;
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
        // Read via the no-follow, size-capped reader (mirrors `merge_context_labels`
        // / repo_hooks / scan). The matched file may be an attacker-controlled repo
        // `.tirith/policy.yaml`, consumed HERE — BEFORE `scope == Repo` sanitization
        // runs in `discover_local` — so a plain `read_to_string` would let a repo
        // make it a FIFO (hang), a huge file (memory blow-up), or a symlink
        // (redirect the read). `read_text_no_follow_capped` refuses non-regular /
        // symlinked / oversize files. ANY read error on a NAMED policy file is a
        // misconfiguration (or a hostile special file), not "no policy" — fail
        // closed (the open default is only for "no policy found anywhere", handled
        // by the discovery walk).
        let bytes = match crate::util::read_text_no_follow_capped(path, POLICY_FILE_READ_CAP) {
            Ok(b) => b,
            Err(e) => {
                eprintln!(
                    "tirith: warning: cannot read policy at {}: {e:?}",
                    path.display()
                );
                return Self::fail_closed_policy();
            }
        };
        let content = match String::from_utf8(bytes) {
            Ok(c) => c,
            Err(e) => {
                eprintln!(
                    "tirith: warning: policy at {} is not valid UTF-8: {e}",
                    path.display()
                );
                return Self::fail_closed_policy();
            }
        };
        let source = path.display().to_string();
        match Self::try_parse_yaml(&content) {
            Ok(mut p) => {
                p.path = Some(source);
                p
            }
            Err(e) => {
                eprintln!("tirith: warning: policy load failed at {source}: {e}");
                // Same logic: a parse failure on a named policy file hides the
                // operator's config — fail closed, don't silently revert to open.
                Self::fail_closed_policy()
            }
        }
    }

    /// Parse YAML into a `Policy`, running migrations first. Returns
    /// `Err(message)` rather than printing+falling back, for fail-mode-aware
    /// callers (remote fetch); [`Self::load_from_yaml`] wraps it warn-and-default.
    pub fn try_parse_yaml(content: &str) -> Result<Self, String> {
        let mut value: serde_yaml::Value =
            serde_yaml::from_str(content).map_err(|e| format!("yaml parse error: {e}"))?;
        crate::policy_migrations::migrate_forward(&mut value)
            .map_err(|e| format!("migration error: {e}"))?;
        let policy = serde_yaml::from_value::<Policy>(value)
            .map_err(|e| format!("deserialize error: {e}"))?;

        // Enforce the pattern-XOR-when invariant at LOAD time (CodeRabbit M13
        // R3): a both/neither rule is a silent no-op, so reject the whole policy
        // here — the single chokepoint every load path routes through.
        //
        // DUPLICATE rule IDs are deliberately NOT rejected here: `compile_rules`
        // does not dedup so both fire (runtime-BENIGN), and hard-failing would
        // flip the engine fail-CLOSED (load_from_path maps parse Err to
        // fail_closed_policy) and pre-empt `tirith rule validate`, which needs the
        // policy to PARSE first. Duplicates are reported by the lenient `policy
        // validate` / `rule validate` validators instead.
        for (idx, rule) in policy.custom_rules.iter().enumerate() {
            rule.validate_shape()
                .map_err(|e| format!("custom_rules[{idx}] (id '{}'): {e}", rule.id))?;
        }

        Ok(policy)
    }

    /// Load a policy from YAML text, running migrations first. Public so tests
    /// can exercise the migrate-then-deserialize sequence without the filesystem.
    pub fn load_from_yaml(content: &str, source: Option<&str>) -> Self {
        match Self::try_parse_yaml(content) {
            Ok(mut p) => {
                p.path = source.map(|s| s.to_string());
                p
            }
            Err(e) => {
                eprintln!(
                    "tirith: warning: policy load failed{}: {e}",
                    source.map(|s| format!(" at {s}")).unwrap_or_default(),
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

    /// **M11 ch5** — merge incident-mode runtime overrides in place. On an
    /// active incident ([`crate::incident::active_cached`]): `fail_mode` →
    /// Closed, both `allow_bypass_env*` → false, and each
    /// [`crate::incident::INCIDENT_ELEVATED_RULES`] entry raised (never lowered)
    /// in `severity_overrides`. Runs on EVERY analyze; the no-incident fast path
    /// is a near-noop behind a 5s per-process stat cache.
    pub fn apply_runtime_overrides(&mut self) {
        // Near-noop fast path: no active incident → leave the policy untouched.
        if crate::incident::active_cached().is_none() {
            return;
        }

        // Incident active: force fail-closed and disable the env bypass in both
        // modes (this is what makes `tirith check` ignore `TIRITH=0`).
        self.fail_mode = FailMode::Closed;
        self.allow_bypass_env = false;
        self.allow_bypass_env_noninteractive = false;

        // Elevate the curated rule set — only ever raising severity.
        for (rule, elevated) in crate::incident::INCIDENT_ELEVATED_RULES {
            let Some(key) = serde_json::to_value(rule)
                .ok()
                .and_then(|v| v.as_str().map(String::from))
            else {
                continue;
            };
            match self.severity_overrides.get(&key).copied() {
                // Operator pin already at/above the incident level — keep it.
                Some(existing) if existing >= *elevated => {}
                // No override, or a lower one: raise to the incident level.
                _ => {
                    self.severity_overrides.insert(key, *elevated);
                }
            }
        }
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

    /// **M8 ch1** — merge user- then repo-scope context-label files (repo wins)
    /// into `context_labels`. Flat YAML map `provider:context: criticality`;
    /// missing/empty files are fine, parse errors are diagnosed and skipped.
    pub fn load_context_labels(&mut self, cwd: Option<&str>) {
        if let Some(user_path) = user_context_labels_path() {
            merge_context_labels(&user_path, &mut self.context_labels);
        }
        if let Some(repo_root) = find_repo_root(cwd) {
            let repo_path = repo_root.join(".tirith").join("context-labels.yaml");
            merge_context_labels(&repo_path, &mut self.context_labels);
        }
    }

    /// **M8 ch2** — merge user- then repo-scope SSH host-label files (repo wins)
    /// into `ssh_host_labels`. Flat YAML map `host: criticality` (host may carry
    /// a `user@` prefix; lookup is exact with bare-host fallback).
    pub fn load_ssh_host_labels(&mut self, cwd: Option<&str>) {
        if let Some(user_path) = user_ssh_host_labels_path() {
            merge_context_labels(&user_path, &mut self.ssh_host_labels);
        }
        if let Some(repo_root) = find_repo_root(cwd) {
            let repo_path = repo_root.join(".tirith").join("ssh-host-labels.yaml");
            merge_context_labels(&repo_path, &mut self.ssh_host_labels);
        }
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

    /// Merge non-expired trust.json entries into allowlist/allowlist_rules.
    /// On the analysis hot path — MUST stay read-only (no file mutation).
    ///
    /// F9 — ONLY the USER `config_dir/trust.json` (operator-controlled, trusted)
    /// is merged. The repo `<repo>/.tirith/trust.json` is NOT auto-honored: it is
    /// attacker-controllable repo content, so a malicious repo could SHIP a
    /// pre-populated trust.json full of non-expired entries and thereby recover
    /// exactly the suppression channel F9 removes — the same class as the repo
    /// `allowlist` field ([`Self::sanitize_repo_scoped`]) and the repo flat-
    /// allowlist file ([`Self::load_org_lists`]), both already skipped. To trust
    /// an entry, add it at user scope (`tirith trust --scope user`); committed
    /// `--scope repo` entries are recorded but no longer auto-suppress.
    pub fn load_trust_entries(&mut self, _cwd: Option<&str>) {
        if let Some(config) = config_dir() {
            let user_trust = config.join("trust.json");
            self.merge_trust_store(&user_trust);
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

    /// Load and merge the REPO-scoped `.tirith/` flat lists (allowlist /
    /// blocklist text files) found by walking up to the repo root.
    ///
    /// F9 — this dir is attacker-influenceable repo content (same trust level as
    /// `.tirith/policy.yaml`), so it is held to the SAME tightening-only rule as
    /// [`Self::sanitize_repo_scoped`]: the repo **blocklist** (a restriction) is
    /// honored, but the repo **allowlist** (a SUPPRESSION) is NOT — otherwise a
    /// hostile repo could re-introduce, via the flat file, exactly the
    /// finding-dropping that the policy.yaml sanitizer just removed. The allowlist
    /// load is skipped unconditionally here (the flat file is always repo-scoped),
    /// not merely when a `policy.yaml` set `scope == Repo`, so a repo that ships
    /// ONLY `.tirith/allowlist` (no policy.yaml) is covered too.
    pub fn load_org_lists(&mut self, cwd: Option<&str>) {
        if let Some(repo_root) = find_repo_root(cwd) {
            let org_dir = repo_root.join(".tirith");
            // F9 — repo allowlist (suppression) is intentionally NOT loaded.
            let allowlist_path = org_dir.join("allowlist");
            if allowlist_path.exists() {
                eprintln!(
                    "tirith: ignoring repo-scoped allowlist at {} (repo policy may tighten but not suppress)",
                    allowlist_path.display()
                );
            }
            let blocklist_path = org_dir.join("blocklist");
            if let Ok(content) = std::fs::read_to_string(&blocklist_path) {
                eprintln!(
                    "tirith: loading repo-scoped blocklist from {}",
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

        // `.git` may be a dir or a file (worktrees); `.exists()` handles both.
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

/// Resolve the path `discover_local` would load, without reading it. Same order
/// (`TIRITH_POLICY_ROOT/.tirith` → walk-up to `.git` → user config). Existence-
/// based: a present-but-unparseable file still yields its path here.
pub fn discover_local_policy_path(cwd: Option<&str>) -> Option<PathBuf> {
    discover_local_policy_path_scoped(cwd).map(|(path, _scope)| path)
}

/// F8/F9 — like [`discover_local_policy_path`] but ALSO reports WHICH branch
/// matched, so the loader can stamp [`Policy::scope`] from the discovery branch
/// (not from the YAML). Order is unchanged: `TIRITH_POLICY_ROOT/.tirith`
/// ([`PolicyScope::Org`]) → walk-up to `.git` ([`PolicyScope::Repo`]) → user
/// config ([`PolicyScope::User`]). Returns `None` (→ [`PolicyScope::Default`])
/// when nothing is found.
pub fn discover_local_policy_path_scoped(cwd: Option<&str>) -> Option<(PathBuf, PolicyScope)> {
    if let Ok(root) = std::env::var("TIRITH_POLICY_ROOT") {
        // F9 — treat an empty/whitespace-only value as unset. `PathBuf::from("")`
        // joins to `./.tirith` (relative to cwd), which would match the REPO's own
        // policy and stamp it `Org`, skipping repo-scope sanitization — a bypass.
        let root = root.trim();
        if !root.is_empty() {
            if let Some(path) = find_policy_in_dir(&PathBuf::from(root).join(".tirith")) {
                return Some((path, PolicyScope::Org));
            }
        }
    }
    if let Some(path) = discover_policy_path(cwd) {
        return Some((path, PolicyScope::Repo));
    }
    user_policy_path().map(|path| (path, PolicyScope::User))
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

/// Nearest ancestor that CONTAINS a `.kiro/` subdir (not `.kiro/` itself), per
/// Kiro CLI's workspace-local agent discovery. Excludes `$HOME` (`~/.kiro` is
/// the user-scope root, not a project workspace).
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

/// Get tirith state directory. MUST match bash-hook.bash
/// (`${XDG_STATE_HOME:-$HOME/.local/state}/tirith`) or hook and binary disagree
/// on where session state lives. Empty `XDG_STATE_HOME` is treated as unset.
pub fn state_dir() -> Option<PathBuf> {
    match std::env::var("XDG_STATE_HOME") {
        Ok(val) if !val.trim().is_empty() => Some(PathBuf::from(val.trim()).join("tirith")),
        _ => home::home_dir().map(|h| h.join(".local/state/tirith")),
    }
}

/// **M8 ch1** — user-scope context-labels path
/// (`~/.config/tirith/context-labels.yaml`), `None` if no config dir.
pub fn user_context_labels_path() -> Option<PathBuf> {
    config_dir().map(|d| d.join("context-labels.yaml"))
}

/// **M8 ch1** — repo-scope context-labels path, `None` outside a git repo.
pub fn repo_context_labels_path(cwd: Option<&str>) -> Option<PathBuf> {
    find_repo_root(cwd).map(|r| r.join(".tirith").join("context-labels.yaml"))
}

/// **M8 ch2** — user-scope SSH host-labels path
/// (`~/.config/tirith/ssh-host-labels.yaml`), `None` if no config dir.
pub fn user_ssh_host_labels_path() -> Option<PathBuf> {
    config_dir().map(|d| d.join("ssh-host-labels.yaml"))
}

/// **M8 ch2** — repo-scope SSH host-labels path, `None` outside a git repo.
pub fn repo_ssh_host_labels_path(cwd: Option<&str>) -> Option<PathBuf> {
    find_repo_root(cwd).map(|r| r.join(".tirith").join("ssh-host-labels.yaml"))
}

/// **M8 ch3** — `state_dir()/iac_plans/`, where `tirith iac check-plan` records
/// reviewed plans as `<sha256>.json`. `None` if `state_dir()` is unresolvable.
pub fn iac_plans_dir() -> Option<PathBuf> {
    state_dir().map(|s| s.join("iac_plans"))
}

/// Maximum size of a policy file (`.tirith/policy.yaml`) we will read in
/// [`Policy::load_from_path`]. Policies are small; 1 MiB is far above any
/// legitimate file and caps a hostile/oversized (or FIFO/symlink) repo file
/// consumed before repo-scope sanitization runs.
const POLICY_FILE_READ_CAP: u64 = 1024 * 1024;

/// Maximum size of a labels file we will read (F17). Flat `provider:context →
/// criticality` maps are tiny; 1 MiB is far above any legitimate file and caps a
/// hostile/oversized one.
const LABELS_FILE_READ_CAP: u64 = 1024 * 1024;

/// Merge a flat-YAML-map labels file into `into`. Missing files are ignored;
/// parse errors emit a stderr diagnostic and continue.
///
/// F17 — reads via [`util::read_text_no_follow_capped`] so a symlinked label
/// file cannot redirect the read onto an arbitrary file (the repo-scope label
/// paths live under an attacker-influenced `<repo>/.tirith/`).
fn merge_context_labels(path: &Path, into: &mut BTreeMap<String, String>) {
    let bytes = match crate::util::read_text_no_follow_capped(path, LABELS_FILE_READ_CAP) {
        Ok(b) => b,
        Err(crate::util::OpenRegularError::NotFound) => return,
        Err(e) => {
            // Surface non-NotFound failures (symlink/special-file refusal,
            // oversize, I/O) so the operator knows labels were skipped
            // (PR-127 review #13).
            eprintln!(
                "tirith: warning: context-labels file at {} read error: {e:?}",
                path.display(),
            );
            return;
        }
    };
    let content = match String::from_utf8(bytes) {
        Ok(c) => c,
        Err(e) => {
            eprintln!(
                "tirith: warning: context-labels file at {} is not valid UTF-8: {e}",
                path.display(),
            );
            return;
        }
    };
    if content.trim().is_empty() {
        return;
    }
    let value: serde_yaml::Value = match serde_yaml::from_str(&content) {
        Ok(v) => v,
        Err(e) => {
            eprintln!(
                "tirith: warning: context-labels file at {} parse error: {e}",
                path.display(),
            );
            return;
        }
    };
    let map = match value {
        serde_yaml::Value::Mapping(m) => m,
        serde_yaml::Value::Null => return,
        _ => {
            eprintln!(
                "tirith: warning: context-labels file at {} must be a YAML mapping",
                path.display(),
            );
            return;
        }
    };
    for (k, v) in map {
        if let (Some(key), Some(val)) = (k.as_str(), v.as_str()) {
            let key = key.trim();
            let val = val.trim();
            if !key.is_empty() && !val.is_empty() {
                into.insert(key.to_string(), val.to_string());
            }
        }
    }
}

/// Write a single label entry (creating file + parent), preserving existing
/// entries and overwriting only the target key. Used by `tirith context label`
/// and `tirith ssh label`.
///
/// F17 — both label paths are `<root>/<dir>/<file>.yaml` where the repo-scope
/// `<dir>` (`<repo>/.tirith`) is attacker-influenceable. The write is hardened
/// two ways:
///   * [`util::canonical_within`] against the GRANDPARENT (`<root>`)
///     canonicalizes through `<dir>`, so a SYMLINKED `.tirith` (or `tirith`)
///     directory that escapes `<root>` is rejected before any write; and
///   * [`util::open_write_no_follow`] refuses a symlinked FINAL component, so a
///     pre-planted `<file>.yaml` symlink cannot redirect the write either.
///
/// The read-back of existing entries already goes through the symlink-refusing
/// [`merge_context_labels`].
pub fn write_context_label(path: &Path, label_key: &str, criticality: &str) -> std::io::Result<()> {
    let mut existing: BTreeMap<String, String> = BTreeMap::new();
    merge_context_labels(path, &mut existing);
    existing.insert(label_key.to_string(), criticality.to_string());

    // The containment root is the grandparent: <repo>/.tirith/<file> → <repo>,
    // <config>/tirith/<file> → <config>. A label path is always at least three
    // components deep; refuse a malformed shallower path rather than guess.
    let containment_root = path.parent().and_then(|p| p.parent()).ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "label path must be <root>/<dir>/<file>",
        )
    })?;

    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }

    // F17 — reject a symlinked containing directory (e.g. a planted `.tirith`
    // symlink) that would redirect the write outside its trusted root. Done
    // after create_dir_all so a legit first-run `.tirith` exists to canonicalize.
    if !crate::util::canonical_within(path, containment_root) {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            format!(
                "refusing to write label outside its trusted root ({})",
                containment_root.display()
            ),
        ));
    }

    let yaml = serde_yaml::to_string(&existing).map_err(|e| {
        std::io::Error::new(std::io::ErrorKind::InvalidData, format!("serialize: {e}"))
    })?;
    // F17 — O_NOFOLLOW + 0600 (refuses a symlinked final component).
    let mut f = crate::util::open_write_no_follow(path, true)?;
    use std::io::Write as _;
    f.write_all(yaml.as_bytes())?;
    Ok(())
}

/// Cache path for remote policy: `~/.cache/tirith/remote-policy.yaml`.
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

/// Load a cached remote policy, running the same migrations as the direct
/// remote-success path (via [`Policy::try_parse_yaml`]) so an older cached
/// policy is upgraded before deserialization (else `cached` mode would drop
/// relocated fields).
fn load_cached_remote_policy() -> Option<Policy> {
    let path = remote_policy_cache_path()?;
    let content = std::fs::read_to_string(&path).ok()?;
    match Policy::try_parse_yaml(&content) {
        Ok(mut p) => {
            p.path = Some(format!("cached:{}", path.display()));
            // A cached remote policy is operator-controlled (it was fetched from
            // the configured server); stamp Remote so it is never repo-sanitized.
            p.scope = PolicyScope::Remote;
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

    // ----------------------------- M5.5 F3 schema_version round-trips -----

    #[test]
    fn shipping_policy_without_schema_version_loads_as_v1() {
        // Mirrors a pre-M5.5 `.tirith/policy.yaml`: no schema_version
        // field at all. The loader must default to v1 (via the migration
        // chain), parse the shipping fields cleanly, and emerge at the
        // current schema version.
        let yaml = "fail_mode: open\nparanoia: 2\n";
        let p = Policy::load_from_yaml(yaml, Some("test"));
        assert_eq!(
            p.schema_version,
            crate::policy_migrations::CURRENT_SCHEMA_VERSION,
            "loaded policy must be at the current schema version after migration"
        );
        assert_eq!(p.paranoia, 2);
        assert_eq!(p.path.as_deref(), Some("test"));
    }

    #[test]
    fn custom_rule_with_both_pattern_and_when_fails_to_load() {
        // CodeRabbit M13 finding R3: a custom rule carrying BOTH `pattern:` and
        // `when:` is a silent no-op and must make the whole policy fail to load.
        let yaml = r#"
custom_rules:
  - id: both-shape
    pattern: "evil"
    when:
      command.uses_sudo: true
    title: "both pattern and when"
    context: [exec]
"#;
        let err =
            Policy::try_parse_yaml(yaml).expect_err("a both-shape custom rule must fail to parse");
        assert!(
            err.contains("both-shape") && err.contains("has both"),
            "error must name the rule and its both-shape defect: {err}"
        );
    }

    #[test]
    fn custom_rule_with_neither_pattern_nor_when_fails_to_load() {
        // CodeRabbit M13 finding R3: a custom rule carrying NEITHER `pattern:`
        // nor `when:` is a silent no-op and must make the policy fail to load.
        let yaml = r#"
custom_rules:
  - id: neither-shape
    title: "neither pattern nor when"
    context: [exec]
"#;
        let err = Policy::try_parse_yaml(yaml)
            .expect_err("a neither-shape custom rule must fail to parse");
        assert!(
            err.contains("neither-shape") && err.contains("has neither"),
            "error must name the rule and its neither-shape defect: {err}"
        );
    }

    #[test]
    fn well_shaped_custom_rule_still_loads() {
        // Counterpoint to the R3 negative tests: a valid when-only rule and a
        // valid pattern-only rule both load cleanly through the same chokepoint.
        let yaml = r#"
custom_rules:
  - id: when-only
    when:
      command.uses_sudo: true
    title: "when only"
    context: [exec]
  - id: pattern-only
    pattern: "rm -rf /"
    title: "pattern only"
    context: [exec]
"#;
        let p = Policy::try_parse_yaml(yaml).expect("well-shaped custom rules must load");
        assert_eq!(p.custom_rules.len(), 2);
    }

    #[test]
    fn explicit_schema_version_v1_loads() {
        let yaml = "schema_version: 1\nparanoia: 3\n";
        let p = Policy::load_from_yaml(yaml, None);
        // After migration through the registered chain, the loaded policy
        // emerges at CURRENT_SCHEMA_VERSION.
        assert_eq!(
            p.schema_version,
            crate::policy_migrations::CURRENT_SCHEMA_VERSION
        );
        assert_eq!(p.paranoia, 3);
    }

    #[test]
    fn future_schema_version_falls_back_to_default() {
        // A policy declaring a version newer than this binary supports
        // must NOT silently drop fields. The loader prints the migration
        // error and returns `Policy::default()` (which itself carries the
        // serde default v1). This pins the no-silent-drop invariant from
        // the F3 design.
        let yaml = "schema_version: 9999\nparanoia: 4\n";
        let p = Policy::load_from_yaml(yaml, Some("synthetic"));
        // Did NOT keep the file's paranoia=4 because deserialization
        // was aborted before that field was read.
        assert_ne!(
            p.paranoia, 4,
            "future-version policy must not be silently honored",
        );
        // The fallback is `Policy::default()` which carries the serde
        // default `schema_version = 1` — NOT the build's current schema.
        // This is intentional: a future-version load shouldn't synthesize
        // a "current schema" policy out of thin air, only the safe default.
        assert_eq!(p.schema_version, 1);
    }

    #[test]
    fn default_policy_carries_schema_version_v1() {
        let p = Policy::default();
        assert_eq!(p.schema_version, 1);
    }

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

        // F9: `policy_fetch_fail_mode` is reset at REPO scope, so this policy must
        // be loaded via the ORG branch (TIRITH_POLICY_ROOT) for its `closed`
        // fetch-fail-mode to be honored. (A repo `.tirith/policy.yaml` could not
        // steer remote-fetch failure.)
        unsafe { std::env::set_var("TIRITH_POLICY_ROOT", dir.path()) };
        unsafe { std::env::set_var("TIRITH_SERVER_URL", "http://127.0.0.1") };
        unsafe { std::env::set_var("TIRITH_API_KEY", "dummy") };

        let policy = Policy::discover(Some(dir.path().to_str().unwrap()));
        assert_eq!(policy.path.as_deref(), Some("fail-closed"));
        assert_eq!(policy.fail_mode, FailMode::Closed);
        assert!(!policy.allow_bypass_env_noninteractive);

        unsafe { std::env::remove_var("TIRITH_API_KEY") };
        unsafe { std::env::remove_var("TIRITH_SERVER_URL") };
        unsafe { std::env::remove_var("TIRITH_POLICY_ROOT") };
    }

    #[test]
    fn discover_local_only_ignores_policy_server_and_never_fetches() {
        // CodeRabbit M13 PR #132 R9-2: the offline discovery path must NEVER
        // make a remote fetch, even when a policy server is configured via BOTH
        // env (`TIRITH_SERVER_URL` + `TIRITH_API_KEY`) AND the local file
        // (`policy_server_url` / `policy_server_api_key`). It must return the
        // bare LOCAL policy with incident overrides applied — not a fetched,
        // cached, or fail-closed remote result.
        //
        // The control is the existing `discover` behavior: with the SAME setup
        // (`policy_fetch_fail_mode: closed` + an unreachable server),
        // `discover` fails closed (path `"fail-closed"`, fail_mode `Closed`,
        // bypass disabled). So observing the LOCAL values here proves no fetch
        // branch ran — `discover_local_only` never touched the network.
        let _guard = crate::TEST_ENV_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());

        // Isolate from ambient runtime state: unset TIRITH_POLICY_ROOT (could
        // redirect discovery) and point XDG_STATE_HOME at an empty tempdir (no
        // incident flag → overrides are a no-op), so the assertions stay hermetic.
        let _root = EnvVarGuard::unset("TIRITH_POLICY_ROOT");
        let state = tempfile::tempdir().unwrap();
        let _xdg_state = EnvVarGuard::set("XDG_STATE_HOME", state.path());
        // Drop any incident-flag cache loaded by an earlier test so the lookup
        // re-reads against our isolated (empty) state dir.
        crate::incident::invalidate_cache();

        let dir = tempfile::tempdir().unwrap();
        let policy_dir = dir.path().join(".tirith");
        std::fs::create_dir_all(&policy_dir).unwrap();
        // Local file also names a (different, equally unreachable) server, so we
        // additionally prove the file-level `policy_server_url` is ignored.
        std::fs::write(
            policy_dir.join("policy.yaml"),
            "fail_mode: open\n\
             policy_fetch_fail_mode: closed\n\
             allow_bypass_env_noninteractive: true\n\
             policy_server_url: http://127.0.0.1:1\n\
             policy_server_api_key: file-key\n\
             paranoia: 3\n",
        )
        .unwrap();

        // Env-configured server too — the other source `discover_resolved`
        // would honor. Both must be ignored by the offline path.
        let _url = EnvVarGuard::set("TIRITH_SERVER_URL", "http://127.0.0.1:1");
        let _key = EnvVarGuard::set("TIRITH_API_KEY", "env-key");

        let policy = Policy::discover_local_only(Some(dir.path().to_str().unwrap()));

        // No fetch happened: we got the LOCAL file, not "remote:" / "fail-closed".
        assert!(
            policy
                .path
                .as_deref()
                .is_some_and(|p| p.ends_with("policy.yaml")),
            "offline discovery must return the LOCAL policy file, got {:?}",
            policy.path
        );
        assert_eq!(
            policy.fail_mode,
            FailMode::Open,
            "local fail_mode must be preserved (a fetch+fail-closed would flip it)"
        );
        // F9: this local file is REPO-scoped (found via the cwd walk-up, no
        // TIRITH_POLICY_ROOT), so its `allow_bypass_env_noninteractive: true` is
        // sanitized to false. The "no fetch happened" proof rests on `paranoia`
        // (a TIGHTENING field the sanitizer keeps) surviving as the local 3 — a
        // fetch+fail-closed would have reset it to the default 1.
        assert!(
            !policy.allow_bypass_env_noninteractive,
            "repo-scoped bypass flag must be sanitized to false (F9)"
        );
        assert_eq!(
            policy.paranoia, 3,
            "local paranoia must be preserved (proves the local file loaded, no fetch)"
        );
        assert_eq!(policy.scope, PolicyScope::Repo, "cwd walk-up is repo scope");

        // Drop the process-global incident cache so the negative result keyed to
        // this about-to-be-removed tempdir does not leak into a sibling test.
        crate::incident::invalidate_cache();
    }

    /// Snapshot an env var on construction and restore it on `Drop` (the
    /// `TEST_ENV_LOCK` serializes env-mutating tests but does not restore).
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
                        ..Default::default()
                    },
                    AgentMatcher {
                        kind: AgentOriginKind::Human,
                        name: None,
                        ..Default::default()
                    },
                ],
                deny: vec![AgentMatcher {
                    kind: AgentOriginKind::Mcp,
                    name: Some("untrusted-client".to_string()),
                    ..Default::default()
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
    fn agent_matcher_without_predicates_loads_unchanged() {
        // M13 ch5: a pre-M13 matcher (kind + name only) must still load, with the
        // three new predicate fields defaulting to None.
        let yaml = "agent_rules:\n  deny:\n    - kind: agent\n      name: untrusted-tool\n";
        let policy: Policy = serde_yaml::from_str(yaml).expect("pre-M13 matcher parse");
        let m = &policy.agent_rules.deny[0];
        assert_eq!(m.kind, AgentOriginKind::Agent);
        assert_eq!(m.name.as_deref(), Some("untrusted-tool"));
        assert_eq!(m.filesystem_write, None);
        assert_eq!(m.network, None);
        assert_eq!(m.secrets_access, None);
    }

    #[test]
    fn agent_matcher_semantic_predicates_round_trip() {
        // M13 ch5: a matcher carrying the three semantic predicates round-trips
        // through `Policy::load` (serialize → YAML → deserialize) byte-for-byte
        // in value. This is the acceptance check that the new predicates persist.
        let matcher = AgentMatcher::with_predicates(
            AgentOriginKind::Agent,
            Some("codex".to_string()),
            Some(FilesystemWriteScope::RepoOnly),
            Some(NetworkPredicate::Block),
            Some(SecretsAccessPredicate::Block),
        );
        let policy = Policy {
            agent_rules: AgentRules {
                allow: vec![],
                deny: vec![matcher.clone()],
            },
            ..Default::default()
        };
        // Serialize the whole policy and re-parse it (the `Policy::load` path).
        let yaml = serde_yaml::to_string(&policy).expect("serialize");
        // The snake_case enum values must appear in the emitted YAML.
        assert!(yaml.contains("filesystem_write: repo_only"), "yaml: {yaml}");
        assert!(yaml.contains("network: block"), "yaml: {yaml}");
        assert!(yaml.contains("secrets_access: block"), "yaml: {yaml}");
        let reparsed: Policy = serde_yaml::from_str(&yaml).expect("reparse");
        assert_eq!(
            reparsed.agent_rules.deny[0], matcher,
            "the predicate-carrying matcher must round-trip unchanged"
        );
        // And `tirith policy validate` must not flag the new fields as UNKNOWN
        // (an "unknown field" warning). They ARE recognized matcher keys. A
        // SEPARATE, intentional "recognized but NOT enforced at runtime" warning
        // is expected on these advisory predicates (CodeRabbit M13 round-15
        // policy_validate.rs:744) and is asserted in `policy_validate`'s tests, so
        // this check targets only the unknown-field category.
        let issues = crate::policy_validate::validate(&yaml);
        assert!(
            !issues.iter().any(|i| i.message.contains("unknown field")
                && i.field.as_deref().is_some_and(|f| {
                    f.contains("filesystem_write")
                        || f.contains("network")
                        || f.contains("secrets_access")
                })),
            "the M13 semantic predicate fields must not be reported as unknown: {issues:?}"
        );
    }

    #[test]
    fn agent_predicate_parsers_accept_documented_values() {
        assert_eq!(
            FilesystemWriteScope::parse("repo_only"),
            Some(FilesystemWriteScope::RepoOnly)
        );
        assert_eq!(
            FilesystemWriteScope::parse("repo-only"),
            Some(FilesystemWriteScope::RepoOnly)
        );
        assert_eq!(
            FilesystemWriteScope::parse("EVERYWHERE"),
            Some(FilesystemWriteScope::Everywhere)
        );
        assert_eq!(FilesystemWriteScope::parse("nonsense"), None);
        assert_eq!(
            NetworkPredicate::parse("warn"),
            Some(NetworkPredicate::Warn)
        );
        assert_eq!(NetworkPredicate::parse("nope"), None);
        assert_eq!(
            SecretsAccessPredicate::parse("block"),
            Some(SecretsAccessPredicate::Block)
        );
        assert_eq!(SecretsAccessPredicate::parse("warn"), None);
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
            ..Default::default()
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
            ..Default::default()
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
            ..Default::default()
        };
        let deny_matcher = AgentMatcher {
            kind: AgentOriginKind::Agent,
            name: Some("bad-actor".to_string()),
            ..Default::default()
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
                        ..Default::default()
                    },
                    AgentMatcher {
                        kind: AgentOriginKind::Gateway,
                        name: Some("xyz".to_string()),
                        ..Default::default()
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
            ..Default::default()
        };
        let ci_matcher = AgentMatcher {
            kind: AgentOriginKind::Ci,
            name: Some("github-actions".to_string()),
            ..Default::default()
        };
        let ide_matcher = AgentMatcher {
            kind: AgentOriginKind::Ide,
            name: Some("vscode".to_string()),
            ..Default::default()
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

    /// Chunk-3 enforcement (deny → Block + `AgentDeniedByPolicy`) lives in
    /// `post_process_verdict`; its behavioral arms are tested in
    /// `escalation.rs::tests`. `engine::analyze` itself still ignores
    /// `agent_rules`, which this test pins.
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
                card_ref: None,
                clipboard_source: crate::clipboard::ClipboardSourceState::Unread,
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

    /// Field-level invariant: setting `agent_rules` changes no OTHER Policy field
    /// the engine reads (it can still flip a verdict via the `escalation.rs`
    /// splice). Guards against a future chunk repurposing it to seed
    /// allowlist/blocklist/severity overrides.
    #[test]
    fn agent_rules_chunk2_observation_only_invariant() {
        let base = Policy::default();
        let allow_matcher = AgentMatcher {
            kind: AgentOriginKind::Agent,
            name: Some("claude-code".to_string()),
            ..Default::default()
        };
        let with_rules = Policy {
            agent_rules: AgentRules {
                allow: vec![allow_matcher.clone()],
                deny: vec![AgentMatcher {
                    kind: AgentOriginKind::Mcp,
                    name: None,
                    ..Default::default()
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

    /// Serialize a RuleId to its severity_overrides map key (snake_case),
    /// matching what `apply_runtime_overrides` / `severity_override` use.
    fn rule_key(rule: &RuleId) -> String {
        serde_json::to_value(rule)
            .ok()
            .and_then(|v| v.as_str().map(String::from))
            .expect("RuleId serializes to a string")
    }

    #[test]
    fn apply_runtime_overrides_preserves_higher_operator_pin_raises_lower() {
        // M11 ch5 regression: `apply_runtime_overrides` must NEVER downgrade an
        // operator's explicit severity_override below the incident level, but
        // MUST raise an override that sits below it. We pin one
        // INCIDENT_ELEVATED_RULES entry ABOVE its incident level and another
        // BELOW, activate an incident, and assert the merge respects both.
        let _lock = crate::TEST_ENV_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());

        // Point state_dir() (hence incident::flag_path()) at a tempdir so the
        // active-incident check reads our flag, never the real machine state.
        // state_dir() reads XDG_STATE_HOME on every platform (Windows included).
        let state = tempfile::tempdir().unwrap();
        let _xdg = EnvVarGuard::set("XDG_STATE_HOME", state.path());

        // ExecRecentlyModified's incident level is High; pin it at Critical
        // (ABOVE) — must be preserved. CredentialFileSweep's incident level is
        // Critical; pin it at Low (BELOW) — must be raised to Critical.
        let above_rule = RuleId::ExecRecentlyModified;
        let below_rule = RuleId::CredentialFileSweep;
        // Sanity-pin the incident levels this test assumes against the table.
        let incident_level = |r: &RuleId| {
            crate::incident::INCIDENT_ELEVATED_RULES
                .iter()
                .find(|(rule, _)| rule == r)
                .map(|(_, sev)| *sev)
                .expect("rule is in INCIDENT_ELEVATED_RULES")
        };
        assert_eq!(incident_level(&above_rule), Severity::High);
        assert_eq!(incident_level(&below_rule), Severity::Critical);
        assert!(
            Severity::Critical > Severity::High,
            "Critical must outrank High for the 'above' pin to be meaningful"
        );

        let mut policy = Policy::default();
        policy
            .severity_overrides
            .insert(rule_key(&above_rule), Severity::Critical); // above incident High
        policy
            .severity_overrides
            .insert(rule_key(&below_rule), Severity::Low); // below incident Critical

        // No incident yet → overrides untouched (fast-path early return).
        crate::incident::invalidate_cache();
        let flag = crate::incident::flag_path().expect("flag path resolves under XDG_STATE_HOME");
        // Defensive: ensure no stale flag from a prior run in this tempdir.
        let _ = crate::incident::stop_at(&flag);
        crate::incident::invalidate_cache();
        let mut no_incident = policy.clone();
        no_incident.apply_runtime_overrides();
        assert_eq!(
            no_incident.fail_mode, policy.fail_mode,
            "no active incident must not change fail_mode"
        );

        // Activate the incident (writes the flag + invalidates the cache).
        crate::incident::start_at(&flag, "downgrade-guard test").unwrap();

        policy.apply_runtime_overrides();

        // The higher operator pin is preserved; the lower one is raised exactly
        // to the incident level (not above).
        assert_eq!(
            policy.severity_override(&above_rule),
            Some(Severity::Critical),
            "operator pin ABOVE the incident level must be preserved, not downgraded"
        );
        assert_eq!(
            policy.severity_override(&below_rule),
            Some(Severity::Critical),
            "operator pin BELOW the incident level must be raised to it"
        );

        // The fail-closed posture + both bypass disables must also be applied.
        assert_eq!(policy.fail_mode, FailMode::Closed);
        assert!(!policy.allow_bypass_env);
        assert!(!policy.allow_bypass_env_noninteractive);

        // Clean up the process-global incident cache + flag so sibling tests
        // (which may run after the lock is released) never see a stale active
        // incident pointing at this now-deleted tempdir.
        let _ = crate::incident::stop_at(&flag);
        crate::incident::invalidate_cache();
    }

    // ----------------------------- F9 sanitize exhaustiveness tripwire -----

    /// F9 tripwire — make `sanitize_repo_scoped` total over the [`Policy`]
    /// struct, so a future field is IMPOSSIBLE to add without a deliberate
    /// trust-boundary decision.
    ///
    /// HOW IT GATES: the body destructures a `Policy` binding EVERY field by
    /// name with NO `..` rest pattern. When someone adds a field to `Policy`,
    /// this destructure stops compiling until they add the field here and
    /// classify it as RESET or KEPT. (A `..` would silently swallow new fields
    /// and defeat the whole point — never add one.)
    ///
    /// WHAT IT ASSERTS: it sanitizes a policy whose every weakening knob is set
    /// to a hostile non-default, then for each field asserts the post-sanitize
    /// value matches its classification — RESET fields equal a fresh
    /// `Policy::default()`'s value, KEPT (tightening-only) fields keep the
    /// hostile value. So the test fails if `sanitize_repo_scoped` and this
    /// classification ever disagree, in EITHER direction (a reset that was
    /// dropped, or a field newly reset without updating the doc/intent here).
    #[test]
    fn f9_sanitize_classification_is_exhaustive() {
        // A maximally-hostile policy: every field that COULD weaken is set to a
        // value distinct from the default, so a missing reset is observable.
        let mut p = Policy {
            // --- fields the sanitizer RESETS (set hostile here) ---
            allowlist: vec!["evil.example".into()],
            allowlist_rules: vec![AllowlistRule {
                rule_id: "curl_pipe_shell".into(),
                patterns: vec!["evil.example".into()],
            }],
            network_allow: vec!["169.254.169.254".into()],
            additional_known_domains: vec!["evil.example".into()],
            severity_overrides: HashMap::from([("curl_pipe_shell".into(), Severity::Low)]),
            allow_bypass_env: true,
            allow_bypass_env_noninteractive: true,
            policy_fetch_fail_mode: Some("cached".into()),
            enforce_fail_mode: Some(true),
            webhooks: vec![WebhookConfig {
                url: "https://attacker.example/exfil".into(),
                min_severity: Severity::Info,
                headers: HashMap::new(),
                payload_template: None,
            }],
            policy_server_url: Some("https://attacker.example/policy".into()),
            policy_server_api_key: Some("planted".into()),
            dlp_custom_patterns: vec!["secret-[0-9]+".into()],
            context_guard_enabled: false,
            package_policy: PackagePolicy {
                block_dependency_confusion: false,
                warn_install_script_network_call: false,
                block_aggregate_score: Some(100),
                block_osv_min_cvss: Some(10.0),
                ..PackagePolicy::default()
            },
            threat_intel: ThreatIntelConfig {
                osv_enabled: false,
                deps_dev_enabled: false,
                ..ThreatIntelConfig::default()
            },
            allowed_install_domains: vec!["attacker.example".into()],
            scan: ScanPolicyConfig {
                trusted_mcp_servers: vec!["attacker-mcp".into()],
                ignore_patterns: vec!["**".into()],
                fail_on: Some("critical".into()),
                profiles: HashMap::from([("loose".into(), ScanProfile::default())]),
                // KEPT scan sub-fields set hostile-distinct too (must survive):
                additional_config_files: vec!["extra.toml".into()],
                mcp_allowed_tools: HashMap::from([("srv".into(), vec!["read".into()])]),
            },
            // --- fields the sanitizer KEEPS (tightening-only; set distinct so a
            //     stray reset would be caught) ---
            blocklist: vec!["blocked.example".into()],
            network_deny: vec!["10.0.0.0/8".into()],
            approval_rules: vec![ApprovalRule {
                rule_ids: vec!["curl_pipe_shell".into()],
                timeout_secs: 0,
                fallback: "block".into(),
            }],
            action_overrides: HashMap::from([("curl_pipe_shell".into(), "block".into())]),
            escalation: vec![crate::escalation::EscalationRule::MultiMedium {
                min_findings: 2,
                action: crate::escalation::EscalationAction::Block,
            }],
            custom_rules: vec![CustomRule {
                id: "x".into(),
                pattern: Some("evil".into()),
                when: None,
                context: vec!["exec".into()],
                severity: Severity::High,
                title: "x".into(),
                description: String::new(),
                action: None,
            }],
            paranoia: 4,
            strict_warn: true,
            iac_require_plan_before_apply: true,
            sudo_require_reason: true,
            sudo_session_ttl: Some(60),
            env_guard_enabled: true,
            env_guard_sensitive_vars: vec!["MY_SECRET".into()],
            exec_guard_enabled: true,
            hooks_guard_enabled: true,
            baseline_enabled: true,
            context_destructive_verbs: HashMap::from([("aws".into(), vec!["nuke".into()])]),
            agent_rules: AgentRules {
                allow: Vec::new(),
                deny: vec![AgentMatcher::new(AgentOriginKind::Mcp, Some("evil".into()))],
            },
            share: ShareConfig {
                customer_id_patterns: vec!["CUST-[0-9]{4}".into()],
            },
            checkpoints: CheckpointPolicyConfig {
                max_count: 1,
                max_age_hours: 1,
                max_storage_bytes: 1,
            },
            fail_mode: FailMode::Closed,
            schema_version: 1,
            // Loader-stamped / serde-skipped — set so the destructure is total.
            path: Some("test".into()),
            scope: PolicyScope::Repo,
            context_labels: BTreeMap::new(),
            ssh_host_labels: BTreeMap::new(),
            // Presentation bookkeeping — `sanitize_repo_scoped` OVERWRITES this,
            // so the initial value is inert; set empty only to keep the
            // (no-`..`) constructor total.
            neutralized_fields: Vec::new(),
        };

        p.sanitize_repo_scoped();

        // The single source of truth for "what a reset field should look like".
        let d = Policy::default();

        // EXHAUSTIVE, NO-`..` DESTRUCTURE — the compile-time gate. Adding a field
        // to `Policy` breaks this line until the new field is bound and
        // classified below. DO NOT add `..` to silence the error; add the field.
        let Policy {
            // RESET group — must equal the default after sanitize.
            allowlist,
            allowlist_rules,
            network_allow,
            additional_known_domains,
            severity_overrides,
            allow_bypass_env,
            allow_bypass_env_noninteractive,
            policy_fetch_fail_mode,
            enforce_fail_mode,
            webhooks,
            policy_server_url,
            policy_server_api_key,
            dlp_custom_patterns,
            context_guard_enabled,
            package_policy,
            threat_intel,
            allowed_install_domains,
            scan,
            // KEPT group — tightening-only; must retain the hostile-distinct value.
            blocklist,
            network_deny,
            approval_rules,
            action_overrides,
            escalation,
            custom_rules,
            paranoia,
            strict_warn,
            iac_require_plan_before_apply,
            sudo_require_reason,
            sudo_session_ttl,
            env_guard_enabled,
            env_guard_sensitive_vars,
            exec_guard_enabled,
            hooks_guard_enabled,
            baseline_enabled,
            context_destructive_verbs,
            agent_rules,
            share,
            checkpoints,
            fail_mode,
            schema_version,
            // Provenance / serde-skipped — not part of the trust decision, but
            // bound so the destructure stays total.
            path,
            scope,
            context_labels,
            ssh_host_labels,
            // Presentation bookkeeping (design C) — NOT a sanitize-classified
            // field (neither RESET nor KEPT). The sanitizer WRITES this with the
            // keys it neutralized; it is `#[serde(skip)]` and a repo cannot set
            // it. Bound here only to keep the no-`..` destructure total; its
            // population is asserted by `sanitize_records_neutralized_fields`.
            neutralized_fields: _,
        } = p;

        // ---- RESET: every weakening/suppression/exfil knob back to default ----
        assert_eq!(allowlist, d.allowlist, "RESET: allowlist");
        assert!(allowlist_rules.is_empty(), "RESET: allowlist_rules");
        assert_eq!(network_allow, d.network_allow, "RESET: network_allow");
        assert_eq!(
            additional_known_domains, d.additional_known_domains,
            "RESET: additional_known_domains"
        );
        assert_eq!(
            severity_overrides, d.severity_overrides,
            "RESET: severity_overrides"
        );
        assert!(
            !allow_bypass_env,
            "RESET: allow_bypass_env (forced false; default is true, a repo cannot enable the bypass)"
        );
        assert_eq!(
            allow_bypass_env_noninteractive, d.allow_bypass_env_noninteractive,
            "RESET: allow_bypass_env_noninteractive"
        );
        assert_eq!(
            policy_fetch_fail_mode, d.policy_fetch_fail_mode,
            "RESET: policy_fetch_fail_mode"
        );
        assert_eq!(
            enforce_fail_mode, d.enforce_fail_mode,
            "RESET: enforce_fail_mode"
        );
        assert_eq!(webhooks.len(), d.webhooks.len(), "RESET: webhooks");
        assert_eq!(
            policy_server_url, d.policy_server_url,
            "RESET: policy_server_url"
        );
        assert_eq!(
            policy_server_api_key, d.policy_server_api_key,
            "RESET: policy_server_api_key"
        );
        assert_eq!(
            dlp_custom_patterns, d.dlp_custom_patterns,
            "RESET: dlp_custom_patterns"
        );
        assert_eq!(
            context_guard_enabled, d.context_guard_enabled,
            "RESET: context_guard_enabled (false would disable the context guard)"
        );
        assert_eq!(
            package_policy, d.package_policy,
            "RESET: package_policy (demotes/silences supply-chain findings)"
        );
        assert_eq!(
            threat_intel.osv_enabled, d.threat_intel.osv_enabled,
            "RESET: threat_intel.osv_enabled"
        );
        assert_eq!(
            threat_intel.deps_dev_enabled, d.threat_intel.deps_dev_enabled,
            "RESET: threat_intel.deps_dev_enabled"
        );
        assert_eq!(
            allowed_install_domains, d.allowed_install_domains,
            "RESET: allowed_install_domains (self-listing downgrades PasteSourceMismatch)"
        );
        assert_eq!(
            scan.trusted_mcp_servers, d.scan.trusted_mcp_servers,
            "RESET: scan.trusted_mcp_servers (a listed name silences MCP findings)"
        );
        assert_eq!(
            scan.ignore_patterns, d.scan.ignore_patterns,
            "RESET: scan.ignore_patterns"
        );
        assert_eq!(scan.fail_on, d.scan.fail_on, "RESET: scan.fail_on");
        assert!(scan.profiles.is_empty(), "RESET: scan.profiles");

        // ---- KEPT: tightening-only knobs survive (hostile-distinct values) ----
        // scan's tightening sub-fields must NOT have been reset.
        assert_eq!(
            scan.additional_config_files,
            vec!["extra.toml".to_string()],
            "KEPT: scan.additional_config_files (adds coverage)"
        );
        assert!(
            scan.mcp_allowed_tools.contains_key("srv"),
            "KEPT: scan.mcp_allowed_tools (opt-in tool allow-list, tightening)"
        );
        assert_eq!(
            blocklist,
            vec!["blocked.example".to_string()],
            "KEPT: blocklist"
        );
        assert_eq!(
            network_deny,
            vec!["10.0.0.0/8".to_string()],
            "KEPT: network_deny"
        );
        assert_eq!(approval_rules.len(), 1, "KEPT: approval_rules");
        assert!(
            action_overrides.contains_key("curl_pipe_shell"),
            "KEPT: action_overrides (upgrade-only)"
        );
        assert_eq!(escalation.len(), 1, "KEPT: escalation (Block-only upgrade)");
        assert_eq!(custom_rules.len(), 1, "KEPT: custom_rules");
        assert_eq!(paranoia, 4, "KEPT: paranoia (higher only keeps more)");
        assert!(strict_warn, "KEPT: strict_warn");
        assert!(
            iac_require_plan_before_apply,
            "KEPT: iac_require_plan_before_apply"
        );
        assert!(sudo_require_reason, "KEPT: sudo_require_reason");
        assert_eq!(sudo_session_ttl, Some(60), "KEPT: sudo_session_ttl");
        assert!(env_guard_enabled, "KEPT: env_guard_enabled");
        assert_eq!(
            env_guard_sensitive_vars,
            vec!["MY_SECRET".to_string()],
            "KEPT: env_guard_sensitive_vars (widens the sensitive set)"
        );
        assert!(exec_guard_enabled, "KEPT: exec_guard_enabled");
        assert!(hooks_guard_enabled, "KEPT: hooks_guard_enabled");
        assert!(baseline_enabled, "KEPT: baseline_enabled");
        assert!(
            context_destructive_verbs.contains_key("aws"),
            "KEPT: context_destructive_verbs (widens destructive verbs)"
        );
        assert_eq!(
            agent_rules.deny.len(),
            1,
            "KEPT: agent_rules (deny tightens)"
        );
        assert_eq!(
            share.customer_id_patterns.len(),
            1,
            "KEPT: share (only adds redactions)"
        );
        assert_eq!(
            checkpoints.max_count, 1,
            "KEPT: checkpoints (retention only)"
        );
        assert_eq!(
            fail_mode,
            FailMode::Closed,
            "KEPT: fail_mode (closed tightens)"
        );
        assert_eq!(schema_version, 1, "KEPT: schema_version (inert)");

        // ---- Provenance / serde-skipped — untouched by the sanitizer. ----
        assert_eq!(path.as_deref(), Some("test"), "untouched: path");
        assert_eq!(scope, PolicyScope::Repo, "untouched: scope");
        assert!(context_labels.is_empty(), "untouched: context_labels");
        assert!(ssh_host_labels.is_empty(), "untouched: ssh_host_labels");
    }

    /// Design C — `sanitize_repo_scoped` records the YAML key of every WEAKENING
    /// field it neutralized into `neutralized_fields`, so the UX layer can surface
    /// which repo settings were ignored. Verifies: (1) repo `allowlist` +
    /// `severity_overrides` are recorded; (2) `allow_bypass_env` (default true,
    /// permissive) is NOT recorded — leaving it at the default is not an author
    /// weakening attempt — while `allow_bypass_env_noninteractive` (default false)
    /// IS recorded when set true; (3) a tightening-only / all-default policy records
    /// nothing, so the operator notice never fires for it.
    #[test]
    fn sanitize_records_neutralized_fields() {
        let mut p = Policy {
            allowlist: vec!["evil.example".into()],
            severity_overrides: HashMap::from([("curl_pipe_shell".into(), Severity::Low)]),
            allow_bypass_env_noninteractive: true,
            ..Policy::default()
        };
        p.sanitize_repo_scoped();

        assert!(
            p.neutralized_fields.contains(&"allowlist"),
            "allowlist (non-default) must be recorded; got {:?}",
            p.neutralized_fields
        );
        assert!(
            p.neutralized_fields.contains(&"severity_overrides"),
            "severity_overrides (non-default) must be recorded; got {:?}",
            p.neutralized_fields
        );
        // Permissive-default `allow_bypass_env` is forced false but NOT recorded;
        // restrictive-default `allow_bypass_env_noninteractive` set true IS recorded.
        assert!(
            !p.neutralized_fields.contains(&"allow_bypass_env"),
            "allow_bypass_env (permissive default) must NOT be recorded; got {:?}",
            p.neutralized_fields
        );
        assert!(
            p.neutralized_fields
                .contains(&"allow_bypass_env_noninteractive"),
            "allow_bypass_env_noninteractive (set true) must be recorded; got {:?}",
            p.neutralized_fields
        );
        // No key recorded more than once (the leading `clear()` prevents append).
        let mut deduped = p.neutralized_fields.clone();
        deduped.sort_unstable();
        deduped.dedup();
        assert_eq!(
            deduped.len(),
            p.neutralized_fields.len(),
            "neutralized keys must be unique; got {:?}",
            p.neutralized_fields
        );
        // The reset VALUES are unchanged: suppression knobs back to default, both
        // bypass flags forced off.
        assert!(p.allowlist.is_empty(), "allowlist still reset to default");
        assert!(
            p.severity_overrides.is_empty(),
            "severity_overrides still reset to default"
        );
        assert!(!p.allow_bypass_env, "allow_bypass_env still forced false");
        assert!(
            !p.allow_bypass_env_noninteractive,
            "allow_bypass_env_noninteractive still forced false"
        );

        // A tightening-only / all-default policy records NOTHING — so the
        // operator-facing weakening notice never fires for a benign repo.
        let mut all_default = Policy::default();
        all_default.sanitize_repo_scoped();
        assert!(
            all_default.neutralized_fields.is_empty(),
            "an all-default (tightening-only) policy must record nothing; got {:?}",
            all_default.neutralized_fields
        );
    }
}
