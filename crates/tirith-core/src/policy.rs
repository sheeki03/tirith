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

/// Default `schema_version` for serde — shipping policies omit the field
/// and we treat them as v1. `u32::default()` is 0, which would falsely flag
/// them as "older than any registered migration".
fn default_schema_version() -> u32 {
    1
}

/// M8 ch1 — `context_guard_enabled` defaults to `true` so a fresh policy
/// (or one that predates M8) opts in to context detection out of the box.
/// Set to `false` to silence the rule while still reading the labels file.
fn default_context_guard_enabled() -> bool {
    true
}

/// Policy configuration loaded from YAML.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct Policy {
    /// Path this policy was loaded from.
    #[serde(skip)]
    pub path: Option<String>,

    /// Schema version of the policy file (M5.5 chunk F3). Shipping policies
    /// omit this field; they're treated as v1 via [`default_schema_version`].
    /// Forward migrations live in [`crate::policy_migrations`] and run on
    /// the raw YAML before deserialization, so newer fields are reachable.
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

    /// **M6 ch7 — package-policy section.**
    ///
    /// Thresholds and actions for the package-reputation signals shipped in
    /// M6 ch6. Replaces the hard-coded `AGGREGATE_BLOCK_SCORE = 76` /
    /// `AGGREGATE_WARN_SCORE = 51` constants and exposes per-signal
    /// thresholds (CVSS, package age, low downloads, typosquat distance,
    /// repo-mismatch cap, ...) plus the `internal_package_names` list the
    /// dependency-confusion heuristic consumes.
    ///
    /// Every field has a sensible default — leaving `package_policy:` empty
    /// keeps the M6 ch6 behavior. See [`PackagePolicy`] for the per-field
    /// docs and effective defaults via [`PackagePolicy::*_effective`]
    /// helpers.
    #[serde(default)]
    pub package_policy: PackagePolicy,

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
    /// Enforcement runs on every analysis path: `tirith check`, the
    /// gateway, `tirith paste`, `tirith install`, `tirith ecosystem scan`,
    /// and the MCP `tools/call_check_*` handlers (`call_check_command`,
    /// `call_check_url`, `call_check_paste`). The CLI / gateway / MCP
    /// `call_check_command` sites route through `post_process_verdict`;
    /// `paste` / `install` / `ecosystem` / `call_check_url` / `call_check_paste`
    /// invoke `apply_agent_rules` directly after stamping origin. The
    /// `TIRITH=0` interactive bypass currently skips `apply_agent_rules`
    /// (pinned by `agent_rules_deny_skipped_under_tirith_bypass_today` in
    /// the CLI integration tests); revisit in M5.
    ///
    /// See `docs/agent-governance-design.md` for the trust model:
    /// **operator-trust**, never adversary-resistant. The matching strings
    /// are caller-claimed signals (`TIRITH_INTEGRATION`,
    /// `clientInfo.name`, etc.); they are informative, not load-bearing
    /// for security policy alone.
    #[serde(default)]
    pub agent_rules: AgentRules,

    /// **M7 ch2 — `tirith share` / `tirith redact` config.**
    ///
    /// Repo-specific patterns for `tirith share` to scrub before sending
    /// content to teammates, LLMs, or public pastes. The shipped pattern
    /// set in `share_patterns.toml` covers cross-org signals (private IPs,
    /// internal-DNS hostnames, `/home/<user>` paths); customer / tenant /
    /// case IDs are necessarily repo-specific so they're supplied here.
    ///
    /// See [`ShareConfig`] for the field layout. Defaults are empty.
    #[serde(default)]
    pub share: ShareConfig,

    /// **M8 ch1 — operational-context guard switch.**
    ///
    /// When `true` (the default), the `rules::context` module evaluates
    /// the active provider context (kube / aws / gcp / azure) against the
    /// labels file and emits a finding for destructive / write /
    /// credential-change commands targeting labeled-production contexts.
    /// Set to `false` to disable the guard while keeping the labels file
    /// readable for `tirith context status` reporting.
    #[serde(default = "default_context_guard_enabled")]
    pub context_guard_enabled: bool,

    /// **M8 ch1 — operator-supplied destructive verbs per provider.**
    ///
    /// Keys are provider strings (`kube`, `aws`, `gcp`, `azure`); values
    /// are verb strings that, when seen as a positional arg in the first
    /// three positions of the parsed command, escalate the match to
    /// `ContextProdDestructiveCommand` (High). The shipped tables in
    /// `rules::context` cover the common verbs; this hook lets an
    /// operator widen the set without code changes.
    #[serde(default)]
    pub context_destructive_verbs: HashMap<String, Vec<String>>,

    /// **M8 ch1 — `provider:context` → criticality map.**
    ///
    /// Populated by [`Policy::load_context_labels`] from
    /// `~/.config/tirith/context-labels.yaml` (user scope) merged with
    /// `<repo>/.tirith/context-labels.yaml` (repo scope). NOT serialized
    /// to `policy.yaml` — labels live in their own dedicated file so a
    /// hand-edited `policy.yaml` is never round-tripped through serde.
    ///
    /// Keys: `kube:prod-us-east`, `aws:prod`, `gcp:svc@my-prod-project`,
    /// `azure:Prod Subscription`. Values: `critical` / `production` /
    /// `prod` / `live` / `p0` / `p1` (case-insensitive).
    #[serde(skip)]
    pub context_labels: BTreeMap<String, String>,

    /// **M8 ch2 — `host` (or `user@host`) → criticality map for SSH.**
    ///
    /// Populated by [`Policy::load_ssh_host_labels`] from
    /// `~/.config/tirith/ssh-host-labels.yaml` (user scope) merged with
    /// `<repo>/.tirith/ssh-host-labels.yaml` (repo scope). Repo wins on
    /// conflict, mirroring the context-labels layout.
    ///
    /// Keys are SSH host strings. The matcher first looks for the exact
    /// `user@host` form (e.g. `root@payments-prod-01`), then falls back
    /// to the bare host (`payments-prod-01`). `~/.ssh/config` aliases
    /// are resolved at label time via `ssh -G alias` — the labels file
    /// always stores the FINAL hostname.
    ///
    /// Values: `critical` / `production` / `prod` / `live` / `p0` / `p1`
    /// (case-insensitive). Other values (`staging`, `dev`, `test`,
    /// `p2`) are recorded but do not fire the M8 ch2 rule — they
    /// document the inventory without enforcing.
    #[serde(skip)]
    pub ssh_host_labels: BTreeMap<String, String>,

    /// **M8 ch3 — gate `apply` invocations behind a recorded plan hash.**
    ///
    /// When `true`, the IaC rules in `rules::iac` enforce a stricter
    /// apply gate:
    ///   * `terraform apply` (no plan file) → `IacApplyWithoutPlan` (High).
    ///   * `terraform apply tfplan` where the file's SHA-256 is NOT in
    ///     `state_dir()/iac_plans/<sha256>` → `IacPlanHashMismatch` (High).
    ///
    /// When `false` (the default), neither rule fires; `iac` is purely
    /// advisory (auto-approve and destroy-in-prod still flag, but the
    /// hash store is consulted only by `tirith iac check-plan`).
    ///
    /// Toggled by `tirith iac require-plan-before-apply on|off`. Persisted
    /// to `policy.yaml` via the same single-line append-or-rewrite the M8
    /// ch1 `context_guard_enabled` flag uses.
    #[serde(default)]
    pub iac_require_plan_before_apply: bool,

    /// **M8 ch4 — require a tagged sudo-session for the sudo rules to
    /// downgrade.**
    ///
    /// When `true`, an active session file under
    /// `state_dir()/sudo-session.json` (created via
    /// `tirith sudo session start --reason "…"`) downgrades the five
    /// M8 ch4 sudo rules from High to Medium. When `false` (the
    /// default), the session file is consulted purely for status
    /// reporting and never affects rule severity — every sudo rule
    /// fires at its baseline High.
    ///
    /// Toggled by `tirith sudo require-reason on|off`. Persisted via
    /// the same single-line append-or-rewrite the M8 ch1
    /// `context_guard_enabled` flag uses.
    #[serde(default)]
    pub sudo_require_reason: bool,

    /// **M8 ch4 — default session lifetime for `tirith sudo session start`.**
    ///
    /// When set, `tirith sudo session start` (with no `--ttl` flag)
    /// uses this value as the session TTL in seconds. When `None`, the
    /// CLI falls back to [`crate::sudo_session::DEFAULT_SESSION_TTL_SECS`]
    /// (30 minutes). The rule module never reads this field directly —
    /// it only affects the CLI default.
    #[serde(default)]
    pub sudo_session_ttl: Option<u64>,

    /// **M9 ch4 — environment-variable lifecycle guard switch.**
    ///
    /// When `true`, the two exec-path env-guard rules in
    /// [`crate::env_guard`] fire from `engine::analyze`:
    ///   * [`crate::verdict::RuleId::EnvSensitiveExposedToUnknownScript`]
    ///     (High) — a sensitive env var is set AND the command pipes remote
    ///     content into a shell interpreter.
    ///   * [`crate::verdict::RuleId::EnvPrintenvToNetworkSink`] (Medium) —
    ///     `printenv`/`env` piped into a network sink.
    ///
    /// When `false` (the default), neither exec-path rule fires; the
    /// `tirith env diff|explain` observability surfaces still work (they read
    /// the snapshot + rc files directly and do not consult this flag).
    ///
    /// Toggled by `tirith env guard on|off`. Persisted to `policy.yaml` via
    /// the same single-line append-or-rewrite the M8 flags use.
    #[serde(default)]
    pub env_guard_enabled: bool,

    /// **M9 ch4 — user extension of the sensitive env-var name list.**
    ///
    /// Merged with the built-in `assets/data/sensitive_env.toml` list (see
    /// [`crate::env_guard::effective_sensitive_vars`]). Lets an operator add
    /// org-specific secret variable names (`MY_CORP_API_KEY`, …) without a
    /// code change. The built-in list is always included; these are appended.
    #[serde(default)]
    pub env_guard_sensitive_vars: Vec<String>,

    /// **M9 ch5 — exec-provenance / PATH-shadowing hot-path guard.**
    ///
    /// When `true`, the three CHEAP exec-provenance rules in
    /// [`crate::path_audit`] fire from `engine::analyze` (Exec context only):
    ///   * [`crate::verdict::RuleId::ExecInTmp`] (Medium) — the resolved
    ///     leader lives under `/tmp` (or `$TMPDIR`).
    ///   * [`crate::verdict::RuleId::ExecInRepoBin`] (Medium) — the resolved
    ///     leader lives inside the current repo's working tree.
    ///   * [`crate::verdict::RuleId::PathWritableDirBeforeSystem`] (High) — the
    ///     resolved leader sits in a user-writable, repo-local-or-`/tmp` `$PATH`
    ///     dir that precedes a system dir (`/usr/bin`, `/bin`, `/usr/sbin`).
    ///
    /// These are stat-free string compares (no `codesign`, no `file`, no
    /// mtime/ownership stat). The seven EXPENSIVE provenance signals
    /// (`ExecRecentlyModified`, `ExecWorldWritable`, `ExecUnsigned`,
    /// `ExecShadowsSystemCommand`, `PathDuplicateCommandName`, `PathDirInRepo`,
    /// `PathDirInTmp`) NEVER fire on the hot path — they run only under explicit
    /// `tirith exec check|provenance` / `tirith path audit|which`.
    ///
    /// When `false` (the default), no exec-provenance rule fires from the hot
    /// path; the `tirith exec` / `tirith path` surfaces still work (they call
    /// the library directly and do not consult this flag). Toggled by
    /// `tirith path guard on|off`.
    #[serde(default)]
    pub exec_guard_enabled: bool,

    /// **M9 ch6 — repo-hook / automation guard hot-path switch.**
    ///
    /// When `true`, the exec hot path proactively scans the repo's git /
    /// husky / lefthook / pre-commit hooks (plus `package.json` lifecycle
    /// scripts and `.envrc`) whenever the parsed command leader is a
    /// hook-triggering command (`git commit|pull|checkout|merge|rebase|push`,
    /// `npm|yarn|pnpm install`, `direnv allow|reload`), surfacing the three
    /// hot-path-eligible repo-hook rules
    /// ([`crate::verdict::RuleId::RepoHookNetworkCall`],
    /// [`RepoHookCredentialRead`](crate::verdict::RuleId::RepoHookCredentialRead),
    /// [`RepoHookSudo`](crate::verdict::RuleId::RepoHookSudo)) for ONLY the hook
    /// types that leader actually triggers (e.g. `git commit` → `pre-commit`,
    /// NOT `pre-push` and NOT the `Makefile`). The scan is per-repo mtime-cached
    /// for 60s (see [`crate::repo_hooks::HOOK_CACHE_TTL`]).
    ///
    /// When `false` (the default), no repo-hook rule fires from the hot path;
    /// `tirith hooks scan|explain` still work (they call the library directly
    /// and do not consult this flag). Toggled by `tirith hooks guard on|off`.
    #[serde(default)]
    pub hooks_guard_enabled: bool,

    /// **M10 ch5 — opt-in anomaly-detection baseline (design-decision D2).**
    ///
    /// When `true`, the exec / paste hot path records every detection-rule
    /// firing as a privacy-hashed observation in the sliding window at
    /// `state_dir()/baseline.jsonl` (`crate::baseline`) and, when a firing
    /// finding's tuple is new / rare for this user, appends one of the two
    /// Info-severity anomaly findings
    /// ([`crate::verdict::RuleId::AnomalyFirstTimeInThisRepo`] /
    /// [`AnomalyRareInBaseline`](crate::verdict::RuleId::AnomalyRareInBaseline)).
    /// The anomaly findings never change the verdict's action — they annotate
    /// "this is new for you".
    ///
    /// When `false` (the default — the D2 opt-in decision), the engine performs
    /// NO baseline I/O on the hot path: no JSONL read, no append, no salt read.
    /// A machine that never opted in pays nothing. The `tirith baseline status`
    /// / `reset` surfaces still read the store directly (independent of this
    /// flag). Toggled by `tirith baseline learn` (on) and persisted via the
    /// same single-line append-or-rewrite the M8/M9 guard flags use.
    #[serde(default)]
    pub baseline_enabled: bool,

    /// **M12 ch1 — trusted install-source hosts for paste provenance.**
    ///
    /// Hosts the operator trusts as legitimate places a pasted install command
    /// may download from (e.g. `github.com`, `objects.githubusercontent.com`,
    /// `registry.npmjs.org`). Consulted ONLY by the `paste_provenance` rule
    /// ([`crate::verdict::RuleId::PasteSourceMismatch`]): when a paste's content
    /// matches a recorded clipboard source but a destination host differs from
    /// the source page's host, a destination host that is NOT in this list is one
    /// of the risk signals that escalates the (otherwise advisory Info) mismatch
    /// to High. A destination host that IS listed keeps the bare mismatch at Info.
    ///
    /// Empty by default — with no list configured, a not-in-list destination host
    /// does NOT by itself escalate (the other risk signals still apply); this is
    /// backward-compatible (`#[serde(default)]`). Matching is case-insensitive and
    /// covers an exact host match OR a dot-suffix subdomain match: a configured
    /// `github.com` also allows `objects.github.com`, but NOT a lookalike like
    /// `evilgithub.com`. See `paste_provenance::host_in_allowed_domains`.
    #[serde(default)]
    pub allowed_install_domains: Vec<String>,
}

/// **M7 ch2** — `tirith share` policy configuration.
///
/// Only `customer_id_patterns` is shipped on day one. Future M7 chunks
/// may add audience-default overrides here; the empty-default contract is
/// the supported forward-compat surface.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct ShareConfig {
    /// Repo-specific regex patterns matched against the content fed to
    /// `tirith share` / `tirith redact`. Every match is replaced with
    /// `[REDACTED:customer_id]` and tallied under the `customer_id`
    /// label in the report. Patterns longer than 1024 chars are skipped
    /// with a warning.
    ///
    /// Examples (a real repo will configure these to its own ID
    /// shapes — there is no shipped default):
    ///   - `CUST-\d{4,6}`
    ///   - `acct_[a-z0-9]{16}`
    ///   - `case#\d+`
    pub customer_id_patterns: Vec<String>,
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
    /// M13 ch5 — OPTIONAL per-agent semantic predicate: the filesystem-write
    /// scope this agent is expected to stay within. Advisory metadata an
    /// operator declares alongside a matcher (emitted by `tirith agent block
    /// --filesystem-write …`); it does NOT change which origins a matcher
    /// matches (matching stays on `kind` + `name`). `#[serde(default)]` so every
    /// pre-M13 matcher loads unchanged.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub filesystem_write: Option<FilesystemWriteScope>,
    /// M13 ch5 — OPTIONAL per-agent semantic predicate: how this agent's network
    /// access should be treated. Advisory metadata (emitted by `tirith agent
    /// block --network …`). Does not affect matching. `#[serde(default)]`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub network: Option<NetworkPredicate>,
    /// M13 ch5 — OPTIONAL per-agent semantic predicate: whether this agent may
    /// read secrets. Advisory metadata (emitted by `tirith agent block
    /// --secrets-access …`). Does not affect matching. `#[serde(default)]`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub secrets_access: Option<SecretsAccessPredicate>,
}

impl Default for AgentMatcher {
    /// A matcher defaulting to `kind: human` with no `name` and no semantic
    /// predicates. Exists so callers can use `..Default::default()` to fill the
    /// M13 ch5 predicate fields without restating them; every real construction
    /// site sets `kind` explicitly, so the `Human` default is never load-bearing.
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
    /// Construct a matcher with the given `kind` + optional `name` and NO
    /// semantic predicates (the pre-M13 shape). The M13 ch5 predicate fields
    /// default to `None`; set them via the struct fields directly or with
    /// [`AgentMatcher::with_predicates`] when emitting from `tirith agent block`.
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

/// M13 ch5 — filesystem-write scope predicate on an [`AgentMatcher`]. The
/// declared scope an agent is expected to write within.
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
///
/// A rule carries EXACTLY ONE of `pattern` (a regex, the original
/// [`crate::rules::custom`] path) or `when` (a semantic-predicate clause, the
/// M13 ch4 DSL — [`crate::custom_rule_dsl`]). [`Self::validate_shape`] enforces
/// the exclusive-or; loaders that skip validation simply ignore a malformed
/// rule (see [`crate::rules::custom::compile_rules`]).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CustomRule {
    /// Unique identifier for this custom rule.
    pub id: String,
    /// Regex pattern to match. Mutually exclusive with `when`. `None` for a
    /// DSL rule.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pattern: Option<String>,
    /// M13 ch4 — semantic-predicate clause. Mutually exclusive with `pattern`.
    /// `None` for a regex rule.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub when: Option<crate::custom_rule_dsl::WhenClause>,
    /// Contexts this rule applies to: "exec", "paste", "file".
    #[serde(default = "default_custom_rule_contexts")]
    pub context: Vec<String>,
    /// Severity level.
    #[serde(default = "default_custom_rule_severity")]
    pub severity: Severity,
    /// Short title for findings. Accepts `message:` as an alias so the M13 ch4
    /// DSL example shape (`message: "..."`) loads into the same field.
    #[serde(alias = "message")]
    pub title: String,
    /// Description for findings.
    #[serde(default)]
    pub description: String,
    /// M13 ch4 — optional declared action (`allow`/`warn`/`block`). RECORDED
    /// metadata in v1: like the regex custom-rule path, the finding's effective
    /// action still derives from its `severity` via
    /// [`crate::verdict::action_from_findings`]. Surfaced by `tirith rule
    /// explain`; lets the documented `action: block` example load.
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
    /// Validate the pattern-XOR-when invariant: a rule must carry EXACTLY ONE.
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
        }
    }
}

/// M6 ch7 — operator-supplied internal-name pattern for the
/// dependency-confusion heuristic.
///
/// `name` is a package-name pattern. A trailing `*` is the only supported
/// wildcard: `@org/*` matches every `@org/<anything>` resolution on the
/// public registry (the textbook 2021 dependency-confusion shape).
///
/// `ecosystem` is optional: when set (`"npm"`, `"pypi"`, `"crates.io"`,
/// `"go"`, ...) the pattern matches only that ecosystem's lookups; when
/// `None` the pattern matches every ecosystem (the previous M6 ch6
/// behavior for the top-level string list).
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
    /// Build a spec from a bare-string pattern (the M6 ch6 shape) — used by
    /// the migration to lift the legacy top-level list.
    pub fn from_pattern(name: impl Into<String>) -> Self {
        Self {
            ecosystem: None,
            name: name.into(),
        }
    }
}

/// M6 ch7 — package-policy section.
///
/// Thresholds and actions for the package-reputation signals shipped in
/// M6 ch6. Every field defaults to the M6 ch6 shipping behavior — the
/// section can be omitted entirely without changing detection.
///
/// All threshold fields are read via `*_effective` helpers that fold in
/// the M6 ch6 baseline so callers do not branch on `Option`.
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
    /// Block when `name_vs_popular == Unknown` AND the install-script
    /// analysis flagged a network call or shell spawn. Requires the
    /// install-script signal — paths where script text is available are
    /// `--online` install (npm inline), `ecosystem scan --installed`, and
    /// `package scan --lockfile --online`. Bare offline `install` cannot
    /// fire it.
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
    /// The aggregate-score Block threshold — `block_aggregate_score` or
    /// the M6 ch6 baseline of 76.
    pub fn block_aggregate_score_effective(&self) -> u32 {
        self.block_aggregate_score
            .unwrap_or(DEFAULT_BLOCK_AGGREGATE_SCORE)
    }
    /// The aggregate-score Warn threshold — `warn_aggregate_score` or
    /// the M6 ch6 baseline of 51.
    pub fn warn_aggregate_score_effective(&self) -> u32 {
        self.warn_aggregate_score
            .unwrap_or(DEFAULT_WARN_AGGREGATE_SCORE)
    }
    /// The OSV CVSS threshold above which the OSV advisory should block —
    /// `block_osv_min_cvss` or the M6 ch6 baseline of 7.0.
    pub fn block_osv_min_cvss_effective(&self) -> f32 {
        self.block_osv_min_cvss
            .unwrap_or(DEFAULT_BLOCK_OSV_MIN_CVSS)
    }
    /// The repo-mismatch verification cap — `repo_mismatch_check_max_packages`
    /// or the M6 ch6 baseline of 50.
    pub fn repo_mismatch_check_max_packages_effective(&self) -> u32 {
        self.repo_mismatch_check_max_packages
            .unwrap_or(DEFAULT_REPO_MISMATCH_CHECK_MAX_PACKAGES)
    }
}

/// M6 ch7 baseline thresholds — these match the constants the M6 ch6
/// install/scan paths previously hard-coded. Centralised here so the
/// `package_policy.*_effective` helpers and the `policy init` template
/// agree on a single source of truth.
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
            // The M6 ch6 install-script signal ships as Warn-baseline; the
            // ch7 default keeps it on so existing operators do not lose the
            // finding silently.
            warn_install_script_network_call: true,
            // The M6 ch6 dep-confusion finding is High → Block by the
            // default severity → action mapping. Default `true` preserves
            // that behavior.
            block_dependency_confusion: true,
            internal_package_names: Vec::new(),
            repo_mismatch_check_max_packages: None,
        }
    }
}

impl Policy {
    /// Discover and load partial policy (just bypass + fail_mode fields).
    /// Used in Tier 2 for fast bypass resolution.
    /// Uses the same resolution order as full discovery (TIRITH_POLICY_ROOT,
    /// walk-up, user-level) so bypass settings are consistent.
    ///
    /// **M11 ch5** — incident-mode runtime overrides are applied here too, so
    /// the engine's tier-2 `TIRITH=0` bypass branch (which reads this partial
    /// policy's `allow_bypass_env*` flags) honors an active incident and
    /// refuses the bypass. Without this, a fast-exiting or bypass-requested
    /// command would skip the override that full [`Self::discover`] applies.
    pub fn discover_partial(cwd: Option<&str>) -> Self {
        let mut p = Self::discover_local(cwd);
        p.apply_runtime_overrides();
        p
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
    ///
    /// **M11 ch5** — after the local/remote policy is resolved, incident-mode
    /// runtime overrides are merged in via [`Self::apply_runtime_overrides`].
    /// This is the single hot-path hook that flips the engine fail-closed and
    /// disables the `TIRITH=0` bypass while an incident is active.
    pub fn discover(cwd: Option<&str>) -> Self {
        let mut p = Self::discover_resolved(cwd);
        p.apply_runtime_overrides();
        p
    }

    /// The local/remote resolution body for [`Self::discover`], WITHOUT the
    /// incident-override merge. Split out so the override is applied exactly
    /// once on the final resolved policy regardless of which remote-fetch
    /// branch produced it.
    fn discover_resolved(cwd: Option<&str>) -> Self {
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
                // Run schema migrations on the raw YAML before deserialization
                // (M5.5 chunk F3). The v1→v2 migration registered by M6 ch7
                // (legacy top-level `internal_package_names` → `package_policy`)
                // runs on remote-fetched policies the same as local ones.
                match Self::try_parse_yaml(&yaml) {
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
        let content = match std::fs::read_to_string(path) {
            Ok(c) => c,
            Err(e) => {
                eprintln!(
                    "tirith: warning: cannot read policy at {}: {e}",
                    path.display()
                );
                // Read failure on a NAMED policy file is a misconfiguration,
                // not "no policy" — fail closed so an operator who shipped a
                // `fail_mode: closed` policy isn't silently downgraded to
                // open. The default open-policy branch is reserved for the
                // "no policy file found anywhere" case (handled by the
                // discovery walk, not this loader).
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
                // Same logic: a parse failure on a named policy file
                // (typo, schema-future-version, etc.) hides the operator's
                // configuration — fail closed rather than silently revert
                // to the open default.
                Self::fail_closed_policy()
            }
        }
    }

    /// Parse YAML text into a `Policy`, running schema migrations first.
    ///
    /// Returns `Err(message)` instead of printing+falling back; callers
    /// that want fail-mode-aware handling (e.g. the remote-policy fetch
    /// path) use this. Local-file loading uses [`Self::load_from_yaml`]
    /// which wraps this with the existing warn-and-default behavior.
    pub fn try_parse_yaml(content: &str) -> Result<Self, String> {
        let mut value: serde_yaml::Value =
            serde_yaml::from_str(content).map_err(|e| format!("yaml parse error: {e}"))?;
        crate::policy_migrations::migrate_forward(&mut value)
            .map_err(|e| format!("migration error: {e}"))?;
        serde_yaml::from_value::<Policy>(value).map_err(|e| format!("deserialize error: {e}"))
    }

    /// Load a policy from YAML text, running schema migrations first.
    ///
    /// Public so tests (and future remote-fetch paths) can exercise the
    /// migrate-then-deserialize sequence without going through the file
    /// system.
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

    /// **M11 ch5** — merge incident-mode runtime overrides on top of this
    /// loaded policy, in place.
    ///
    /// When [`crate::incident::active_cached`] reports an active incident,
    /// the following overrides are applied:
    ///
    /// * `fail_mode` → [`FailMode::Closed`]
    /// * `allow_bypass_env` → `false`
    /// * `allow_bypass_env_noninteractive` → `false`
    /// * a `severity_overrides` entry for each rule in
    ///   [`crate::incident::INCIDENT_ELEVATED_RULES`], applied ONLY when it
    ///   would *raise* the rule's effective severity above what the operator
    ///   already pinned (we never downgrade an explicit override).
    ///
    /// This runs on EVERY analyze (it is called from [`Self::discover`] and
    /// [`Self::discover_partial`], which back all hot paths). To keep the
    /// common no-incident case cheap, the active-check is behind a 5-second
    /// per-process stat cache in [`crate::incident::active_cached`]; when no
    /// flag file exists the cost is a single `metadata()` stat (and nothing
    /// within the TTL window), and this method is a near-noop early return.
    pub fn apply_runtime_overrides(&mut self) {
        // Near-noop fast path: no active incident → leave the policy untouched.
        if crate::incident::active_cached().is_none() {
            return;
        }

        // Incident active: force fail-closed and disable the env bypass in both
        // interactivity modes. The bypass disable is what makes `tirith check`
        // ignore `TIRITH=0` while an incident is active (see the engine's
        // `bypass_requested` branch, which reads these two flags).
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
                // Operator already pinned this rule at or above the incident
                // level — respect it, don't lower it.
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

    /// **M8 ch1** — load context-label entries from the user-scope and
    /// repo-scope label files and merge them into `context_labels`.
    ///
    /// Files (resolution order, both applied — repo wins on conflict):
    ///   1. `~/.config/tirith/context-labels.yaml` (user scope)
    ///   2. `<repo>/.tirith/context-labels.yaml` (repo scope)
    ///
    /// Format is a flat YAML map: `provider:context: criticality`. Empty
    /// or missing files are not errors. Parse failures emit a diagnostic
    /// and continue with the other file.
    pub fn load_context_labels(&mut self, cwd: Option<&str>) {
        if let Some(user_path) = user_context_labels_path() {
            merge_context_labels(&user_path, &mut self.context_labels);
        }
        if let Some(repo_root) = find_repo_root(cwd) {
            let repo_path = repo_root.join(".tirith").join("context-labels.yaml");
            merge_context_labels(&repo_path, &mut self.context_labels);
        }
    }

    /// **M8 ch2** — load SSH host-label entries from the user-scope and
    /// repo-scope label files and merge them into `ssh_host_labels`.
    ///
    /// Files (resolution order, both applied — repo wins on conflict):
    ///   1. `~/.config/tirith/ssh-host-labels.yaml` (user scope)
    ///   2. `<repo>/.tirith/ssh-host-labels.yaml` (repo scope)
    ///
    /// Format is a flat YAML map: `host: criticality`. The host string
    /// may include a `user@` prefix; the lookup is exact-match with a
    /// fall-back to the bare host (see `rules::ssh_context`).
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

/// **M8 ch1** — user-scope context-labels file path.
///
/// `~/.config/tirith/context-labels.yaml` (XDG `${XDG_CONFIG_HOME}` honored
/// via `etcetera`). Returns `None` if no config dir is resolvable.
pub fn user_context_labels_path() -> Option<PathBuf> {
    config_dir().map(|d| d.join("context-labels.yaml"))
}

/// **M8 ch1** — repo-scope context-labels file path for a given cwd, if
/// the cwd is inside a git repo. Returns `None` when no `.git` is found.
pub fn repo_context_labels_path(cwd: Option<&str>) -> Option<PathBuf> {
    find_repo_root(cwd).map(|r| r.join(".tirith").join("context-labels.yaml"))
}

/// **M8 ch2** — user-scope SSH host-labels file path.
///
/// `~/.config/tirith/ssh-host-labels.yaml`. Returns `None` if no config
/// dir is resolvable.
pub fn user_ssh_host_labels_path() -> Option<PathBuf> {
    config_dir().map(|d| d.join("ssh-host-labels.yaml"))
}

/// **M8 ch2** — repo-scope SSH host-labels file path for a given cwd, if
/// the cwd is inside a git repo. Returns `None` when no `.git` is found.
pub fn repo_ssh_host_labels_path(cwd: Option<&str>) -> Option<PathBuf> {
    find_repo_root(cwd).map(|r| r.join(".tirith").join("ssh-host-labels.yaml"))
}

/// **M8 ch3** — directory where `tirith iac check-plan` records the
/// SHA-256 hash of each plan it has reviewed.
///
/// Path: `state_dir()/iac_plans/`. Files inside are named after the plan's
/// hex SHA-256 (`<hash>.json`) with the recorded metadata. Returns `None`
/// when `state_dir()` itself is unresolvable.
pub fn iac_plans_dir() -> Option<PathBuf> {
    state_dir().map(|s| s.join("iac_plans"))
}

/// Merge a single labels file's entries into `into`. The file is a flat
/// YAML map (`String -> String`). Missing files are silently ignored;
/// parse errors emit a stderr diagnostic and continue.
fn merge_context_labels(path: &Path, into: &mut BTreeMap<String, String>) {
    let content = match std::fs::read_to_string(path) {
        Ok(c) => c,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return,
        Err(e) => {
            // Permission / UTF-8 / other I/O — surface the failure so the
            // operator knows labels were skipped (PR-127 review #13).
            eprintln!(
                "tirith: warning: context-labels file at {} read error: {e}",
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

/// Write a single label entry to a labels file (creates the file and
/// parent directory if needed). Used by `tirith context label`. Preserves
/// existing entries — only the target key is overwritten.
pub fn write_context_label(path: &Path, label_key: &str, criticality: &str) -> std::io::Result<()> {
    let mut existing: BTreeMap<String, String> = BTreeMap::new();
    merge_context_labels(path, &mut existing);
    existing.insert(label_key.to_string(), criticality.to_string());

    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }

    let yaml = serde_yaml::to_string(&existing).map_err(|e| {
        std::io::Error::new(std::io::ErrorKind::InvalidData, format!("serialize: {e}"))
    })?;
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let mut f = opts.open(path)?;
    use std::io::Write as _;
    f.write_all(yaml.as_bytes())?;
    Ok(())
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
///
/// Runs the same forward-migration sequence as the direct remote-success
/// path (via [`Policy::try_parse_yaml`]) so a cached policy written by an
/// older tirith version is upgraded before deserialization. Without this,
/// `policy_fetch_fail_mode: cached` would silently skip migrations and
/// drop fields the schema relocated (e.g. legacy `internal_package_names`
/// migrated into `package_policy` by the v1→v2 migration).
fn load_cached_remote_policy() -> Option<Policy> {
    let path = remote_policy_cache_path()?;
    let content = std::fs::read_to_string(&path).ok()?;
    match Policy::try_parse_yaml(&content) {
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
        // And `tirith policy validate` must not flag the new fields as unknown.
        let issues = crate::policy_validate::validate(&yaml);
        assert!(
            !issues.iter().any(|i| i
                .field
                .as_deref()
                .map(|f| f.contains("filesystem_write")
                    || f.contains("network")
                    || f.contains("secrets_access"))
                .unwrap_or(false)),
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
}
