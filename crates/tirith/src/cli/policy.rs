use std::path::PathBuf;

use tirith_core::engine::{self, AnalysisContext};
use tirith_core::extract::ScanContext;
use tirith_core::policy::Policy;
use tirith_core::policy_validate::{self, IssueLevel};
use tirith_core::scan;
use tirith_core::tokenize::ShellType;
use tirith_core::verdict::Severity;

const FULL_TEMPLATE: &str = r#"# Tirith security policy
# Documentation: https://tirith.dev/docs/policy

# Fail mode: "open" (allow on error) or "closed" (block on error)
fail_mode: open

# Paranoia level (1-4): higher = more sensitive detection
paranoia: 1

# Allow TIRITH=0 bypass in interactive terminals
allow_bypass_env: true

# Require explicit acknowledgement for warn findings in interactive mode
strict_warn: false

# Severity overrides per rule (e.g., shortened_url: LOW)
severity_overrides: {}

# URL patterns to always allow
allowlist: []

# URL patterns to always block (overrides allowlist)
blocklist: []

# Force specific rules to block (upgrade only, cannot downgrade)
# action_overrides:
#   shortened_url: block

# Escalation: upgrade warnings to blocks based on session history
# escalation:
#   - trigger: repeat_count    # block after N warnings for the same rule
#     rule_ids: ["*"]          # "*" = any rule, or list specific rule IDs
#     threshold: 5
#     window_minutes: 60
#     action: block
#   - trigger: multi_medium    # block when N+ medium findings on one command
#     min_findings: 3
#     action: block

# Scan configuration overrides.
scan:
  # Glob patterns to ignore during scan
  ignore_patterns: []

  # MCP server names you trust. A name listed here suppresses every
  # per-server MCP config finding (insecure transport, raw IP, suspicious
  # args, wildcard tools, duplicate name) and exempts the server from
  # drift detection via `tirith mcp verify` / the `mcp_server_drift` rule.
  # Run `tirith mcp policy init` to scaffold this list from `.tirith/mcp.lock`.
  # trusted_mcp_servers:
  #   - my-trusted-server

  # Per-server allowed tools. Keys are MCP server names; values are the
  # tool names that server may expose. A tool the lockfile records that
  # is NOT in this set raises a High-severity `mcp_server_drift` finding,
  # and drift that adds a tool outside the set upgrades the drift finding
  # from Medium to High. Servers not listed here are unconstrained.
  # mcp_allowed_tools:
  #   my-trusted-server:
  #     - read_only

# Per-agent governance rules — M4 item 8 (enforcement).
#
# `agent_rules` lets a policy declare which AgentOrigin variants it
# allows or denies, where `AgentOrigin` is the recorded caller — Human,
# Agent, Mcp, Gateway, Ci, or Ide. A `deny` match forces the verdict to
# Block and appends an `agent_denied_by_policy` finding naming the
# matched origin and policy file; a `deny` entry beats any matching
# `allow` entry, mirroring how `blocklist` beats `allowlist`. `allow`
# is NOT a bypass — a verdict the engine already blocked stays blocked
# even if the caller is on the allow list. See `rule_explanations.toml`
# (`agent_denied_by_policy`) for the operator-facing description.
#
# Enforcement scope: `apply_agent_rules` runs on every analysis path —
# `tirith check`, the gateway request / notification paths, `tirith
# paste`, `tirith install`, `tirith ecosystem scan`, and all MCP
# `tools/call_check_*` handlers (`call_check_command`, `call_check_url`,
# `call_check_paste`). The interactive `TIRITH=0` bypass currently
# skips `apply_agent_rules` (pinned by
# `agent_rules_deny_skipped_under_tirith_bypass_today`); revisit that
# semantic in M5.
#
# Trust caveat: every signal feeding AgentOrigin is OPERATOR-TRUST,
# never adversary-resistant — TIRITH_INTEGRATION, MCP clientInfo, CI
# env vars are all settable by any process running as the user. Use
# `agent_rules` for operator-trust scoping ("I do not run my MCP
# server's commands on traffic my CI ran"), not adversarial security;
# layer real authentication elsewhere if the decision must withstand a
# hostile environment.
#
# Run `tirith agent policy init` to scaffold this block from the local
# audit log's observed origins.
# agent_rules:
#   allow:
#     - kind: agent
#       name: claude-code
#     - kind: human
#   deny:
#     - kind: agent
#       name: untrusted-tool
"#;

const MINIMAL_TEMPLATE: &str = r#"fail_mode: open
paranoia: 1
allowlist: []
blocklist: []
"#;

/// `individual` — defaults for a single developer (fail-open, paranoia 1, the
/// noisiest pipe-to-shell rule escalated, empty allowlist). Body lives in
/// `assets/policy_templates/individual.yaml`, resolved via `include_str!` so the
/// on-disk `.yaml` is the single source of truth (shared with the validity test).
const TEMPLATE_INDIVIDUAL: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/assets/policy_templates/individual.yaml"
));

/// `ci-strict` — locked-down CI settings: fail-closed, no bypass, strict warn,
/// and a `scan.fail_on` threshold that fails the build on high-severity findings.
const TEMPLATE_CI_STRICT: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/assets/policy_templates/ci-strict.yaml"
));

/// `ai-agent-heavy` — for environments where AI agents run many commands.
/// Fail-open (so an agent isn't wedged by an internal error) but raised
/// paranoia, no non-interactive bypass, approval for the highest-risk rules, and
/// escalation on repeated warnings.
const TEMPLATE_AI_AGENT_HEAVY: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/assets/policy_templates/ai-agent-heavy.yaml"
));

/// `oss-maintainer` — for a public OSS repo maintainer. Moderate (paranoia 2,
/// fail-open) with the untrusted-contributor threat model in focus: typosquat,
/// install-script, and untrusted-registry rules escalated.
const TEMPLATE_OSS_MAINTAINER: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/assets/policy_templates/oss-maintainer.yaml"
));

/// `startup` — for a small fast team: a notch stricter than `individual`
/// (paranoia 2, strict-warn on, noisiest pipe-to-shell rules escalated) but not
/// fail-closed.
const TEMPLATE_STARTUP: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/assets/policy_templates/startup.yaml"
));

/// `enterprise` — strict, audit-friendly defaults: fail-closed, no bypass,
/// paranoia 3, and (uniquely) an ACTIVE `package_policy:` block with strict
/// supply-chain thresholds out of the box.
const TEMPLATE_ENTERPRISE: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/assets/policy_templates/enterprise.yaml"
));

/// `mcp-strict` — locked-down for MCP-heavy environments: fail-closed,
/// paranoia 3, every MCP config rule (insecure / untrusted / overly-permissive /
/// suspicious-args / drift) escalated.
const TEMPLATE_MCP_STRICT: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/assets/policy_templates/mcp-strict.yaml"
));

/// A curated starter policy selected via `tirith policy init --template`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PolicyTemplate {
    Individual,
    CiStrict,
    AiAgentHeavy,
    OssMaintainer,
    Startup,
    Enterprise,
    McpStrict,
}

impl PolicyTemplate {
    /// Every variant, in canonical display order. The single source of truth for
    /// "which templates exist" (R20): the `--template` help list is built from
    /// this via [`PolicyTemplate::canonical_name`], so it can never go stale.
    pub const ALL: &'static [PolicyTemplate] = &[
        Self::Individual,
        Self::CiStrict,
        Self::AiAgentHeavy,
        Self::OssMaintainer,
        Self::Startup,
        Self::Enterprise,
        Self::McpStrict,
    ];

    /// Comma-separated canonical template names for help/error text, derived from
    /// [`PolicyTemplate::ALL`] so it stays in lock-step with the enum.
    fn names_csv() -> String {
        Self::ALL
            .iter()
            .map(|t| t.canonical_name())
            .collect::<Vec<_>>()
            .join(", ")
    }

    /// Parse a `--template` value (`None` if unrecognized). `personal` is an alias
    /// for `individual` (the shipping name); both resolve to the same body.
    pub fn parse(name: &str) -> Option<Self> {
        match name.trim().to_ascii_lowercase().as_str() {
            "individual" | "personal" => Some(Self::Individual),
            "ci-strict" | "ci_strict" => Some(Self::CiStrict),
            "ai-agent-heavy" | "ai_agent_heavy" => Some(Self::AiAgentHeavy),
            "oss-maintainer" | "oss_maintainer" => Some(Self::OssMaintainer),
            "startup" => Some(Self::Startup),
            "enterprise" => Some(Self::Enterprise),
            "mcp-strict" | "mcp_strict" => Some(Self::McpStrict),
            _ => None,
        }
    }

    /// The canonical hyphenated name. Round-trips through [`PolicyTemplate::parse`]
    /// so `tirith onboard` can pass it to `policy init --template <name>`. The
    /// `personal` alias maps to `Individual`, so its canonical name is `individual`.
    pub fn canonical_name(self) -> &'static str {
        match self {
            Self::Individual => "individual",
            Self::CiStrict => "ci-strict",
            Self::AiAgentHeavy => "ai-agent-heavy",
            Self::OssMaintainer => "oss-maintainer",
            Self::Startup => "startup",
            Self::Enterprise => "enterprise",
            Self::McpStrict => "mcp-strict",
        }
    }

    /// The YAML body this template writes.
    fn body(self) -> &'static str {
        match self {
            Self::Individual => TEMPLATE_INDIVIDUAL,
            Self::CiStrict => TEMPLATE_CI_STRICT,
            Self::AiAgentHeavy => TEMPLATE_AI_AGENT_HEAVY,
            Self::OssMaintainer => TEMPLATE_OSS_MAINTAINER,
            Self::Startup => TEMPLATE_STARTUP,
            Self::Enterprise => TEMPLATE_ENTERPRISE,
            Self::McpStrict => TEMPLATE_MCP_STRICT,
        }
    }
}

pub fn init(force: bool, minimal: bool, template: Option<&str>) -> i32 {
    // Resolve the template before touching the filesystem so a typo fails fast.
    let selected_template = match template {
        Some(name) => match PolicyTemplate::parse(name) {
            Some(t) => Some(t),
            None => {
                eprintln!("tirith policy init: unknown template '{name}'");
                // Derived from `PolicyTemplate::ALL` so it can't drift (R20).
                eprintln!("  valid templates: {}", PolicyTemplate::names_csv());
                eprintln!("  ('personal' is accepted as an alias of 'individual')");
                return 1;
            }
        },
        None => None,
    };

    if selected_template.is_some() && minimal {
        eprintln!("tirith policy init: --template and --minimal cannot be combined");
        return 1;
    }

    init_with_template(force, minimal, selected_template)
}

fn init_with_template(force: bool, minimal: bool, template: Option<PolicyTemplate>) -> i32 {
    let cwd = std::env::current_dir()
        .ok()
        .map(|p| p.display().to_string());
    let repo_root = match tirith_core::policy::find_repo_root(cwd.as_deref()) {
        Some(r) => r,
        None => {
            // No git repo — fall back to cwd.
            match std::env::current_dir() {
                Ok(d) => d,
                Err(e) => {
                    eprintln!("tirith policy init: cannot determine working directory: {e}");
                    return 1;
                }
            }
        }
    };

    let tirith_dir = repo_root.join(".tirith");
    let policy_path = tirith_dir.join("policy.yaml");

    if policy_path.exists() && !force {
        eprintln!(
            "tirith policy init: {} already exists (use --force to overwrite)",
            policy_path.display()
        );
        return 1;
    }

    // If we create `.tirith` on a fresh repo, its new entry in `repo_root` must be
    // fsync'd too, or a crash could lose it — `write_file_atomic` only fsyncs
    // `.tirith` (policy.yaml's parent), not `repo_root`. CodeRabbit R13b.
    let tirith_dir_existed = tirith_dir.exists();
    if let Err(e) = std::fs::create_dir_all(&tirith_dir) {
        eprintln!(
            "tirith policy init: cannot create {}: {e}",
            tirith_dir.display()
        );
        return 1;
    }
    if !tirith_dir_existed {
        tirith_core::util::fsync_parent_dir_logged(&tirith_dir, "policy .tirith directory");
    }

    let template_body = match (template, minimal) {
        (Some(t), _) => t.body(),
        (None, true) => MINIMAL_TEMPLATE,
        (None, false) => FULL_TEMPLATE,
    };

    // Write the policy ATOMICALLY (temp → fsync → rename → parent fsync), so a
    // crash mid-write never loses the prior policy. Without `--force`,
    // `overwrite=false` makes it no-clobber, so a policy created in the race window
    // after the `exists()` check surfaces as a write error instead of being lost.
    if let Err(e) = super::write_file_atomic(&policy_path, template_body.as_bytes(), force) {
        eprintln!(
            "tirith policy init: cannot write {}: {e}",
            policy_path.display()
        );
        return 1;
    }

    let label = match template {
        Some(PolicyTemplate::Individual) => " (individual template)",
        Some(PolicyTemplate::CiStrict) => " (ci-strict template)",
        Some(PolicyTemplate::AiAgentHeavy) => " (ai-agent-heavy template)",
        Some(PolicyTemplate::OssMaintainer) => " (oss-maintainer template)",
        Some(PolicyTemplate::Startup) => " (startup template)",
        Some(PolicyTemplate::Enterprise) => " (enterprise template)",
        Some(PolicyTemplate::McpStrict) => " (mcp-strict template)",
        None if minimal => " (minimal template)",
        None => "",
    };
    eprintln!(
        "tirith policy init: created {}{label}",
        policy_path.display()
    );
    0
}

pub fn validate(path: Option<&str>, json: bool) -> i32 {
    let policy_path = match resolve_policy_path(path) {
        Some(p) => p,
        None => {
            eprintln!("tirith policy validate: no policy file found");
            eprintln!("  run `tirith policy init` to create one");
            return 1;
        }
    };

    let yaml = match std::fs::read_to_string(&policy_path) {
        Ok(s) => s,
        Err(e) => {
            eprintln!(
                "tirith policy validate: cannot read {}: {e}",
                policy_path.display()
            );
            return 1;
        }
    };

    let issues = policy_validate::validate(&yaml);

    if json {
        print_validate_json(&policy_path, &issues);
    } else {
        print_validate_human(&policy_path, &issues);
    }

    if issues.iter().any(|i| i.level == IssueLevel::Error) {
        1
    } else {
        0
    }
}

fn print_validate_json(path: &std::path::Path, issues: &[policy_validate::PolicyIssue]) {
    #[derive(serde::Serialize)]
    struct Output<'a> {
        path: String,
        valid: bool,
        error_count: usize,
        warning_count: usize,
        issues: &'a [policy_validate::PolicyIssue],
    }

    let error_count = issues
        .iter()
        .filter(|i| i.level == IssueLevel::Error)
        .count();
    let warning_count = issues
        .iter()
        .filter(|i| i.level == IssueLevel::Warning)
        .count();

    let output = Output {
        path: path.display().to_string(),
        valid: error_count == 0,
        error_count,
        warning_count,
        issues,
    };

    if let Err(e) = serde_json::to_writer_pretty(std::io::stdout().lock(), &output) {
        eprintln!("tirith policy validate: failed to write JSON output: {e}");
    }
    println!();
}

fn print_validate_human(path: &std::path::Path, issues: &[policy_validate::PolicyIssue]) {
    if issues.is_empty() {
        eprintln!(
            "tirith policy validate: {} — valid, no issues",
            path.display()
        );
        return;
    }

    let error_count = issues
        .iter()
        .filter(|i| i.level == IssueLevel::Error)
        .count();
    let warning_count = issues
        .iter()
        .filter(|i| i.level == IssueLevel::Warning)
        .count();

    eprintln!(
        "tirith policy validate: {} — {} error(s), {} warning(s)",
        path.display(),
        error_count,
        warning_count
    );

    for issue in issues {
        let s = tirith_core::style::Stream::Stderr;
        let prefix = match issue.level {
            IssueLevel::Error => tirith_core::style::red("error", s),
            IssueLevel::Warning => tirith_core::style::yellow("warning", s),
        };
        let field_suffix = issue
            .field
            .as_ref()
            .map(|f| format!(" ({f})"))
            .unwrap_or_default();
        eprintln!("  {prefix}: {}{field_suffix}", issue.message);
    }
}

pub fn test(command: Option<&str>, file: Option<&str>, json: bool) -> i32 {
    if command.is_none() && file.is_none() {
        eprintln!("tirith policy test: specify a command or --file <path>");
        return 1;
    }

    if let Some(file_path) = file {
        return test_file(file_path, json);
    }

    test_command(command.unwrap(), json)
}

fn test_command(command: &str, json: bool) -> i32 {
    let cwd = std::env::current_dir()
        .ok()
        .map(|p| p.display().to_string());

    let ctx = AnalysisContext {
        input: command.to_string(),
        shell: ShellType::Posix,
        scan_context: ScanContext::Exec,
        raw_bytes: None,
        interactive: false,
        cwd: cwd.clone(),
        file_path: None,
        repo_root: None,
        is_config_override: false,
        clipboard_html: None,
        card_ref: None,
        clipboard_source: tirith_core::clipboard::ClipboardSourceState::Unread,
    };

    let mut verdict = engine::analyze(&ctx);
    let policy = Policy::discover(cwd.as_deref());
    engine::filter_findings_by_paranoia(&mut verdict, policy.paranoia);

    let trace = build_policy_trace(command, &policy);

    if json {
        print_test_command_json(command, &verdict, &policy, &trace);
    } else {
        print_test_command_human(command, &verdict, &policy, &trace);
    }

    verdict.action.exit_code()
}

fn test_file(file_path: &str, json: bool) -> i32 {
    let path = PathBuf::from(file_path);
    if !path.exists() {
        eprintln!("tirith policy test: file not found: {file_path}");
        return 1;
    }

    // Guarded so a crafted file that panics a rule reports an error instead of
    // crashing the process.
    let result = match scan::scan_single_file_guarded(&path) {
        Ok(Some(r)) => r,
        Ok(None) => {
            eprintln!("tirith policy test: could not read file: {file_path}");
            return 1;
        }
        Err(scan::RulePanic) => {
            eprintln!("tirith policy test: internal error scanning {file_path}: a rule panicked");
            return 1;
        }
    };

    let cwd = std::env::current_dir()
        .ok()
        .map(|p| p.display().to_string());
    let policy = Policy::discover(cwd.as_deref());

    if json {
        print_test_file_json(file_path, &result, &policy);
    } else {
        print_test_file_human(file_path, &result, &policy);
    }

    if result.findings.is_empty() {
        0
    } else if result.findings.iter().any(|f| f.severity >= Severity::High) {
        1 // block-equivalent
    } else {
        2 // warn-equivalent
    }
}

/// Run `tirith policy tune --from-audit`: roll up per-rule audit-log statistics
/// and print deterministic tuning suggestions. Never edits the policy.
pub fn tune(from_audit: bool, json: bool) -> i32 {
    if !from_audit {
        eprintln!("tirith policy tune: specify a source — currently only --from-audit");
        eprintln!("  try: tirith policy tune --from-audit");
        return 1;
    }

    let log_path = match tirith_core::policy::data_dir() {
        Some(d) => d.join("log.jsonl"),
        None => {
            eprintln!("tirith policy tune: could not determine audit log path");
            return 1;
        }
    };

    if !log_path.exists() {
        eprintln!(
            "tirith policy tune: no audit log found at {}",
            log_path.display()
        );
        eprintln!("  tirith records an audit log as you use it; come back once you have history.");
        return 1;
    }

    let result = match tirith_core::audit_aggregator::read_log(&log_path) {
        Ok(r) => r,
        Err(e) => {
            // `read_log` only fails on an I/O error (malformed lines are skipped),
            // so re-probe to distinguish an actionable permissions problem.
            eprintln!(
                "tirith policy tune: could not read the audit log at {}",
                log_path.display()
            );
            match std::fs::File::open(&log_path) {
                Err(probe) if probe.kind() == std::io::ErrorKind::PermissionDenied => {
                    eprintln!(
                        "  permission denied — check that you can read the file \
                         (its directory may also need execute permission)."
                    );
                }
                _ => {
                    eprintln!("  {e}");
                    eprintln!(
                        "  the file may be unreadable or have been removed mid-read; \
                         retry, or check the path's permissions."
                    );
                }
            }
            return 1;
        }
    };
    if result.skipped_lines > 0 {
        eprintln!(
            "tirith policy tune: warning: {} malformed audit log line(s) skipped",
            result.skipped_lines
        );
    }

    // Every rule tirith can emit — to point out rules that never fired.
    let known_rules: Vec<&str> = tirith_core::rule_explanations::list_all()
        .iter()
        .map(|r| r.id)
        .collect();

    let report = tirith_core::audit_tune::analyze(&result.records, &known_rules);

    if json {
        if serde_json::to_writer_pretty(std::io::stdout().lock(), &report).is_err() {
            eprintln!("tirith policy tune: failed to write JSON output");
            return 1;
        }
        println!();
    } else {
        print_tune_human(&report);
    }

    0
}

fn print_tune_human(report: &tirith_core::audit_tune::TuneReport) {
    eprintln!(
        "tirith policy tune: analyzed {} audit record(s)",
        report.records_analyzed
    );

    if report.data_is_thin {
        eprintln!(
            "  not enough audit history to suggest anything yet (need at least {}).",
            tirith_core::audit_tune::MIN_OBSERVATIONS
        );
        eprintln!("  keep using tirith and re-run this once more commands have been analyzed.");
        return;
    }

    if report.suggestions.is_empty() {
        eprintln!(
            "  no policy changes suggested — your current policy looks well matched to your usage."
        );
        return;
    }

    eprintln!(
        "  {} suggestion(s) — these are SUGGESTIONS only; review each, then edit your policy yourself:",
        report.suggestions.len()
    );
    eprintln!();

    for (i, s) in report.suggestions.iter().enumerate() {
        let conf = match s.confidence {
            tirith_core::audit_tune::Confidence::Strong => "strong",
            tirith_core::audit_tune::Confidence::Moderate => "moderate",
        };
        eprintln!("  {}. [{}] {}", i + 1, conf, s.observation);
        eprintln!("     {}", s.recommendation);
        if let Some(snippet) = &s.policy_snippet {
            eprintln!("     suggested policy snippet:");
            for line in snippet.lines() {
                eprintln!("       {line}");
            }
        }
        eprintln!();
    }

    eprintln!("  tirith did not change your policy. Apply any suggestion by editing your .tirith/policy.yaml.");
}

/// The fully-resolved local policy plus its provenance, as gathered for
/// `tirith policy effective`. Factored out of [`effective`] so the gathering is
/// unit-testable without capturing stdout (the rendering is a thin function of
/// these fields).
struct EffectivePolicy {
    /// Source file the policy was loaded from, or `None` for built-in defaults.
    source_path: Option<String>,
    /// Discovery scope (which branch matched) — drives the trust framing below.
    scope: tirith_core::policy::PolicyScope,
    /// The resolved policy itself (repo-scope sanitization already applied).
    policy: Policy,
}

/// Map a [`PolicyScope`] to its lowercase label for output. The single mapping
/// point shared by both the JSON `scope` field and the human framing.
///
/// [`PolicyScope`]: tirith_core::policy::PolicyScope
fn scope_label(scope: tirith_core::policy::PolicyScope) -> &'static str {
    use tirith_core::policy::PolicyScope;
    match scope {
        PolicyScope::Repo => "repo",
        PolicyScope::User => "user",
        PolicyScope::Org => "org",
        PolicyScope::Remote => "remote",
        PolicyScope::Default => "default",
    }
}

/// Gather the effective local policy for `cwd`: its source path + scope (via
/// [`discover_local_policy_path_scoped`]) and the fully-resolved policy (via
/// [`Policy::discover_local_only`], which runs LOCAL resolution + repo-scope
/// sanitize and NEVER fetches remotely). Discovery-only; no network.
///
/// [`discover_local_policy_path_scoped`]: tirith_core::policy::discover_local_policy_path_scoped
fn gather_effective(cwd: Option<&str>) -> EffectivePolicy {
    let (source_path, scope) = match tirith_core::policy::discover_local_policy_path_scoped(cwd) {
        Some((path, scope)) => (Some(path.display().to_string()), scope),
        None => (None, tirith_core::policy::PolicyScope::Default),
    };
    let policy = Policy::discover_local_only(cwd);
    EffectivePolicy {
        source_path,
        scope,
        policy,
    }
}

/// `tirith policy effective` — a transparency surface that prints the FULLY-
/// RESOLVED effective policy for the current directory, where it came from, and
/// (for a repo-scoped policy) which weakening fields were neutralized down to
/// tightening-only. Discovery-only: no path argument, no network fetch (uses
/// [`Policy::discover_local_only`], not [`Policy::discover`]).
pub fn effective(json: bool) -> i32 {
    let cwd = std::env::current_dir()
        .ok()
        .map(|p| p.display().to_string());

    let info = gather_effective(cwd.as_deref());

    if json {
        print_effective_json(&info)
    } else {
        print_effective_human(&info)
    }
}

fn print_effective_json(info: &EffectivePolicy) -> i32 {
    #[derive(serde::Serialize)]
    struct Output<'a> {
        source_path: Option<&'a str>,
        scope: &'a str,
        neutralized_fields: &'a [&'static str],
        policy: &'a Policy,
    }

    let output = Output {
        source_path: info.source_path.as_deref(),
        scope: scope_label(info.scope),
        neutralized_fields: &info.policy.neutralized_fields,
        policy: &info.policy,
    };

    if super::write_json_stdout(
        &output,
        "tirith policy effective: failed to write JSON output",
    ) {
        0
    } else {
        1
    }
}

fn print_effective_human(info: &EffectivePolicy) -> i32 {
    use tirith_core::policy::PolicyScope;

    eprintln!(
        "tirith policy effective: source = {}",
        info.source_path
            .as_deref()
            .unwrap_or("(none — built-in defaults)")
    );
    eprintln!("  scope: {}", scope_label(info.scope));
    eprintln!();

    // Render the resolved policy as readable YAML (the crate already depends on
    // serde_yaml; the policy is `Serialize`). On the unlikely serialize error,
    // fall back to a note rather than failing the command — the provenance and
    // neutralization sections below are the load-bearing transparency output.
    match serde_yaml::to_string(&info.policy) {
        Ok(yaml) => {
            eprintln!("  effective policy:");
            for line in yaml.lines() {
                eprintln!("    {line}");
            }
        }
        Err(e) => {
            eprintln!("  (could not render effective policy as YAML: {e})");
        }
    }
    eprintln!();

    let neutralized = &info.policy.neutralized_fields;
    match info.scope {
        PolicyScope::Repo if !neutralized.is_empty() => {
            eprintln!(
                "  Neutralized (this repo policy is tightening-only; these weakening fields \
                 were ignored): {}",
                neutralized.join(", ")
            );
        }
        PolicyScope::Repo => {
            eprintln!("  No weakening fields — this repo policy only tightens.");
        }
        _ => {
            eprintln!("  Operator-scoped policy — all fields honored (nothing neutralized).");
        }
    }

    0
}

#[derive(serde::Serialize)]
struct PolicyTrace {
    policy_path: Option<String>,
    allowlist_checked: Vec<AllowBlockMatch>,
    blocklist_checked: Vec<AllowBlockMatch>,
}

#[derive(serde::Serialize)]
struct AllowBlockMatch {
    pattern: String,
    matched: bool,
}

fn build_policy_trace(input: &str, policy: &Policy) -> PolicyTrace {
    let input_lower = input.to_lowercase();
    let allowlist_checked: Vec<AllowBlockMatch> = policy
        .allowlist
        .iter()
        .map(|pattern| AllowBlockMatch {
            pattern: pattern.clone(),
            matched: tirith_core::policy::allowlist_pattern_matches(pattern, input),
        })
        .collect();

    let blocklist_checked: Vec<AllowBlockMatch> = policy
        .blocklist
        .iter()
        .map(|pattern| AllowBlockMatch {
            pattern: pattern.clone(),
            matched: input_lower.contains(&pattern.to_lowercase()),
        })
        .collect();

    PolicyTrace {
        policy_path: policy.path.clone(),
        allowlist_checked,
        blocklist_checked,
    }
}

fn print_test_command_json(
    command: &str,
    verdict: &tirith_core::verdict::Verdict,
    _policy: &Policy,
    trace: &PolicyTrace,
) {
    #[derive(serde::Serialize)]
    struct Output<'a> {
        command: &'a str,
        action: &'a tirith_core::verdict::Action,
        finding_count: usize,
        findings: &'a [tirith_core::verdict::Finding],
        policy_trace: &'a PolicyTrace,
    }

    let output = Output {
        command,
        action: &verdict.action,
        finding_count: verdict.findings.len(),
        findings: &verdict.findings,
        policy_trace: trace,
    };

    if let Err(e) = serde_json::to_writer_pretty(std::io::stdout().lock(), &output) {
        eprintln!("tirith policy test: failed to write JSON output: {e}");
    }
    println!();
}

fn print_test_file_json(file_path: &str, result: &scan::FileScanResult, _policy: &Policy) {
    #[derive(serde::Serialize)]
    struct Output<'a> {
        file: &'a str,
        finding_count: usize,
        findings: &'a [tirith_core::verdict::Finding],
    }

    let output = Output {
        file: file_path,
        finding_count: result.findings.len(),
        findings: &result.findings,
    };

    if let Err(e) = serde_json::to_writer_pretty(std::io::stdout().lock(), &output) {
        eprintln!("tirith policy test: failed to write JSON output: {e}");
    }
    println!();
}

fn print_test_command_human(
    command: &str,
    verdict: &tirith_core::verdict::Verdict,
    _policy: &Policy,
    trace: &PolicyTrace,
) {
    eprintln!("tirith policy test: command = {:?}", command);
    eprintln!(
        "  policy: {}",
        trace
            .policy_path
            .as_deref()
            .unwrap_or("(default — no policy file)")
    );
    eprintln!("  action: {:?}", verdict.action);
    eprintln!("  findings: {}", verdict.findings.len());

    for finding in &verdict.findings {
        let sev = tirith_core::style::severity_label(
            &finding.severity,
            tirith_core::style::Stream::Stderr,
        );
        eprintln!("    {} {} — {}", sev, finding.rule_id, finding.title);
    }

    if !trace.allowlist_checked.is_empty() || !trace.blocklist_checked.is_empty() {
        eprintln!();
        eprintln!("  policy trace:");
        for entry in &trace.allowlist_checked {
            let mark = if entry.matched { "MATCH" } else { "no match" };
            eprintln!("    allowlist: {:?} -> {mark}", entry.pattern);
        }
        for entry in &trace.blocklist_checked {
            let mark = if entry.matched { "MATCH" } else { "no match" };
            eprintln!("    blocklist: {:?} -> {mark}", entry.pattern);
        }
    }
}

fn print_test_file_human(file_path: &str, result: &scan::FileScanResult, _policy: &Policy) {
    if result.findings.is_empty() {
        eprintln!("tirith policy test: {} — no findings", file_path);
        return;
    }

    eprintln!(
        "tirith policy test: {} — {} finding(s)",
        file_path,
        result.findings.len()
    );

    for finding in &result.findings {
        let sev = tirith_core::style::severity_label(
            &finding.severity,
            tirith_core::style::Stream::Stderr,
        );
        eprintln!("  {} {} — {}", sev, finding.rule_id, finding.title);
        eprintln!("    {}", finding.description);
    }
}

fn resolve_policy_path(explicit: Option<&str>) -> Option<PathBuf> {
    if let Some(p) = explicit {
        let path = PathBuf::from(p);
        if path.exists() {
            return Some(path);
        }
        eprintln!("tirith policy validate: specified path does not exist: {p}");
        return None;
    }

    // Existence-based local discovery (same resolver engine/`doctor` use).
    // `Policy::discover` would drop the path on a parse error, so `validate` could
    // not locate a corrupt policy to report on, and could resolve a `remote:` URL.
    tirith_core::policy::discover_local_policy_path(None)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tirith_core::policy_validate::{self, IssueLevel};

    /// Every curated template must validate cleanly — no errors AND no warnings
    /// (warnings include the unknown-field typo guard, so this proves every key
    /// is a real schema key).
    fn assert_template_valid(name: &str, body: &str) {
        let issues = policy_validate::validate(body);
        let errors: Vec<_> = issues
            .iter()
            .filter(|i| i.level == IssueLevel::Error)
            .collect();
        let warnings: Vec<_> = issues
            .iter()
            .filter(|i| i.level == IssueLevel::Warning)
            .collect();
        assert!(
            errors.is_empty(),
            "{name} template must have no validation errors: {errors:?}"
        );
        assert!(
            warnings.is_empty(),
            "{name} template must have no validation warnings \
             (unknown/typo keys are warnings): {warnings:?}"
        );
    }

    #[test]
    fn individual_template_validates() {
        assert_template_valid("individual", TEMPLATE_INDIVIDUAL);
    }

    // R20: the help/error list is derived from `PolicyTemplate::ALL`, so assert
    // the CSV contains every canonical name and each round-trips through `parse`.
    #[test]
    fn template_names_csv_covers_every_variant() {
        let csv = PolicyTemplate::names_csv();
        for t in PolicyTemplate::ALL {
            let name = t.canonical_name();
            assert!(
                csv.split(", ").any(|n| n == name),
                "names_csv ({csv:?}) must list the canonical name {name:?} for {t:?}"
            );
        }
        // Every comma-separated entry is a real, parseable canonical name.
        for entry in csv.split(", ") {
            assert!(
                PolicyTemplate::parse(entry).is_some(),
                "names_csv entry {entry:?} must parse back to a PolicyTemplate variant"
            );
        }
        // The count matches: no duplicates, no extras.
        assert_eq!(
            csv.split(", ").count(),
            PolicyTemplate::ALL.len(),
            "names_csv must have exactly one entry per variant"
        );
    }

    #[test]
    fn ci_strict_template_validates() {
        assert_template_valid("ci-strict", TEMPLATE_CI_STRICT);
    }

    #[test]
    fn ai_agent_heavy_template_validates() {
        assert_template_valid("ai-agent-heavy", TEMPLATE_AI_AGENT_HEAVY);
    }

    #[test]
    fn oss_maintainer_template_validates() {
        assert_template_valid("oss-maintainer", TEMPLATE_OSS_MAINTAINER);
    }

    #[test]
    fn startup_template_validates() {
        assert_template_valid("startup", TEMPLATE_STARTUP);
    }

    #[test]
    fn enterprise_template_validates() {
        assert_template_valid("enterprise", TEMPLATE_ENTERPRISE);
    }

    #[test]
    fn mcp_strict_template_validates() {
        assert_template_valid("mcp-strict", TEMPLATE_MCP_STRICT);
    }

    #[test]
    fn builtin_full_and_minimal_templates_validate() {
        // Guards the unchanged default + minimal templates alongside the new ones.
        assert_template_valid("full", FULL_TEMPLATE);
        assert_template_valid("minimal", MINIMAL_TEMPLATE);
    }

    #[test]
    fn template_parse_accepts_canonical_and_underscore_names() {
        assert_eq!(
            PolicyTemplate::parse("individual"),
            Some(PolicyTemplate::Individual)
        );
        assert_eq!(
            PolicyTemplate::parse("ci-strict"),
            Some(PolicyTemplate::CiStrict)
        );
        assert_eq!(
            PolicyTemplate::parse("CI-STRICT"),
            Some(PolicyTemplate::CiStrict)
        );
        assert_eq!(
            PolicyTemplate::parse("ai-agent-heavy"),
            Some(PolicyTemplate::AiAgentHeavy)
        );
        assert_eq!(
            PolicyTemplate::parse(" ai_agent_heavy "),
            Some(PolicyTemplate::AiAgentHeavy)
        );
        // M13 ch2 — the four new templates.
        assert_eq!(
            PolicyTemplate::parse("oss-maintainer"),
            Some(PolicyTemplate::OssMaintainer)
        );
        assert_eq!(
            PolicyTemplate::parse("oss_maintainer"),
            Some(PolicyTemplate::OssMaintainer)
        );
        assert_eq!(
            PolicyTemplate::parse("startup"),
            Some(PolicyTemplate::Startup)
        );
        assert_eq!(
            PolicyTemplate::parse("Enterprise"),
            Some(PolicyTemplate::Enterprise)
        );
        assert_eq!(
            PolicyTemplate::parse("mcp-strict"),
            Some(PolicyTemplate::McpStrict)
        );
        assert_eq!(
            PolicyTemplate::parse("mcp_strict"),
            Some(PolicyTemplate::McpStrict)
        );
    }

    #[test]
    fn template_parse_personal_is_alias_for_individual() {
        // `personal` is the spec word; `individual` is the shipping name. The
        // alias resolves to the same variant — and therefore the same body.
        assert_eq!(
            PolicyTemplate::parse("personal"),
            Some(PolicyTemplate::Individual)
        );
        assert_eq!(
            PolicyTemplate::parse(" PERSONAL "),
            Some(PolicyTemplate::Individual)
        );
        // The alias' canonical name is the shipping name, so `tirith onboard`
        // never emits `personal`.
        assert_eq!(
            PolicyTemplate::parse("personal").unwrap().canonical_name(),
            "individual"
        );
        // Byte-for-byte: the alias writes exactly the individual body.
        assert_eq!(
            PolicyTemplate::parse("personal").unwrap().body(),
            TEMPLATE_INDIVIDUAL
        );
        assert_eq!(
            PolicyTemplate::Individual.body(),
            PolicyTemplate::parse("personal").unwrap().body()
        );
    }

    #[test]
    fn template_parse_rejects_unknown_and_deferred_names() {
        assert_eq!(PolicyTemplate::parse("fintech"), None);
        assert_eq!(PolicyTemplate::parse("windows-enterprise"), None);
        assert_eq!(PolicyTemplate::parse(""), None);
        assert_eq!(PolicyTemplate::parse("default"), None);
    }

    /// Every template body must deserialize through the same
    /// `serde_yaml::from_str::<Policy>` path `Policy::load` uses (not just the
    /// validator).
    #[test]
    fn all_templates_deserialize_into_policy() {
        // Iterate `PolicyTemplate::ALL` (R20) so a new template is auto-covered.
        for t in PolicyTemplate::ALL {
            let body = t.body();
            let parsed: Result<tirith_core::policy::Policy, _> = serde_yaml::from_str(body);
            assert!(
                parsed.is_ok(),
                "{} template must deserialize into Policy: {:?}",
                t.canonical_name(),
                parsed.err()
            );
        }
    }

    #[test]
    fn oss_maintainer_template_is_moderate_fail_open() {
        // Contract of oss-maintainer: moderate (paranoia 2), still fail-open,
        // and a human may bypass interactively.
        let p: tirith_core::policy::Policy = serde_yaml::from_str(TEMPLATE_OSS_MAINTAINER).unwrap();
        assert_eq!(p.fail_mode, tirith_core::policy::FailMode::Open);
        assert_eq!(p.paranoia, 2);
        assert!(p.allow_bypass_env);
        assert!(!p.allow_bypass_env_noninteractive);
    }

    #[test]
    fn startup_template_is_balanced_strict_warn() {
        // Contract of startup: a notch stricter than individual — paranoia 2,
        // strict-warn on, fail-open, no non-interactive bypass.
        let p: tirith_core::policy::Policy = serde_yaml::from_str(TEMPLATE_STARTUP).unwrap();
        assert_eq!(p.fail_mode, tirith_core::policy::FailMode::Open);
        assert_eq!(p.paranoia, 2);
        assert!(p.strict_warn);
        assert!(!p.allow_bypass_env_noninteractive);
    }

    #[test]
    fn enterprise_template_is_strict_with_active_package_policy() {
        // Contract of enterprise: fail-closed, no bypass at all, AND an
        // ACTIVE (uncommented) package_policy block with strict defaults.
        // This is the M13 ch2 acceptance pin (M6_TO_M14_PLAN.md).
        let p: tirith_core::policy::Policy = serde_yaml::from_str(TEMPLATE_ENTERPRISE).unwrap();
        assert_eq!(p.fail_mode, tirith_core::policy::FailMode::Closed);
        assert!(!p.allow_bypass_env);
        assert!(!p.allow_bypass_env_noninteractive);
        // The active package_policy block — not defaults, real strict values.
        assert!(
            p.package_policy.block_not_found,
            "enterprise must ship block_not_found: true"
        );
        assert_eq!(
            p.package_policy.block_osv_min_cvss,
            Some(7.0),
            "enterprise must ship block_osv_min_cvss: 7.0"
        );
        assert_eq!(p.package_policy.block_newer_than_days, Some(7));
        assert_eq!(p.package_policy.block_typosquat_distance, Some(1));
        assert!(p.package_policy.block_repo_mismatch);
    }

    #[test]
    fn mcp_strict_template_escalates_mcp_rules() {
        // Contract of mcp-strict: fail-closed and every MCP config rule
        // escalated; the two highest-risk MCP rules are forced to block.
        let p: tirith_core::policy::Policy = serde_yaml::from_str(TEMPLATE_MCP_STRICT).unwrap();
        assert_eq!(p.fail_mode, tirith_core::policy::FailMode::Closed);
        for rule in [
            "mcp_insecure_server",
            "mcp_untrusted_server",
            "mcp_overly_permissive",
            "mcp_suspicious_args",
            "mcp_server_drift",
        ] {
            assert!(
                p.severity_overrides.contains_key(rule),
                "mcp-strict must escalate {rule}"
            );
        }
        assert_eq!(
            p.action_overrides
                .get("mcp_untrusted_server")
                .map(String::as_str),
            Some("block")
        );
    }

    #[test]
    fn ci_strict_template_is_fail_closed_no_bypass() {
        // The contract of ci-strict: fail-closed and no bypass at all.
        let p: tirith_core::policy::Policy = serde_yaml::from_str(TEMPLATE_CI_STRICT).unwrap();
        assert_eq!(p.fail_mode, tirith_core::policy::FailMode::Closed);
        assert!(!p.allow_bypass_env);
        assert!(!p.allow_bypass_env_noninteractive);
    }

    #[test]
    fn ai_agent_heavy_template_blocks_agent_bypass() {
        // An AI agent runs non-interactively; it must not be able to bypass.
        let p: tirith_core::policy::Policy = serde_yaml::from_str(TEMPLATE_AI_AGENT_HEAVY).unwrap();
        assert!(!p.allow_bypass_env_noninteractive);
        assert!(!p.approval_rules.is_empty());
        assert!(!p.escalation.is_empty());
    }

    /// `policy effective` transparency contract: for a REPO-scoped policy that
    /// declares a weakening field (a non-empty `allowlist`), the gathered data
    /// must name the source path, classify the scope as `repo`, and list
    /// `allowlist` among the neutralized fields (repo policies are tightening-
    /// only). Drives [`gather_effective`] directly so no stdout capture is
    /// needed — the renderer is a thin function of these fields.
    #[test]
    fn effective_repo_scope_lists_neutralized_allowlist() {
        use crate::cli::test_harness::{with_fake_env, EnvGuard};

        with_fake_env(true, |_home, cwd| {
            let cwd = cwd.expect("cwd set");
            // Isolate machine-level policy sources so only our repo policy is
            // discovered (these are not faked by `with_fake_env`).
            let _root = EnvGuard::remove("TIRITH_POLICY_ROOT");
            let _xdg = EnvGuard::remove("XDG_CONFIG_HOME");

            // A repo checkout: `.git` makes the walk-up stamp PolicyScope::Repo,
            // which triggers repo-scope sanitization of the weakening `allowlist`.
            std::fs::create_dir_all(cwd.join(".git")).unwrap();
            std::fs::create_dir_all(cwd.join(".tirith")).unwrap();
            std::fs::write(
                cwd.join(".tirith/policy.yaml"),
                "fail_mode: open\nallowlist:\n  - evil.example\n",
            )
            .unwrap();

            let info = gather_effective(cwd.to_str());

            // Source path: the repo-root policy we just wrote.
            let expected_path = cwd.join(".tirith/policy.yaml").display().to_string();
            assert_eq!(
                info.source_path.as_deref(),
                Some(expected_path.as_str()),
                "effective must name the repo-root policy as the source",
            );

            // Scope: repo (and its lowercase label).
            assert_eq!(info.scope, tirith_core::policy::PolicyScope::Repo);
            assert_eq!(scope_label(info.scope), "repo");

            // The weakening `allowlist` was neutralized AND recorded — this is the
            // drop list `policy effective` surfaces.
            assert!(
                info.policy.neutralized_fields.contains(&"allowlist"),
                "allowlist must be listed as neutralized for a repo policy; got {:?}",
                info.policy.neutralized_fields,
            );
            // And the value itself was actually reset to tightening-only default.
            assert!(
                info.policy.allowlist.is_empty(),
                "the repo allowlist must be reset (neutralized), not honored",
            );
        });
    }
}
