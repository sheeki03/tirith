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

/// `individual` — sensible defaults for a single developer on their own machine.
/// Stays out of the way (fail-open, paranoia 1) but escalates the noisiest
/// pipe-to-shell rule and ships an empty allowlist ready to fill in.
///
/// The body lives in `crates/tirith/assets/policy_templates/individual.yaml`
/// (same crate as this CLI, so the asset is bundled in the crate tarball the
/// same way `assets/shell/*` are — see [`crate::assets`]). `include_str!`
/// resolves it at compile time, so the on-disk `.yaml` is the single source of
/// truth shared by the template body and the `assert_template_valid` test.
const TEMPLATE_INDIVIDUAL: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/assets/policy_templates/individual.yaml"
));

/// `ci-strict` — locked-down settings for an automated CI environment.
/// Fail-closed, no bypass at all, strict warn handling, and a `scan.fail_on`
/// threshold so `tirith scan` fails the build on high-severity findings.
const TEMPLATE_CI_STRICT: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/assets/policy_templates/ci-strict.yaml"
));

/// `ai-agent-heavy` — tuned for environments where AI agents run many
/// commands. Keeps fail-open so an agent is not wedged by an internal error,
/// but raises paranoia, disables the non-interactive bypass (an agent must not
/// be able to bypass tirith), requires approval for the highest-risk rules,
/// and escalates on repeated warnings.
const TEMPLATE_AI_AGENT_HEAVY: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/assets/policy_templates/ai-agent-heavy.yaml"
));

/// `oss-maintainer` — for the maintainer of a public open-source repository.
/// Moderate strictness (paranoia 2, fail-open) with the untrusted-contributor
/// threat model in focus: typosquat, install-script, and untrusted-registry
/// rules escalated for reviewing contributor branches.
const TEMPLATE_OSS_MAINTAINER: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/assets/policy_templates/oss-maintainer.yaml"
));

/// `startup` — for a small team moving fast. Balanced and a notch stricter
/// than `individual` (paranoia 2, strict-warn on, the noisiest pipe-to-shell
/// rules escalated) without failing closed.
const TEMPLATE_STARTUP: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/assets/policy_templates/startup.yaml"
));

/// `enterprise` — strict, audit-friendly defaults for a larger organization.
/// Fail-closed, no bypass, paranoia 3, and — uniquely among the templates — an
/// ACTIVE (uncommented) `package_policy:` block with strict supply-chain
/// thresholds enforced out of the box.
const TEMPLATE_ENTERPRISE: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/assets/policy_templates/enterprise.yaml"
));

/// `mcp-strict` — a locked-down posture for environments that lean heavily on
/// MCP servers. Fail-closed, paranoia 3, and every MCP config rule
/// (insecure / untrusted / overly-permissive / suspicious-args / drift)
/// escalated so an MCP change cannot pass quietly.
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
    /// Every template variant, in the canonical display order. The single source
    /// of truth for "which templates exist" (CodeRabbit M13 PR #132 R20): the
    /// `--template` help list is BUILT from this via [`canonical_name`], so
    /// adding or renaming a variant can never leave the help string stale.
    ///
    /// [`canonical_name`]: PolicyTemplate::canonical_name
    pub const ALL: &'static [PolicyTemplate] = &[
        Self::Individual,
        Self::CiStrict,
        Self::AiAgentHeavy,
        Self::OssMaintainer,
        Self::Startup,
        Self::Enterprise,
        Self::McpStrict,
    ];

    /// The comma-separated list of canonical template names for help / error
    /// text, derived from [`ALL`] so it stays in lock-step with the enum.
    ///
    /// [`ALL`]: PolicyTemplate::ALL
    fn names_csv() -> String {
        Self::ALL
            .iter()
            .map(|t| t.canonical_name())
            .collect::<Vec<_>>()
            .join(", ")
    }

    /// Parse a `--template` value. Returns `None` for an unrecognized name.
    ///
    /// `personal` is accepted as an ALIAS for `individual`: `personal` is the
    /// spec/persona word, `individual` is the shipping name. Both are supported
    /// and resolve to the same template body — the rename is additive, the
    /// original name is never dropped.
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

    /// The canonical hyphenated name (`individual` / `ci-strict` /
    /// `ai-agent-heavy` / `oss-maintainer` / `startup` / `enterprise` /
    /// `mcp-strict`). Round-trips through [`PolicyTemplate::parse`], so a
    /// recommender (`tirith onboard`) can pass it straight to
    /// `tirith policy init --template <name>`. Note the `personal` alias maps
    /// to `Individual`, so its canonical name is `individual`.
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
    // Resolve the template selection before touching the filesystem so a typo
    // fails fast with the list of valid names.
    let selected_template = match template {
        Some(name) => match PolicyTemplate::parse(name) {
            Some(t) => Some(t),
            None => {
                eprintln!("tirith policy init: unknown template '{name}'");
                // Derived from `PolicyTemplate::ALL` so this list can never drift
                // from the actual variants (R20).
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
            // No git repo — fall back to cwd so `tirith policy init` still works.
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

    // Note whether `.tirith` already existed: if we create it on a fresh repo, the
    // new directory entry in `repo_root` must itself be fsync'd, or a crash could
    // lose `.tirith` (and the `policy.yaml` inside it) even though init returned
    // success. `write_file_atomic` below only fsyncs `.tirith` (policy.yaml's
    // parent), not `repo_root` (.tirith's parent). CodeRabbit R13b.
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

    // Write the policy ATOMICALLY (temp-in-same-dir → fsync → rename → parent
    // fsync): with `--force` this overwrites an existing policy, and a crash
    // mid-write must never lose the prior policy or leave a half-written one.
    // Without `--force`, `overwrite=false` makes the publish no-clobber, so a
    // policy created in the race window after the `exists()` check above is NOT
    // silently clobbered (it surfaces as a write error instead).
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

    let result = match scan::scan_single_file(&path) {
        Some(r) => r,
        None => {
            eprintln!("tirith policy test: could not read file: {file_path}");
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
        // Block-equivalent exit code for high+ severity.
        1
    } else {
        // Warn-equivalent exit code for medium/low severity.
        2
    }
}

/// Run `tirith policy tune --from-audit`.
///
/// Reads the local audit log, rolls up per-rule statistics, and prints
/// conservative, deterministic tuning suggestions. It never edits the policy —
/// the user reviews each suggestion and applies it by hand.
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
            // `read_log` only fails on an I/O error reading the file (malformed
            // JSONL lines are skipped, not errored), so name the path and the
            // likely cause. Re-probe the file to distinguish a permissions
            // problem — the one a user can actually act on — from other I/O.
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

    // Every rule tirith can emit — used to point out rules that never fired.
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

    // Existence-based local discovery — the same resolver the engine and
    // `doctor` use. `Policy::discover` would parse the policy and, on a parse
    // error, drop the path, so `validate` could not even locate a corrupt
    // policy to report on; it would also resolve to an unreadable `remote:` URL
    // when a remote policy server is configured.
    tirith_core::policy::discover_local_policy_path(None)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tirith_core::policy_validate::{self, IssueLevel};

    /// Every curated template must pass `tirith policy validate` cleanly —
    /// no errors AND no warnings (warnings include the unknown-field typo
    /// guard, so this also proves every key is a real schema key).
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

    // CodeRabbit M13 PR #132 R20: the `--template` help/error list is DERIVED
    // from `PolicyTemplate::ALL` via `canonical_name`, not hand-maintained, so it
    // can never drift from the actual variants. Assert the derived CSV contains
    // every canonical name AND that every name in it round-trips through `parse`
    // back to a variant (so a stale/typo'd entry can't sneak in).
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

    /// Every curated template body must deserialize cleanly through the same
    /// `serde_yaml::from_str::<Policy>` path `Policy::load` uses — i.e. it
    /// round-trips into the real `Policy` struct, not just the validator.
    #[test]
    fn all_templates_deserialize_into_policy() {
        // Iterate `PolicyTemplate::ALL` (the single source of truth, R20) rather
        // than a hand-maintained list, so a newly-added template is automatically
        // covered by this deserialize check (CodeRabbit M13 PR #132 round-21).
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
}
