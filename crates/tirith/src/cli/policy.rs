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
const TEMPLATE_INDIVIDUAL: &str = r#"# Tirith security policy — "individual" template
# Sensible defaults for a single developer on their own machine.
# Documentation: https://tirith.dev/docs/policy

# Fail mode: "open" (allow on error) keeps tirith out of your way if it
# ever fails internally. A solo machine does not need fail-closed.
fail_mode: open

# Paranoia level (1-4): 1 is the recommended default for daily use.
paranoia: 1

# Allow the per-command `TIRITH=0` bypass in interactive terminals — handy
# when you knowingly run something tirith flags.
allow_bypass_env: true

# Do NOT allow the bypass in non-interactive shells (scripts, CI-like runs).
allow_bypass_env_noninteractive: false

# Warn findings are shown but do not require an explicit acknowledgement.
strict_warn: false

# Severity overrides per rule. shortened_url is upgraded so link-shortened
# install URLs stand out; everything else keeps its built-in severity.
severity_overrides:
  shortened_url: HIGH

# URL / host patterns that always pass analysis. Add the install sources you
# trust here instead of reaching for `TIRITH=0`. Examples:
#   - "sh.rustup.rs"
#   - "get.docker.com"
allowlist: []

# URL / host patterns that are always blocked (overrides allowlist).
blocklist: []

# Per-rule allowlist scoping — trust a source for ONE rule only.
# allowlist_rules:
#   - rule_id: curl_pipe_shell
#     patterns:
#       - "get.docker.com"

# Scan configuration.
scan:
  ignore_patterns:
    - "node_modules"
    - "target"
    - ".git"

  # MCP server names you trust — suppresses per-server MCP config findings
  # and drift detection for those names. See `tirith mcp policy init`.
  # trusted_mcp_servers: []

  # Per-server allowed tools — see `tirith mcp policy init` to scaffold.
  # mcp_allowed_tools: {}

# Per-agent governance — M4 item 8 (enforcement).
# `tirith agent sessions` shows which AgentOrigin variants you see in
# practice; `tirith agent policy init` scaffolds this block. A `deny`
# match forces the verdict to Block and appends an
# `agent_denied_by_policy` finding; `deny` beats any matching `allow`.
# Enforcement is active on every analysis path: `tirith check`, `paste`,
# `install`, `ecosystem scan`, and all MCP `tools/call_check_*` handlers.
# The interactive `TIRITH=0` bypass currently skips `agent_rules`;
# revisit in M5.
# agent_rules:
#   allow:
#     - kind: agent
#       name: claude-code

# Package-policy section — M6 ch7. Thresholds and actions for the
# package-reputation signals (newer-than-days, low downloads, OSV CVSS,
# typosquat distance, repo-mismatch cap). Defaults preserve the M6 ch6
# behavior; uncomment a knob to tighten one signal.
# package_policy:
#   block_not_found: false                    # block on registry HTTP 404 (--online only)
#   block_newer_than_days:                    # block when first publication is <= N days
#   warn_newer_than_days:                     # warn when first publication is <= N days
#   warn_low_downloads_below:                 # warn when recent_downloads <= N
#   block_install_scripts_for_unknown_packages: false   # block Unknown + script signal
#   block_typosquat_distance:                 # block when edit-distance to popular <= N
#   block_aggregate_score: 76                 # baseline; lower to tighten
#   warn_aggregate_score: 51                  # baseline; lower to surface earlier
#   block_osv_min_cvss: 7.0                   # any OSV >= this CVSS escalates to Block
#   block_repo_mismatch: false                # elevate `package_repo_mismatch` to Block
#   warn_install_script_network_call: true    # disable to silence install-script signal
#   block_dependency_confusion: true          # disable to demote dep-confusion to Warn
#   internal_package_names: []                # [{ ecosystem: npm, name: "@my-co/*" }]
#   repo_mismatch_check_max_packages: 50      # cap on packages checked under --online
"#;

/// `ci-strict` — locked-down settings for an automated CI environment.
/// Fail-closed, no bypass at all, strict warn handling, and a `scan.fail_on`
/// threshold so `tirith scan` fails the build on high-severity findings.
const TEMPLATE_CI_STRICT: &str = r#"# Tirith security policy — "ci-strict" template
# Locked-down settings for an automated CI environment.
# Documentation: https://tirith.dev/docs/policy

# Fail mode: "closed" — if tirith cannot evaluate a command it blocks rather
# than allowing it. CI should never silently let an unanalysed command run.
fail_mode: closed

# Paranoia level (1-4): 2 enables stricter detection than the daily default.
paranoia: 2

# Disable the `TIRITH=0` bypass entirely — interactive AND non-interactive.
# A bypass in CI is a permanent hole, so neither form is permitted.
allow_bypass_env: false
allow_bypass_env_noninteractive: false

# Require explicit acknowledgement for warn findings. In non-interactive CI
# this means a warn cannot be silently passed through.
strict_warn: true

# Escalate the most common remote-execution rules to CRITICAL so they are
# unmistakable in CI logs.
severity_overrides:
  shortened_url: HIGH
  plain_http_to_sink: CRITICAL
  curl_pipe_shell: CRITICAL
  wget_pipe_shell: CRITICAL
  pipe_to_interpreter: HIGH

# Force specific rules to always block, regardless of their default action.
# Only "block" is supported (escalation can upgrade, never downgrade).
action_overrides:
  shortened_url: block

# URL / host patterns that always pass analysis. Keep this list short and
# reviewed — every entry is a trusted hole in CI.
allowlist: []

# URL / host patterns that are always blocked (overrides allowlist).
blocklist: []

# `tirith scan` configuration. fail_on sets the severity threshold at which
# a scan exits non-zero and fails the CI job.
scan:
  fail_on: high
  ignore_patterns:
    - "node_modules"
    - "target"
    - ".git"

  # MCP server names CI considers trusted. Keep this tight — a trusted name
  # silences every per-server MCP config finding and exempts the server
  # from drift detection in CI. Generate from `tirith mcp policy init`.
  # trusted_mcp_servers: []

  # Per-server allowed tools — a CI guardrail against an agent or merge
  # smuggling a new MCP tool past the lockfile. See `tirith mcp policy init`.
  # mcp_allowed_tools: {}

# Per-agent governance — M4 item 8 (enforcement).
# A CI policy that wants to declare which callers are expected can list
# them here. A `deny` match forces the verdict to Block and appends an
# `agent_denied_by_policy` finding; `deny` beats any matching `allow`.
# Enforcement runs via `apply_agent_rules` on every analysis path:
# `tirith check` (the surface CI most often calls), `install`, `ecosystem
# scan`, `paste`, and all MCP `tools/call_check_*` handlers. The
# interactive `TIRITH=0` bypass currently skips `agent_rules`; in CI
# this combines with `allow_bypass_env: false` below to close that
# path. `tirith agent sessions` shows the AgentOrigins your CI actually
# sees.
# agent_rules:
#   allow:
#     - kind: ci
#       name: github-actions

# Package-policy section — M6 ch7. CI baseline tightens several knobs:
# strict environments typically want the block-on-not-found / install-script
# / aggregate-score elevations on by default. Uncomment to opt in.
# package_policy:
#   block_not_found: true                     # block on registry HTTP 404 (--online only)
#   block_newer_than_days: 3                  # CI rejects brand-new packages
#   warn_newer_than_days: 14
#   warn_low_downloads_below: 100
#   block_install_scripts_for_unknown_packages: true
#   block_typosquat_distance: 1
#   block_aggregate_score: 76
#   warn_aggregate_score: 51
#   block_osv_min_cvss: 7.0
#   block_repo_mismatch: true
#   warn_install_script_network_call: true
#   block_dependency_confusion: true
#   internal_package_names: []
#   repo_mismatch_check_max_packages: 50
"#;

/// `ai-agent-heavy` — tuned for environments where AI agents run many
/// commands. Keeps fail-open so an agent is not wedged by an internal error,
/// but raises paranoia, disables the non-interactive bypass (an agent must not
/// be able to bypass tirith), requires approval for the highest-risk rules,
/// and escalates on repeated warnings.
const TEMPLATE_AI_AGENT_HEAVY: &str = r#"# Tirith security policy — "ai-agent-heavy" template
# Tuned for environments where AI agents run many shell commands.
# Documentation: https://tirith.dev/docs/policy

# Fail mode: "open" — an internal tirith error should not wedge an agent
# mid-task. Risk is managed below via paranoia, approval, and escalation.
fail_mode: open

# Paranoia level (1-4): 3 — agents paste and run far more untrusted input
# than a human, so detection is turned up.
paranoia: 3

# A human may bypass interactively, but an AI agent (non-interactive) must
# never be able to set TIRITH=0 to skip analysis.
allow_bypass_env: true
allow_bypass_env_noninteractive: false

# Require explicit acknowledgement for warn findings.
strict_warn: true

# Escalate remote-execution and Docker-registry rules — the patterns agents
# most often produce from hallucinated or copy-pasted instructions.
severity_overrides:
  curl_pipe_shell: CRITICAL
  wget_pipe_shell: CRITICAL
  pipe_to_interpreter: HIGH
  shortened_url: HIGH
  docker_untrusted_registry: HIGH

# Approval rules: a command matching any listed rule pauses for human
# approval before it runs. fallback is what happens on timeout.
approval_rules:
  - rule_ids:
      - curl_pipe_shell
      - wget_pipe_shell
      - pipe_to_interpreter
    timeout_secs: 120
    fallback: block

# Escalation: upgrade to a block when an agent keeps re-trying flagged work.
escalation:
  # Block any rule that fires 5+ times within an hour.
  - trigger: repeat_count
    rule_ids: ["*"]
    threshold: 5
    window_minutes: 60
    action: block
  # Block when one command produces 3+ medium-or-higher findings at once.
  - trigger: multi_medium
    min_findings: 3
    action: block

# URL / host patterns that always pass analysis. Keep this list tight — an
# over-broad allowlist lets an agent route around tirith.
allowlist: []

# URL / host patterns that are always blocked (overrides allowlist).
blocklist: []

# `tirith scan` configuration.
scan:
  ignore_patterns:
    - "node_modules"
    - "target"
    - ".git"

  # MCP server names you trust. Agents that load arbitrary MCP servers from
  # their environment make a tight `trusted_mcp_servers` list especially
  # valuable — every untrusted server raises findings, and drift on a
  # trusted server is silent. Scaffold from `tirith mcp policy init`.
  # trusted_mcp_servers: []

  # Per-server allowed tools — pin the exact tool set you accept for each
  # MCP server an agent may use. A new tool outside the set surfaces as a
  # High-severity drift finding. See `tirith mcp policy init`.
  # mcp_allowed_tools: {}

# Per-agent governance — M4 item 8 (enforcement).
# An agent-heavy environment benefits most from per-origin policy.
# `tirith agent sessions` shows which agents have invoked tirith;
# `tirith agent policy init` scaffolds this block from observed
# origins. A `deny` match forces the verdict to Block and appends an
# `agent_denied_by_policy` finding; `deny` beats any matching `allow`,
# and `allow` is NOT a bypass — a verdict the engine already blocked
# stays blocked even if the caller is on the allow list. Enforcement is
# active on every analysis path: `tirith check`, the gateway, `paste`,
# `install`, `ecosystem scan`, and all MCP `tools/call_check_*`
# handlers. The interactive `TIRITH=0` bypass currently skips
# `agent_rules`; revisit in M5.
# agent_rules:
#   allow:
#     - kind: agent
#       name: claude-code
#     - kind: agent
#       name: cursor
#   deny:
#     - kind: agent
#       name: untrusted-agent

# Package-policy section — M6 ch7. AI-agent environments benefit from
# tight package-reputation gates: agents are most likely to hallucinate
# package names that don't exist, or to grab brand-new packages without
# vetting. Recommended thresholds below.
# package_policy:
#   block_not_found: true
#   block_newer_than_days: 7
#   warn_newer_than_days: 30
#   warn_low_downloads_below: 1000
#   block_install_scripts_for_unknown_packages: true
#   block_typosquat_distance: 2
#   block_aggregate_score: 76
#   warn_aggregate_score: 51
#   block_osv_min_cvss: 7.0
#   block_repo_mismatch: true
#   warn_install_script_network_call: true
#   block_dependency_confusion: true
#   internal_package_names: []                # [{ ecosystem: npm, name: "@my-co/*" }]
#   repo_mismatch_check_max_packages: 50
"#;

/// A curated starter policy selected via `tirith policy init --template`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PolicyTemplate {
    Individual,
    CiStrict,
    AiAgentHeavy,
}

impl PolicyTemplate {
    /// Parse a `--template` value. Returns `None` for an unrecognized name.
    pub fn parse(name: &str) -> Option<Self> {
        match name.trim().to_ascii_lowercase().as_str() {
            "individual" => Some(Self::Individual),
            "ci-strict" | "ci_strict" => Some(Self::CiStrict),
            "ai-agent-heavy" | "ai_agent_heavy" => Some(Self::AiAgentHeavy),
            _ => None,
        }
    }

    /// The YAML body this template writes.
    fn body(self) -> &'static str {
        match self {
            Self::Individual => TEMPLATE_INDIVIDUAL,
            Self::CiStrict => TEMPLATE_CI_STRICT,
            Self::AiAgentHeavy => TEMPLATE_AI_AGENT_HEAVY,
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
                eprintln!("  valid templates: individual, ci-strict, ai-agent-heavy");
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
        clipboard_source: None,
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

    #[test]
    fn ci_strict_template_validates() {
        assert_template_valid("ci-strict", TEMPLATE_CI_STRICT);
    }

    #[test]
    fn ai_agent_heavy_template_validates() {
        assert_template_valid("ai-agent-heavy", TEMPLATE_AI_AGENT_HEAVY);
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
    }

    #[test]
    fn template_parse_rejects_unknown_and_deferred_names() {
        assert_eq!(PolicyTemplate::parse("fintech"), None);
        assert_eq!(PolicyTemplate::parse("windows-enterprise"), None);
        assert_eq!(PolicyTemplate::parse(""), None);
        assert_eq!(PolicyTemplate::parse("default"), None);
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
