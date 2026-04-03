use std::path::PathBuf;

use tirith_core::engine::{self, AnalysisContext};
use tirith_core::extract::ScanContext;
use tirith_core::policy::Policy;
use tirith_core::policy_validate::{self, IssueLevel};
use tirith_core::scan;
use tirith_core::tokenize::ShellType;
use tirith_core::verdict::Severity;

// ---------------------------------------------------------------------------
// tirith policy init
// ---------------------------------------------------------------------------

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

# Glob patterns to ignore during scan
scan:
  ignore_patterns: []
"#;

const MINIMAL_TEMPLATE: &str = r#"fail_mode: open
paranoia: 1
allowlist: []
blocklist: []
"#;

pub fn init(force: bool, minimal: bool) -> i32 {
    let cwd = std::env::current_dir()
        .ok()
        .map(|p| p.display().to_string());
    let repo_root = match tirith_core::policy::find_repo_root(cwd.as_deref()) {
        Some(r) => r,
        None => {
            // Fall back to cwd if no git repo found
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

    if let Err(e) = std::fs::create_dir_all(&tirith_dir) {
        eprintln!(
            "tirith policy init: cannot create {}: {e}",
            tirith_dir.display()
        );
        return 1;
    }

    let template = if minimal {
        MINIMAL_TEMPLATE
    } else {
        FULL_TEMPLATE
    };

    if let Err(e) = std::fs::write(&policy_path, template) {
        eprintln!(
            "tirith policy init: cannot write {}: {e}",
            policy_path.display()
        );
        return 1;
    }

    eprintln!("tirith policy init: created {}", policy_path.display());
    0
}

// ---------------------------------------------------------------------------
// tirith policy validate
// ---------------------------------------------------------------------------

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
        let prefix = match issue.level {
            IssueLevel::Error => "\x1b[31merror\x1b[0m",
            IssueLevel::Warning => "\x1b[33mwarning\x1b[0m",
        };
        let field_suffix = issue
            .field
            .as_ref()
            .map(|f| format!(" ({f})"))
            .unwrap_or_default();
        eprintln!("  {prefix}: {}{field_suffix}", issue.message);
    }
}

// ---------------------------------------------------------------------------
// tirith policy test
// ---------------------------------------------------------------------------

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
    };

    let mut verdict = engine::analyze(&ctx);
    let policy = Policy::discover(cwd.as_deref());
    engine::filter_findings_by_paranoia(&mut verdict, policy.paranoia);

    // Gather policy match trace
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
        1 // Block-equivalent: high+ findings
    } else {
        2 // Warn-equivalent: medium/low findings
    }
}

// ---------------------------------------------------------------------------
// Policy trace: which allowlist/blocklist entries were checked
// ---------------------------------------------------------------------------

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

// ---------------------------------------------------------------------------
// JSON output helpers
// ---------------------------------------------------------------------------

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

// ---------------------------------------------------------------------------
// Human output helpers
// ---------------------------------------------------------------------------

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
        let severity_color = match finding.severity {
            Severity::Critical => "\x1b[91m",
            Severity::High => "\x1b[31m",
            Severity::Medium => "\x1b[33m",
            Severity::Low => "\x1b[36m",
            Severity::Info => "\x1b[90m",
        };
        eprintln!(
            "    {}[{}]\x1b[0m {} — {}",
            severity_color, finding.severity, finding.rule_id, finding.title
        );
    }

    // Show allowlist/blocklist trace
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
        let severity_color = match finding.severity {
            Severity::Critical => "\x1b[91m",
            Severity::High => "\x1b[31m",
            Severity::Medium => "\x1b[33m",
            Severity::Low => "\x1b[36m",
            Severity::Info => "\x1b[90m",
        };
        eprintln!(
            "  {}[{}]\x1b[0m {} — {}",
            severity_color, finding.severity, finding.rule_id, finding.title
        );
        eprintln!("    {}", finding.description);
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn resolve_policy_path(explicit: Option<&str>) -> Option<PathBuf> {
    if let Some(p) = explicit {
        let path = PathBuf::from(p);
        if path.exists() {
            return Some(path);
        }
        eprintln!("tirith policy validate: specified path does not exist: {p}");
        return None;
    }

    // Reuse the core policy discovery logic: loads and returns the path if found.
    let policy = tirith_core::policy::Policy::discover(None);
    policy.path.map(PathBuf::from)
}
