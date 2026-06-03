use std::io::Read;
use std::path::PathBuf;

use tirith_core::policy::Policy;
use tirith_core::scan::{self, ScanConfig};
use tirith_core::verdict::{RuleId, Severity};

// `tirith scan --profile <name>` tunes a scan for a use case. A policy
// `scan.profiles.<name>` entry overrides a same-named built-in. A built-in sets
// a default `fail_on`, an `exclude` list, and a per-rule overlay applied AFTER
// the scan — it may only suppress or re-grade findings, never invent one.

/// What a built-in profile does to one rule's findings.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ProfileRuleAction {
    /// Drop every finding for this rule — the check is out of scope for the
    /// profile's use case.
    Suppress,
    /// Pin every finding for this rule to a fixed severity.
    SetSeverity(Severity),
}

/// A built-in scan profile: a default `fail_on`, scan-scope `exclude`
/// patterns, and a per-rule overlay.
struct BuiltInProfile {
    /// Default CI-failure threshold (overridden by an explicit `--fail-on`).
    fail_on: &'static str,
    /// Glob patterns excluded from the scan (merged with `--exclude`).
    exclude: &'static [&'static str],
    /// Per-rule overlay applied to the scan results.
    rule_overlay: &'static [(RuleId, ProfileRuleAction)],
}

/// Resolve a built-in profile by name, or `None`. All three default `fail_on`
/// to `high`:
/// * `ci-hardening` — pinning-gap findings kept but pinned to `medium`.
/// * `ai-agent-repo` — pinning-gap findings suppressed (low-value noise for an agent).
/// * `oss-maintainer` — pinning-gap findings downgraded to `low`.
fn built_in_profile(name: &str) -> Option<BuiltInProfile> {
    match name {
        "ci-hardening" => Some(BuiltInProfile {
            fail_on: "high",
            exclude: &[],
            rule_overlay: &[
                (
                    RuleId::WorkflowUnpinnedAction,
                    ProfileRuleAction::SetSeverity(Severity::Medium),
                ),
                (
                    RuleId::DockerfileUnpinnedImage,
                    ProfileRuleAction::SetSeverity(Severity::Medium),
                ),
            ],
        }),
        "ai-agent-repo" => Some(BuiltInProfile {
            fail_on: "high",
            exclude: &[],
            rule_overlay: &[
                (RuleId::WorkflowUnpinnedAction, ProfileRuleAction::Suppress),
                (RuleId::DockerfileUnpinnedImage, ProfileRuleAction::Suppress),
            ],
        }),
        "oss-maintainer" => Some(BuiltInProfile {
            fail_on: "high",
            exclude: &[],
            rule_overlay: &[
                (
                    RuleId::WorkflowUnpinnedAction,
                    ProfileRuleAction::SetSeverity(Severity::Low),
                ),
                (
                    RuleId::DockerfileUnpinnedImage,
                    ProfileRuleAction::SetSeverity(Severity::Low),
                ),
            ],
        }),
        _ => None,
    }
}

/// Names of every built-in profile, for help text and the unknown-profile error.
const BUILT_IN_PROFILE_NAMES: &[&str] = &["ci-hardening", "ai-agent-repo", "oss-maintainer"];

/// Apply a built-in profile's per-rule overlay: suppress or re-grade findings.
fn apply_rule_overlay(
    findings: Vec<tirith_core::verdict::Finding>,
    overlay: &[(RuleId, ProfileRuleAction)],
) -> Vec<tirith_core::verdict::Finding> {
    findings
        .into_iter()
        .filter_map(
            |mut f| match overlay.iter().find(|(rule, _)| *rule == f.rule_id) {
                Some((_, ProfileRuleAction::Suppress)) => None,
                Some((_, ProfileRuleAction::SetSeverity(sev))) => {
                    f.severity = *sev;
                    Some(f)
                }
                None => Some(f),
            },
        )
        .collect()
}

#[allow(clippy::too_many_arguments)]
pub fn run(
    path: Option<&str>,
    file: Option<&str>,
    stdin: bool,
    ci: bool,
    fail_on: &str,
    json: bool,
    sarif: bool,
    ignore: &[String],
    include: &[String],
    exclude: &[String],
    profile: Option<&str>,
) -> i32 {
    let mut effective_include: Vec<String> = include.to_vec();
    let mut effective_exclude: Vec<String> = exclude.to_vec();
    let mut effective_ignore: Vec<String> = ignore.to_vec();
    let mut effective_fail_on = fail_on.to_string();
    // Per-rule overlay from a resolved built-in profile (empty otherwise).
    let mut rule_overlay: Vec<(RuleId, ProfileRuleAction)> = Vec::new();

    if let Some(profile_name) = profile {
        let policy = Policy::discover(None);
        let policy_profile = policy.scan.profiles.get(profile_name);
        let built_in = built_in_profile(profile_name);

        if let Some(scan_profile) = policy_profile {
            // A policy profile entry — the user's policy wins over a built-in.
            if effective_include.is_empty() {
                effective_include = scan_profile.include.clone();
            }
            if effective_exclude.is_empty() {
                effective_exclude = scan_profile.exclude.clone();
            }
            if effective_ignore.is_empty() {
                effective_ignore = scan_profile.ignore.clone();
            }
            // Profile fail_on applies only at the CLI default.
            if fail_on == "critical" {
                if let Some(ref profile_fail_on) = scan_profile.fail_on {
                    effective_fail_on = profile_fail_on.clone();
                }
            }
        } else if let Some(bp) = &built_in {
            if effective_exclude.is_empty() {
                effective_exclude = bp.exclude.iter().map(|s| s.to_string()).collect();
            }
            if fail_on == "critical" {
                effective_fail_on = bp.fail_on.to_string();
            }
            rule_overlay = bp.rule_overlay.to_vec();
        } else {
            eprintln!(
                "tirith scan: warning: profile '{profile_name}' not found — \
                 built-in profiles are: {}",
                BUILT_IN_PROFILE_NAMES.join(", ")
            );
        }
    }

    let fail_on_severity = parse_severity(&effective_fail_on);

    if stdin {
        return run_stdin(json, sarif, ci, fail_on_severity, &rule_overlay);
    }

    if let Some(file_path) = file {
        if should_skip_file(
            file_path,
            &effective_include,
            &effective_exclude,
            &effective_ignore,
        ) {
            return 0;
        }
        return run_single_file(file_path, json, sarif, ci, fail_on_severity, &rule_overlay);
    }

    let scan_path = path
        .map(PathBuf::from)
        .unwrap_or_else(|| std::env::current_dir().unwrap_or_else(|_| PathBuf::from(".")));

    if scan_path.is_file() {
        let path_str = scan_path.display().to_string();
        if should_skip_file(
            &path_str,
            &effective_include,
            &effective_exclude,
            &effective_ignore,
        ) {
            return 0;
        }
        return run_single_file(&path_str, json, sarif, ci, fail_on_severity, &rule_overlay);
    }

    let config = ScanConfig {
        path: scan_path,
        recursive: true,
        fail_on: fail_on_severity,
        ignore_patterns: effective_ignore,
        include_patterns: effective_include,
        exclude_patterns: effective_exclude,
        max_files: None,
    };

    let mut result = scan::scan(&config);
    // Apply the overlay before output and the exit-code decision, so CI sees the
    // profile's verdict. `scanned_count` is left untouched.
    if !rule_overlay.is_empty() {
        for file_result in &mut result.file_results {
            let findings = std::mem::take(&mut file_result.findings);
            file_result.findings = apply_rule_overlay(findings, &rule_overlay);
        }
    }

    // A JSON/SARIF write failure must surface exit 1 instead of a `0` paired
    // with truncated output; a finding-driven non-zero code is kept.
    let output_ok = if sarif {
        print_sarif_result(&result)
    } else if json {
        print_json_result(&result)
    } else {
        if !ci {
            print_human_result(&result);
        }
        true
    };

    // Always surface a panic-incomplete scan (a subset of skipped files). Goes
    // to stderr so it never corrupts --json/--sarif stdout.
    if !result.panic_files.is_empty() {
        eprintln!(
            "tirith scan: WARNING: incomplete scan — {} file(s) were skipped because a rule \
             panicked (see messages above); results may be missing.",
            result.panic_files.len()
        );
        if ci {
            eprintln!("tirith scan: --ci: treating an incomplete scan as a failure.");
        }
    }

    if result.has_findings_at_or_above(fail_on_severity) {
        1
    } else if ci && !result.panic_files.is_empty() {
        // Fail closed in CI: an incomplete scan must not report success.
        1
    } else if result.total_findings() > 0 {
        2
    } else if !output_ok {
        1
    } else {
        0
    }
}

fn run_stdin(
    json: bool,
    sarif: bool,
    ci: bool,
    fail_on: Severity,
    rule_overlay: &[(RuleId, ProfileRuleAction)],
) -> i32 {
    const MAX_STDIN: u64 = 10 * 1024 * 1024;

    let mut raw_bytes = Vec::new();
    if let Err(e) = std::io::stdin()
        .take(MAX_STDIN + 1)
        .read_to_end(&mut raw_bytes)
    {
        eprintln!("tirith scan: failed to read stdin: {e}");
        return 1;
    }
    if raw_bytes.len() as u64 > MAX_STDIN {
        eprintln!("tirith scan: stdin exceeds 10 MiB limit");
        eprintln!("  try: tirith scan --file /path/to/file  (scan the file directly)");
        return 1;
    }
    if raw_bytes.is_empty() {
        return 0;
    }

    let content = String::from_utf8_lossy(&raw_bytes).into_owned();
    let mut result = scan::scan_stdin(&content, &raw_bytes);
    if !rule_overlay.is_empty() {
        result.findings = apply_rule_overlay(std::mem::take(&mut result.findings), rule_overlay);
    }

    // Write failure must not be a `0` success — see `run`.
    let output_ok = if sarif {
        print_sarif_file_result(&result)
    } else if json {
        print_json_file_result(&result)
    } else {
        if !ci {
            print_human_file_result(&result);
        }
        true
    };

    if result.findings.iter().any(|f| f.severity >= fail_on) {
        1
    } else if !result.findings.is_empty() {
        2
    } else if !output_ok {
        1
    } else {
        0
    }
}

fn run_single_file(
    file_path: &str,
    json: bool,
    sarif: bool,
    ci: bool,
    fail_on: Severity,
    rule_overlay: &[(RuleId, ProfileRuleAction)],
) -> i32 {
    let path = PathBuf::from(file_path);
    if !path.exists() {
        eprintln!("tirith scan: file not found: {file_path}");
        eprintln!("  try: tirith scan ./  (scan the current directory)");
        return 1;
    }

    let mut result = match scan::scan_single_file(&path) {
        Some(r) => r,
        None => {
            eprintln!("tirith scan: could not read file: {file_path}");
            return 1;
        }
    };
    if !rule_overlay.is_empty() {
        result.findings = apply_rule_overlay(std::mem::take(&mut result.findings), rule_overlay);
    }

    // Write failure must not be a `0` success — see `run`.
    let output_ok = if sarif {
        print_sarif_file_result(&result)
    } else if json {
        print_json_file_result(&result)
    } else {
        if !ci {
            print_human_file_result(&result);
        }
        true
    };

    if result.findings.iter().any(|f| f.severity >= fail_on) {
        1
    } else if !result.findings.is_empty() {
        2
    } else if !output_ok {
        1
    } else {
        0
    }
}

fn parse_severity(s: &str) -> Severity {
    match s.to_lowercase().as_str() {
        "info" => Severity::Info,
        "low" => Severity::Low,
        "medium" => Severity::Medium,
        "high" => Severity::High,
        "critical" => Severity::Critical,
        _ => {
            eprintln!("tirith scan: warning: unknown severity '{s}', defaulting to critical");
            Severity::Critical
        }
    }
}

/// Emit a directory-scan result as JSON. Returns `false` on a write failure so
/// the caller can exit non-zero (no truncated JSON with a success code).
fn print_json_result(result: &scan::ScanResult) -> bool {
    #[derive(serde::Serialize)]
    struct JsonScanOutput<'a> {
        schema_version: u32,
        scanned_count: usize,
        skipped_count: usize,
        truncated: bool,
        #[serde(skip_serializing_if = "Option::is_none")]
        truncation_reason: &'a Option<String>,
        // Subset of `skipped_count`: files a rule panicked on. Always present so
        // a consumer can detect an incomplete scan; empty list when none.
        panic_count: usize,
        panic_files: Vec<String>,
        total_findings: usize,
        files: Vec<JsonFileOutput<'a>>,
    }

    #[derive(serde::Serialize)]
    struct JsonFileOutput<'a> {
        path: String,
        is_config_file: bool,
        findings: &'a [tirith_core::verdict::Finding],
    }

    let files: Vec<JsonFileOutput> = result
        .file_results
        .iter()
        .filter(|r| !r.findings.is_empty())
        .map(|r| JsonFileOutput {
            path: r.path.display().to_string(),
            is_config_file: r.is_config_file,
            findings: &r.findings,
        })
        .collect();

    let output = JsonScanOutput {
        schema_version: 4,
        scanned_count: result.scanned_count,
        skipped_count: result.skipped_count,
        truncated: result.truncated,
        truncation_reason: &result.truncation_reason,
        panic_count: result.panic_files.len(),
        panic_files: result
            .panic_files
            .iter()
            .map(|p| p.display().to_string())
            .collect(),
        total_findings: result.total_findings(),
        files,
    };

    super::write_json_stdout(&output, "tirith scan: failed to write JSON output")
}

/// Emit a single-file scan result as JSON. Returns `false` on a JSON-write
/// failure.
fn print_json_file_result(result: &scan::FileScanResult) -> bool {
    #[derive(serde::Serialize)]
    struct JsonOutput<'a> {
        schema_version: u32,
        path: String,
        is_config_file: bool,
        findings: &'a [tirith_core::verdict::Finding],
    }

    let output = JsonOutput {
        schema_version: 3,
        path: result.path.display().to_string(),
        is_config_file: result.is_config_file,
        findings: &result.findings,
    };

    super::write_json_stdout(&output, "tirith scan: failed to write JSON output")
}

fn print_human_result(result: &scan::ScanResult) {
    let total = result.total_findings();
    let files_with_findings = result
        .file_results
        .iter()
        .filter(|r| !r.findings.is_empty())
        .count();

    if total == 0 {
        eprintln!(
            "tirith scan: {} files scanned, no issues found",
            result.scanned_count
        );
        return;
    }

    eprintln!(
        "tirith scan: {} files scanned, {} finding(s) in {} file(s)",
        result.scanned_count, total, files_with_findings
    );

    for file_result in &result.file_results {
        if file_result.findings.is_empty() {
            continue;
        }
        eprintln!();
        let label = if file_result.is_config_file {
            " [AI config]"
        } else {
            ""
        };
        eprintln!("  {}{label}", file_result.path.display());
        for finding in &file_result.findings {
            let sev = tirith_core::style::severity_label(
                &finding.severity,
                tirith_core::style::Stream::Stderr,
            );
            eprintln!("    {} {} — {}", sev, finding.rule_id, finding.title);
        }
    }

    if result.truncated {
        if let Some(ref reason) = result.truncation_reason {
            eprintln!();
            let styled = tirith_core::style::dim(reason, tirith_core::style::Stream::Stderr);
            eprintln!("  {styled}");
        }
    }
}

/// Emit a directory-scan result as SARIF. Returns `false` on a write failure.
fn print_sarif_result(result: &scan::ScanResult) -> bool {
    use tirith_core::sarif::{self, SarifFinding};

    let version = env!("CARGO_PKG_VERSION");
    let findings: Vec<SarifFinding> = result
        .file_results
        .iter()
        .flat_map(|fr| {
            fr.findings.iter().map(move |f| SarifFinding {
                finding: f,
                file_path: Some(fr.path.display().to_string()),
                line_number: None,
                suppressed: false,
            })
        })
        .collect();

    let sarif_json = sarif::to_sarif(&findings, version);
    super::write_json_stdout(&sarif_json, "tirith scan: failed to write SARIF output")
}

/// Emit a single-file scan result as SARIF. Returns `false` on a write failure.
fn print_sarif_file_result(result: &scan::FileScanResult) -> bool {
    use tirith_core::sarif::{self, SarifFinding};

    let version = env!("CARGO_PKG_VERSION");
    let findings: Vec<SarifFinding> = result
        .findings
        .iter()
        .map(|f| SarifFinding {
            finding: f,
            file_path: Some(result.path.display().to_string()),
            line_number: None,
            suppressed: false,
        })
        .collect();

    let sarif_json = sarif::to_sarif(&findings, version);
    super::write_json_stdout(&sarif_json, "tirith scan: failed to write SARIF output")
}

fn print_human_file_result(result: &scan::FileScanResult) {
    if result.findings.is_empty() {
        eprintln!("tirith scan: {} — no issues found", result.path.display());
        return;
    }

    eprintln!(
        "tirith scan: {} — {} finding(s)",
        result.path.display(),
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

/// Whether a file should be skipped per include/exclude/ignore filters.
fn should_skip_file(
    file_path: &str,
    include: &[String],
    exclude: &[String],
    ignore: &[String],
) -> bool {
    let file_name = std::path::Path::new(file_path)
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or(file_path);

    let matches = |patterns: &[String]| -> bool {
        patterns.iter().any(|p| {
            tirith_core::scan::matches_ignore_pattern(file_name, p)
                || tirith_core::scan::matches_ignore_pattern(file_path, p)
        })
    };

    if matches(ignore) {
        return true;
    }

    if matches(exclude) {
        return true;
    }

    // '!'-prefixed include patterns act as excludes, not includes.
    let positive_includes: Vec<&String> = include.iter().filter(|p| !p.starts_with('!')).collect();
    let negated_includes: Vec<String> = include
        .iter()
        .filter(|p| p.starts_with('!'))
        .map(|p| p[1..].to_string())
        .collect();

    if !positive_includes.is_empty() {
        let matches_any = positive_includes.iter().any(|p| {
            tirith_core::scan::matches_ignore_pattern(file_name, p)
                || tirith_core::scan::matches_ignore_pattern(file_path, p)
        });
        if !matches_any {
            return true;
        }
    }

    if negated_includes.iter().any(|p| {
        tirith_core::scan::matches_ignore_pattern(file_name, p)
            || tirith_core::scan::matches_ignore_pattern(file_path, p)
    }) {
        return true;
    }

    false
}

#[cfg(test)]
mod tests {
    use super::*;
    use tirith_core::verdict::Finding;

    fn finding(rule: RuleId, sev: Severity) -> Finding {
        Finding {
            rule_id: rule,
            severity: sev,
            title: "t".to_string(),
            description: "d".to_string(),
            evidence: vec![],
            human_view: None,
            agent_view: None,
            mitre_id: None,
            custom_rule_id: None,
        }
    }

    #[test]
    fn built_in_profiles_resolve() {
        assert!(built_in_profile("ci-hardening").is_some());
        assert!(built_in_profile("ai-agent-repo").is_some());
        assert!(built_in_profile("oss-maintainer").is_some());
        assert!(built_in_profile("nonexistent").is_none());
        for name in BUILT_IN_PROFILE_NAMES {
            assert!(
                built_in_profile(name).is_some(),
                "advertised profile '{name}' must resolve"
            );
        }
    }

    #[test]
    fn ci_hardening_keeps_high_findings_and_regrades_pinning() {
        let bp = built_in_profile("ci-hardening").unwrap();
        assert_eq!(bp.fail_on, "high");
        let findings = vec![
            finding(RuleId::WorkflowDangerousTrigger, Severity::High),
            finding(RuleId::WorkflowUnpinnedAction, Severity::Medium),
        ];
        let out = apply_rule_overlay(findings, bp.rule_overlay);
        assert!(
            out.iter()
                .any(|f| f.rule_id == RuleId::WorkflowDangerousTrigger
                    && f.severity == Severity::High)
        );
        // Unpinned-action kept (still Medium under ci-hardening).
        assert!(
            out.iter()
                .any(|f| f.rule_id == RuleId::WorkflowUnpinnedAction
                    && f.severity == Severity::Medium)
        );
    }

    #[test]
    fn ai_agent_repo_suppresses_pinning_noise_keeps_injection() {
        let bp = built_in_profile("ai-agent-repo").unwrap();
        let findings = vec![
            finding(RuleId::WorkflowUntrustedInput, Severity::High),
            finding(RuleId::WorkflowUnpinnedAction, Severity::Medium),
            finding(RuleId::DockerfileUnpinnedImage, Severity::Medium),
        ];
        let out = apply_rule_overlay(findings, bp.rule_overlay);
        // Injection finding stays; pinning-hygiene findings suppressed.
        assert!(out
            .iter()
            .any(|f| f.rule_id == RuleId::WorkflowUntrustedInput));
        assert!(!out
            .iter()
            .any(|f| f.rule_id == RuleId::WorkflowUnpinnedAction));
        assert!(!out
            .iter()
            .any(|f| f.rule_id == RuleId::DockerfileUnpinnedImage));
    }

    #[test]
    fn oss_maintainer_downgrades_pinning_to_low() {
        let bp = built_in_profile("oss-maintainer").unwrap();
        let findings = vec![
            finding(RuleId::PackageScriptDangerous, Severity::High),
            finding(RuleId::WorkflowUnpinnedAction, Severity::Medium),
        ];
        let out = apply_rule_overlay(findings, bp.rule_overlay);
        // Dangerous-script stays High; unpinned-action downgraded to Low.
        assert!(out
            .iter()
            .any(|f| f.rule_id == RuleId::PackageScriptDangerous && f.severity == Severity::High));
        assert!(out
            .iter()
            .any(|f| f.rule_id == RuleId::WorkflowUnpinnedAction && f.severity == Severity::Low));
    }

    #[test]
    fn empty_overlay_is_identity() {
        let findings = vec![finding(RuleId::WorkflowDangerousTrigger, Severity::High)];
        let out = apply_rule_overlay(findings.clone(), &[]);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].rule_id, RuleId::WorkflowDangerousTrigger);
        assert_eq!(out[0].severity, Severity::High);
    }

    #[test]
    fn overlay_leaves_unlisted_rules_untouched() {
        let bp = built_in_profile("ci-hardening").unwrap();
        let findings = vec![finding(RuleId::ConfigInjection, Severity::High)];
        let out = apply_rule_overlay(findings, bp.rule_overlay);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].rule_id, RuleId::ConfigInjection);
        assert_eq!(out[0].severity, Severity::High);
    }
}
