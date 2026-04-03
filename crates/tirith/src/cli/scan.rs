use std::io::Read;
use std::path::PathBuf;

use tirith_core::policy::Policy;
use tirith_core::scan::{self, ScanConfig};
use tirith_core::verdict::Severity;

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
    // Resolve effective settings: CLI args merged with profile (if any)
    let mut effective_include: Vec<String> = include.to_vec();
    let mut effective_exclude: Vec<String> = exclude.to_vec();
    let mut effective_ignore: Vec<String> = ignore.to_vec();
    let mut effective_fail_on = fail_on.to_string();

    if let Some(profile_name) = profile {
        let policy = Policy::discover(None);
        if let Some(scan_profile) = policy.scan.profiles.get(profile_name) {
            // Profile values are defaults; CLI flags override when non-empty
            if effective_include.is_empty() {
                effective_include = scan_profile.include.clone();
            }
            if effective_exclude.is_empty() {
                effective_exclude = scan_profile.exclude.clone();
            }
            if effective_ignore.is_empty() {
                // Merge profile ignore and profile exclude-as-ignore
                effective_ignore = scan_profile.ignore.clone();
            }
            // Profile fail_on is used only when CLI is at the default value
            if fail_on == "critical" {
                if let Some(ref profile_fail_on) = scan_profile.fail_on {
                    effective_fail_on = profile_fail_on.clone();
                }
            }
        } else {
            eprintln!("tirith scan: warning: profile '{profile_name}' not found in policy");
        }
    }

    let fail_on_severity = parse_severity(&effective_fail_on);

    // --stdin mode: read from stdin
    if stdin {
        return run_stdin(json, sarif, ci, fail_on_severity);
    }

    // --file mode: scan a single file
    if let Some(file_path) = file {
        if should_skip_file(
            file_path,
            &effective_include,
            &effective_exclude,
            &effective_ignore,
        ) {
            return 0;
        }
        return run_single_file(file_path, json, sarif, ci, fail_on_severity);
    }

    // Directory/path mode
    let scan_path = path
        .map(PathBuf::from)
        .unwrap_or_else(|| std::env::current_dir().unwrap_or_else(|_| PathBuf::from(".")));

    // Single file passed as positional argument
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
        return run_single_file(&path_str, json, sarif, ci, fail_on_severity);
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

    let result = scan::scan(&config);

    if sarif {
        print_sarif_result(&result);
    } else if json {
        print_json_result(&result);
    } else if !ci {
        print_human_result(&result);
    }

    if result.has_findings_at_or_above(fail_on_severity) {
        1
    } else if result.total_findings() > 0 {
        2
    } else {
        0
    }
}

fn run_stdin(json: bool, sarif: bool, ci: bool, fail_on: Severity) -> i32 {
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
        return 1;
    }
    if raw_bytes.is_empty() {
        return 0;
    }

    let content = String::from_utf8_lossy(&raw_bytes).into_owned();
    let result = scan::scan_stdin(&content, &raw_bytes);

    if sarif {
        print_sarif_file_result(&result);
    } else if json {
        print_json_file_result(&result);
    } else if !ci {
        print_human_file_result(&result);
    }

    if result.findings.iter().any(|f| f.severity >= fail_on) {
        1
    } else if !result.findings.is_empty() {
        2
    } else {
        0
    }
}

fn run_single_file(file_path: &str, json: bool, sarif: bool, ci: bool, fail_on: Severity) -> i32 {
    let path = PathBuf::from(file_path);
    if !path.exists() {
        eprintln!("tirith scan: file not found: {file_path}");
        return 1;
    }

    let result = match scan::scan_single_file(&path) {
        Some(r) => r,
        None => {
            eprintln!("tirith scan: could not read file: {file_path}");
            return 1;
        }
    };

    if sarif {
        print_sarif_file_result(&result);
    } else if json {
        print_json_file_result(&result);
    } else if !ci {
        print_human_file_result(&result);
    }

    if result.findings.iter().any(|f| f.severity >= fail_on) {
        1
    } else if !result.findings.is_empty() {
        2
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

fn print_json_result(result: &scan::ScanResult) {
    #[derive(serde::Serialize)]
    struct JsonScanOutput<'a> {
        schema_version: u32,
        scanned_count: usize,
        skipped_count: usize,
        truncated: bool,
        #[serde(skip_serializing_if = "Option::is_none")]
        truncation_reason: &'a Option<String>,
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
        schema_version: 3,
        scanned_count: result.scanned_count,
        skipped_count: result.skipped_count,
        truncated: result.truncated,
        truncation_reason: &result.truncation_reason,
        total_findings: result.total_findings(),
        files,
    };

    if serde_json::to_writer_pretty(std::io::stdout().lock(), &output).is_err() {
        eprintln!("tirith scan: failed to write JSON output");
        return;
    }
    println!();
}

fn print_json_file_result(result: &scan::FileScanResult) {
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

    if serde_json::to_writer_pretty(std::io::stdout().lock(), &output).is_err() {
        eprintln!("tirith scan: failed to write JSON output");
        return;
    }
    println!();
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
    }

    if result.truncated {
        if let Some(ref reason) = result.truncation_reason {
            eprintln!();
            eprintln!("  \x1b[33m{reason}\x1b[0m");
        }
    }
}

fn print_sarif_result(result: &scan::ScanResult) {
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
    if serde_json::to_writer_pretty(std::io::stdout().lock(), &sarif_json).is_err() {
        eprintln!("tirith scan: failed to write SARIF output");
    }
    println!();
}

fn print_sarif_file_result(result: &scan::FileScanResult) {
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
    if serde_json::to_writer_pretty(std::io::stdout().lock(), &sarif_json).is_err() {
        eprintln!("tirith scan: failed to write SARIF output");
    }
    println!();
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

/// Check whether a single file should be skipped based on include/exclude/ignore filters.
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

    // Ignore patterns: skip if matched
    if matches(ignore) {
        return true;
    }

    // Exclude patterns: skip if matched
    if matches(exclude) {
        return true;
    }

    // Include patterns: if non-empty, file must match at least one positive include
    // (negation patterns starting with '!' are treated as excludes, not includes)
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

    // Negated includes: skip if matched
    if negated_includes.iter().any(|p| {
        tirith_core::scan::matches_ignore_pattern(file_name, p)
            || tirith_core::scan::matches_ignore_pattern(file_path, p)
    }) {
        return true;
    }

    false
}
