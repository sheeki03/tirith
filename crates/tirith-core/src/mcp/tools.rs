use std::path::PathBuf;

use serde_json::{json, Value};

use crate::engine::{self, AnalysisContext};
use crate::extract::ScanContext;
use crate::scan;
use crate::tokenize::ShellType;

use super::types::{ContentItem, ToolCallResult, ToolDefinition};

/// Return the list of available tools.
pub fn list() -> Vec<ToolDefinition> {
    let mut tools = vec![
        ToolDefinition {
            name: "tirith_check_command".into(),
            description: "Check a shell command for security issues (pipe-to-shell, \
                          homograph URLs, env injection, etc.) before execution."
                .into(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "command": {
                        "type": "string",
                        "description": "The shell command to analyze"
                    },
                    "shell": {
                        "type": "string",
                        "description": "Shell type: posix (default) or powershell",
                        "enum": ["posix", "powershell"]
                    }
                },
                "required": ["command"]
            }),
        },
        ToolDefinition {
            name: "tirith_check_url".into(),
            description: "Score a URL for security risk — homograph attacks, \
                          punycode tricks, shortened URLs, raw IPs."
                .into(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "url": {
                        "type": "string",
                        "description": "The URL to analyze"
                    }
                },
                "required": ["url"]
            }),
        },
        ToolDefinition {
            name: "tirith_check_paste".into(),
            description: "Check pasted content for hidden payloads — ANSI escapes, \
                          bidi controls, zero-width chars, hidden multiline."
                .into(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "content": {
                        "type": "string",
                        "description": "The pasted text to analyze"
                    }
                },
                "required": ["content"]
            }),
        },
        ToolDefinition {
            name: "tirith_scan_file".into(),
            description: "Scan a single file for hidden content, config poisoning, \
                          invisible Unicode, and MCP config issues."
                .into(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "path": {
                        "type": "string",
                        "description": "Absolute path to the file to scan"
                    }
                },
                "required": ["path"]
            }),
        },
        ToolDefinition {
            name: "tirith_scan_directory".into(),
            description: "Scan a directory for AI config file security issues. \
                          Known config files (.cursorrules, CLAUDE.md, mcp.json, etc.) \
                          are prioritized."
                .into(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "path": {
                        "type": "string",
                        "description": "Absolute path to the directory to scan"
                    },
                    "recursive": {
                        "type": "boolean",
                        "description": "Recurse into subdirectories (default: true)"
                    }
                },
                "required": ["path"]
            }),
        },
        ToolDefinition {
            name: "tirith_verify_mcp_config".into(),
            description: "Validate an MCP configuration file for security issues — \
                          insecure HTTP, raw IP servers, shell injection in args, \
                          duplicate names, wildcard tools."
                .into(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "path": {
                        "type": "string",
                        "description": "Absolute path to the MCP config file (mcp.json)"
                    }
                },
                "required": ["path"]
            }),
        },
    ];

    // Unix-only: cloaking detection (stub until Part 8)
    #[cfg(unix)]
    tools.push(ToolDefinition {
        name: "tirith_fetch_cloaking".into(),
        description: "Detect server-side cloaking by comparing responses across \
                      different user-agents (browser vs AI bot vs curl)."
            .into(),
        input_schema: json!({
            "type": "object",
            "properties": {
                "url": {
                    "type": "string",
                    "description": "The URL to check for cloaking"
                }
            },
            "required": ["url"]
        }),
    });

    tools
}

/// Dispatch a tool call by name.
pub fn call(name: &str, arguments: &Value) -> ToolCallResult {
    match name {
        "tirith_check_command" => call_check_command(arguments),
        "tirith_check_url" => call_check_url(arguments),
        "tirith_check_paste" => call_check_paste(arguments),
        "tirith_scan_file" => call_scan_file(arguments),
        "tirith_scan_directory" => call_scan_directory(arguments),
        "tirith_verify_mcp_config" => call_verify_mcp_config(arguments),
        #[cfg(unix)]
        "tirith_fetch_cloaking" => call_fetch_cloaking(arguments),
        #[cfg(not(unix))]
        "tirith_fetch_cloaking" => tool_error("Not available on this platform"),
        _ => tool_error(&format!("Unknown tool: {name}")),
    }
}

// ---------------------------------------------------------------------------
// Tool implementations
// ---------------------------------------------------------------------------

fn call_check_command(args: &Value) -> ToolCallResult {
    let command = match args.get("command").and_then(|v| v.as_str()) {
        Some(c) => c,
        None => return tool_error("Missing required parameter: command"),
    };
    let shell = match args
        .get("shell")
        .and_then(|v| v.as_str())
        .unwrap_or("posix")
    {
        "powershell" => ShellType::PowerShell,
        _ => ShellType::Posix,
    };

    let ctx = AnalysisContext {
        input: command.to_string(),
        shell,
        scan_context: ScanContext::Exec,
        raw_bytes: None,
        interactive: false,
        cwd: std::env::current_dir()
            .ok()
            .map(|p| p.display().to_string()),
        file_path: None,
    };

    let verdict = engine::analyze(&ctx);
    let structured = serde_json::to_value(&verdict).ok();
    let text = format_verdict_text(&verdict);

    ToolCallResult {
        content: vec![ContentItem {
            content_type: "text".into(),
            text,
        }],
        is_error: false,
        structured_content: structured,
    }
}

fn call_check_url(args: &Value) -> ToolCallResult {
    let url = match args.get("url").and_then(|v| v.as_str()) {
        Some(u) => u,
        None => return tool_error("Missing required parameter: url"),
    };

    // Wrap URL in a minimal curl command so the full pipeline runs
    let input = format!("curl {url}");
    let ctx = AnalysisContext {
        input,
        shell: ShellType::Posix,
        scan_context: ScanContext::Exec,
        raw_bytes: None,
        interactive: false,
        cwd: None,
        file_path: None,
    };

    let verdict = engine::analyze(&ctx);
    let structured = serde_json::to_value(&verdict).ok();
    let text = format_verdict_text(&verdict);

    ToolCallResult {
        content: vec![ContentItem {
            content_type: "text".into(),
            text,
        }],
        is_error: false,
        structured_content: structured,
    }
}

fn call_check_paste(args: &Value) -> ToolCallResult {
    let content = match args.get("content").and_then(|v| v.as_str()) {
        Some(c) => c,
        None => return tool_error("Missing required parameter: content"),
    };

    let raw_bytes = content.as_bytes().to_vec();
    let ctx = AnalysisContext {
        input: content.to_string(),
        shell: ShellType::Posix,
        scan_context: ScanContext::Paste,
        raw_bytes: Some(raw_bytes),
        interactive: false,
        cwd: None,
        file_path: None,
    };

    let verdict = engine::analyze(&ctx);
    let structured = serde_json::to_value(&verdict).ok();
    let text = format_verdict_text(&verdict);

    ToolCallResult {
        content: vec![ContentItem {
            content_type: "text".into(),
            text,
        }],
        is_error: false,
        structured_content: structured,
    }
}

fn call_scan_file(args: &Value) -> ToolCallResult {
    let path_str = match args.get("path").and_then(|v| v.as_str()) {
        Some(p) => p,
        None => return tool_error("Missing required parameter: path"),
    };

    let path = PathBuf::from(path_str);
    if !path.exists() {
        return tool_error(&format!("File not found: {path_str}"));
    }

    match scan::scan_single_file(&path) {
        Some(result) => {
            let structured = json!({
                "path": result.path.display().to_string(),
                "is_config_file": result.is_config_file,
                "findings_count": result.findings.len(),
                "findings": result.findings,
            });
            let text = format_file_scan_text(&result);
            ToolCallResult {
                content: vec![ContentItem {
                    content_type: "text".into(),
                    text,
                }],
                is_error: false,
                structured_content: Some(structured),
            }
        }
        None => tool_error(&format!("Could not read file: {path_str}")),
    }
}

fn call_scan_directory(args: &Value) -> ToolCallResult {
    let path_str = match args.get("path").and_then(|v| v.as_str()) {
        Some(p) => p,
        None => return tool_error("Missing required parameter: path"),
    };

    let recursive = args
        .get("recursive")
        .and_then(|v| v.as_bool())
        .unwrap_or(true);

    let path = PathBuf::from(path_str);
    if !path.is_dir() {
        return tool_error(&format!("Not a directory: {path_str}"));
    }

    let config = scan::ScanConfig {
        path,
        recursive,
        fail_on: crate::verdict::Severity::Critical,
        ignore_patterns: vec![],
        max_files: None,
    };

    let result = scan::scan(&config);
    let structured = json!({
        "scanned_count": result.scanned_count,
        "skipped_count": result.skipped_count,
        "truncated": result.truncated,
        "truncation_reason": result.truncation_reason,
        "total_findings": result.total_findings(),
        "files": result.file_results.iter()
            .filter(|r| !r.findings.is_empty())
            .map(|r| json!({
                "path": r.path.display().to_string(),
                "is_config_file": r.is_config_file,
                "findings": r.findings,
            }))
            .collect::<Vec<_>>(),
    });

    let text = format_dir_scan_text(&result);

    ToolCallResult {
        content: vec![ContentItem {
            content_type: "text".into(),
            text,
        }],
        is_error: false,
        structured_content: Some(structured),
    }
}

fn call_verify_mcp_config(args: &Value) -> ToolCallResult {
    let path_str = match args.get("path").and_then(|v| v.as_str()) {
        Some(p) => p,
        None => return tool_error("Missing required parameter: path"),
    };

    let path = PathBuf::from(path_str);
    if !path.exists() {
        return tool_error(&format!("File not found: {path_str}"));
    }

    // Use scan_single_file — it routes through FileScan which runs configfile rules
    match scan::scan_single_file(&path) {
        Some(result) => {
            let mcp_findings: Vec<_> = result
                .findings
                .iter()
                .filter(|f| {
                    matches!(
                        f.rule_id,
                        crate::verdict::RuleId::McpInsecureServer
                            | crate::verdict::RuleId::McpUntrustedServer
                            | crate::verdict::RuleId::McpDuplicateServerName
                            | crate::verdict::RuleId::McpOverlyPermissive
                            | crate::verdict::RuleId::McpSuspiciousArgs
                            | crate::verdict::RuleId::ConfigInvisibleUnicode
                            | crate::verdict::RuleId::ConfigNonAscii
                            | crate::verdict::RuleId::ConfigInjection
                    )
                })
                .collect();

            let text = if mcp_findings.is_empty() {
                format!("{path_str}: MCP config is clean — no issues found.")
            } else {
                let mut out = format!("{path_str}: {} issue(s) found:\n", mcp_findings.len());
                for f in &mcp_findings {
                    out.push_str(&format!("  [{}] {} — {}\n", f.severity, f.rule_id, f.title));
                }
                out
            };

            let structured = json!({
                "path": path_str,
                "findings_count": mcp_findings.len(),
                "findings": mcp_findings,
            });

            ToolCallResult {
                content: vec![ContentItem {
                    content_type: "text".into(),
                    text,
                }],
                is_error: false,
                structured_content: Some(structured),
            }
        }
        None => tool_error(&format!("Could not read file: {path_str}")),
    }
}

#[cfg(unix)]
fn call_fetch_cloaking(_args: &Value) -> ToolCallResult {
    // Stub — actual detection added in Part 8
    ToolCallResult {
        content: vec![ContentItem {
            content_type: "text".into(),
            text: "Not yet implemented — cloaking detection will be available in a future release."
                .into(),
        }],
        is_error: false,
        structured_content: None,
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn tool_error(msg: &str) -> ToolCallResult {
    ToolCallResult {
        content: vec![ContentItem {
            content_type: "text".into(),
            text: msg.to_string(),
        }],
        is_error: true,
        structured_content: None,
    }
}

fn format_verdict_text(verdict: &crate::verdict::Verdict) -> String {
    if verdict.findings.is_empty() {
        return format!("Action: {:?} — no issues found.", verdict.action);
    }
    let mut out = format!(
        "Action: {:?} — {} finding(s):\n",
        verdict.action,
        verdict.findings.len()
    );
    for f in &verdict.findings {
        out.push_str(&format!("  [{}] {} — {}\n", f.severity, f.rule_id, f.title));
    }
    out
}

fn format_file_scan_text(result: &scan::FileScanResult) -> String {
    if result.findings.is_empty() {
        return format!("{}: no issues found.", result.path.display());
    }
    let mut out = format!(
        "{}: {} finding(s):\n",
        result.path.display(),
        result.findings.len()
    );
    for f in &result.findings {
        out.push_str(&format!("  [{}] {} — {}\n", f.severity, f.rule_id, f.title));
    }
    out
}

fn format_dir_scan_text(result: &scan::ScanResult) -> String {
    let total = result.total_findings();
    if total == 0 {
        return format!("{} files scanned, no issues found.", result.scanned_count);
    }
    let files_with = result
        .file_results
        .iter()
        .filter(|r| !r.findings.is_empty())
        .count();
    let mut out = format!(
        "{} files scanned, {} finding(s) in {} file(s):\n",
        result.scanned_count, total, files_with
    );
    for fr in &result.file_results {
        if fr.findings.is_empty() {
            continue;
        }
        out.push_str(&format!("\n  {}:\n", fr.path.display()));
        for f in &fr.findings {
            out.push_str(&format!(
                "    [{}] {} — {}\n",
                f.severity, f.rule_id, f.title
            ));
        }
    }
    if result.truncated {
        if let Some(ref reason) = result.truncation_reason {
            out.push_str(&format!("\n  {reason}\n"));
        }
    }
    out
}
