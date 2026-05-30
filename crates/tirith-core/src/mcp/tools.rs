use std::path::PathBuf;

use serde_json::{json, Value};

use crate::engine::{self, AnalysisContext};
use crate::extract::ScanContext;
use crate::scan;
use crate::tokenize::ShellType;

use super::types::{ContentItem, ToolCallResult, ToolDefinition};

/// Validate that a path is within the current working directory (path traversal protection).
fn validate_path_scope(path: &std::path::Path) -> Result<PathBuf, String> {
    let cwd =
        std::env::current_dir().map_err(|e| format!("Cannot determine working directory: {e}"))?;
    let canonical_cwd = cwd
        .canonicalize()
        .map_err(|e| format!("Cannot canonicalize working directory: {e}"))?;
    let canonical_path = path.canonicalize().map_err(|_| {
        format!(
            "Path does not exist or is not accessible: {}",
            path.display()
        )
    })?;
    if !canonical_path.starts_with(&canonical_cwd) {
        return Err(format!(
            "Access denied: path '{}' is outside the working directory",
            path.display()
        ));
    }
    Ok(canonical_path)
}

/// Return the list of available tools.
pub fn list() -> Vec<ToolDefinition> {
    #[allow(unused_mut)]
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

    // Unix-only: cloaking detection (requires network access)
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

fn call_check_command(args: &Value) -> ToolCallResult {
    let command = match args.get("command").and_then(|v| v.as_str()) {
        Some(c) => c,
        None => return tool_error("Missing required parameter: command"),
    };
    let shell = args
        .get("shell")
        .and_then(|v| v.as_str())
        .unwrap_or("posix")
        .parse::<ShellType>()
        .unwrap_or(ShellType::Posix);

    let cwd = std::env::current_dir()
        .ok()
        .map(|p| p.display().to_string());
    let ctx = AnalysisContext {
        input: command.to_string(),
        shell,
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

    let (mut raw_verdict, policy) = engine::analyze_returning_policy(&ctx);

    // M4 item 8. Stamp the MCP client origin on the raw verdict;
    // post-processing (below) consults this via
    // `escalation::apply_agent_rules` against the active policy's
    // `agent_rules.deny`, then clones the origin through to the
    // effective verdict, and the audit entry picks it up automatically.
    // The `bypass_honored` branch skips post-processing, so deny does
    // not currently enforce under bypass on this path.
    raw_verdict.agent_origin = super::origin::current();

    let mut verdict = if raw_verdict.bypass_honored {
        // M4 item 8 chunk 3 — the engine no longer audits its own bypass
        // path; the caller does. Log the bypass-honored verdict here so
        // the audit entry carries the MCP client origin we just stamped.
        // Best-effort — a write failure must not change the verdict.
        let _ = crate::audit::log_verdict(
            &raw_verdict,
            command,
            None,
            None,
            &policy.dlp_custom_patterns,
        );
        raw_verdict
    } else {
        let session_id = crate::session::resolve_session_id();
        crate::escalation::post_process_verdict(
            &raw_verdict,
            &policy,
            command,
            &session_id,
            crate::escalation::CallerContext::McpServer,
        )
    };

    crate::redact::redact_verdict(&mut verdict, &policy.dlp_custom_patterns);
    let structured = serde_json::to_value(&verdict)
        .map_err(|e| eprintln!("tirith: mcp: verdict serialization failed: {e}"))
        .ok();
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

    // Wrap URL in a minimal curl command so the full pipeline runs.
    // Shell-quote the URL to prevent metacharacters from being tokenized as separate commands.
    let input = format!("curl '{}'", url.replace('\'', "'\\''"));
    let ctx = AnalysisContext {
        input: input.clone(),
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
        clipboard_source: None,
    };

    // PR #120 fix-8 (CodeRabbit Major): use the same engine API as
    // `call_check_command` so analysis and enforcement / approval /
    // audit all see the same Policy snapshot. The split
    // `engine::analyze(&ctx)` + `Policy::discover(None)` pair allowed a
    // mid-call edit of `.tirith/policy.yaml` to swap the policy out
    // from under the rest of the pipeline.
    let (mut verdict, policy) = engine::analyze_returning_policy(&ctx);

    // Diagnostic tool — use paranoia filter + approval only, no escalation/session recording
    engine::filter_findings_by_paranoia(&mut verdict, policy.paranoia);

    // M4 item 8 chunk 3 follow-up — stamp the MCP client origin so the
    // verdict carries the caller's identity for both observation and
    // enforcement.
    verdict.agent_origin = super::origin::current();

    if verdict.bypass_honored {
        // M4 PR #120 fix-7 (Greptile P1): pre-fix-3 the engine wrote this
        // audit entry on its own bypass-fast-exit path; fix-3 (5d94c71)
        // moved that responsibility to the caller. `call_check_command`
        // was correctly updated to write a bypass-honored audit entry
        // (see lines 230-236 above) but the two diagnostic MCP tools
        // (`call_check_url`, `call_check_paste`) were missed. Restore
        // the audit-write here so an operator running an MCP-driven
        // `tirith_check_url` under `TIRITH=0` still gets an audit trail
        // for the honored-bypass verdict (with the freshly-stamped
        // `agent_origin`). Best-effort — a write failure must not change
        // the verdict. The non-bypass diagnostic path remains
        // audit-silent by design (pre-existing).
        let _ =
            crate::audit::log_verdict(&verdict, &input, None, None, &policy.dlp_custom_patterns);
    } else {
        // M4 item 8 chunk 3 follow-up — enforce `agent_rules.deny` on
        // this diagnostic MCP tool. `call_check_url` does not route
        // through `post_process_verdict` (it intentionally skips
        // escalation / session bookkeeping), so without this call an
        // operator who writes a `deny` matcher to block an untrusted
        // MCP client would see deny enforce on `tirith_check_command`
        // but silently fail on `tirith_check_url`. The helper is a
        // no-op on `Allowed`/`Unspecified`.
        //
        // M4 PR #120 fix-6 (Greptile P1): the bypass-skip behavior the
        // hot paths in `check`/`gateway`/`call_check_command` use is
        // now captured by the outer `else` — under `TIRITH=0`, the raw
        // verdict already wins and `apply_agent_rules` must NOT
        // silently re-Block. Pinned by
        // `agent_rules_deny_skipped_under_tirith_bypass_today` and the
        // per-surface mirrors.
        crate::escalation::apply_agent_rules(&mut verdict, &policy);

        // M4 PR #120 fix-6 (CodeRabbit Major): derive approval AFTER
        // `apply_agent_rules` and ONLY when the verdict is not already
        // Block. Otherwise a denied MCP client would receive both
        // `action: block` AND `requires_approval` / `approval_*`
        // metadata, which gives conflicting client instructions ("Block
        // this" plus "Ask the user to approve"). Pinned by
        // `mcp_check_url_deny_does_not_emit_approval_metadata`.
        if verdict.action != crate::verdict::Action::Block {
            if let Some(meta) = crate::approval::check_approval(&verdict, &policy) {
                crate::approval::apply_approval(&mut verdict, &meta);
            }
        }
    }

    crate::redact::redact_verdict(&mut verdict, &policy.dlp_custom_patterns);
    let structured = serde_json::to_value(&verdict)
        .map_err(|e| eprintln!("tirith: mcp: verdict serialization failed: {e}"))
        .ok();
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
    let input = content.to_string();
    let ctx = AnalysisContext {
        input: input.clone(),
        shell: ShellType::Posix,
        scan_context: ScanContext::Paste,
        raw_bytes: Some(raw_bytes),
        interactive: false,
        cwd: None,
        file_path: None,
        repo_root: None,
        is_config_override: false,
        clipboard_html: None,
        card_ref: None,
        clipboard_source: None,
    };

    // PR #120 fix-8 (CodeRabbit Major): single Policy snapshot for
    // analysis + enforcement + approval + audit. See `call_check_url`
    // for the rationale.
    let (mut verdict, policy) = engine::analyze_returning_policy(&ctx);

    // Diagnostic tool — use paranoia filter + approval only, no escalation/session recording
    engine::filter_findings_by_paranoia(&mut verdict, policy.paranoia);

    // M4 item 8 chunk 3 follow-up — stamp the MCP caller origin on the
    // paste-diagnostic verdict the same way `check_command` does.
    verdict.agent_origin = super::origin::current();

    if verdict.bypass_honored {
        // M4 PR #120 fix-7 (Greptile P1): paired with the same fix in
        // `call_check_url` — pre-fix-3 the engine wrote this audit
        // entry on its bypass-fast-exit path; fix-3 (5d94c71) moved
        // that responsibility to the caller and `call_check_command`
        // was updated, but the two diagnostic MCP tools were missed.
        // Restore the audit-write here so an operator running an
        // MCP-driven `tirith_check_paste` under `TIRITH=0` still gets
        // an audit trail for the honored-bypass verdict. Best-effort —
        // a write failure must not change the verdict. The non-bypass
        // diagnostic path remains audit-silent by design (pre-existing).
        let _ =
            crate::audit::log_verdict(&verdict, &input, None, None, &policy.dlp_custom_patterns);
    } else {
        // M4 item 8 chunk 3 follow-up — enforce `agent_rules.deny` on
        // this diagnostic MCP tool. `call_check_paste` does not route
        // through `post_process_verdict` (it intentionally skips
        // escalation / session bookkeeping), so without this call deny
        // would stamp but not enforce on the MCP-side clipboard-
        // poisoning surface. The helper is a no-op on
        // `Allowed`/`Unspecified`.
        //
        // M4 PR #120 fix-6 (Greptile P1): the bypass-skip behavior the
        // hot paths use is now captured by the outer `else` — under
        // `TIRITH=0`, the raw verdict already wins and
        // `apply_agent_rules` must NOT silently re-Block.
        crate::escalation::apply_agent_rules(&mut verdict, &policy);

        // M4 PR #120 fix-6 (CodeRabbit Major): derive approval AFTER
        // `apply_agent_rules` and ONLY when the verdict is not already
        // Block. Otherwise a denied MCP client would receive both
        // `action: block` AND `requires_approval` / `approval_*`
        // metadata. Pinned by
        // `mcp_check_paste_deny_does_not_emit_approval_metadata`.
        if verdict.action != crate::verdict::Action::Block {
            if let Some(meta) = crate::approval::check_approval(&verdict, &policy) {
                crate::approval::apply_approval(&mut verdict, &meta);
            }
        }
    }

    crate::redact::redact_verdict(&mut verdict, &policy.dlp_custom_patterns);
    let structured = serde_json::to_value(&verdict)
        .map_err(|e| eprintln!("tirith: mcp: verdict serialization failed: {e}"))
        .ok();
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
    let path = match validate_path_scope(&path) {
        Ok(p) => p,
        Err(e) => return tool_error(&e),
    };

    let policy = crate::policy::Policy::discover(None);

    match scan::scan_single_file(&path) {
        Some(mut result) => {
            crate::redact::redact_findings(&mut result.findings, &policy.dlp_custom_patterns);
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
    let path = match validate_path_scope(&path) {
        Ok(p) => p,
        Err(e) => return tool_error(&e),
    };
    if !path.is_dir() {
        return tool_error(&format!("Not a directory: {path_str}"));
    }

    let config = scan::ScanConfig {
        path,
        recursive,
        fail_on: crate::verdict::Severity::Critical,
        ignore_patterns: vec![],
        include_patterns: vec![],
        exclude_patterns: vec![],
        max_files: Some(crate::mcp::resources::MCP_SCAN_MAX_FILES),
    };

    let policy = crate::policy::Policy::discover(None);
    let mut result = scan::scan(&config);
    for fr in &mut result.file_results {
        crate::redact::redact_findings(&mut fr.findings, &policy.dlp_custom_patterns);
    }

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
    let path = match validate_path_scope(&path) {
        Ok(p) => p,
        Err(e) => return tool_error(&e),
    };

    let policy = crate::policy::Policy::discover(None);

    // Use scan_single_file — it routes through FileScan which runs configfile rules
    match scan::scan_single_file(&path) {
        Some(mut result) => {
            crate::redact::redact_findings(&mut result.findings, &policy.dlp_custom_patterns);
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
fn call_fetch_cloaking(args: &Value) -> ToolCallResult {
    let url = match args.get("url").and_then(|v| v.as_str()) {
        Some(u) => u,
        None => return tool_error("Missing required parameter: url"),
    };

    let policy = crate::policy::Policy::discover(None);

    match crate::rules::cloaking::check(url) {
        Ok(mut result) => {
            crate::redact::redact_findings(&mut result.findings, &policy.dlp_custom_patterns);
            build_cloaking_response(result, &policy.dlp_custom_patterns)
        }
        Err(e) => tool_error(&format!("Cloaking check failed: {e}")),
    }
}

/// Build the MCP response for a cloaking check result.
/// Extracted for testability — diff_text is DLP-redacted before serialization.
#[cfg(unix)]
fn build_cloaking_response(
    mut result: crate::rules::cloaking::CloakingResult,
    dlp_patterns: &[String],
) -> ToolCallResult {
    let text = if result.cloaking_detected {
        let differing: Vec<&str> = result
            .diff_pairs
            .iter()
            .map(|d| d.agent_b.as_str())
            .collect();
        format!(
            "Cloaking detected for {}. Differing agents: {}",
            result.url,
            differing.join(", ")
        )
    } else {
        format!("No cloaking detected for {}", result.url)
    };

    // DLP-redact diff text before serialization
    for diff in &mut result.diff_pairs {
        if let Some(ref text) = diff.diff_text {
            diff.diff_text = Some(crate::redact::redact_with_custom(text, dlp_patterns));
        }
    }

    let structured = result.to_json(true);

    ToolCallResult {
        content: vec![ContentItem {
            content_type: "text".into(),
            text,
        }],
        is_error: false,
        structured_content: Some(structured),
    }
}

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

#[cfg(test)]
#[cfg(unix)]
mod tests {
    use super::*;

    #[test]
    fn test_cloaking_diff_text_is_dlp_redacted() {
        use crate::rules::cloaking::{AgentResponse, CloakingResult, DiffPair};

        let secret = "sk-abcdefghijklmnopqrstuvwxyz12345678";
        let result = CloakingResult {
            url: "https://example.com".into(),
            cloaking_detected: true,
            findings: vec![],
            agent_responses: vec![
                AgentResponse {
                    agent_name: "Chrome".into(),
                    status_code: 200,
                    content_length: 100,
                },
                AgentResponse {
                    agent_name: "ClaudeBot".into(),
                    status_code: 200,
                    content_length: 80,
                },
            ],
            diff_pairs: vec![DiffPair {
                agent_a: "Chrome".into(),
                agent_b: "ClaudeBot".into(),
                diff_chars: 50,
                diff_text: Some(format!("Added: config key={secret}")),
            }],
        };

        let resp = build_cloaking_response(result, &[]);
        let structured = resp.structured_content.unwrap();
        let diff_text = structured["diffs"][0]["diff_text"]
            .as_str()
            .expect("diff_text should be present");

        // The OpenAI key pattern should be redacted
        assert!(
            !diff_text.contains(secret),
            "diff_text should not contain raw secret: {diff_text}"
        );
        assert!(
            diff_text.contains("[REDACTED:OpenAI API Key]"),
            "diff_text should contain redaction marker: {diff_text}"
        );
    }

    #[test]
    fn test_cloaking_diff_text_present_in_structured_output() {
        use crate::rules::cloaking::{AgentResponse, CloakingResult, DiffPair};

        let result = CloakingResult {
            url: "https://example.com".into(),
            cloaking_detected: true,
            findings: vec![],
            agent_responses: vec![AgentResponse {
                agent_name: "Chrome".into(),
                status_code: 200,
                content_length: 100,
            }],
            diff_pairs: vec![DiffPair {
                agent_a: "Chrome".into(),
                agent_b: "ClaudeBot".into(),
                diff_chars: 50,
                diff_text: Some("some diff content".into()),
            }],
        };

        let resp = build_cloaking_response(result, &[]);
        let structured = resp.structured_content.unwrap();
        assert!(
            structured["diffs"][0].get("diff_text").is_some(),
            "diff_text should be present in structured output"
        );
    }

    #[test]
    fn test_cloaking_custom_dlp_pattern_redacts_diff_text() {
        use crate::rules::cloaking::{AgentResponse, CloakingResult, DiffPair};

        let result = CloakingResult {
            url: "https://example.com".into(),
            cloaking_detected: true,
            findings: vec![],
            agent_responses: vec![AgentResponse {
                agent_name: "Chrome".into(),
                status_code: 200,
                content_length: 100,
            }],
            diff_pairs: vec![DiffPair {
                agent_a: "Chrome".into(),
                agent_b: "ClaudeBot".into(),
                diff_chars: 30,
                diff_text: Some("internal ref PROJ-99999 leaked".into()),
            }],
        };

        let custom = vec![r"PROJ-\d+".to_string()];
        let resp = build_cloaking_response(result, &custom);
        let structured = resp.structured_content.unwrap();
        let diff_text = structured["diffs"][0]["diff_text"]
            .as_str()
            .expect("diff_text should be present");

        assert!(
            !diff_text.contains("PROJ-99999"),
            "custom DLP pattern should redact: {diff_text}"
        );
        assert!(
            diff_text.contains("[REDACTED:custom]"),
            "should contain custom redaction marker: {diff_text}"
        );
    }

    /// Snapshot an env var on construction and restore on `Drop` — same shape
    /// as the `EnvVarGuard` in `policy.rs::tests` (cannot import directly
    /// because that one is `mod tests`-scoped).
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
    }

    impl Drop for EnvVarGuard {
        fn drop(&mut self) {
            match &self.prev {
                Some(v) => unsafe { std::env::set_var(self.key, v) },
                None => unsafe { std::env::remove_var(self.key) },
            }
        }
    }

    /// Seed a `.tirith/policy.yaml` under `root` whose `agent_rules.deny`
    /// matches an MCP client named `client`. Returns the temp dir handle so
    /// the caller can hold it for the lifetime of the test.
    fn seed_mcp_deny_policy(client: &str) -> tempfile::TempDir {
        let dir = tempfile::tempdir().expect("tempdir");
        let tirith_dir = dir.path().join(".tirith");
        std::fs::create_dir_all(&tirith_dir).expect("create .tirith dir");
        let policy = format!("agent_rules:\n  deny:\n    - kind: mcp\n      name: {client}\n");
        std::fs::write(tirith_dir.join("policy.yaml"), policy).expect("write policy");
        dir
    }

    /// M4 item 8 chunk 3 follow-up — finding B in the M4 PR #120 wave-end
    /// review. `tirith_check_url` is a diagnostic MCP tool that does not
    /// route through `post_process_verdict`. Before this fix the path
    /// stamped `agent_origin` for audit but never invoked
    /// `apply_agent_rules`, so an operator who wrote a `deny` matcher to
    /// block a hostile MCP client would see deny enforce on
    /// `tirith_check_command` but silently fail on `tirith_check_url`.
    /// The fix calls `apply_agent_rules` directly between the origin
    /// stamp and the response build.
    #[test]
    fn mcp_check_url_with_agent_rules_deny_forces_block() {
        let _env_lock = crate::TEST_ENV_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let _origin_guard = super::super::origin::reset_for_test();

        // Seed the MCP origin to a name our deny matcher will catch.
        super::super::origin::set_from_initialize(Some(&super::super::types::ClientInfo {
            name: "hostile-mcp-client".to_string(),
            version: None,
        }));

        // Seed a policy that denies this client. Discovery walks
        // `TIRITH_POLICY_ROOT/.tirith` first.
        let policy_dir = seed_mcp_deny_policy("hostile-mcp-client");
        let _root = EnvVarGuard::set("TIRITH_POLICY_ROOT", policy_dir.path());

        // A clean URL — would otherwise be Allow.
        let resp = call_check_url(&json!({"url": "https://example.com/"}));
        assert!(!resp.is_error, "tool dispatch must succeed: {resp:?}");
        let structured = resp
            .structured_content
            .expect("structured_content must be present");
        assert_eq!(
            structured["action"], "block",
            "deny matcher must flip the verdict to Block: {structured}"
        );
        let has_deny_finding = structured["findings"]
            .as_array()
            .expect("findings must be an array")
            .iter()
            .any(|f| f["rule_id"] == "agent_denied_by_policy");
        assert!(
            has_deny_finding,
            "AgentDeniedByPolicy finding must be present: {structured}"
        );
    }

    /// Seed a `.tirith/policy.yaml` with BOTH a deny matcher AND an
    /// approval rule targeting `plain_http_to_sink`. Used by the
    /// "deny does not emit approval metadata" tests below: a plain
    /// HTTP URL in sink context would otherwise raise PlainHttpToSink
    /// (HIGH) and match the approval rule. The CodeRabbit Major fix
    /// reorders the MCP handler so `apply_agent_rules` runs BEFORE
    /// `check_approval`, and `check_approval` is gated on `action !=
    /// Block`. With deny firing the verdict is Block, and the response
    /// must NOT carry `requires_approval` / `approval_*` fields.
    fn seed_mcp_deny_plus_approval_policy(client: &str) -> tempfile::TempDir {
        let dir = tempfile::tempdir().expect("tempdir");
        let tirith_dir = dir.path().join(".tirith");
        std::fs::create_dir_all(&tirith_dir).expect("create .tirith dir");
        let policy = format!(
            "agent_rules:\n  \
             deny:\n    \
             - kind: mcp\n      \
               name: {client}\n\
             approval_rules:\n  \
             - rule_ids: [\"plain_http_to_sink\"]\n    \
               timeout_secs: 60\n    \
               fallback: \"block\"\n"
        );
        std::fs::write(tirith_dir.join("policy.yaml"), policy).expect("write policy");
        dir
    }

    /// M4 PR #120 fix-6 (CodeRabbit Major) — pin that the
    /// `call_check_url` handler does NOT emit approval metadata when
    /// the verdict is denied. Before fix-6, the handler computed
    /// `check_approval` / `apply_approval` BEFORE `apply_agent_rules`,
    /// so a denied MCP client received both `action: block` and
    /// `requires_approval` / `approval_*` fields — conflicting client
    /// instructions ("Block this" plus "Ask the user to approve").
    /// Fix-6 reorders the pipeline so apply_agent_rules runs first
    /// and approval is only derived when the verdict isn't already Block.
    #[test]
    fn mcp_check_url_deny_does_not_emit_approval_metadata() {
        let _env_lock = crate::TEST_ENV_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let _origin_guard = super::super::origin::reset_for_test();

        super::super::origin::set_from_initialize(Some(&super::super::types::ClientInfo {
            name: "hostile-mcp-client".to_string(),
            version: None,
        }));

        let policy_dir = seed_mcp_deny_plus_approval_policy("hostile-mcp-client");
        let _root = EnvVarGuard::set("TIRITH_POLICY_ROOT", policy_dir.path());

        // Plain HTTP URL in sink context — would normally raise
        // PlainHttpToSink (HIGH), which matches the approval rule and
        // would normally populate the approval_* metadata. With the
        // deny matcher in play the verdict is Block and approval must
        // NOT be derived.
        let resp = call_check_url(&json!({"url": "http://example.com/install.sh"}));
        assert!(!resp.is_error, "tool dispatch must succeed: {resp:?}");
        let structured = resp
            .structured_content
            .expect("structured_content must be present");

        // Pin (1) — verdict is Block (deny enforced).
        assert_eq!(
            structured["action"], "block",
            "deny matcher must produce Block verdict: {structured}"
        );

        // Pin (2) — NO approval metadata. The fields may be absent
        // entirely (serde `skip_serializing_if = "Option::is_none"`)
        // OR explicitly null; both are acceptable. The pin is that
        // they are NOT a populated approval contract.
        let requires_approval = structured.get("requires_approval");
        assert!(
            requires_approval.is_none() || requires_approval == Some(&json!(null)),
            "denied verdict MUST NOT emit requires_approval=true: {structured}"
        );
        for key in [
            "approval_timeout_secs",
            "approval_fallback",
            "approval_rule",
            "approval_description",
        ] {
            let v = structured.get(key);
            assert!(
                v.is_none() || v == Some(&json!(null)),
                "denied verdict MUST NOT emit `{key}`: {structured}"
            );
        }
    }

    /// M4 PR #120 fix-6 (CodeRabbit Major) — paired with
    /// `mcp_check_url_deny_does_not_emit_approval_metadata` above; the
    /// paste handler had the same reorder bug.
    #[test]
    fn mcp_check_paste_deny_does_not_emit_approval_metadata() {
        let _env_lock = crate::TEST_ENV_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let _origin_guard = super::super::origin::reset_for_test();

        super::super::origin::set_from_initialize(Some(&super::super::types::ClientInfo {
            name: "hostile-mcp-client".to_string(),
            version: None,
        }));

        let policy_dir = seed_mcp_deny_plus_approval_policy("hostile-mcp-client");
        let _root = EnvVarGuard::set("TIRITH_POLICY_ROOT", policy_dir.path());

        // Paste content with a plain HTTP URL — normally raises
        // PlainHttpToSink (matches the approval rule). Under deny,
        // verdict must be Block with no approval_* metadata.
        let resp = call_check_paste(&json!({"content": "curl http://example.com/install.sh"}));
        assert!(!resp.is_error, "tool dispatch must succeed: {resp:?}");
        let structured = resp
            .structured_content
            .expect("structured_content must be present");

        assert_eq!(
            structured["action"], "block",
            "deny matcher must produce Block verdict on paste: {structured}"
        );

        let requires_approval = structured.get("requires_approval");
        assert!(
            requires_approval.is_none() || requires_approval == Some(&json!(null)),
            "denied paste verdict MUST NOT emit requires_approval=true: {structured}"
        );
        for key in [
            "approval_timeout_secs",
            "approval_fallback",
            "approval_rule",
            "approval_description",
        ] {
            let v = structured.get(key);
            assert!(
                v.is_none() || v == Some(&json!(null)),
                "denied paste verdict MUST NOT emit `{key}`: {structured}"
            );
        }
    }

    /// M4 item 8 chunk 3 follow-up — paired with `mcp_check_url_*` above.
    /// `tirith_check_paste` had the same enforcement gap as
    /// `tirith_check_url`; this test pins the fix for the paste handler.
    #[test]
    fn mcp_check_paste_with_agent_rules_deny_forces_block() {
        let _env_lock = crate::TEST_ENV_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let _origin_guard = super::super::origin::reset_for_test();

        super::super::origin::set_from_initialize(Some(&super::super::types::ClientInfo {
            name: "hostile-mcp-client".to_string(),
            version: None,
        }));

        let policy_dir = seed_mcp_deny_policy("hostile-mcp-client");
        let _root = EnvVarGuard::set("TIRITH_POLICY_ROOT", policy_dir.path());

        // Clean paste content — would otherwise be Allow.
        let resp = call_check_paste(&json!({"content": "hello world"}));
        assert!(!resp.is_error, "tool dispatch must succeed: {resp:?}");
        let structured = resp
            .structured_content
            .expect("structured_content must be present");
        assert_eq!(
            structured["action"], "block",
            "deny matcher must flip the paste verdict to Block: {structured}"
        );
        let has_deny_finding = structured["findings"]
            .as_array()
            .expect("findings must be an array")
            .iter()
            .any(|f| f["rule_id"] == "agent_denied_by_policy");
        assert!(
            has_deny_finding,
            "AgentDeniedByPolicy finding must be present: {structured}"
        );
    }

    // -----------------------------------------------------------------
    // M4 PR #120 fix-7 (Greptile P1) — bypass-honored MCP diagnostic
    // tools must still write the audit entry.
    //
    // Background. fix-3 (5d94c71) removed the engine's internal
    // bypass-fast-exit audit-write and moved the responsibility to the
    // caller so each surface can stamp `agent_origin` BEFORE the entry
    // is recorded. `call_check_command` was correctly updated (see the
    // `if raw_verdict.bypass_honored { audit::log_verdict(...) }`
    // branch in `call_check_command`). The two diagnostic MCP tools
    // (`call_check_url`, `call_check_paste`) were missed — fix-7
    // restores the audit-write on those bypass paths.
    //
    // Test plan, per handler:
    //   1. Seed `agent_origin` to a hostile client name.
    //   2. Seed a policy that BOTH opts in to non-interactive bypass
    //      AND carries a deny matcher for that client (so we can pin
    //      that deny does NOT fire under honored bypass — the audit
    //      `rule_ids` must NOT carry `agent_denied_by_policy`).
    //   3. Point `XDG_DATA_HOME` at a tempdir so the audit log lands
    //      there and the test can read it back.
    //   4. Set `TIRITH=0` to request bypass.
    //   5. Invoke the handler with input that fires tier-1 (so the
    //      engine reaches the bypass branch — tier-1-clean input
    //      fast-exits at tier-1 and never produces `bypass_honored:
    //      true`).
    //   6. Assert: `bypass_honored: true` in the structured response,
    //      audit log has a `verdict` entry with `bypass_honored: true`
    //      and the stamped `agent_origin`, and the entry carries NO
    //      `agent_denied_by_policy` rule id (bypass-skip contract).
    // -----------------------------------------------------------------

    /// Seed a `.tirith/policy.yaml` that opts in to `TIRITH=0` bypass
    /// in non-interactive contexts (cargo test spawns non-interactive
    /// children — same with in-process MCP `interactive: false`) AND
    /// carries a deny matcher for `client`. Used by the fix-7 audit
    /// tests below — see the module-level comment for the contract.
    fn seed_mcp_bypass_plus_deny_policy(client: &str) -> tempfile::TempDir {
        let dir = tempfile::tempdir().expect("tempdir");
        let tirith_dir = dir.path().join(".tirith");
        std::fs::create_dir_all(&tirith_dir).expect("create .tirith dir");
        let policy = format!(
            "allow_bypass_env: true\n\
             allow_bypass_env_noninteractive: true\n\
             agent_rules:\n  \
             deny:\n    \
             - kind: mcp\n      \
               name: {client}\n"
        );
        std::fs::write(tirith_dir.join("policy.yaml"), policy).expect("write policy");
        dir
    }

    /// M4 PR #120 fix-7 (Greptile P1) — pin that `call_check_url`
    /// writes an audit entry on the bypass-honored fast-exit path.
    /// Pre-fix-3 the engine did this internally; fix-3 moved
    /// responsibility to the caller and `call_check_command` was
    /// updated, but the diagnostic MCP tools were missed. See the
    /// module-level comment above for the full test plan.
    #[test]
    fn mcp_check_url_bypass_writes_audit_entry() {
        let _env_lock = crate::TEST_ENV_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let _origin_guard = super::super::origin::reset_for_test();

        super::super::origin::set_from_initialize(Some(&super::super::types::ClientInfo {
            name: "hostile-mcp-client".to_string(),
            version: None,
        }));

        let policy_dir = seed_mcp_bypass_plus_deny_policy("hostile-mcp-client");
        let _root = EnvVarGuard::set("TIRITH_POLICY_ROOT", policy_dir.path());

        // Point audit log at a tempdir we control. `data_dir()` uses
        // `etcetera::choose_base_strategy().data_dir()` which on macOS
        // & Linux honors `XDG_DATA_HOME` (etcetera 0.8 returns the Xdg
        // base on macOS — verified in
        // `etcetera-0.8.0/src/base_strategy.rs:47-59`).
        let data_tmp = tempfile::tempdir().expect("data tempdir");
        let _data = EnvVarGuard::set("XDG_DATA_HOME", data_tmp.path());
        // Be explicit — TIRITH_LOG default is "on" but the env may
        // carry a stale "0" from a prior test in this process.
        let _log = EnvVarGuard::set("TIRITH_LOG", "1");
        let _bypass = EnvVarGuard::set("TIRITH", "0");

        // URL that fires tier-1 once wrapped in `curl '...'` —
        // `plain_http_to_sink` triggers on http:// + .sh path. Tier-1
        // MUST trigger for the engine to reach the bypass branch
        // (line 482 of engine.rs); tier-1-clean inputs fast-exit at
        // line 461 without setting `bypass_honored`.
        let resp = call_check_url(&json!({"url": "http://example.com/install.sh"}));
        assert!(!resp.is_error, "tool dispatch must succeed: {resp:?}");
        let structured = resp
            .structured_content
            .expect("structured_content must be present");

        // Pin (1) — bypass was honored.
        assert_eq!(
            structured["bypass_honored"], true,
            "TIRITH=0 + opted-in non-interactive bypass must honor bypass: {structured}"
        );

        // Pin (2) — bypass-skip contract on `apply_agent_rules`: no
        // deny finding even though the matcher would otherwise fire.
        let has_deny_finding = structured["findings"]
            .as_array()
            .map(|arr| arr.iter().any(|f| f["rule_id"] == "agent_denied_by_policy"))
            .unwrap_or(false);
        assert!(
            !has_deny_finding,
            "agent_denied_by_policy MUST NOT fire under honored bypass: {structured}"
        );

        // Pin (3) — fix-7 contract: the audit entry is written.
        let log_path = data_tmp.path().join("tirith").join("log.jsonl");
        let log = std::fs::read_to_string(&log_path).unwrap_or_else(|e| {
            panic!(
                "fix-7: audit log {} not written on bypass-honored MCP check_url path: {e}",
                log_path.display()
            )
        });
        let entry: serde_json::Value = log
            .lines()
            .filter_map(|l| serde_json::from_str::<serde_json::Value>(l).ok())
            .find(|e| e["entry_type"] == "verdict")
            .expect("a verdict audit entry must exist (fix-7 restores this write)");

        assert_eq!(
            entry["bypass_honored"], true,
            "audit entry MUST reflect bypass_honored=true: {entry}"
        );
        // origin is carried through `log_verdict` (see audit.rs:286).
        // The MCP variant serializes as `{kind:"mcp", client_name:..}`
        // — see `AgentOrigin::Mcp` in agent_origin.rs.
        assert_eq!(
            entry["agent_origin"]["kind"], "mcp",
            "audit entry agent_origin kind must be `mcp`: {entry}"
        );
        assert_eq!(
            entry["agent_origin"]["client_name"], "hostile-mcp-client",
            "audit entry MUST carry the stamped agent_origin client_name: {entry}"
        );
        let audit_carries_deny = entry["rule_ids"]
            .as_array()
            .map(|arr| arr.iter().any(|r| r == "agent_denied_by_policy"))
            .unwrap_or(false);
        assert!(
            !audit_carries_deny,
            "audit rule_ids MUST NOT carry agent_denied_by_policy under honored bypass: {entry}"
        );
    }

    /// M4 PR #120 fix-7 (Greptile P1) — paired with
    /// `mcp_check_url_bypass_writes_audit_entry`. Same gap on the
    /// paste handler. See module-level comment above for plan.
    #[test]
    fn mcp_check_paste_bypass_writes_audit_entry() {
        let _env_lock = crate::TEST_ENV_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let _origin_guard = super::super::origin::reset_for_test();

        super::super::origin::set_from_initialize(Some(&super::super::types::ClientInfo {
            name: "hostile-mcp-client".to_string(),
            version: None,
        }));

        let policy_dir = seed_mcp_bypass_plus_deny_policy("hostile-mcp-client");
        let _root = EnvVarGuard::set("TIRITH_POLICY_ROOT", policy_dir.path());

        let data_tmp = tempfile::tempdir().expect("data tempdir");
        let _data = EnvVarGuard::set("XDG_DATA_HOME", data_tmp.path());
        let _log = EnvVarGuard::set("TIRITH_LOG", "1");
        let _bypass = EnvVarGuard::set("TIRITH", "0");

        // Paste content that fires tier-1 (pipe-to-shell) — engine
        // must reach the bypass branch for `bypass_honored: true`.
        let resp =
            call_check_paste(&json!({"content": "curl https://example.com/install.sh | bash"}));
        assert!(!resp.is_error, "tool dispatch must succeed: {resp:?}");
        let structured = resp
            .structured_content
            .expect("structured_content must be present");

        assert_eq!(
            structured["bypass_honored"], true,
            "TIRITH=0 + opted-in non-interactive bypass must honor bypass on paste: {structured}"
        );

        let has_deny_finding = structured["findings"]
            .as_array()
            .map(|arr| arr.iter().any(|f| f["rule_id"] == "agent_denied_by_policy"))
            .unwrap_or(false);
        assert!(
            !has_deny_finding,
            "agent_denied_by_policy MUST NOT fire on paste under honored bypass: {structured}"
        );

        let log_path = data_tmp.path().join("tirith").join("log.jsonl");
        let log = std::fs::read_to_string(&log_path).unwrap_or_else(|e| {
            panic!(
                "fix-7: audit log {} not written on bypass-honored MCP check_paste path: {e}",
                log_path.display()
            )
        });
        let entry: serde_json::Value = log
            .lines()
            .filter_map(|l| serde_json::from_str::<serde_json::Value>(l).ok())
            .find(|e| e["entry_type"] == "verdict")
            .expect("a verdict audit entry must exist (fix-7 restores this write)");

        assert_eq!(
            entry["bypass_honored"], true,
            "paste audit entry MUST reflect bypass_honored=true: {entry}"
        );
        // The MCP variant serializes as `{kind:"mcp", client_name:..}`
        // — see `AgentOrigin::Mcp` in agent_origin.rs.
        assert_eq!(
            entry["agent_origin"]["kind"], "mcp",
            "paste audit entry agent_origin kind must be `mcp`: {entry}"
        );
        assert_eq!(
            entry["agent_origin"]["client_name"], "hostile-mcp-client",
            "paste audit entry MUST carry the stamped agent_origin client_name: {entry}"
        );
        let audit_carries_deny = entry["rule_ids"]
            .as_array()
            .map(|arr| arr.iter().any(|r| r == "agent_denied_by_policy"))
            .unwrap_or(false);
        assert!(
            !audit_carries_deny,
            "paste audit rule_ids MUST NOT carry agent_denied_by_policy under honored bypass: \
             {entry}"
        );
    }
}
