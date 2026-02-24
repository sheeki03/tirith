use std::time::Instant;

use crate::extract::{self, ScanContext};
use crate::normalize;
use crate::policy::Policy;
use crate::tokenize::ShellType;
use crate::verdict::{Finding, Timings, Verdict};

/// Extract the raw path from a URL string before any normalization.
fn extract_raw_path_from_url(raw: &str) -> Option<String> {
    if let Some(idx) = raw.find("://") {
        let after = &raw[idx + 3..];
        if let Some(slash_idx) = after.find('/') {
            // Find end of path (before ? or #)
            let path_start = &after[slash_idx..];
            let end = path_start.find(['?', '#']).unwrap_or(path_start.len());
            return Some(path_start[..end].to_string());
        }
    }
    None
}

/// Analysis context passed through the pipeline.
pub struct AnalysisContext {
    pub input: String,
    pub shell: ShellType,
    pub scan_context: ScanContext,
    pub raw_bytes: Option<Vec<u8>>,
    pub interactive: bool,
    pub cwd: Option<String>,
}

/// Check if the input contains an inline `TIRITH=0` bypass prefix.
/// Handles bare prefix (`TIRITH=0 cmd`) and env wrappers (`env -i TIRITH=0 cmd`).
fn find_inline_bypass(input: &str, _shell: ShellType) -> bool {
    use crate::tokenize;

    let words = split_raw_words(input);
    if words.is_empty() {
        return false;
    }

    // Case 1: Leading VAR=VALUE assignments before the command
    let mut idx = 0;
    while idx < words.len() && tokenize::is_env_assignment(&words[idx]) {
        if words[idx] == "TIRITH=0" {
            return true;
        }
        idx += 1;
    }

    // Case 2: First real word is `env` — parse env-style args
    if idx < words.len() {
        let cmd = words[idx].rsplit('/').next().unwrap_or(&words[idx]);
        if cmd == "env" {
            idx += 1;
            while idx < words.len() {
                let w = &words[idx];
                if w == "--" {
                    idx += 1;
                    // After --, remaining are VAR=VALUE or command
                    break;
                }
                if tokenize::is_env_assignment(w) {
                    if w == "TIRITH=0" {
                        return true;
                    }
                    idx += 1;
                    continue;
                }
                if w.starts_with('-') {
                    // -u takes a value arg
                    if w == "-u" {
                        idx += 2; // skip -u and its value
                        continue;
                    }
                    idx += 1;
                    continue;
                }
                // Non-flag, non-assignment = the command, stop
                break;
            }
            // Check remaining words after -- for TIRITH=0
            while idx < words.len() && tokenize::is_env_assignment(&words[idx]) {
                if words[idx] == "TIRITH=0" {
                    return true;
                }
                idx += 1;
            }
        }
    }

    false
}

/// Split input into raw words respecting quotes (for bypass/self-invocation parsing).
/// Unlike tokenize(), this doesn't split on pipes/semicolons — just whitespace-splits
/// the raw input to inspect the first segment's words.
fn split_raw_words(input: &str) -> Vec<String> {
    // Take only up to the first unquoted pipe/semicolon/&&/||
    let mut words = Vec::new();
    let mut current = String::new();
    let chars: Vec<char> = input.chars().collect();
    let len = chars.len();
    let mut i = 0;

    while i < len {
        let ch = chars[i];
        match ch {
            ' ' | '\t' if !current.is_empty() => {
                words.push(current.clone());
                current.clear();
                i += 1;
                while i < len && (chars[i] == ' ' || chars[i] == '\t') {
                    i += 1;
                }
            }
            ' ' | '\t' => {
                i += 1;
            }
            '|' | ';' | '\n' | '&' => break, // Stop at segment boundary
            '\'' => {
                current.push(ch);
                i += 1;
                while i < len && chars[i] != '\'' {
                    current.push(chars[i]);
                    i += 1;
                }
                if i < len {
                    current.push(chars[i]);
                    i += 1;
                }
            }
            '"' => {
                current.push(ch);
                i += 1;
                while i < len && chars[i] != '"' {
                    if chars[i] == '\\' && i + 1 < len {
                        current.push(chars[i]);
                        current.push(chars[i + 1]);
                        i += 2;
                    } else {
                        current.push(chars[i]);
                        i += 1;
                    }
                }
                if i < len {
                    current.push(chars[i]);
                    i += 1;
                }
            }
            '\\' if i + 1 < len => {
                current.push(chars[i]);
                current.push(chars[i + 1]);
                i += 2;
            }
            _ => {
                current.push(ch);
                i += 1;
            }
        }
    }
    if !current.is_empty() {
        words.push(current);
    }
    words
}

/// Check if the input is a self-invocation of tirith (single-segment only).
/// Returns true if the resolved command is `tirith` itself.
fn is_self_invocation(input: &str, shell: ShellType) -> bool {
    use crate::tokenize;

    // Must be single segment (no pipes, &&, etc.)
    let segments = tokenize::tokenize(input, shell);
    if segments.len() != 1 {
        return false;
    }

    let words = split_raw_words(input);
    if words.is_empty() {
        return false;
    }

    // Skip leading VAR=VALUE
    let mut idx = 0;
    while idx < words.len() && tokenize::is_env_assignment(&words[idx]) {
        idx += 1;
    }
    if idx >= words.len() {
        return false;
    }

    let cmd = &words[idx];
    let cmd_base = cmd.rsplit('/').next().unwrap_or(cmd);

    // Try to resolve wrappers (one level)
    let resolved = match cmd_base {
        "env" => resolve_env_wrapper(&words[idx + 1..]),
        "command" => resolve_command_wrapper(&words[idx + 1..]),
        "time" => resolve_time_wrapper(&words[idx + 1..]),
        other => Some(other.to_string()),
    };

    match resolved {
        Some(ref cmd_name) => is_tirith_command(cmd_name),
        None => false,
    }
}

/// Resolve through `env` wrapper: skip options, VAR=VALUE, find command.
fn resolve_env_wrapper(args: &[String]) -> Option<String> {
    use crate::tokenize;
    let mut i = 0;
    while i < args.len() {
        let w = &args[i];
        if w == "--" {
            i += 1;
            break;
        }
        if tokenize::is_env_assignment(w) {
            i += 1;
            continue;
        }
        if w.starts_with('-') {
            if w == "-u" {
                i += 2; // skip -u and its value
                continue;
            }
            i += 1;
            continue;
        }
        // First non-option, non-assignment is the command
        return Some(w.rsplit('/').next().unwrap_or(w).to_string());
    }
    // After --, skip remaining VAR=VALUE to find command
    while i < args.len() {
        let w = &args[i];
        if tokenize::is_env_assignment(w) {
            i += 1;
            continue;
        }
        return Some(w.rsplit('/').next().unwrap_or(w).to_string());
    }
    None
}

/// Resolve through `command` wrapper: skip flags (e.g. -v, -p, -V) and `--`, take next arg.
fn resolve_command_wrapper(args: &[String]) -> Option<String> {
    let mut i = 0;
    // Skip flags like -v, -p, -V
    while i < args.len() && args[i].starts_with('-') && args[i] != "--" {
        i += 1;
    }
    // Skip -- if present
    if i < args.len() && args[i] == "--" {
        i += 1;
    }
    if i < args.len() {
        let w = &args[i];
        Some(w.rsplit('/').next().unwrap_or(w).to_string())
    } else {
        None
    }
}

/// Resolve through `time` wrapper: skip -prefixed flags, take next non-flag.
fn resolve_time_wrapper(args: &[String]) -> Option<String> {
    for w in args {
        if w.starts_with('-') {
            continue;
        }
        return Some(w.rsplit('/').next().unwrap_or(w).to_string());
    }
    None
}

/// Check if a command name is tirith.
/// All callers strip path prefixes via `rsplit('/')`, so only bare name comparison is needed.
fn is_tirith_command(cmd: &str) -> bool {
    cmd == "tirith"
}

/// Run the tiered analysis pipeline.
pub fn analyze(ctx: &AnalysisContext) -> Verdict {
    let start = Instant::now();

    // Tier 0: Check bypass flag
    let tier0_start = Instant::now();
    let bypass_env = std::env::var("TIRITH").ok().as_deref() == Some("0");
    let bypass_inline = find_inline_bypass(&ctx.input, ctx.shell);
    let bypass_requested = bypass_env || bypass_inline;
    let tier0_ms = tier0_start.elapsed().as_secs_f64() * 1000.0;

    // Tier 1: Fast scan (no I/O)
    let tier1_start = Instant::now();

    // Step 1 (paste only): byte-level scan for control chars
    let byte_scan_triggered = if ctx.scan_context == ScanContext::Paste {
        if let Some(ref bytes) = ctx.raw_bytes {
            let scan = extract::scan_bytes(bytes);
            scan.has_ansi_escapes
                || scan.has_control_chars
                || scan.has_bidi_controls
                || scan.has_zero_width
                || scan.has_invalid_utf8
        } else {
            false
        }
    } else {
        false
    };

    // Step 2: URL-like regex scan
    let regex_triggered = extract::tier1_scan(&ctx.input, ctx.scan_context);

    // Step 3 (exec only): check for bidi/zero-width chars even without URLs
    let exec_bidi_triggered = if ctx.scan_context == ScanContext::Exec {
        let scan = extract::scan_bytes(ctx.input.as_bytes());
        scan.has_bidi_controls || scan.has_zero_width
    } else {
        false
    };

    let tier1_ms = tier1_start.elapsed().as_secs_f64() * 1000.0;

    // If nothing triggered, fast exit
    if !byte_scan_triggered && !regex_triggered && !exec_bidi_triggered {
        let total_ms = start.elapsed().as_secs_f64() * 1000.0;
        return Verdict::allow_fast(
            1,
            Timings {
                tier0_ms,
                tier1_ms,
                tier2_ms: None,
                tier3_ms: None,
                total_ms,
            },
        );
    }

    // Self-invocation guard: allow tirith's own commands (single-segment only)
    if ctx.scan_context == ScanContext::Exec && is_self_invocation(&ctx.input, ctx.shell) {
        let total_ms = start.elapsed().as_secs_f64() * 1000.0;
        return Verdict::allow_fast(
            1,
            Timings {
                tier0_ms,
                tier1_ms,
                tier2_ms: None,
                tier3_ms: None,
                total_ms,
            },
        );
    }

    // Tier 2: Policy + data loading (deferred I/O)
    let tier2_start = Instant::now();

    if bypass_requested {
        // Load partial policy to check bypass settings
        let policy = Policy::discover_partial(ctx.cwd.as_deref());
        let allow_bypass = if ctx.interactive {
            policy.allow_bypass_env
        } else {
            policy.allow_bypass_env_noninteractive
        };

        if allow_bypass {
            let tier2_ms = tier2_start.elapsed().as_secs_f64() * 1000.0;
            let total_ms = start.elapsed().as_secs_f64() * 1000.0;
            let mut verdict = Verdict::allow_fast(
                2,
                Timings {
                    tier0_ms,
                    tier1_ms,
                    tier2_ms: Some(tier2_ms),
                    tier3_ms: None,
                    total_ms,
                },
            );
            verdict.bypass_requested = true;
            verdict.bypass_honored = true;
            verdict.interactive_detected = ctx.interactive;
            verdict.policy_path_used = policy.path.clone();
            // Log bypass to audit
            crate::audit::log_verdict(&verdict, &ctx.input, None, None);
            return verdict;
        }
    }

    let mut policy = Policy::discover(ctx.cwd.as_deref());
    policy.load_user_lists();
    policy.load_org_lists(ctx.cwd.as_deref());
    let tier2_ms = tier2_start.elapsed().as_secs_f64() * 1000.0;

    // Tier 3: Full analysis
    let tier3_start = Instant::now();
    let mut findings = Vec::new();

    // Run byte-level rules for paste context
    if ctx.scan_context == ScanContext::Paste {
        if let Some(ref bytes) = ctx.raw_bytes {
            let byte_findings = crate::rules::terminal::check_bytes(bytes);
            findings.extend(byte_findings);
        }
        // Check for hidden multiline content in pasted text
        let multiline_findings = crate::rules::terminal::check_hidden_multiline(&ctx.input);
        findings.extend(multiline_findings);
    }

    // Bidi and zero-width checks apply to both exec and paste contexts
    // (exec context: bidi in URLs/commands is always dangerous)
    if ctx.scan_context == ScanContext::Exec {
        let byte_input = ctx.input.as_bytes();
        let scan = extract::scan_bytes(byte_input);
        if scan.has_bidi_controls || scan.has_zero_width {
            let byte_findings = crate::rules::terminal::check_bytes(byte_input);
            // Only keep bidi and zero-width findings for exec context
            findings.extend(byte_findings.into_iter().filter(|f| {
                matches!(
                    f.rule_id,
                    crate::verdict::RuleId::BidiControls | crate::verdict::RuleId::ZeroWidthChars
                )
            }));
        }
    }

    // Extract and analyze URLs
    let extracted = extract::extract_urls(&ctx.input, ctx.shell);

    for url_info in &extracted {
        // Normalize path if available — use raw extracted URL's path for non-ASCII detection
        // since url::Url percent-encodes non-ASCII during parsing
        let raw_path = extract_raw_path_from_url(&url_info.raw);
        let normalized_path = url_info.parsed.path().map(normalize::normalize_path);

        // Run all rule categories
        let hostname_findings = crate::rules::hostname::check(&url_info.parsed, &policy);
        findings.extend(hostname_findings);

        let path_findings = crate::rules::path::check(
            &url_info.parsed,
            normalized_path.as_ref(),
            raw_path.as_deref(),
        );
        findings.extend(path_findings);

        let transport_findings =
            crate::rules::transport::check(&url_info.parsed, url_info.in_sink_context);
        findings.extend(transport_findings);

        let ecosystem_findings = crate::rules::ecosystem::check(&url_info.parsed);
        findings.extend(ecosystem_findings);
    }

    // Run command-shape rules on full input
    let command_findings = crate::rules::command::check(&ctx.input, ctx.shell);
    findings.extend(command_findings);

    // Run environment rules
    let env_findings = crate::rules::environment::check(&crate::rules::environment::RealEnv);
    findings.extend(env_findings);

    // Apply policy severity overrides
    for finding in &mut findings {
        if let Some(override_sev) = policy.severity_override(&finding.rule_id) {
            finding.severity = override_sev;
        }
    }

    // Filter by allowlist/blocklist
    // Blocklist: if any extracted URL matches blocklist, escalate to Block
    for url_info in &extracted {
        if policy.is_blocklisted(&url_info.raw) {
            findings.push(Finding {
                rule_id: crate::verdict::RuleId::PolicyBlocklisted,
                severity: crate::verdict::Severity::Critical,
                title: "URL matches blocklist".to_string(),
                description: format!("URL '{}' matches a blocklist pattern", url_info.raw),
                evidence: vec![crate::verdict::Evidence::Url {
                    raw: url_info.raw.clone(),
                }],
            });
        }
    }

    // Allowlist: remove findings for URLs that match allowlist
    // (blocklist takes precedence — if blocklisted, findings remain)
    if !policy.allowlist.is_empty() {
        let blocklisted_urls: Vec<String> = extracted
            .iter()
            .filter(|u| policy.is_blocklisted(&u.raw))
            .map(|u| u.raw.clone())
            .collect();

        findings.retain(|f| {
            // Keep all findings that aren't URL-based
            let url_in_evidence = f.evidence.iter().find_map(|e| {
                if let crate::verdict::Evidence::Url { raw } = e {
                    Some(raw.clone())
                } else {
                    None
                }
            });
            match url_in_evidence {
                Some(ref url) => {
                    // Keep if blocklisted, otherwise drop if allowlisted
                    blocklisted_urls.contains(url) || !policy.is_allowlisted(url)
                }
                None => true, // Keep non-URL findings
            }
        });
    }

    let tier3_ms = tier3_start.elapsed().as_secs_f64() * 1000.0;
    let total_ms = start.elapsed().as_secs_f64() * 1000.0;

    let mut verdict = Verdict::from_findings(
        findings,
        3,
        Timings {
            tier0_ms,
            tier1_ms,
            tier2_ms: Some(tier2_ms),
            tier3_ms: Some(tier3_ms),
            total_ms,
        },
    );
    verdict.bypass_requested = bypass_requested;
    verdict.interactive_detected = ctx.interactive;
    verdict.policy_path_used = policy.path.clone();
    verdict.urls_extracted_count = Some(extracted.len());

    verdict
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_exec_bidi_without_url() {
        // Input with bidi control but no URL — should NOT fast-exit at tier 1
        let input = format!("echo hello{}world", '\u{202E}');
        let ctx = AnalysisContext {
            input,
            shell: ShellType::Posix,
            scan_context: ScanContext::Exec,
            raw_bytes: None,
            interactive: true,
            cwd: None,
        };
        let verdict = analyze(&ctx);
        // Should reach tier 3 (not fast-exit at tier 1)
        assert!(
            verdict.tier_reached >= 3,
            "bidi in exec should reach tier 3, got tier {}",
            verdict.tier_reached
        );
        // Should have findings about bidi
        assert!(
            verdict
                .findings
                .iter()
                .any(|f| matches!(f.rule_id, crate::verdict::RuleId::BidiControls)),
            "should detect bidi controls in exec context"
        );
    }
}
