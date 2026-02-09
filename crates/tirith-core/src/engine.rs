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

/// Run the tiered analysis pipeline.
pub fn analyze(ctx: &AnalysisContext) -> Verdict {
    let start = Instant::now();

    // Tier 0: Check bypass flag
    let tier0_start = Instant::now();
    let bypass_requested = std::env::var("TIRITH").ok().as_deref() == Some("0");
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
