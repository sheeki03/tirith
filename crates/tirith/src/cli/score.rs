use std::io::Write;
use tirith_core::engine::{self, AnalysisContext};
use tirith_core::extract::ScanContext;
use tirith_core::output;
use tirith_core::scoring::{self, ScoreBreakdown};
use tirith_core::tokenize::ShellType;

/// Run `tirith score <url>`. `explain` adds the full deterministic factor
/// breakdown so a user can reproduce the score by hand.
pub fn run(url: &str, json: bool, explain: bool) -> i32 {
    let ctx = AnalysisContext {
        input: url.to_string(),
        shell: ShellType::Posix,
        scan_context: ScanContext::Exec,
        raw_bytes: None,
        interactive: true,
        cwd: std::env::current_dir()
            .ok()
            .map(|p| p.display().to_string()),
        file_path: None,
        repo_root: None,
        is_config_override: false,
        clipboard_html: None,
        card_ref: None,
        clipboard_source: tirith_core::clipboard::ClipboardSourceState::Unread,
    };

    let (verdict, policy) = engine::analyze_returning_policy(&ctx);
    let breakdown = scoring::score_verdict(&verdict);
    // Defence in depth: assert the factors-sum-to-score invariant in debug.
    debug_assert!(
        breakdown.verify(),
        "score breakdown factors must sum to the final score"
    );

    if json {
        print_json(
            url,
            &verdict,
            &breakdown,
            explain,
            &policy.dlp_custom_patterns,
        );
    } else {
        print_human(
            url,
            &verdict,
            &breakdown,
            explain,
            &policy.dlp_custom_patterns,
        );
    }

    0
}

fn print_json(
    url: &str,
    verdict: &tirith_core::verdict::Verdict,
    breakdown: &ScoreBreakdown,
    explain: bool,
    custom_patterns: &[String],
) {
    let value = build_json_value(url, verdict, breakdown, explain, custom_patterns);
    super::write_json_stdout(&value, "tirith: failed to write JSON output");
}

fn build_json_value(
    url: &str,
    verdict: &tirith_core::verdict::Verdict,
    breakdown: &ScoreBreakdown,
    explain: bool,
    custom_patterns: &[String],
) -> serde_json::Value {
    #[derive(serde::Serialize)]
    struct ScoreOutput<'a> {
        url: String,
        score: u32,
        risk_level: &'a str,
        findings: &'a [tirith_core::verdict::Finding],
        /// Full factor breakdown — only with `--explain`.
        #[serde(skip_serializing_if = "Option::is_none")]
        score_breakdown: Option<&'a ScoreBreakdown>,
        dlp_redaction_incomplete: bool,
    }

    let compiled = tirith_core::redact::CompiledCustomPatterns::new_silent(custom_patterns);
    let mut display = verdict.clone();
    tirith_core::redact::redact_verdict_with_compiled(&mut display, &compiled);
    tirith_core::verdict::bound_verdict_for_output(&mut display);
    let mut safe_breakdown = breakdown.clone();
    for factor in &mut safe_breakdown.factors {
        factor.label =
            tirith_core::redact::redact_sanitize_redact_with_compiled(&factor.label, &compiled);
        factor.detail =
            tirith_core::redact::redact_sanitize_redact_with_compiled(&factor.detail, &compiled);
    }
    let out = ScoreOutput {
        // `url` and the finding evidence are raw observations, not executable
        // suggestions. Preserve their schema only through a projected RSR-safe
        // value; score JSON has no executable field to rewrite or retain.
        url: tirith_core::redact::redact_sanitize_redact_with_compiled(url, &compiled),
        score: breakdown.score,
        risk_level: breakdown.risk_level,
        findings: &display.findings,
        score_breakdown: if explain { Some(&safe_breakdown) } else { None },
        dlp_redaction_incomplete: compiled.incomplete_reason().is_some(),
    };
    let mut value = serde_json::to_value(out).unwrap_or_else(|_| {
        serde_json::json!({
            "presentation_truncated": true,
            "analysis_incomplete": true,
            "error": "score serialization failed"
        })
    });
    // Apply the recursive boundary to the completed projection before its
    // presentation bound. This covers nested evidence and protects against a
    // control/invisible separator whose removal reconstitutes a custom secret.
    tirith_core::redact::redact_json_strings(&mut value, &compiled);
    tirith_core::verdict::bound_json_value_for_output(value)
}

fn print_human(
    url: &str,
    verdict: &tirith_core::verdict::Verdict,
    breakdown: &ScoreBreakdown,
    explain: bool,
    custom_patterns: &[String],
) {
    let mut invocation = output::HumanInvocationWriter::new(
        std::io::stderr().lock(),
        tirith_core::style::use_color_for(tirith_core::style::Stream::Stderr),
    );
    let compiled = tirith_core::redact::CompiledCustomPatterns::new_silent(custom_patterns);
    if let Some(reason) = compiled.incomplete_reason() {
        let _ = writeln!(
            invocation,
            "tirith score: WARNING: DLP redaction plan is incomplete ({reason}); dynamic output fields were fully redacted."
        );
    }
    let safe_url = output::sanitize_human_field_with_compiled(url, &compiled);
    if verdict.findings.is_empty() {
        // repo-0423: the inspected URL is untrusted — sanitize before rendering.
        let _ = writeln!(
            invocation,
            "tirith: {} — no issues found (score: 0/100)",
            safe_url
        );
    } else {
        let _ = writeln!(
            invocation,
            "tirith: {} — risk score: {}/100 ({})",
            safe_url, breakdown.score, breakdown.risk_level
        );
        let _ = output::write_human_to_invocation_with_compiled(
            verdict,
            false,
            &compiled,
            &mut invocation,
        );
    }

    if explain {
        let _ = write_breakdown_human(breakdown, &compiled, &mut invocation);
    }
    let _ = invocation.finish();
}

/// Write the factor breakdown to `w` so tests and the bounded invocation
/// renderer share identical output.
fn write_breakdown_human(
    breakdown: &ScoreBreakdown,
    compiled: &tirith_core::redact::CompiledCustomPatterns,
    w: &mut impl std::io::Write,
) -> std::io::Result<()> {
    writeln!(w)?;
    writeln!(
        w,
        "  score breakdown (each factor is fixed and inspectable — no model, no learned weights):"
    )?;
    let mut running: i32 = 0;
    for factor in &breakdown.factors {
        running += factor.points;
        // `+NN` for positive contributions, bare `-NN` for the clamp factor.
        let sign = if factor.points >= 0 { "+" } else { "" };
        writeln!(
            w,
            "    {sign}{:<4} {}  (running total: {running})",
            factor.points,
            output::sanitize_human_field_with_compiled(&factor.label, compiled)
        )?;
        writeln!(
            w,
            "           {}",
            output::sanitize_human_field_with_compiled(&factor.detail, compiled)
        )?;
    }
    writeln!(
        w,
        "    = {} / {}  ({}) — sum of every factor above",
        breakdown.score,
        scoring::MAX_SCORE,
        breakdown.risk_level
    )?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tirith_core::scoring::ScoreFactor;
    use tirith_core::verdict::{Evidence, Finding, RuleId, Severity, Timings, Verdict};

    fn render(breakdown: &ScoreBreakdown) -> String {
        let mut buf: Vec<u8> = Vec::new();
        let compiled = tirith_core::redact::CompiledCustomPatterns::new_silent(&[]);
        write_breakdown_human(breakdown, &compiled, &mut buf).expect("write to Vec never fails");
        String::from_utf8(buf).expect("breakdown output is valid UTF-8")
    }

    fn finding(rule_id: RuleId, severity: Severity) -> Finding {
        Finding {
            rule_id,
            severity,
            title: "test".to_string(),
            description: "test".to_string(),
            evidence: vec![Evidence::Text {
                detail: "t".to_string(),
            }],
            human_view: None,
            agent_view: None,
            mitre_id: None,
            custom_rule_id: None,
        }
    }

    #[test]
    fn breakdown_human_renders_clean_zero_finding_url() {
        // No findings: the breakdown still renders, every factor +0, total 0/100.
        let breakdown = scoring::score_findings(&[]);
        assert_eq!(breakdown.score, 0);
        let out = render(&breakdown);

        assert!(
            out.contains("score breakdown"),
            "must print the breakdown header: {out}"
        );
        assert!(
            out.contains("+0"),
            "a zero-finding breakdown must show a +0 factor: {out}"
        );
        // No factor should render negative on a clean URL.
        assert!(
            !out.contains("    -"),
            "a clean URL has no negative (clamp) factor: {out}"
        );
        assert!(
            out.contains("= 0 / 100"),
            "total line must read 0/100 for a clean URL: {out}"
        );
        assert!(
            out.contains("(low)"),
            "a 0 score is the 'low' risk bucket: {out}"
        );
    }

    #[test]
    fn breakdown_human_renders_negative_clamp_factor() {
        // 5 critical findings: 110 raw → clamps to 100 with an explicit -10
        // factor rendered without a leading '+'; total reads 100/100.
        let findings: Vec<Finding> = (0..5)
            .map(|_| finding(RuleId::CurlPipeShell, Severity::Critical))
            .collect();
        let breakdown = scoring::score_findings(&findings);
        assert_eq!(breakdown.score, 100);
        // Sanity: the clamp factor is present and negative.
        let clamp = breakdown
            .factors
            .iter()
            .find(|f| f.id == "clamp")
            .expect("clamp factor must exist when the raw sum exceeds 100");
        assert_eq!(clamp.points, -10);

        let out = render(&breakdown);
        // The clamp factor renders as `-10` (no '+' sign) at column start.
        assert!(
            out.contains("    -10 "),
            "clamp factor must render as a bare -10: {out}"
        );
        assert!(
            !out.contains("+-10"),
            "the negative clamp factor must not get a '+' prefix: {out}"
        );
        assert!(
            out.contains("= 100 / 100"),
            "total line must read 100/100 after clamping: {out}"
        );
        assert!(
            out.contains("(critical)"),
            "a 100 score is the 'critical' risk bucket: {out}"
        );
    }

    #[test]
    fn score_json_recursively_redacts_zero_width_split_custom_secret() {
        let secret = "C02_SCORE_CUSTOM_RECONSTITUTION_CANARY";
        let split = format!("{}\u{200b}{}", &secret[..15], &secret[15..]);
        let patterns = vec![regex::escape(secret)];
        let finding = Finding {
            rule_id: RuleId::NonAsciiHostname,
            severity: Severity::Low,
            title: split.clone(),
            description: format!("nested {split}"),
            evidence: vec![Evidence::Url { raw: split.clone() }],
            human_view: Some(split.clone()),
            agent_view: Some(split.clone()),
            mitre_id: None,
            custom_rule_id: None,
        };
        let verdict = Verdict::from_findings(vec![finding], 3, Timings::default());
        let mut breakdown = scoring::score_verdict(&verdict);
        breakdown.factors.push(ScoreFactor {
            id: "projection_regression",
            label: split.clone(),
            points: 0,
            detail: format!("factor {split}"),
        });
        assert!(breakdown.verify());

        let value = build_json_value(
            &format!("https://example.test/{split}"),
            &verdict,
            &breakdown,
            true,
            &patterns,
        );
        let rendered = serde_json::to_string(&value).unwrap();

        assert!(!rendered.contains(secret), "{rendered}");
        assert!(!rendered.contains('\u{200b}'), "{rendered}");
        assert!(rendered.matches("[REDACTED:custom]").count() >= 5);
        assert!(value["url"]
            .as_str()
            .is_some_and(|url| url.contains("[REDACTED:custom]")));
        assert!(value["findings"][0]["evidence"][0]["raw"]
            .as_str()
            .is_some_and(|raw| raw.contains("[REDACTED:custom]")));
        assert!(value["score_breakdown"]["factors"]
            .as_array()
            .is_some_and(|factors| factors.iter().any(|factor| factor["label"]
                .as_str()
                .is_some_and(|label| label.contains("[REDACTED:custom]")))));
    }
}
