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

    let verdict = engine::analyze(&ctx);
    let breakdown = scoring::score_verdict(&verdict);
    // Defence in depth: assert the factors-sum-to-score invariant in debug.
    debug_assert!(
        breakdown.verify(),
        "score breakdown factors must sum to the final score"
    );

    if json {
        print_json(url, &verdict, &breakdown, explain);
    } else {
        print_human(url, &verdict, &breakdown, explain);
    }

    0
}

fn print_json(
    url: &str,
    verdict: &tirith_core::verdict::Verdict,
    breakdown: &ScoreBreakdown,
    explain: bool,
) {
    #[derive(serde::Serialize)]
    struct ScoreOutput<'a> {
        url: &'a str,
        score: u32,
        risk_level: &'a str,
        findings: &'a [tirith_core::verdict::Finding],
        /// Full factor breakdown — only with `--explain`.
        #[serde(skip_serializing_if = "Option::is_none")]
        score_breakdown: Option<&'a ScoreBreakdown>,
    }

    let out = ScoreOutput {
        url,
        score: breakdown.score,
        risk_level: breakdown.risk_level,
        findings: &verdict.findings,
        score_breakdown: if explain { Some(breakdown) } else { None },
    };
    if serde_json::to_writer_pretty(std::io::stdout().lock(), &out).is_err() {
        eprintln!("tirith: failed to write JSON output");
    }
    println!();
}

fn print_human(
    url: &str,
    verdict: &tirith_core::verdict::Verdict,
    breakdown: &ScoreBreakdown,
    explain: bool,
) {
    if verdict.findings.is_empty() {
        eprintln!("tirith: {url} — no issues found (score: 0/100)");
    } else {
        eprintln!(
            "tirith: {url} — risk score: {}/100 ({})",
            breakdown.score, breakdown.risk_level
        );
        if output::write_human_auto(verdict, false).is_err() {
            eprintln!("tirith: failed to write output");
        }
    }

    if explain {
        print_breakdown_human(breakdown);
    }
}

/// Render the factor breakdown to stderr so the reader can reproduce the score
/// by hand. Formatting lives in [`write_breakdown_human`] for testability.
fn print_breakdown_human(breakdown: &ScoreBreakdown) {
    let _ = write_breakdown_human(breakdown, &mut std::io::stderr().lock());
}

/// Write the factor breakdown to `w`. Separated from [`print_breakdown_human`]
/// so tests can capture the rendered text; output is identical.
fn write_breakdown_human(
    breakdown: &ScoreBreakdown,
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
            factor.points, factor.label
        )?;
        writeln!(w, "           {}", factor.detail)?;
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
    use tirith_core::verdict::{Evidence, Finding, RuleId, Severity};

    fn render(breakdown: &ScoreBreakdown) -> String {
        let mut buf: Vec<u8> = Vec::new();
        write_breakdown_human(breakdown, &mut buf).expect("write to Vec never fails");
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
}
