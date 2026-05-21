use tirith_core::engine::{self, AnalysisContext};
use tirith_core::extract::ScanContext;
use tirith_core::output;
use tirith_core::scoring::{self, ScoreBreakdown};
use tirith_core::tokenize::ShellType;

/// Run `tirith score <url>`.
///
/// `explain` switches on the full deterministic factor breakdown — exactly how
/// the risk score was derived, factor by factor, so a user can reproduce the
/// number by hand.
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
    };

    let verdict = engine::analyze(&ctx);
    let breakdown = scoring::score_verdict(&verdict);
    // Defence in depth: the breakdown is the public contract that the factors
    // sum to the score. score_findings guarantees this; assert it in debug so a
    // future factor that breaks the invariant is caught immediately.
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
        /// Full factor breakdown — present only with `--explain`.
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

/// Render the factor breakdown so the reader can reproduce the score by hand:
/// each factor's contribution is printed, then the running total, then the
/// final score with an explicit "sum of the above" note.
fn print_breakdown_human(breakdown: &ScoreBreakdown) {
    eprintln!();
    eprintln!(
        "  score breakdown (each factor is fixed and inspectable — no model, no learned weights):"
    );
    let mut running: i32 = 0;
    for factor in &breakdown.factors {
        running += factor.points;
        // `+NN` for positive contributions, `-NN` for the clamp factor.
        let sign = if factor.points >= 0 { "+" } else { "" };
        eprintln!(
            "    {sign}{:<4} {}  (running total: {running})",
            factor.points, factor.label
        );
        eprintln!("           {}", factor.detail);
    }
    eprintln!(
        "    = {} / {}  ({}) — sum of every factor above",
        breakdown.score,
        scoring::MAX_SCORE,
        breakdown.risk_level
    );
}
