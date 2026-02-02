use tirith_core::engine::{self, AnalysisContext};
use tirith_core::extract::ScanContext;
use tirith_core::output;
use tirith_core::tokenize::ShellType;
use tirith_core::verdict::Severity;

pub fn run(url: &str, json: bool) -> i32 {
    let ctx = AnalysisContext {
        input: url.to_string(),
        shell: ShellType::Posix,
        scan_context: ScanContext::Exec,
        raw_bytes: None,
        interactive: true,
        cwd: std::env::current_dir()
            .ok()
            .map(|p| p.display().to_string()),
    };

    let verdict = engine::analyze(&ctx);

    if json {
        #[derive(serde::Serialize)]
        struct ScoreOutput<'a> {
            url: &'a str,
            score: u32,
            risk_level: &'a str,
            findings: &'a [tirith_core::verdict::Finding],
        }

        let max_severity = verdict
            .findings
            .iter()
            .map(|f| f.severity)
            .max()
            .unwrap_or(Severity::Low);

        let (score, level) = severity_to_score(max_severity, verdict.findings.len());

        let out = ScoreOutput {
            url,
            score,
            risk_level: level,
            findings: &verdict.findings,
        };
        let _ = serde_json::to_writer_pretty(std::io::stdout().lock(), &out);
        println!();
    } else if verdict.findings.is_empty() {
        eprintln!("tirith: {url} — no issues found (score: 0/100)");
    } else {
        let max_severity = verdict
            .findings
            .iter()
            .map(|f| f.severity)
            .max()
            .unwrap_or(Severity::Low);
        let (score, level) = severity_to_score(max_severity, verdict.findings.len());
        eprintln!("tirith: {url} — risk score: {score}/100 ({level})");
        let _ = output::write_human_auto(&verdict);
    }

    0
}

fn severity_to_score(max: Severity, count: usize) -> (u32, &'static str) {
    let base = match max {
        Severity::Critical => 90,
        Severity::High => 70,
        Severity::Medium => 40,
        Severity::Low => 15,
    };
    let bonus = (count.saturating_sub(1) as u32) * 5;
    let score = (base + bonus).min(100);
    let level = match score {
        0..=20 => "low",
        21..=50 => "medium",
        51..=75 => "high",
        _ => "critical",
    };
    (score, level)
}
