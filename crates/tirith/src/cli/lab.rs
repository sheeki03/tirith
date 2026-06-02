//! `tirith lab` — adversarial training mode (experimental).
//!
//! Runs the curated `lab_corpus.toml` through `engine::analyze`, comparing each
//! scenario's verdict against its `expected_action`. Three modes: interactive
//! (default on a TTY — prompt before each verdict), non-interactive
//! (`--non-interactive`, summary table), and JSON (`--format json`, implies
//! non-interactive).
//!
//! The corpus is embedded via `include_str!` (deterministic, no network). The
//! same TOML drives the `test_lab_corpus_reaches_tier3` safeguard in
//! `golden_fixtures.rs`, which enforces that every non-allow scenario produces a
//! finding so corpus expansion can't silently lose coverage.

use std::io::{self, BufRead, Write};

use serde::Deserialize;
use tirith_core::engine::{self, AnalysisContext};
use tirith_core::extract::ScanContext;
use tirith_core::tokenize::ShellType;
use tirith_core::verdict::{Action, Finding, RuleId, Severity};

/// Embedded corpus. Lives inside the `tirith` crate so `cargo package` can see
/// it (an `include_str!` path reaching outside the manifest dir would make the
/// crate unpackageable).
const LAB_CORPUS: &str = include_str!("../../assets/lab_corpus.toml");

#[derive(Debug, Deserialize)]
struct LabCorpus {
    #[serde(rename = "scenario")]
    scenarios: Vec<LabScenario>,
}

#[derive(Debug, Deserialize)]
struct LabScenario {
    name: String,
    description: String,
    input: String,
    context: String,
    #[serde(default = "default_posix")]
    shell: String,
    expected_action: String,
    #[serde(default)]
    tags: Vec<String>,
    #[serde(default)]
    raw_bytes: Vec<u8>,
}

fn default_posix() -> String {
    "posix".to_string()
}

/// JSON-serializable per-scenario result. Stable so CI / dashboards can consume
/// `tirith lab --format json`.
#[derive(Debug, serde::Serialize)]
struct ScenarioResult<'a> {
    name: &'a str,
    expected: &'a str,
    actual: &'a str,
    pass: bool,
    /// Deterministic 0-100 risk score (max finding severity). Only populated when
    /// `--score` is on, so legacy consumers see no schema drift.
    #[serde(skip_serializing_if = "Option::is_none")]
    score: Option<u8>,
    findings: Vec<FindingSummary>,
}

/// Deterministic 0-100 risk score from the max finding severity (Critical 100,
/// High 75, Medium 50, Low 25, Info 5; empty → 0). A single `.max()`, no ML.
fn scenario_score(findings: &[Finding]) -> u8 {
    findings
        .iter()
        .map(|f| match f.severity {
            Severity::Critical => 100,
            Severity::High => 75,
            Severity::Medium => 50,
            Severity::Low => 25,
            Severity::Info => 5,
        })
        .max()
        .unwrap_or(0)
}

/// One serialised finding row for `tirith lab --format json` / `--score`. Holds
/// the typed `RuleId`/`Severity` enums; JSON output is byte-identical to the old
/// `to_string()` form via their serde rename attrs.
#[derive(Debug, serde::Serialize)]
struct FindingSummary {
    rule_id: RuleId,
    severity: Severity,
    title: String,
}

/// Validate an `expected_action` corpus string into a typed [`Action`].
///
/// Restricted to the three observable actions (`allow`/`warn`/`block`).
/// `warn_ack` is rejected: `action_to_str` collapses `WarnAck → "warn"`, so
/// accepting it would parse a scenario that then never matches any verdict —
/// silently always-FAILing (Greptile P1 on the M5 wave-end review).
fn parse_expected_action(s: &str) -> Result<Action, String> {
    match s {
        "allow" | "warn" | "block" => s.parse::<Action>(),
        other => Err(format!(
            "unknown expected_action '{other}' (must be one of: allow, warn, block)"
        )),
    }
}

/// Entry point for `tirith lab`. Exit code: `0` all matched (or empty filter);
/// `1` corpus/parse error or a verdict mismatch; `2` interactive stdin read
/// failed mid-loop (distinct so callers can tell a TTY break from a corpus
/// failure). `score`: add a deterministic 0-100 risk score (see
/// [`scenario_score`]) per entry / a `Score` column.
pub fn run(interactive: bool, filter: Option<&str>, json: bool, score: bool) -> i32 {
    let corpus: LabCorpus = match toml::from_str(LAB_CORPUS) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("tirith lab: failed to parse embedded corpus: {e}");
            return 1;
        }
    };

    // Filter by exact tag match (documented behavior). `is_none_or` folds the
    // "no filter → keep" branch into the same `.filter`.
    let filtered: Vec<&LabScenario> = corpus
        .scenarios
        .iter()
        .filter(|s| filter.is_none_or(|tag| s.tags.iter().any(|t| t == tag)))
        .collect();

    if filtered.is_empty() {
        if json {
            // Emit an empty array for unambiguous parsing; still exit 0 (a no-op).
            println!("[]");
        } else if let Some(tag) = filter {
            println!("No scenarios match filter '{tag}'");
        } else {
            println!("Lab corpus is empty");
        }
        return 0;
    }

    let mut results: Vec<ScenarioResult> = Vec::with_capacity(filtered.len());
    let mut passed = 0usize;
    let mut failed = 0usize;

    let stdin = io::stdin();
    let mut stdin_lock = stdin.lock();
    let mut line_buf = String::new();
    let mut quit_early = false;

    for scenario in &filtered {
        if quit_early {
            break;
        }

        // An unknown context string is a hard failure (silently skipping would
        // mask a regression and still exit 0). Shared `FromStr` impls so this CLI
        // and the `test_lab_corpus_reaches_tier3` safeguard parse from one place.
        let scan_context = match scenario.context.parse::<ScanContext>() {
            Ok(c) => c,
            Err(_) => {
                eprintln!(
                    "tirith lab: scenario '{}' has unknown context '{}' — corpus error",
                    scenario.name, scenario.context
                );
                return 1;
            }
        };

        let shell = match scenario.shell.parse::<ShellType>() {
            Ok(s) => s,
            Err(_) => {
                // Hard-fail rather than coerce: a typo like `shell = "powershel"`
                // would silently route a PS scenario through POSIX tokenization.
                eprintln!(
                    "tirith lab: scenario '{}' has unknown shell '{}' — corpus error",
                    scenario.name, scenario.shell
                );
                return 1;
            }
        };

        // Validate `expected_action` up front (C2): a typo like `"blocK"` used to
        // silently always-FAIL; now fail-fast like the shell/context errors above.
        if parse_expected_action(&scenario.expected_action).is_err() {
            eprintln!(
                "tirith lab: scenario '{}' has unknown expected_action '{}' — corpus error",
                scenario.name, scenario.expected_action
            );
            return 1;
        }

        let raw_bytes: Option<Vec<u8>> = match (scenario.raw_bytes.as_slice(), scan_context) {
            ([], ScanContext::Paste) => Some(scenario.input.as_bytes().to_vec()),
            ([], _) => None,
            (bytes, _) => Some(bytes.to_vec()),
        };

        let ctx = AnalysisContext {
            input: scenario.input.clone(),
            shell,
            scan_context,
            raw_bytes,
            interactive: true,
            cwd: None,
            file_path: None,
            repo_root: None,
            is_config_override: false,
            clipboard_html: None,
            card_ref: None,
            // AbsentOrInvalid, not Unread (CodeRabbit R6): `tirith lab` is
            // deterministic, so it must skip the ambient `clipboard_source.json`
            // disk read.
            clipboard_source: tirith_core::clipboard::ClipboardSourceState::AbsentOrInvalid,
        };

        // Interactive prelude — prompt before revealing the verdict; `q` aborts.
        if interactive {
            println!();
            println!("── {} ──", scenario.name);
            println!("  {}", scenario.description);
            println!("  input: {}", scenario.input);
            print!("Press Enter for verdict (q to quit): ");
            let _ = io::stdout().flush();
            line_buf.clear();
            match stdin_lock.read_line(&mut line_buf) {
                Ok(0) => {
                    quit_early = true; // EOF — stop cleanly
                    continue;
                }
                Ok(_) => {
                    if line_buf.trim().eq_ignore_ascii_case("q") {
                        quit_early = true;
                        continue;
                    }
                }
                Err(e) => {
                    eprintln!(
                        "tirith lab: stdin read failed at scenario '{}': {e} — aborting",
                        scenario.name
                    );
                    return 2;
                }
            }
        }

        let verdict = engine::analyze(&ctx);
        let actual = action_to_str(verdict.action);
        let expected = scenario.expected_action.as_str();
        let pass = actual == expected;
        if pass {
            passed += 1;
        } else {
            failed += 1;
        }

        if interactive {
            println!(
                "  verdict: {} (expected {}) — {}",
                actual,
                expected,
                if pass { "PASS" } else { "FAIL" }
            );
            for f in &verdict.findings {
                println!("    [{}] {} — {}", f.severity, f.rule_id, f.title);
            }
        }

        let scenario_score_value = if score {
            Some(scenario_score(&verdict.findings))
        } else {
            None
        };
        results.push(ScenarioResult {
            name: scenario.name.as_str(),
            expected,
            actual,
            pass,
            score: scenario_score_value,
            findings: verdict.findings.iter().map(summarize_finding).collect(),
        });
    }

    // Output dispatch: JSON wins; non-interactive prints a table; interactive
    // already printed per-scenario.
    if json {
        let stdout = io::stdout();
        let mut out = stdout.lock();
        if serde_json::to_writer_pretty(&mut out, &results).is_err() || writeln!(out).is_err() {
            eprintln!("tirith lab: failed to write JSON output");
            return 1;
        }
    } else if !interactive {
        print_summary_table(&results, passed, failed, score);
    } else {
        // Interactive: print a trailing summary line.
        println!();
        println!("Summary: {passed} passed, {failed} failed");
    }

    i32::from(failed > 0)
}

fn action_to_str(action: Action) -> &'static str {
    match action {
        Action::Allow => "allow",
        Action::Warn | Action::WarnAck => "warn",
        Action::Block => "block",
    }
}

fn summarize_finding(f: &Finding) -> FindingSummary {
    FindingSummary {
        rule_id: f.rule_id,
        severity: f.severity,
        title: f.title.clone(),
    }
}

fn print_summary_table(results: &[ScenarioResult], passed: usize, failed: usize, score: bool) {
    // Width from the longest scenario name; never truncated.
    let name_width = results
        .iter()
        .map(|r| r.name.len())
        .max()
        .unwrap_or(4)
        .max(4);

    if score {
        println!(
            "{:<name_width$}  {:<8}  {:<8}  {:<5}  result",
            "name", "expected", "actual", "score"
        );
        println!(
            "{:-<name_width$}  {:-<8}  {:-<8}  {:-<5}  {:-<6}",
            "", "", "", "", "",
        );
        for r in results {
            // `score` is Some(_) whenever `--score` was passed; if a refactor
            // leaves it unpopulated, print 0 but warn to stderr so the gap is
            // auditable instead of looking like a legitimate allow=0.
            let score_str = match r.score {
                Some(s) => s.to_string(),
                None => {
                    eprintln!(
                        "tirith lab: internal — score expected but missing for scenario '{}'; printing 0",
                        r.name
                    );
                    "0".to_string()
                }
            };
            println!(
                "{:<name_width$}  {:<8}  {:<8}  {:<5}  {}",
                r.name,
                r.expected,
                r.actual,
                score_str,
                if r.pass { "PASS" } else { "FAIL" },
                name_width = name_width
            );
        }
    } else {
        println!(
            "{:<name_width$}  {:<8}  {:<8}  result",
            "name", "expected", "actual"
        );
        println!("{:-<name_width$}  {:-<8}  {:-<8}  {:-<6}", "", "", "", "",);
        for r in results {
            println!(
                "{:<name_width$}  {:<8}  {:<8}  {}",
                r.name,
                r.expected,
                r.actual,
                if r.pass { "PASS" } else { "FAIL" },
                name_width = name_width
            );
        }
    }
    println!();
    println!("Total: {passed} passed, {failed} failed");
}

#[cfg(test)]
mod tests {
    use super::*;
    use tirith_core::verdict::{Finding, RuleId, Severity};

    fn finding(severity: Severity) -> Finding {
        Finding {
            rule_id: RuleId::Base64DecodeExecute,
            severity,
            title: String::new(),
            description: String::new(),
            evidence: vec![],
            human_view: None,
            agent_view: None,
            mitre_id: None,
            custom_rule_id: None,
        }
    }

    #[test]
    fn scenario_score_empty_is_zero() {
        assert_eq!(scenario_score(&[]), 0);
    }

    #[test]
    fn scenario_score_max_wins() {
        let f = vec![
            finding(Severity::Low),
            finding(Severity::Critical),
            finding(Severity::Medium),
        ];
        assert_eq!(scenario_score(&f), 100);
    }

    #[test]
    fn scenario_score_info_is_5_not_0() {
        assert_eq!(scenario_score(&[finding(Severity::Info)]), 5);
    }

    #[test]
    fn scenario_score_buckets_are_exact() {
        assert_eq!(scenario_score(&[finding(Severity::Critical)]), 100u8);
        assert_eq!(scenario_score(&[finding(Severity::High)]), 75u8);
        assert_eq!(scenario_score(&[finding(Severity::Medium)]), 50u8);
        assert_eq!(scenario_score(&[finding(Severity::Low)]), 25u8);
        assert_eq!(scenario_score(&[finding(Severity::Info)]), 5u8);
    }

    // `parse_expected_action` is the C2 fail-fast fix: a corpus typo used to
    // silently always-FAIL. Pin both happy and sad paths so loosening trips CI.
    #[test]
    fn parse_expected_action_accepts_known_tokens() {
        assert_eq!(parse_expected_action("allow"), Ok(Action::Allow));
        assert_eq!(parse_expected_action("warn"), Ok(Action::Warn));
        assert_eq!(parse_expected_action("block"), Ok(Action::Block));
    }

    #[test]
    fn parse_expected_action_rejects_typos() {
        // Strict-case on purpose, so even a single-letter slip ("blocK", "Allow")
        // surfaces as a corpus error instead of silently always-FAILing.
        assert!(parse_expected_action("blocK").is_err());
        assert!(parse_expected_action("Allow").is_err());
        assert!(parse_expected_action("allwo").is_err());
        assert!(parse_expected_action("").is_err());
        assert!(parse_expected_action("warning").is_err());
        assert!(parse_expected_action("deny").is_err());
        // warn_ack collapses to "warn" in action_to_str, so accepting it would
        // silently always-FAIL (Greptile P1, M5 wave-end review).
        assert!(parse_expected_action("warn_ack").is_err());
    }
}
