//! `tirith lab` — adversarial training mode (experimental).
//!
//! Runs the curated corpus at `crates/tirith/assets/lab_corpus.toml` through
//! `tirith_core::engine::analyze`, comparing each scenario's actual verdict
//! against its declared `expected_action`. Three modes:
//!
//! * **interactive** (default when both stdout and stdin are TTYs): for each
//!   scenario, show the description and input, prompt for Enter, then print
//!   the verdict and whether it matches the expectation.
//! * **non-interactive** (`--non-interactive`): run all scenarios silently
//!   and print a summary table.
//! * **JSON** (`--format json`): emit a single JSON array of result objects
//!   (always implies non-interactive).
//!
//! The corpus is embedded via `include_str!` at compile time — no runtime
//! file lookup, no network, deterministic. The same TOML is consumed by the
//! `test_lab_corpus_reaches_tier3` safeguard in
//! `crates/tirith-core/tests/golden_fixtures.rs`, which enforces that every
//! non-allow scenario produces at least one finding so corpus expansion can't
//! silently lose detection coverage.

use std::io::{self, BufRead, Write};

use serde::Deserialize;
use tirith_core::engine::{self, AnalysisContext};
use tirith_core::extract::ScanContext;
use tirith_core::tokenize::ShellType;
use tirith_core::verdict::{Action, Finding, RuleId, Severity};

/// Embedded corpus. Lives inside the `tirith` crate so `cargo package` can
/// see it (`include_str!` paths that reach outside the manifest directory
/// make the crate unpackageable). Path is 3 levels up from this file:
///   crates/tirith/src/cli/lab.rs
///     -> crates/tirith/src/cli/
///     -> crates/tirith/src/
///     -> crates/tirith/
///     -> crates/tirith/assets/lab_corpus.toml
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

/// JSON-serializable per-scenario result. Kept stable so downstream tooling
/// (CI, dashboards) can consume `tirith lab --format json` without a parser
/// dance.
#[derive(Debug, serde::Serialize)]
struct ScenarioResult<'a> {
    name: &'a str,
    expected: &'a str,
    actual: &'a str,
    pass: bool,
    /// Deterministic risk score 0-100, derived from the max finding severity.
    /// Only populated when `--score` is on so legacy consumers see no schema
    /// drift.
    #[serde(skip_serializing_if = "Option::is_none")]
    score: Option<u8>,
    findings: Vec<FindingSummary>,
}

/// Compute the deterministic risk score 0-100 from a scenario's findings.
///
/// The score is the max severity mapped to a fixed bucket:
///   Critical = 100, High = 75, Medium = 50, Low = 25, Info = 5.
///
/// Empty findings → 0 (allow). The function is intentionally cheap and
/// explainable — no ML, no network, the score is a single `.max()` over the
/// finding list. `u8` is the tightest fit for a 0-100 value with six discrete
/// buckets — no caller has ever needed >255.
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

/// One serialised finding row for `tirith lab --format json` / `--score`.
///
/// `rule_id` and `severity` hold the typed `RuleId` / `Severity` enums rather
/// than free `String`s. JSON output is byte-identical: `RuleId` carries
/// `#[serde(rename_all = "snake_case")]` and `Severity` carries
/// `#[serde(rename_all = "UPPERCASE")]`, which is exactly what the previous
/// `to_string()` calls emitted.
#[derive(Debug, serde::Serialize)]
struct FindingSummary {
    rule_id: RuleId,
    severity: Severity,
    title: String,
}

/// Validate an `expected_action` corpus string and return the typed [`Action`].
///
/// The lab corpus is intentionally restricted to the three observable verdict
/// actions: "allow", "warn", "block". `Action::from_str` also accepts
/// "warn_ack" (a strict-warn variant), but `action_to_str` collapses
/// `Action::WarnAck → "warn"` for comparison — so accepting `warn_ack` here
/// would let a scenario parse as `Action::WarnAck` and then never match any
/// produced verdict, silently always-FAILing. Reject `warn_ack` explicitly to
/// make the contract honest. (Greptile P1 on the M5 wave-end review.)
///
/// Future expansion that wants to distinguish strict-warn-ack at the corpus
/// level should also remove the `WarnAck → "warn"` collapse in `action_to_str`,
/// not just relax this parser.
fn parse_expected_action(s: &str) -> Result<Action, String> {
    match s {
        "allow" | "warn" | "block" => s.parse::<Action>(),
        other => Err(format!(
            "unknown expected_action '{other}' (must be one of: allow, warn, block)"
        )),
    }
}

/// Public entry point for the `tirith lab` subcommand.
///
/// Returns the process exit code:
///   - `0` — every scenario matched its `expected_action` (or filter is empty).
///   - `1` — corpus parse error, unknown context/shell/expected_action in a
///     scenario, or at least one scenario's verdict did not match.
///   - `2` — interactive stdin read failed mid-loop (distinct from "scenario
///     mismatch" so callers can tell a TTY break from a corpus failure).
///
/// `score`: when true, each `ScenarioResult` gets a deterministic 0-100
/// risk score (see [`scenario_score`]) and the human summary table grows
/// a `Score` column. JSON gains a `score` field per entry (omitted
/// otherwise via `skip_serializing_if`).
pub fn run(interactive: bool, filter: Option<&str>, json: bool, score: bool) -> i32 {
    let corpus: LabCorpus = match toml::from_str(LAB_CORPUS) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("tirith lab: failed to parse embedded corpus: {e}");
            return 1;
        }
    };

    // Apply filter (substring-of-any-tag isn't what the spec asks for —
    // exact tag match is documented behavior and matches the corpus's tag
    // taxonomy). `is_none_or` collapses the "no filter → keep" branch into
    // the same `.filter` call.
    let filtered: Vec<&LabScenario> = corpus
        .scenarios
        .iter()
        .filter(|s| filter.is_none_or(|tag| s.tags.iter().any(|t| t == tag)))
        .collect();

    if filtered.is_empty() {
        if json {
            // In JSON mode, emit an empty array so consumers can parse
            // unambiguously. The empty-corpus / empty-filter case is still
            // exit 0 — it's not a failure, just a no-op.
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

        // Build the analysis context. An unknown context string in the
        // corpus is a hard failure — silently skipping would let a typo
        // mask a real corpus regression and still return exit 0. Use the
        // shared `FromStr` impls in tirith-core so this CLI and the
        // `test_lab_corpus_reaches_tier3` safeguard parse from one place.
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
                // Mirror the unknown-context handling: hard-fail rather than
                // coerce. A typo like `shell = "powershel"` (missing l) would
                // silently route a PS scenario through POSIX tokenization and
                // mask a real corpus regression.
                eprintln!(
                    "tirith lab: scenario '{}' has unknown shell '{}' — corpus error",
                    scenario.name, scenario.shell
                );
                return 1;
            }
        };

        // Validate `expected_action` up front (closes type-design C2). A
        // corpus typo like `expected_action = "blocK"` previously slipped
        // through and silently always-FAILed every scenario; now we fail-fast
        // here with the same shape as the shell/context errors above.
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
            clipboard_source: None,
        };

        // Interactive prelude — show description, prompt before revealing
        // verdict.  A `q` input aborts the loop (exit code reflects what
        // ran).
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
                    // EOF — stop cleanly
                    quit_early = true;
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

    // Output mode dispatch.  JSON wins; otherwise non-interactive prints a
    // summary table; interactive already printed per-scenario.
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
    // Column widths derived from the longest scenario name; never truncated.
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
            // `score` field is Some(_) whenever the caller passed --score; if
            // a future refactor leaves it unpopulated we still print 0, but we
            // surface a contract-violation warning to stderr so the discrepancy
            // is auditable instead of silently looking like a legitimate
            // allow=0.
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

    // `parse_expected_action` is the type-design C2 fix for the CLI side:
    // a corpus typo in `expected_action` previously silently always-FAILed
    // every scenario; now we fail-fast inside `run`. Pin both happy and
    // sad paths so a future refactor that loosens validation trips CI.
    #[test]
    fn parse_expected_action_accepts_known_tokens() {
        // The three tokens the corpus actually uses today.
        assert_eq!(parse_expected_action("allow"), Ok(Action::Allow));
        assert_eq!(parse_expected_action("warn"), Ok(Action::Warn));
        assert_eq!(parse_expected_action("block"), Ok(Action::Block));
    }

    #[test]
    fn parse_expected_action_rejects_typos() {
        // The exact regression class the CLI fail-fast guards against: a
        // typo that previously slipped past the `actual == expected` string
        // comparison and silently always-FAILed the scenario. We are
        // deliberately strict-case so even a single-letter case slip
        // ("blocK", "Allow") surfaces as a corpus error.
        assert!(parse_expected_action("blocK").is_err());
        assert!(parse_expected_action("Allow").is_err());
        assert!(parse_expected_action("allwo").is_err());
        assert!(parse_expected_action("").is_err());
        assert!(parse_expected_action("warning").is_err());
        assert!(parse_expected_action("deny").is_err());
        // warn_ack would parse as Action::WarnAck but action_to_str collapses
        // WarnAck → "warn", so accepting it here would silently always-FAIL.
        // Greptile P1 on the M5 wave-end review.
        assert!(parse_expected_action("warn_ack").is_err());
    }
}
