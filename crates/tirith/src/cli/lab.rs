//! `tirith lab` — adversarial training mode (experimental).
//!
//! Runs the curated corpus at `tests/fixtures/lab_corpus.toml` through
//! `tirith_core::engine::analyze`, comparing each scenario's actual verdict
//! against its declared `expected_action`. Three modes:
//!
//! * **interactive** (default when stdout is a TTY): for each scenario, show
//!   the description and input, prompt for Enter, then print the verdict and
//!   whether it matches the expectation.
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
use tirith_core::verdict::{Action, Finding};

/// Embedded corpus. Path is 4 levels up from this file:
///   crates/tirith/src/cli/lab.rs
///     -> crates/tirith/src/cli/
///     -> crates/tirith/src/
///     -> crates/tirith/
///     -> crates/
///     -> <workspace root>/tests/fixtures/lab_corpus.toml
const LAB_CORPUS: &str = include_str!("../../../../tests/fixtures/lab_corpus.toml");

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
    findings: Vec<FindingSummary>,
}

#[derive(Debug, serde::Serialize)]
struct FindingSummary {
    rule_id: String,
    severity: String,
    title: String,
}

/// Public entry point for the `tirith lab` subcommand.
///
/// Returns the process exit code: `0` on all-pass (or filter-empty), `1` on
/// any failure (parse error, unparseable scenario, or expected_action
/// mismatch).
pub fn run(interactive: bool, filter: Option<&str>, json: bool) -> i32 {
    let corpus: LabCorpus = match toml::from_str(LAB_CORPUS) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("tirith lab: failed to parse embedded corpus: {e}");
            return 1;
        }
    };

    // Apply filter (substring-of-any-tag isn't what the spec asks for —
    // exact tag match is documented behavior and matches the corpus's tag
    // taxonomy).
    let filtered: Vec<&LabScenario> = if let Some(tag) = filter {
        corpus
            .scenarios
            .iter()
            .filter(|s| s.tags.iter().any(|t| t == tag))
            .collect()
    } else {
        corpus.scenarios.iter().collect()
    };

    if filtered.is_empty() {
        if let Some(tag) = filter {
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

        // Build the analysis context, skipping any scenario whose context
        // string is unparseable so a typo in the corpus doesn't take down
        // the whole run silently.
        let scan_context = match scenario.context.as_str() {
            "exec" => ScanContext::Exec,
            "paste" => ScanContext::Paste,
            other => {
                eprintln!(
                    "tirith lab: scenario '{}' has unknown context '{}', skipping",
                    scenario.name, other
                );
                continue;
            }
        };

        let shell = match scenario.shell.as_str() {
            "posix" => ShellType::Posix,
            "powershell" => ShellType::PowerShell,
            other => {
                eprintln!(
                    "tirith lab: scenario '{}' has unknown shell '{}', defaulting to posix",
                    scenario.name, other
                );
                ShellType::Posix
            }
        };

        let raw_bytes: Option<Vec<u8>> = if !scenario.raw_bytes.is_empty() {
            Some(scenario.raw_bytes.clone())
        } else if scan_context == ScanContext::Paste {
            Some(scenario.input.as_bytes().to_vec())
        } else {
            None
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
                    eprintln!("tirith lab: stdin read failed: {e}");
                    quit_early = true;
                    continue;
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

        results.push(ScenarioResult {
            name: scenario.name.as_str(),
            expected,
            actual,
            pass,
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
        print_summary_table(&results, passed, failed);
    } else {
        // Interactive: print a trailing summary line.
        println!();
        println!("Summary: {passed} passed, {failed} failed");
    }

    if failed > 0 {
        1
    } else {
        0
    }
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
        rule_id: f.rule_id.to_string(),
        severity: f.severity.to_string(),
        title: f.title.clone(),
    }
}

fn print_summary_table(results: &[ScenarioResult], passed: usize, failed: usize) {
    // Column widths chosen for the canonical 10-scenario corpus; long
    // names just push the rest right rather than getting truncated.
    let name_width = results
        .iter()
        .map(|r| r.name.len())
        .max()
        .unwrap_or(4)
        .max(4);

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
    println!();
    println!("Total: {passed} passed, {failed} failed");
}
