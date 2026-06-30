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
    /// Optional on-disk artifact path (relative to `assets/lab_artifacts/`) to
    /// inspect through the artifact pipeline instead of running `input` through
    /// `engine::analyze`. Reserved for prebuilt members; the current corpus drives
    /// the synthetic wheels via `binary_fixture` (G2).
    #[serde(default)]
    artifact_path: Option<String>,
    /// Optional named synthetic artifact fixture (a [`super::lab_artifacts`]
    /// token). When set, the scenario materializes inert wheel bytes and runs them
    /// through `inspect_artifact_set` + `all_findings` + `finalize_static_verdict`,
    /// comparing the resulting action to `expected_action` (G2).
    #[serde(default)]
    binary_fixture: Option<String>,
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

        // An artifact-fixture scenario (`binary_fixture`/`artifact_path`) runs the
        // synthetic wheel bytes through the artifact pipeline; everything else runs
        // `input` through the engine. A fixture that cannot be resolved/materialized
        // is a hard corpus/IO error (return 1), like the parse errors above.
        let verdict = match evaluate_scenario(scenario, &ctx) {
            Ok(v) => v,
            Err(e) => {
                eprintln!(
                    "tirith lab: scenario '{}' artifact fixture failed: {e}",
                    scenario.name
                );
                return 1;
            }
        };
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
                println!(
                    "    [{}] {} — {}",
                    f.severity,
                    f.rule_id,
                    super::sanitize_for_human_output(&f.title, false)
                );
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

/// Produce the verdict for one scenario. An artifact-fixture scenario
/// (`binary_fixture` or `artifact_path`) materializes inert wheel bytes and runs
/// them through the artifact pipeline; every other scenario runs `input` through
/// `engine::analyze`. Returns the on-disk/materialization error string on failure
/// so the caller can fail the corpus rather than silently pass.
fn evaluate_scenario(
    scenario: &LabScenario,
    ctx: &AnalysisContext,
) -> Result<tirith_core::verdict::Verdict, String> {
    match (&scenario.binary_fixture, &scenario.artifact_path) {
        (Some(_), Some(_)) => {
            Err("scenario sets both binary_fixture and artifact_path; use exactly one".to_string())
        }
        (Some(token), None) => {
            let fixture =
                super::lab_artifacts::ArtifactFixture::from_token(token).ok_or_else(|| {
                    let known: Vec<&str> = super::lab_artifacts::ArtifactFixture::all()
                        .iter()
                        .map(|f| f.as_str())
                        .collect();
                    format!(
                        "unknown binary_fixture '{token}' (known: {})",
                        known.join(", ")
                    )
                })?;
            // Materialize into a per-scenario temp dir, kept alive for the whole
            // inspection. Inspection re-reads the files from disk, so the guard must
            // outlive `inspect_artifact_paths`.
            let dir = tempfile::tempdir()
                .map_err(|e| format!("could not create temp dir for fixture: {e}"))?;
            let paths = fixture
                .materialize(dir.path())
                .map_err(|e| format!("could not materialize fixture '{token}': {e}"))?;
            Ok(inspect_artifact_paths(&paths))
        }
        (None, Some(rel)) => {
            // A prebuilt member under assets/lab_artifacts/, located relative to this
            // crate's manifest dir. Reject path escapes so a corpus typo cannot read
            // outside the fixtures tree.
            let path = resolve_artifact_asset(rel)?;
            Ok(inspect_artifact_paths(&[path]))
        }
        (None, None) => Ok(engine::analyze(ctx)),
    }
}

/// Inspect a set of on-disk artifact paths through the SAME seam the package
/// firewall uses (`inspect_artifact_set` -> `all_findings` -> the policy-aware
/// `finalize_static_verdict`), yielding one verdict. The lab is deterministic and
/// repo-independent, so it finalizes against a default policy and never reaches the
/// threat DB (`None`) — the synthetic fixtures must fire on their structural shape
/// alone, not on any local DB or override.
fn inspect_artifact_paths(paths: &[std::path::PathBuf]) -> tirith_core::verdict::Verdict {
    use tirith_core::artifact::inspect::inspect_artifact_set;
    use tirith_core::escalation::finalize_static_verdict;
    use tirith_core::policy::Policy;
    use tirith_core::verdict::Timings;

    let set = inspect_artifact_set(paths);
    let findings = set.all_findings(None);
    // Tier 3 by construction (no tier-1 command gate on this seam), mirroring
    // `crate::artifact::firewall::firewall_resolved_set`.
    finalize_static_verdict(findings, &Policy::default(), 3, Timings::default())
}

/// Resolve a corpus `artifact_path` (relative) into an absolute path under
/// `assets/lab_artifacts/`, rejecting any component that would escape the fixtures
/// directory (no `..`, no absolute path). A missing file is reported by the
/// inspection as a coverage gap, so we only guard traversal here.
fn resolve_artifact_asset(rel: &str) -> Result<std::path::PathBuf, String> {
    use std::path::{Component, Path, PathBuf};
    let rel_path = Path::new(rel);
    for comp in rel_path.components() {
        match comp {
            Component::Normal(_) | Component::CurDir => {}
            _ => {
                return Err(format!(
                    "artifact_path '{rel}' must be a relative path inside assets/lab_artifacts/ (no '..' or absolute components)"
                ))
            }
        }
    }
    let base = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("assets")
        .join("lab_artifacts");
    Ok(base.join(rel_path))
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

    // ---- G2 artifact-fixture scenarios ----------------------------------------
    // These run the synthetic wheels through the artifact pipeline; the engine-side
    // golden_fixtures safeguard skips them, so the equivalent coverage lives here
    // (this crate owns both the wheel builder and the artifact runner).

    use super::super::lab_artifacts::ArtifactFixture;

    /// Resolve `expected_action` to the same bucket the runner compares against
    /// (Warn/WarnAck collapse to "warn").
    fn corpus() -> LabCorpus {
        toml::from_str(LAB_CORPUS).expect("embedded lab corpus parses")
    }

    #[test]
    fn artifact_scenarios_reference_known_fixtures() {
        // Every binary_fixture token in the corpus must resolve to a real fixture,
        // and an artifact scenario must not also set artifact_path.
        let mut artifact_count = 0usize;
        for s in &corpus().scenarios {
            if let Some(tok) = &s.binary_fixture {
                artifact_count += 1;
                assert!(
                    ArtifactFixture::from_token(tok).is_some(),
                    "scenario '{}' references unknown binary_fixture '{}'",
                    s.name,
                    tok
                );
                assert!(
                    s.artifact_path.is_none(),
                    "scenario '{}' sets both binary_fixture and artifact_path",
                    s.name
                );
            }
        }
        assert!(
            artifact_count >= 6,
            "expected the G2 artifact scenarios in the corpus, found {artifact_count}"
        );
    }

    #[test]
    fn artifact_scenarios_produce_expected_action() {
        // Drive each artifact scenario through the real pipeline (materialize ->
        // inspect_artifact_set -> finalize_static_verdict) and assert the action
        // matches expected_action, bucketing Warn/WarnAck like the runner.
        let bucket = |a: Action| match a {
            Action::Warn | Action::WarnAck => "warn",
            Action::Allow => "allow",
            Action::Block => "block",
        };
        for s in &corpus().scenarios {
            let Some(tok) = &s.binary_fixture else {
                continue;
            };
            let fixture = ArtifactFixture::from_token(tok).unwrap();
            let dir = tempfile::tempdir().unwrap();
            let paths = fixture.materialize(dir.path()).unwrap();
            let verdict = inspect_artifact_paths(&paths);
            assert_eq!(
                bucket(verdict.action),
                s.expected_action.as_str(),
                "scenario '{}' ({}): expected {} but pipeline returned {:?} ({} findings: {:?})",
                s.name,
                tok,
                s.expected_action,
                verdict.action,
                verdict.findings.len(),
                verdict
                    .findings
                    .iter()
                    .map(|f| f.rule_id)
                    .collect::<Vec<_>>(),
            );
            // A non-allow artifact scenario must reach tier-3 with a finding, the
            // same coverage invariant the engine-side safeguard enforces.
            if s.expected_action != "allow" {
                assert!(
                    verdict.tier_reached >= 3,
                    "scenario '{}': artifact verdict must be tier-3",
                    s.name
                );
                assert!(
                    !verdict.findings.is_empty(),
                    "scenario '{}': a blocking artifact scenario must carry a finding",
                    s.name
                );
            }
        }
    }

    #[test]
    fn artifact_path_rejects_traversal() {
        // A corpus artifact_path must stay inside assets/lab_artifacts/.
        assert!(resolve_artifact_asset("../../etc/passwd").is_err());
        assert!(resolve_artifact_asset("/etc/passwd").is_err());
        // A plain relative member resolves under the fixtures dir.
        let p = resolve_artifact_asset("pth_cross_runtime.pth").unwrap();
        assert!(p.ends_with("assets/lab_artifacts/pth_cross_runtime.pth"));
    }

    #[test]
    fn evaluate_scenario_rejects_both_fixture_fields() {
        let mut s = corpus()
            .scenarios
            .into_iter()
            .find(|s| s.binary_fixture.is_some())
            .expect("an artifact scenario exists");
        s.artifact_path = Some("pth_cross_runtime.pth".to_string());
        let ctx = AnalysisContext {
            input: s.input.clone(),
            shell: ShellType::Posix,
            scan_context: ScanContext::Exec,
            raw_bytes: None,
            interactive: false,
            cwd: None,
            file_path: None,
            repo_root: None,
            is_config_override: false,
            clipboard_html: None,
            card_ref: None,
            clipboard_source: tirith_core::clipboard::ClipboardSourceState::AbsentOrInvalid,
        };
        assert!(evaluate_scenario(&s, &ctx).is_err());
    }
}
