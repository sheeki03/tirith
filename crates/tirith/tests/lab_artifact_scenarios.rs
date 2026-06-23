//! End-to-end coverage for the lab corpus artifact-fixture (G2) block scenarios.
//!
//! `lab_corpus.toml` defines several scenarios whose verdict comes from the
//! ARTIFACT pipeline (`binary_fixture` -> synthetic inert wheel bytes ->
//! `inspect_artifact_set`), not from `engine::analyze`. The engine-side
//! `test_lab_corpus_reaches_tier3` safeguard in `golden_fixtures.rs` therefore
//! SKIPS them (see its comment at the `is_artifact_fixture` continue, and the
//! corpus header at `assets/lab_corpus.toml`), deferring their coverage to "the
//! `tirith` crate's `lab_artifact_scenarios` integration test" — this file.
//!
//! The `tirith` binary is a bin-only crate (no `lib.rs`), so an integration test
//! cannot reach `cli::lab_artifacts::ArtifactFixture` directly. Instead we drive
//! the REAL binary end to end via `tirith lab --format json`, which materializes
//! the synthetic wheels, runs them through the same
//! `inspect_artifact_set` -> `all_findings` -> `finalize_static_verdict` seam the
//! package firewall uses, and emits each scenario's action + the RuleIds that
//! fired. We assert the named `.pth` block scenarios actually BLOCK with the
//! expected rule, so a regression that quietly stops a startup-hook wheel from
//! tripping its rule fails CI here even though the engine-side safeguard cannot
//! see it.
//!
//! Every fixture is synthetic and inert: the wheels are built at lab time from
//! reviewable `.pth` bodies under `assets/lab_artifacts/`, and every
//! network-shaped string targets the reserved `example.invalid` domain (RFC
//! 6761). Nothing here is real malware.

use std::process::Command;

fn tirith() -> Command {
    Command::new(env!("CARGO_BIN_EXE_tirith"))
}

/// Run `tirith lab --format json --filter artifact --non-interactive` and return
/// the parsed top-level array of scenario results. Filtering to the `artifact`
/// tag keeps this test scoped to the G2 fixtures (the same tag every artifact
/// scenario in the corpus carries) and independent of the rest of the corpus.
fn run_lab_artifact_json() -> Vec<serde_json::Value> {
    let out = tirith()
        .args([
            "lab",
            "--format",
            "json",
            "--filter",
            "artifact",
            "--non-interactive",
        ])
        .output()
        .expect("failed to run tirith lab");
    assert_eq!(
        out.status.code(),
        Some(0),
        "lab --filter artifact should exit 0 on all-pass; stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let json: serde_json::Value =
        serde_json::from_slice(&out.stdout).expect("lab --format json must emit valid JSON");
    json.as_array()
        .expect("lab JSON output must be a top-level array")
        .clone()
}

/// Find the scenario entry by its corpus `name`.
fn scenario<'a>(entries: &'a [serde_json::Value], name: &str) -> &'a serde_json::Value {
    entries
        .iter()
        .find(|e| e["name"] == name)
        .unwrap_or_else(|| panic!("lab corpus is missing the '{name}' artifact scenario"))
}

/// The set of `rule_id` strings that fired for a scenario entry.
fn fired_rules(entry: &serde_json::Value) -> Vec<String> {
    entry["findings"]
        .as_array()
        .expect("findings must be an array")
        .iter()
        .map(|f| {
            f["rule_id"]
                .as_str()
                .expect("rule_id must be a string")
                .to_string()
        })
        .collect()
}

/// Assert one artifact scenario blocked end to end and fired the expected rule.
fn assert_blocks_with_rule(name: &str, expected_rule: &str) {
    let entries = run_lab_artifact_json();
    let entry = scenario(&entries, name);
    assert_eq!(
        entry["expected"], "block",
        "corpus '{name}' must declare expected_action = block"
    );
    assert_eq!(
        entry["actual"], "block",
        "artifact scenario '{name}' must BLOCK end to end through the real binary; entry: {entry}"
    );
    assert_eq!(
        entry["pass"], true,
        "artifact scenario '{name}' must pass (actual == expected): {entry}"
    );
    let rules = fired_rules(entry);
    assert!(
        rules.iter().any(|r| r == expected_rule),
        "artifact scenario '{name}' must fire '{expected_rule}'; fired {rules:?}"
    );
    assert!(
        !rules.is_empty(),
        "a blocking artifact scenario '{name}' must carry at least one finding"
    );
}

/// `artifact_pth_cross_runtime_wheel`: a wheel whose `.pth` import line launches a
/// cross-runtime (node) payload via `os.system`. The cross-runtime launch makes
/// this a Critical `python_startup_hook_cross_runtime` block. (Corpus
/// `binary_fixture = pth_cross_runtime_wheel`, expected_action = block.)
#[test]
fn lab_pth_cross_runtime_wheel_blocks_cross_runtime() {
    assert_blocks_with_rule(
        "artifact_pth_cross_runtime_wheel",
        "python_startup_hook_cross_runtime",
    );
}

/// `artifact_pth_subprocess_wheel`: a wheel whose `.pth` import line spawns a
/// subprocess that reaches a URL. No foreign runtime is launched, so this is the
/// High `python_startup_hook_suspicious` block. (Corpus
/// `binary_fixture = pth_subprocess_wheel`, expected_action = block.)
#[test]
fn lab_pth_subprocess_wheel_blocks_suspicious() {
    assert_blocks_with_rule(
        "artifact_pth_subprocess_wheel",
        "python_startup_hook_suspicious",
    );
}

/// `artifact_cross_distribution_split`: a loader wheel whose `.pth` searches
/// `sys.path` and launches a payload member OWNED by a separate payload wheel.
/// The set inspection resolves the reference across distributions and, because
/// the loader also launches `node`, blocks Critical with
/// `python_startup_hook_cross_runtime`. (Corpus
/// `binary_fixture = cross_distribution_split`, expected_action = block.)
#[test]
fn lab_cross_distribution_split_blocks() {
    assert_blocks_with_rule(
        "artifact_cross_distribution_split",
        "python_startup_hook_cross_runtime",
    );
}

/// The native `.so` execution-chain wheel is also an artifact-pipeline scenario.
/// Its low-level triage is unit-tested in `cli/lab_artifacts.rs`
/// (`native_so_triages_to_the_execution_chain`); this end-to-end assertion pins
/// that the CLI still blocks it with `native_import_execution_chain`, so the
/// whole startup/native artifact family is covered through the binary in one
/// place. (Corpus `binary_fixture = native_chain_wheel`, expected_action =
/// block.)
#[test]
fn lab_native_chain_wheel_blocks() {
    assert_blocks_with_rule(
        "artifact_native_chain_wheel",
        "native_import_execution_chain",
    );
}

/// The benign negative-control wheels must NOT block (no finding). This guards
/// against an over-broad artifact rule that would turn a benign editable / pure
/// wheel into a false positive. (Corpus `benign_editable_wheel` /
/// `benign_pure_wheel`, expected_action = allow.)
#[test]
fn lab_benign_artifact_wheels_allow() {
    let entries = run_lab_artifact_json();
    for name in [
        "artifact_benign_editable_wheel",
        "artifact_benign_pure_wheel",
    ] {
        let entry = scenario(&entries, name);
        assert_eq!(
            entry["actual"], "allow",
            "benign control '{name}' must allow end to end: {entry}"
        );
        assert!(
            fired_rules(entry).is_empty(),
            "benign control '{name}' must carry no findings: {entry}"
        );
    }
}

/// All three `.pth` block scenarios the corpus comments specifically defer to
/// this file are present and blocking. A single assertion over the set so a
/// dropped scenario (not just a downgraded verdict) also fails CI.
#[test]
fn lab_pth_block_scenarios_are_all_present_and_blocking() {
    let entries = run_lab_artifact_json();
    for name in [
        "artifact_pth_cross_runtime_wheel",
        "artifact_pth_subprocess_wheel",
        "artifact_cross_distribution_split",
    ] {
        let entry = scenario(&entries, name);
        assert_eq!(
            entry["actual"], "block",
            "deferred .pth block scenario '{name}' must block: {entry}"
        );
    }
}
