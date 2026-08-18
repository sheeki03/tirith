//! C15: repository-level contracts for the cross-workflow artifact-flow
//! post-pass (`rules::workflow_artifacts` driven from `scan::scan`).
//!
//! The unit tests inside `rules::workflow_artifacts` own the flow semantics.
//! These tests own the PLUMBING: that a proven chain reaches a real directory
//! scan attached to the consumer workflow, that a single-file scan can never
//! produce one, that the repository bounds turn into coverage gaps instead of
//! guesses, and that the presence-level `workflow_run` severity is lowered only
//! when the post-pass actually had full visibility.

use std::fs;
use std::path::{Path, PathBuf};

use tirith_core::scan::{
    scan, scan_single_file, scan_single_file_guarded, CoverageGapKind, GuardedScanOutcome,
    ScanConfig, ScanFileOutcome, ScanResult,
};
use tirith_core::verdict::{RuleId, Severity};

/// A fork-reachable producer that uploads `build`.
const PRODUCER: &str = "\
name: CI
on:
  pull_request:
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: make dist
      - uses: actions/upload-artifact@v4
        with:
          name: build
          path: dist
";

/// A privileged `workflow_run` consumer that downloads `build` from the
/// triggering run and executes it.
const POISONED_CONSUMER: &str = "\
name: Deploy
on:
  workflow_run:
    workflows: [CI]
    types: [completed]
jobs:
  ship:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/download-artifact@v4
        with:
          name: build
          path: dist
          run-id: ${{ github.event.workflow_run.id }}
          github-token: ${{ secrets.GITHUB_TOKEN }}
      - run: bash ./dist/install.sh
";

/// The same consumer with no dangerous sink: a downloaded report is not a High.
const BENIGN_CONSUMER: &str = "\
name: Deploy
on:
  workflow_run:
    workflows: [CI]
    types: [completed]
jobs:
  ship:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/download-artifact@v4
        with:
          name: build
          path: dist
          run-id: ${{ github.event.workflow_run.id }}
      - run: cat dist/coverage.json
";

/// A named fork-reachable producer whose local action could contain the upload.
const UNRESOLVED_PRODUCER: &str = "\
name: CI
on:
  pull_request:
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: ./.github/actions/build
";

fn find_consumer(command: &str) -> String {
    format!(
        concat!(
            "name: Deploy\n",
            "on:\n",
            "  workflow_run:\n",
            "    workflows: [CI]\n",
            "    types: [completed]\n",
            "jobs:\n",
            "  ship:\n",
            "    runs-on: ubuntu-latest\n",
            "    steps:\n",
            "      - uses: actions/download-artifact@v4\n",
            "        with:\n",
            "          name: build\n",
            "          path: dist\n",
            "          run-id: ${{{{ github.event.workflow_run.id }}}}\n",
            "      - run: {command}\n",
        ),
        command = command,
    )
}

fn event_budget_consumer(event_count: usize) -> String {
    let mut workflow = String::from(concat!(
        "name: Deploy\n",
        "on:\n",
        "  workflow_run:\n",
        "    workflows: [CI]\n",
        "    types: [completed]\n",
        "jobs:\n",
        "  ship:\n",
        "    runs-on: ubuntu-latest\n",
        "    steps:\n",
    ));
    for _ in 0..event_count {
        workflow.push_str(concat!(
            "      - uses: actions/download-artifact@v4\n",
            "        with:\n",
            "          name: build\n",
            "          path: dist\n",
            "          run-id: ${{ github.event.workflow_run.id }}\n",
        ));
    }
    workflow
}

fn workflows_dir(root: &Path) -> PathBuf {
    let dir = root.join(".github").join("workflows");
    fs::create_dir_all(&dir).expect("create .github/workflows");
    dir
}

fn scan_tree(root: &Path) -> ScanResult {
    scan_tree_capped(root, None)
}

fn scan_tree_capped(root: &Path, max_files: Option<usize>) -> ScanResult {
    scan(&ScanConfig {
        path: root.to_path_buf(),
        recursive: true,
        fail_on: Severity::High,
        ignore_patterns: Vec::new(),
        include_patterns: Vec::new(),
        exclude_patterns: Vec::new(),
        max_files,
    })
}

fn scan_tree_filtered(
    root: &Path,
    ignore_patterns: Vec<String>,
    include_patterns: Vec<String>,
    exclude_patterns: Vec<String>,
) -> ScanResult {
    scan(&ScanConfig {
        path: root.to_path_buf(),
        recursive: true,
        fail_on: Severity::High,
        ignore_patterns,
        include_patterns,
        exclude_patterns,
        max_files: None,
    })
}

fn findings_for(result: &ScanResult, rule: RuleId) -> Vec<(PathBuf, Severity)> {
    result
        .file_results
        .iter()
        .flat_map(|file| {
            file.findings
                .iter()
                .filter(|f| f.rule_id == rule)
                .map(|f| (file.path.clone(), f.severity))
        })
        .collect()
}

#[test]
fn poisoned_pair_in_a_repository_scan_is_a_high_on_the_consumer() {
    let tree = tempfile::tempdir().expect("tempdir");
    let dir = workflows_dir(tree.path());
    fs::write(dir.join("ci.yml"), PRODUCER).expect("write producer");
    fs::write(dir.join("deploy.yml"), POISONED_CONSUMER).expect("write consumer");

    let result = scan_tree(tree.path());
    let hits = findings_for(&result, RuleId::WorkflowArtifactPoisoning);
    assert_eq!(
        hits.len(),
        1,
        "expected exactly one chain finding: {hits:?}"
    );
    assert_eq!(hits[0].0, dir.join("deploy.yml"), "located at the consumer");
    assert_eq!(hits[0].1, Severity::High);

    // Within every bound, so the post-pass adds no coverage gap of its own. This
    // mirrors the existing directory-walk regression guard, which asserts an
    // empty `coverage_gaps` for a tree containing `.github/workflows/ci.yml`.
    assert!(
        result.coverage_gaps.is_empty(),
        "a bounded scan must add no gaps: {:?}",
        result.coverage_gaps
    );

    // The chain IS proven, so the presence-level trigger keeps its High.
    let trigger = findings_for(&result, RuleId::WorkflowRunTrigger);
    assert_eq!(trigger.len(), 1, "{trigger:?}");
    assert_eq!(trigger[0].1, Severity::High);
}

#[test]
fn benign_consumer_gets_no_chain_and_a_lowered_presence_trigger() {
    let tree = tempfile::tempdir().expect("tempdir");
    let dir = workflows_dir(tree.path());
    fs::write(dir.join("ci.yml"), PRODUCER).expect("write producer");
    fs::write(dir.join("deploy.yml"), BENIGN_CONSUMER).expect("write consumer");

    let result = scan_tree(tree.path());
    assert!(
        findings_for(&result, RuleId::WorkflowArtifactPoisoning).is_empty(),
        "a downloaded report with no dangerous sink is not a High"
    );
    let trigger = findings_for(&result, RuleId::WorkflowRunTrigger);
    assert_eq!(trigger.len(), 1, "{trigger:?}");
    assert_eq!(
        trigger[0].1,
        Severity::Medium,
        "full repository visibility with no proven chain lowers the presence rule"
    );
}

#[test]
fn unresolved_named_producer_without_direct_upload_keeps_trigger_high() {
    let tree = tempfile::tempdir().expect("tempdir");
    let dir = workflows_dir(tree.path());
    fs::write(dir.join("ci.yml"), UNRESOLVED_PRODUCER).expect("write producer");
    fs::write(dir.join("deploy.yml"), BENIGN_CONSUMER).expect("write consumer");

    let result = scan_tree(tree.path());
    assert!(
        findings_for(&result, RuleId::WorkflowArtifactPoisoning).is_empty(),
        "missing producer visibility must not fabricate a chain"
    );
    let trigger = findings_for(&result, RuleId::WorkflowRunTrigger);
    assert_eq!(trigger.len(), 1, "{trigger:?}");
    assert_eq!(
        trigger[0].1,
        Severity::High,
        "a bound local action may contain the producer upload"
    );
}

#[test]
fn find_exec_after_download_keeps_trigger_high() {
    let tree = tempfile::tempdir().expect("tempdir");
    let dir = workflows_dir(tree.path());
    fs::write(dir.join("ci.yml"), PRODUCER).expect("write producer");
    fs::write(
        dir.join("deploy.yml"),
        find_consumer("find dist -type f -exec sh {} +"),
    )
    .expect("write consumer");

    let result = scan_tree(tree.path());
    assert!(
        findings_for(&result, RuleId::WorkflowArtifactPoisoning).is_empty(),
        "an unmodelled find action is incomplete, not a fabricated chain"
    );
    let trigger = findings_for(&result, RuleId::WorkflowRunTrigger);
    assert_eq!(trigger.len(), 1, "{trigger:?}");
    assert_eq!(trigger[0].1, Severity::High);
}

#[test]
fn read_only_find_after_download_remains_downgradable() {
    let tree = tempfile::tempdir().expect("tempdir");
    let dir = workflows_dir(tree.path());
    fs::write(dir.join("ci.yml"), PRODUCER).expect("write producer");
    fs::write(
        dir.join("deploy.yml"),
        find_consumer("find -L dist -maxdepth 2 -type f -print"),
    )
    .expect("write consumer");

    let result = scan_tree(tree.path());
    assert!(findings_for(&result, RuleId::WorkflowArtifactPoisoning).is_empty());
    let trigger = findings_for(&result, RuleId::WorkflowRunTrigger);
    assert_eq!(trigger.len(), 1, "{trigger:?}");
    assert_eq!(trigger[0].1, Severity::Medium);
}

#[test]
fn single_file_scan_never_emits_the_chain_rule_and_keeps_the_trigger_high() {
    let tree = tempfile::tempdir().expect("tempdir");
    let dir = workflows_dir(tree.path());
    fs::write(dir.join("ci.yml"), PRODUCER).expect("write producer");
    let consumer = dir.join("deploy.yml");
    fs::write(&consumer, POISONED_CONSUMER).expect("write consumer");

    // `tirith check <file>`, the MCP scan tool, and the LSP all take this path:
    // one file cannot prove a producer-to-consumer chain, and none of them runs
    // the repository post-pass, so the presence-level rule must stay High.
    let ScanFileOutcome::Scanned(direct) = scan_single_file(&consumer) else {
        panic!("single-file scan must analyze the workflow");
    };
    assert!(direct
        .findings
        .iter()
        .all(|f| f.rule_id != RuleId::WorkflowArtifactPoisoning));
    assert!(direct
        .findings
        .iter()
        .any(|f| f.rule_id == RuleId::WorkflowRunTrigger && f.severity == Severity::High));

    let GuardedScanOutcome::Completed(ScanFileOutcome::Scanned(guarded)) =
        scan_single_file_guarded(&consumer)
    else {
        panic!("guarded single-file scan must analyze the workflow");
    };
    assert!(guarded
        .findings
        .iter()
        .all(|f| f.rule_id != RuleId::WorkflowArtifactPoisoning));
    assert!(guarded
        .findings
        .iter()
        .any(|f| f.rule_id == RuleId::WorkflowRunTrigger && f.severity == Severity::High));
}

#[test]
fn workflow_count_bound_records_a_truncated_gap_and_blocks_the_downgrade() {
    let tree = tempfile::tempdir().expect("tempdir");
    let dir = workflows_dir(tree.path());
    fs::write(dir.join("ci.yml"), PRODUCER).expect("write producer");
    fs::write(dir.join("deploy.yml"), BENIGN_CONSUMER).expect("write consumer");
    // 256 is the retained-workflow ceiling; the files here plus the filler push
    // the tree past it.
    for index in 0..300 {
        fs::write(
            dir.join(format!("filler-{index:03}.yml")),
            "name: Filler\non: [push]\njobs:\n  noop:\n    runs-on: ubuntu-latest\n    steps:\n      - run: 'true'\n",
        )
        .expect("write filler");
    }

    let result = scan_tree(tree.path());
    let truncated: Vec<_> = result
        .coverage_gaps
        .iter()
        .filter(|gap| gap.kind == CoverageGapKind::Truncated)
        .collect();
    assert!(
        !truncated.is_empty(),
        "exceeding the workflow ceiling must record a Truncated gap"
    );
    for gap in &truncated {
        let path = gap
            .primary_path()
            .expect("gap has a path")
            .to_string_lossy();
        assert!(
            path.contains(".github/workflows/") && path.ends_with(".yml"),
            "the gap must be located at the workflow it dropped: {path}"
        );
    }
    assert!(
        findings_for(&result, RuleId::WorkflowArtifactPoisoning).is_empty(),
        "a partial model must not manufacture a High"
    );
    let trigger = findings_for(&result, RuleId::WorkflowRunTrigger);
    assert_eq!(trigger.len(), 1, "{trigger:?}");
    assert_eq!(
        trigger[0].1,
        Severity::High,
        "an exhausted bound must never be read as proof that no chain exists"
    );
}

#[test]
fn step_bound_records_a_truncated_gap_and_blocks_the_downgrade() {
    let tree = tempfile::tempdir().expect("tempdir");
    let dir = workflows_dir(tree.path());
    fs::write(dir.join("ci.yml"), PRODUCER).expect("write producer");
    fs::write(dir.join("deploy.yml"), BENIGN_CONSUMER).expect("write consumer");

    // 4096 modelled steps is the repository ceiling; one workflow blows it alone.
    let mut giant = String::from(
        "name: Giant\non: [push]\njobs:\n  big:\n    runs-on: ubuntu-latest\n    steps:\n",
    );
    for _ in 0..5000 {
        giant.push_str("      - run: 'true'\n");
    }
    // `a-giant.yml` sorts before `ci.yml` and `deploy.yml`, so the budget is
    // already spent when the interesting pair is reached.
    fs::write(dir.join("a-giant.yml"), &giant).expect("write giant");

    let result = scan_tree(tree.path());
    assert!(
        result
            .coverage_gaps
            .iter()
            .any(|gap| gap.kind == CoverageGapKind::Truncated),
        "exceeding the step ceiling must record a Truncated gap"
    );
    assert!(findings_for(&result, RuleId::WorkflowArtifactPoisoning).is_empty());
    let trigger = findings_for(&result, RuleId::WorkflowRunTrigger);
    assert_eq!(trigger.len(), 1, "{trigger:?}");
    assert_eq!(trigger[0].1, Severity::High);
}

#[test]
fn event_bound_is_exact_and_overflow_records_a_truncated_gap() {
    const EVENT_LIMIT: usize = 512;

    let at_limit = tempfile::tempdir().expect("at-limit tempdir");
    let at_limit_dir = workflows_dir(at_limit.path());
    fs::write(at_limit_dir.join("ci.yml"), PRODUCER).expect("write producer");
    fs::write(
        at_limit_dir.join("deploy.yml"),
        event_budget_consumer(EVENT_LIMIT),
    )
    .expect("write at-limit consumer");

    let result = scan_tree(at_limit.path());
    assert!(
        result.coverage_gaps.is_empty(),
        "the exact event limit is complete: {:?}",
        result.coverage_gaps
    );
    let trigger = findings_for(&result, RuleId::WorkflowRunTrigger);
    assert_eq!(trigger.len(), 1, "{trigger:?}");
    assert_eq!(
        trigger[0].1,
        Severity::Medium,
        "a fully modelled benign consumer remains downgradeable"
    );

    let over_limit = tempfile::tempdir().expect("over-limit tempdir");
    let over_limit_dir = workflows_dir(over_limit.path());
    fs::write(over_limit_dir.join("ci.yml"), PRODUCER).expect("write producer");
    fs::write(
        over_limit_dir.join("deploy.yml"),
        event_budget_consumer(EVENT_LIMIT + 1),
    )
    .expect("write over-limit consumer");

    let result = scan_tree(over_limit.path());
    let over_limit_consumer = over_limit_dir.join("deploy.yml");
    assert!(result.coverage_gaps.iter().any(|gap| {
        gap.kind == CoverageGapKind::Truncated
            && gap.primary_path() == Some(over_limit_consumer.as_path())
    }));
    assert!(findings_for(&result, RuleId::WorkflowArtifactPoisoning).is_empty());
    let trigger = findings_for(&result, RuleId::WorkflowRunTrigger);
    assert_eq!(trigger.len(), 1, "{trigger:?}");
    assert_eq!(
        trigger[0].1,
        Severity::High,
        "an event-overflowed consumer must never be reported as chain-free"
    );
}

// The 32 MiB aggregate-source ceiling is exercised by
// `workflow_budget_stops_at_the_aggregate_byte_ceiling` in `scan.rs`: reaching it
// through a real directory scan means pushing 33 MiB of YAML through the whole
// engine, which costs about a minute of test time to prove arithmetic the unit
// test proves exactly. The gap kind, the gap location, and the blocked downgrade
// that the byte ceiling produces are the SAME code path the workflow-count and
// step ceilings below already cover end to end.

#[test]
fn malformed_sibling_workflow_blocks_the_downgrade_without_panicking() {
    let tree = tempfile::tempdir().expect("tempdir");
    let dir = workflows_dir(tree.path());
    fs::write(dir.join("ci.yml"), PRODUCER).expect("write producer");
    fs::write(dir.join("deploy.yml"), BENIGN_CONSUMER).expect("write consumer");
    fs::write(
        dir.join("broken.yml"),
        "name: Broken\non: [push\njobs: {{{\n",
    )
    .expect("write broken");

    let result = scan_tree(tree.path());
    assert!(findings_for(&result, RuleId::WorkflowArtifactPoisoning).is_empty());
    let trigger = findings_for(&result, RuleId::WorkflowRunTrigger);
    assert_eq!(trigger.len(), 1, "{trigger:?}");
    assert_eq!(
        trigger[0].1,
        Severity::High,
        "a workflow the pass could not read into could be the missing producer"
    );
}

#[test]
fn a_max_files_cap_blocks_the_downgrade() {
    let tree = tempfile::tempdir().expect("tempdir");
    let dir = workflows_dir(tree.path());
    fs::write(dir.join("ci.yml"), PRODUCER).expect("write producer");
    fs::write(dir.join("deploy.yml"), BENIGN_CONSUMER).expect("write consumer");
    fs::write(tree.path().join("Dockerfile"), "FROM ubuntu:latest\n").expect("write Dockerfile");

    // The caller's own cap drops candidates wholesale, so one of them could have
    // been the producer this consumer is actually fed by.
    let result = scan_tree_capped(tree.path(), Some(2));
    let trigger = findings_for(&result, RuleId::WorkflowRunTrigger);
    assert_eq!(trigger.len(), 1, "{trigger:?}");
    assert_eq!(trigger[0].1, Severity::High);
}

#[test]
fn a_pattern_filtered_workflow_blocks_the_downgrade() {
    let tree = tempfile::tempdir().expect("tempdir");
    let dir = workflows_dir(tree.path());
    fs::write(dir.join("ci.yml"), PRODUCER).expect("write producer");
    fs::write(dir.join("deploy.yml"), POISONED_CONSUMER).expect("write consumer");

    // Unfiltered, the chain is proven and the trigger keeps its High.
    let baseline = scan_tree(tree.path());
    assert_eq!(
        findings_for(&baseline, RuleId::WorkflowArtifactPoisoning).len(),
        1
    );

    // Each of these drops the PRODUCER before analysis. The post-pass then never
    // modelled it, so it has no basis to report the absence of a chain, and a
    // `--fail-on high` gate that would have failed must not start passing.
    for (ignore, include, exclude) in [
        (vec!["ci.yml".to_string()], vec![], vec![]),
        (vec![], vec![], vec!["ci.yml".to_string()]),
        (vec![], vec!["deploy.yml".to_string()], vec![]),
    ] {
        let result = scan_tree_filtered(
            tree.path(),
            ignore.clone(),
            include.clone(),
            exclude.clone(),
        );
        assert!(
            findings_for(&result, RuleId::WorkflowArtifactPoisoning).is_empty(),
            "the producer was filtered away, so no chain can be proven"
        );
        let trigger = findings_for(&result, RuleId::WorkflowRunTrigger);
        assert_eq!(trigger.len(), 1, "{trigger:?}");
        assert_eq!(
            trigger[0].1,
            Severity::High,
            "a pattern-filtered workflow could be the missing producer \
             (ignore={ignore:?} include={include:?} exclude={exclude:?})"
        );
    }

    // A filter that drops something that is NOT a workflow costs the post-pass
    // nothing, so the downgrade still happens on a benign consumer.
    fs::write(dir.join("deploy.yml"), BENIGN_CONSUMER).expect("rewrite consumer");
    fs::write(tree.path().join("Dockerfile"), "FROM ubuntu:latest\n").expect("write Dockerfile");
    let result = scan_tree_filtered(tree.path(), vec!["Dockerfile".to_string()], vec![], vec![]);
    let trigger = findings_for(&result, RuleId::WorkflowRunTrigger);
    assert_eq!(trigger.len(), 1, "{trigger:?}");
    assert_eq!(trigger[0].1, Severity::Medium);
}

#[test]
fn publish_chain_relevant_to_dapp_build_output_is_proven() {
    let tree = tempfile::tempdir().expect("tempdir");
    let dir = workflows_dir(tree.path());
    fs::write(dir.join("ci.yml"), PRODUCER).expect("write producer");
    fs::write(
        dir.join("release.yml"),
        "\
name: Release
on:
  workflow_run:
    workflows: [CI]
jobs:
  publish:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/download-artifact@v4
        with:
          name: build
          path: dist
          run-id: ${{ github.event.workflow_run.id }}
      - run: npm publish ./dist
",
    )
    .expect("write release");

    let result = scan_tree(tree.path());
    let hits = findings_for(&result, RuleId::WorkflowArtifactPoisoning);
    assert_eq!(hits.len(), 1, "{hits:?}");
    assert_eq!(hits[0].0, dir.join("release.yml"));
}

#[test]
fn a_tree_with_no_workflows_is_unchanged_by_the_post_pass() {
    let tree = tempfile::tempdir().expect("tempdir");
    fs::write(
        tree.path().join("Dockerfile"),
        "FROM ubuntu:latest\nRUN apt-get update\n",
    )
    .expect("write Dockerfile");

    let result = scan_tree(tree.path());
    assert!(
        result.coverage_gaps.is_empty(),
        "{:?}",
        result.coverage_gaps
    );
    assert!(findings_for(&result, RuleId::WorkflowArtifactPoisoning).is_empty());
}
