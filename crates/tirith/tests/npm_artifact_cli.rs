//! Product routing and canonical reports for local, non-executing npm analysis.
use std::path::Path;
use std::process::{Command, Output};

use serde_json::Value;
use tirith_test_support::GlobalStateGuard;

const FIXTURE: &[u8] =
    include_bytes!("../../tirith-core/tests/fixtures/npm/npm-11.19.0-portable-pax.tgz");
const SHA: &str = "769755af559bda513cfe86d6c433bf8e6c0b2431dbb24955393e0dc69eeb2c0f";

fn run(state: &GlobalStateGuard, args: &[&str]) -> Output {
    let mut command = Command::new(env!("CARGO_BIN_EXE_tirith"));
    state.apply_to_command(&mut command);
    command
        .current_dir(&state.roots().cwd)
        .args(args)
        .output()
        .unwrap()
}

fn report(output: &Output) -> Value {
    assert!(
        matches!(output.status.code(), Some(0 | 2)),
        "stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).unwrap()
}

fn fixture(directory: &Path, name: &str) -> String {
    let path = directory.join(name);
    std::fs::write(&path, FIXTURE).unwrap();
    path.to_str().unwrap().into()
}

#[test]
fn both_inspection_routes_and_release_diff_share_exact_artifact_identity() {
    let state = GlobalStateGuard::new().unwrap();
    let path = fixture(&state.roots().cwd, "package-1.0.0.tgz");
    let first = report(&run(&state, &["pkg", "inspect", &path, "--format", "json"]));
    let alias = report(&run(
        &state,
        &["package", "inspect", "--artifact", &path, "--json"],
    ));
    assert_eq!(first, alias);
    assert_eq!(first["kind"], "npm_inspection");
    assert_eq!(first["artifacts"][0]["artifact"]["sha256"], SHA);
    assert_eq!(first["redaction"]["remote_policy"], "unavailable_offline");
    assert_eq!(first["redaction"]["effective_runtime_policy"], false);
    let renamed = fixture(&state.roots().cwd, "renamed.tar.gz");
    let compared = report(&run(
        &state,
        &[
            "pkg",
            "diff",
            &path,
            &renamed,
            "--ecosystem",
            "npm",
            "--format",
            "json",
        ],
    ));
    assert_eq!(compared["kind"], "npm_comparison");
    assert_eq!(compared["same_artifact"], true);
    assert_eq!(compared["old_artifact"]["sha256"], SHA);
    assert_eq!(compared["new_artifact"]["sha256"], SHA);
    assert!(compared["deltas"].as_array().unwrap().is_empty());
    assert!(!state.roots().cwd.join("node_modules").exists());
    assert!(!state.roots().cwd.join("package-lock.json").exists());
}

#[test]
fn sarif_and_usage_errors_keep_canonical_metadata_under_broad_dlp() {
    let state = GlobalStateGuard::new().unwrap();
    let config = tirith_core::policy::config_dir().unwrap();
    std::fs::create_dir_all(&config).unwrap();
    std::fs::write(
        config.join("policy.yaml"),
        "dlp_custom_patterns:\n  - '.+'\n",
    )
    .unwrap();
    let path = fixture(&state.roots().cwd, "PRIVATE-package.tgz");
    let output = run(&state, &["pkg", "inspect", &path, "--format", "sarif"]);
    let sarif = report(&output);
    assert_eq!(sarif["version"], "2.1.0");
    let artifact = &sarif["runs"][0]["properties"]["tirithReport"]["artifacts"][0];
    assert_eq!(artifact["artifact"]["sha256"], SHA);
    assert_eq!(artifact["archive_state"], "accepted");
    assert!(!String::from_utf8_lossy(&output.stdout).contains("PRIVATE-package"));
    let mixed = run(&state, &["pkg", "diff", &path, "other.whl", "--json"]);
    assert_eq!(mixed.status.code(), Some(2));
    let error = report(&mixed);
    assert_eq!(error["kind"], "npm_artifact_error");
    assert_eq!(error["status"], "unavailable");
}

#[test]
fn ambiguous_tar_gz_preserves_python_contract_unless_npm_is_explicit() {
    let state = GlobalStateGuard::new().unwrap();
    let path = fixture(&state.roots().cwd, "package-1.0.0.tar.gz");
    for args in [
        vec!["pkg", "inspect", &path, "--json"],
        vec!["package", "inspect", "--artifact", &path, "--json"],
    ] {
        let output = run(&state, &args);
        assert_eq!(output.status.code(), Some(1));
        let refused: Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(refused["action"], "block");
        assert!(refused["coverage_gaps"]
            .as_array()
            .unwrap()
            .iter()
            .any(|gap| gap["kind"] == "unsupported"));
        assert!(refused["findings"]
            .as_array()
            .unwrap()
            .iter()
            .any(|finding| finding["rule_id"] == "analysis_incomplete"));
    }
    let selected = report(&run(
        &state,
        &["pkg", "inspect", &path, "--ecosystem", "npm", "--json"],
    ));
    let alias = report(&run(
        &state,
        &[
            "package",
            "inspect",
            "--artifact",
            &path,
            "--ecosystem",
            "npm",
            "--json",
        ],
    ));
    assert_eq!(selected, alias);
    assert_eq!(selected["kind"], "npm_inspection");
    assert_eq!(selected["artifacts"][0]["artifact"]["sha256"], SHA);
    let tgz = fixture(&state.roots().cwd, "package-1.0.0.tgz");
    let python = run(
        &state,
        &["pkg", "inspect", &tgz, "--ecosystem", "python", "--json"],
    );
    assert_eq!(python.status.code(), Some(1));
    assert_eq!(
        serde_json::from_slice::<Value>(&python.stdout).unwrap()["action"],
        "block"
    );
    let invalid = run(
        &state,
        &[
            "package",
            "inspect",
            "--installed",
            ".",
            "--ecosystem",
            "npm",
        ],
    );
    assert_eq!(invalid.status.code(), Some(2));
    assert!(!state.roots().cwd.join("node_modules").exists());
}
