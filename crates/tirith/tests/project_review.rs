//! Product review never starts selected project tooling or follows project links.
use serde_json::{json, Value};
use std::process::Command;
use tirith_test_support::GlobalStateGuard;

fn fixture() -> GlobalStateGuard {
    let mut state = GlobalStateGuard::new().unwrap();
    state.set_env("TIRITH_OFFLINE", "1");
    for key in ["SUDO_USER", "SUDO_UID", "TIRITH_POLICY_ROOT"] {
        state.remove_env(key);
    }
    state
}
fn run(state: &GlobalStateGuard, paths: &[&str]) -> (i32, Value) {
    let mut command = Command::new(env!("CARGO_BIN_EXE_tirith"));
    state.apply_to_command(&mut command);
    command
        .current_dir(&state.roots().cwd)
        .args(["review", "--json"]);
    for path in paths {
        command.args(["--path", path]);
    }
    let output = command.output().unwrap();
    let value = serde_json::from_slice(&output.stdout)
        .unwrap_or_else(|_| json!({"error":String::from_utf8_lossy(&output.stderr)}));
    (output.status.code().unwrap_or(-1), value)
}
#[test]
fn selected_project_review_is_offline_bounded_and_inert() {
    let state = fixture();
    let root = &state.roots().cwd;
    std::fs::write(root.join("package.json"),r#"{"name":"fixture","scripts":{"install":"touch never-created"},"dependencies":{"left-pad":"1.3.0"}}"#).unwrap();
    let (code, report) = run(&state, &["package.json"]);
    assert_eq!(code, 2, "{report}");
    assert_eq!(report["executed"], false);
    assert_eq!(report["files"].as_array().unwrap().len(), 1);
    assert_eq!(report["files"][0]["dependency_count"], 1);
    assert_eq!(report["coverage"]["registry_network"], "not_requested");
    assert!(!root.join("never-created").exists());
    assert!(!root.join("node_modules").exists());
    assert!(report.to_string().len() < 256 * 1024);
    assert_eq!(run(&state, &["../outside"]).0, 1);
}
#[test]
fn current_local_privacy_preserves_review_protocol() {
    let state = fixture();
    let config = tirith_core::policy::config_dir().unwrap();
    std::fs::create_dir_all(&config).unwrap();
    std::fs::write(config.join("policy.yaml"), "dlp_custom_patterns: ['.+']\n").unwrap();
    std::fs::write(
        state.roots().cwd.join(".mcp.json"),
        r#"{"mcpServers":{"private-server-name":{"command":"private-command-name"}}}"#,
    )
    .unwrap();
    let (_, report) = run(&state, &[".mcp.json"]);
    assert_eq!(report["kind"], "project_review");
    assert_eq!(report["files"][0]["status"], "inspected");
    assert_eq!(report["files"][0]["servers"][0]["transport"], "stdio");
    assert!(!report.to_string().contains("private-server-name"));
    assert!(!report.to_string().contains("private-command-name"));
    assert_eq!(report["redaction"]["effective_runtime_policy"], false);
}
