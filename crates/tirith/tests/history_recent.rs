use serde_json::Value;
use std::process::{Command, Output};
use tirith_test_support::GlobalStateGuard;

fn run(state: &GlobalStateGuard, args: &[&str]) -> Output {
    let mut command = Command::new(env!("CARGO_BIN_EXE_tirith"));
    state.apply_to_command(&mut command);
    command
        .current_dir(&state.roots().cwd)
        .args(["audit", "recent", "--json"])
        .args(args)
        .output()
        .unwrap()
}

#[test]
fn history_distinguishes_absent_disabled_empty_and_corrupt() {
    let mut state = GlobalStateGuard::new().unwrap();
    let path = tirith_core::audit::audit_log_path().unwrap();
    let absent = run(&state, &[]);
    assert!(absent.status.success());
    assert_eq!(
        serde_json::from_slice::<Value>(&absent.stdout).unwrap()["availability"],
        "absent"
    );
    state.set_env("TIRITH_LOG", "0");
    let disabled = run(&state, &[]);
    assert_eq!(
        serde_json::from_slice::<Value>(&disabled.stdout).unwrap()["availability"],
        "disabled"
    );
    state.remove_env("TIRITH_LOG");
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(&path, "").unwrap();
    let empty = run(&state, &[]);
    assert_eq!(
        serde_json::from_slice::<Value>(&empty.stdout).unwrap()["availability"],
        "empty"
    );
    std::fs::write(&path, "broken\n").unwrap();
    let corrupt = run(&state, &[]);
    assert!(!corrupt.status.success());
    assert_eq!(
        serde_json::from_slice::<Value>(&corrupt.stdout).unwrap()["availability"],
        "corrupt"
    );
}

#[test]
fn broad_current_dlp_redacts_history_without_rewriting_signed_source() {
    let state = GlobalStateGuard::new().unwrap();
    let directory = state.roots().policy.join(".tirith");
    std::fs::create_dir_all(&directory).unwrap();
    std::fs::write(
        directory.join("policy.yaml"),
        "dlp_custom_patterns: ['.+']\n",
    )
    .unwrap();
    let path = tirith_core::audit::audit_log_path().unwrap();
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    let original = format!(
        "{}\n",
        serde_json::json!({"timestamp":"2026-09-12T00:00:00Z", "action":"WarnAck",
        "command_redacted":"operator-private-command", "rule_ids":["curl_pipe_shell"], "policy_path":"operator-private-policy", "sig":"canonical-signature"})
    );
    std::fs::write(&path, &original).unwrap();
    let result = run(&state, &["--action", "warn_ack"]);
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    let value: Value = serde_json::from_slice(&result.stdout).unwrap();
    assert_eq!(value["events"].as_array().unwrap().len(), 1);
    let event = &value["events"][0];
    assert_eq!(event["record"]["action"], "WarnAck");
    assert_eq!(event["record"]["rule_ids"][0], "curl_pipe_shell");
    assert_eq!(event["semantics"], "recorded_check");
    assert_eq!(
        event["execution_evidence"],
        "not_established_by_this_record"
    );
    assert!(!String::from_utf8_lossy(&result.stdout).contains("operator-private"));
    assert!(event["record"].get("sig").is_none());
    assert!(value.get("next_cursor").is_none());
    assert_eq!(std::fs::read_to_string(&path).unwrap(), original);
}

#[test]
fn recent_cli_selects_the_newest_records_in_a_small_busy_log() {
    let state = GlobalStateGuard::new().unwrap();
    let path = tirith_core::audit::audit_log_path().unwrap();
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    let bytes = (0..600).map(|i| format!("{}\n", serde_json::json!({"timestamp":"2026-09-12T00:00:00Z", "action":"Block", "command_redacted":format!("check-{i}")}))).collect::<String>();
    std::fs::write(&path, &bytes).unwrap();
    let output = run(&state, &["--limit", "10"]);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let result: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(
        result["events"][0]["record"]["command_redacted"],
        "check-590"
    );
    assert_eq!(
        result["events"][9]["record"]["command_redacted"],
        "check-599"
    );
    assert_eq!(result["earlier_history_uninspected"], true);
    assert_eq!(std::fs::read_to_string(path).unwrap(), bytes);
}
