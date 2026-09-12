use serde_json::Value;
use std::process::{Command, Output};
use tirith_test_support::GlobalStateGuard;

fn run(state: &GlobalStateGuard, args: &[&str]) -> Output {
    let mut command = Command::new(env!("CARGO_BIN_EXE_tirith"));
    state.apply_to_command(&mut command);
    command
        .current_dir(&state.roots().cwd)
        .args(args)
        .output()
        .unwrap()
}
fn success(output: Output) -> Value {
    assert!(
        output.status.success(),
        "stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).unwrap()
}

#[test]
fn reviewed_rollout_is_read_only_until_activation_and_undo_preserves_unrelated_fields() {
    let state = GlobalStateGuard::new().unwrap();
    let id = uuid::Uuid::new_v4().to_string();
    let path = tirith_core::policy::config_dir()
        .unwrap()
        .join("policy.yaml");
    let prepared = success(run(
        &state,
        &[
            "policy",
            "rollout",
            "prepare",
            "balanced",
            "--command",
            "touch SHOULD_NOT_EXIST",
            "--command",
            "curl https://example.com/x",
            "--operation-id",
            &id,
            "--json",
        ],
    ));
    assert_eq!(prepared["operation"]["state"], "planned");
    assert_eq!(prepared["impact"]["scope"], "personal_user");
    assert_eq!(prepared["impact"]["candidate_profile"], "balanced");
    assert_eq!(prepared["impact"]["execution_permitted"], false);
    assert_eq!(prepared["impact"]["fleet_adoption_verified"], false);
    assert!(!state.roots().cwd.join("SHOULD_NOT_EXIST").exists());
    assert!(!path.exists());
    let shown = success(run(&state, &["policy", "rollout", "show", &id, "--json"]));
    assert_eq!(prepared["impact"], shown["impact"]);
    let applied = success(run(
        &state,
        &["policy", "rollout", "activate", &id, "--json"],
    ));
    assert_eq!(applied["operation"]["state"], "completed");
    let mut current: serde_yaml::Value =
        serde_yaml::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
    current["unrelated_operator_note"] = "keep".into();
    std::fs::write(&path, serde_yaml::to_string(&current).unwrap()).unwrap();
    let undone = success(run(&state, &["policy", "rollout", "undo", &id, "--json"]));
    assert!(matches!(
        undone["operation"]["state"].as_str(),
        Some("undone" | "undone-with-recovery")
    ));
    let current: serde_yaml::Value =
        serde_yaml::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
    assert_eq!(current["unrelated_operator_note"].as_str(), Some("keep"));
    assert!(current.get("protection_profile").is_none());
}

#[test]
fn retry_keeps_original_impact_after_policy_drift_and_changed_intent_refuses() {
    let state = GlobalStateGuard::new().unwrap();
    let id = uuid::Uuid::new_v4().to_string();
    let args = [
        "policy",
        "rollout",
        "prepare",
        "balanced",
        "--command",
        "curl https://PRIVATE.example/x",
        "--operation-id",
        &id,
        "--json",
    ];
    let first = success(run(&state, &args));
    let config = tirith_core::policy::config_dir().unwrap();
    std::fs::create_dir_all(&config).unwrap();
    std::fs::write(
        config.join("policy.yaml"),
        "strict_warn: true\ndlp_custom_patterns:\n  - '.+'\n",
    )
    .unwrap();
    let retry = success(run(&state, &args));
    assert_eq!(first["impact"], retry["impact"]);
    assert!(!retry.to_string().contains("PRIVATE.example"));
    assert!(uuid::Uuid::parse_str(retry["impact"]["workflows"][0]["id"].as_str().unwrap()).is_ok());
    assert!(!run(
        &state,
        &[
            "policy",
            "rollout",
            "prepare",
            "balanced",
            "--command",
            "echo different",
            "--operation-id",
            &id,
            "--json"
        ]
    )
    .status
    .success());
    assert!(
        !run(&state, &["policy", "rollout", "activate", &id, "--json"])
            .status
            .success()
    );
}

#[test]
fn no_change_rollout_stores_review_and_never_changes_into_a_later_mutation() {
    let state = GlobalStateGuard::new().unwrap();
    success(run(&state, &["policy", "profile", "balanced", "--json"]));
    let id = uuid::Uuid::new_v4().to_string();
    let args = [
        "policy",
        "rollout",
        "prepare",
        "balanced",
        "--command",
        "echo ready",
        "--operation-id",
        &id,
        "--json",
    ];
    let first = success(run(&state, &args));
    assert_eq!(first["operation"]["no_op"], true);
    assert_eq!(first["operation"]["state"], "completed");
    success(run(&state, &["policy", "profile", "strict", "--json"]));
    let retry = success(run(&state, &args));
    assert_eq!(first["impact"], retry["impact"]);
    assert_eq!(retry["operation"]["no_op"], true);
    assert_eq!(retry["live"]["selected_profile"]["name"], "strict");
}
