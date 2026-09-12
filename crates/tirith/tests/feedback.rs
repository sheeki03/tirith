use serde_json::{json, Value};
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
        "{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).unwrap()
}
fn fixture() -> (GlobalStateGuard, String, String) {
    let mut state = GlobalStateGuard::new().unwrap();
    for key in ["SUDO_USER", "SUDO_UID", "TIRITH_POLICY_ROOT"] {
        state.remove_env(key);
    }
    state.set_env("TIRITH_OFFLINE", "1");
    let id = uuid::Uuid::new_v4().to_string();
    let log = tirith_core::audit::audit_log_path().unwrap();
    std::fs::create_dir_all(log.parent().unwrap()).unwrap();
    let bytes = format!(
        "{}\n",
        json!({"timestamp":"2026-09-12T00:00:00Z","action":"Block","event_id":id,"command_redacted":"operator-private-command"})
    );
    std::fs::write(log, &bytes).unwrap();
    (state, id, bytes)
}

#[test]
fn accepted_timestamp_fraction_is_normalized_before_feedback_storage() {
    let (state, id, _) = fixture();
    let timestamp = format!("2026-09-12T00:00:00.{}Z", "0".repeat(100_000));
    let record = json!({"timestamp":timestamp,"action":"Block","event_id":id,"command_redacted":"echo intended"});
    std::fs::write(
        tirith_core::audit::audit_log_path().unwrap(),
        format!("{record}\n"),
    )
    .unwrap();
    let result = success(run(
        &state,
        &[
            "audit",
            "feedback",
            "--event-id",
            &id,
            "--expectation",
            "expected",
            "--json",
        ],
    ));
    assert!(result.to_string().len() < 4096);
    let bytes = std::fs::read(
        tirith_core::policy::state_dir()
            .unwrap()
            .join("feedback")
            .join(format!("{id}.json")),
    )
    .unwrap();
    assert!(bytes.len() < 4096);
    let value: Value = serde_json::from_slice(&bytes).unwrap();
    assert!(value["recorded_check_timestamp"].as_str().unwrap().len() < 64);
    // A subsequent operation can read the normalized existing-record contract.
    success(run(
        &state,
        &[
            "audit",
            "feedback",
            "--event-id",
            &id,
            "--expectation",
            "unexpected",
            "--json",
        ],
    ));
}

#[test]
fn feedback_is_owned_replayable_undoable_and_does_not_change_trust_or_audit() {
    let (state, id, original) = fixture();
    let operation = uuid::Uuid::new_v4().to_string();
    let args = [
        "audit",
        "feedback",
        "--event-id",
        &id,
        "--expectation",
        "expected",
        "--operation-id",
        &operation,
        "--json",
    ];
    let root = tirith_core::policy::state_dir().unwrap();
    let destination = root.join("feedback").join(format!("{id}.json"));
    let mut dry = args.to_vec();
    dry.push("--dry-run");
    let preview = success(run(&state, &dry));
    assert_eq!(preview["record"]["expectation"], "expected");
    assert!(!destination.exists());
    assert!(!root.join("operations").exists());
    let applied = success(run(&state, &args));
    assert_eq!(applied["operation_id"], operation);
    let saved = std::fs::read(&destination).unwrap();
    assert!(!String::from_utf8_lossy(&saved).contains("operator-private-command"));
    assert_eq!(success(run(&state, &args))["operation_id"], operation);
    assert_eq!(std::fs::read(&destination).unwrap(), saved);
    assert!(!run(
        &state,
        &[
            "audit",
            "feedback",
            "--event-id",
            &id,
            "--expectation",
            "unexpected",
            "--operation-id",
            &operation,
            "--json"
        ]
    )
    .status
    .success());
    assert_eq!(
        std::fs::read_to_string(tirith_core::audit::audit_log_path().unwrap()).unwrap(),
        original
    );
    let config = tirith_core::policy::config_dir().unwrap();
    assert!(!config.join("policy.yaml").exists() && !config.join("policy.yml").exists());
    assert!(!config.join("trust.json").exists());
    let undo = success(run(
        &state,
        &[
            "policy",
            "operation",
            &operation,
            "--action",
            "undo",
            "--json",
        ],
    ));
    assert_eq!(undo["state"], "undone");
    assert!(std::fs::read_to_string(&destination)
        .unwrap_or_default()
        .is_empty());
    // A new annotation after undo is a fresh operation; the empty compensation
    // is still bound as an existing preimage, never mistaken for absent bytes.
    success(run(
        &state,
        &[
            "audit",
            "feedback",
            "--event-id",
            &id,
            "--expectation",
            "unsure",
            "--json",
        ],
    ));
}

#[test]
fn feedback_rejects_absent_incidents_and_preserves_unknown_future_records() {
    let (state, id, _) = fixture();
    let missing = uuid::Uuid::new_v4().to_string();
    assert!(!run(
        &state,
        &[
            "audit",
            "feedback",
            "--event-id",
            &missing,
            "--expectation",
            "expected",
            "--json"
        ]
    )
    .status
    .success());
    let root = tirith_core::policy::state_dir().unwrap();
    assert!(!root.join("operations").exists());
    let destination = root.join("feedback").join(format!("{id}.json"));
    std::fs::create_dir_all(destination.parent().unwrap()).unwrap();
    std::fs::write(
        &destination,
        "{\"schema_version\":99,\"future_field\":\"preserve\"}",
    )
    .unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&destination, std::fs::Permissions::from_mode(0o600)).unwrap();
    }
    let before = std::fs::read(&destination).unwrap();
    assert!(!run(
        &state,
        &[
            "audit",
            "feedback",
            "--event-id",
            &id,
            "--expectation",
            "expected",
            "--json"
        ]
    )
    .status
    .success());
    assert_eq!(std::fs::read(&destination).unwrap(), before);
}
