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

fn invoke_health_command(state: &GlobalStateGuard, args: &[&str]) -> Output {
    let mut command = Command::new(env!("CARGO_BIN_EXE_tirith"));
    state.apply_to_command(&mut command);
    command
        .current_dir(&state.roots().cwd)
        .args(args)
        .output()
        .unwrap()
}

fn failed_writer_state() -> GlobalStateGuard {
    let mut state = GlobalStateGuard::new().unwrap();
    for key in ["SUDO_USER", "SUDO_UID", "TIRITH_POLICY_ROOT"] {
        state.remove_env(key);
    }
    state.set_env("TIRITH_LOG", "1");
    state.set_env("TIRITH_OFFLINE", "1");
    let log = tirith_core::audit::audit_log_path().unwrap();
    // An actual directory at the destination forces append failure on every OS,
    // without relying on root-sensitive permission bits or a full host disk.
    std::fs::create_dir_all(log).unwrap();
    state
}

#[test]
fn failed_writer_is_visible_across_processes_without_changing_the_check_verdict() {
    let state = failed_writer_state();
    let config = tirith_core::policy::config_dir().unwrap();
    std::fs::create_dir_all(&config).unwrap();
    std::fs::write(config.join("policy.yaml"), "dlp_custom_patterns: ['.+']\n").unwrap();
    let notice = tirith_core::policy::state_dir()
        .unwrap()
        .join("audit-append-failure-v1.json");
    // The real notice writer deliberately waits only 25 ms. Other processes
    // share the Unix setup lock, so one failed append need not persist a notice.
    // Retry the same inert check within a fixed budget, checking the actual
    // verdict and privacy on EVERY attempt; never seed a notice in the fixture.
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
    let mut attempts = 0;
    let captured = loop {
        attempts += 1;
        let checked = invoke_health_command(
            &state,
            &[
                "check",
                "--json",
                "--shell",
                "posix",
                "--no-daemon",
                "--",
                "echo private-health-fixture",
            ],
        );
        let stderr = String::from_utf8_lossy(&checked.stderr);
        assert!(checked.status.success(), "attempt {attempts}: {stderr}");
        assert_eq!(
            serde_json::from_slice::<Value>(&checked.stdout).unwrap()["action"],
            "allow",
            "attempt {attempts}: {stderr}"
        );
        assert!(
            stderr.contains("audit append failed; recorded history may be incomplete"),
            "attempt {attempts}: {stderr}"
        );
        assert!(
            !stderr.contains("private-health-fixture"),
            "attempt {attempts}"
        );
        assert!(
            !String::from_utf8_lossy(&checked.stdout).contains("private-health-fixture"),
            "attempt {attempts}"
        );
        match std::fs::read(&notice) {
            Ok(bytes) => break bytes,
            Err(error) => {
                assert_eq!(
                    error.kind(),
                    std::io::ErrorKind::NotFound,
                    "attempt {attempts}: notice unavailable: {error}"
                );
                assert!(
                    std::time::Instant::now() < deadline && attempts < 16,
                    "no best-effort notice persisted after {attempts} actual checks: {error}; {stderr}"
                );
                std::thread::sleep(std::time::Duration::from_millis(25));
            }
        }
    };
    assert!(captured.len() <= 1024);
    assert!(!String::from_utf8_lossy(&captured).contains("private-health-fixture"));
    for args in [
        vec!["audit", "recent", "--json"],
        vec!["status", "--json"],
        vec!["doctor", "--json"],
    ] {
        let result = invoke_health_command(&state, &args);
        // An unreadable history is allowed to return nonzero with its typed DTO.
        let value: Value = serde_json::from_slice(&result.stdout).unwrap_or_else(|error| {
            panic!(
                "{args:?}: {error}; stdout={} stderr={}",
                String::from_utf8_lossy(&result.stdout),
                String::from_utf8_lossy(&result.stderr)
            )
        });
        let health = &value["audit_recording"];
        assert_eq!(health["schema_version"], 1, "{args:?}: {value}");
        assert_eq!(health["state"], "failure_observed");
        assert_eq!(health["source"], "private_failure_notice");
        assert_eq!(health["claims_current_success"], false);
        assert_eq!(health["detects_all_losses"], false);
        assert!(uuid::Uuid::parse_str(
            health["failure_observation"]["observation_id"]
                .as_str()
                .unwrap()
        )
        .is_ok());
        assert!(!health.to_string().contains("destination_binding"));
    }
    assert_eq!(
        std::fs::read(notice).unwrap(),
        captured,
        "health readers must not rewrite the observation"
    );
}

#[test]
fn unavailable_notice_storage_does_not_turn_a_missing_observation_into_success() {
    let state = failed_writer_state();
    let destination = tirith_core::policy::state_dir().unwrap();
    std::fs::create_dir_all(destination.parent().unwrap()).unwrap();
    std::fs::write(&destination, b"retained-sentinel").unwrap();
    let checked = invoke_health_command(
        &state,
        &[
            "check",
            "--json",
            "--shell",
            "posix",
            "--no-daemon",
            "--",
            "echo inert",
        ],
    );
    assert!(
        checked.status.success(),
        "{}",
        String::from_utf8_lossy(&checked.stderr)
    );
    assert!(String::from_utf8_lossy(&checked.stderr).contains("audit append failed"));
    let result = run(&state, &[]);
    let value: Value = serde_json::from_slice(&result.stdout).unwrap();
    assert_eq!(value["audit_recording"]["state"], "unknown");
    assert_eq!(value["audit_recording"]["claims_current_success"], false);
    assert_eq!(value["audit_recording"]["detects_all_losses"], false);
    assert_eq!(std::fs::read(destination).unwrap(), b"retained-sentinel");
}
