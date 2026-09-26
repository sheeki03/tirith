use serde_json::{json, Value};
use std::process::Command;
use tirith_test_support::GlobalStateGuard;

fn run(state: &GlobalStateGuard, args: &[&str]) -> Value {
    let mut command = Command::new(env!("CARGO_BIN_EXE_tirith"));
    state.apply_to_command(&mut command);
    let output = command
        .current_dir(&state.roots().cwd)
        .args(args)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).unwrap()
}

#[test]
fn tuning_bounds_history_preserves_protocol_and_reads_labels_without_relaxation() {
    let mut state = GlobalStateGuard::new().unwrap();
    state.set_env("TIRITH_OFFLINE", "1");
    for key in ["SUDO_USER", "SUDO_UID", "TIRITH_POLICY_ROOT"] {
        state.remove_env(key);
    }
    let config = tirith_core::policy::config_dir().unwrap();
    std::fs::create_dir_all(&config).unwrap();
    let policy = "dlp_custom_patterns: ['.+']\n";
    std::fs::write(config.join("policy.yml"), policy).unwrap();
    let id = uuid::Uuid::new_v4().to_string();
    let log = tirith_core::audit::audit_log_path().unwrap();
    std::fs::create_dir_all(log.parent().unwrap()).unwrap();
    let mut original = String::new();
    for index in 0..600 {
        let event_id = if index == 599 {
            id.clone()
        } else {
            uuid::Uuid::new_v4().to_string()
        };
        original.push_str(&format!("{}\n", json!({"timestamp":"2026-09-12T00:00:00Z","event_id":event_id,
            "action":"Block","rule_ids":["curl_pipe_shell"],"command_redacted":format!("operator-private-command-{index}")})));
    }
    std::fs::write(&log, &original).unwrap();
    run(
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
    );
    let report = run(
        &state,
        &["policy", "tune", "--from-audit", "--format", "json"],
    );
    assert_eq!(report["kind"], "policy_tuning_review");
    assert_eq!(report["records_analyzed"], 500);
    assert_eq!(report["coverage"]["earlier_history_uninspected"], true);
    assert_eq!(report["rule_stats"][0]["rule_id"], "curl_pipe_shell");
    assert_eq!(report["rule_stats"][0]["blocked"], 500);
    assert!(report["suggestions"].as_array().unwrap().is_empty());
    assert_eq!(
        report["annotations"]["entries"][0]["expectation"],
        "expected"
    );
    assert_eq!(report["annotations"]["policy_changed"], false);
    assert_eq!(report["automatic_approval"], false);
    assert!(!report.to_string().contains("operator-private-command"));
    assert!(serde_json::to_vec_pretty(&report).unwrap().len() <= 256 * 1024);
    assert_eq!(std::fs::read_to_string(&log).unwrap(), original);
    assert_eq!(
        std::fs::read_to_string(config.join("policy.yml")).unwrap(),
        policy
    );
    assert!(!config.join("trust.json").exists());

    let recent = run(&state, &["audit", "recent", "--limit", "10", "--json"]);
    assert_eq!(recent["annotations"]["entries"][0]["event_id"], id);
    assert_eq!(
        recent["annotations"]["entries"][0]["expectation"],
        "expected"
    );
    let annotation = tirith_core::policy::state_dir()
        .unwrap()
        .join("feedback")
        .join(format!("{id}.json"));
    let broken = b"{\"unrecognized_future_annotation\":true}";
    std::fs::write(&annotation, broken).unwrap();
    let recent = run(&state, &["audit", "recent", "--limit", "10", "--json"]);
    assert_eq!(
        recent["annotations"]["entries"][0]["availability"],
        "unavailable"
    );
    assert_eq!(std::fs::read(annotation).unwrap(), broken);
}

#[test]
fn duplicated_event_id_never_selects_an_arbitrary_annotation() {
    let mut state = GlobalStateGuard::new().unwrap();
    state.set_env("TIRITH_OFFLINE", "1");
    let id = uuid::Uuid::new_v4().to_string();
    let record = json!({"timestamp":"2026-09-12T00:00:00Z","event_id":id,"action":"Block"});
    let log = tirith_core::audit::audit_log_path().unwrap();
    std::fs::create_dir_all(log.parent().unwrap()).unwrap();
    std::fs::write(log, format!("{record}\n{record}\n")).unwrap();
    let report = run(
        &state,
        &["policy", "tune", "--from-audit", "--format", "json"],
    );
    assert_eq!(
        report["annotations"]["coverage"]["ambiguous_or_invalid_ids"],
        2
    );
    assert!(report["annotations"]["entries"]
        .as_array()
        .unwrap()
        .is_empty());
    assert!(!tirith_core::policy::state_dir()
        .unwrap()
        .join("feedback")
        .exists());
}

#[test]
fn human_tuning_neutralizes_hostile_rule_ids_in_counts_and_suggestions() {
    let mut state = GlobalStateGuard::new().unwrap();
    state.set_env("TIRITH_OFFLINE", "1");
    let log = tirith_core::audit::audit_log_path().unwrap();
    std::fs::create_dir_all(log.parent().unwrap()).unwrap();
    let hostile = "rule\u{1b}]52;c;ZmFrZQ==\u{7}\rforged-row";
    for action in ["Block", "Allow"] {
        let rows = (0..25)
            .map(|_| {
                format!(
                    "{}\n",
                    json!({"timestamp":"2026-09-12T00:00:00Z",
            "action":action,"rule_ids":[hostile],"command_redacted":"inert-example"})
                )
            })
            .collect::<String>();
        std::fs::write(&log, &rows).unwrap();
        let mut command = Command::new(env!("CARGO_BIN_EXE_tirith"));
        state.apply_to_command(&mut command);
        let output = command
            .current_dir(&state.roots().cwd)
            .args(["policy", "tune", "--from-audit"])
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        for bytes in [&output.stdout, &output.stderr] {
            assert!(!bytes.contains(&0x1b), "terminal escape survived");
            assert!(!bytes.contains(&0x07), "terminal bell survived");
            assert!(!bytes.contains(&b'\r'), "carriage return survived");
        }
        assert_eq!(std::fs::read_to_string(&log).unwrap(), rows);
    }
}
