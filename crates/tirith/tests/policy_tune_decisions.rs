//! Tuning must distinguish observed friction from a recommendation to relax policy.

use std::fs;
use std::process::{Command, Output};

fn run_tune(record_count: usize, action: &str, json: bool) -> Output {
    let root = tempfile::tempdir().expect("temporary environment");
    let data = root.path().join("data");
    fs::create_dir_all(data.join("tirith")).unwrap();
    let record = serde_json::json!({
        "timestamp": "2026-05-20T10:00:00Z",
        "session_id": "isolated-tuning-test",
        "action": action,
        "rule_ids": ["curl_pipe_shell", "curl_pipe_shell"],
        "command_redacted": "cmd",
        "bypass_requested": false,
        "bypass_honored": false,
        "interactive": true,
        "tier_reached": 3,
        "entry_type": "verdict"
    });
    let log = format!("{record}\n").repeat(record_count);
    fs::write(data.join("tirith/log.jsonl"), &log).unwrap();
    let mut command = Command::new(env!("CARGO_BIN_EXE_tirith"));
    command
        .current_dir(root.path())
        .env("HOME", root.path())
        .env("USERPROFILE", root.path())
        .env("XDG_CONFIG_HOME", root.path().join("config"))
        .env("XDG_DATA_HOME", &data)
        .env("XDG_STATE_HOME", root.path().join("state"))
        .env("XDG_CACHE_HOME", root.path().join("cache"))
        .env("XDG_RUNTIME_DIR", root.path().join("runtime"))
        .env("APPDATA", &data)
        .env("LOCALAPPDATA", root.path().join("localappdata"))
        .env("TIRITH_LOG", "0")
        .env("NO_COLOR", "1")
        .args(["policy", "tune", "--from-audit"]);
    for key in [
        "TIRITH",
        "TIRITH_POLICY_ROOT",
        "TIRITH_SERVER_URL",
        "TIRITH_API_KEY",
        "TIRITH_LICENSE",
        "TIRITH_AUDIT_DEBUG",
        "TIRITH_SESSION_ID",
    ] {
        command.env_remove(key);
    }
    if json {
        command.args(["--format", "json"]);
    }
    let output = command.output().expect("run tune");
    assert_eq!(output.status.code(), Some(0), "{:?}", output);
    assert_eq!(
        fs::read_to_string(data.join("tirith/log.jsonl")).unwrap(),
        log
    );
    assert!(!root.path().join(".tirith/policy.yaml").exists());
    assert!(!root.path().join("config/tirith/policy.yaml").exists());
    output
}

#[test]
fn recurring_blocks_are_visible_with_or_without_enough_history_for_recommendations() {
    for record_count in [5, 25] {
        let output = run_tune(record_count, "Block", false);
        assert!(output.stdout.is_empty());
        let text = String::from_utf8(output.stderr).unwrap();
        assert!(text.contains("Recurring blocked checks"), "{text}");
        assert!(
            text.contains(&format!(
                "curl_pipe_shell: {record_count} blocked / {record_count} checks"
            )),
            "{text}"
        );
        assert!(text.contains("No safe relaxation is established"), "{text}");
        assert!(!text.contains("well matched"), "{text}");
        if record_count < 20 {
            assert!(text.contains("not enough audit history"), "{text}");
        } else {
            assert!(text.contains("No policy changes suggested"), "{text}");
        }
    }
}

#[test]
fn tuning_guidance_requires_an_authorized_policy_target() {
    let output = run_tune(25, "Allow", false);
    let text = String::from_utf8(output.stderr).unwrap();
    assert!(text.contains("tirith policy effective --runtime"), "{text}");
    assert!(
        text.contains("Repository policy cannot lower severity or suppress findings"),
        "{text}"
    );
    assert!(!text.contains("editing your .tirith/policy.yaml"), "{text}");
    assert!(
        text.contains("not confirmed execution or validated false positives"),
        "{text}"
    );
}

#[test]
fn blocked_tuning_json_retains_the_existing_counts_and_suggestion_contract() {
    let output = run_tune(25, "Block", true);
    let value: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(value["records_analyzed"], 25);
    assert_eq!(value["data_is_thin"], false);
    assert_eq!(value["suggestions"], serde_json::json!([]));
    assert_eq!(value["rule_stats"][0]["rule_id"], "curl_pipe_shell");
    assert_eq!(value["rule_stats"][0]["blocked"], 25);
    assert_eq!(value["rule_stats"][0]["total"], 25);
}
