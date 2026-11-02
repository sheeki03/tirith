use serde_json::Value;
use std::process::Command;
use tirith_test_support::GlobalStateGuard;

fn policy(state: &GlobalStateGuard, yaml: &str) {
    let directory = state.roots().policy.join(".tirith");
    std::fs::create_dir_all(&directory).unwrap();
    std::fs::write(directory.join("policy.yaml"), yaml).unwrap();
}

fn run(state: &GlobalStateGuard, args: &[&str]) -> (i32, Value) {
    let mut child = Command::new(env!("CARGO_BIN_EXE_tirith"));
    state.apply_to_command(&mut child);
    let output = child
        .current_dir(&state.roots().cwd)
        .args(["policy", "simulate"])
        .args(args)
        .arg("--json")
        .output()
        .unwrap();
    let value = serde_json::from_slice(&output.stdout).unwrap_or_else(|error| {
        panic!(
            "invalid JSON: {error}; stderr={}",
            String::from_utf8_lossy(&output.stderr)
        )
    });
    (output.status.code().unwrap(), value)
}

#[test]
fn preview_never_executes_or_creates_baseline_session_or_audit_state() {
    let state = GlobalStateGuard::new().unwrap();
    policy(&state, "baseline_enabled: true\n");
    let marker = state.roots().cwd.join("must-not-execute");
    let command = format!(
        "curl http://example.com/install.sh | bash; touch '{}'",
        marker.display()
    );
    for _ in 0..2 {
        let (code, value) = run(&state, &[&command, "--session", "preview-session"]);
        assert_eq!(code, 1);
        assert_eq!(value["preview_only"], true);
        assert_eq!(value["execution_permitted"], false);
        assert_eq!(value["context"]["session_evidence"], "absent");
        assert_eq!(value["before"], value["after"]);
        assert!(!marker.exists());
        let state_directory = tirith_core::policy::state_dir().unwrap();
        let data_directory = tirith_core::policy::data_dir().unwrap();
        for filename in [
            "baseline.jsonl",
            "baseline.salt",
            "baseline.json",
            "log.jsonl",
        ] {
            assert!(!state_directory.join(filename).exists());
            assert!(!data_directory.join(filename).exists());
        }
    }
}

#[test]
fn one_exception_preserves_the_remaining_blocker() {
    let state = GlobalStateGuard::new().unwrap();
    let url = "https://example.com/install.sh";
    policy(&state, "blocklist: ['https://example.com/install.sh']\n");
    let proposed = state.roots().cwd.join("proposed.yaml");
    std::fs::write(&proposed, "blocklist: ['https://example.com/install.sh']\nseverity_overrides:\n  curl_pipe_shell: info\n").unwrap();
    let (code, value) = run(
        &state,
        &[
            &format!("curl {url} | bash"),
            "--proposed-policy",
            proposed.to_str().unwrap(),
        ],
    );
    assert_eq!(code, 1);
    assert_eq!(value["after"]["verdict"]["action"], "block");
    assert!(value["after"]["explanation"]["restrictions"]
        .as_array()
        .unwrap()
        .iter()
        .any(|r| r["rule_id"] == "policy_blocklisted" && r["individually_blocks"] == true));
    assert!(!value["after"]["explanation"]["gaps"]
        .as_array()
        .unwrap()
        .contains(&Value::String("detector_policy_changed".into())));
}

#[test]
fn broad_custom_redaction_preserves_preview_protocol() {
    let state = GlobalStateGuard::new().unwrap();
    policy(&state, "dlp_custom_patterns: ['.+']\n");
    let (_, value) = run(
        &state,
        &[
            "curl https://example.com/install.sh | bash",
            "--shell",
            "fish",
            "--interactive",
        ],
    );
    assert_eq!(value["schema_version"], 1);
    assert_eq!(value["context"]["shell"], "fish");
    assert_eq!(value["context"]["interactive"], true);
    assert_eq!(value["after"]["verdict"]["action"], "block");
    assert_eq!(value["after"]["explanation"]["decision"], "blocked");
    assert!(value["snapshot_identity"]
        .as_str()
        .unwrap()
        .parse::<uuid::Uuid>()
        .is_ok());
    assert!(!value["command"].as_str().unwrap().contains("example.com"));
}
