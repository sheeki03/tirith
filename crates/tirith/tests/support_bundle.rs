//! Explicit selection, fresh privacy projection, and private export boundaries.
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
        "stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).unwrap()
}
fn state() -> GlobalStateGuard {
    let mut state = GlobalStateGuard::new().unwrap();
    for key in ["SUDO_USER", "SUDO_UID", "TIRITH_POLICY_ROOT"] {
        state.remove_env(key);
    }
    state.set_env("TIRITH_OFFLINE", "1");
    state
}

#[test]
fn home_substitution_cannot_bypass_custom_dlp_and_large_unselected_rows_do_not_hide_selection() {
    let mut state = state();
    let sensitive_path = format!(
        "{}/private-suffix-never-export",
        state.roots().home.display()
    );
    state.set_env("TERM_PROGRAM", &sensitive_path);
    let config = tirith_core::policy::config_dir().unwrap();
    std::fs::create_dir_all(&config).unwrap();
    std::fs::write(
        config.join("policy.yml"),
        serde_yaml::to_string(&json!({"dlp_custom_patterns":[regex::escape(&sensitive_path)]}))
            .unwrap(),
    )
    .unwrap();
    let selected = uuid::Uuid::new_v4().to_string();
    let audit = tirith_core::audit::audit_log_path().unwrap();
    std::fs::create_dir_all(audit.parent().unwrap()).unwrap();
    let record = |id: String, command: String| json!({"timestamp":"2026-09-12T00:00:00Z","action":"Block","event_id":id,"command_redacted":command});
    std::fs::write(
        &audit,
        format!(
            "{}\n{}\n",
            record(uuid::Uuid::new_v4().to_string(), "x".repeat(400 * 1024)),
            record(selected.clone(), "selected-small-record".into())
        ),
    )
    .unwrap();
    let report = success(run(
        &state,
        &[
            "doctor",
            "--bundle",
            "--bundle-preview",
            "--bundle-incident",
            &selected,
            "--json",
        ],
    ));
    assert!(!report.to_string().contains("private-suffix-never-export"));
    assert_eq!(report["incidents"][0]["availability"], "available");
    assert_eq!(
        report["incidents"][0]["content"]["record"]["command_redacted"],
        "selected-small-record"
    );
}

#[test]
fn preview_selects_only_requested_incidents_and_uses_fresh_dlp() {
    let mut state = state();
    state.set_env("TERM_PROGRAM", "support-secret-visible-before-policy");
    let config = tirith_core::policy::config_dir().unwrap();
    std::fs::create_dir_all(&config).unwrap();
    let path = config.join("policy.yml");
    std::fs::write(
        &path,
        "dlp_custom_patterns:\n  - 'support-secret-[a-z-]+'\n",
    )
    .unwrap();
    let selected = uuid::Uuid::new_v4().to_string();
    let excluded = uuid::Uuid::new_v4().to_string();
    let audit = tirith_core::audit::audit_log_path().unwrap();
    std::fs::create_dir_all(audit.parent().unwrap()).unwrap();
    let record = |id: &str, command: &str| json!({"timestamp":"2026-09-12T00:00:00Z","action":"Block","event_id":id,"command_redacted":command});
    let original = format!(
        "{}\n{}\n",
        record(&selected, "echo support-secret-command"),
        record(&excluded, "unselected-private-command")
    );
    std::fs::write(&audit, &original).unwrap();
    let report = success(run(
        &state,
        &[
            "doctor",
            "--bundle",
            "--bundle-preview",
            "--bundle-incident",
            &selected,
            "--json",
        ],
    ));
    let encoded = report.to_string();
    assert_eq!(report["incidents"].as_array().unwrap().len(), 1);
    assert_eq!(report["incidents"][0]["id"], selected);
    assert!(!encoded.contains("support-secret-"));
    assert!(!encoded.contains("unselected-private-command"));
    assert!(!tirith_core::policy::state_dir()
        .unwrap()
        .join("support")
        .exists());
    assert!(!tirith_core::policy::state_dir()
        .unwrap()
        .join("operations")
        .exists());
    assert_eq!(std::fs::read_to_string(&audit).unwrap(), original);
    assert!(encoded.len() <= 256 * 1024);
    assert_eq!(report["shared"], false);
    // Additional restrictions are applied on the next preview, even though the
    // retained audit bytes did not change.
    std::fs::write(
        &path,
        "dlp_custom_patterns:\n  - 'support-secret-[a-z-]+'\n  - 'echo'\n",
    )
    .unwrap();
    let fresh = success(run(
        &state,
        &[
            "doctor",
            "--bundle",
            "--bundle-preview",
            "--bundle-incident",
            &selected,
            "--json",
        ],
    ));
    assert!(!fresh["incidents"].to_string().contains("echo"));
}

#[test]
fn selected_operation_is_read_without_replaying_and_export_is_private() {
    let state = state();
    let applied = success(run(&state, &["policy", "profile", "balanced", "--json"]));
    let id = applied["operation_id"].as_str().unwrap();
    let root = tirith_core::policy::state_dir().unwrap();
    let journal = root.join("operations").join(format!("{id}.json"));
    let before = std::fs::read(&journal).unwrap();
    let report = success(run(
        &state,
        &[
            "doctor",
            "--bundle",
            "--bundle-preview",
            "--bundle-operation",
            id,
            "--json",
        ],
    ));
    assert_eq!(report["operations"][0]["content"]["operation_id"], id);
    assert_eq!(std::fs::read(&journal).unwrap(), before);
    let saved = success(run(
        &state,
        &["doctor", "--bundle", "--bundle-operation", id, "--json"],
    ));
    assert_eq!(saved["shared"], false);
    let files: Vec<_> = std::fs::read_dir(root.join("support"))
        .unwrap()
        .map(|e| e.unwrap().path())
        .filter(|p| p.extension().is_some_and(|e| e == "json"))
        .collect();
    assert_eq!(files.len(), 1);
    let bytes = std::fs::read(&files[0]).unwrap();
    assert!(bytes.len() <= 256 * 1024);
    assert_eq!(
        serde_json::from_slice::<Value>(&bytes).unwrap()["operations"][0]["id"],
        id
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            std::fs::metadata(&files[0]).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }
    assert_eq!(std::fs::read(&journal).unwrap(), before);
    assert!(!run(
        &state,
        &[
            "doctor",
            "--bundle",
            "--bundle-preview",
            "--bundle-operation",
            "../policy.yaml",
            "--json"
        ]
    )
    .status
    .success());
}

#[cfg(unix)]
#[test]
fn export_refuses_symlinked_support_directory() {
    let state = state();
    let root = tirith_core::policy::state_dir().unwrap();
    std::fs::create_dir_all(&root).unwrap();
    let outside = state.roots().cwd.join("outside");
    std::fs::create_dir(&outside).unwrap();
    std::os::unix::fs::symlink(&outside, root.join("support")).unwrap();
    assert!(!run(&state, &["doctor", "--bundle", "--json"])
        .status
        .success());
    assert_eq!(std::fs::read_dir(&outside).unwrap().count(), 0);
}
