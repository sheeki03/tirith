//! Profile changes use the same durable operation service as other controls.
use std::process::{Command, Output};

use serde_json::Value;
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
    state.remove_env("TIRITH_POLICY_ROOT");
    state.remove_env("SUDO_USER");
    state.remove_env("SUDO_UID");
    state
}

#[test]
fn preview_is_read_only_and_apply_targets_personal_policy() {
    let state = state();
    let config = tirith_core::policy::config_dir().unwrap();
    let policy = config.join("policy.yaml");
    let repo = state.roots().cwd.join(".tirith");
    std::fs::create_dir_all(&repo).unwrap();
    std::fs::create_dir_all(state.roots().cwd.join(".git")).unwrap();
    let repo_policy = "paranoia: 3\nstrict_warn: true\n";
    std::fs::write(repo.join("policy.yaml"), repo_policy).unwrap();
    let preview = success(run(
        &state,
        &["policy", "profile", "balanced", "--dry-run", "--json"],
    ));
    assert_eq!(preview["applied"], false);
    assert!(!policy.exists());
    let applied = success(run(&state, &["policy", "profile", "balanced", "--json"]));
    assert_eq!(applied["state"], "completed");
    let document: serde_yaml::Value =
        serde_yaml::from_str(&std::fs::read_to_string(&policy).unwrap()).unwrap();
    assert_eq!(
        document["protection_profile"]["name"].as_str(),
        Some("balanced")
    );
    assert_eq!(
        std::fs::read_to_string(repo.join("policy.yaml")).unwrap(),
        repo_policy
    );
    let effective = success(run(&state, &["policy", "effective", "--runtime", "--json"]));
    assert_eq!(effective["policy"]["paranoia"], 3);
    assert_eq!(effective["policy"]["strict_warn"], true);
    let id = applied["operation_id"].as_str().unwrap();
    assert!(uuid::Uuid::parse_str(id).is_ok());
    let retry = success(run(
        &state,
        &["policy", "operation", id, "--action", "apply", "--json"],
    ));
    assert_eq!(retry["operation_id"], id);
    assert_eq!(retry["state"], "completed");
}

#[test]
fn reset_preserves_custom_settings_and_undo_preserves_unrelated_edits() {
    let state = state();
    let config = tirith_core::policy::config_dir().unwrap();
    std::fs::create_dir_all(&config).unwrap();
    let path = config.join("policy.yaml");
    std::fs::write(
        &path,
        "severity_overrides:\n  non_standard_port: HIGH\ncustom_operator_note: keep-me\n",
    )
    .unwrap();
    let applied = success(run(&state, &["policy", "profile", "balanced", "--json"]));
    let mut current: serde_yaml::Value =
        serde_yaml::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
    assert_eq!(
        current["severity_overrides"]["non_standard_port"].as_str(),
        Some("HIGH")
    );
    current["another_operator_note"] = "preserve-this-too".into();
    std::fs::write(&path, serde_yaml::to_string(&current).unwrap()).unwrap();
    let id = applied["operation_id"].as_str().unwrap();
    let undone = success(run(
        &state,
        &["policy", "operation", id, "--action", "undo", "--json"],
    ));
    assert_eq!(
        undone["state"],
        if cfg!(windows) {
            "undone-with-recovery"
        } else {
            "undone"
        }
    );
    let undone: serde_yaml::Value =
        serde_yaml::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
    assert_eq!(
        undone["another_operator_note"].as_str(),
        Some("preserve-this-too")
    );
    assert_eq!(undone["custom_operator_note"].as_str(), Some("keep-me"));
    assert_eq!(
        undone["severity_overrides"]["non_standard_port"].as_str(),
        Some("HIGH")
    );
    assert!(undone.get("protection_profile").is_none());
    success(run(&state, &["policy", "profile", "balanced", "--json"]));
    success(run(&state, &["policy", "profile", "reset", "--json"]));
    let reset: serde_yaml::Value =
        serde_yaml::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
    assert_eq!(
        reset["severity_overrides"]["non_standard_port"].as_str(),
        Some("HIGH")
    );
    assert_eq!(
        reset["another_operator_note"].as_str(),
        Some("preserve-this-too")
    );
    assert!(reset.get("protection_profile").is_none());
}

#[test]
fn profile_respects_yml_and_yaml_precedence_without_shadowing_settings() {
    let state = state();
    let config = tirith_core::policy::config_dir().unwrap();
    std::fs::create_dir_all(&config).unwrap();
    let yml = config.join("policy.yml");
    let yaml = config.join("policy.yaml");
    std::fs::write(&yml, "custom_operator_note: preserve-yml\n").unwrap();
    success(run(&state, &["policy", "profile", "balanced", "--json"]));
    assert!(!yaml.exists(), "must not shadow an existing yml policy");
    let content = std::fs::read_to_string(&yml).unwrap();
    assert!(content.contains("preserve-yml"));
    assert!(content.contains("protection_profile"));
    std::fs::write(&yaml, "custom_operator_note: preferred-yaml\n").unwrap();
    success(run(&state, &["policy", "profile", "strict", "--json"]));
    assert_eq!(std::fs::read_to_string(&yml).unwrap(), content);
    let content = std::fs::read_to_string(&yaml).unwrap();
    assert!(content.contains("preferred-yaml"));
    assert!(content.contains("strict"));
}

#[cfg(unix)]
#[test]
fn dangling_preferred_policy_is_refused_without_modifying_fallback() {
    let state = state();
    let config = tirith_core::policy::config_dir().unwrap();
    std::fs::create_dir_all(&config).unwrap();
    let yml = config.join("policy.yml");
    std::fs::write(&yml, "paranoia: 3\n").unwrap();
    std::os::unix::fs::symlink(config.join("missing"), config.join("policy.yaml")).unwrap();
    let result = run(&state, &["policy", "profile", "balanced", "--json"]);
    assert!(!result.status.success());
    assert_eq!(std::fs::read_to_string(yml).unwrap(), "paranoia: 3\n");
}

#[test]
fn unselected_user_dlp_protects_profile_validation_errors_before_preview_exists() {
    let mut state = state();
    let org_root = state.roots().policy.clone();
    state.set_env("TIRITH_POLICY_ROOT", &org_root);
    let org = org_root.join(".tirith");
    let config = tirith_core::policy::config_dir().unwrap();
    std::fs::create_dir_all(&org).unwrap();
    std::fs::create_dir_all(&config).unwrap();
    std::fs::write(org.join("policy.yaml"), "paranoia: 2\n").unwrap();
    let original = "dlp_custom_patterns: [PROFILE_PRIVATE]\nfail_mode: PROFILE_PRIVATE\n";
    let user = config.join("policy.yml");
    std::fs::write(&user, original).unwrap();
    let result = run(
        &state,
        &["policy", "profile", "balanced", "--dry-run", "--json"],
    );
    assert!(!result.status.success());
    let output = format!(
        "{}{}",
        String::from_utf8_lossy(&result.stdout),
        String::from_utf8_lossy(&result.stderr)
    );
    assert!(!output.contains("PROFILE_PRIVATE"), "{output}");
    assert!(
        output.contains("REDACTED"),
        "validation error should be useful after redaction: {output}"
    );
    assert_eq!(std::fs::read_to_string(&user).unwrap(), original);
    assert!(!config.join("policy.yaml").exists());
}

#[test]
fn explicit_equal_profile_setting_survives_later_profile_reset() {
    let state = state();
    success(run(&state, &["policy", "profile", "strict", "--json"]));
    let path = tirith_core::policy::config_dir()
        .unwrap()
        .join("policy.yaml");
    let before = std::fs::read(&path).unwrap();
    let preview = success(run(
        &state,
        &[
            "policy",
            "setting",
            "strict_warn",
            "true",
            "--dry-run",
            "--json",
        ],
    ));
    assert_eq!(preview["kind"], "personal_setting_preview");
    assert_eq!(std::fs::read(&path).unwrap(), before);
    let changed = success(run(
        &state,
        &["policy", "setting", "strict_warn", "true", "--json"],
    ));
    assert_eq!(
        changed["state"],
        if cfg!(windows) {
            "completed-with-recovery"
        } else {
            "completed"
        }
    );
    let document: serde_yaml::Value =
        serde_yaml::from_slice(&std::fs::read(&path).unwrap()).unwrap();
    assert!(!document["protection_profile"]["owned_fields"]
        .as_sequence()
        .unwrap()
        .iter()
        .any(|field| field.as_str() == Some("strict_warn")));
    success(run(&state, &["policy", "profile", "reset", "--json"]));
    let document: serde_yaml::Value =
        serde_yaml::from_slice(&std::fs::read(&path).unwrap()).unwrap();
    assert_eq!(document["strict_warn"], true);
    assert!(document.get("protection_profile").is_none());
}

#[test]
fn personal_setting_undo_preserves_unrelated_changes_and_typed_limits() {
    let state = state();
    let path = tirith_core::policy::config_dir()
        .unwrap()
        .join("policy.yml");
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(&path, "strict_warn: true\ncustom_operator_note: before\n").unwrap();
    let changed = success(run(
        &state,
        &["policy", "setting", "strict_warn", "false", "--json"],
    ));
    let mut document: serde_yaml::Value =
        serde_yaml::from_slice(&std::fs::read(&path).unwrap()).unwrap();
    document["custom_operator_note"] = "after".into();
    std::fs::write(&path, serde_yaml::to_string(&document).unwrap()).unwrap();
    let undone = success(run(
        &state,
        &[
            "policy",
            "operation",
            changed["operation_id"].as_str().unwrap(),
            "--action",
            "undo",
            "--json",
        ],
    ));
    assert_eq!(
        undone["state"],
        if cfg!(windows) {
            "undone-with-recovery"
        } else {
            "undone"
        }
    );
    let document: serde_yaml::Value =
        serde_yaml::from_slice(&std::fs::read(&path).unwrap()).unwrap();
    assert_eq!(document["strict_warn"], true);
    assert_eq!(document["custom_operator_note"], "after");
    let before = std::fs::read(&path).unwrap();
    assert!(
        !run(&state, &["policy", "setting", "paranoia", "0", "--json"])
            .status
            .success()
    );
    assert!(!run(
        &state,
        &["policy", "setting", "strict_warn", "maybe", "--json"]
    )
    .status
    .success());
    assert_eq!(std::fs::read(&path).unwrap(), before);
    success(run(
        &state,
        &["policy", "setting", "paranoia", "4", "--dry-run", "--json"],
    ));
}

#[test]
fn empty_personal_document_accepts_a_typed_setting_without_shadowing() {
    let state = state();
    let path = tirith_core::policy::config_dir()
        .unwrap()
        .join("policy.yml");
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(&path, "  \n").unwrap();
    let changed = success(run(
        &state,
        &["policy", "setting", "strict_warn", "true", "--json"],
    ));
    assert_eq!(
        changed["state"],
        if cfg!(windows) {
            "completed-with-recovery"
        } else {
            "completed"
        }
    );
    assert!(!path.with_file_name("policy.yaml").exists());
    let doc: serde_yaml::Value = serde_yaml::from_slice(&std::fs::read(&path).unwrap()).unwrap();
    assert_eq!(doc["strict_warn"], true);
}
