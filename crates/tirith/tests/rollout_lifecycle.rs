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

#[cfg(unix)]
mod managed {
    use super::*;
    use std::os::unix::fs::PermissionsExt;
    use std::path::PathBuf;

    fn prepare(state: &GlobalStateGuard, id: &str) -> Output {
        run(
            state,
            &[
                "policy",
                "rollout",
                "prepare",
                "balanced",
                "--scope",
                "org",
                "--command",
                "touch SHOULD_NOT_EXIST",
                "--operation-id",
                id,
                "--json",
            ],
        )
    }

    fn fixture() -> Option<(GlobalStateGuard, PathBuf)> {
        let mut state = GlobalStateGuard::new().unwrap();
        let root = state.roots().policy.clone();
        let directory = root.join(".tirith");
        std::fs::create_dir_all(&directory).unwrap();
        for path in [&root, &directory] {
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700)).unwrap();
        }
        // Exercise the resolver's .yml fallback, not just a hard-coded .yaml destination.
        let target = directory.join("policy.yml");
        std::fs::write(&target, "{}\n").unwrap();
        std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o600)).unwrap();
        state.set_env("TIRITH_POLICY_ROOT", &root);
        if unsafe { libc::geteuid() } == 0 || unsafe { libc::geteuid() != libc::getuid() } {
            assert!(!prepare(&state, &uuid::Uuid::new_v4().to_string())
                .status
                .success());
            assert_eq!(std::fs::read_to_string(&target).unwrap(), "{}\n");
            eprintln!("managed lifecycle requires an ordinary owner; this host exercised privileged refusal only");
            return None;
        }
        Some((state, target))
    }

    #[test]
    fn selected_organization_rollout_is_explicit_reviewed_and_reversible() {
        let Some((state, target)) = fixture() else {
            return;
        };
        let original = "# organization-owned comment\norganization_note: \"keep this spelling\"\n";
        std::fs::write(&target, original).unwrap();
        let id = uuid::Uuid::new_v4().to_string();
        let first = success(prepare(&state, &id));
        assert_eq!(first["operation"]["kind"], "set-managed-profile");
        assert_eq!(first["impact"]["scope"], "local_managed");
        assert_eq!(first["impact"]["exception_inventory_complete"], false);
        assert_eq!(first["impact"]["remote_publication_available"], false);
        assert_eq!(first["impact"]["fleet_adoption_verified"], false);
        assert_eq!(first["live"]["organization_target_effective"], true);
        assert_eq!(first["live"]["personal_target_effective"], false);
        assert_eq!(std::fs::read_to_string(&target).unwrap(), original);
        assert!(!state.roots().cwd.join("SHOULD_NOT_EXIST").exists());
        assert!(!target.with_extension("yaml").exists());
        assert!(!tirith_core::policy::config_dir()
            .unwrap()
            .join("policy.yaml")
            .exists());
        assert_eq!(success(prepare(&state, &id))["impact"], first["impact"]);
        let applied = success(run(
            &state,
            &["policy", "rollout", "activate", &id, "--json"],
        ));
        assert_eq!(applied["operation"]["state"], "completed");
        let document: serde_yaml::Value =
            serde_yaml::from_str(&std::fs::read_to_string(&target).unwrap()).unwrap();
        assert_eq!(
            document["protection_profile"]["name"].as_str(),
            Some("balanced")
        );
        let published = std::fs::read(&target).unwrap();
        success(run(
            &state,
            &["policy", "rollout", "activate", &id, "--json"],
        ));
        assert_eq!(std::fs::read(&target).unwrap(), published);
        let undone = success(run(&state, &["policy", "rollout", "undo", &id, "--json"]));
        assert!(matches!(
            undone["operation"]["state"].as_str(),
            Some("undone" | "undone-with-recovery")
        ));
        let document: serde_yaml::Value =
            serde_yaml::from_str(&std::fs::read_to_string(&target).unwrap()).unwrap();
        assert!(document.get("protection_profile").is_none());
        let restored = std::fs::read(&target).unwrap();
        assert_eq!(restored, original.as_bytes());
        success(run(&state, &["policy", "rollout", "undo", &id, "--json"]));
        assert_eq!(std::fs::read(&target).unwrap(), restored);
    }

    #[test]
    fn newer_managed_generation_refuses_activation_and_rollback_without_overwrite() {
        let Some((state, target)) = fixture() else {
            return;
        };
        let id = uuid::Uuid::new_v4().to_string();
        success(prepare(&state, &id));
        let newer = "organization_note: newer\n";
        std::fs::write(&target, newer).unwrap();
        assert!(
            !run(&state, &["policy", "rollout", "activate", &id, "--json"])
                .status
                .success()
        );
        assert_eq!(std::fs::read_to_string(&target).unwrap(), newer);
        let second = uuid::Uuid::new_v4().to_string();
        success(prepare(&state, &second));
        success(run(
            &state,
            &["policy", "rollout", "activate", &second, "--json"],
        ));
        let mut document: serde_yaml::Value =
            serde_yaml::from_str(&std::fs::read_to_string(&target).unwrap()).unwrap();
        document["organization_note"] = "later unrelated managed update".into();
        let newer = serde_yaml::to_string(&document).unwrap();
        std::fs::write(&target, &newer).unwrap();
        let refusal = run(&state, &["policy", "rollout", "undo", &second, "--json"]);
        assert!(!refusal.status.success());
        assert!(
            String::from_utf8_lossy(&refusal.stdout).contains("newer managed authority document")
        );
        assert_eq!(std::fs::read_to_string(&target).unwrap(), newer);
    }

    #[test]
    fn changed_authority_and_changed_scope_cannot_retarget_a_saved_operation() {
        let Some((mut state, target)) = fixture() else {
            return;
        };
        let id = uuid::Uuid::new_v4().to_string();
        let first = success(prepare(&state, &id));
        assert!(!run(
            &state,
            &[
                "policy",
                "rollout",
                "prepare",
                "balanced",
                "--scope",
                "user",
                "--command",
                "touch SHOULD_NOT_EXIST",
                "--operation-id",
                &id,
                "--json"
            ]
        )
        .status
        .success());
        let other_root = state.roots().root.join("other-organization");
        std::fs::create_dir_all(other_root.join(".tirith")).unwrap();
        let other_target = other_root.join(".tirith/policy.yaml");
        std::fs::write(&other_target, "organization_note: other\n").unwrap();
        state.set_env("TIRITH_POLICY_ROOT", &other_root);
        // An identical retry still reports the immutable original; it is never a new publication.
        assert_eq!(success(prepare(&state, &id))["impact"], first["impact"]);
        assert!(
            !run(&state, &["policy", "rollout", "activate", &id, "--json"])
                .status
                .success()
        );
        assert_eq!(std::fs::read_to_string(&target).unwrap(), "{}\n");
        assert_eq!(
            std::fs::read_to_string(&other_target).unwrap(),
            "organization_note: other\n"
        );
    }

    #[test]
    fn root_scope_symlinks_shared_write_and_remote_configuration_refuse() {
        let Some((mut state, target)) = fixture() else {
            return;
        };
        for mode in [0o620, 0o602] {
            std::fs::set_permissions(&target, std::fs::Permissions::from_mode(mode)).unwrap();
            assert!(!prepare(&state, &uuid::Uuid::new_v4().to_string())
                .status
                .success());
        }
        std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o600)).unwrap();
        let root = state.roots().policy.clone();
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o770)).unwrap();
        assert!(!prepare(&state, &uuid::Uuid::new_v4().to_string())
            .status
            .success());
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).unwrap();
        let held = target.with_extension("held");
        std::fs::rename(&target, &held).unwrap();
        std::os::unix::fs::symlink(&held, &target).unwrap();
        assert!(!prepare(&state, &uuid::Uuid::new_v4().to_string())
            .status
            .success());
        std::fs::remove_file(&target).unwrap();
        std::fs::rename(&held, &target).unwrap();
        let alias = target.with_extension("link");
        std::fs::hard_link(&target, &alias).unwrap();
        assert!(!prepare(&state, &uuid::Uuid::new_v4().to_string())
            .status
            .success());
        std::fs::remove_file(alias).unwrap();
        state.remove_env("TIRITH_POLICY_ROOT");
        assert!(!prepare(&state, &uuid::Uuid::new_v4().to_string())
            .status
            .success());
        state.set_env("TIRITH_POLICY_ROOT", &root);
        // An incomplete environment pair is rejected without any remote fetch.
        state.set_env("TIRITH_SERVER_URL", "https://example.invalid");
        state.remove_env("TIRITH_API_KEY");
        assert!(!prepare(&state, &uuid::Uuid::new_v4().to_string())
            .status
            .success());
        assert_eq!(std::fs::read_to_string(&target).unwrap(), "{}\n");
    }

    #[test]
    fn name_precedence_and_permission_change_after_review_require_refresh() {
        let Some((state, target)) = fixture() else {
            return;
        };
        let id = uuid::Uuid::new_v4().to_string();
        success(prepare(&state, &id));
        let higher_precedence = target.with_extension("yaml");
        std::fs::write(&higher_precedence, "organization_note: replacement\n").unwrap();
        assert!(
            !run(&state, &["policy", "rollout", "activate", &id, "--json"])
                .status
                .success()
        );
        assert_eq!(std::fs::read_to_string(&target).unwrap(), "{}\n");
        std::fs::remove_file(&higher_precedence).unwrap();
        let id = uuid::Uuid::new_v4().to_string();
        success(prepare(&state, &id));
        std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o620)).unwrap();
        assert!(
            !run(&state, &["policy", "rollout", "activate", &id, "--json"])
                .status
                .success()
        );
        assert_eq!(std::fs::read_to_string(&target).unwrap(), "{}\n");
    }

    #[test]
    fn explicit_managed_constraints_and_repository_incident_overlays_remain_effective() {
        let Some((state, target)) = fixture() else {
            return;
        };
        std::fs::write(&target, "allow_bypass_env: false\nstrict_warn: true\n").unwrap();
        std::fs::create_dir(state.roots().cwd.join(".git")).unwrap();
        std::fs::create_dir(state.roots().cwd.join(".tirith")).unwrap();
        let repo = state.roots().cwd.join(".tirith/policy.yaml");
        std::fs::write(&repo, "paranoia: 4\n").unwrap();
        let incident = tirith_core::incident::flag_path().unwrap();
        std::fs::create_dir_all(incident.parent().unwrap()).unwrap();
        std::fs::write(
            &incident,
            r#"{"started_at":1,"started_by":"fixture","reason":"retained"}"#,
        )
        .unwrap();
        let incident_before = std::fs::read(&incident).unwrap();
        let id = uuid::Uuid::new_v4().to_string();
        let review = success(prepare(&state, &id));
        assert!(review["impact"]["gaps"]
            .as_array()
            .unwrap()
            .contains(&Value::String("managed_constraints_unresolved".into())));
        success(run(
            &state,
            &["policy", "rollout", "activate", &id, "--json"],
        ));
        let document: serde_yaml::Value =
            serde_yaml::from_str(&std::fs::read_to_string(&target).unwrap()).unwrap();
        assert_eq!(document["allow_bypass_env"].as_bool(), Some(false));
        assert_eq!(document["strict_warn"].as_bool(), Some(true));
        let policy = tirith_core::policy::Policy::discover(state.roots().cwd.to_str());
        assert_eq!(policy.paranoia, 4);
        assert!(!policy.allow_bypass_env);
        assert_eq!(policy.fail_mode, tirith_core::policy::FailMode::Closed);
        assert_eq!(std::fs::read_to_string(&repo).unwrap(), "paranoia: 4\n");
        assert_eq!(std::fs::read(&incident).unwrap(), incident_before);
    }
}
