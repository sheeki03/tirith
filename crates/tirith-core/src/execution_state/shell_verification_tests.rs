use super::*;

#[test]
fn only_complete_exact_inert_commands_are_probe_commands() {
    let id = uuid::Uuid::new_v4().to_string();
    for kind in ["allowed", "blocked", "status"] {
        assert!(parse_probe(&format!("{HELPER} {id} {kind}")).is_some());
    }
    for value in [
        format!("{HELPER}  {id} allowed"),
        format!(" {HELPER} {id} blocked"),
        format!("{HELPER} {id} blocked "),
        format!("{HELPER} {id} blocked\n"),
        format!("command {HELPER} {id} blocked"),
        format!("{HELPER} {id} blocked; touch sentinel"),
        format!("{HELPER} {id} blocked && echo x"),
        format!("{HELPER} {id} blocked | sh"),
        format!("{HELPER} {id} blocked >out"),
        format!("{HELPER} {id} blocked#comment"),
        format!("{HELPER} {id} unknown"),
        format!("{HELPER} '{}' blocked", id),
        format!("{HELPER} {} blocked", id.replace('-', "")),
    ] {
        assert!(parse_probe(&value).is_none(), "{value}");
    }
}

#[cfg(unix)]
mod native {
    use super::*;
    use tirith_test_support::GlobalStateGuard;

    const LOADED: &str = "1111111111111111111111111111111111111111111111111111111111111111";
    const OTHER: &str = "2222222222222222222222222222222222222222222222222222222222222222";
    const CHANNEL: ShellReceiptChannel = ShellReceiptChannel::Zsh;

    fn fixture(test: impl FnOnce(&Path, &[PathBuf], &str, &mut GlobalStateGuard)) {
        let mut guard = GlobalStateGuard::new().unwrap();
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().canonicalize().unwrap();
        guard.set_env("HOME", &root);
        guard.set_env("XDG_CONFIG_HOME", root.join("config"));
        guard.set_env("XDG_STATE_HOME", root.join("state"));
        guard.remove_env("TIRITH_POLICY_ROOT");
        guard.set_cwd(&root).unwrap();
        std::fs::create_dir_all(root.join("config/tirith")).unwrap();
        let config = root.join("hook.zsh");
        std::fs::write(&config, b"# inert owned hook fixture\n").unwrap();
        let session = crate::session::resolve_session_id();
        let shell_pid = unsafe { libc::getppid() } as u32;
        let secret =
            register_shell_hook_instance(shell_pid, ShellHookFamily::Zsh, &session).unwrap();
        guard.set_env("_TIRITH_RECEIPT_INSTANCE", &secret);
        guard.set_env("_TIRITH_RECEIPT_SHELL_PID", shell_pid.to_string());
        guard.set_env("_TIRITH_RECEIPT_FAMILY", "zsh");
        test(&root, &[config], &secret, &mut guard);
    }

    fn allowed(challenge: &ShellVerificationChallenge) {
        assert_eq!(
            observe_shell_verification_hook(&challenge.allowed_command, CHANNEL, Some(LOADED))
                .unwrap(),
            ShellVerificationHookDecision::ContinueProbe
        );
        let observation = execute_shell_verification_probe(
            &challenge.id,
            ShellVerificationProbe::Allowed,
            CHANNEL,
            LOADED,
        )
        .unwrap();
        assert_eq!(observation.status, ShellVerificationStatus::Pending);
    }

    #[test]
    fn authenticated_sequence_requires_actual_body_then_later_status_observation() {
        fixture(|_, configs, _, _| {
            let challenge = start_shell_verification(CHANNEL, configs, LOADED).unwrap();
            allowed(&challenge);
            assert_eq!(
                observe_shell_verification_hook(&challenge.blocked_command, CHANNEL, Some(LOADED))
                    .unwrap(),
                ShellVerificationHookDecision::ForceDiagnosticBlock
            );
            // Merely asking core for status cannot manufacture a later hook.
            assert_eq!(
                finish_shell_verification(&challenge.id, CHANNEL, LOADED)
                    .unwrap()
                    .status,
                ShellVerificationStatus::Pending
            );
            observe_shell_verification_hook(&challenge.status_command, CHANNEL, Some(LOADED))
                .unwrap();
            let observed = finish_shell_verification(&challenge.id, CHANNEL, LOADED).unwrap();
            assert_eq!(observed.status, ShellVerificationStatus::ObservedBlocking);
            assert!(observed.observed_unix_ms.is_some());
            assert_eq!(observed.scope, "current_shell_only");
            let old_timestamp = observed.observed_unix_ms;
            observe_shell_verification_hook(&challenge.status_command, CHANNEL, Some(LOADED))
                .unwrap();
            assert_eq!(
                finish_shell_verification(&challenge.id, CHANNEL, LOADED)
                    .unwrap()
                    .observed_unix_ms,
                old_timestamp
            );
        });
    }

    #[test]
    fn repeated_status_requires_a_new_hook_even_with_unchanged_loaded_digest() {
        fixture(|_, configs, _, _| {
            let challenge = start_shell_verification(CHANNEL, configs, LOADED).unwrap();
            allowed(&challenge);
            observe_shell_verification_hook(&challenge.blocked_command, CHANNEL, Some(LOADED))
                .unwrap();
            observe_shell_verification_hook(&challenge.status_command, CHANNEL, Some(LOADED))
                .unwrap();
            let first = finish_shell_verification(&challenge.id, CHANNEL, LOADED).unwrap();
            assert_eq!(first.status, ShellVerificationStatus::ObservedBlocking);

            // A same-line hook removal can defeat a stale native trap sample.
            // The unchanged function digest is insufficient without another
            // actual status-hook event before the helper body.
            let repeated = finish_shell_verification(&challenge.id, CHANNEL, LOADED).unwrap();
            assert_eq!(repeated.status, ShellVerificationStatus::Failed);
            assert_eq!(repeated.observed_unix_ms, first.observed_unix_ms);
            observe_shell_verification_hook(&challenge.status_command, CHANNEL, Some(LOADED))
                .unwrap();
            assert_eq!(
                finish_shell_verification(&challenge.id, CHANNEL, LOADED)
                    .unwrap()
                    .status,
                ShellVerificationStatus::Failed
            );
        });
    }

    #[test]
    fn check_only_out_of_order_duplicate_and_executed_block_probes_never_attest() {
        fixture(|_, configs, _, _| {
            let challenge = start_shell_verification(CHANNEL, configs, LOADED).unwrap();
            observe_shell_verification_hook(&challenge.allowed_command, CHANNEL, Some(LOADED))
                .unwrap();
            assert_eq!(
                observe_shell_verification_hook(&challenge.blocked_command, CHANNEL, Some(LOADED))
                    .unwrap(),
                ShellVerificationHookDecision::ContinueProbe
            );
            observe_shell_verification_hook(&challenge.status_command, CHANNEL, Some(LOADED))
                .unwrap();
            assert_eq!(
                finish_shell_verification(&challenge.id, CHANNEL, LOADED)
                    .unwrap()
                    .status,
                ShellVerificationStatus::Failed
            );
            let challenge = start_shell_verification(CHANNEL, configs, LOADED).unwrap();
            allowed(&challenge);
            assert_eq!(
                execute_shell_verification_probe(
                    &challenge.id,
                    ShellVerificationProbe::Allowed,
                    CHANNEL,
                    LOADED
                )
                .unwrap()
                .status,
                ShellVerificationStatus::Failed
            );
            let challenge = start_shell_verification(CHANNEL, configs, LOADED).unwrap();
            allowed(&challenge);
            observe_shell_verification_hook(&challenge.blocked_command, CHANNEL, Some(LOADED))
                .unwrap();
            assert_eq!(
                execute_shell_verification_probe(
                    &challenge.id,
                    ShellVerificationProbe::Blocked,
                    CHANNEL,
                    LOADED
                )
                .unwrap()
                .status,
                ShellVerificationStatus::Failed
            );
            observe_shell_verification_hook(&challenge.status_command, CHANNEL, Some(LOADED))
                .unwrap();
            assert_eq!(
                finish_shell_verification(&challenge.id, CHANNEL, LOADED)
                    .unwrap()
                    .status,
                ShellVerificationStatus::Failed
            );
        });
    }

    #[test]
    fn policy_disk_hook_loaded_hook_and_cwd_drift_invalidate_observations() {
        fixture(|root, configs, secret, guard| {
            let challenge = start_shell_verification(CHANNEL, configs, LOADED).unwrap();
            allowed(&challenge);
            assert_eq!(
                finish_shell_verification(&challenge.id, CHANNEL, OTHER)
                    .unwrap()
                    .status,
                ShellVerificationStatus::Stale
            );
            std::fs::write(&configs[0], "# changed hook\n").unwrap();
            assert_eq!(
                finish_shell_verification(&challenge.id, CHANNEL, LOADED)
                    .unwrap()
                    .status,
                ShellVerificationStatus::Stale
            );
            let challenge = start_shell_verification(CHANNEL, configs, LOADED).unwrap();
            std::fs::write(
                root.join("config/tirith/policy.yaml"),
                "strict_warn: true\n",
            )
            .unwrap();
            assert_eq!(
                finish_shell_verification(&challenge.id, CHANNEL, LOADED)
                    .unwrap()
                    .status,
                ShellVerificationStatus::Stale
            );
            let challenge = start_shell_verification(CHANNEL, configs, LOADED).unwrap();
            let record = VerificationStore::open(secret)
                .unwrap()
                .load(secret, unix_time_ms().unwrap())
                .unwrap()
                .unwrap();
            std::fs::create_dir(root.join("other-cwd")).unwrap();
            guard.set_cwd(root.join("other-cwd")).unwrap();
            // Prove the verification's own cwd witness independently of the
            // earlier capability gate. In a fixture without a shell-exported
            // session ID, the existing fallback session also changes with cwd.
            assert_eq!(
                context_status(&record, secret, Some(LOADED), unix_time_ms().unwrap()).unwrap(),
                Some(ShellVerificationStatus::Stale)
            );
            match finish_shell_verification(&challenge.id, CHANNEL, LOADED) {
                Ok(observation) => assert_eq!(observation.status, ShellVerificationStatus::Stale),
                Err(error) => assert_eq!(
                    error,
                    "shell hook capability belongs to a different session"
                ),
            }
        });
    }

    #[test]
    fn matched_hook_checks_require_the_actual_loaded_helper_fingerprint() {
        fixture(|_, configs, _, _| {
            let challenge = start_shell_verification(CHANNEL, configs, LOADED).unwrap();
            assert!(
                observe_shell_verification_hook(&challenge.allowed_command, CHANNEL, None).is_err()
            );
            allowed(&challenge);
            assert!(observe_shell_verification_hook(
                &challenge.blocked_command,
                CHANNEL,
                Some(OTHER)
            )
            .is_err());
            // A body/status fingerprint restored later cannot turn that failed
            // check into an observed diagnostic block.
            observe_shell_verification_hook(&challenge.status_command, CHANNEL, Some(LOADED))
                .unwrap();
            assert_eq!(
                finish_shell_verification(&challenge.id, CHANNEL, LOADED)
                    .unwrap()
                    .status,
                ShellVerificationStatus::Pending
            );
            assert_eq!(
                observe_shell_verification_hook("echo ordinary", CHANNEL, None).unwrap(),
                ShellVerificationHookDecision::NotProbe
            );
        });
    }

    #[test]
    fn inherited_marker_wrong_process_family_and_forged_persisted_state_refuse() {
        fixture(|_, configs, secret, guard| {
            guard.set_env("_TIRITH_RECEIPT_INSTANCE", OTHER);
            assert!(start_shell_verification(CHANNEL, configs, LOADED).is_err());
            guard.set_env("_TIRITH_RECEIPT_INSTANCE", secret);
            guard.set_env("_TIRITH_RECEIPT_SHELL_PID", std::process::id().to_string());
            assert!(start_shell_verification(CHANNEL, configs, LOADED).is_err());
            guard.set_env(
                "_TIRITH_RECEIPT_SHELL_PID",
                (unsafe { libc::getppid() } as u32).to_string(),
            );
            assert!(start_shell_verification(ShellReceiptChannel::Fish, configs, LOADED).is_err());
            let challenge = start_shell_verification(CHANNEL, configs, LOADED).unwrap();
            {
                let store = VerificationStore::open(secret).unwrap();
                let bytes = store.file.read_capped(VERIFICATION_FILE_CAP).unwrap();
                let mut value: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
                value["phase"] = "verified".into();
                value["allowed_executions"] = 1.into();
                value["observed_unix_ms"] = unix_time_ms().unwrap().into();
                store
                    .file
                    .write_atomic_if_observed(&serde_json::to_vec(&value).unwrap(), true)
                    .unwrap();
            }
            assert!(finish_shell_verification(&challenge.id, CHANNEL, LOADED).is_err());
        });
    }

    #[test]
    fn expired_evidence_never_refreshes_and_private_bindings_do_not_enter_output() {
        fixture(|_, configs, secret, _| {
            let challenge = start_shell_verification(CHANNEL, configs, LOADED).unwrap();
            {
                let store = VerificationStore::open(secret).unwrap();
                let now = unix_time_ms().unwrap();
                let mut record = store.load(secret, now).unwrap().unwrap();
                record.created_unix_ms = now - VERIFICATION_TTL_MS - 1;
                record.expires_unix_ms = now - 1;
                store.publish(&mut record, secret).unwrap();
            }
            let observation = finish_shell_verification(&challenge.id, CHANNEL, LOADED).unwrap();
            assert_eq!(observation.status, ShellVerificationStatus::Expired);
            let output = serde_json::to_string(&observation).unwrap();
            for private in [
                secret,
                LOADED,
                configs[0].to_str().unwrap(),
                "policy_guard",
                "cwd_binding",
                "hook_binding",
            ] {
                assert!(!output.contains(private));
            }
        });
    }

    #[test]
    fn linked_or_oversized_configuration_and_unsupported_channels_refuse() {
        fixture(|root, configs, _, _| {
            assert!(
                start_shell_verification(ShellReceiptChannel::PowerShell, configs, LOADED).is_err()
            );
            assert!(start_shell_verification(CHANNEL, &[], LOADED).is_err());
            let link = root.join("linked-hook");
            std::os::unix::fs::symlink(&configs[0], &link).unwrap();
            assert!(start_shell_verification(CHANNEL, &[link], LOADED).is_err());
            std::fs::write(&configs[0], vec![b'x'; MAX_CONFIG_BYTES as usize + 1]).unwrap();
            assert!(start_shell_verification(CHANNEL, configs, LOADED).is_err());
        });
    }
}
