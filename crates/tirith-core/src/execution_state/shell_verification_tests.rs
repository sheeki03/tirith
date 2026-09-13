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

    fn completed_proof(
        configs: &[PathBuf],
    ) -> (ShellVerificationChallenge, ShellVerificationProof) {
        let challenge = start_shell_verification(CHANNEL, configs, LOADED).unwrap();
        allowed(&challenge);
        assert_eq!(
            observe_shell_verification_hook(&challenge.blocked_command, CHANNEL, Some(LOADED))
                .unwrap(),
            ShellVerificationHookDecision::ForceDiagnosticBlock,
        );
        observe_shell_verification_hook(&challenge.status_command, CHANNEL, Some(LOADED)).unwrap();
        let proof =
            finish_shell_verification_authenticated(&challenge.id, CHANNEL, LOADED).unwrap();
        (challenge, proof)
    }

    #[test]
    fn canonical_projection_consumes_fresh_authority_without_renewing_observation() {
        fixture(|_, configs, _, _| {
            let (challenge, proof) = completed_proof(configs);
            let first = proof.into_current_observation();
            assert_eq!(first.status, ShellVerificationStatus::ObservedBlocking);
            observe_shell_verification_hook(&challenge.status_command, CHANNEL, Some(LOADED))
                .unwrap();
            let next = finish_shell_verification_authenticated(&challenge.id, CHANNEL, LOADED)
                .unwrap()
                .into_current_observation();
            assert_eq!(next.status, ShellVerificationStatus::ObservedBlocking);
            assert_eq!(next.observed_unix_ms, first.observed_unix_ms);
            assert_eq!(next.expires_unix_ms, first.expires_unix_ms);
            // The saved report cannot stand in for another native status event.
            let replay = finish_shell_verification_authenticated(&challenge.id, CHANNEL, LOADED)
                .unwrap()
                .into_current_observation();
            assert_eq!(replay.status, ShellVerificationStatus::Failed);
        });
    }

    #[test]
    fn projection_revalidates_policy_configuration_cwd_and_loaded_binding_after_capture() {
        for change in ["policy", "configuration", "cwd", "loaded", "record"] {
            fixture(|root, configs, _, guard| {
                let (_, mut proof) = completed_proof(configs);
                match change {
                    "policy" => std::fs::write(
                        root.join("config/tirith/policy.yaml"),
                        "strict_warn: true\n",
                    )
                    .unwrap(),
                    "configuration" => {
                        std::fs::write(&configs[0], "# changed during status capture\n").unwrap()
                    }
                    "cwd" => {
                        std::fs::create_dir(root.join("other-cwd")).unwrap();
                        guard.set_cwd(root.join("other-cwd")).unwrap();
                    }
                    // Core owns this binding; production callers cannot replace it.
                    "loaded" => proof.binding.loaded_hook_state = OTHER.into(),
                    "record" => {
                        start_shell_verification(CHANNEL, configs, LOADED).unwrap();
                    }
                    _ => unreachable!(),
                }
                assert_eq!(
                    proof.into_current_observation().status,
                    ShellVerificationStatus::Stale,
                    "{change}"
                );
            });
        }
    }

    #[test]
    fn projection_revalidates_live_capability_and_refuses_retained_or_foreign_process_proofs() {
        for change in ["secret", "parent", "family", "issuer", "elapsed"] {
            fixture(|_, configs, _, guard| {
                let (_, mut proof) = completed_proof(configs);
                match change {
                    "secret" => guard.set_env("_TIRITH_RECEIPT_INSTANCE", OTHER),
                    "parent" => {
                        guard.set_env("_TIRITH_RECEIPT_SHELL_PID", std::process::id().to_string())
                    }
                    "family" => guard.set_env("_TIRITH_RECEIPT_FAMILY", "fish"),
                    // These private-field changes exercise failure predicates
                    // without a fork or sleeping in the shared native test process.
                    "issuer" => proof.binding.issuer_pid = 0,
                    "elapsed" => {
                        proof.binding.issued_at = std::time::Instant::now() - PROJECTION_TTL
                    }
                    _ => unreachable!(),
                }
                assert_eq!(
                    proof.into_current_observation().status,
                    ShellVerificationStatus::Stale,
                    "{change}"
                );
            });
        }
    }

    #[test]
    fn expired_projection_never_renews_a_saved_success() {
        fixture(|_, configs, secret, _| {
            let (_, mut proof) = completed_proof(configs);
            let now = unix_time_ms().unwrap();
            {
                let store = VerificationStore::open(secret).unwrap();
                let mut record = store.load(secret, now).unwrap().unwrap();
                record.created_unix_ms = now - VERIFICATION_TTL_MS - 2;
                record.expires_unix_ms = now - 2;
                record.observed_unix_ms = Some(record.created_unix_ms + 1);
                store.publish(&mut record, secret).unwrap();
                proof.observation = record.observation(ShellVerificationStatus::ObservedBlocking);
                proof.binding.record_seal = record.seal;
            }
            let expired = proof.into_current_observation();
            assert_eq!(expired.status, ShellVerificationStatus::Expired);
            assert!(expired.expires_unix_ms < now);
        });
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

    fn automatic_owner<'a>(
        context: &'a AuthenticatedShellContext,
        configs: &[PathBuf],
        id: &str,
    ) -> AutomaticShellVerification<'a> {
        start_automatic_shell_verification(
            context,
            &uuid::Uuid::new_v4().to_string(),
            id,
            configs,
            LOADED,
        )
        .unwrap()
    }

    fn automatic_through_status(owner: &mut AutomaticShellVerification<'_>, id: &str) {
        assert_eq!(
            owner.issue_next().unwrap(),
            AutomaticVerificationStage::Allowed
        );
        assert_eq!(
            observe_shell_verification_hook(
                &format!("{HELPER} {id} allowed"),
                CHANNEL,
                Some(LOADED)
            )
            .unwrap(),
            ShellVerificationHookDecision::ContinueProbe
        );
        assert_eq!(
            execute_automatic_shell_verification_probe(
                id,
                ShellVerificationProbe::Allowed,
                CHANNEL,
                LOADED
            )
            .unwrap()
            .status,
            ShellVerificationStatus::Pending
        );
        assert_eq!(
            owner.issue_next().unwrap(),
            AutomaticVerificationStage::Blocked
        );
        assert_eq!(
            observe_shell_verification_hook(
                &format!("{HELPER} {id} blocked"),
                CHANNEL,
                Some(LOADED)
            )
            .unwrap(),
            ShellVerificationHookDecision::ForceDiagnosticBlock
        );
        assert_eq!(
            owner.issue_next().unwrap(),
            AutomaticVerificationStage::Status
        );
        observe_shell_verification_hook(&format!("{HELPER} {id} status"), CHANNEL, Some(LOADED))
            .unwrap();
        finish_automatic_shell_verification_status(id, CHANNEL, LOADED).unwrap();
    }

    #[test]
    fn automatic_complete_sequence_requires_restoration_and_reports_historical_scope() {
        fixture(|_, configs, secret, _| {
            let context =
                authenticate_shell_context(CHANNEL, &crate::session::resolve_session_id()).unwrap();
            let id = uuid::Uuid::new_v4().to_string();
            let mut owner = automatic_owner(&context, configs, &id);
            assert!(start_shell_verification(CHANNEL, configs, LOADED).is_err());
            assert!(start_automatic_shell_verification(
                &context,
                &uuid::Uuid::new_v4().to_string(),
                &uuid::Uuid::new_v4().to_string(),
                configs,
                LOADED
            )
            .is_err());
            automatic_through_status(&mut owner, &id);
            {
                let store = VerificationStore::open(secret).unwrap();
                let record = store
                    .load(secret, unix_time_ms().unwrap())
                    .unwrap()
                    .unwrap();
                assert_eq!(record.phase, Phase::AwaitingRestoration);
                assert!(record.observed_unix_ms.is_none());
            }
            assert_eq!(
                owner.issue_next().unwrap(),
                AutomaticVerificationStage::Restore
            );
            let report = owner.finish_restored(LOADED).unwrap();
            assert_eq!(report.status, ShellVerificationStatus::ObservedBlocking);
            assert_eq!(report.source, "fresh_terminal_activation");
            assert_eq!(report.scope, "completed_setup_shell_observation");
            let output = serde_json::to_string(&report).unwrap();
            for private in [
                secret,
                LOADED,
                configs[0].to_str().unwrap(),
                "broker_identity",
                "operation_id",
            ] {
                assert!(!output.contains(private));
            }
            assert!(finish_shell_verification_authenticated(&id, CHANNEL, LOADED).is_err());
        });
    }

    #[test]
    fn manual_and_automatic_body_routes_cannot_substitute_for_each_other() {
        fixture(|_, configs, _, _| {
            let challenge = start_shell_verification(CHANNEL, configs, LOADED).unwrap();
            assert!(execute_automatic_shell_verification_probe(
                &challenge.id,
                ShellVerificationProbe::Allowed,
                CHANNEL,
                LOADED
            )
            .is_err());
            assert!(
                finish_automatic_shell_verification_status(&challenge.id, CHANNEL, LOADED).is_err()
            );
            allowed(&challenge);
        });
        fixture(|_, configs, _, _| {
            let context =
                authenticate_shell_context(CHANNEL, &crate::session::resolve_session_id()).unwrap();
            let id = uuid::Uuid::new_v4().to_string();
            let mut owner = automatic_owner(&context, configs, &id);
            assert!(execute_shell_verification_probe(
                &id,
                ShellVerificationProbe::Allowed,
                CHANNEL,
                LOADED
            )
            .is_err());
            assert!(finish_shell_verification_authenticated(&id, CHANNEL, LOADED).is_err());
            automatic_through_status(&mut owner, &id);
            assert_eq!(
                owner.issue_next().unwrap(),
                AutomaticVerificationStage::Restore
            );
            assert_eq!(
                owner.finish_restored(LOADED).unwrap().status,
                ShellVerificationStatus::ObservedBlocking
            );
        });
    }

    #[test]
    fn automatic_lost_reply_repeated_hook_and_bypassed_block_cannot_complete() {
        for scenario in [
            "lost_reply",
            "repeated_allow_hook",
            "allowed_without_hook",
            "block_executed",
            "status_without_hook",
            "repeated_status",
            "restore_unissued",
            "cancel",
        ] {
            fixture(|_, configs, _, _| {
                let context =
                    authenticate_shell_context(CHANNEL, &crate::session::resolve_session_id())
                        .unwrap();
                let id = uuid::Uuid::new_v4().to_string();
                let mut owner = automatic_owner(&context, configs, &id);
                if matches!(scenario, "repeated_status" | "restore_unissued") {
                    automatic_through_status(&mut owner, &id);
                    if scenario == "repeated_status" {
                        assert!(
                            finish_automatic_shell_verification_status(&id, CHANNEL, LOADED)
                                .is_err()
                        );
                    }
                } else {
                    assert_eq!(
                        owner.issue_next().unwrap(),
                        AutomaticVerificationStage::Allowed
                    );
                    match scenario {
                        "lost_reply" => {
                            assert!(owner.issue_next().is_err());
                        }
                        "repeated_allow_hook" => {
                            for _ in 0..2 {
                                observe_shell_verification_hook(
                                    &format!("{HELPER} {id} allowed"),
                                    CHANNEL,
                                    Some(LOADED),
                                )
                                .unwrap();
                            }
                            execute_automatic_shell_verification_probe(
                                &id,
                                ShellVerificationProbe::Allowed,
                                CHANNEL,
                                LOADED,
                            )
                            .unwrap();
                        }
                        "allowed_without_hook" => {
                            execute_automatic_shell_verification_probe(
                                &id,
                                ShellVerificationProbe::Allowed,
                                CHANNEL,
                                LOADED,
                            )
                            .unwrap();
                        }
                        "block_executed" => {
                            execute_automatic_shell_verification_probe(
                                &id,
                                ShellVerificationProbe::Blocked,
                                CHANNEL,
                                LOADED,
                            )
                            .unwrap();
                        }
                        "status_without_hook" => {
                            assert!(finish_automatic_shell_verification_status(
                                &id, CHANNEL, LOADED
                            )
                            .is_err());
                        }
                        "cancel" => {
                            owner.cancel().unwrap();
                            return;
                        }
                        _ => unreachable!(),
                    }
                }
                assert!(owner.finish_restored(LOADED).is_err(), "{scenario}");
            });
        }
    }

    #[test]
    fn automatic_restoration_refuses_changed_configuration_policy_and_capability() {
        for change in ["configuration", "policy", "loaded", "capability"] {
            fixture(|root, configs, _, guard| {
                let context =
                    authenticate_shell_context(CHANNEL, &crate::session::resolve_session_id())
                        .unwrap();
                let id = uuid::Uuid::new_v4().to_string();
                let mut owner = automatic_owner(&context, configs, &id);
                automatic_through_status(&mut owner, &id);
                assert_eq!(
                    owner.issue_next().unwrap(),
                    AutomaticVerificationStage::Restore
                );
                let loaded = match change {
                    "configuration" => {
                        std::fs::write(&configs[0], b"changed").unwrap();
                        LOADED
                    }
                    "policy" => {
                        std::fs::write(
                            root.join("config/tirith/policy.yaml"),
                            b"strict_warn: true\n",
                        )
                        .unwrap();
                        LOADED
                    }
                    "loaded" => OTHER,
                    "capability" => {
                        guard.set_env("_TIRITH_RECEIPT_INSTANCE", "forged");
                        LOADED
                    }
                    _ => unreachable!(),
                };
                assert!(owner.finish_restored(loaded).is_err(), "{change}");
            });
        }
    }

    #[test]
    fn manual_record_omits_automatic_field_and_retains_legacy_seal_bytes() {
        fixture(|_, configs, secret, _| {
            start_shell_verification(CHANNEL, configs, LOADED).unwrap();
            let store = VerificationStore::open(secret).unwrap();
            let record = store
                .load(secret, unix_time_ms().unwrap())
                .unwrap()
                .unwrap();
            let mut value = serde_json::to_value(&record).unwrap();
            assert!(value.get("automatic").is_none());
            value["seal"] = serde_json::Value::Null;
            assert_eq!(
                record.seal,
                secret_seal(secret, "tirith-caller-shell-verification-v1", &value)
            );
        });
    }

    fn rewrite_automatic_record(secret: &str, change: impl FnOnce(&mut serde_json::Value)) {
        let store = VerificationStore::open(secret).unwrap();
        let record = store
            .load(secret, unix_time_ms().unwrap())
            .unwrap()
            .unwrap();
        let mut value = serde_json::to_value(record).unwrap();
        change(&mut value["automatic"]);
        let mut record: VerificationRecord = serde_json::from_value(value).unwrap();
        record.seal = record.seal_value(secret).unwrap();
        store
            .file
            .write_atomic_if_observed(&serde_json::to_vec(&record).unwrap(), true)
            .unwrap();
    }

    #[test]
    fn automatic_valid_seal_cannot_authorize_expired_changed_clock_or_broker() {
        for change in ["expired", "future", "coordinate", "broker", "operation"] {
            fixture(|_, configs, secret, _| {
                let context =
                    authenticate_shell_context(CHANNEL, &crate::session::resolve_session_id())
                        .unwrap();
                let id = uuid::Uuid::new_v4().to_string();
                let mut owner = automatic_owner(&context, configs, &id);
                rewrite_automatic_record(secret, |automatic| match change {
                    "expired" => {
                        automatic["clock"]["started_ns"] = 1u64.into();
                        automatic["clock"]["deadline_ns"] = 10_000_000_001u64.into();
                    }
                    "future" => {
                        automatic["clock"]["started_ns"] = (u64::MAX - 10_000_000_000).into();
                        automatic["clock"]["deadline_ns"] = u64::MAX.into();
                    }
                    "coordinate" => automatic["clock"]["coordinate"] = "different-clock".into(),
                    "broker" => {
                        automatic["broker_identity"]["start_fingerprint"] =
                            "changed-native-start".into()
                    }
                    "operation" => {
                        automatic["operation_id"] = uuid::Uuid::new_v4().to_string().into()
                    }
                    _ => unreachable!(),
                });
                assert!(owner.issue_next().is_err(), "{change}");
            });
        }
    }

    #[test]
    fn automatic_projection_rechecks_deadline_after_final_capability_work() {
        fixture(|_, configs, secret, _| {
            let context =
                authenticate_shell_context(CHANNEL, &crate::session::resolve_session_id()).unwrap();
            let id = uuid::Uuid::new_v4().to_string();
            let mut owner = automatic_owner(&context, configs, &id);
            automatic_through_status(&mut owner, &id);
            assert_eq!(
                owner.issue_next().unwrap(),
                AutomaticVerificationStage::Restore
            );
            let now = automatic::monotonic_now().unwrap().1;
            rewrite_automatic_record(secret, |binding| {
                binding["clock"]["started_ns"] = (now - 9_000_000_000).into();
                binding["clock"]["deadline_ns"] = (now + 1_000_000_000).into();
            });
            struct Reset;
            impl Drop for Reset {
                fn drop(&mut self) {
                    PROJECTION_FINAL_DELAY.with(|delay| delay.set(None));
                }
            }
            let _reset = Reset;
            PROJECTION_FINAL_DELAY
                .with(|delay| delay.set(Some(std::time::Duration::from_millis(1250))));
            assert!(owner.finish_restored(LOADED).is_err());
            assert!(
                PROJECTION_FINAL_DELAY.with(|delay| delay.get().is_none()),
                "must reach the final capability boundary while the shorter deadline is live"
            );
        });
    }
}
