use super::*;

fn record() -> ReportRecord {
    let authority = Id::new();
    let policy = Id::new();
    let client = Id::new();
    let revision = Id::new();
    let now = now_ms().unwrap();
    ReportRecord {
        phase: ReportPhase::Active,
        archive_id: None,
        archived: Vec::new(),
        schema_version: SCHEMA_VERSION,
        cwd: if cfg!(windows) {
            r"C:\private\test-only"
        } else {
            "/private/test-only"
        }
        .into(),
        binding: RuntimeBinding {
            connection_id: Id::new(),
            authority_id: authority.clone(),
            policy_id: policy.clone(),
            activation_id: Id::new(),
            client_id: client.clone(),
            revision: revision.clone(),
            fetched_unix_ms: now - 1,
        },
        selection: PrivateCommitment::of("test-only-selection", b"test-only-credential"),
        runtime_guard: serde_json::from_value(json!({"digest":vec![0u8;32]})).unwrap(),
        request: ClientReportRequest {
            schema_version: SCHEMA_VERSION,
            report_id: policy_team::report_id(&authority, &client, 1).unwrap(),
            authority_id: authority,
            policy_id: policy,
            report_sequence: 1,
            applied_revision: revision,
            observed_unix_ms: now,
            client_version: "1.0.0".into(),
            state: ReportState::Applied,
            failure_reason: None,
        },
        receipt: None,
    }
}
#[test]
fn post_gate_requires_exact_clean_written_outcome() {
    assert!(report_post_allowed(TransactionOutcome::Written));
    for outcome in [
        TransactionOutcome::WrittenWithRecovery,
        TransactionOutcome::Unchanged,
        TransactionOutcome::DryRunWouldWrite,
    ] {
        assert!(!report_post_allowed(outcome));
    }
}
#[test]
fn public_inputs_reject_credentials_documents_fabricated_states_and_timestamps() {
    let base = json!({"expected_connection_id":Id::new(),"expected_activation_id":Id::new()});
    for field in [
        "credential",
        "token",
        "yaml",
        "applied",
        "state",
        "report_sequence",
        "observed_unix_ms",
        "fetched_unix_ms",
        "runtime_guard",
        "selection",
    ] {
        let mut value = base.clone();
        value[field] = json!("caller-data");
        assert!(serde_json::from_value::<ActivateRequest>(value.clone()).is_err());
        assert!(serde_json::from_value::<SelectedRequest>(value.clone()).is_err());
        assert!(serde_json::from_value::<ReportRequest>(value).is_err());
    }
    assert!(serde_json::from_value::<DisableRequest>(base).is_err());
}
#[test]
fn expected_activation_never_reinterprets_malformed_or_replaced_state() {
    let activation = Id::new();
    let other = Id::new();
    assert!(expected_activation(None, false, None).is_ok());
    assert!(expected_activation(Some(&activation), true, Some(&activation)).is_ok());
    assert!(expected_activation(None, true, None).is_err());
    assert!(expected_activation(Some(&activation), true, None).is_err());
    assert!(expected_activation(Some(&activation), true, Some(&other)).is_err());
    assert!(expected_activation(None, false, Some(&activation)).is_err());
}
#[test]
fn pending_roundtrip_preserves_exact_request_id_sequence_and_observation() {
    let _shared_state = tirith_test_support::SharedStateGuard::acquire();
    let original = record();
    let request = serde_json::to_vec(&original.request).unwrap();
    let restored = decode_report(&encoded(&original).unwrap()).unwrap();
    assert_eq!(serde_json::to_vec(&restored.request).unwrap(), request);
    assert_eq!(restored.request.report_id, original.request.report_id);
    assert_eq!(
        restored.request.report_sequence,
        original.request.report_sequence
    );
    assert_eq!(
        restored.request.observed_unix_ms,
        original.request.observed_unix_ms
    );
    assert!(restored.receipt.is_none());
}
#[test]
fn pending_schema_rejects_ambiguous_unknown_oversized_or_rebound_fields() {
    let _shared_state = tirith_test_support::SharedStateGuard::acquire();
    let original = record();
    let bytes = encoded(&original).unwrap();
    let mut value: Value = serde_json::from_slice(&bytes).unwrap();
    value["extra"] = json!(true);
    assert!(decode_report(&serde_json::to_vec(&value).unwrap()).is_err());
    let text = std::str::from_utf8(&bytes).unwrap();
    assert!(decode_report(format!("{{\"schema_version\":1,{}", &text[1..]).as_bytes()).is_err());
    assert!(decode_report(&vec![b' '; TeamRecord::Report.cap() + 1]).is_err());
    for path in ["authority_id", "policy_id", "applied_revision", "report_id"] {
        let mut value: Value = serde_json::from_slice(&bytes).unwrap();
        value["request"][path] = json!(Id::new());
        assert!(
            decode_report(&serde_json::to_vec(&value).unwrap()).is_err(),
            "{path}"
        );
    }
    let mut wrong = record();
    wrong.request.report_sequence += 1;
    assert!(wrong.validate().is_err());
    let mut wrong = record();
    wrong.binding.client_id = Id::new();
    assert!(wrong.validate().is_err());
    let mut wrong = record();
    wrong.binding.fetched_unix_ms = wrong.request.observed_unix_ms + 1;
    assert!(wrong.validate().is_err());
}
#[test]
fn downloaded_failed_or_invented_receipt_cannot_promote_pending_report() {
    let _shared_state = tirith_test_support::SharedStateGuard::acquire();
    for state in [ReportState::Downloaded, ReportState::Failed] {
        let mut r = record();
        r.request.state = state;
        assert!(r.validate().is_err());
    }
    let mut r = record();
    r.receipt = Some(ReportReceipt {
        schema_version: SCHEMA_VERSION,
        authority_id: r.binding.authority_id.clone(),
        policy_id: r.binding.policy_id.clone(),
        report_id: Id::new(),
        client_id: r.binding.client_id.clone(),
        report_sequence: 1,
        received_unix_ms: now_ms().unwrap(),
    });
    assert!(r.validate().is_err());
}
#[test]
fn report_projection_omits_private_commitments_policy_and_paths() {
    let _shared_state = tirith_test_support::SharedStateGuard::acquire();
    let r = record();
    let output = report_result(
        &r,
        "pending_outcome_unknown",
        "written",
        Some(policy_team::ErrorCode::OutcomeUnknown),
    )
    .to_string();
    for private in [
        r.cwd.as_str(),
        r.selection.as_str(),
        "runtime_guard",
        "selection",
        "test-only-credential",
        "yaml",
    ] {
        assert!(!output.contains(private));
    }
    assert!(output.contains(r.request.report_id.as_str()));
    assert!(output.contains("pending"));
    assert!(!output.contains("acknowledged"));
}

#[test]
fn bounded_archive_preserves_exact_context_and_never_silently_evicts() {
    let _shared_state = tirith_test_support::SharedStateGuard::acquire();
    let mut previous = record();
    let original = serde_json::to_vec(&previous.request).unwrap();
    previous.phase = ReportPhase::ArchivedUnknown;
    previous.archive_id = Some(Id::new());
    let archived = carry_archives(Some(&previous)).unwrap();
    assert_eq!(serde_json::to_vec(&archived[0].request).unwrap(), original);
    assert_eq!(archived[0].runtime_guard, previous.runtime_guard);
    assert_eq!(archived[0].selection, previous.selection);
    let mut current = record();
    current.archived = archived;
    while current.archived.len() < MAX_ARCHIVED_REPORTS {
        let mut entry = record();
        entry.phase = ReportPhase::ArchivedUnknown;
        entry.archive_id = Some(Id::new());
        current.archived.push(entry);
    }
    assert!(current.validate().is_ok());
    current.phase = ReportPhase::ArchivedUnknown;
    current.archive_id = Some(Id::new());
    assert!(current.validate().is_err());
    assert!(carry_archives(Some(&current)).is_err());
    assert_eq!(current.archived.len(), MAX_ARCHIVED_REPORTS);
}
#[test]
fn deterministic_report_id_reuse_requires_exact_archive_identity_for_reconciliation() {
    let _shared_state = tirith_test_support::SharedStateGuard::acquire();
    let mut current = record();
    let mut archived = current.clone();
    archived.phase = ReportPhase::ArchivedUnknown;
    let archive_id = Id::new();
    archived.archive_id = Some(archive_id.clone());
    archived.request.observed_unix_ms -= 1; // Different complete request, same deterministic sequence ID.
    current.archived.push(archived);
    assert_eq!(
        reconciliation_target(&current, &current.request.report_id, None).unwrap(),
        None
    );
    assert_eq!(
        reconciliation_target(&current, &current.request.report_id, Some(&archive_id)).unwrap(),
        Some(0)
    );
    assert!(reconciliation_target(&current, &current.request.report_id, Some(&Id::new())).is_err());
}
#[test]
fn nested_archive_and_private_history_projection_are_bounded() {
    let _shared_state = tirith_test_support::SharedStateGuard::acquire();
    let mut current = record();
    let mut archived = record();
    archived.phase = ReportPhase::ArchivedUnknown;
    archived.archive_id = Some(Id::new());
    archived.archived.push(record());
    current.archived.push(archived);
    assert!(current.validate().is_err());
    current.archived[0].archived.clear();
    assert!(current.validate().is_ok());
    let view = report_projection(&current).to_string();
    assert!(view.contains("archived_unknown"));
    for secret in [
        current.cwd.as_str(),
        current.selection.as_str(),
        "runtime_guard",
        "selection",
    ] {
        assert!(!view.contains(secret));
    }
}
#[cfg(unix)]
mod native {
    use super::*;
    use std::os::unix::fs::PermissionsExt;
    use std::path::{Path, PathBuf};
    use tirith_core::policy_snapshot::ResolutionMode;
    fn fixture() -> (tirith_test_support::GlobalStateGuard, PathBuf) {
        let guard = tirith_test_support::GlobalStateGuard::new().unwrap();
        let parent = tirith_core::policy::config_dir()
            .unwrap()
            .join("team-policy");
        std::fs::create_dir_all(&parent).unwrap();
        std::fs::set_permissions(&parent, std::fs::Permissions::from_mode(0o700)).unwrap();
        (guard, parent)
    }
    fn private_file(path: &Path, bytes: &[u8]) {
        std::fs::write(path, bytes).unwrap();
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).unwrap();
    }
    #[test]
    fn closed_report_reader_writer_preserve_private_cap_and_native_generation() {
        let (_guard, parent) = fixture();
        let r = record();
        let (absent, none) = load_report().unwrap();
        assert!(none.is_none());
        let outcome = save_report(&r, &absent, || absent.revalidate().map_err(error)).unwrap();
        assert_eq!(outcome, TransactionOutcome::Written);
        assert_eq!(
            std::fs::metadata(parent.join("report.json"))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
        assert!(absent.revalidate().is_err());
        let (prior, loaded) = load_report().unwrap();
        assert_eq!(encoded(&loaded.unwrap()).unwrap(), encoded(&r).unwrap());
        private_file(&parent.join("next.json"), &encoded(&r).unwrap());
        std::fs::rename(parent.join("next.json"), parent.join("report.json")).unwrap();
        assert!(save_report(&r, &prior, || Ok(())).is_err());
    }
    #[test]
    fn exact_pending_retry_republishes_identical_request_without_incrementing() {
        let (_guard, _parent) = fixture();
        let r = record();
        let (prior, _) = load_report().unwrap();
        save_report(&r, &prior, || Ok(())).unwrap();
        drop(prior);
        let (pending, loaded) = load_report().unwrap();
        let loaded = loaded.unwrap();
        let original = serde_json::to_vec(&loaded.request).unwrap();
        assert_eq!(
            save_report(&loaded, &pending, || pending.revalidate().map_err(error)).unwrap(),
            TransactionOutcome::Written
        );
        assert_eq!(
            serde_json::to_vec(&load_report().unwrap().1.unwrap().request).unwrap(),
            original
        );
    }
    #[test]
    fn enrollment_delete_uses_two_mib_cap_without_broadening_connection_or_report_deletion() {
        let (_guard, parent) = fixture();
        let bytes = vec![b'x'; 256 * 1024];
        private_file(&parent.join("enrollment.json"), &bytes);
        let witness = TeamRecord::Enrollment.capture_current().unwrap();
        setup::delete_private_team_record(
            &TeamRecord::Enrollment,
            |bytes| witness.matches_private_bytes(bytes),
            || witness.revalidate().map_err(error),
        )
        .unwrap();
        assert!(!parent.join("enrollment.json").exists());
        assert!(
            setup::delete_private_team_record(&TeamRecord::Report, |_| true, || Ok(())).is_err()
        );
        assert!(setup::delete_private_team_record(
            &TeamRecord::Rollout(Id::new()),
            |_| true,
            || Ok(())
        )
        .is_err());
        assert_eq!(
            tirith_core::policy_team_connection::MAX_CONNECTION_BYTES,
            128 * 1024
        );
    }
    #[test]
    fn changed_enrollment_is_preserved_by_closed_delete() {
        let (_guard, parent) = fixture();
        private_file(&parent.join("enrollment.json"), b"old");
        let witness = TeamRecord::Enrollment.capture_current().unwrap();
        private_file(&parent.join("next.json"), b"changed");
        std::fs::rename(parent.join("next.json"), parent.join("enrollment.json")).unwrap();
        assert!(setup::delete_private_team_record(
            &TeamRecord::Enrollment,
            |bytes| witness.matches_private_bytes(bytes),
            || witness.revalidate().map_err(error)
        )
        .is_err());
        assert_eq!(
            std::fs::read(parent.join("enrollment.json")).unwrap(),
            b"changed"
        );
    }
    #[test]
    fn local_status_is_off_and_does_not_create_records_or_contact_legacy_authority() {
        let (mut guard, parent) = fixture();
        guard.set_env("TIRITH_SERVER_URL", "must-not-connect://legacy");
        guard.set_env("TIRITH_API_KEY", "test-secret");
        let status = TeamEnrollmentService::capture(None)
            .unwrap()
            .current()
            .unwrap();
        assert_eq!(status["state"], "off");
        assert!(!parent.join("enrollment.json").exists());
        assert!(!parent.join("report.json").exists());
        assert!(!status.to_string().contains("test-secret"));
    }
    #[test]
    fn malformed_report_is_preserved_and_not_exposed_in_status() {
        let (_guard, parent) = fixture();
        private_file(&parent.join("report.json"), b"{private-malformed-secret");
        assert!(load_report().is_err());
        let status = report_status();
        assert_eq!(status["state"], "unavailable");
        assert!(!status.to_string().contains("private-malformed-secret"));
        assert_eq!(
            std::fs::read(parent.join("report.json")).unwrap(),
            b"{private-malformed-secret"
        );
    }
    #[test]
    fn malformed_repo_replacement_cannot_produce_applied_runtime_evidence_or_report() {
        use tirith_core::policy_team::{PolicyDocument, POLICY_SEMANTICS_VERSION};
        use tirith_core::policy_team_client::AuthorityBinding;
        let (mut guard, parent) = fixture();
        guard.set_env("TIRITH_OFFLINE", "1");
        let authority_id = Id::new();
        let policy_id = Id::new();
        let connection_id = Id::new();
        let activation_id = Id::new();
        let binding = AuthorityBinding {
            schema_version: SCHEMA_VERSION,
            base_url: "https://must-not-contact.invalid".into(),
            authority_id: authority_id.clone(),
            policy_id: policy_id.clone(),
            transport: Default::default(),
        };
        private_file(&parent.join("connection.json"), &serde_json::to_vec(&json!({"schema_version":1,"connection_id":connection_id,"binding":binding,"credential":"c".repeat(64)})).unwrap());
        let connection = SelectedConnection::capture_current().unwrap();
        let now = now_ms().unwrap();
        let document = PolicyDocument {
            schema_version: 1,
            authority_id: authority_id.clone(),
            policy_id: policy_id.clone(),
            revision: Id::new(),
            created_unix_ms: now,
            policy_semantics_version: POLICY_SEMANTICS_VERSION,
            yaml: "paranoia: 2\n".into(),
        };
        private_file(&parent.join("enrollment.json"), &serde_json::to_vec(&json!({"schema_version":1,"connection_id":connection_id,"authority_id":authority_id,"policy_id":policy_id,"activation_id":activation_id,"client_id":Id::new(),"selection_commitment":connection.private_selection_commitment().unwrap(),"fetched_unix_ms":now,"cached_policy":document})).unwrap());
        let cwd = guard.roots().cwd.clone();
        std::fs::create_dir_all(cwd.join(".git")).unwrap();
        std::fs::create_dir_all(cwd.join(".tirith")).unwrap();
        std::fs::write(cwd.join(".tirith/policy.yaml"), "paranoia: [").unwrap();
        let snapshot = EffectivePolicySnapshot::resolve(cwd.to_str(), ResolutionMode::Runtime);
        assert!(
            snapshot.team_runtime_evidence().is_err(),
            "failure replacement must not attest the discarded team baseline"
        );
        assert!(
            EffectivePolicySnapshot::resolve_team_preview(cwd.to_str(), &document).is_err(),
            "activation must refuse invalid complete composition"
        );
        let service = TeamEnrollmentService::capture(cwd.to_str()).unwrap();
        let error = service
            .report(ReportRequest {
                expected_connection_id: connection_id.as_str().into(),
                expected_activation_id: activation_id.as_str().into(),
                retry_report_id: None,
            })
            .unwrap_err();
        assert!(
            error.contains("Runtime"),
            "invalid Runtime must refuse before any authentication: {error}"
        );
        assert!(!parent.join("report.json").exists());
    }
    #[test]
    fn acknowledged_same_invocation_malformed_repair_is_offline_and_refuses_valid_records() {
        let (mut guard, parent) = fixture();
        guard.set_env("TIRITH_OFFLINE", "1");
        private_file(&parent.join("enrollment.json"), b"{malformed-secret");
        assert!(TeamEnrollmentService::repair(RepairRequest {
            remove_malformed: false
        })
        .is_err());
        assert!(parent.join("enrollment.json").exists());
        let repaired = TeamEnrollmentService::repair(RepairRequest {
            remove_malformed: true,
        })
        .unwrap();
        assert_eq!(repaired["absence_confirmed"], true);
        assert!(!parent.join("enrollment.json").exists());
        let valid = json!({"schema_version":1,"connection_id":Id::new(),"authority_id":Id::new(),"policy_id":Id::new(),"activation_id":Id::new(),"client_id":Id::new(),"selection_commitment":PrivateCommitment::of("test",b"x"),"fetched_unix_ms":1,"cached_policy":null});
        let bytes = serde_json::to_vec(&valid).unwrap();
        private_file(&parent.join("enrollment.json"), &bytes);
        assert!(TeamEnrollmentService::repair(RepairRequest {
            remove_malformed: true
        })
        .is_err());
        assert_eq!(
            std::fs::read(parent.join("enrollment.json")).unwrap(),
            bytes
        );
    }
    #[test]
    fn explicit_abandonment_retains_unknown_request_and_requires_exact_id_and_acknowledgment() {
        let (_guard, _parent) = fixture();
        let r = record();
        let request = serde_json::to_vec(&r.request).unwrap();
        let (prior, _) = load_report().unwrap();
        save_report(&r, &prior, || Ok(())).unwrap();
        drop(prior);
        assert!(TeamEnrollmentService::abandon(AbandonRequest {
            report_id: r.request.report_id.as_str().into(),
            acknowledge_unknown_outcome: false
        })
        .is_err());
        assert!(TeamEnrollmentService::abandon(AbandonRequest {
            report_id: Id::new().as_str().into(),
            acknowledge_unknown_outcome: true
        })
        .is_err());
        let view = TeamEnrollmentService::abandon(AbandonRequest {
            report_id: r.request.report_id.as_str().into(),
            acknowledge_unknown_outcome: true,
        })
        .unwrap();
        assert_eq!(view["outcome"], "archived_outcome_unknown");
        let stored = load_report().unwrap().1.unwrap();
        assert!(stored.phase == ReportPhase::ArchivedUnknown);
        assert!(stored.receipt.is_none());
        assert_eq!(serde_json::to_vec(&stored.request).unwrap(), request);
        assert_eq!(carry_archives(Some(&stored)).unwrap().len(), 1);
    }
    #[test]
    fn status_offline_cache_fails_closed_when_runtime_refuses_a_fresh_cache() {
        use tirith_core::policy_team::{PolicyDocument, POLICY_SEMANTICS_VERSION};
        use tirith_core::policy_team_client::AuthorityBinding;
        let (mut guard, parent) = fixture();
        guard.set_env("TIRITH_OFFLINE", "1");
        let authority_id = Id::new();
        let policy_id = Id::new();
        let connection_id = Id::new();
        let binding = AuthorityBinding {
            schema_version: SCHEMA_VERSION,
            base_url: "https://must-not-contact.invalid".into(),
            authority_id: authority_id.clone(),
            policy_id: policy_id.clone(),
            transport: Default::default(),
        };
        private_file(&parent.join("connection.json"), &serde_json::to_vec(&json!({"schema_version":1,"connection_id":connection_id,"binding":binding,"credential":"c".repeat(64)})).unwrap());
        let connection = SelectedConnection::capture_current().unwrap();
        let now = now_ms().unwrap();
        let document = PolicyDocument {
            schema_version: 1,
            authority_id: authority_id.clone(),
            policy_id: policy_id.clone(),
            revision: Id::new(),
            created_unix_ms: now,
            policy_semantics_version: POLICY_SEMANTICS_VERSION,
            yaml: "paranoia: 2\n".into(),
        };
        private_file(&parent.join("enrollment.json"), &serde_json::to_vec(&json!({"schema_version":1,"connection_id":connection_id,"authority_id":authority_id,"policy_id":policy_id,"activation_id":Id::new(),"client_id":Id::new(),"selection_commitment":connection.private_selection_commitment().unwrap(),"fetched_unix_ms":now,"cached_policy":document})).unwrap());
        let cwd = guard.roots().cwd.clone();
        let status = || {
            TeamEnrollmentService::capture(cwd.to_str())
                .unwrap()
                .current()
                .unwrap()
        };
        let ready = status();
        assert_eq!(ready["state"], "ready_offline_cache", "{ready}");
        assert_eq!(ready["offline_cache"]["state"], "fresh");
        assert_eq!(ready["offline_cache"]["enforced"], true);
        assert_eq!(ready["offline_cache"]["fails_closed"], false);
        assert_eq!(ready["offline_cache"]["runtime_refused"], false);

        // A competing legacy authority makes Runtime fail closed although the
        // cache is fresh by age; the cache projection must agree.
        guard.set_env("TIRITH_SERVER_URL", "https://must-not-contact.invalid");
        guard.set_env("TIRITH_API_KEY", "legacy-secret");
        let refused = status();
        assert_eq!(refused["state"], "runtime_refused", "{refused}");
        let cache = &refused["offline_cache"];
        assert_eq!(cache["state"], "fresh");
        assert_eq!(cache["runtime_refused"], true);
        assert_eq!(cache["enforced"], false);
        assert_eq!(cache["fails_closed"], true);
        assert!(cache["time_left_ms"].is_null());
        let summary = cache["summary"].as_str().unwrap();
        assert!(summary.contains("Runtime refuses"), "{summary}");
        assert!(!summary.contains("is enforced"), "{summary}");
        assert!(!refused.to_string().contains("legacy-secret"));
    }
    /// R4.5: an expired cache is itself why Runtime refuses the enrollment, so
    /// status must name that cause, not a competing authority. With a
    /// competing authority as well, the cache cause still comes first: a sync
    /// is needed either way, and both fail closed.
    #[test]
    fn status_offline_cache_names_the_cache_cause_when_the_cache_is_unusable() {
        use tirith_core::policy_team::{PolicyDocument, POLICY_SEMANTICS_VERSION};
        use tirith_core::policy_team_client::AuthorityBinding;
        let (mut guard, parent) = fixture();
        guard.set_env("TIRITH_OFFLINE", "1");
        let authority_id = Id::new();
        let policy_id = Id::new();
        let connection_id = Id::new();
        let binding = AuthorityBinding {
            schema_version: SCHEMA_VERSION,
            base_url: "https://must-not-contact.invalid".into(),
            authority_id: authority_id.clone(),
            policy_id: policy_id.clone(),
            transport: Default::default(),
        };
        private_file(&parent.join("connection.json"), &serde_json::to_vec(&json!({"schema_version":1,"connection_id":connection_id,"binding":binding,"credential":"c".repeat(64)})).unwrap());
        let connection = SelectedConnection::capture_current().unwrap();
        // 24 h fresh window + 72 h default grace have both passed.
        let fetched = now_ms().unwrap() - 200 * 3_600_000;
        let document = PolicyDocument {
            schema_version: 1,
            authority_id: authority_id.clone(),
            policy_id: policy_id.clone(),
            revision: Id::new(),
            created_unix_ms: fetched,
            policy_semantics_version: POLICY_SEMANTICS_VERSION,
            yaml: "paranoia: 2\n".into(),
        };
        private_file(&parent.join("enrollment.json"), &serde_json::to_vec(&json!({"schema_version":1,"connection_id":connection_id,"authority_id":authority_id,"policy_id":policy_id,"activation_id":Id::new(),"client_id":Id::new(),"selection_commitment":connection.private_selection_commitment().unwrap(),"fetched_unix_ms":fetched,"cached_policy":document})).unwrap());
        let cwd = guard.roots().cwd.clone();
        let status = || {
            TeamEnrollmentService::capture(cwd.to_str())
                .unwrap()
                .current()
                .unwrap()
        };
        let check = |view: &Value| {
            assert_eq!(view["state"], "runtime_refused", "{view}");
            let cache = &view["offline_cache"];
            assert_eq!(cache["state"], "expired", "{view}");
            assert_eq!(cache["runtime_refused"], false, "{view}");
            assert_eq!(cache["enforced"], false);
            assert_eq!(cache["fails_closed"], true);
            assert_eq!(cache["time_left_ms"], 0);
            let summary = cache["summary"].as_str().unwrap();
            assert!(summary.contains("expired after its 72h"), "{summary}");
            assert!(summary.contains("blocked (fail closed)"), "{summary}");
            assert!(!summary.contains("Runtime refuses"), "{summary}");
            assert!(!summary.contains("competing"), "{summary}");
        };
        check(&status());
        guard.set_env("TIRITH_SERVER_URL", "https://must-not-contact.invalid");
        guard.set_env("TIRITH_API_KEY", "legacy-secret");
        let competing = status();
        check(&competing);
        assert!(!competing.to_string().contains("legacy-secret"));
    }
    #[test]
    fn withdrawal_between_capture_and_resolution_never_falls_through_to_legacy_contact() {
        let (mut guard, parent) = fixture();
        guard.set_env("TIRITH_SERVER_URL", "https://must-not-contact.invalid");
        guard.set_env("TIRITH_API_KEY", "legacy-secret");
        private_file(&parent.join("enrollment.json"), b"{malformed");
        let retained = TeamEnrollment::capture_current().unwrap();
        std::fs::remove_file(parent.join("enrollment.json")).unwrap();
        let snapshot = EffectivePolicySnapshot::resolve_runtime_without_network(None);
        assert_eq!(snapshot.remote.availability, "refused_local_mutation");
        assert!(retained.revalidate().is_err());
        assert!(!parent.join("report.json").exists());
    }
}

mod background_refresh {
    use super::*;

    #[test]
    fn background_refresh_is_claimed_at_most_once_per_interval() {
        let _guard = tirith_test_support::GlobalStateGuard::new().unwrap();
        let state = tirith_core::policy::state_dir().unwrap();
        let now = 10 * REFRESH_CLAIM_INTERVAL_MS;
        assert!(claim_background_refresh(&state, now));
        assert!(!claim_background_refresh(&state, now));
        assert!(!claim_background_refresh(
            &state,
            now + REFRESH_CLAIM_INTERVAL_MS - 1
        ));
        assert!(claim_background_refresh(
            &state,
            now + REFRESH_CLAIM_INTERVAL_MS
        ));
        // A clock that moved backwards cannot suppress refresh indefinitely.
        assert!(claim_background_refresh(&state, now));
        // Another process holding the claim lock means no claim here.
        #[cfg(unix)]
        {
            let _held = crate::cli::setup::fs_helpers::try_lock_operation(
                &state.join(REFRESH_CLAIM_LOCK),
                &state,
            )
            .unwrap()
            .unwrap();
            assert!(!claim_background_refresh(
                &state,
                now + 5 * REFRESH_CLAIM_INTERVAL_MS
            ));
        }
    }

    /// R4.8: one attempt per claim interval within a process, so the
    /// long-running MCP server and gateway retry while `tirith check` (one
    /// call) behaves as before.
    #[test]
    fn refresh_gate_allows_one_attempt_per_interval_in_a_process() {
        let gate = RefreshGate(AtomicU64::new(0));
        let now = 10 * REFRESH_CLAIM_INTERVAL_MS;
        assert!(gate.try_pass(now));
        assert!(!gate.try_pass(now));
        assert!(!gate.try_pass(now + REFRESH_CLAIM_INTERVAL_MS - 1));
        assert!(gate.try_pass(now + REFRESH_CLAIM_INTERVAL_MS));
        assert!(!gate.try_pass(now + REFRESH_CLAIM_INTERVAL_MS + 1));
        // A clock that moved back by more than an interval does not
        // suppress refresh indefinitely.
        assert!(gate.try_pass(now - 5 * REFRESH_CLAIM_INTERVAL_MS));
    }

    #[test]
    fn offline_mode_and_missing_enrollment_never_claim_or_spawn() {
        let mut guard = tirith_test_support::GlobalStateGuard::new().unwrap();
        let state = tirith_core::policy::state_dir().unwrap();
        guard.set_env("TIRITH_OFFLINE", "1");
        maybe_background_refresh(false);
        assert!(!state.join(REFRESH_CLAIM_FILE).exists());
        // Not enrolled: nothing is due, so nothing is claimed.
        assert!(TeamEnrollment::background_refresh_target(now_ms().unwrap()).is_none());
    }

    #[cfg(unix)]
    #[test]
    fn a_refresh_child_that_outlives_its_limit_is_killed_and_reaped() {
        let child = std::process::Command::new("sleep")
            .arg("30")
            .stdin(std::process::Stdio::null())
            .spawn()
            .unwrap();
        let pid = child.id();
        let started = std::time::Instant::now();
        reap_refresh_child(child, std::time::Duration::from_millis(200));
        assert!(
            started.elapsed() < std::time::Duration::from_secs(10),
            "the server refresh thread must not wait for a stuck child: {:?}",
            started.elapsed()
        );
        // Reaped: the pid no longer names our child.
        let alive = std::process::Command::new("kill")
            .args(["-0", &pid.to_string()])
            .status()
            .unwrap()
            .success();
        assert!(!alive, "child {pid} is still running");
    }

    #[test]
    fn background_child_arguments_parse_as_a_hidden_exact_sync() {
        use clap::Parser;
        #[derive(Parser)]
        struct Harness {
            #[command(subcommand)]
            action: Action,
        }
        let (connection, activation) = (Id::new(), Id::new());
        let args = background_sync_args(&connection, &activation);
        assert_eq!(&args[..4], ["policy", "team", "enrollment", "sync"]);
        let parsed = Harness::try_parse_from(
            std::iter::once("enrollment".to_string()).chain(args[3..].iter().cloned()),
        )
        .unwrap();
        match parsed.action {
            Action::Sync {
                options,
                background,
                json,
            } => {
                assert!(background);
                assert!(!json);
                assert_eq!(options.expected_connection_id, connection.as_str());
                assert_eq!(options.expected_activation_id, activation.as_str());
            }
            _ => panic!("background child must run the exact sync action"),
        }
    }
}
#[test]
fn status_shows_fresh_grace_and_fail_closed_cache_states_with_time_left() {
    let _shared_state = tirith_test_support::SharedStateGuard::acquire();
    const HOUR: u64 = 3_600_000;
    let now = 1_000 * HOUR;
    let status = |state, fetched_age: u64| CacheStatus {
        state,
        fetched_unix_ms: now - fetched_age,
        fresh_until_unix_ms: now - fetched_age + 24 * HOUR,
        grace_ms: Some(72 * HOUR),
        grace_until_unix_ms: Some(now - fetched_age + 96 * HOUR),
        refresh_due: fetched_age >= HOUR,
    };
    let fresh = offline_cache_projection(&status(CacheState::Fresh, 2 * HOUR), now, true);
    assert_eq!(fresh["state"], "fresh");
    assert_eq!(fresh["enforced"], true);
    assert_eq!(fresh["fails_closed"], false);
    assert_eq!(fresh["time_left_ms"], 22 * HOUR);
    assert_eq!(fresh["grace_hours"], 72);
    assert_eq!(fresh["refresh_due"], true);
    let summary = fresh["summary"].as_str().unwrap();
    assert!(
        summary.contains("fresh") && summary.contains("22h 0m more"),
        "{summary}"
    );
    assert!(summary.contains("background refresh is due"), "{summary}");

    let grace = offline_cache_projection(&status(CacheState::Grace, 30 * HOUR + 90_000), now, true);
    assert_eq!(grace["state"], "grace");
    assert_eq!(grace["enforced"], true);
    assert_eq!(grace["time_left_ms"], 66 * HOUR - 90_000);
    let summary = grace["summary"].as_str().unwrap();
    assert!(summary.contains("grace period"), "{summary}");
    assert!(summary.contains("2d 17h more"), "{summary}");
    assert!(summary.contains("fail closed"), "{summary}");
    assert!(
        summary.contains("tirith policy team enrollment sync"),
        "{summary}"
    );

    let expired = offline_cache_projection(&status(CacheState::Expired, 97 * HOUR), now, true);
    assert_eq!(expired["state"], "expired");
    assert_eq!(expired["enforced"], false);
    assert_eq!(expired["fails_closed"], true);
    assert_eq!(expired["time_left_ms"], 0);
    let summary = expired["summary"].as_str().unwrap();
    assert!(summary.contains("expired after its 72h"), "{summary}");
    assert!(summary.contains("blocked (fail closed)"), "{summary}");

    for state in [
        CacheState::FutureTimestamp,
        CacheState::Missing,
        CacheState::Invalid,
    ] {
        let value = offline_cache_projection(&status(state, 0), now, true);
        assert_eq!(value["fails_closed"], true, "{state:?}");
        assert!(value["time_left_ms"].is_null());
        assert!(value["summary"].as_str().unwrap().contains("fail closed"));
    }
    // A fresh or in-grace cache that Runtime refuses (competing authority,
    // replaced connection) is not enforced: every command fails closed.
    for state in [CacheState::Fresh, CacheState::Grace] {
        let value = offline_cache_projection(&status(state, 2 * HOUR), now, false);
        assert_eq!(value["runtime_refused"], true, "{state:?}");
        assert_eq!(value["enforced"], false, "{state:?}");
        assert_eq!(value["fails_closed"], true, "{state:?}");
        assert!(value["time_left_ms"].is_null(), "{state:?}");
        let summary = value["summary"].as_str().unwrap();
        assert!(summary.contains("Runtime refuses"), "{summary}");
        assert!(summary.contains("fail closed"), "{summary}");
        assert!(!summary.contains("is enforced"), "{summary}");
    }
    // R4.5: Runtime refuses an expired, future, missing or invalid cache
    // because of that state, so `runtime_ready` is false there. The projection
    // must still give the per-state cause, exactly as when it is true.
    for (state, cause) in [
        (CacheState::Expired, "expired after its 72h"),
        (CacheState::FutureTimestamp, "future fetch time"),
        (CacheState::Missing, "cache is missing"),
        (CacheState::Invalid, "cache is invalid"),
    ] {
        let refused = offline_cache_projection(&status(state, 97 * HOUR), now, false);
        let ready = offline_cache_projection(&status(state, 97 * HOUR), now, true);
        assert_eq!(refused, ready, "{state:?}");
        assert_eq!(refused["runtime_refused"], false, "{state:?}");
        assert_eq!(refused["enforced"], false, "{state:?}");
        assert_eq!(refused["fails_closed"], true, "{state:?}");
        let summary = refused["summary"].as_str().unwrap();
        assert!(summary.contains(cause), "{summary}");
        assert!(summary.contains("fail closed"), "{summary}");
        assert!(!summary.contains("Runtime refuses"), "{summary}");
    }
    assert_eq!(fresh["runtime_refused"], false);
    assert_eq!(duration(59_999), "0m");
    assert_eq!(duration(HOUR + 60_000), "1h 1m");
    assert_eq!(duration(49 * HOUR), "2d 1h");
}
