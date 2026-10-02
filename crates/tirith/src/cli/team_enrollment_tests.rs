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
