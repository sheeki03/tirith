use super::*;

#[test]
fn wire_ids_and_private_commitments_have_closed_encodings() {
    let id = "aabbccdd-1122-4333-8444-555566667777";
    assert!(Id::parse(id).is_ok());
    for invalid in [
        id.to_uppercase(),
        "00000000-0000-0000-0000-000000000000".into(),
        id.replace('-', ""),
        format!("{{{id}}}"),
    ] {
        assert!(Id::parse(&invalid).is_err());
        assert!(serde_json::from_str::<Id>(&serde_json::to_string(&invalid).unwrap()).is_err());
    }
    let private = PrivateCommitment::of("publication-v1", b"private policy fixture");
    assert!(!format!("{private:?}").contains(private.as_str()));
    assert_ne!(
        private,
        PrivateCommitment::of("rollback-v1", b"private policy fixture")
    );
    assert!(PrivateCommitment::parse(&private.as_str().to_uppercase()).is_err());
}

#[test]
fn distributed_policy_uses_runtime_schema_and_rejects_connection_credentials() {
    let valid = "paranoia: 2\nprotection_profile:\n  name: balanced\n  version: 1\n";
    assert_eq!(validate_policy(valid).unwrap().paranoia, 2);
    for invalid in [
        "paranoia: 2\nunknown_root: true\n",
        "paranoia: 2\nprotection_profile:\n  name: balanced\n  version: 1\n  mystery: true\n",
        "policy_server_url: https://authority.example\n",
        "policy_server_api_key: secret\n",
        "policy_server_api_key: null\n",
        "policy_server_url: null\n",
        "paranoia: 1\nparanoia: 3\n",
        "paranoia: 999\n",
    ] {
        assert_eq!(
            validate_policy(invalid).err(),
            Some(ErrorCode::InvalidPolicy)
        );
    }
}

#[test]
fn policy_structure_and_alias_expansion_are_bounded_before_value_allocation() {
    let valid = "allowlist: &hosts [example.com]\nblocklist: *hosts\n";
    assert!(bounded_yaml::parse(valid).is_ok());
    let mut aliases = String::from("a: &a [leaf, leaf, leaf, leaf]\n");
    for (current, prior) in [
        ('b', 'a'),
        ('c', 'b'),
        ('d', 'c'),
        ('e', 'd'),
        ('f', 'e'),
        ('g', 'f'),
        ('h', 'g'),
    ] {
        aliases.push_str(&format!(
            "{current}: &{current} [*{prior}, *{prior}, *{prior}, *{prior}]\n"
        ));
    }
    assert!(aliases.len() < 1024);
    assert_eq!(
        bounded_yaml::parse(&aliases).err(),
        Some(ErrorCode::InvalidPolicy)
    );
    let deep = format!("list: {}0{}\n", "[".repeat(33), "]".repeat(33));
    let nodes = format!("list: [{}]\n", vec!["x"; 17000].join(","));
    for invalid in [
        deep,
        nodes,
        "paranoia: !custom 1\n".into(),
        "paranoia: 1\n---\nparanoia: 3\n".into(),
        "? [a,b]\n: true\n".into(),
        "paranoia: .nan\n".into(),
        "x".repeat(MAX_POLICY_BYTES + 1),
    ] {
        assert_eq!(
            bounded_yaml::parse(&invalid).err(),
            Some(ErrorCode::InvalidPolicy)
        );
    }
}

#[test]
fn review_time_has_exact_age_and_future_boundaries() {
    let now = MAX_REVIEW_AGE_MS * 4;
    assert!(validate_review_time(now, now).is_ok());
    assert!(validate_review_time(now - MAX_REVIEW_AGE_MS + 1, now).is_ok());
    for time in [0, now + 1, now - MAX_REVIEW_AGE_MS] {
        assert_eq!(
            validate_review_time(time, now),
            Err(ErrorCode::ReviewExpired)
        );
    }
}

fn report(state: ReportState, observed: u64) -> RecordedClientReport {
    RecordedClientReport {
        report_id: Id::new(),
        report_sequence: 1,
        applied_revision: Id::new(),
        observed_unix_ms: observed,
        received_unix_ms: observed,
        client_version: "0.4.2".into(),
        state,
        failure_reason: (state == ReportState::Failed).then_some(FailureReason::StorageUnavailable),
    }
}

#[test]
fn authenticated_reports_never_turn_missing_or_downloaded_into_applied() {
    let now = REPORT_STALE_MS * 4;
    let mut recorded = report(ReportState::Downloaded, now);
    let revision = recorded.applied_revision.clone();
    assert_eq!(
        classify_client(None, &revision, now),
        ClientStatus::Unreported
    );
    assert_eq!(
        classify_client(Some(&recorded), &revision, now),
        ClientStatus::Downloaded
    );
    recorded.state = ReportState::Applied;
    assert_eq!(
        classify_client(Some(&recorded), &revision, now),
        ClientStatus::AppliedCurrent
    );
    assert_eq!(
        classify_client(Some(&recorded), &Id::new(), now),
        ClientStatus::AppliedOlder
    );
    assert_eq!(
        classify_client(Some(&recorded), &revision, now + REPORT_STALE_MS),
        ClientStatus::Stale
    );
    recorded.observed_unix_ms = now + MAX_FUTURE_SKEW_MS + 1;
    assert_eq!(
        classify_client(Some(&recorded), &revision, now),
        ClientStatus::Stale
    );
}

#[test]
fn complete_roster_is_not_verified_enforcement_and_rejects_duplicate_clients() {
    let now = REPORT_STALE_MS * 4;
    let mut recorded = report(ReportState::Applied, now);
    let authority_id = Id::new();
    let client_id = Id::new();
    recorded.report_id = report_id(&authority_id, &client_id, recorded.report_sequence).unwrap();
    let mut status = FleetStatus {
        schema_version: SCHEMA_VERSION,
        authority_id,
        policy_id: Id::new(),
        roster_revision: Id::new(),
        sampled_unix_ms: now,
        current_revision: recorded.applied_revision.clone(),
        clients: vec![ClientStatusEntry {
            client_id,
            status: ClientStatus::AppliedCurrent,
            report: Some(recorded),
        }],
        roster_complete: true,
        fleet_adoption_verified: false,
    };
    assert!(status.validate().is_ok());
    let original_client = status.clients[0].client_id.clone();
    status.clients[0].client_id = Id::new();
    assert_eq!(status.validate(), Err(ErrorCode::InvalidResponse));
    status.clients[0].client_id = original_client;
    status.clients[0].report.as_mut().unwrap().report_sequence += 1;
    assert_eq!(status.validate(), Err(ErrorCode::InvalidResponse));
    status.clients[0].report.as_mut().unwrap().report_sequence -= 1;
    assert!(status.validate().is_ok());
    status.fleet_adoption_verified = true;
    assert_eq!(status.validate(), Err(ErrorCode::InvalidResponse));
    status.fleet_adoption_verified = false;
    status.clients.push(status.clients[0].clone());
    assert_eq!(status.validate(), Err(ErrorCode::InvalidResponse));
    status.clients.pop();
    status.clients[0].report = None;
    assert_eq!(status.validate(), Err(ErrorCode::InvalidResponse));
    status.clients[0].status = ClientStatus::Unreported;
    assert!(status.validate().is_ok());
}

#[test]
fn wire_unknown_fields_and_duplicate_fields_do_not_gain_authority() {
    let request = RollbackRequest {
        schema_version: SCHEMA_VERSION,
        operation_id: Id::new(),
        publication_id: Id::new(),
        authority_id: Id::new(),
        policy_id: Id::new(),
        expected_revision: Id::new(),
    };
    let mut value = serde_json::to_value(&request).unwrap();
    value["principal_id"] = serde_json::json!(Id::new());
    assert!(serde_json::from_value::<RollbackRequest>(value).is_err());
    let value = serde_json::to_string(&request).unwrap();
    let duplicate = value.replacen('{', "{\"schema_version\":1,", 1);
    assert!(serde_json::from_str::<RollbackRequest>(&duplicate).is_err());
}

#[test]
fn report_failure_shape_and_exact_time_bounds_are_enforced() {
    let now = REPORT_STALE_MS * 4;
    let mut request = ClientReportRequest {
        schema_version: SCHEMA_VERSION,
        report_id: Id::new(),
        report_sequence: 1,
        authority_id: Id::new(),
        policy_id: Id::new(),
        applied_revision: Id::new(),
        observed_unix_ms: now,
        client_version: "0.4.2".into(),
        state: ReportState::Applied,
        failure_reason: None,
    };
    assert!(request.validate_structure().is_ok());
    request.failure_reason = Some(FailureReason::OtherUnavailable);
    assert!(request.validate_structure().is_err());
    request.state = ReportState::Failed;
    assert!(request.validate_structure().is_ok());
    request.observed_unix_ms = now + MAX_FUTURE_SKEW_MS;
    assert!(request.validate_time(now).is_ok());
    request.observed_unix_ms += 1;
    assert!(request.validate_time(now).is_err());
    request.observed_unix_ms = now - REPORT_STALE_MS;
    assert!(request.validate_time(now).is_err());
    request.client_version = "0.4.2\nsecret".into();
    assert!(request.validate_structure().is_err());
}

#[test]
fn report_identity_is_bound_to_authority_client_and_sequence() {
    let authority = Id::new();
    let client = Id::new();
    let first = report_id(&authority, &client, 1).unwrap();
    assert_eq!(first, report_id(&authority, &client, 1).unwrap());
    assert_ne!(first, report_id(&authority, &client, 2).unwrap());
    assert_ne!(first, report_id(&Id::new(), &client, 1).unwrap());
    assert_ne!(first, report_id(&authority, &Id::new(), 1).unwrap());
    assert!(report_id(&authority, &client, 0).is_err());
    assert!(report_id(&authority, &client, u64::MAX).is_err());
    assert_eq!(first.as_str().as_bytes()[14], b'8');
}
