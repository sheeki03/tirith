use super::*;
use crate::ssrf_guard::test_support::{http_response, ScriptedHttpServer};

fn private_options(address: &str) -> EndpointOptions {
    EndpointOptions {
        pinned_addresses: vec![address.parse().unwrap()],
        additional_ca_pem: None,
    }
}

#[test]
fn explicit_private_endpoint_pins_never_relax_tls_or_allow_metadata() {
    for address in ["10.1.2.3", "127.0.0.1", "100.64.3.2", "fd00::1", "::1"] {
        assert!(endpoint("https://policy.example/team", &private_options(address)).is_ok());
    }
    for address in [
        "0.0.0.0",
        "169.254.169.254",
        "100.100.100.200",
        "fd00:ec2::254",
        "fd20:ce::254",
        "224.0.0.1",
        "255.255.255.255",
        "::",
        "fe80::1",
        "ff02::1",
        "::ffff:127.0.0.1",
    ] {
        assert!(
            endpoint("https://policy.example", &private_options(address)).is_err(),
            "{address}"
        );
    }
    let options = private_options("10.1.2.3");
    for url in [
        "http://policy.example",
        "https://user:secret@policy.example",
        "https://policy.example?token=x",
        "https://policy.example/#x",
        "https://10.9.9.9",
        "https://policy.example:0",
        "https://metadata.google.internal",
    ] {
        assert!(endpoint(url, &options).is_err(), "{url}");
    }
    assert!(endpoint("https://10.1.2.3", &options).is_ok());
    assert!(endpoint("https://10.1.2.3", &EndpointOptions::default()).is_err());
    let mut duplicate = options;
    duplicate.pinned_addresses.push("10.1.2.3".parse().unwrap());
    assert!(endpoint("https://policy.example", &duplicate).is_err());
}

#[test]
fn credential_is_strict_and_debug_redacted() {
    let token = "c".repeat(64);
    let header = credential(&token).unwrap();
    assert!(!format!("{header:?}").contains(&token));
    for value in [
        "a".repeat(63),
        "a".repeat(65),
        "A".repeat(64),
        format!("{}\n", "a".repeat(63)),
    ] {
        assert_eq!(credential(&value).err(), Some(ErrorCode::Unauthorized));
    }
}

fn fixture_client(server: &ScriptedHttpServer, binding: &AuthorityBinding) -> TeamClient {
    let base = url::Url::parse(&format!("http://{}/tenant", server.address())).unwrap();
    // This constructor is private to unit tests; production endpoint admission
    // requires TLS, including explicit private address connections.
    TeamClient {
        http: reqwest::blocking::Client::builder()
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .timeout(Duration::from_secs(2))
            .build()
            .unwrap(),
        base,
        credential: credential(&"c".repeat(64)).unwrap(),
        binding: binding.clone(),
    }
}
fn binding() -> AuthorityBinding {
    AuthorityBinding {
        schema_version: SCHEMA_VERSION,
        base_url: "https://policy.example/tenant".into(),
        authority_id: Id::new(),
        policy_id: Id::new(),
        transport: EndpointOptions::default(),
    }
}
fn response(value: &impl Serialize) -> Vec<u8> {
    http_response(
        "200 OK",
        &[("Content-Type", "application/json")],
        &serde_json::to_vec(value).unwrap(),
    )
}

#[test]
fn actual_transport_binds_current_policy_authority_and_fixed_route() {
    let binding = binding();
    let value = PolicyDocument {
        schema_version: SCHEMA_VERSION,
        authority_id: Id::new(),
        policy_id: binding.policy_id.clone(),
        revision: Id::new(),
        created_unix_ms: clock_ms().unwrap(),
        policy_semantics_version: POLICY_SEMANTICS_VERSION,
        yaml: "paranoia: 2\n".into(),
    };
    let server = ScriptedHttpServer::start(vec![response(&value)]);
    assert_eq!(
        fixture_client(&server, &binding).current().err(),
        Some(ErrorCode::AuthorityChanged)
    );
    let requests = server.finish();
    assert_eq!(requests.len(), 1);
    let request = String::from_utf8_lossy(&requests[0]);
    assert!(request.starts_with("GET /tenant/api/policy/v1/current HTTP/1.1\r\n"));
    assert_eq!(request.matches("authorization:").count(), 1);
    assert!(!request.lines().next().unwrap().contains(&"c".repeat(64)));
}

#[test]
fn live_status_refuses_a_replayed_old_fleet_snapshot() {
    let binding = binding();
    let value = FleetStatus {
        schema_version: SCHEMA_VERSION,
        authority_id: binding.authority_id.clone(),
        policy_id: binding.policy_id.clone(),
        roster_revision: Id::new(),
        sampled_unix_ms: clock_ms().unwrap() - REPORT_STALE_MS,
        current_revision: Id::new(),
        clients: Vec::new(),
        roster_complete: true,
        fleet_adoption_verified: false,
    };
    assert!(value.validate().is_ok());
    let server = ScriptedHttpServer::start(vec![response(&value)]);
    assert_eq!(
        fixture_client(&server, &binding).status().err(),
        Some(ErrorCode::InvalidResponse)
    );
    assert_eq!(server.finish().len(), 1);
}

#[test]
fn malformed_publication_success_is_unknown_and_never_retried() {
    let binding = binding();
    let request = PublicationRequest {
        schema_version: SCHEMA_VERSION,
        operation_id: Id::new(),
        authority_id: binding.authority_id.clone(),
        policy_id: binding.policy_id.clone(),
        expected_revision: Id::new(),
        yaml: "paranoia: 3\n".into(),
        reviewed_unix_ms: clock_ms().unwrap(),
        review_commitment: PrivateCommitment::of("test", b"review"),
    };
    let server = ScriptedHttpServer::start(vec![http_response(
        "200 OK",
        &[("Content-Type", "application/json")],
        b"{\"schema_version\":1}",
    )]);
    assert_eq!(
        fixture_client(&server, &binding).publish(&request).err(),
        Some(ErrorCode::OutcomeUnknown)
    );
    let requests = server.finish();
    assert_eq!(requests.len(), 1);
    assert!(String::from_utf8_lossy(&requests[0]).contains(request.operation_id.as_str()));
}

#[test]
fn publication_response_cannot_substitute_the_expected_revision() {
    let binding = binding();
    let request = PublicationRequest {
        schema_version: SCHEMA_VERSION,
        operation_id: Id::new(),
        authority_id: binding.authority_id.clone(),
        policy_id: binding.policy_id.clone(),
        expected_revision: Id::new(),
        yaml: "paranoia: 3\n".into(),
        reviewed_unix_ms: clock_ms().unwrap(),
        review_commitment: PrivateCommitment::of("test", b"review"),
    };
    let published = Id::new();
    let status = OperationStatus {
        schema_version: SCHEMA_VERSION,
        authority_id: binding.authority_id.clone(),
        policy_id: binding.policy_id.clone(),
        operation_id: request.operation_id.clone(),
        actor_id: Id::new(),
        kind: OperationKind::Publication,
        outcome: OperationOutcome::Committed,
        failure_code: None,
        publication_id: None,
        expected_revision: Id::new(),
        published_revision: Some(published.clone()),
        current_revision: published,
        created_unix_ms: clock_ms().unwrap(),
        rollback_until_unix_ms: None,
        rollback_eligible: false,
    };
    let server = ScriptedHttpServer::start(vec![response(&status)]);
    assert_eq!(
        fixture_client(&server, &binding).publish(&request).err(),
        Some(ErrorCode::OutcomeUnknown)
    );
    assert_eq!(server.finish().len(), 1);
}

#[test]
fn actual_report_receipt_must_match_credential_client_and_sequence() {
    let binding = binding();
    let client_id = Id::new();
    let request = ClientReportRequest {
        schema_version: SCHEMA_VERSION,
        report_id: report_id(&binding.authority_id, &client_id, 5).unwrap(),
        report_sequence: 5,
        authority_id: binding.authority_id.clone(),
        policy_id: binding.policy_id.clone(),
        applied_revision: Id::new(),
        observed_unix_ms: clock_ms().unwrap(),
        client_version: "0.4.2".into(),
        state: ReportState::Downloaded,
        failure_reason: None,
    };
    let capabilities = Capabilities {
        schema_version: SCHEMA_VERSION,
        contract: CONTRACT.into(),
        authority_id: binding.authority_id.clone(),
        policy_id: binding.policy_id.clone(),
        role: Role::Client,
        client_id: Some(client_id),
        client_report_sequence: Some(4),
        credential_expires_unix_ms: clock_ms().unwrap() + 100_000,
        policy_semantics_version: POLICY_SEMANTICS_VERSION,
        limits: Limits::default(),
    };
    let receipt = ReportReceipt {
        schema_version: SCHEMA_VERSION,
        authority_id: binding.authority_id.clone(),
        policy_id: binding.policy_id.clone(),
        report_id: request.report_id.clone(),
        client_id: Id::new(),
        report_sequence: 5,
        received_unix_ms: clock_ms().unwrap(),
    };
    let server = ScriptedHttpServer::start(vec![response(&capabilities), response(&receipt)]);
    assert_eq!(
        fixture_client(&server, &binding).report(&request).err(),
        Some(ErrorCode::OutcomeUnknown)
    );
    assert_eq!(server.finish().len(), 2);
}
