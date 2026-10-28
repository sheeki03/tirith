use super::*;
use std::os::unix::fs::{symlink, PermissionsExt};
use std::sync::{Arc, Barrier};

#[test]
fn report_reconciliation_is_read_only_and_binds_principal_and_exact_intent() {
    let fixture = Fixture::new();
    let identity = fixture.store.identity().unwrap();
    let client = fixture
        .store
        .register_client(&identity.authority_id, &identity.roster_revision)
        .unwrap();
    let (_, token) = fixture.credential(Role::Client, Some(&client));
    let request = ClientReportRequest {
        schema_version: SCHEMA_VERSION,
        report_id: report_id(&identity.authority_id, &client, 1).unwrap(),
        report_sequence: 1,
        authority_id: identity.authority_id.clone(),
        policy_id: identity.policy_id.clone(),
        applied_revision: identity.current_revision.clone(),
        observed_unix_ms: unix_ms().unwrap() - 1000,
        client_version: "0.4.2".into(),
        state: ReportState::Applied,
        failure_reason: None,
    };
    assert_error(
        fixture.store.reconcile_report(&token, request.clone()),
        ErrorCode::OperationNotFound,
    );
    assert_eq!(
        fixture
            .store
            .capabilities(&token)
            .unwrap()
            .client_report_sequence,
        Some(0)
    );
    assert_eq!(
        fixture.store.status(&fixture.token).unwrap().clients[0].status,
        ClientStatus::Unreported
    );
    let receipt = fixture.store.report(&token, request.clone()).unwrap();
    let reconciled = fixture
        .store
        .reconcile_report(&token, request.clone())
        .unwrap();
    assert_eq!(
        serde_json::to_value(receipt).unwrap(),
        serde_json::to_value(reconciled).unwrap()
    );
    for variant in 0..4 {
        let mut different = request.clone();
        match variant {
            0 => different.state = ReportState::Downloaded,
            1 => different.observed_unix_ms += 1,
            2 => different.applied_revision = Id::new(),
            _ => different.client_version = "0.4.3".into(),
        }
        assert_error(
            fixture.store.reconcile_report(&token, different),
            ErrorCode::OperationConflict,
        );
    }
    let (_, other_actor) = fixture.credential(Role::Client, Some(&client));
    assert_error(
        fixture
            .store
            .reconcile_report(&other_actor, request.clone()),
        ErrorCode::OperationConflict,
    );
    assert_error(
        fixture
            .store
            .reconcile_report(&fixture.token, request.clone()),
        ErrorCode::Forbidden,
    );
    let mut future = request.clone();
    future.report_sequence = 2;
    future.report_id = report_id(&identity.authority_id, &client, 2).unwrap();
    future.observed_unix_ms += 1;
    assert_error(
        fixture.store.reconcile_report(&token, future.clone()),
        ErrorCode::OperationNotFound,
    );
    assert_eq!(
        fixture
            .store
            .capabilities(&token)
            .unwrap()
            .client_report_sequence,
        Some(1)
    );
    fixture.store.report(&token, future).unwrap();
    assert_error(
        fixture.store.reconcile_report(&token, request),
        ErrorCode::OperationNotFound,
    );
    assert_eq!(
        fixture
            .store
            .capabilities(&token)
            .unwrap()
            .client_report_sequence,
        Some(2)
    );
}

#[test]
fn exact_intent_reconciliation_is_read_only_and_rejects_colliding_publications() {
    let f = Fixture::new();
    let request = f.request();
    let original = f.store.identity().unwrap().current_revision;
    assert_eq!(
        f.store
            .reconcile(&f.token, OperationRequest::Publication(request.clone()))
            .err(),
        Some(ErrorCode::OperationNotFound)
    );
    assert_eq!(f.store.identity().unwrap().current_revision, original);
    assert_eq!(
        f.store
            .operation_status(&f.token, &request.operation_id)
            .err(),
        Some(ErrorCode::OperationNotFound)
    );
    let published = f.store.publish(&f.token, request.clone()).unwrap();
    let reconciled = f
        .store
        .reconcile(&f.token, OperationRequest::Publication(request.clone()))
        .unwrap();
    assert_eq!(reconciled.published_revision, published.published_revision);
    for field in ["yaml", "review", "clock", "revision"] {
        let mut changed = request.clone();
        match field {
            "yaml" => changed.yaml = "paranoia: 4\n".into(),
            "review" => {
                changed.review_commitment = PrivateCommitment::of("other-review", b"different")
            }
            "clock" => changed.reviewed_unix_ms += 1,
            _ => changed.expected_revision = Id::new(),
        }
        assert_eq!(
            f.store
                .reconcile(&f.token, OperationRequest::Publication(changed))
                .err(),
            Some(ErrorCode::OperationConflict),
            "{field}"
        );
    }
    let (_, other_publisher) = f.credential(Role::Publisher, None);
    assert_eq!(
        f.store
            .reconcile(
                &other_publisher,
                OperationRequest::Publication(request.clone())
            )
            .err(),
        Some(ErrorCode::OperationConflict)
    );
    let (_, observer) = f.credential(Role::Observer, None);
    assert_eq!(
        f.store
            .reconcile(&observer, OperationRequest::Publication(request))
            .err(),
        Some(ErrorCode::Forbidden)
    );
    assert_eq!(
        Some(f.store.identity().unwrap().current_revision),
        published.published_revision
    );
}

#[test]
fn exact_rollback_reconciliation_cannot_create_or_retarget_an_operation() {
    let f = Fixture::new();
    let original = f.store.publish(&f.token, f.request()).unwrap();
    let rollback = RollbackRequest {
        schema_version: 1,
        operation_id: Id::new(),
        publication_id: original.operation_id,
        authority_id: original.authority_id,
        policy_id: original.policy_id,
        expected_revision: original.published_revision.unwrap(),
    };
    assert_eq!(
        f.store
            .reconcile(&f.token, OperationRequest::Rollback(rollback.clone()))
            .err(),
        Some(ErrorCode::OperationNotFound)
    );
    assert_eq!(
        f.store.identity().unwrap().current_revision,
        rollback.expected_revision
    );
    let result = f.store.rollback(&f.token, rollback.clone()).unwrap();
    assert_eq!(
        f.store
            .reconcile(&f.token, OperationRequest::Rollback(rollback.clone()))
            .unwrap()
            .published_revision,
        result.published_revision
    );
    let mut changed = rollback;
    changed.publication_id = Id::new();
    assert_eq!(
        f.store
            .reconcile(&f.token, OperationRequest::Rollback(changed))
            .err(),
        Some(ErrorCode::OperationConflict)
    );
}

pub(super) struct Fixture {
    pub root: tempfile::TempDir,
    pub path: std::path::PathBuf,
    pub store: Store,
    pub token: String,
    pub credential: Id,
}
impl Fixture {
    pub fn new() -> Self {
        assert_ne!(
            unsafe { libc::geteuid() },
            0,
            "native policy-server tests require an ordinary account"
        );
        let root = tempfile::tempdir().unwrap();
        let base = root.path().canonicalize().unwrap();
        std::fs::set_permissions(&base, std::fs::Permissions::from_mode(0o700)).unwrap();
        let path = base.join("authority");
        let store = Store::initialize(&path, "paranoia: 2\n").unwrap();
        let identity = store.identity().unwrap();
        let output = base.join("publisher.token");
        let credential = store
            .issue_credential(
                &identity.authority_id,
                Role::Publisher,
                &Id::new(),
                None,
                unix_ms().unwrap() + 80 * 24 * 60 * 60 * 1000,
                &output,
            )
            .unwrap();
        let token = std::fs::read_to_string(output)
            .unwrap()
            .trim_end_matches('\n')
            .to_owned();
        Self {
            root,
            path,
            store,
            token,
            credential,
        }
    }
    pub fn request(&self) -> PublicationRequest {
        let identity = self.store.identity().unwrap();
        PublicationRequest {
            schema_version: SCHEMA_VERSION,
            operation_id: Id::new(),
            authority_id: identity.authority_id,
            policy_id: identity.policy_id,
            expected_revision: identity.current_revision,
            yaml: "paranoia: 3\n".into(),
            reviewed_unix_ms: unix_ms().unwrap(),
            review_commitment: PrivateCommitment::of(
                "native-review-fixture",
                b"not independent review proof",
            ),
        }
    }
    pub fn credential(&self, role: Role, client: Option<&Id>) -> (Id, String) {
        let identity = self.store.identity().unwrap();
        let output = self
            .root
            .path()
            .canonicalize()
            .unwrap()
            .join(format!("{}.token", Id::new().as_str()));
        let id = self
            .store
            .issue_credential(
                &identity.authority_id,
                role,
                &Id::new(),
                client,
                unix_ms().unwrap() + 60_000,
                &output,
            )
            .unwrap();
        (
            id,
            std::fs::read_to_string(output)
                .unwrap()
                .trim_end_matches('\n')
                .into(),
        )
    }
}
fn assert_error<T>(result: Result<T>, expected: ErrorCode) {
    match result {
        Err(actual) => assert_eq!(actual, expected),
        Ok(_) => panic!("operation unexpectedly succeeded"),
    }
}
#[test]
fn native_initialize_reopen_and_private_credential() {
    let fixture = Fixture::new();
    let original = fixture.store.identity().unwrap();
    let reopened = Store::open(&fixture.path).unwrap();
    assert_eq!(
        reopened.identity().unwrap().authority_id,
        original.authority_id
    );
    assert_eq!(
        reopened.current(&fixture.token).unwrap().yaml,
        "paranoia: 2\n"
    );
    assert_eq!(fixture.token.len(), 64);
    assert!(fixture
        .token
        .bytes()
        .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)));
    assert_eq!(
        std::fs::metadata(fixture.path.join(DB))
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o600
    );
    assert_eq!(
        std::fs::metadata(fixture.root.path().join("publisher.token"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o600
    );
    let connection = fixture.store.inner.connection.lock().unwrap();
    let stored: Vec<u8> = connection
        .query_row(
            "SELECT token_hash FROM credentials WHERE id=?1",
            [fixture.credential.as_str()],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(stored, Sha256::digest(fixture.token.as_bytes()).to_vec());
    assert!(!std::fs::read(fixture.path.join(DB))
        .unwrap()
        .windows(64)
        .any(|w| w == fixture.token.as_bytes()));
}
#[test]
fn roles_expiry_revocation_and_scope_rechecked() {
    let fixture = Fixture::new();
    let (_, observer) = fixture.credential(Role::Observer, None);
    assert!(fixture.store.current(&observer).is_ok());
    assert!(fixture.store.status(&observer).is_ok());
    assert_error(
        fixture.store.publish(&observer, fixture.request()),
        ErrorCode::Forbidden,
    );
    let mut wrong = fixture.request();
    wrong.authority_id = Id::new();
    assert_error(
        fixture.store.publish(&fixture.token, wrong),
        ErrorCode::AuthorityChanged,
    );
    fixture
        .store
        .inner
        .connection
        .lock()
        .unwrap()
        .execute(
            "UPDATE credentials SET expires=1 WHERE id=?1",
            [fixture.credential.as_str()],
        )
        .unwrap();
    assert_error(
        fixture.store.current(&fixture.token),
        ErrorCode::Unauthorized,
    );
    fixture
        .store
        .inner
        .connection
        .lock()
        .unwrap()
        .execute(
            "UPDATE credentials SET expires=?1 WHERE id=?2",
            params![unix_ms().unwrap() + 10000, fixture.credential.as_str()],
        )
        .unwrap();
    fixture
        .store
        .revoke(
            &fixture.store.identity().unwrap().authority_id,
            &fixture.credential,
        )
        .unwrap();
    assert_error(
        fixture.store.publish(&fixture.token, fixture.request()),
        ErrorCode::Unauthorized,
    );
}
#[test]
fn lost_response_replay_precedes_age_and_newer_revision_and_reopen() {
    let mut fixture = Fixture::new();
    let request = fixture.request();
    let first = fixture
        .store
        .publish(&fixture.token, request.clone())
        .unwrap();
    let newer = fixture
        .store
        .publish(&fixture.token, fixture.request())
        .unwrap();
    fn tomorrow() -> Result<u64> {
        Ok(unix_ms()? + MAX_REVIEW_AGE_MS + 1)
    }
    fixture.store.clock = tomorrow;
    let again = fixture
        .store
        .publish(&fixture.token, request.clone())
        .unwrap();
    assert_eq!(again.published_revision, first.published_revision);
    assert_eq!(again.current_revision, newer.published_revision.unwrap());
    assert!(!again.rollback_eligible);
    let mut reopened = Store::open(&fixture.path).unwrap();
    reopened.clock = tomorrow;
    assert_eq!(
        reopened
            .publish(&fixture.token, request.clone())
            .unwrap()
            .published_revision,
        first.published_revision
    );
    let mut changed = request;
    changed.yaml = "paranoia: 4\n".into();
    assert_error(
        reopened.publish(&fixture.token, changed),
        ErrorCode::OperationConflict,
    );
}
#[test]
fn rejected_operation_is_retained_and_cannot_be_repurposed() {
    let fixture = Fixture::new();
    let mut request = fixture.request();
    request.reviewed_unix_ms = 1;
    let refused = fixture
        .store
        .publish(&fixture.token, request.clone())
        .unwrap();
    assert_eq!(refused.outcome, OperationOutcome::Rejected);
    assert_eq!(refused.failure_code, Some(ErrorCode::ReviewExpired));
    assert!(refused.published_revision.is_none());
    assert_eq!(
        fixture
            .store
            .publish(&fixture.token, request.clone())
            .unwrap()
            .failure_code,
        Some(ErrorCode::ReviewExpired)
    );
    request.reviewed_unix_ms = unix_ms().unwrap();
    assert_error(
        fixture.store.publish(&fixture.token, request),
        ErrorCode::OperationConflict,
    );
    let mut malformed = fixture.request();
    malformed.yaml = "unknown_team_field: true\n".into();
    let operation = malformed.operation_id.clone();
    assert_error(
        fixture.store.publish(&fixture.token, malformed),
        ErrorCode::InvalidPolicy,
    );
    assert_error(
        fixture.store.operation_status(&fixture.token, &operation),
        ErrorCode::OperationNotFound,
    );
}
#[test]
fn concurrent_distinct_publishers_compare_one_real_sqlite_generation() {
    let fixture = Fixture::new();
    let first = fixture.request();
    let mut second = first.clone();
    second.operation_id = Id::new();
    let barrier = Arc::new(Barrier::new(2));
    let other = Store::open(&fixture.path).unwrap();
    let token = fixture.token.clone();
    let gate = barrier.clone();
    let worker = std::thread::spawn(move || {
        gate.wait();
        other.publish(&token, second).unwrap()
    });
    barrier.wait();
    let result = fixture.store.publish(&fixture.token, first).unwrap();
    let other = worker.join().unwrap();
    assert_eq!(
        [result.outcome, other.outcome]
            .iter()
            .filter(|value| **value == OperationOutcome::Committed)
            .count(),
        1
    );
    assert_eq!(
        [result.failure_code, other.failure_code]
            .iter()
            .filter(|value| **value == Some(ErrorCode::RevisionConflict))
            .count(),
        1
    );
}
#[test]
fn rollback_restores_exact_yaml_as_new_revision_and_preserves_later_update() {
    let fixture = Fixture::new();
    let old = fixture.store.current(&fixture.token).unwrap();
    let published = fixture
        .store
        .publish(&fixture.token, fixture.request())
        .unwrap();
    let identity = fixture.store.identity().unwrap();
    let request = RollbackRequest {
        schema_version: SCHEMA_VERSION,
        operation_id: Id::new(),
        publication_id: published.operation_id,
        authority_id: identity.authority_id,
        policy_id: identity.policy_id,
        expected_revision: identity.current_revision,
    };
    let rolled = fixture
        .store
        .rollback(&fixture.token, request.clone())
        .unwrap();
    assert_eq!(rolled.outcome, OperationOutcome::Committed);
    let current = fixture.store.current(&fixture.token).unwrap();
    assert_eq!(current.yaml, old.yaml);
    assert_ne!(current.revision, old.revision);
    assert_eq!(
        fixture
            .store
            .rollback(&fixture.token, request.clone())
            .unwrap()
            .published_revision,
        rolled.published_revision
    );
    let newer = fixture
        .store
        .publish(&fixture.token, fixture.request())
        .unwrap();
    let mut retry = request;
    retry.operation_id = Id::new();
    retry.expected_revision = newer.published_revision.clone().unwrap();
    assert_eq!(
        fixture
            .store
            .rollback(&fixture.token, retry)
            .unwrap()
            .failure_code,
        Some(ErrorCode::RevisionConflict)
    );
    assert_eq!(
        fixture.store.current(&fixture.token).unwrap().revision,
        newer.published_revision.unwrap()
    );
}
#[test]
fn rollback_expiry_is_a_durable_rejected_operation() {
    let mut fixture = Fixture::new();
    let published = fixture
        .store
        .publish(&fixture.token, fixture.request())
        .unwrap();
    let identity = fixture.store.identity().unwrap();
    fn expired() -> Result<u64> {
        Ok(unix_ms()? + ROLLBACK_WINDOW_MS + 1)
    }
    fixture.store.clock = expired;
    let request = RollbackRequest {
        schema_version: SCHEMA_VERSION,
        operation_id: Id::new(),
        publication_id: published.operation_id,
        authority_id: identity.authority_id,
        policy_id: identity.policy_id,
        expected_revision: identity.current_revision,
    };
    let refused = fixture
        .store
        .rollback(&fixture.token, request.clone())
        .unwrap();
    assert_eq!(refused.failure_code, Some(ErrorCode::RollbackExpired));
    assert_eq!(
        fixture
            .store
            .rollback(&fixture.token, request)
            .unwrap()
            .failure_code,
        Some(ErrorCode::RollbackExpired)
    );
}
#[test]
fn native_sqlite_full_cannot_partially_publish_or_reserve_an_operation() {
    let fixture = Fixture::new();
    let before = fixture.store.current(&fixture.token).unwrap();
    let mut request = fixture.request();
    request.yaml = format!("paranoia: 3\n#{}\n", "x".repeat(256 * 1024));
    let operation = request.operation_id.clone();
    {
        let connection = fixture.store.inner.connection.lock().unwrap();
        let pages: u64 = connection
            .pragma_query_value(None, "page_count", |r| r.get(0))
            .unwrap();
        connection
            .pragma_update(None, "max_page_count", pages)
            .unwrap();
    }
    assert_error(
        fixture.store.publish(&fixture.token, request),
        ErrorCode::OutcomeUnknown,
    );
    assert_eq!(
        fixture.store.current(&fixture.token).unwrap().revision,
        before.revision
    );
    assert_error(
        fixture.store.operation_status(&fixture.token, &operation),
        ErrorCode::OperationNotFound,
    );
    assert_eq!(
        Store::open(&fixture.path)
            .unwrap()
            .current(&fixture.token)
            .unwrap()
            .yaml,
        before.yaml
    );
}
#[test]
fn private_file_symlink_shared_parent_and_secret_overwrite_refuse() {
    let fixture = Fixture::new();
    let base = fixture.root.path().canonicalize().unwrap();
    let link = base.join("linked");
    symlink(&fixture.path, &link).unwrap();
    assert!(Store::open(&link).is_err());
    let journal = fixture.path.join("authority.sqlite3-journal");
    symlink(base.join("not-owned"), &journal).unwrap();
    assert!(Store::open(&fixture.path).is_err());
    std::fs::remove_file(journal).unwrap();
    let secret = base.join("publisher.token");
    let old = std::fs::read(&secret).unwrap();
    assert!(fixture
        .store
        .issue_credential(
            &fixture.store.identity().unwrap().authority_id,
            Role::Publisher,
            &Id::new(),
            None,
            unix_ms().unwrap() + 10000,
            &secret
        )
        .is_err());
    assert_eq!(std::fs::read(secret).unwrap(), old);
    std::fs::set_permissions(&fixture.path, std::fs::Permissions::from_mode(0o750)).unwrap();
    assert!(Store::open(&fixture.path).is_err());
}
#[test]
fn local_import_and_roster_changes_are_revision_bound() {
    let fixture = Fixture::new();
    let identity = fixture.store.identity().unwrap();
    let first = fixture
        .store
        .register_client(&identity.authority_id, &identity.roster_revision)
        .unwrap();
    assert_error(
        fixture
            .store
            .register_client(&identity.authority_id, &identity.roster_revision),
        ErrorCode::RevisionConflict,
    );
    let changed = fixture
        .store
        .import(
            &identity.authority_id,
            &identity.current_revision,
            "paranoia: 4\n",
        )
        .unwrap();
    assert_ne!(changed, identity.current_revision);
    assert_error(
        fixture.store.import(
            &identity.authority_id,
            &identity.current_revision,
            "paranoia: 1\n",
        ),
        ErrorCode::RevisionConflict,
    );
    let (_, client_token) = fixture.credential(Role::Client, Some(&first));
    assert!(fixture.store.current(&client_token).is_ok());
    let roster = fixture.store.identity().unwrap().roster_revision;
    fixture
        .store
        .deactivate_client(&identity.authority_id, &roster, &first)
        .unwrap();
    assert_error(
        fixture.store.current(&client_token),
        ErrorCode::Unauthorized,
    );
    assert!(fixture
        .store
        .status(&fixture.token)
        .unwrap()
        .clients
        .is_empty());
}
#[test]
fn unsupported_schema_is_not_silently_reinitialized() {
    let fixture = Fixture::new();
    fixture
        .store
        .inner
        .connection
        .lock()
        .unwrap()
        .pragma_update(None, "user_version", 2)
        .unwrap();
    assert_error(Store::open(&fixture.path), ErrorCode::UnsupportedContract);
}
#[test]
fn reports_keep_one_monotonic_latest_row_and_never_claim_enforcement() {
    let fixture = Fixture::new();
    let identity = fixture.store.identity().unwrap();
    let client = fixture
        .store
        .register_client(&identity.authority_id, &identity.roster_revision)
        .unwrap();
    let (_, token) = fixture.credential(Role::Client, Some(&client));
    let caps = fixture.store.capabilities(&token).unwrap();
    assert_eq!(caps.client_id, Some(client.clone()));
    assert_eq!(caps.client_report_sequence, Some(0));
    let before = fixture.store.status(&fixture.token).unwrap();
    assert!(before.roster_complete);
    assert!(!before.fleet_adoption_verified);
    assert_eq!(before.clients[0].status, ClientStatus::Unreported);
    let request = ClientReportRequest {
        schema_version: SCHEMA_VERSION,
        report_id: report_id(&identity.authority_id, &client, 1).unwrap(),
        report_sequence: 1,
        authority_id: identity.authority_id.clone(),
        policy_id: identity.policy_id.clone(),
        applied_revision: identity.current_revision.clone(),
        observed_unix_ms: unix_ms().unwrap() - 1000,
        client_version: "0.4.2".into(),
        state: ReportState::Applied,
        failure_reason: None,
    };
    let first = fixture.store.report(&token, request.clone()).unwrap();
    let duplicate = fixture.store.report(&token, request.clone()).unwrap();
    assert_eq!(duplicate.received_unix_ms, first.received_unix_ms);
    let applied = fixture.store.status(&fixture.token).unwrap();
    assert_eq!(applied.clients[0].status, ClientStatus::AppliedCurrent);
    assert!(!applied.fleet_adoption_verified);
    let mut changed = request.clone();
    changed.state = ReportState::Downloaded;
    assert_error(
        fixture.store.report(&token, changed),
        ErrorCode::OperationConflict,
    );
    let mut gap = request.clone();
    gap.report_sequence = 3;
    gap.report_id = report_id(&identity.authority_id, &client, 3).unwrap();
    assert_error(
        fixture.store.report(&token, gap),
        ErrorCode::ReportOutOfOrder,
    );
    let mut next = request.clone();
    next.report_sequence = 2;
    next.report_id = report_id(&identity.authority_id, &client, 2).unwrap();
    next.observed_unix_ms += 1;
    next.state = ReportState::Downloaded;
    fixture.store.report(&token, next.clone()).unwrap();
    assert_error(
        fixture.store.report(&token, request.clone()),
        ErrorCode::ReportOutOfOrder,
    );
    assert_eq!(
        fixture
            .store
            .capabilities(&token)
            .unwrap()
            .client_report_sequence,
        Some(2)
    );
    let rows: u64 = fixture
        .store
        .inner
        .connection
        .lock()
        .unwrap()
        .query_row("SELECT count(*) FROM reports", [], |r| r.get(0))
        .unwrap();
    assert_eq!(rows, 1);
    let mut wrong_id = next.clone();
    wrong_id.report_sequence = 3;
    wrong_id.observed_unix_ms += 1;
    assert_error(
        fixture.store.report(&token, wrong_id),
        ErrorCode::InvalidRequest,
    );
    next.report_sequence = 3;
    next.report_id = report_id(&identity.authority_id, &client, 3).unwrap();
    assert_error(
        fixture.store.report(&token, next.clone()),
        ErrorCode::ReportOutOfOrder,
    );
    next.observed_unix_ms = 1;
    assert_error(
        fixture.store.report(&token, next.clone()),
        ErrorCode::ReportStale,
    );
    next.observed_unix_ms = unix_ms().unwrap();
    next.applied_revision = Id::new();
    assert_error(
        fixture.store.report(&token, next),
        ErrorCode::RevisionUnknown,
    );
    let (_, rotated) = fixture.credential(Role::Client, Some(&client));
    assert_eq!(
        fixture
            .store
            .capabilities(&rotated)
            .unwrap()
            .client_report_sequence,
        Some(2)
    );
    // New principal cannot impersonate the previous report's exact retry.
    let latest: RecordedClientReport = decode(
        &fixture
            .store
            .inner
            .connection
            .lock()
            .unwrap()
            .query_row::<String, _, _>(
                "SELECT record FROM reports WHERE client=?1",
                [client.as_str()],
                |r| r.get(0),
            )
            .unwrap(),
    )
    .unwrap();
    let old = ClientReportRequest {
        schema_version: SCHEMA_VERSION,
        report_sequence: latest.report_sequence,
        report_id: latest.report_id,
        authority_id: identity.authority_id,
        policy_id: identity.policy_id,
        applied_revision: latest.applied_revision,
        observed_unix_ms: latest.observed_unix_ms,
        client_version: latest.client_version,
        state: latest.state,
        failure_reason: latest.failure_reason,
    };
    assert_error(
        fixture.store.report(&rotated, old),
        ErrorCode::OperationConflict,
    );
}
#[test]
fn stale_reporting_remains_observation_and_active_roster_is_complete() {
    let mut fixture = Fixture::new();
    let identity = fixture.store.identity().unwrap();
    let client = fixture
        .store
        .register_client(&identity.authority_id, &identity.roster_revision)
        .unwrap();
    let output = fixture
        .root
        .path()
        .canonicalize()
        .unwrap()
        .join("long-client.token");
    fixture
        .store
        .issue_credential(
            &identity.authority_id,
            Role::Client,
            &Id::new(),
            Some(&client),
            unix_ms().unwrap() + 3 * MAX_REVIEW_AGE_MS,
            &output,
        )
        .unwrap();
    let token = std::fs::read_to_string(output)
        .unwrap()
        .trim_end_matches('\n')
        .to_owned();
    let request = ClientReportRequest {
        schema_version: SCHEMA_VERSION,
        report_sequence: 1,
        report_id: report_id(&identity.authority_id, &client, 1).unwrap(),
        authority_id: identity.authority_id,
        policy_id: identity.policy_id,
        applied_revision: identity.current_revision,
        observed_unix_ms: unix_ms().unwrap(),
        client_version: "0.4.2".into(),
        state: ReportState::Applied,
        failure_reason: None,
    };
    fixture.store.report(&token, request.clone()).unwrap();
    fn tomorrow() -> Result<u64> {
        Ok(unix_ms()? + REPORT_STALE_MS + 1)
    }
    fixture.store.clock = tomorrow;
    assert!(fixture
        .store
        .reconcile_report(&token, request.clone())
        .is_ok());
    assert!(fixture.store.report(&token, request).is_ok());
    let status = fixture.store.status(&fixture.token).unwrap();
    assert_eq!(status.clients[0].status, ClientStatus::Stale);
    assert!(status.roster_complete);
    assert!(!status.fleet_adoption_verified);
}
#[test]
fn expired_request_deadline_cannot_start_or_wait_then_publish() {
    let fixture = Fixture::new();
    let before = fixture.store.identity().unwrap().current_revision;
    let request = fixture.request();
    let operation = request.operation_id.clone();
    let expired = fixture
        .store
        .with_deadline(std::time::Instant::now() - Duration::from_millis(1));
    assert_error(
        expired.publish(&fixture.token, request),
        ErrorCode::OutcomeUnknown,
    );
    assert_eq!(fixture.store.identity().unwrap().current_revision, before);
    assert_error(
        fixture.store.operation_status(&fixture.token, &operation),
        ErrorCode::OperationNotFound,
    );
    let request = fixture.request();
    let queued = fixture
        .store
        .with_deadline(std::time::Instant::now() + Duration::from_millis(50));
    let token = fixture.token.clone();
    let guard = fixture.store.inner.connection.lock().unwrap();
    let worker = std::thread::spawn(move || queued.publish(&token, request));
    // The worker must finish from its own original deadline while the lock is held.
    let result = worker.join().unwrap();
    assert_error(result, ErrorCode::OutcomeUnknown);
    drop(guard);
    assert_eq!(fixture.store.identity().unwrap().current_revision, before);
}
#[test]
fn local_credential_inventory_recovers_identity_without_secret_material() {
    let fixture = Fixture::new();
    let identity = fixture.store.identity().unwrap();
    let rows = fixture.store.credentials(&identity.authority_id).unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].credential_id, fixture.credential);
    assert_eq!(rows[0].role, Role::Publisher);
    let serialized = serde_json::to_string(&rows).unwrap();
    assert!(!serialized.contains(&fixture.token));
    assert!(!serialized.contains("token_hash"));
    assert_error(
        fixture.store.credentials(&Id::new()),
        ErrorCode::AuthorityChanged,
    );
}

// Run in a genuinely separate process: SQLite's own inode bookkeeping would
// otherwise conceal loss of the kernel's process-scoped POSIX record locks.
#[test]
fn native_sqlite_lock_probe_child() {
    let Some(path) = std::env::var_os("TIRITH_POLICY_TEST_LOCK_DB") else {
        return;
    };
    assert_ne!(unsafe { libc::geteuid() }, 0);
    let mut connection = Connection::open_with_flags(
        path,
        OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_NOFOLLOW,
    )
    .unwrap();
    connection.busy_timeout(Duration::from_millis(50)).unwrap();
    let result = connection.transaction_with_behavior(TransactionBehavior::Immediate);
    match result {
        Err(rusqlite::Error::SqliteFailure(error, _))
            if error.code == rusqlite::ErrorCode::DatabaseBusy => {}
        _ => panic!("another process entered a transaction while the owner still held it"),
    }
}

fn assert_other_process_cannot_write(path: &Path) {
    let output = std::process::Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "store::tests::native_sqlite_lock_probe_child",
            "--nocapture",
        ])
        .env("TIRITH_POLICY_TEST_LOCK_DB", path.join(DB))
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "separate-process SQLite lock probe failed: {} {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
    assert!(String::from_utf8_lossy(&output.stdout).contains("1 passed"));
}

#[test]
fn native_identity_reopen_and_handle_drop_preserve_other_process_exclusion() {
    let fixture = Fixture::new();
    let reopened = Store::open(&fixture.path).unwrap();
    assert!(Arc::ptr_eq(
        fixture.store.inner.state.as_ref().unwrap(),
        reopened.inner.state.as_ref().unwrap(),
    ));
    let mut connection = fixture.store.inner.connection.lock().unwrap();
    let tx = connection
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .unwrap();
    tx.execute("UPDATE revisions SET created=created+1", [])
        .unwrap();
    // This was the v1 lock-loss point, even without another worker thread.
    fixture.store.check_files().unwrap();
    // A second Store must share the witness, and dropping it must not close one.
    drop(reopened);
    assert_other_process_cannot_write(&fixture.path);

    let queued = fixture
        .store
        .with_deadline(std::time::Instant::now() + Duration::from_millis(50));
    let worker = std::thread::spawn(move || queued.identity());
    assert_error(worker.join().unwrap(), ErrorCode::StorageUnavailable);
    // The worker above exercised the pre-mutex identity check too.
    assert_other_process_cannot_write(&fixture.path);
    tx.rollback().unwrap();
    drop(connection);
    let after = Store::open(&fixture.path).unwrap();
    assert_eq!(after.current(&fixture.token).unwrap().yaml, "paranoia: 2\n");
}

#[test]
fn native_sidecar_hardlink_refusal_preserves_other_database_process_locks() {
    let owner = Fixture::new();
    let inspected = Fixture::new();
    let mut connection = owner.store.inner.connection.lock().unwrap();
    let tx = connection
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .unwrap();
    tx.execute("UPDATE revisions SET created=created+1", [])
        .unwrap();
    let alias = inspected.path.join("authority.sqlite3-shm");
    std::fs::hard_link(owner.path.join(DB), &alias).unwrap();
    // The alias must be rejected using metadata, without opening then dropping
    // a descriptor belonging to the other live database's inode.
    assert_error(inspected.store.identity(), ErrorCode::StorageUnavailable);
    assert_other_process_cannot_write(&owner.path);
    std::fs::remove_file(alias).unwrap();
    tx.rollback().unwrap();
}

#[cfg(target_os = "macos")]
#[test]
fn native_macos_acl_revalidation_refuses_access_without_reopening_database() {
    let fixture = Fixture::new();
    let mut connection = fixture.store.inner.connection.lock().unwrap();
    let tx = connection
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .unwrap();
    let database = fixture.path.join(DB);
    let changed = std::process::Command::new("/bin/chmod")
        .args(["+a", "everyone allow read"])
        .arg(&database)
        .status()
        .unwrap();
    assert!(changed.success());
    let refused = Store::open(&fixture.path);
    let restored = std::process::Command::new("/bin/chmod")
        .args(["-a", "everyone allow read"])
        .arg(&database)
        .status()
        .unwrap();
    assert!(restored.success());
    assert_error(refused, ErrorCode::StorageUnavailable);
    assert_other_process_cannot_write(&fixture.path);
    tx.rollback().unwrap();
}
