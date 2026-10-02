use super::*;
use crate::engine::AnalysisContext;
use crate::escalation::CallerContext;
use crate::evaluation::SessionEvidence;
use crate::extract::ScanContext;
use crate::tokenize::ShellType;
use tirith_test_support::GlobalStateGuard;

#[test]
fn connected_publisher_observation_is_scoped_fresh_and_never_execution_or_adoption() {
    let _state = GlobalStateGuard::new().unwrap();
    let snapshot = EffectivePolicySnapshot::resolve(None, ResolutionMode::Runtime);
    let now = Utc::now();
    let publisher = crate::policy_team_client::PublisherObservation {
        observed_unix_ms: now.timestamp_millis() as u64,
    };
    assert!(
        review_for_publisher(request(&snapshot, &snapshot.policy, &[], now), &publisher).is_err()
    );
    let mut input = request(&snapshot, &snapshot.policy, &[], now);
    input.scope = RolloutScope::RemoteManaged;
    let report = review_for_publisher(input, &publisher).unwrap();
    assert!(report.remote_publication_available);
    assert!(
        !report.execution_permitted
            && !report.automatically_approved
            && !report.fleet_adoption_verified
    );
    assert!(report.gaps.contains(&ImpactGap::FleetAdoptionUnavailable));
    assert!(!report
        .gaps
        .contains(&ImpactGap::RemotePublicationUnavailable));
    report.validate_stored().unwrap();
    let mut input = request(
        &snapshot,
        &snapshot.policy,
        &[],
        now + chrono::Duration::milliseconds(60_001),
    );
    input.scope = RolloutScope::RemoteManaged;
    assert!(review_for_publisher(input, &publisher).is_err());
    let mut forged = report;
    forged.scope = RolloutScope::PersonalUser;
    assert!(forged.validate_stored().is_err());
}

fn id() -> RecordId {
    RecordId::parse(&uuid::Uuid::new_v4().to_string()).unwrap()
}
fn capture(snapshot: &EffectivePolicySnapshot) -> FrozenEvaluation {
    FrozenEvaluation::capture(
        AnalysisContext {
            input: "curl https://example.com/PRIVATE_WORKFLOW".into(),
            shell: ShellType::Posix,
            scan_context: ScanContext::Exec,
            raw_bytes: None,
            interactive: true,
            cwd: std::env::current_dir()
                .ok()
                .map(|path| path.display().to_string()),
            file_path: None,
            repo_root: None,
            is_config_override: false,
            clipboard_html: None,
            card_ref: None,
            clipboard_source: crate::clipboard::ClipboardSourceState::AbsentOrInvalid,
        },
        snapshot,
        CallerContext::Cli,
        None,
        SessionEvidence::Unavailable,
    )
}
fn request<'a>(
    snapshot: &'a EffectivePolicySnapshot,
    candidate: &'a Policy,
    workflows: &'a [Workflow<'a>],
    now: DateTime<Utc>,
) -> ImpactRequest<'a> {
    ImpactRequest {
        id: id(),
        candidate_id: id(),
        scope: RolloutScope::PersonalUser,
        baseline: snapshot,
        candidate,
        candidate_coverage: CandidateCoverage::EffectivePolicy,
        workflows,
        exceptions: &[],
        exception_inventory_complete: true,
        clients: &[],
        now,
    }
}

fn history_fixture() -> ImpactReport {
    let now = DateTime::parse_from_rfc3339("2026-01-02T00:00:00Z")
        .unwrap()
        .with_timezone(&Utc);
    ImpactReport {
        schema_version: ROLLOUT_SCHEMA_VERSION,
        id: id(),
        candidate_id: id(),
        baseline_policy_identity: id(),
        scope: RolloutScope::LocalManaged,
        candidate_coverage: CandidateCoverage::EffectivePolicy,
        candidate_profile: None,
        candidate_profile_version: None,
        evaluated_at: now,
        workflows: vec![],
        exceptions: vec![],
        exception_inventory_complete: false,
        clients: vec![],
        counts: ImpactCounts::default(),
        gaps: vec![
            ImpactGap::RemotePublicationUnavailable,
            ImpactGap::FleetAdoptionUnavailable,
            ImpactGap::NoWorkflows,
            ImpactGap::ExceptionInventoryUnavailable,
        ],
        execution_permitted: false,
        automatically_approved: false,
        remote_publication_available: false,
        fleet_adoption_verified: false,
    }
}

#[test]
fn historical_age_projection_preserves_original_states_and_incomplete_inventory() {
    let mut report = history_fixture();
    let now = report.evaluated_at;
    report.clients = vec![
        ClientImpact {
            id: id(),
            state: ClientState::LocalPolicyEquivalent,
            observed_at: Some(now - chrono::Duration::seconds(EVIDENCE_MAX_AGE_SECONDS - 1)),
        },
        ClientImpact {
            id: id(),
            state: ClientState::UnverifiedReport,
            observed_at: Some(now),
        },
        ClientImpact {
            id: id(),
            state: ClientState::InvalidTimestamp,
            observed_at: Some(now + chrono::Duration::seconds(60)),
        },
        ClientImpact {
            id: id(),
            state: ClientState::Unavailable,
            observed_at: None,
        },
    ];
    report.counts.local_equivalent = 1;
    report.counts.unverified_clients = 1;
    report.counts.unavailable_clients = 2;
    let original = serde_json::to_vec(&report).unwrap();
    let initial = report.historical_evidence_status(now).unwrap();
    assert_eq!(initial.stale_client_timestamps, 0);
    let next = report
        .historical_evidence_status(now + chrono::Duration::seconds(1))
        .unwrap();
    assert_eq!(next.stale_client_timestamps, 1);
    assert_eq!(next.future_client_timestamps, 1);
    assert_eq!(next.missing_client_timestamps, 1);
    assert!(!next.current_client_policy_observed);
    assert!(!next.current_grant_state_observed);
    assert!(!next.fleet_adoption_verified);
    assert_eq!(serde_json::to_vec(&report).unwrap(), original);
    assert!(!report.exception_inventory_complete);
}

#[test]
fn historical_age_projection_handles_exact_expiry_staleness_and_clock_boundaries() {
    let mut report = history_fixture();
    let now = report.evaluated_at;
    for (seconds, before) in [(-1, GrantState::Expired), (15, GrantState::Effective)] {
        report.exceptions.push(ExceptionImpact {
            id: id(),
            owner: ExceptionOwner::LocalOperator { id: id() },
            scope: ExceptionScope::User,
            before,
            proposed: before,
            expires_at: Some(now + chrono::Duration::seconds(seconds)),
            permanent: false,
            owner_verified: true,
            proposed_eligibility_available: true,
        });
    }
    report.counts.expired_exceptions = 1;
    let at = |seconds| {
        report
            .historical_evidence_status(now + chrono::Duration::seconds(seconds))
            .unwrap()
    };
    assert_eq!(at(14).expiries_reached_since_review, Some(0));
    assert_eq!(at(15).expiries_reached_since_review, Some(1));
    assert_eq!(at(-1).expiries_reached_since_review, None);
    assert_eq!(
        at(-1).review_freshness,
        HistoricalReviewFreshness::InvalidTimestamp
    );
    assert_eq!(
        at(EVIDENCE_MAX_AGE_SECONDS - 1).review_freshness,
        HistoricalReviewFreshness::Recent
    );
    assert_eq!(
        at(EVIDENCE_MAX_AGE_SECONDS).review_freshness,
        HistoricalReviewFreshness::Stale
    );
    assert_eq!(report.counts.expired_exceptions, 1);
    assert_eq!(report.exceptions[1].before, GrantState::Effective);
}

#[test]
fn historical_age_projection_rejects_invalid_stored_authority_and_counts() {
    let mut report = history_fixture();
    report.execution_permitted = true;
    assert!(report
        .historical_evidence_status(report.evaluated_at)
        .is_err());
    report.execution_permitted = false;
    report.counts.local_equivalent = 1;
    assert!(report
        .historical_evidence_status(report.evaluated_at)
        .is_err());
    report.counts = ImpactCounts::default();
    report.clients = (0..=MAX_CLIENTS)
        .map(|_| ClientImpact {
            id: id(),
            state: ClientState::Unavailable,
            observed_at: None,
        })
        .collect();
    assert!(report
        .historical_evidence_status(report.evaluated_at)
        .is_err());
}

#[test]
fn frozen_impact_is_repeatable_and_never_approves_or_serializes_content() {
    let _state = GlobalStateGuard::new().unwrap();
    let snapshot = EffectivePolicySnapshot::resolve(None, ResolutionMode::Runtime);
    let frozen = capture(&snapshot);
    let workflows = [Workflow {
        id: id(),
        evidence: &frozen,
        owner: None,
    }];
    let mut candidate = snapshot.policy.clone();
    candidate.blocklist.push("example.com".into());
    let now = frozen.captured_at;
    let first = review(request(&snapshot, &candidate, &workflows, now)).unwrap();
    assert_eq!(first.workflows[0].change, ImpactChange::MoreRestrictive);
    assert_eq!(first.workflows[0].proposed, DecisionKind::Blocked);
    assert!(first.workflows[0]
        .proposed_gaps
        .contains(&EvidenceGap::SessionUnavailable));
    for _ in 0..3 {
        let again = review(request(&snapshot, &candidate, &workflows, now)).unwrap();
        assert_eq!(
            serde_json::to_value(&first.workflows).unwrap(),
            serde_json::to_value(&again.workflows).unwrap()
        );
        assert!(!again.execution_permitted);
        assert!(!again.automatically_approved);
        assert!(!again.remote_publication_available);
        assert!(!again.fleet_adoption_verified);
    }
    let text = serde_json::to_string(&first).unwrap();
    assert!(!text.contains("PRIVATE_WORKFLOW"));
    assert!(!text.contains("example.com"));
}

#[test]
fn detector_change_and_managed_constraints_do_not_invent_an_impact_direction() {
    let _state = GlobalStateGuard::new().unwrap();
    let snapshot = EffectivePolicySnapshot::resolve(None, ResolutionMode::Runtime);
    let frozen = capture(&snapshot);
    let workflows = [Workflow {
        id: id(),
        evidence: &frozen,
        owner: None,
    }];
    let mut candidate = snapshot.policy.clone();
    candidate.context_guard_enabled = !candidate.context_guard_enabled;
    let report = review(request(
        &snapshot,
        &candidate,
        &workflows,
        frozen.captured_at,
    ))
    .unwrap();
    assert_eq!(report.workflows[0].change, ImpactChange::Unavailable);
    assert!(report.workflows[0]
        .gaps
        .contains(&ImpactGap::DetectorEvidenceUnavailable));
    let mut input = request(&snapshot, &snapshot.policy, &workflows, frozen.captured_at);
    input.candidate_coverage = CandidateCoverage::ManagedConstraintsUnresolved;
    let managed = review(input).unwrap();
    assert_eq!(managed.counts.unavailable, 1);
    assert!(!managed.workflows[0].comparison_available);
}

#[test]
fn stale_and_future_workflow_evidence_are_explicitly_unavailable() {
    let _state = GlobalStateGuard::new().unwrap();
    let snapshot = EffectivePolicySnapshot::resolve(None, ResolutionMode::Runtime);
    let frozen = capture(&snapshot);
    let workflows = [Workflow {
        id: id(),
        evidence: &frozen,
        owner: None,
    }];
    let stale = review(request(
        &snapshot,
        &snapshot.policy,
        &workflows,
        frozen.captured_at + chrono::Duration::seconds(EVIDENCE_MAX_AGE_SECONDS),
    ))
    .unwrap();
    assert_eq!(stale.counts.unavailable, 1);
    assert!(stale.workflows[0].gaps.contains(&ImpactGap::StaleWorkflow));
    let future = review(request(
        &snapshot,
        &snapshot.policy,
        &workflows,
        frozen.captured_at - chrono::Duration::seconds(1),
    ))
    .unwrap();
    assert!(future.workflows[0]
        .gaps
        .contains(&ImpactGap::FutureWorkflow));
}

#[test]
fn exception_expiry_and_unverified_owner_remain_visible_without_leaking_patterns() {
    let _state = GlobalStateGuard::new().unwrap();
    let snapshot = EffectivePolicySnapshot::resolve(None, ResolutionMode::Runtime);
    let now = Utc::now();
    let grant = TrustGrant {
        id: id().as_str().into(),
        pattern: "PRIVATE_EXCEPTION".into(),
        rule_id: None,
        scope: GrantScope::User,
        created_at: (now - chrono::Duration::hours(1)).to_rfc3339(),
        expires_at: Some(now.to_rfc3339()),
        revoked_at: None,
        reason: Some("PRIVATE_REASON".into()),
    };
    let exceptions = [Exception {
        grant: &grant,
        owner: ExceptionOwner::DeclaredUnverified { id: id() },
        project: None,
    }];
    let mut input = request(&snapshot, &snapshot.policy, &[], now);
    input.exceptions = &exceptions;
    let report = review(input).unwrap();
    assert_eq!(report.counts.expired_exceptions, 1);
    assert_eq!(report.counts.unowned_exceptions, 1);
    assert!(!report.exceptions[0].permanent);
    assert!(!report.exceptions[0].owner_verified);
    assert_eq!(report.exceptions[0].before, GrantState::Expired);
    assert!(!serde_json::to_string(&report).unwrap().contains("PRIVATE_"));
}

#[test]
fn local_equivalence_is_distinct_from_stale_partial_or_unverified_fleet_adoption() {
    let _state = GlobalStateGuard::new().unwrap();
    let snapshot = EffectivePolicySnapshot::resolve(None, ResolutionMode::Runtime);
    let local_only = EffectivePolicySnapshot::resolve(None, ResolutionMode::LocalOnly);
    let mut other = snapshot.policy.clone();
    other.strict_warn = !other.strict_warn;
    let now = Utc::now();
    let clients = [
        ClientObservation::local_runtime(id(), &snapshot, &snapshot.policy, now),
        ClientObservation::local_runtime(id(), &snapshot, &other, now),
        ClientObservation::unverified_report(id(), now),
        ClientObservation::unverified_report(id(), now - chrono::Duration::days(1)),
        ClientObservation::unavailable(id()),
        ClientObservation::local_runtime(id(), &local_only, &local_only.policy, now),
    ];
    let mut input = request(&snapshot, &snapshot.policy, &[], now);
    input.clients = &clients;
    let report = review(input).unwrap();
    assert_eq!(report.counts.local_equivalent, 1);
    assert_eq!(report.counts.local_different, 1);
    assert_eq!(report.counts.unverified_clients, 1);
    assert_eq!(report.counts.stale_clients, 1);
    assert_eq!(report.counts.unavailable_clients, 2);
    assert!(!report.fleet_adoption_verified);
}

#[test]
fn identity_and_collection_limits_fail_before_running_evaluations() {
    let _state = GlobalStateGuard::new().unwrap();
    let snapshot = EffectivePolicySnapshot::resolve(None, ResolutionMode::Runtime);
    let frozen = capture(&snapshot);
    assert!(RecordId::parse("secret-content-hash").is_err());
    let workflows: Vec<_> = (0..MAX_WORKFLOWS + 1)
        .map(|_| Workflow {
            id: id(),
            evidence: &frozen,
            owner: None,
        })
        .collect();
    assert!(review(request(
        &snapshot,
        &snapshot.policy,
        &workflows,
        frozen.captured_at
    ))
    .is_err());
    assert!(review(request(
        &snapshot,
        &snapshot.policy,
        &workflows[..2],
        frozen.captured_at
    ))
    .is_err());
}

#[test]
fn stored_report_rejects_forged_authority_unknown_fields_and_inconsistent_evidence() {
    let _state = GlobalStateGuard::new().unwrap();
    let snapshot = EffectivePolicySnapshot::resolve(None, ResolutionMode::Runtime);
    let frozen = capture(&snapshot);
    let workflows = [Workflow {
        id: id(),
        evidence: &frozen,
        owner: None,
    }];
    let report = review(request(
        &snapshot,
        &snapshot.policy,
        &workflows,
        frozen.captured_at,
    ))
    .unwrap();
    let value = serde_json::to_value(&report).unwrap();
    let parsed: ImpactReport = serde_json::from_value(value.clone()).unwrap();
    parsed.validate_stored().unwrap();
    let mut forged = value.clone();
    forged["execution_permitted"] = true.into();
    assert!(serde_json::from_value::<ImpactReport>(forged)
        .unwrap()
        .validate_stored()
        .is_err());
    let mut forged = value.clone();
    forged["counts"]["more_restrictive"] = 99.into();
    assert!(serde_json::from_value::<ImpactReport>(forged)
        .unwrap()
        .validate_stored()
        .is_err());
    let mut forged = value.clone();
    forged["raw_command"] = "PRIVATE_INJECTION".into();
    assert!(serde_json::from_value::<ImpactReport>(forged).is_err());
    let mut forged = value;
    forged["id"] = "PRIVATE_IDENTIFIER".into();
    assert!(serde_json::from_value::<ImpactReport>(forged).is_err());
}
