use super::*;
use crate::engine::AnalysisContext;
use crate::escalation::CallerContext;
use crate::evaluation::SessionEvidence;
use crate::extract::ScanContext;
use crate::tokenize::ShellType;
use tirith_test_support::GlobalStateGuard;

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
