//! Bounded policy impact and adoption evidence. Evaluation is pure over captured
//! observations; this module neither publishes policy nor issues permission.
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

use crate::evaluation::{DecisionKind, EvidenceGap, FrozenEvaluation};
use crate::policy::Policy;
use crate::policy_snapshot::{EffectivePolicySnapshot, ResolutionMode};
use crate::trust_grants::{GrantScope, GrantState, ProjectIdentity, TrustGrant};
use crate::verdict::RuleId;

pub const ROLLOUT_SCHEMA_VERSION: u32 = 1;
pub const MAX_WORKFLOWS: usize = 128;
pub const MAX_EXCEPTIONS: usize = 512;
pub const MAX_CLIENTS: usize = 1024;
pub const MAX_RULES_PER_WORKFLOW: usize = 32;
pub const EVIDENCE_MAX_AGE_SECONDS: i64 = 24 * 60 * 60;

/// Random record identity only: the team policy identity type, a canonical
/// nonzero UUID. A credential or command digest cannot be used as a public
/// record identifier through this API.
pub use crate::policy_team::Id as RecordId;

/// A record identity given in any UUID spelling (except nil), kept canonical.
pub fn record_id(value: &str) -> Result<RecordId, &'static str> {
    RecordId::normalize(value).map_err(|_| "rollout record identifiers must be UUIDs")
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RolloutScope {
    PersonalUser,
    LocalManaged,
    RemoteManaged,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CandidateCoverage {
    /// The caller has constructed the exact effective policy for this scope.
    EffectivePolicy,
    /// Personal settings may be masked by managed/repository/incident inputs.
    ManagedConstraintsUnresolved,
}

pub struct Workflow<'a> {
    pub id: RecordId,
    pub evidence: &'a FrozenEvaluation,
    pub owner: Option<RecordId>,
}

/// Ownership describes the captured operator-owned grant store. A declared
/// owner imported from another client is not authenticated by this read model.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum ExceptionOwner {
    LocalOperator { id: RecordId },
    Unavailable,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExceptionScope {
    User,
    Project,
}
pub struct Exception<'a> {
    pub grant: &'a TrustGrant,
    pub owner: ExceptionOwner,
    pub project: Option<&'a ProjectIdentity>,
}

/// Only a local Runtime snapshot can produce observed effective equivalence.
/// A client-supplied revision remains a report, never verified adoption.
pub struct ClientObservation {
    id: RecordId,
    observed_at: Option<DateTime<Utc>>,
    state: ClientState,
}
impl ClientObservation {
    pub fn local_runtime(
        id: RecordId,
        snapshot: &EffectivePolicySnapshot,
        candidate: &Policy,
        observed_at: DateTime<Utc>,
    ) -> Self {
        let state = if snapshot.resolution_mode != ResolutionMode::Runtime {
            ClientState::Unavailable
        } else if snapshot.policy.enforcement_projection_hash()
            == candidate.enforcement_projection_hash()
        {
            ClientState::LocalPolicyEquivalent
        } else {
            ClientState::LocalPolicyDifferent
        };
        Self {
            id,
            observed_at: Some(observed_at),
            state,
        }
    }
    pub fn unavailable(id: RecordId) -> Self {
        Self {
            id,
            observed_at: None,
            state: ClientState::Unavailable,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ClientState {
    LocalPolicyEquivalent,
    LocalPolicyDifferent,
    Stale,
    InvalidTimestamp,
    Unavailable,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ImpactChange {
    Unchanged,
    MoreRestrictive,
    LessRestrictive,
    Unavailable,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ImpactGap {
    StaleWorkflow,
    FutureWorkflow,
    DetectorEvidenceUnavailable,
    ManagedConstraintsUnresolved,
    NoWorkflows,
    ExceptionOwnersUnavailable,
    ExceptionInventoryUnavailable,
    RemotePublicationUnavailable,
    FleetAdoptionUnavailable,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkflowImpact {
    pub id: RecordId,
    pub evidence_id: RecordId,
    pub captured_at: DateTime<Utc>,
    pub owner: Option<RecordId>,
    pub before: DecisionKind,
    pub proposed: DecisionKind,
    pub change: ImpactChange,
    pub comparison_available: bool,
    pub before_gaps: Vec<EvidenceGap>,
    pub proposed_gaps: Vec<EvidenceGap>,
    pub gaps: Vec<ImpactGap>,
    pub rules: Vec<RuleId>,
    pub omitted_rules: usize,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExceptionImpact {
    pub id: RecordId,
    pub owner: ExceptionOwner,
    pub scope: ExceptionScope,
    pub before: GrantState,
    pub proposed: GrantState,
    pub expires_at: Option<DateTime<Utc>>,
    pub permanent: bool,
    pub owner_verified: bool,
    pub proposed_eligibility_available: bool,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClientImpact {
    pub id: RecordId,
    pub state: ClientState,
    pub observed_at: Option<DateTime<Utc>>,
}
#[derive(Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ImpactCounts {
    pub unchanged: usize,
    pub more_restrictive: usize,
    pub less_restrictive: usize,
    pub unavailable: usize,
    pub expired_exceptions: usize,
    pub unowned_exceptions: usize,
    pub local_equivalent: usize,
    pub local_different: usize,
    pub stale_clients: usize,
    pub unavailable_clients: usize,
}

/// This serializable contract contains only typed protocol fields, UUIDs and
/// timestamps. User labels/commands/reasons stay in the caller's private store
/// and must cross its captured DLP boundary separately.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ImpactReport {
    pub schema_version: u32,
    pub id: RecordId,
    pub candidate_id: RecordId,
    pub baseline_policy_identity: RecordId,
    pub scope: RolloutScope,
    pub candidate_coverage: CandidateCoverage,
    pub candidate_profile: Option<crate::protection_profiles::ProtectionProfile>,
    pub candidate_profile_version: Option<u32>,
    pub evaluated_at: DateTime<Utc>,
    pub workflows: Vec<WorkflowImpact>,
    pub exceptions: Vec<ExceptionImpact>,
    pub exception_inventory_complete: bool,
    pub clients: Vec<ClientImpact>,
    pub counts: ImpactCounts,
    pub gaps: Vec<ImpactGap>,
    pub remote_publication_available: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum HistoricalReviewFreshness {
    Recent,
    Stale,
    InvalidTimestamp,
}
impl HistoricalReviewFreshness {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Recent => "recent",
            Self::Stale => "stale",
            Self::InvalidTimestamp => "invalid_timestamp",
        }
    }
}

/// Read-time age checks on a validated historical attachment. No current grant
/// inventory, client contact, policy evaluation or adoption observation occurs.
/// This separate projection never changes the durable reviewed report.
#[derive(Clone, Debug, Serialize)]
pub struct HistoricalEvidenceStatus {
    pub schema_version: u32,
    pub checked_at: DateTime<Utc>,
    pub review_freshness: HistoricalReviewFreshness,
    /// Null when the review itself is future-dated; no elapsed interval exists.
    pub expiries_reached_since_review: Option<usize>,
    pub stale_client_timestamps: usize,
    pub future_client_timestamps: usize,
    pub missing_client_timestamps: usize,
}

impl ImpactReport {
    pub fn historical_evidence_status(
        &self,
        now: DateTime<Utc>,
    ) -> Result<HistoricalEvidenceStatus, String> {
        self.validate_stored()?;
        let review_freshness = if self.evaluated_at > now {
            HistoricalReviewFreshness::InvalidTimestamp
        } else if (now - self.evaluated_at).num_seconds() >= EVIDENCE_MAX_AGE_SECONDS {
            HistoricalReviewFreshness::Stale
        } else {
            HistoricalReviewFreshness::Recent
        };
        let expiries_reached_since_review = (self.evaluated_at <= now).then(|| {
            self.exceptions
                .iter()
                .filter(|exception| {
                    exception
                        .expires_at
                        .is_some_and(|at| self.evaluated_at < at && at <= now)
                })
                .count()
        });
        let mut result = HistoricalEvidenceStatus {
            schema_version: 1,
            checked_at: now,
            review_freshness,
            expiries_reached_since_review,
            stale_client_timestamps: 0,
            future_client_timestamps: 0,
            missing_client_timestamps: 0,
        };
        for client in &self.clients {
            match client.observed_at {
                Some(at) if at > now => result.future_client_timestamps += 1,
                Some(at) if (now - at).num_seconds() >= EVIDENCE_MAX_AGE_SECONDS => {
                    result.stale_client_timestamps += 1;
                }
                None => result.missing_client_timestamps += 1,
                _ => {}
            }
        }
        Ok(result)
    }

    /// Validate a private stored attachment before public projection. The
    /// report carries no authority flags (unknown fields are refused), and every
    /// derived value (row changes, client freshness, counts) must equal what the
    /// same derivation `review` uses gives for the stored rows.
    pub fn validate_stored(&self) -> Result<(), String> {
        if self.schema_version != ROLLOUT_SCHEMA_VERSION
            || (self.remote_publication_available && self.scope != RolloutScope::RemoteManaged)
        {
            return Err("unsupported rollout report version or authority claim".into());
        }
        match (self.candidate_profile, self.candidate_profile_version) {
            (Some(name), Some(version)) => {
                crate::protection_profiles::definition(name, version)?;
            }
            (None, None) => {}
            _ => return Err("stored rollout profile identity is incomplete".into()),
        }
        if self.workflows.len() > MAX_WORKFLOWS
            || self.exceptions.len() > MAX_EXCEPTIONS
            || self.clients.len() > MAX_CLIENTS
            || self.gaps.len() > 9
        {
            return Err("stored rollout report exceeds collection limits".into());
        }
        if self.gaps.contains(&ImpactGap::RemotePublicationUnavailable)
            == self.remote_publication_available
            || !self.gaps.contains(&ImpactGap::FleetAdoptionUnavailable)
            || (self.workflows.is_empty() && !self.gaps.contains(&ImpactGap::NoWorkflows))
        {
            return Err("stored rollout report omits required unavailable evidence".into());
        }
        if !self.exception_inventory_complete
            && !self
                .gaps
                .contains(&ImpactGap::ExceptionInventoryUnavailable)
        {
            return Err("stored rollout omits unavailable exception inventory".into());
        }
        let mut ids = BTreeSet::new();
        let mut evidence_ids = BTreeSet::new();
        for workflow in &self.workflows {
            if !ids.insert(&workflow.id)
                || !evidence_ids.insert(&workflow.evidence_id)
                || workflow.rules.len() > MAX_RULES_PER_WORKFLOW
                || workflow.before_gaps.len() > 5
                || workflow.proposed_gaps.len() > 5
                || workflow.gaps.len() > 4
            {
                return Err("stored rollout workflow has duplicate IDs or exceeds limits".into());
            }
            if workflow.comparison_available != workflow.gaps.is_empty()
                || workflow.change
                    != impact_change(workflow.before, workflow.proposed, &workflow.gaps)
                || (workflow
                    .before_gaps
                    .contains(&EvidenceGap::DetectorPolicyChanged)
                    || workflow
                        .proposed_gaps
                        .contains(&EvidenceGap::DetectorPolicyChanged))
                    && !workflow
                        .gaps
                        .contains(&ImpactGap::DetectorEvidenceUnavailable)
                || (self.candidate_coverage == CandidateCoverage::ManagedConstraintsUnresolved
                    && !workflow
                        .gaps
                        .contains(&ImpactGap::ManagedConstraintsUnresolved))
                || (workflow.captured_at > self.evaluated_at
                    && !workflow.gaps.contains(&ImpactGap::FutureWorkflow))
                || ((self.evaluated_at - workflow.captured_at).num_seconds()
                    >= EVIDENCE_MAX_AGE_SECONDS
                    && !workflow.gaps.contains(&ImpactGap::StaleWorkflow))
            {
                return Err("stored rollout workflow has inconsistent impact evidence".into());
            }
        }
        ids.clear();
        for exception in &self.exceptions {
            if !ids.insert(&exception.id)
                || exception.owner_verified
                    != matches!(exception.owner, ExceptionOwner::LocalOperator { .. })
                || (exception.permanent && exception.expires_at.is_some())
                || exception.proposed_eligibility_available
                    != (self.candidate_coverage == CandidateCoverage::EffectivePolicy)
            {
                return Err(
                    "stored rollout exception has inconsistent identity or ownership".into(),
                );
            }
        }
        ids.clear();
        for client in &self.clients {
            if !ids.insert(&client.id) {
                return Err("stored rollout has duplicate client IDs".into());
            }
            let expected = match client.observed_at {
                None => Some(ClientState::Unavailable),
                observed => client_freshness(observed, self.evaluated_at),
            };
            if expected.is_some_and(|expected| client.state != expected) {
                return Err("stored rollout client has inconsistent observation freshness".into());
            }
        }
        if ImpactCounts::derive(&self.workflows, &self.exceptions, &self.clients) != self.counts {
            return Err("stored rollout aggregate counts disagree with evidence".into());
        }
        if serde_json::to_vec(self)
            .map_err(|_| "cannot encode stored rollout report")?
            .len()
            > 256 * 1024
        {
            return Err("stored rollout report exceeds 256 KiB".into());
        }
        Ok(())
    }
}

pub struct ImpactRequest<'a> {
    pub id: RecordId,
    pub candidate_id: RecordId,
    pub scope: RolloutScope,
    pub baseline: &'a EffectivePolicySnapshot,
    pub candidate: &'a Policy,
    pub candidate_coverage: CandidateCoverage,
    pub workflows: &'a [Workflow<'a>],
    pub exceptions: &'a [Exception<'a>],
    pub exception_inventory_complete: bool,
    pub clients: &'a [ClientObservation],
    pub now: DateTime<Utc>,
}

pub fn review_for_publisher(
    request: ImpactRequest<'_>,
    publisher: &crate::policy_team_client::PublisherObservation,
) -> Result<ImpactReport, &'static str> {
    let now: u64 = request
        .now
        .timestamp_millis()
        .try_into()
        .map_err(|_| "invalid review clock")?;
    if request.scope != RolloutScope::RemoteManaged
        || now
            .checked_sub(publisher.observed_unix_ms)
            .is_none_or(|age| age > 60_000)
    {
        return Err("publisher observation is unavailable or stale");
    }
    let mut report = review(request)?;
    report.remote_publication_available = true;
    report
        .gaps
        .retain(|gap| *gap != ImpactGap::RemotePublicationUnavailable);
    report
        .validate_stored()
        .map_err(|_| "connected impact report failed validation")?;
    Ok(report)
}

pub fn review(request: ImpactRequest<'_>) -> Result<ImpactReport, &'static str> {
    if request.workflows.len() > MAX_WORKFLOWS
        || request.exceptions.len() > MAX_EXCEPTIONS
        || request.clients.len() > MAX_CLIENTS
    {
        return Err("rollout evidence exceeds bounded collection limits");
    }
    let mut workflow_ids = BTreeSet::new();
    let mut evidence_ids = BTreeSet::new();
    let mut exception_ids = BTreeSet::new();
    let mut client_ids = BTreeSet::new();
    for workflow in request.workflows {
        if !workflow_ids.insert(&workflow.id)
            || !evidence_ids.insert(record_id(&workflow.evidence.identity)?)
        {
            return Err("duplicate rollout workflow or evidence identity");
        }
    }
    for exception in request.exceptions {
        if !exception_ids.insert(record_id(&exception.grant.id)?) {
            return Err("duplicate rollout exception identity");
        }
    }
    for client in request.clients {
        if !client_ids.insert(&client.id) {
            return Err("duplicate rollout client identity");
        }
    }
    let mut gaps = vec![
        ImpactGap::RemotePublicationUnavailable,
        ImpactGap::FleetAdoptionUnavailable,
    ];
    if request.workflows.is_empty() {
        gaps.push(ImpactGap::NoWorkflows);
    }
    if !request.exception_inventory_complete {
        gaps.push(ImpactGap::ExceptionInventoryUnavailable);
    }
    if request.candidate_coverage == CandidateCoverage::ManagedConstraintsUnresolved {
        gaps.push(ImpactGap::ManagedConstraintsUnresolved);
    }
    let mut workflows = Vec::with_capacity(request.workflows.len());
    for workflow in request.workflows {
        let before = workflow
            .evidence
            .evaluate(&request.baseline.policy)
            .explanation;
        let proposed = workflow.evidence.evaluate(request.candidate).explanation;
        let mut row_gaps = Vec::new();
        if workflow.evidence.captured_at > request.now {
            row_gaps.push(ImpactGap::FutureWorkflow);
        } else if (request.now - workflow.evidence.captured_at).num_seconds()
            >= EVIDENCE_MAX_AGE_SECONDS
        {
            row_gaps.push(ImpactGap::StaleWorkflow);
        }
        if before.gaps.contains(&EvidenceGap::DetectorPolicyChanged)
            || proposed.gaps.contains(&EvidenceGap::DetectorPolicyChanged)
        {
            row_gaps.push(ImpactGap::DetectorEvidenceUnavailable);
        }
        if request.candidate_coverage == CandidateCoverage::ManagedConstraintsUnresolved {
            row_gaps.push(ImpactGap::ManagedConstraintsUnresolved);
        }
        let available = row_gaps.is_empty();
        let change = impact_change(before.decision, proposed.decision, &row_gaps);
        let mut rules = Vec::new();
        for restriction in before.restrictions.iter().chain(&proposed.restrictions) {
            if !rules.contains(&restriction.rule_id) {
                rules.push(restriction.rule_id);
            }
        }
        let omitted_rules = rules.len().saturating_sub(MAX_RULES_PER_WORKFLOW);
        rules.truncate(MAX_RULES_PER_WORKFLOW);
        workflows.push(WorkflowImpact {
            id: workflow.id.clone(),
            evidence_id: record_id(&workflow.evidence.identity)?,
            captured_at: workflow.evidence.captured_at,
            owner: workflow.owner.clone(),
            before: before.decision,
            proposed: proposed.decision,
            change,
            comparison_available: available,
            before_gaps: before.gaps,
            proposed_gaps: proposed.gaps,
            gaps: row_gaps,
            rules,
            omitted_rules,
        });
    }
    let mut exceptions = Vec::with_capacity(request.exceptions.len());
    for exception in request.exceptions {
        let before = exception
            .grant
            .status(
                exception.project,
                Some(&request.baseline.policy),
                request.now,
            )
            .state;
        let proposed = exception
            .grant
            .status(exception.project, Some(request.candidate), request.now)
            .state;
        let owner_verified = matches!(exception.owner, ExceptionOwner::LocalOperator { .. });
        exceptions.push(ExceptionImpact {
            id: record_id(&exception.grant.id)?,
            owner: exception.owner.clone(),
            scope: if matches!(exception.grant.scope, GrantScope::User) {
                ExceptionScope::User
            } else {
                ExceptionScope::Project
            },
            before,
            proposed,
            expires_at: exception
                .grant
                .expires_at
                .as_deref()
                .and_then(|value| DateTime::parse_from_rfc3339(value).ok())
                .map(|value| value.with_timezone(&Utc)),
            permanent: exception.grant.expires_at.is_none(),
            owner_verified,
            proposed_eligibility_available: request.candidate_coverage
                == CandidateCoverage::EffectivePolicy,
        });
    }
    if exceptions.iter().any(|exception| !exception.owner_verified) {
        gaps.push(ImpactGap::ExceptionOwnersUnavailable);
    }
    let clients: Vec<ClientImpact> = request
        .clients
        .iter()
        .map(|client| ClientImpact {
            id: client.id.clone(),
            state: client_freshness(client.observed_at, request.now).unwrap_or(client.state),
            observed_at: client.observed_at,
        })
        .collect();
    let counts = ImpactCounts::derive(&workflows, &exceptions, &clients);
    let report = ImpactReport {
        schema_version: ROLLOUT_SCHEMA_VERSION,
        id: request.id,
        candidate_id: request.candidate_id,
        baseline_policy_identity: record_id(&request.baseline.identity)?,
        scope: request.scope,
        candidate_coverage: request.candidate_coverage,
        candidate_profile: request
            .candidate
            .protection_profile
            .as_ref()
            .map(|profile| profile.name),
        candidate_profile_version: request
            .candidate
            .protection_profile
            .as_ref()
            .map(|profile| profile.version),
        evaluated_at: request.now,
        workflows,
        exceptions,
        exception_inventory_complete: request.exception_inventory_complete,
        clients,
        counts,
        gaps,
        remote_publication_available: false,
    };
    report
        .validate_stored()
        .map_err(|_| "rollout report exceeded its canonical evidence contract")?;
    Ok(report)
}

impl ImpactCounts {
    /// The one derivation of the aggregate counts, used to build a report and to
    /// check a stored one.
    fn derive(
        workflows: &[WorkflowImpact],
        exceptions: &[ExceptionImpact],
        clients: &[ClientImpact],
    ) -> Self {
        let mut counts = Self::default();
        for workflow in workflows {
            match workflow.change {
                ImpactChange::Unchanged => counts.unchanged += 1,
                ImpactChange::MoreRestrictive => counts.more_restrictive += 1,
                ImpactChange::LessRestrictive => counts.less_restrictive += 1,
                ImpactChange::Unavailable => counts.unavailable += 1,
            }
        }
        for exception in exceptions {
            if exception.before == GrantState::Expired {
                counts.expired_exceptions += 1;
            }
            if !exception.owner_verified {
                counts.unowned_exceptions += 1;
            }
        }
        for client in clients {
            match client.state {
                ClientState::LocalPolicyEquivalent => counts.local_equivalent += 1,
                ClientState::LocalPolicyDifferent => counts.local_different += 1,
                ClientState::Stale => counts.stale_clients += 1,
                ClientState::InvalidTimestamp | ClientState::Unavailable => {
                    counts.unavailable_clients += 1
                }
            }
        }
        counts
    }
}

/// A row's change: unavailable whenever the row has a gap, else the direction
/// of the decision rank.
fn impact_change(before: DecisionKind, proposed: DecisionKind, gaps: &[ImpactGap]) -> ImpactChange {
    if !gaps.is_empty() {
        return ImpactChange::Unavailable;
    }
    match rank(proposed).cmp(&rank(before)) {
        std::cmp::Ordering::Equal => ImpactChange::Unchanged,
        std::cmp::Ordering::Greater => ImpactChange::MoreRestrictive,
        std::cmp::Ordering::Less => ImpactChange::LessRestrictive,
    }
}

/// The state an observation's age forces at `at`: a future timestamp is
/// invalid and one at least `EVIDENCE_MAX_AGE_SECONDS` old is stale.
fn client_freshness(observed_at: Option<DateTime<Utc>>, at: DateTime<Utc>) -> Option<ClientState> {
    match observed_at {
        Some(observed) if observed > at => Some(ClientState::InvalidTimestamp),
        Some(observed) if (at - observed).num_seconds() >= EVIDENCE_MAX_AGE_SECONDS => {
            Some(ClientState::Stale)
        }
        _ => None,
    }
}

fn rank(decision: DecisionKind) -> u8 {
    match decision {
        DecisionKind::Allowed => 0,
        DecisionKind::Advisory => 1,
        DecisionKind::AcknowledgementRequired => 2,
        DecisionKind::Blocked => 3,
    }
}

#[cfg(test)]
#[path = "policy_rollout_tests.rs"]
mod tests;
