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

/// Random record identity only. A credential or command digest cannot be used
/// as a public record identifier through this API.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(transparent)]
pub struct RecordId(String);
impl RecordId {
    pub fn parse(value: &str) -> Result<Self, &'static str> {
        uuid::Uuid::parse_str(value)
            .map(|id| Self(id.to_string()))
            .map_err(|_| "rollout record identifiers must be UUIDs")
    }
    pub fn as_str(&self) -> &str {
        &self.0
    }
}
impl<'de> Deserialize<'de> for RecordId {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let value = String::deserialize(deserializer)?;
        Self::parse(&value).map_err(serde::de::Error::custom)
    }
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
    DeclaredUnverified { id: RecordId },
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
    pub fn unverified_report(id: RecordId, observed_at: DateTime<Utc>) -> Self {
        Self {
            id,
            observed_at: Some(observed_at),
            state: ClientState::UnverifiedReport,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ClientState {
    LocalPolicyEquivalent,
    LocalPolicyDifferent,
    UnverifiedReport,
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
    pub unverified_clients: usize,
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
    pub execution_permitted: bool,
    pub automatically_approved: bool,
    pub remote_publication_available: bool,
    pub fleet_adoption_verified: bool,
}

impl ImpactReport {
    /// Validate a private stored attachment before public projection. No flag in
    /// a deserialized report may turn historical impact into execution authority.
    pub fn validate_stored(&self) -> Result<(), String> {
        if self.schema_version != ROLLOUT_SCHEMA_VERSION
            || self.execution_permitted
            || self.automatically_approved
            || self.remote_publication_available
            || self.fleet_adoption_verified
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
        if !self.gaps.contains(&ImpactGap::RemotePublicationUnavailable)
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
        let mut counts = ImpactCounts::default();
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
            let expected = if workflow.gaps.is_empty() {
                match rank(workflow.proposed).cmp(&rank(workflow.before)) {
                    std::cmp::Ordering::Equal => ImpactChange::Unchanged,
                    std::cmp::Ordering::Greater => ImpactChange::MoreRestrictive,
                    std::cmp::Ordering::Less => ImpactChange::LessRestrictive,
                }
            } else {
                ImpactChange::Unavailable
            };
            if workflow.comparison_available != workflow.gaps.is_empty()
                || workflow.change != expected
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
            match workflow.change {
                ImpactChange::Unchanged => counts.unchanged += 1,
                ImpactChange::MoreRestrictive => counts.more_restrictive += 1,
                ImpactChange::LessRestrictive => counts.less_restrictive += 1,
                ImpactChange::Unavailable => counts.unavailable += 1,
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
            if exception.before == GrantState::Expired {
                counts.expired_exceptions += 1;
            }
            if !exception.owner_verified {
                counts.unowned_exceptions += 1;
            }
        }
        ids.clear();
        for client in &self.clients {
            if !ids.insert(&client.id) {
                return Err("stored rollout has duplicate client IDs".into());
            }
            let age_state = match client.observed_at {
                Some(at) if at > self.evaluated_at => Some(ClientState::InvalidTimestamp),
                Some(at) if (self.evaluated_at - at).num_seconds() >= EVIDENCE_MAX_AGE_SECONDS => {
                    Some(ClientState::Stale)
                }
                None => Some(ClientState::Unavailable),
                _ => None,
            };
            if age_state.is_some_and(|expected| client.state != expected) {
                return Err("stored rollout client has inconsistent observation freshness".into());
            }
            match client.state {
                ClientState::LocalPolicyEquivalent => counts.local_equivalent += 1,
                ClientState::LocalPolicyDifferent => counts.local_different += 1,
                ClientState::Stale => counts.stale_clients += 1,
                ClientState::UnverifiedReport => counts.unverified_clients += 1,
                ClientState::InvalidTimestamp | ClientState::Unavailable => {
                    counts.unavailable_clients += 1
                }
            }
        }
        if counts != self.counts {
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
            || !evidence_ids.insert(RecordId::parse(&workflow.evidence.identity)?)
        {
            return Err("duplicate rollout workflow or evidence identity");
        }
    }
    for exception in request.exceptions {
        if !exception_ids.insert(RecordId::parse(&exception.grant.id)?) {
            return Err("duplicate rollout exception identity");
        }
    }
    for client in request.clients {
        if !client_ids.insert(&client.id) {
            return Err("duplicate rollout client identity");
        }
    }
    let mut counts = ImpactCounts::default();
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
        let change = if !available {
            ImpactChange::Unavailable
        } else {
            match rank(proposed.decision).cmp(&rank(before.decision)) {
                std::cmp::Ordering::Equal => ImpactChange::Unchanged,
                std::cmp::Ordering::Greater => ImpactChange::MoreRestrictive,
                std::cmp::Ordering::Less => ImpactChange::LessRestrictive,
            }
        };
        match change {
            ImpactChange::Unchanged => counts.unchanged += 1,
            ImpactChange::MoreRestrictive => counts.more_restrictive += 1,
            ImpactChange::LessRestrictive => counts.less_restrictive += 1,
            ImpactChange::Unavailable => counts.unavailable += 1,
        }
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
            evidence_id: RecordId::parse(&workflow.evidence.identity)?,
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
        if !owner_verified {
            counts.unowned_exceptions += 1;
        }
        if before == GrantState::Expired {
            counts.expired_exceptions += 1;
        }
        exceptions.push(ExceptionImpact {
            id: RecordId::parse(&exception.grant.id)?,
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
    if counts.unowned_exceptions > 0 {
        gaps.push(ImpactGap::ExceptionOwnersUnavailable);
    }
    let mut clients = Vec::with_capacity(request.clients.len());
    for client in request.clients {
        let state = match client.observed_at {
            Some(at) if at > request.now => ClientState::InvalidTimestamp,
            Some(at) if (request.now - at).num_seconds() >= EVIDENCE_MAX_AGE_SECONDS => {
                ClientState::Stale
            }
            _ => client.state,
        };
        match state {
            ClientState::LocalPolicyEquivalent => counts.local_equivalent += 1,
            ClientState::LocalPolicyDifferent => counts.local_different += 1,
            ClientState::Stale => counts.stale_clients += 1,
            ClientState::UnverifiedReport => counts.unverified_clients += 1,
            ClientState::InvalidTimestamp | ClientState::Unavailable => {
                counts.unavailable_clients += 1
            }
        }
        clients.push(ClientImpact {
            id: client.id.clone(),
            state,
            observed_at: client.observed_at,
        });
    }
    let report = ImpactReport {
        schema_version: ROLLOUT_SCHEMA_VERSION,
        id: request.id,
        candidate_id: request.candidate_id,
        baseline_policy_identity: RecordId::parse(&request.baseline.identity)?,
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
        execution_permitted: false,
        automatically_approved: false,
        remote_publication_available: false,
        fleet_adoption_verified: false,
    };
    report
        .validate_stored()
        .map_err(|_| "rollout report exceeded its canonical evidence contract")?;
    Ok(report)
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
