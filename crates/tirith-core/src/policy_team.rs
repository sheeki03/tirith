//! Wire contract for an explicitly selected, optional team policy authority.
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;

pub const SCHEMA_VERSION: u32 = 1;
pub const POLICY_SEMANTICS_VERSION: u32 = 1;
pub const CONTRACT: &str = "tirith_policy_management_v1";
pub const MAX_POLICY_BYTES: usize = 1024 * 1024;
pub const MAX_REQUEST_BYTES: usize = 2 * 1024 * 1024;
pub const MAX_RESPONSE_BYTES: usize = 2 * 1024 * 1024;
pub const MAX_CLIENTS: usize = 1024;
pub const MAX_REVIEW_AGE_MS: u64 = 24 * 60 * 60 * 1000;
pub const ROLLBACK_WINDOW_MS: u64 = 7 * 24 * 60 * 60 * 1000;
pub const REPORT_STALE_MS: u64 = 24 * 60 * 60 * 1000;
pub const MAX_FUTURE_SKEW_MS: u64 = 60 * 1000;

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(transparent)]
pub struct Id(String);
impl Id {
    pub fn parse(value: &str) -> Result<Self, ErrorCode> {
        let id = uuid::Uuid::parse_str(value).map_err(|_| ErrorCode::InvalidRequest)?;
        if id.is_nil() || id.to_string() != value {
            return Err(ErrorCode::InvalidRequest);
        }
        Ok(Self(value.into()))
    }
    pub fn new() -> Self {
        Self(uuid::Uuid::new_v4().to_string())
    }
    pub fn as_str(&self) -> &str {
        &self.0
    }
}
impl Default for Id {
    fn default() -> Self {
        Self::new()
    }
}
impl<'de> Deserialize<'de> for Id {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        Self::parse(&String::deserialize(d)?)
            .map_err(|_| serde::de::Error::custom("canonical nonzero UUID required"))
    }
}

#[derive(Clone, PartialEq, Eq, Serialize)]
#[serde(transparent)]
pub struct PrivateCommitment(String);
impl PrivateCommitment {
    pub fn parse(value: &str) -> Result<Self, ErrorCode> {
        if value.len() != 64
            || !value
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        {
            return Err(ErrorCode::InvalidRequest);
        }
        Ok(Self(value.into()))
    }
    pub fn of(domain: &'static str, bytes: &[u8]) -> Self {
        let mut digest = Sha256::new();
        digest.update((domain.len() as u64).to_be_bytes());
        digest.update(domain.as_bytes());
        digest.update((bytes.len() as u64).to_be_bytes());
        digest.update(bytes);
        Self(hex::encode(digest.finalize()))
    }
    pub fn as_str(&self) -> &str {
        &self.0
    }
}
impl std::fmt::Debug for PrivateCommitment {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("PrivateCommitment([redacted])")
    }
}
impl<'de> Deserialize<'de> for PrivateCommitment {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        Self::parse(&String::deserialize(d)?)
            .map_err(|_| serde::de::Error::custom("private commitment is invalid"))
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Role {
    Publisher,
    Observer,
    Client,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ErrorCode {
    InvalidRequest,
    Unauthorized,
    Forbidden,
    UnsupportedContract,
    AuthorityChanged,
    PolicyUninitialized,
    InvalidPolicy,
    ReviewExpired,
    RevisionConflict,
    OperationConflict,
    OperationNotFound,
    RollbackExpired,
    RollbackUnavailable,
    ClientUnknown,
    RevisionUnknown,
    ReportOutOfOrder,
    ReportStale,
    CapacityExceeded,
    StorageUnavailable,
    OutcomeUnknown,
    TransportUnavailable,
    InvalidResponse,
}
impl std::fmt::Display for ErrorCode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let value = serde_json::to_value(self).map_err(|_| std::fmt::Error)?;
        f.write_str(value.as_str().ok_or(std::fmt::Error)?)
    }
}
impl std::error::Error for ErrorCode {}

macro_rules! wire {
    ($name:ident { $($field:ident : $ty:ty),* $(,)? }) => {
        #[derive(Clone, Serialize, Deserialize)]
        #[serde(deny_unknown_fields)]
        pub struct $name { $(pub $field: $ty),* }
    };
}
wire!(Limits {
    max_policy_bytes: usize,
    max_clients: usize,
    max_review_age_ms: u64,
    rollback_window_ms: u64,
    report_stale_ms: u64,
});
impl Default for Limits {
    fn default() -> Self {
        Self {
            max_policy_bytes: MAX_POLICY_BYTES,
            max_clients: MAX_CLIENTS,
            max_review_age_ms: MAX_REVIEW_AGE_MS,
            rollback_window_ms: ROLLBACK_WINDOW_MS,
            report_stale_ms: REPORT_STALE_MS,
        }
    }
}
wire!(Capabilities {
    schema_version: u32,
    contract: String,
    authority_id: Id,
    policy_id: Id,
    role: Role,
    client_id: Option<Id>,
    client_report_sequence: Option<u64>,
    credential_expires_unix_ms: u64,
    policy_semantics_version: u32,
    limits: Limits,
});
wire!(PolicyDocument {
    schema_version: u32,
    authority_id: Id,
    policy_id: Id,
    revision: Id,
    created_unix_ms: u64,
    policy_semantics_version: u32,
    yaml: String,
});
wire!(PublicationRequest {
    schema_version: u32,
    operation_id: Id,
    authority_id: Id,
    policy_id: Id,
    expected_revision: Id,
    yaml: String,
    reviewed_unix_ms: u64,
    review_commitment: PrivateCommitment,
});
wire!(RollbackRequest {
    schema_version: u32,
    operation_id: Id,
    publication_id: Id,
    authority_id: Id,
    policy_id: Id,
    expected_revision: Id,
});
#[derive(Clone, Serialize, Deserialize)]
#[serde(
    tag = "kind",
    content = "request",
    rename_all = "snake_case",
    deny_unknown_fields
)]
pub enum OperationRequest {
    Publication(PublicationRequest),
    Rollback(RollbackRequest),
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OperationKind {
    Publication,
    Rollback,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OperationOutcome {
    Committed,
    Rejected,
}
wire!(OperationStatus {
    schema_version: u32, authority_id: Id, policy_id: Id, operation_id: Id, actor_id: Id,
    kind: OperationKind, outcome: OperationOutcome, failure_code: Option<ErrorCode>,
    publication_id: Option<Id>, expected_revision: Id, published_revision: Option<Id>,
    current_revision: Id, created_unix_ms: u64, rollback_until_unix_ms: Option<u64>,
    rollback_eligible: bool,
});
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReportState {
    Downloaded,
    Applied,
    Failed,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FailureReason {
    InvalidPolicy,
    IncompatibleClient,
    StorageUnavailable,
    LocalRestrictions,
    OtherUnavailable,
}
wire!(ClientReportRequest {
    schema_version: u32, report_id: Id, authority_id: Id, policy_id: Id,
    report_sequence: u64, applied_revision: Id, observed_unix_ms: u64, client_version: String,
    state: ReportState, failure_reason: Option<FailureReason>,
});
wire!(ReportReceipt {
    schema_version: u32,
    authority_id: Id,
    policy_id: Id,
    report_id: Id,
    client_id: Id,
    report_sequence: u64,
    received_unix_ms: u64,
});
wire!(RecordedClientReport {
    report_id: Id, report_sequence: u64, applied_revision: Id, observed_unix_ms: u64, received_unix_ms: u64,
    client_version: String, state: ReportState, failure_reason: Option<FailureReason>,
});
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ClientStatus {
    Unreported,
    Stale,
    Downloaded,
    AppliedCurrent,
    AppliedOlder,
    Failed,
}
wire!(ClientStatusEntry {
    client_id: Id, status: ClientStatus, report: Option<RecordedClientReport>,
});
wire!(FleetStatus {
    schema_version: u32, authority_id: Id, policy_id: Id, roster_revision: Id,
    sampled_unix_ms: u64, current_revision: Id, clients: Vec<ClientStatusEntry>,
    roster_complete: bool, fleet_adoption_verified: bool,
});
wire!(ErrorResponse {
    schema_version: u32,
    error: ErrorCode
});

pub fn schema(version: u32) -> Result<(), ErrorCode> {
    if version == SCHEMA_VERSION {
        Ok(())
    } else {
        Err(ErrorCode::UnsupportedContract)
    }
}
pub fn validate_review_time(observed: u64, now: u64) -> Result<(), ErrorCode> {
    if observed == 0
        || now
            .checked_sub(observed)
            .is_none_or(|age| age >= MAX_REVIEW_AGE_MS)
    {
        Err(ErrorCode::ReviewExpired)
    } else {
        Ok(())
    }
}
pub fn validate_client_version(value: &str) -> Result<(), ErrorCode> {
    if value.is_empty()
        || value.len() > 64
        || !value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b'+'))
    {
        return Err(ErrorCode::InvalidRequest);
    }
    Ok(())
}
impl Capabilities {
    pub fn validate(&self, now: u64) -> Result<(), ErrorCode> {
        schema(self.schema_version)?;
        if (self.role == Role::Client)
            != (self.client_id.is_some() && self.client_report_sequence.is_some())
            || (self.role != Role::Client
                && (self.client_id.is_some() || self.client_report_sequence.is_some()))
            || self
                .client_report_sequence
                .is_some_and(|sequence| sequence > i64::MAX as u64)
        {
            return Err(ErrorCode::InvalidResponse);
        }
        if self.contract != CONTRACT
            || self.policy_semantics_version != POLICY_SEMANTICS_VERSION
            || self.credential_expires_unix_ms <= now
            || self.limits.max_policy_bytes == 0
            || self.limits.max_policy_bytes > MAX_POLICY_BYTES
            || self.limits.max_clients == 0
            || self.limits.max_clients > MAX_CLIENTS
            || self.limits.max_review_age_ms != MAX_REVIEW_AGE_MS
            || self.limits.rollback_window_ms != ROLLBACK_WINDOW_MS
            || self.limits.report_stale_ms != REPORT_STALE_MS
        {
            return Err(ErrorCode::UnsupportedContract);
        }
        Ok(())
    }
}
impl PolicyDocument {
    pub fn validate(&self) -> Result<(), ErrorCode> {
        self.parsed_policy().map(|_| ())
    }
    pub(crate) fn parsed_policy(&self) -> Result<crate::policy::Policy, ErrorCode> {
        schema(self.schema_version)?;
        if self.created_unix_ms == 0 || self.policy_semantics_version != POLICY_SEMANTICS_VERSION {
            return Err(ErrorCode::InvalidResponse);
        }
        validate_policy(&self.yaml)
    }
}
impl PublicationRequest {
    pub fn validate_structure(&self) -> Result<(), ErrorCode> {
        schema(self.schema_version)?;
        if self.yaml.is_empty() || self.yaml.len() > MAX_POLICY_BYTES {
            return Err(ErrorCode::InvalidPolicy);
        }
        Ok(())
    }
}
impl ClientReportRequest {
    pub fn validate_structure(&self) -> Result<(), ErrorCode> {
        schema(self.schema_version)?;
        validate_client_version(&self.client_version)?;
        if self.report_sequence == 0
            || self.report_sequence > i64::MAX as u64
            || self.observed_unix_ms == 0
            || (self.state == ReportState::Failed) != self.failure_reason.is_some()
        {
            return Err(ErrorCode::InvalidRequest);
        }
        Ok(())
    }
    pub fn validate_time(&self, now: u64) -> Result<(), ErrorCode> {
        if self.observed_unix_ms > now.saturating_add(MAX_FUTURE_SKEW_MS)
            || now.saturating_sub(self.observed_unix_ms) >= REPORT_STALE_MS
        {
            return Err(ErrorCode::ReportStale);
        }
        Ok(())
    }
}
pub fn report_id(authority_id: &Id, client_id: &Id, sequence: u64) -> Result<Id, ErrorCode> {
    if sequence == 0 || sequence > i64::MAX as u64 {
        return Err(ErrorCode::InvalidRequest);
    }
    let mut digest = Sha256::new();
    digest.update(b"tirith-policy-client-report-id-v1\0");
    digest.update(authority_id.as_str().as_bytes());
    digest.update(client_id.as_str().as_bytes());
    digest.update(sequence.to_be_bytes());
    let hash = digest.finalize();
    let mut bytes = [0u8; 16];
    bytes.copy_from_slice(&hash[..16]);
    bytes[6] = (bytes[6] & 0x0f) | 0x80;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    Id::parse(&uuid::Uuid::from_bytes(bytes).to_string())
}

pub fn classify_client(
    report: Option<&RecordedClientReport>,
    current: &Id,
    now: u64,
) -> ClientStatus {
    let Some(report) = report else {
        return ClientStatus::Unreported;
    };
    if report.observed_unix_ms > now.saturating_add(MAX_FUTURE_SKEW_MS)
        || report.received_unix_ms > now
        || now.saturating_sub(report.observed_unix_ms) >= REPORT_STALE_MS
        || now.saturating_sub(report.received_unix_ms) >= REPORT_STALE_MS
    {
        return ClientStatus::Stale;
    }
    match report.state {
        ReportState::Downloaded => ClientStatus::Downloaded,
        ReportState::Failed => ClientStatus::Failed,
        ReportState::Applied if &report.applied_revision == current => ClientStatus::AppliedCurrent,
        ReportState::Applied => ClientStatus::AppliedOlder,
    }
}
impl FleetStatus {
    pub fn validate(&self) -> Result<(), ErrorCode> {
        schema(self.schema_version)?;
        if self.sampled_unix_ms == 0
            || self.clients.len() > MAX_CLIENTS
            || self.fleet_adoption_verified
            || !self.roster_complete
        {
            return Err(ErrorCode::InvalidResponse);
        }
        let mut seen = BTreeSet::new();
        for client in &self.clients {
            if !seen.insert(&client.client_id)
                || client.status
                    != classify_client(
                        client.report.as_ref(),
                        &self.current_revision,
                        self.sampled_unix_ms,
                    )
            {
                return Err(ErrorCode::InvalidResponse);
            }
            if let Some(report) = &client.report {
                validate_client_version(&report.client_version)?;
                if report.report_sequence == 0
                    || report.report_sequence > i64::MAX as u64
                    || report.report_id
                        != report_id(
                            &self.authority_id,
                            &client.client_id,
                            report.report_sequence,
                        )?
                    || report.observed_unix_ms == 0
                    || report.received_unix_ms == 0
                    || (report.state == ReportState::Failed) != report.failure_reason.is_some()
                {
                    return Err(ErrorCode::InvalidResponse);
                }
            }
        }
        Ok(())
    }
}

#[path = "policy_team_yaml.rs"]
mod bounded_yaml;
pub fn validate_policy(yaml: &str) -> Result<crate::policy::Policy, ErrorCode> {
    let bounded = bounded_yaml::parse(yaml)?;
    let mapping = bounded.as_mapping().ok_or(ErrorCode::InvalidPolicy)?;
    if ["policy_server_url", "policy_server_api_key"]
        .iter()
        .any(|key| mapping.contains_key(serde_yaml::Value::String((*key).into())))
    {
        return Err(ErrorCode::InvalidPolicy);
    }
    let normalized = serde_yaml::to_string(&bounded).map_err(|_| ErrorCode::InvalidPolicy)?;
    if normalized.len() > MAX_REQUEST_BYTES {
        return Err(ErrorCode::InvalidPolicy);
    }
    let document =
        crate::policy::Policy::parse_document(&normalized).map_err(|_| ErrorCode::InvalidPolicy)?;
    if !crate::policy_ignored::collect(document.migrated)
        .map_err(|_| ErrorCode::InvalidPolicy)?
        .is_empty()
        || document
            .policy
            .custom_rules
            .iter()
            .any(|rule| rule.validate_shape().is_err())
        || crate::policy_validate::validate(&normalized)
            .iter()
            .any(|issue| issue.level == crate::policy_validate::IssueLevel::Error)
    {
        return Err(ErrorCode::InvalidPolicy);
    }
    Ok(document.policy)
}

#[cfg(test)]
#[path = "policy_team_tests.rs"]
mod tests;
