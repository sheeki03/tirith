//! Explicit optional team Runtime enrollment and bounded offline policy cache.
//!
//! Selected connection configuration is not enrollment. Only the fixed private
//! enrollment record opts Runtime in. This module never publishes files: its
//! writer intents require an ordinary-owner native compare-and-swap adapter.
use crate::policy_team::{
    Capabilities, Id, PolicyDocument, PrivateCommitment, Role, SCHEMA_VERSION,
};
use crate::policy_team_connection::{
    ConnectionError, ConnectionWitness, SelectedConnection, TeamRecord, TeamRecordWitness,
};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::sync::Arc;

pub const MAX_ENROLLMENT_BYTES: usize = 2 * 1024 * 1024;
/// A cached team policy is fresh for 24 hours after its authenticated fetch.
pub const CACHE_MAX_AGE_MS: u64 = 24 * 60 * 60 * 1000;
/// After the fresh window, Runtime keeps enforcing the last-known-good team
/// policy (with a warning) for this long unless the team policy sets
/// `team_offline_grace_hours`. Only then does Runtime fail closed.
pub const DEFAULT_GRACE_HOURS: u32 = 72;
pub const DEFAULT_GRACE_MS: u64 = DEFAULT_GRACE_HOURS as u64 * HOUR_MS;
/// Fixed ceiling for an authority-selected grace period (30 days).
pub const MAX_GRACE_HOURS: u32 = 720;
/// A cache this old is refreshed by a detached background sync. The command
/// that notices it never waits for the network.
pub const REFRESH_AFTER_MS: u64 = HOUR_MS;
const HOUR_MS: u64 = 60 * 60 * 1000;
/// A network observation can prepare a private write for one minute. Long user
/// reviews need a fresh fetch and comparison; this is not a server CAS lease.
pub const FETCH_PREPARATION_MAX_AGE_MS: u64 = 60 * 1000;
pub const PRIVATE_RECORD_MODE: u32 = 0o600;

#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum EnrollmentError {
    #[error("team enrollment storage is unavailable or not private")]
    UnsafeStorage,
    #[error("team enrollment changed; repeat the explicit action")]
    ChangedEnrollment,
    #[error("team enrollment is malformed; explicit captured-record repair is required")]
    InvalidRecord,
    #[error("team Runtime is not enrolled")]
    NotEnrolled,
    #[error("expected team activation does not match the captured enrollment")]
    ActivationConflict,
    #[error("selected team connection changed; explicit activation is required")]
    ChangedConnection,
    #[error("team enrollment has no cached policy")]
    MissingCache,
    #[error("team policy cache is invalid")]
    InvalidCache,
    #[error(
        "team policy cache expired after its offline grace period; synchronization is required"
    )]
    StaleCache,
    #[error("team policy cache has a future fetch timestamp")]
    FutureCache,
    #[error("team authentication is unavailable")]
    AuthenticationFailed,
    #[error("team Runtime enrollment requires a client credential")]
    ClientRoleRequired,
    #[error("team fetch observation expired; fetch and compare again")]
    FetchExpired,
}
fn storage_error(error: ConnectionError) -> EnrollmentError {
    match error {
        ConnectionError::ChangedSelection => EnrollmentError::ChangedEnrollment,
        _ => EnrollmentError::UnsafeStorage,
    }
}
fn now_ms() -> Result<u64, EnrollmentError> {
    crate::util::now_ms().ok_or(EnrollmentError::FutureCache)
}
/// How Runtime may use a cached team policy of a given age.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CacheAge {
    /// Younger than [`CACHE_MAX_AGE_MS`].
    Fresh,
    /// Past the fresh window: the last-known-good policy is still enforced,
    /// with a warning, until `expires_unix_ms`.
    Grace { expires_unix_ms: u64 },
}
fn cache_time(fetched: u64, now: u64, grace_ms: u64) -> Result<CacheAge, EnrollmentError> {
    if fetched == 0 {
        return Err(EnrollmentError::InvalidCache);
    }
    let age = now
        .checked_sub(fetched)
        .ok_or(EnrollmentError::FutureCache)?;
    if age < CACHE_MAX_AGE_MS {
        return Ok(CacheAge::Fresh);
    }
    let expires_unix_ms = fetched
        .saturating_add(CACHE_MAX_AGE_MS)
        .saturating_add(grace_ms);
    if now < expires_unix_ms {
        Ok(CacheAge::Grace { expires_unix_ms })
    } else {
        Err(EnrollmentError::StaleCache)
    }
}
/// The authority chooses the grace period inside its own signed-off policy
/// document; local or repository policy cannot extend it.
fn grace_ms(policy: &crate::policy::Policy) -> u64 {
    u64::from(
        policy
            .team_offline_grace_hours
            .unwrap_or(DEFAULT_GRACE_HOURS)
            .min(MAX_GRACE_HOURS),
    ) * HOUR_MS
}
/// A background refresh is due once the cache is an hour old. A cache from the
/// future is not refreshed automatically; Runtime already refuses it.
fn refresh_due(fetched: u64, now: u64) -> bool {
    now.checked_sub(fetched)
        .is_some_and(|age| age >= REFRESH_AFTER_MS)
}

// Atomically embedding the document avoids a present enrollment accidentally
// using a missing or unrelated sidecar. Selection commitment is PRIVATE,
// contains no raw credential, and is never part of a status/report DTO.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Record {
    schema_version: u32,
    connection_id: Id,
    authority_id: Id,
    policy_id: Id,
    activation_id: Id,
    client_id: Id,
    selection_commitment: PrivateCommitment,
    fetched_unix_ms: u64,
    cached_policy: Option<PolicyDocument>,
}
fn decode(bytes: &[u8]) -> Result<Record, EnrollmentError> {
    if bytes.len() > MAX_ENROLLMENT_BYTES {
        return Err(EnrollmentError::InvalidRecord);
    }
    let record: Record =
        serde_json::from_slice(bytes).map_err(|_| EnrollmentError::InvalidRecord)?;
    if record.schema_version != SCHEMA_VERSION {
        return Err(EnrollmentError::InvalidRecord);
    }
    Ok(record)
}
/// Validate the cached document and classify its age. Returns the grace period
/// the document selected so later revalidation needs no reparse.
fn document(
    record: &Record,
    now: u64,
) -> Result<(&PolicyDocument, CacheAge, u64), EnrollmentError> {
    if record.fetched_unix_ms == 0 {
        return Err(EnrollmentError::InvalidCache);
    }
    let document = record
        .cached_policy
        .as_ref()
        .ok_or(EnrollmentError::MissingCache)?;
    if document.authority_id != record.authority_id
        || document.policy_id != record.policy_id
        || document.created_unix_ms
            > record
                .fetched_unix_ms
                .saturating_add(crate::policy_team::MAX_FUTURE_SKEW_MS)
    {
        return Err(EnrollmentError::InvalidCache);
    }
    let policy = document
        .parsed_policy()
        .map_err(|_| EnrollmentError::InvalidCache)?;
    let grace = grace_ms(&policy);
    let age = cache_time(record.fetched_unix_ms, now, grace)?;
    Ok((document, age, grace))
}
fn selected(record: &Record, connection: &ConnectionWitness) -> Result<(), EnrollmentError> {
    connection
        .revalidate()
        .map_err(|_| EnrollmentError::ChangedConnection)?;
    let binding = connection
        .binding()
        .ok_or(EnrollmentError::ChangedConnection)?;
    if connection.connection_id() != Some(&record.connection_id)
        || binding.authority_id != record.authority_id
        || binding.policy_id != record.policy_id
        || connection
            .private_selection_commitment()
            .map_err(|_| EnrollmentError::ChangedConnection)?
            != record.selection_commitment
    {
        return Err(EnrollmentError::ChangedConnection);
    }
    Ok(())
}

pub struct TeamEnrollment;
/// Captured private bytes and native generation, separate from Runtime admission.
/// Stale or malformed contents remain capturable for exact explicit recovery.
pub struct EnrollmentWitness {
    input: TeamRecordWitness,
    capture_id: Id,
    record: Result<Option<Record>, EnrollmentError>,
}
impl TeamEnrollment {
    pub fn capture_current() -> Result<EnrollmentWitness, EnrollmentError> {
        let input = TeamRecord::Enrollment
            .capture_current()
            .map_err(storage_error)?;
        let record = input.private_bytes().map(decode).transpose();
        Ok(EnrollmentWitness {
            input,
            capture_id: Id::new(),
            record,
        })
    }
    /// No DNS, HTTP, authentication refresh, directory creation, or cache write.
    pub(crate) fn capture_runtime() -> Result<RuntimeEnrollment, EnrollmentError> {
        let config_root = crate::policy::config_dir();
        if runtime_entry_absent(config_root.as_deref())? {
            let runtime = RuntimeEnrollment::Off { config_root };
            runtime.revalidate()?;
            return Ok(runtime);
        }
        // A present entry must pass the private reader. Its removal or a root
        // change between the probe and capture must not downgrade it to off.
        let enrollment = Arc::new(Self::capture_current()?);
        if !enrollment.configured() || config_root.as_deref() != Some(enrollment.private_scope()) {
            return Err(EnrollmentError::ChangedEnrollment);
        }
        enrollment.admit_runtime()
    }
    /// Offline and read-only: the exact activation to refresh when an enrolled
    /// cache is at least [`REFRESH_AFTER_MS`] old (including a cache in or past
    /// its grace period). Absent, withdrawn or malformed enrollment is never
    /// refreshed, so a background sync cannot recreate a withdrawn activation.
    pub fn background_refresh_target(now: u64) -> Option<RefreshTarget> {
        let config_root = crate::policy::config_dir();
        if runtime_entry_absent(config_root.as_deref()).unwrap_or(true) {
            return None;
        }
        let enrollment = Self::capture_current().ok()?;
        let record = enrollment.record().ok()?;
        refresh_due(record.fetched_unix_ms, now).then(|| RefreshTarget {
            connection_id: record.connection_id.clone(),
            activation_id: record.activation_id.clone(),
        })
    }
}
/// IDs a background `enrollment sync` must match exactly (compare-and-swap).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RefreshTarget {
    connection_id: Id,
    activation_id: Id,
}
impl RefreshTarget {
    pub fn connection_id(&self) -> &Id {
        &self.connection_id
    }
    pub fn activation_id(&self) -> &Id {
        &self.activation_id
    }
}
impl EnrollmentWitness {
    pub fn revalidate(&self) -> Result<(), EnrollmentError> {
        self.input.revalidate().map_err(storage_error)
    }
    fn record(&self) -> Result<&Record, EnrollmentError> {
        self.record
            .as_ref()
            .map_err(|error| *error)?
            .as_ref()
            .ok_or(EnrollmentError::NotEnrolled)
    }
    /// Opaque per-capture identity for explicit malformed-record repair. It is
    /// not a portable authorization token or a deterministic policy digest.
    pub fn capture_id(&self) -> &Id {
        &self.capture_id
    }
    pub fn configured(&self) -> bool {
        self.input.private_bytes().is_some()
    }
    pub fn activation_id(&self) -> Option<&Id> {
        self.record().ok().map(|record| &record.activation_id)
    }
    pub fn private_path(&self) -> &Path {
        self.input.private_path()
    }
    pub fn private_scope(&self) -> &Path {
        self.input.private_scope()
    }
    pub fn matches_private_bytes(&self, bytes: Option<&[u8]>) -> bool {
        self.input.private_bytes() == bytes
    }

    pub(crate) fn admit_runtime(self: &Arc<Self>) -> Result<RuntimeEnrollment, EnrollmentError> {
        self.revalidate()?;
        let (selected_connection, grace_ms) = match self.record.as_ref().map_err(|error| *error)? {
            None => (None, 0),
            Some(record) => {
                let connection = Arc::new(
                    SelectedConnection::capture_current()
                        .map_err(|_| EnrollmentError::ChangedConnection)?,
                );
                selected(record, &connection)?;
                let (_, _, grace_ms) = document(record, now_ms()?)?;
                (Some(connection), grace_ms)
            }
        };
        let runtime = RuntimeEnrollment::Strict {
            enrollment: Arc::clone(self),
            selected_connection,
            grace_ms,
        };
        runtime.revalidate()?;
        Ok(runtime)
    }
    /// Explicit activation can replace only the exact expected prior activation.
    /// Existing malformed bytes require a separate captured-record repair first.
    pub fn prepare_activation(
        self: &Arc<Self>,
        expected_activation: Option<&Id>,
        fetched: FetchedTeamPolicy,
    ) -> Result<EnrollmentWriteIntent, EnrollmentError> {
        self.revalidate()?;
        let previous = self.record.as_ref().map_err(|error| *error)?;
        if previous.as_ref().map(|record| &record.activation_id) != expected_activation {
            return Err(EnrollmentError::ActivationConflict);
        }
        self.prepare_write(fetched, Id::new(), EnrollmentWriteKind::Activate)
    }
    /// A sync repairs an expired/invalid/missing cached document but cannot
    /// rebind selection or change the activation identity.
    pub fn prepare_sync(
        self: &Arc<Self>,
        expected_activation: &Id,
        fetched: FetchedTeamPolicy,
    ) -> Result<EnrollmentWriteIntent, EnrollmentError> {
        self.revalidate()?;
        let previous = self.record()?;
        if &previous.activation_id != expected_activation {
            return Err(EnrollmentError::ActivationConflict);
        }
        selected(previous, &fetched.connection)?;
        if fetched.capabilities.client_id.as_ref() != Some(&previous.client_id) {
            return Err(EnrollmentError::ChangedConnection);
        }
        self.prepare_write(
            fetched,
            previous.activation_id.clone(),
            EnrollmentWriteKind::Sync,
        )
    }
    fn prepare_write(
        self: &Arc<Self>,
        fetched: FetchedTeamPolicy,
        activation: Id,
        kind: EnrollmentWriteKind,
    ) -> Result<EnrollmentWriteIntent, EnrollmentError> {
        fetched.revalidate()?;
        if fetched.connection.private_scope() != self.private_scope() {
            return Err(EnrollmentError::ChangedConnection);
        }
        let connection_id = fetched
            .connection
            .connection_id()
            .ok_or(EnrollmentError::ChangedConnection)?
            .clone();
        let record = Record {
            schema_version: SCHEMA_VERSION,
            connection_id,
            authority_id: fetched.document.authority_id.clone(),
            policy_id: fetched.document.policy_id.clone(),
            activation_id: activation,
            client_id: fetched
                .capabilities
                .client_id
                .clone()
                .ok_or(EnrollmentError::ClientRoleRequired)?,
            selection_commitment: fetched.selection_commitment.clone(),
            fetched_unix_ms: fetched.fetched_unix_ms,
            cached_policy: Some(fetched.document.clone()),
        };
        document(&record, now_ms()?)?;
        let encoded = serde_json::to_vec(&record).map_err(|_| EnrollmentError::InvalidCache)?;
        if encoded.len() > MAX_ENROLLMENT_BYTES {
            return Err(EnrollmentError::InvalidCache);
        }
        let intent = EnrollmentWriteIntent {
            previous: Arc::clone(self),
            replacement: Some(PrivateEnrollmentBytes(encoded)),
            fetched: Some(fetched),
            kind,
        };
        intent.revalidate()?;
        Ok(intent)
    }
    /// Withdrawal needs no valid/fresh policy, selected connection, or network.
    pub fn prepare_disable(
        self: &Arc<Self>,
        expected_activation: &Id,
    ) -> Result<EnrollmentWriteIntent, EnrollmentError> {
        self.revalidate()?;
        if &self.record()?.activation_id != expected_activation {
            return Err(EnrollmentError::ActivationConflict);
        }
        Ok(EnrollmentWriteIntent {
            previous: Arc::clone(self),
            replacement: None,
            fetched: None,
            kind: EnrollmentWriteKind::Disable,
        })
    }
    /// Only malformed captured bytes can use this path. The retained opaque
    /// capture identity binds removal without interpreting corrupt IDs/YAML.
    pub fn prepare_malformed_removal(
        self: &Arc<Self>,
        expected_capture: &Id,
    ) -> Result<EnrollmentWriteIntent, EnrollmentError> {
        self.revalidate()?;
        if expected_capture != &self.capture_id || self.record.is_ok() || !self.configured() {
            return Err(EnrollmentError::ActivationConflict);
        }
        Ok(EnrollmentWriteIntent {
            previous: Arc::clone(self),
            replacement: None,
            fetched: None,
            kind: EnrollmentWriteKind::RemoveMalformed,
        })
    }
}

/// Nonconstructible report evidence from the exact admitted enrollment. A caller
/// must additionally resolve and revalidate a full Runtime snapshot before any
/// Applied report; obtaining this object alone does not prove application.
#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub struct TeamRuntimeEvidence {
    connection_id: Id,
    authority_id: Id,
    policy_id: Id,
    activation_id: Id,
    client_id: Id,
    revision: Id,
    fetched_unix_ms: u64,
}
impl TeamRuntimeEvidence {
    pub fn connection_id(&self) -> &Id {
        &self.connection_id
    }
    pub fn authority_id(&self) -> &Id {
        &self.authority_id
    }
    pub fn policy_id(&self) -> &Id {
        &self.policy_id
    }
    pub fn activation_id(&self) -> &Id {
        &self.activation_id
    }
    pub fn client_id(&self) -> &Id {
        &self.client_id
    }
    pub fn revision(&self) -> &Id {
        &self.revision
    }
    pub fn fetched_unix_ms(&self) -> u64 {
        self.fetched_unix_ms
    }
}
/// Observe only the fixed final name. Missing optional enrollment does not
/// impose private-storage or alias restrictions on an ordinary personal setup.
/// Any final entry (including a dangling symlink) is present; other I/O errors
/// are ambiguous and must refuse. This reads no file content and creates nothing.
fn runtime_entry_absent(config_root: Option<&Path>) -> Result<bool, EnrollmentError> {
    let Some(root) = config_root else {
        return Ok(true);
    };
    let path = root.join("team-policy").join("enrollment.json");
    if !path.is_absolute()
        || path.as_os_str().len() > 8192
        || path.components().count() > 128
        || path.components().any(|component| {
            matches!(
                component,
                std::path::Component::ParentDir | std::path::Component::CurDir
            )
        })
    {
        return Err(EnrollmentError::UnsafeStorage);
    }
    match std::fs::symlink_metadata(path) {
        Ok(_) => Ok(false),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(true),
        Err(_) => Err(EnrollmentError::UnsafeStorage),
    }
}

/// Off retains the selected root and exact final-name absence, not a private
/// directory lease. Revalidation detects enrollment appearing through an alias
/// as well as a changed root. Present enrollment retains its strict native lease.
#[derive(Clone)]
pub(crate) enum RuntimeEnrollment {
    Off {
        config_root: Option<PathBuf>,
    },
    Strict {
        enrollment: Arc<EnrollmentWitness>,
        selected_connection: Option<Arc<ConnectionWitness>>,
        /// Grace period chosen by the admitted document (0 without one).
        grace_ms: u64,
    },
}
impl RuntimeEnrollment {
    /// Age class of the admitted cache, for Runtime's grace-period warning.
    /// `None` when team policy is off or the cache no longer qualifies.
    pub fn cache_age(&self) -> Option<CacheAge> {
        let Self::Strict {
            enrollment,
            grace_ms,
            ..
        } = self
        else {
            return None;
        };
        let record = enrollment.record().ok()?;
        cache_time(record.fetched_unix_ms, now_ms().ok()?, *grace_ms).ok()
    }
    pub fn document(&self) -> Option<&PolicyDocument> {
        match self {
            Self::Off { .. } => None,
            Self::Strict { enrollment, .. } => enrollment
                .record()
                .ok()
                .and_then(|record| record.cached_policy.as_ref()),
        }
    }
    pub fn evidence(&self) -> Option<TeamRuntimeEvidence> {
        let Self::Strict { enrollment, .. } = self else {
            return None;
        };
        let record = enrollment.record().ok()?;
        let document = record.cached_policy.as_ref()?;
        Some(TeamRuntimeEvidence {
            connection_id: record.connection_id.clone(),
            authority_id: record.authority_id.clone(),
            policy_id: record.policy_id.clone(),
            activation_id: record.activation_id.clone(),
            client_id: record.client_id.clone(),
            revision: document.revision.clone(),
            fetched_unix_ms: record.fetched_unix_ms,
        })
    }
    /// Private replay material also includes the selected native-generation
    /// commitment and exact cached bytes. Never expose it in a report or DTO.
    pub(crate) fn private_replay_commitment(&self) -> PrivateCommitment {
        let enrollment = match self {
            Self::Off { config_root } => {
                let mut bytes = vec![u8::from(config_root.is_some())];
                if let Some(root) = config_root {
                    bytes.extend_from_slice(root.as_os_str().as_encoded_bytes());
                }
                return PrivateCommitment::of("tirith.team.runtime-off.v1", &bytes);
            }
            Self::Strict { enrollment, .. } => enrollment,
        };
        let scope = enrollment.private_scope().as_os_str().as_encoded_bytes();
        let record = enrollment.input.private_bytes();
        let mut bytes = Vec::with_capacity(scope.len() + record.map_or(0, |bytes| bytes.len()) + 9);
        bytes.extend_from_slice(&(scope.len() as u64).to_be_bytes());
        bytes.extend_from_slice(scope);
        bytes.push(u8::from(record.is_some()));
        if let Some(record) = record {
            bytes.extend_from_slice(record);
        }
        PrivateCommitment::of("tirith.team.runtime-enrollment.v1", &bytes)
    }
    pub fn revalidate(&self) -> Result<(), EnrollmentError> {
        let (enrollment, selected_connection) = match self {
            Self::Off { config_root } => {
                if crate::policy::config_dir().as_ref() != config_root.as_ref()
                    || !runtime_entry_absent(config_root.as_deref())?
                {
                    return Err(EnrollmentError::ChangedEnrollment);
                }
                return Ok(());
            }
            Self::Strict {
                enrollment,
                selected_connection,
                grace_ms,
            } => (enrollment, (selected_connection, *grace_ms)),
        };
        enrollment.revalidate()?;
        let (selected_connection, grace_ms) = selected_connection;
        match (
            enrollment.record.as_ref().map_err(|error| *error)?,
            selected_connection,
        ) {
            (None, None) => Ok(()),
            (Some(record), Some(connection)) => {
                selected(record, connection)?;
                // The parsed document is immutable behind the witness; recheck
                // its age (with the grace it selected) without reparsing YAML.
                cache_time(record.fetched_unix_ms, now_ms()?, grace_ms).map(|_| ())
            }
            _ => Err(EnrollmentError::ChangedEnrollment),
        }
    }
}

/// Sealed observation of a successful Client-role authenticated current-policy
/// fetch. No public constructor accepts a caller-supplied document or timestamp.
pub struct FetchedTeamPolicy {
    connection: Arc<ConnectionWitness>,
    capabilities: Capabilities,
    document: PolicyDocument,
    fetched_unix_ms: u64,
    selection_commitment: PrivateCommitment,
}
impl FetchedTeamPolicy {
    pub fn fetch(connection: Arc<ConnectionWitness>) -> Result<Self, EnrollmentError> {
        connection
            .revalidate()
            .map_err(|_| EnrollmentError::ChangedConnection)?;
        let (client, capabilities) = connection
            .authenticate()
            .map_err(|_| EnrollmentError::AuthenticationFailed)?;
        if capabilities.role != Role::Client {
            return Err(EnrollmentError::ClientRoleRequired);
        }
        let document = client
            .current()
            .map_err(|_| EnrollmentError::InvalidCache)?;
        let fetched_unix_ms = now_ms()?;
        connection
            .revalidate()
            .map_err(|_| EnrollmentError::ChangedConnection)?;
        let selection_commitment = connection
            .private_selection_commitment()
            .map_err(|_| EnrollmentError::ChangedConnection)?;
        let fetched = Self {
            connection,
            capabilities,
            document,
            fetched_unix_ms,
            selection_commitment,
        };
        fetched.revalidate()?;
        Ok(fetched)
    }
    pub fn document(&self) -> &PolicyDocument {
        &self.document
    }
    pub fn fetched_unix_ms(&self) -> u64 {
        self.fetched_unix_ms
    }
    pub fn revalidate(&self) -> Result<(), EnrollmentError> {
        let now = now_ms()?;
        self.connection
            .revalidate()
            .map_err(|_| EnrollmentError::ChangedConnection)?;
        self.capabilities
            .validate(now)
            .map_err(|_| EnrollmentError::AuthenticationFailed)?;
        if self.capabilities.role != Role::Client {
            return Err(EnrollmentError::ClientRoleRequired);
        }
        if now
            .checked_sub(self.fetched_unix_ms)
            .is_none_or(|age| age >= FETCH_PREPARATION_MAX_AGE_MS)
        {
            return Err(EnrollmentError::FetchExpired);
        }
        let binding = self
            .connection
            .binding()
            .ok_or(EnrollmentError::ChangedConnection)?;
        if self.document.authority_id != binding.authority_id
            || self.document.policy_id != binding.policy_id
            || self.capabilities.authority_id != binding.authority_id
            || self.capabilities.policy_id != binding.policy_id
            || self
                .connection
                .private_selection_commitment()
                .map_err(|_| EnrollmentError::ChangedConnection)?
                != self.selection_commitment
        {
            return Err(EnrollmentError::ChangedConnection);
        }
        Ok(())
    }
}
/// Private output lacks Debug/Serialize. Native publication requires 0600 (or
/// owner/system-only Windows ACL), a private parent, and durable atomic CAS.
pub struct PrivateEnrollmentBytes(Vec<u8>);
impl PrivateEnrollmentBytes {
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EnrollmentWriteKind {
    Activate,
    Sync,
    Disable,
    RemoveMalformed,
}
/// This is a private writer intent, not permission to modify the filesystem or
/// proof that the selected document reached Runtime.
pub struct EnrollmentWriteIntent {
    previous: Arc<EnrollmentWitness>,
    replacement: Option<PrivateEnrollmentBytes>,
    fetched: Option<FetchedTeamPolicy>,
    kind: EnrollmentWriteKind,
}
impl EnrollmentWriteIntent {
    pub fn kind(&self) -> EnrollmentWriteKind {
        self.kind
    }
    pub fn revalidate(&self) -> Result<(), EnrollmentError> {
        self.previous.revalidate()?;
        if let Some(fetched) = &self.fetched {
            fetched.revalidate()?;
        }
        Ok(())
    }
    pub fn private_path(&self) -> &Path {
        self.previous.private_path()
    }
    pub fn private_scope(&self) -> &Path {
        self.previous.private_scope()
    }
    #[cfg(test)]
    pub fn expected_private_bytes(&self) -> Option<&[u8]> {
        self.previous.input.private_bytes()
    }
    pub fn replacement(&self) -> Option<&PrivateEnrollmentBytes> {
        self.replacement.as_ref()
    }
    pub fn previous(&self) -> &Arc<EnrollmentWitness> {
        &self.previous
    }
}

#[cfg(test)]
#[path = "policy_team_enrollment_tests.rs"]
mod tests;
