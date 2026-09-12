//! Authoritative policy resolution, captured as the resolver reads and composes
//! its inputs. A snapshot is not an execution permit. Mutation callers retain
//! it and revalidate immediately before their atomic, authorized write.

use crate::policy::{Policy, PolicyScope};
use serde::Serialize;
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::cell::RefCell;
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ResolutionMode {
    Runtime,
    /// No remote request or list/trust/label overlays. Includes incidents.
    LocalOnly,
}

/// Source identity, not a claim that a caller may write that source. Paths and
/// user-defined field names still require the consumer's normal output DLP.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PolicySource {
    pub kind: String,
    pub path: Option<String>,
}

impl PolicySource {
    pub(crate) fn new(kind: &str, path: Option<&Path>) -> Self {
        Self {
            kind: kind.into(),
            path: path.map(|p| p.display().to_string()),
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct FieldContribution {
    pub source: PolicySource,
    pub reason: String,
    pub changed_effective_value: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct FieldProvenance {
    pub effective_source: PolicySource,
    pub contributions: Vec<FieldContribution>,
}

#[derive(Debug, Clone, Serialize)]
pub struct NeutralizedSetting {
    pub field: String,
    pub source: PolicySource,
    pub reason: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum InputState {
    Present,
    Absent,
    Unreadable,
}

/// Opaque revisions deliberately expose no deterministic digest of policy
/// bytes: a policy may contain a low-entropy API key. The private witness is
/// kept in memory; this public token is never a portable authorization token.
#[derive(Debug, Clone, Serialize)]
pub struct InputRevision {
    pub source: PolicySource,
    pub revision: String,
    pub state: InputState,
}

#[derive(Debug, Clone, Serialize)]
pub struct OperatorTarget {
    pub scope: String,
    pub path: String,
    /// Describes the authority of this location, not filesystem permissions.
    pub allowed_operation: String,
    pub effective: bool,
    pub reason: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct RemotePolicyEvidence {
    pub availability: String,
    pub fallback: Option<String>,
    pub failure: Option<String>,
    /// Recorded only after a complete successful fetch and validated parse.
    /// An older cache without a bound receipt has unknown freshness.
    pub fetched_at: Option<String>,
    pub validated_at: Option<String>,
    pub server_date: Option<String>,
    pub etag: Option<String>,
    pub last_modified: Option<String>,
    pub cache_age_seconds: Option<u64>,
    pub freshness: String,
}

impl Default for RemotePolicyEvidence {
    fn default() -> Self {
        Self {
            availability: "not_configured".into(),
            fallback: None,
            failure: None,
            fetched_at: None,
            validated_at: None,
            server_date: None,
            etag: None,
            last_modified: None,
            cache_age_seconds: None,
            freshness: "unknown".into(),
        }
    }
}

/// Deliberately not serializable: the policy and private revision witnesses
/// contain sensitive data. Consumers build redacted display projections.
#[derive(Clone)]
pub struct EffectivePolicySnapshot {
    pub schema_version: u32,
    pub identity: String,
    pub policy: Policy,
    pub resolution_mode: ResolutionMode,
    /// Non-secret posture digest; not an input revision or authorization key.
    pub policy_posture_sha256: String,
    pub field_provenance: BTreeMap<String, FieldProvenance>,
    pub neutralized_settings: Vec<NeutralizedSetting>,
    pub input_revisions: Vec<InputRevision>,
    pub primary_input_revision: Option<String>,
    pub operator_targets: Vec<OperatorTarget>,
    /// Opaque revision of the exact trust store consumed by this resolution.
    pub trust_generation: Option<String>,
    pub next_trust_expiry: Option<String>,
    pub requested_profile: Option<crate::protection_profiles::ProfileSelection>,
    pub custom_profile_overrides: Vec<String>,
    pub remote: RemotePolicyEvidence,
    witnesses: Vec<InputWitness>,
    resolution_cwd: Option<String>,
}

impl std::fmt::Debug for EffectivePolicySnapshot {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EffectivePolicySnapshot")
            .field("identity", &self.identity)
            .field("resolution_mode", &self.resolution_mode)
            .field("inputs", &self.input_revisions.len())
            .finish_non_exhaustive()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PolicyConflict {
    pub reason: String,
    /// Opaque IDs only; never include raw input bytes or credentials.
    pub changed_revisions: Vec<String>,
}

impl std::fmt::Display for PolicyConflict {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}; resolve policy again before applying the change",
            self.reason
        )
    }
}

impl std::error::Error for PolicyConflict {}

/// Private persisted comparison material for a protected operation journal.
/// This MUST NOT appear in public output: its digest binds secret-bearing
/// inputs and is suitable only for an operator-owned mode-0600 journal. The
/// public snapshot identity/input revisions remain random, non-oracular IDs.
#[derive(Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct PrivatePolicyReplayGuard {
    digest: [u8; 32],
}

impl std::fmt::Debug for PrivatePolicyReplayGuard {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("PrivatePolicyReplayGuard([private])")
    }
}

impl EffectivePolicySnapshot {
    pub fn resolve(cwd: Option<&str>, mode: ResolutionMode) -> Self {
        let capture = ResolutionCapture::start();
        let policy = match mode {
            ResolutionMode::Runtime => resolve_runtime_policy(cwd),
            ResolutionMode::LocalOnly => Policy::discover_local_only(cwd),
        };
        crate::policy::freeze_captured_policy_dlp_patterns(&policy.dlp_custom_patterns);
        let mut captured = capture.finish();
        if mode == ResolutionMode::LocalOnly {
            captured.remote.availability = "not_queried_local_only".into();
        }
        // The target path is resolved by the same config helper as runtime
        // overlays. No policy document is re-read to invent provenance.
        let operator_targets = captured.operator_targets(&policy);
        let requested_profile = captured
            .requested_profile
            .clone()
            .or_else(|| policy.protection_profile.clone());
        let custom_profile_overrides = requested_profile
            .as_ref()
            .map(|selection| {
                crate::protection_profiles::custom_override_fields(
                    &serde_yaml::to_value(&policy).expect("profile policy serialization"),
                    selection,
                )
            })
            .unwrap_or_default();
        Self {
            schema_version: 1,
            identity: uuid::Uuid::new_v4().to_string(),
            policy_posture_sha256: policy.enforcement_projection_hash(),
            policy,
            resolution_mode: mode,
            field_provenance: captured.fields,
            neutralized_settings: captured.neutralized,
            input_revisions: captured.inputs,
            primary_input_revision: captured.primary,
            operator_targets,
            trust_generation: captured.trust_generation,
            next_trust_expiry: captured.next_trust_expiry.map(|t| t.to_rfc3339()),
            requested_profile,
            custom_profile_overrides,
            remote: captured.remote,
            witnesses: captured.witnesses,
            resolution_cwd: cwd.map(str::to_string),
        }
    }

    /// Check the same inputs using their original reader/trust semantics.
    /// Does not fetch remote policy, mutate caches, or resolve a second policy.
    /// A remote snapshot requires a new resolution for a remote-authorized
    /// mutation: a local recheck cannot prove the server has not changed.
    pub fn revalidate_inputs(&self) -> Result<(), PolicyConflict> {
        let changed_revisions: Vec<_> = self
            .witnesses
            .iter()
            .filter(|witness| !witness.is_current())
            .map(|witness| witness.revision.clone())
            .collect();
        if !changed_revisions.is_empty() {
            return Err(PolicyConflict {
                reason: "policy inputs changed since resolution".into(),
                changed_revisions,
            });
        }
        if self.next_trust_expiry.as_ref().is_some_and(|expiry| {
            chrono::DateTime::parse_from_rfc3339(expiry)
                .map(|expiry| chrono::Utc::now() >= expiry)
                .unwrap_or(true)
        }) {
            return Err(PolicyConflict {
                reason: "a trust grant expired since resolution".into(),
                changed_revisions: self.trust_generation.clone().into_iter().collect(),
            });
        }
        Ok(())
    }

    /// Mutation guard when the complete live policy must remain authoritative.
    /// A local witness cannot assert freshness of remote server authorization:
    /// the fetch API currently has no atomic server revision precondition.
    pub fn revalidate_for_mutation(&self) -> Result<(), PolicyConflict> {
        self.revalidate_inputs()?;
        if self.resolution_mode != ResolutionMode::Runtime {
            return Err(PolicyConflict {
                reason: "local-only diagnostics cannot authorize policy mutations".into(),
                changed_revisions: Vec::new(),
            });
        }
        if self.remote.availability != "not_configured" {
            return Err(PolicyConflict {
                reason: "remote policy authority requires a server-bound revision precondition"
                    .into(),
                changed_revisions: self.primary_input_revision.clone().into_iter().collect(),
            });
        }
        Ok(())
    }

    /// Exact caller scope captured at resolution, retained for private replay.
    pub fn resolution_cwd(&self) -> Option<&str> {
        self.resolution_cwd.as_deref()
    }

    /// Resolve the original caller scope. Call outside a writer lock: Runtime
    /// may query a remote server, whose snapshots cannot authorize mutations.
    pub fn refresh_runtime(&self) -> Self {
        Self::resolve(self.resolution_cwd(), ResolutionMode::Runtime)
    }

    /// Persist only in an operator-owned private journal, then compare with a
    /// fresh runtime snapshot when resuming. Equality is a conflict check, not
    /// authorization; the resumed operation still calls revalidate_for_mutation.
    pub fn private_replay_guard(&self) -> PrivatePolicyReplayGuard {
        self.replay_guard(true, &BTreeSet::new())
    }

    /// Private journal-only guard for a multi-step operation's EXTERNAL inputs.
    /// The caller must independently prove exact owned pre/postimages for every
    /// excluded path, resolve fresh policy, and authorize each publication. This
    /// guard is NOT authorization and never ignores environment, incident, CWD,
    /// project identity, or a changed resolver input graph. Only exact observed
    /// file/discovery paths in the bound set are excluded; no prefix exclusion.
    pub fn private_external_inputs_guard(
        &self,
        excluded_paths: &BTreeSet<PathBuf>,
    ) -> PrivatePolicyReplayGuard {
        self.replay_guard(false, excluded_paths)
    }

    fn replay_guard(
        &self,
        include_policy: bool,
        excluded_paths: &BTreeSet<PathBuf>,
    ) -> PrivatePolicyReplayGuard {
        let mut hash = Sha256::new();
        fn part(hash: &mut Sha256, bytes: &[u8]) {
            hash.update((bytes.len() as u64).to_be_bytes());
            hash.update(bytes);
        }
        part(
            &mut hash,
            if include_policy {
                b"tirith-private-policy-replay-v1"
            } else {
                b"tirith-private-external-inputs-v1"
            },
        );
        part(
            &mut hash,
            &serde_json::to_vec(&(self.resolution_mode, &self.resolution_cwd, excluded_paths))
                .expect("resolution replay serialization"),
        );
        if include_policy {
            let mut projection = serde_json::json!({
                "policy": self.policy, "mode": self.resolution_mode,
                "scope": self.policy.scope.as_str(), "path": self.policy.path,
                "context_labels": self.policy.context_labels, "ssh_host_labels": self.policy.ssh_host_labels,
                "next_trust_expiry": self.next_trust_expiry,
            });
            projection.sort_all_objects();
            part(
                &mut hash,
                &serde_json::to_vec(&projection).expect("policy replay serialization"),
            );
        }
        for witness in &self.witnesses {
            if matches!(&witness.kind, WitnessKind::File(path, _, _) | WitnessKind::Discovery(path, _, _) | WitnessKind::NamedDestination(path, _) if excluded_paths.contains(path))
            {
                continue;
            }
            match &witness.kind {
                WitnessKind::File(path, reader, expected) => {
                    part(&mut hash, b"file");
                    part(&mut hash, path.as_os_str().as_encoded_bytes());
                    let reader = match reader {
                        InputReader::Trusted(cap) => format!("trusted:{cap}"),
                        InputReader::NoFollow(cap) => format!("no_follow:{cap}"),
                        InputReader::Repository => "repository".into(),
                        InputReader::UserList => "user_list".into(),
                    };
                    part(&mut hash, reader.as_bytes());
                    match expected {
                        ReadWitness::Bytes(bytes) => {
                            part(&mut hash, b"present");
                            part(&mut hash, bytes);
                        }
                        ReadWitness::Absent => part(&mut hash, b"absent"),
                        ReadWitness::Unreadable => part(&mut hash, b"unreadable"),
                    }
                }
                WitnessKind::Discovery(path, follow, existed) => {
                    part(&mut hash, b"discovery");
                    part(&mut hash, path.as_os_str().as_encoded_bytes());
                    part(&mut hash, &[*follow as u8, *existed as u8]);
                }
                WitnessKind::NamedDestination(path, state) => {
                    part(&mut hash, b"named_destination");
                    part(&mut hash, path.as_os_str().as_encoded_bytes());
                    part(
                        &mut hash,
                        &serde_json::to_vec(state).expect("destination replay serialization"),
                    );
                }
                WitnessKind::Environment(name, value) => {
                    part(&mut hash, b"environment");
                    part(&mut hash, name.as_bytes());
                    part(&mut hash, &[value.is_some() as u8]);
                    if let Some(value) = value {
                        part(&mut hash, value.as_encoded_bytes());
                    }
                }
                WitnessKind::Incident(path, state) => {
                    part(&mut hash, b"incident");
                    part(
                        &mut hash,
                        &serde_json::to_vec(&(path, state)).expect("incident replay serialization"),
                    );
                }
                WitnessKind::CurrentDirectory(path) => {
                    part(&mut hash, b"cwd");
                    if let Some(path) = path {
                        part(&mut hash, path.as_os_str().as_encoded_bytes());
                    }
                }
                WitnessKind::Project(identity) => {
                    part(&mut hash, b"project_identity");
                    part(
                        &mut hash,
                        &serde_json::to_vec(identity).expect("project replay serialization"),
                    );
                }
            }
        }
        PrivatePolicyReplayGuard {
            digest: hash.finalize().into(),
        }
    }
}

pub(crate) fn resolve_runtime_policy(cwd: Option<&str>) -> Policy {
    let mut policy = Policy::discover(cwd);
    policy.load_user_lists();
    policy.load_org_lists(cwd);
    policy.load_trust_entries(cwd);
    policy.load_context_labels(cwd);
    policy.load_ssh_host_labels(cwd);
    policy
}

#[derive(Clone, Copy)]
pub(crate) enum InputReader {
    Trusted(u64),
    NoFollow(u64),
    Repository,
    /// Preserves the pre-existing unrestricted operator list reader.
    UserList,
}

#[derive(Clone)]
enum WitnessKind {
    File(PathBuf, InputReader, ReadWitness),
    Discovery(PathBuf, bool, bool),
    NamedDestination(PathBuf, InputState),
    Environment(String, Option<std::ffi::OsString>),
    Incident(Option<PathBuf>, Option<crate::incident::IncidentState>),
    CurrentDirectory(Option<PathBuf>),
    Project(crate::trust_grants::ProjectIdentity),
}

#[derive(Clone)]
struct InputWitness {
    revision: String,
    kind: WitnessKind,
}

#[derive(Clone, PartialEq, Eq)]
enum ReadWitness {
    Bytes([u8; 32]),
    Absent,
    Unreadable,
}

fn digest(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}

impl ReadWitness {
    fn from_result(result: &Result<Vec<u8>, crate::util::OpenRegularError>) -> Self {
        match result {
            Ok(bytes) => Self::Bytes(digest(bytes)),
            Err(crate::util::OpenRegularError::NotFound) => Self::Absent,
            Err(_) => Self::Unreadable,
        }
    }

    fn state(&self) -> InputState {
        match self {
            Self::Bytes(_) => InputState::Present,
            Self::Absent => InputState::Absent,
            Self::Unreadable => InputState::Unreadable,
        }
    }
}

impl InputWitness {
    fn is_current(&self) -> bool {
        match &self.kind {
            WitnessKind::File(path, reader, expected) => {
                // Unreadable inputs never authorize a mutation, even when a
                // second read fails the same way: their content is unknown.
                if *expected == ReadWitness::Unreadable {
                    return false;
                }
                ReadWitness::from_result(&read_input(path, *reader)) == *expected
            }
            WitnessKind::Discovery(path, follow, existed) => {
                (if *follow {
                    path.exists()
                } else {
                    std::fs::symlink_metadata(path).is_ok()
                }) == *existed
            }
            WitnessKind::NamedDestination(path, expected) => {
                *expected != InputState::Unreadable && named_destination_state(path) == *expected
            }
            WitnessKind::Environment(name, expected) => std::env::var_os(name) == *expected,
            WitnessKind::Incident(path, expected) => {
                let now = path.as_deref().and_then(crate::incident::read_state_at);
                now == *expected && crate::incident::flag_path() == *path
            }
            WitnessKind::CurrentDirectory(expected) => std::env::current_dir().ok() == *expected,
            WitnessKind::Project(identity) => identity.is_current(),
        }
    }
}

fn read_input(path: &Path, reader: InputReader) -> Result<Vec<u8>, crate::util::OpenRegularError> {
    match reader {
        InputReader::Trusted(cap) => crate::util::read_regular_capped(path, cap),
        InputReader::NoFollow(cap) => crate::util::read_text_no_follow_capped(path, cap),
        InputReader::Repository => crate::policy::read_repository_policy(path),
        InputReader::UserList => std::fs::read(path).map_err(|error| {
            if error.kind() == std::io::ErrorKind::NotFound {
                crate::util::OpenRegularError::NotFound
            } else {
                crate::util::OpenRegularError::Io(error)
            }
        }),
    }
}

#[derive(Default)]
struct CapturedResolution {
    fields: BTreeMap<String, FieldProvenance>,
    neutralized: Vec<NeutralizedSetting>,
    inputs: Vec<InputRevision>,
    witnesses: Vec<InputWitness>,
    primary: Option<String>,
    config_dir: Option<PathBuf>,
    user_destination: Option<PathBuf>,
    trusted_path: Option<(PathBuf, PolicyScope)>,
    repo_path: Option<PathBuf>,
    trust_generation: Option<String>,
    next_trust_expiry: Option<chrono::DateTime<chrono::Utc>>,
    remote: RemotePolicyEvidence,
    requested_profile: Option<crate::protection_profiles::ProfileSelection>,
}

impl CapturedResolution {
    fn operator_targets(&self, policy: &Policy) -> Vec<OperatorTarget> {
        let mut targets = Vec::new();
        if let Some(config) = &self.config_dir {
            let user_path = self
                .user_destination
                .clone()
                .unwrap_or_else(|| config.join("policy.yaml"));
            let effective = policy.scope != PolicyScope::Remote
                && !self
                    .trusted_path
                    .as_ref()
                    .is_some_and(|(_, scope)| *scope == PolicyScope::Org);
            targets.push(OperatorTarget {
                scope: "user".into(), path: user_path.display().to_string(),
                allowed_operation: "personal_policy".into(), effective,
                reason: if effective { "personal baseline; repository and incident restrictions still apply" }
                    else { "recorded personal preference is overridden by the selected organization or remote policy" }.into(),
            });
        }
        if let Some((path, PolicyScope::Org)) = &self.trusted_path {
            targets.push(OperatorTarget {
                scope: "org".into(), path: path.display().to_string(),
                allowed_operation: "organization_operator_only".into(),
                effective: policy.scope != PolicyScope::Remote,
                reason: "organization location requires explicit operator authority; remote replacement and incident restrictions still apply".into(),
            });
        }
        if let Some(path) = &self.repo_path {
            targets.push(OperatorTarget {
                scope: "repo".into(),
                path: path.display().to_string(),
                allowed_operation: "tightening_only".into(),
                effective: policy.scope != PolicyScope::Remote,
                reason: "repository content cannot relax trusted restrictions or grant trust"
                    .into(),
            });
        }
        targets
    }
}

thread_local! {
    static CAPTURES: RefCell<Vec<CapturedResolution>> = const { RefCell::new(Vec::new()) };
}

struct ResolutionCapture {
    active: bool,
    _not_send: std::marker::PhantomData<std::rc::Rc<()>>,
}

impl ResolutionCapture {
    fn start() -> Self {
        CAPTURES.with(|captures| captures.borrow_mut().push(CapturedResolution::default()));
        let capture = Self {
            active: true,
            _not_send: std::marker::PhantomData,
        };
        // These ambient inputs determine the roots used by etcetera/home and
        // must remain stable while a revision-bound operation is in flight.
        for name in [
            "HOME",
            "XDG_CONFIG_HOME",
            "XDG_STATE_HOME",
            "XDG_CACHE_HOME",
            "APPDATA",
            "LOCALAPPDATA",
            "USERPROFILE",
            "TIRITH_POLICY_ROOT",
        ] {
            observe_env(name);
        }
        with_capture(|capture| {
            let revision = uuid::Uuid::new_v4().to_string();
            let cwd = std::env::current_dir().ok();
            capture.inputs.push(InputRevision {
                source: PolicySource::new("working_directory", cwd.as_deref()),
                revision: revision.clone(),
                state: if cwd.is_some() {
                    InputState::Present
                } else {
                    InputState::Unreadable
                },
            });
            capture.witnesses.push(InputWitness {
                revision,
                kind: WitnessKind::CurrentDirectory(cwd),
            });
        });
        capture
    }

    fn finish(mut self) -> CapturedResolution {
        self.active = false;
        CAPTURES.with(|captures| captures.borrow_mut().pop().expect("resolution capture"))
    }
}

impl Drop for ResolutionCapture {
    fn drop(&mut self) {
        if self.active {
            CAPTURES.with(|captures| {
                captures.borrow_mut().pop();
            });
        }
    }
}

fn with_capture(f: impl FnOnce(&mut CapturedResolution)) {
    CAPTURES.with(|captures| {
        if let Some(capture) = captures.borrow_mut().last_mut() {
            f(capture);
        }
    });
}

pub(crate) fn is_capturing() -> bool {
    CAPTURES.with(|captures| !captures.borrow().is_empty())
}

pub(crate) fn observe_env(name: &str) -> Option<std::ffi::OsString> {
    let value = std::env::var_os(name);
    with_capture(|capture| {
        let revision = uuid::Uuid::new_v4().to_string();
        capture.inputs.push(InputRevision {
            source: PolicySource::new("environment", Some(Path::new(name))),
            revision: revision.clone(),
            state: if value.is_some() {
                InputState::Present
            } else {
                InputState::Absent
            },
        });
        capture.witnesses.push(InputWitness {
            revision,
            kind: WitnessKind::Environment(name.into(), value.clone()),
        });
    });
    value
}

pub(crate) fn observe_discovery(path: &Path, follow: bool, exists: bool) {
    with_capture(|capture| {
        let revision = uuid::Uuid::new_v4().to_string();
        capture.inputs.push(InputRevision {
            source: PolicySource::new("discovery", Some(path)),
            revision: revision.clone(),
            state: if exists {
                InputState::Present
            } else {
                InputState::Absent
            },
        });
        capture.witnesses.push(InputWitness {
            revision,
            kind: WitnessKind::Discovery(path.into(), follow, exists),
        });
    });
}

pub(crate) fn observe_read(
    path: &Path,
    kind: &str,
    reader: InputReader,
    result: &Result<Vec<u8>, crate::util::OpenRegularError>,
) {
    with_capture(|capture| {
        let witness = ReadWitness::from_result(result);
        let revision = uuid::Uuid::new_v4().to_string();
        if matches!(kind, "user_trust" | "operator_trust") {
            capture.trust_generation = Some(revision.clone());
        }
        capture.inputs.push(InputRevision {
            source: PolicySource::new(kind, Some(path)),
            revision: revision.clone(),
            state: witness.state(),
        });
        capture.witnesses.push(InputWitness {
            revision,
            kind: WitnessKind::File(path.into(), reader, witness),
        });
    });
}

pub(crate) fn observe_project_identity(identity: &crate::trust_grants::ProjectIdentity) {
    with_capture(|capture| {
        let revision = uuid::Uuid::new_v4().to_string();
        capture.inputs.push(InputRevision {
            source: PolicySource::new("project_identity", Some(&identity.canonical_root)),
            revision: revision.clone(),
            state: InputState::Present,
        });
        capture.witnesses.push(InputWitness {
            revision,
            kind: WitnessKind::Project(identity.clone()),
        });
    });
}

pub(crate) fn observe_config_dir(path: &Path) {
    with_capture(|capture| {
        if capture.config_dir.is_some() {
            return;
        }
        capture.config_dir = Some(path.into());
        // The authoring destination has its own discovery. An org/remote
        // baseline may skip user policy loading, but may not cause a new yaml
        // file to silently shadow an existing yml document. Observe both named
        // entries once; never read an unselected document to invent provenance.
        for name in ["policy.yaml", "policy.yml"] {
            let candidate = path.join(name);
            let state = named_destination_state(&candidate);
            let revision = uuid::Uuid::new_v4().to_string();
            capture.inputs.push(InputRevision {
                source: PolicySource::new("operator_destination", Some(&candidate)),
                revision: revision.clone(),
                state,
            });
            capture.witnesses.push(InputWitness {
                revision,
                kind: WitnessKind::NamedDestination(candidate.clone(), state),
            });
            if capture.user_destination.is_none() && state != InputState::Absent {
                capture.user_destination = Some(candidate);
            }
        }
        capture
            .user_destination
            .get_or_insert_with(|| path.join("policy.yaml"));
    });
}

fn named_destination_state(path: &Path) -> InputState {
    match std::fs::symlink_metadata(path) {
        Ok(_) => InputState::Present,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => InputState::Absent,
        Err(_) => InputState::Unreadable,
    }
}

pub(crate) fn observe_policy_target(path: &Path, scope: PolicyScope) {
    with_capture(|capture| match scope {
        PolicyScope::Repo => capture.repo_path = Some(path.into()),
        _ => capture.trusted_path = Some((path.into(), scope)),
    });
}

pub(crate) fn values(policy: &Policy) -> Option<BTreeMap<String, Value>> {
    if !is_capturing() {
        return None;
    }
    let mut value = serde_json::to_value(policy).expect("policy serialization");
    value["context_labels"] =
        serde_json::to_value(&policy.context_labels).expect("label serialization");
    value["ssh_host_labels"] =
        serde_json::to_value(&policy.ssh_host_labels).expect("label serialization");
    Some(flatten(&value))
}

fn flatten(value: &Value) -> BTreeMap<String, Value> {
    fn visit(value: &Value, prefix: String, into: &mut BTreeMap<String, Value>) {
        if let Value::Object(map) = value {
            if !map.is_empty() {
                for (key, value) in map {
                    visit(
                        value,
                        if prefix.is_empty() {
                            key.clone()
                        } else {
                            format!("{prefix}.{key}")
                        },
                        into,
                    );
                }
                return;
            }
        }
        into.insert(prefix, value.clone());
    }
    let mut into = BTreeMap::new();
    visit(value, String::new(), &mut into);
    into
}

fn declared(field: &str, document: Option<&serde_yaml::Value>) -> bool {
    let Some(mut current) = document else {
        return false;
    };
    for part in field.split('.') {
        match current.as_mapping() {
            Some(map) => match map.get(serde_yaml::Value::String(part.into())) {
                Some(value) => current = value,
                None => return false,
            },
            None => return true,
        }
    }
    true
}

pub(crate) fn observe_replacement(
    policy: &Policy,
    source: PolicySource,
    document: Option<&serde_yaml::Value>,
    reason: &str,
) {
    let Some(values) = values(policy) else {
        return;
    };
    with_capture(|capture| {
        let previous = std::mem::take(&mut capture.fields);
        if matches!(source.kind.as_str(), "user" | "org") {
            capture.requested_profile = policy.protection_profile.clone();
        }
        for field in values.keys() {
            let effective_source = if declared(field, document) || document.is_none() {
                source.clone()
            } else {
                PolicySource::new("default", None)
            };
            let mut contributions = previous
                .get(field)
                .map(|old| {
                    let mut history = old.contributions.clone();
                    history.push(FieldContribution {
                        source: old.effective_source.clone(),
                        reason: format!("superseded by {} replacement", source.kind),
                        changed_effective_value: false,
                    });
                    history
                })
                .unwrap_or_default();
            contributions.push(FieldContribution {
                source: source.clone(),
                reason: reason.into(),
                changed_effective_value: true,
            });
            capture.fields.insert(
                field.clone(),
                FieldProvenance {
                    effective_source,
                    contributions,
                },
            );
        }
        capture.primary = capture
            .inputs
            .iter()
            .rev()
            .find(|input| input.source.path == source.path && input.source.kind != "discovery")
            .map(|input| input.revision.clone());
    });
}

pub(crate) fn observe_overlay(
    before: Option<BTreeMap<String, Value>>,
    policy: &Policy,
    source: PolicySource,
    document: Option<&serde_yaml::Value>,
    reason: &str,
) {
    let (Some(before), Some(after)) = (before, values(policy)) else {
        return;
    };
    observe_values_overlay(before, after, source, document, reason);
}

fn observe_values_overlay(
    before: BTreeMap<String, Value>,
    after: BTreeMap<String, Value>,
    source: PolicySource,
    document: Option<&serde_yaml::Value>,
    reason: &str,
) {
    with_capture(|capture| {
        for removed in before.keys().filter(|field| !after.contains_key(*field)) {
            capture.fields.remove(removed);
        }
        for (field, value) in &after {
            let changed = before.get(field) != Some(value);
            if !changed && !declared(field, document) {
                continue;
            }
            let provenance =
                capture
                    .fields
                    .entry(field.clone())
                    .or_insert_with(|| FieldProvenance {
                        effective_source: PolicySource::new("default", None),
                        contributions: Vec::new(),
                    });
            if changed {
                provenance.effective_source = source.clone();
            }
            provenance.contributions.push(FieldContribution {
                source: source.clone(),
                reason: reason.into(),
                changed_effective_value: changed,
            });
        }
    });
}

pub(crate) fn observe_labels(
    before: &BTreeMap<String, String>,
    after: &BTreeMap<String, String>,
    field: &str,
    source: PolicySource,
) {
    if !is_capturing() {
        return;
    }
    let before = flatten(&serde_json::json!({ field: before }));
    let after = flatten(&serde_json::json!({ field: after }));
    observe_values_overlay(
        before,
        after,
        source,
        None,
        "label overlay; repository labels may only add or raise criticality",
    );
}

pub(crate) fn observe_neutralized(fields: &[&str], source: PolicySource) {
    with_capture(|capture| {
        for field in fields {
            if capture
                .neutralized
                .iter()
                .any(|setting| setting.field == *field && setting.source == source)
            {
                continue;
            }
            capture.neutralized.push(NeutralizedSetting { field: (*field).into(), source: source.clone(),
            reason: "repository policy may tighten protection but cannot relax trusted restrictions, grant trust, or redirect credentials".into() });
        }
    });
}

pub(crate) fn observe_incident(state: Option<&crate::incident::IncidentState>) {
    with_capture(|capture| {
        let revision = uuid::Uuid::new_v4().to_string();
        let path = crate::incident::flag_path();
        capture.inputs.push(InputRevision {
            source: PolicySource::new("incident", path.as_deref()),
            revision: revision.clone(),
            state: if state.is_some() {
                InputState::Present
            } else {
                InputState::Absent
            },
        });
        capture.witnesses.push(InputWitness {
            revision,
            kind: WitnessKind::Incident(path, state.cloned()),
        });
    });
}

/// Constraints matter even when the selected value was already equally
/// restrictive. Keep them visible so an editor does not offer an effective
/// relaxation while incident mode remains active.
pub(crate) fn observe_constraint(field: &str, source: PolicySource, reason: &str) {
    with_capture(|capture| {
        if let Some(provenance) = capture.fields.get_mut(field) {
            if !provenance
                .contributions
                .iter()
                .any(|item| item.source == source)
            {
                provenance.contributions.push(FieldContribution {
                    source,
                    reason: reason.into(),
                    changed_effective_value: false,
                });
            }
        }
    });
}

pub(crate) fn observe_trust_expiry(expiry: chrono::DateTime<chrono::Utc>) {
    with_capture(|capture| {
        if capture.next_trust_expiry.is_none_or(|old| expiry < old) {
            capture.next_trust_expiry = Some(expiry);
        }
    });
}

pub(crate) fn observe_remote(update: impl FnOnce(&mut RemotePolicyEvidence)) {
    with_capture(|capture| update(&mut capture.remote));
}

/// A fresh remote response is an input too, although it cannot be rechecked
/// locally. The opaque token refers to the exact bytes used for parsing.
pub(crate) fn observe_remote_bytes(bytes: &[u8]) {
    with_capture(|capture| {
        let _ = bytes; // Deliberately never expose a hash of remote credentials.
        let revision = uuid::Uuid::new_v4().to_string();
        capture.inputs.push(InputRevision {
            source: PolicySource::new("remote", None),
            revision: revision.clone(),
            state: InputState::Present,
        });
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::{FailMode, PolicyScope};
    use tirith_test_support::GlobalStateGuard;

    #[test]
    fn runtime_includes_overlays_and_preserves_repository_tightening() {
        let state = GlobalStateGuard::new().unwrap();
        let root = state.roots().policy.join(".tirith");
        std::fs::create_dir_all(&root).unwrap();
        std::fs::write(root.join("policy.yaml"), "allow_bypass_env: true\n").unwrap();
        let cwd = &state.roots().cwd;
        std::fs::create_dir_all(cwd.join(".git")).unwrap();
        std::fs::create_dir_all(cwd.join(".tirith")).unwrap();
        std::fs::write(
            cwd.join(".tirith/policy.yaml"),
            "allow_bypass_env: true\nallowlist: [hostile.example]\n",
        )
        .unwrap();
        std::fs::write(cwd.join(".tirith/allowlist"), "also-hostile.example\n").unwrap();
        std::fs::write(cwd.join(".tirith/blocklist"), "blocked.example\n").unwrap();
        std::fs::write(
            cwd.join(".tirith/context-labels.yaml"),
            "production: critical\n",
        )
        .unwrap();
        std::fs::write(
            cwd.join(".tirith/ssh-host-labels.yaml"),
            "host: production\n",
        )
        .unwrap();
        let config = crate::policy::config_dir().unwrap();
        std::fs::create_dir_all(&config).unwrap();
        std::fs::write(config.join("allowlist"), "user.example\n").unwrap();
        std::fs::write(config.join("blocklist"), "user-blocked.example\n").unwrap();
        std::fs::write(
            config.join("trust.json"),
            r#"{"version":1,"entries":[
                {"pattern":"trusted.example","rule_id":"shortened_url"},
                {"pattern":"expired.example","ttl_expires":"2000-01-01T00:00:00Z"}
            ]}"#,
        )
        .unwrap();

        let snapshot = EffectivePolicySnapshot::resolve(cwd.to_str(), ResolutionMode::Runtime);
        let policy = &snapshot.policy;
        assert_eq!(policy.scope, PolicyScope::Org);
        assert_eq!(policy.path.as_deref(), root.join("policy.yaml").to_str());
        assert!(!policy.allow_bypass_env);
        assert!(policy.neutralized_fields.contains(&"allowlist"));
        assert_eq!(policy.allowlist, ["user.example"]);
        assert!(policy.is_blocklisted("blocked.example"));
        assert!(policy.is_blocklisted("user-blocked.example"));
        assert!(policy.is_allowlisted_for_rule("shortened_url", "trusted.example"));
        assert_eq!(policy.context_labels.get("production").unwrap(), "critical");
        assert_eq!(policy.ssh_host_labels.get("host").unwrap(), "production");
        assert_eq!(
            snapshot.policy_posture_sha256,
            policy.enforcement_projection_hash()
        );
    }

    #[test]
    fn offline_diagnostic_does_not_query_remote_or_claim_list_overlays() {
        let mut state = GlobalStateGuard::new().unwrap();
        // HTTP is refused before opening a socket. Runtime resolution must
        // select fail-closed; the offline diagnostic must never take this path.
        state.set_env("TIRITH_SERVER_URL", "http://127.0.0.1:1");
        state.set_env("TIRITH_API_KEY", "fixture-key");
        std::fs::create_dir_all(state.roots().policy.join(".tirith")).unwrap();
        std::fs::write(
            state.roots().policy.join(".tirith/policy.yaml"),
            "fail_mode: open\npolicy_fetch_fail_mode: closed\n",
        )
        .unwrap();
        let config = crate::policy::config_dir().unwrap();
        std::fs::create_dir_all(&config).unwrap();
        std::fs::write(config.join("blocklist"), "overlay.example\n").unwrap();

        let offline = EffectivePolicySnapshot::resolve(None, ResolutionMode::LocalOnly);
        assert_eq!(offline.policy.fail_mode, FailMode::Open);
        assert!(!offline.policy.is_blocklisted("overlay.example"));
        let runtime = EffectivePolicySnapshot::resolve(None, ResolutionMode::Runtime);
        assert_eq!(runtime.policy.fail_mode, FailMode::Closed);
        assert!(runtime
            .policy
            .custom_rules
            .iter()
            .any(|rule| rule.id == "tirith-effective-policy-unavailable"));
        assert!(runtime.policy.is_blocklisted("overlay.example"));
    }

    #[test]
    fn snapshot_is_not_reloaded_after_a_policy_edit() {
        let state = GlobalStateGuard::new().unwrap();
        std::fs::create_dir_all(state.roots().policy.join(".tirith")).unwrap();
        let path = state.roots().policy.join(".tirith/policy.yaml");
        std::fs::write(&path, "allow_bypass_env: true\n").unwrap();
        let before = EffectivePolicySnapshot::resolve(None, ResolutionMode::Runtime);
        std::fs::write(&path, "allow_bypass_env: false\n").unwrap();
        let after = EffectivePolicySnapshot::resolve(None, ResolutionMode::Runtime);
        assert!(before.policy.allow_bypass_env);
        assert!(!after.policy.allow_bypass_env);
        assert_ne!(before.policy_posture_sha256, after.policy_posture_sha256);
        assert!(before.revalidate_inputs().is_err());
        assert!(after.revalidate_inputs().is_ok());
    }

    #[test]
    fn user_destination_preserves_named_yml_when_organization_policy_is_selected() {
        let state = GlobalStateGuard::new().unwrap();
        let org = state.roots().policy.join(".tirith");
        let config = crate::policy::config_dir().unwrap();
        std::fs::create_dir_all(&org).unwrap();
        std::fs::create_dir_all(&config).unwrap();
        std::fs::write(org.join("policy.yaml"), "paranoia: 2\n").unwrap();
        // A malformed, unselected preference is still the authoring target.
        // Selecting the org baseline must not read or repair this document.
        std::fs::write(config.join("policy.yml"), "{ invalid yaml").unwrap();
        let snapshot = EffectivePolicySnapshot::resolve(None, ResolutionMode::Runtime);
        assert_eq!(snapshot.policy.scope, PolicyScope::Org);
        let target = snapshot
            .operator_targets
            .iter()
            .find(|target| target.scope == "user")
            .unwrap();
        assert_eq!(target.path, config.join("policy.yml").display().to_string());
        assert!(!target.effective);
        assert!(snapshot.revalidate_inputs().is_ok());
        std::fs::write(config.join("policy.yaml"), "paranoia: 1\n").unwrap();
        assert!(snapshot.revalidate_inputs().is_err());
    }

    #[test]
    #[cfg(unix)]
    fn user_destination_preserves_dangling_yaml_precedence() {
        let state = GlobalStateGuard::new().unwrap();
        let org = state.roots().policy.join(".tirith");
        let config = crate::policy::config_dir().unwrap();
        std::fs::create_dir_all(&org).unwrap();
        std::fs::create_dir_all(&config).unwrap();
        std::fs::write(org.join("policy.yaml"), "paranoia: 2\n").unwrap();
        std::fs::write(config.join("policy.yml"), "paranoia: 1\n").unwrap();
        std::os::unix::fs::symlink(config.join("missing"), config.join("policy.yaml")).unwrap();
        let snapshot = EffectivePolicySnapshot::resolve(None, ResolutionMode::Runtime);
        assert_eq!(
            snapshot
                .operator_targets
                .iter()
                .find(|target| target.scope == "user")
                .unwrap()
                .path,
            config.join("policy.yaml").display().to_string()
        );
        assert!(snapshot
            .input_revisions
            .iter()
            .any(|input| input.source.kind == "operator_destination"
                && input.source.path.as_deref() == config.join("policy.yaml").to_str()
                && input.state == InputState::Present));
    }

    #[test]
    fn provenance_tracks_field_sources_and_rejected_repository_settings() {
        let state = GlobalStateGuard::new().unwrap();
        let org = state.roots().policy.join(".tirith");
        let cwd = &state.roots().cwd;
        std::fs::create_dir_all(&org).unwrap();
        std::fs::create_dir_all(cwd.join(".git")).unwrap();
        std::fs::create_dir_all(cwd.join(".tirith")).unwrap();
        std::fs::write(
            org.join("policy.yml"),
            "paranoia: 2\nallow_bypass_env: true\nscan:\n  require_complete: true\n",
        )
        .unwrap();
        std::fs::write(
            cwd.join(".tirith/policy.yaml"),
            "paranoia: 4\nallowlist: [hostile.example]\nallow_bypass_env: true\n",
        )
        .unwrap();
        let snapshot = EffectivePolicySnapshot::resolve(cwd.to_str(), ResolutionMode::Runtime);
        assert_eq!(
            snapshot.field_provenance["paranoia"].effective_source.kind,
            "repo"
        );
        assert_eq!(
            snapshot.field_provenance["scan.require_complete"]
                .effective_source
                .kind,
            "org"
        );
        assert_eq!(
            snapshot.field_provenance["env_guard_enabled"]
                .effective_source
                .kind,
            "default"
        );
        assert!(snapshot
            .neutralized_settings
            .iter()
            .any(|setting| setting.field == "allowlist" && setting.source.kind == "repo"));
        assert!(snapshot
            .operator_targets
            .iter()
            .any(|target| target.scope == "user" && !target.effective));
        assert!(snapshot
            .operator_targets
            .iter()
            .any(|target| target.scope == "repo" && target.allowed_operation == "tightening_only"));
        let primary = snapshot.primary_input_revision.as_ref().unwrap();
        assert!(snapshot
            .input_revisions
            .iter()
            .any(|input| &input.revision == primary
                && input.source.path.as_deref() == org.join("policy.yml").to_str()));
        assert!(snapshot.revalidate_for_mutation().is_ok());
    }

    #[test]
    fn absent_candidates_and_overlay_bytes_are_revision_inputs() {
        let state = GlobalStateGuard::new().unwrap();
        let config = crate::policy::config_dir().unwrap();
        std::fs::create_dir_all(&config).unwrap();
        std::fs::write(config.join("blocklist"), "one.example\n").unwrap();
        let before = EffectivePolicySnapshot::resolve(None, ResolutionMode::Runtime);
        assert!(before.revalidate_inputs().is_ok());
        std::fs::write(config.join("policy.yml"), "paranoia: 4\n").unwrap();
        assert!(
            before.revalidate_inputs().is_err(),
            "a newly created higher-priority input must invalidate defaults"
        );
        let after = EffectivePolicySnapshot::resolve(None, ResolutionMode::Runtime);
        std::fs::write(config.join("blocklist"), "two.example\n").unwrap();
        assert!(after.revalidate_inputs().is_err());
        assert!(after.policy.is_blocklisted("one.example"));
        drop(state);
    }

    #[test]
    fn revision_tokens_and_debug_do_not_reveal_credential_hashes() {
        let _state = GlobalStateGuard::new().unwrap();
        let config = crate::policy::config_dir().unwrap();
        std::fs::create_dir_all(&config).unwrap();
        let content = "policy_server_api_key: short-secret\n";
        std::fs::write(config.join("policy.yaml"), content).unwrap();
        let first = EffectivePolicySnapshot::resolve(None, ResolutionMode::Runtime);
        let second = EffectivePolicySnapshot::resolve(None, ResolutionMode::Runtime);
        let public = serde_json::to_string(&first.input_revisions).unwrap();
        assert!(!public.contains("short-secret"));
        assert!(!public.contains(&format!("{:x}", Sha256::digest(content.as_bytes()))));
        assert!(!format!("{first:?}").contains("short-secret"));
        assert_ne!(first.identity, second.identity);
        assert_ne!(first.primary_input_revision, second.primary_input_revision);
        assert_eq!(first.private_replay_guard(), second.private_replay_guard());
        assert!(!format!("{:?}", first.private_replay_guard()).contains("digest"));
        assert!(first.revalidate_inputs().is_ok());
    }

    #[test]
    fn trust_generation_and_deadline_use_only_accepted_live_grants() {
        let _state = GlobalStateGuard::new().unwrap();
        let config = crate::policy::config_dir().unwrap();
        std::fs::create_dir_all(&config).unwrap();
        let expiry = (chrono::Utc::now() + chrono::Duration::hours(2)).to_rfc3339();
        let later = (chrono::Utc::now() + chrono::Duration::hours(3)).to_rfc3339();
        let invalid_earlier = (chrono::Utc::now() + chrono::Duration::hours(1)).to_rfc3339();
        std::fs::write(
            config.join("trust.json"),
            serde_json::to_vec(&serde_json::json!({"version":1,"entries":[
                {"pattern":"live.example","ttl_expires":expiry},
                {"pattern":"later.example","ttl_expires":later},
                {"pattern":"bad.example","rule_id":12,"ttl_expires":invalid_earlier},
                {"pattern":"old.example","ttl_expires":"2000-01-01T00:00:00Z"},
                {"pattern":"invalid.example","ttl_expires":"tomorrow"}
            ]}))
            .unwrap(),
        )
        .unwrap();
        let snapshot = EffectivePolicySnapshot::resolve(None, ResolutionMode::Runtime);
        assert_eq!(snapshot.next_trust_expiry.as_deref(), Some(expiry.as_str()));
        assert!(snapshot.trust_generation.is_some());
        assert!(!snapshot.policy.is_allowlisted("https://bad.example"));
        assert!(!snapshot.policy.is_allowlisted("https://old.example"));
        assert!(snapshot.revalidate_inputs().is_ok());
        std::fs::write(config.join("trust.json"), "{\"version\":1,\"entries\":[]}").unwrap();
        assert!(snapshot.revalidate_inputs().is_err());
    }

    #[test]
    fn incident_start_and_stop_revalidate_fresh_state_and_report_constraints() {
        let _state = GlobalStateGuard::new().unwrap();
        crate::incident::invalidate_cache();
        let before = EffectivePolicySnapshot::resolve(None, ResolutionMode::Runtime);
        assert!(before.revalidate_inputs().is_ok());
        crate::incident::start("snapshot regression").unwrap();
        assert!(before.revalidate_inputs().is_err());
        let active = EffectivePolicySnapshot::resolve(None, ResolutionMode::Runtime);
        assert_eq!(active.policy.fail_mode, FailMode::Closed);
        assert!(active.field_provenance["allow_bypass_env_noninteractive"]
            .contributions
            .iter()
            .any(|item| item.source.kind == "incident"));
        assert!(active.revalidate_inputs().is_ok());
        crate::incident::stop().unwrap();
        assert!(active.revalidate_inputs().is_err());
    }

    #[test]
    fn actual_read_witness_is_not_reconstructed_from_a_later_file_version() {
        let _state = GlobalStateGuard::new().unwrap();
        let config = crate::policy::config_dir().unwrap();
        std::fs::create_dir_all(&config).unwrap();
        let path = config.join("policy.yaml");
        std::fs::write(&path, "paranoia: 1\n").unwrap();
        let capture = ResolutionCapture::start();
        let policy = Policy::discover(None);
        std::fs::write(&path, "paranoia: 4\n").unwrap();
        let captured = capture.finish();
        assert_eq!(policy.paranoia, 1);
        assert!(captured.witnesses.iter().any(|witness| matches!(&witness.kind, WitnessKind::File(observed, _, _) if observed == &path) && !witness.is_current()));
    }

    #[cfg(unix)]
    #[test]
    fn trusted_policy_symlinks_keep_their_reader_semantics_during_revalidation() {
        let _state = GlobalStateGuard::new().unwrap();
        let config = crate::policy::config_dir().unwrap();
        std::fs::create_dir_all(&config).unwrap();
        let target = config.join("managed-policy.yaml");
        std::fs::write(&target, "paranoia: 3\n").unwrap();
        std::os::unix::fs::symlink(&target, config.join("policy.yaml")).unwrap();
        let snapshot = EffectivePolicySnapshot::resolve(None, ResolutionMode::Runtime);
        assert_eq!(snapshot.policy.paranoia, 3);
        assert!(snapshot.revalidate_inputs().is_ok());
        std::fs::write(&target, "paranoia: 4\n").unwrap();
        assert!(snapshot.revalidate_inputs().is_err());
    }

    #[test]
    fn labels_are_attributed_to_the_actual_winning_overlay() {
        let state = GlobalStateGuard::new().unwrap();
        let config = crate::policy::config_dir().unwrap();
        let cwd = &state.roots().cwd;
        std::fs::create_dir_all(&config).unwrap();
        std::fs::create_dir_all(cwd.join(".git")).unwrap();
        std::fs::create_dir_all(cwd.join(".tirith")).unwrap();
        std::fs::write(
            config.join("context-labels.yaml"),
            "staging: low\nproduction: critical\n",
        )
        .unwrap();
        std::fs::write(
            cwd.join(".tirith/context-labels.yaml"),
            "staging: critical\nproduction: low\n",
        )
        .unwrap();
        let snapshot = EffectivePolicySnapshot::resolve(cwd.to_str(), ResolutionMode::Runtime);
        assert_eq!(
            snapshot.field_provenance["context_labels.staging"]
                .effective_source
                .kind,
            "repo_labels"
        );
        assert_eq!(
            snapshot.field_provenance["context_labels.production"]
                .effective_source
                .kind,
            "user_labels"
        );
        assert!(!snapshot.field_provenance.contains_key("context_labels"));
        assert!(snapshot.revalidate_inputs().is_ok());
    }
    #[test]
    fn external_guard_survives_owned_policy_creation_but_detects_unowned_fallback_creation() {
        let _state = GlobalStateGuard::new().unwrap();
        let config = crate::policy::config_dir().unwrap();
        std::fs::create_dir_all(&config).unwrap();
        let yaml = config.join("policy.yaml");
        let yml = config.join("policy.yml");
        let excluded = BTreeSet::from([yaml.clone()]);
        let before = EffectivePolicySnapshot::resolve(None, ResolutionMode::Runtime);
        std::fs::write(&yaml, "paranoia: 2\n").unwrap();
        let after = before.refresh_runtime();
        assert_eq!(after.policy.scope, PolicyScope::User);
        assert_eq!(after.policy.paranoia, 2);
        assert_eq!(
            before.private_external_inputs_guard(&excluded),
            after.private_external_inputs_guard(&excluded)
        );
        assert_ne!(before.private_replay_guard(), after.private_replay_guard());

        // The newly shadowed sibling is still an external discovery input.
        // Creating it cannot disappear behind the owned YAML publication.
        std::fs::write(&yml, "paranoia: 3\n").unwrap();
        let sibling = after.refresh_runtime();
        assert_eq!(sibling.policy.path.as_deref(), yaml.to_str());
        assert_eq!(sibling.policy.paranoia, 2);
        assert_ne!(
            after.private_external_inputs_guard(&excluded),
            sibling.private_external_inputs_guard(&excluded)
        );
        assert!(after.revalidate_inputs().is_err());
    }

    #[test]
    fn external_guard_preserves_selected_unowned_yml_content_and_precedence() {
        let _state = GlobalStateGuard::new().unwrap();
        let config = crate::policy::config_dir().unwrap();
        std::fs::create_dir_all(&config).unwrap();
        let yaml = config.join("policy.yaml");
        let yml = config.join("policy.yml");
        std::fs::write(&yml, "paranoia: 2\n").unwrap();
        let excluded = BTreeSet::from([yaml.clone()]);
        let before = EffectivePolicySnapshot::resolve(None, ResolutionMode::Runtime);
        assert_eq!(before.policy.path.as_deref(), yml.to_str());
        std::fs::write(&yml, "paranoia: 3\n").unwrap();
        let changed = before.refresh_runtime();
        assert_eq!(changed.policy.paranoia, 3);
        assert_ne!(
            before.private_external_inputs_guard(&excluded),
            changed.private_external_inputs_guard(&excluded)
        );

        // Shadowing an already-selected external policy changes the read graph
        // and still requires a new plan; exact-path exclusion cannot bless it.
        std::fs::write(&yaml, "paranoia: 1\n").unwrap();
        let shadowed = changed.refresh_runtime();
        assert_eq!(shadowed.policy.path.as_deref(), yaml.to_str());
        assert_eq!(shadowed.policy.paranoia, 1);
        assert_ne!(
            changed.private_external_inputs_guard(&excluded),
            shadowed.private_external_inputs_guard(&excluded)
        );
    }

    #[test]
    fn external_replay_guard_excludes_only_exact_owned_inputs_and_preserves_scope() {
        let state = GlobalStateGuard::new().unwrap();
        let config = crate::policy::config_dir().unwrap();
        std::fs::create_dir_all(&config).unwrap();
        let owned = config.join(crate::trust_grants::STORE_FILE);
        let excluded = BTreeSet::from([owned.clone()]);
        let before = EffectivePolicySnapshot::resolve(None, ResolutionMode::Runtime);
        assert!(before.resolution_cwd().is_none());
        std::fs::write(&owned, r#"{"schema_version":1,"grants":[]}"#).unwrap();
        let after = before.refresh_runtime();
        assert_eq!(
            before.private_external_inputs_guard(&excluded),
            after.private_external_inputs_guard(&excluded)
        );
        assert_ne!(before.private_replay_guard(), after.private_replay_guard());
        assert_ne!(
            before.private_external_inputs_guard(&BTreeSet::from([config.clone()])),
            after.private_external_inputs_guard(&BTreeSet::from([config.clone()]))
        );
        let explicit =
            EffectivePolicySnapshot::resolve(state.roots().cwd.to_str(), ResolutionMode::Runtime);
        assert_ne!(
            after.private_external_inputs_guard(&excluded),
            explicit.private_external_inputs_guard(&excluded)
        );
        std::fs::write(config.join("blocklist"), "changed-authority.example\n").unwrap();
        let external = after.refresh_runtime();
        assert_ne!(
            after.private_external_inputs_guard(&excluded),
            external.private_external_inputs_guard(&excluded)
        );
    }
}
