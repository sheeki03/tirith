//! Optional selected team connection. Saved bytes are configuration, never
//! Runtime enrollment, policy adoption, approval, or an authenticated response.
use crate::policy_team::{Capabilities, Id, PrivateCommitment, Role, SCHEMA_VERSION};
use crate::policy_team_client::{AuthorityBinding, TeamClient};
use serde::{Deserialize, Serialize};
use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};
#[path = "policy_team_connection_native.rs"]
mod native;

pub const MAX_CONNECTION_BYTES: usize = 128 * 1024;
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum ConnectionError {
    #[error("team connection storage is unavailable or not private")]
    UnsafeStorage,
    #[error("selected team connection changed; repeat the explicit action")]
    ChangedSelection,
    #[error("team connection input is invalid")]
    InvalidInput,
    #[error("no team connection is configured")]
    NotConfigured,
    #[error("team authority authentication failed")]
    AuthenticationFailed,
    #[error("team authority or policy identity did not match the selected pins")]
    IdentityMismatch,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Record {
    schema_version: u32,
    connection_id: Id,
    binding: AuthorityBinding,
    credential: String,
}
fn token(bytes: &[u8]) -> Result<&str, ConnectionError> {
    let bytes = bytes.strip_suffix(b"\n").unwrap_or(bytes);
    if bytes.len() != 64
        || !bytes
            .iter()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(b))
    {
        return Err(ConnectionError::InvalidInput);
    }
    std::str::from_utf8(bytes).map_err(|_| ConnectionError::InvalidInput)
}
fn decode(bytes: &[u8]) -> Result<Record, ConnectionError> {
    if bytes.len() > MAX_CONNECTION_BYTES {
        return Err(ConnectionError::InvalidInput);
    }
    let r: Record = serde_json::from_slice(bytes).map_err(|_| ConnectionError::InvalidInput)?;
    if r.schema_version != SCHEMA_VERSION
        || r.binding.schema_version != SCHEMA_VERSION
        || token(r.credential.as_bytes())? != r.credential
        || r.credential.len() != 64
    {
        return Err(ConnectionError::InvalidInput);
    }
    Ok(r)
}
/// Crate-private retained configuration bytes, never authentication or effect
/// authority. Shared with the separately authorized enrollment reader.
pub(crate) struct Input {
    path: PathBuf,
    parents: native::HeldPath,
    file: Option<File>,
    generation: Option<native::Facts>,
    bytes: Option<Vec<u8>>,
    cap: usize,
    private: bool,
}
impl Input {
    pub(crate) fn capture(
        path: PathBuf,
        cap: usize,
        private: bool,
        private_parent: bool,
    ) -> Result<Self, ConnectionError> {
        let parents = native::HeldPath::capture(&path, private_parent)?;
        let file = match parents.open_file(cap) {
            Ok(f) => Some(f),
            Err(crate::util::OpenRegularError::NotFound) => None,
            Err(_) => return Err(ConnectionError::UnsafeStorage),
        };
        let mut result = Self {
            path,
            parents,
            file,
            generation: None,
            bytes: None,
            cap,
            private,
        };
        if let Some(file) = &mut result.file {
            let before = native::facts(file, private)?;
            let mut bytes = Vec::new();
            (&mut *file)
                .take(cap as u64 + 1)
                .read_to_end(&mut bytes)
                .map_err(|_| ConnectionError::UnsafeStorage)?;
            if bytes.len() > cap || native::facts(file, private)? != before {
                return Err(ConnectionError::ChangedSelection);
            }
            result.generation = Some(before);
            result.bytes = Some(bytes);
        }
        result.parents.revalidate()?;
        result.revalidate()?;
        Ok(result)
    }
    pub(crate) fn bytes(&self) -> Option<&[u8]> {
        self.bytes.as_deref()
    }
    pub(crate) fn path(&self) -> &Path {
        &self.path
    }
    pub(crate) fn revalidate(&self) -> Result<(), ConnectionError> {
        self.parents.revalidate()?;
        if let Some(f) = &self.file {
            if Some(native::facts(f, self.private)?) != self.generation {
                return Err(ConnectionError::ChangedSelection);
            }
        }
        let mut live = match self.parents.open_file(self.cap) {
            Ok(f) => Some(f),
            Err(crate::util::OpenRegularError::NotFound) => None,
            Err(_) => return Err(ConnectionError::UnsafeStorage),
        };
        match (&mut live, &self.bytes) {
            (None, None) => {}
            (Some(f), Some(expected)) => {
                let before = native::facts(f, self.private)?;
                if Some(&before) != self.generation.as_ref() {
                    return Err(ConnectionError::ChangedSelection);
                }
                f.seek(SeekFrom::Start(0))
                    .map_err(|_| ConnectionError::UnsafeStorage)?;
                let mut bytes = Vec::new();
                (&mut *f)
                    .take(self.cap as u64 + 1)
                    .read_to_end(&mut bytes)
                    .map_err(|_| ConnectionError::UnsafeStorage)?;
                if bytes != *expected || native::facts(f, self.private)? != before {
                    return Err(ConnectionError::ChangedSelection);
                }
            }
            _ => return Err(ConnectionError::ChangedSelection),
        }
        self.parents.revalidate()
    }
}
/// Public redacted state. Local status does not invent a role or credential age.
#[derive(Clone, Debug, Serialize)]
pub struct ConnectionStatus {
    pub schema_version: u32,
    pub configured: bool,
    pub connection_id: Option<Id>,
    pub authority_id: Option<Id>,
    pub policy_id: Option<Id>,
    pub endpoint_origin: Option<String>,
    pub authentication: ConnectionAuthentication,
    pub role: Option<Role>,
    pub credential_expires_unix_ms: Option<u64>,
}
#[derive(Clone, Copy, Debug, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ConnectionAuthentication {
    NotRequested,
    AuthenticatedNow,
}
fn status(record: Option<&Record>, caps: Option<&Capabilities>) -> ConnectionStatus {
    ConnectionStatus {
        schema_version: SCHEMA_VERSION,
        configured: record.is_some(),
        connection_id: record.map(|r| r.connection_id.clone()),
        authority_id: record.map(|r| r.binding.authority_id.clone()),
        policy_id: record.map(|r| r.binding.policy_id.clone()),
        endpoint_origin: record
            .and_then(|r| url::Url::parse(&r.binding.base_url).ok())
            .map(|u| u.origin().ascii_serialization()),
        authentication: if caps.is_some() {
            ConnectionAuthentication::AuthenticatedNow
        } else {
            ConnectionAuthentication::NotRequested
        },
        role: caps.map(|c| c.role),
        credential_expires_unix_ms: caps.map(|c| c.credential_expires_unix_ms),
    }
}
/// Closed private data stores used by optional team enrollment and review.
/// Deliberately excludes the connection credential record. IDs and retained
/// bytes are intent/evidence only, never policy, approval or network authority.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TeamRecord {
    Enrollment,
    /// Exact bounded pending client report, never policy or credential storage.
    Report,
    Rollout(Id),
}
impl TeamRecord {
    pub fn cap(&self) -> usize {
        match self {
            Self::Enrollment => 2 * 1024 * 1024,
            Self::Report => 16 * 1024,
            Self::Rollout(_) => 4 * 1024 * 1024,
        }
    }
    fn path_in_scope(&self, scope: &Path) -> PathBuf {
        let root = scope.join("team-policy");
        match self {
            Self::Enrollment => root.join("enrollment.json"),
            Self::Report => root.join("report.json"),
            Self::Rollout(id) => root.join("rollouts").join(format!("{}.json", id.as_str())),
        }
    }
    /// Read-only capture, including absence. Does not contact an authority,
    /// create a directory, or turn deserialized record bytes into a permission.
    pub fn capture_current(&self) -> Result<TeamRecordWitness, ConnectionError> {
        let scope = crate::policy::config_dir().ok_or(ConnectionError::UnsafeStorage)?;
        let input = Input::capture(self.path_in_scope(&scope), self.cap(), true, true)?;
        let witness = TeamRecordWitness { scope, input };
        witness.revalidate()?;
        Ok(witness)
    }
}
/// Non-Clone/non-Serialize private source witness. Authority must be recaptured
/// independently; private_bytes is never a public DTO or an approval proof.
pub struct TeamRecordWitness {
    scope: PathBuf,
    input: Input,
}
impl TeamRecordWitness {
    pub fn private_bytes(&self) -> Option<&[u8]> {
        self.input.bytes()
    }
    pub fn private_path(&self) -> &Path {
        self.input.path()
    }
    pub fn private_scope(&self) -> &Path {
        &self.scope
    }
    pub fn matches_private_bytes(&self, bytes: Option<&[u8]>) -> bool {
        self.input.bytes() == bytes
    }
    pub fn revalidate(&self) -> Result<(), ConnectionError> {
        if crate::policy::config_dir().as_ref() != Some(&self.scope) {
            return Err(ConnectionError::ChangedSelection);
        }
        self.input.revalidate()
    }
}

pub struct SelectedConnection;
/// Nonserializable retained source witness. Holding this object alone does not
/// authenticate the server or enable Runtime. Every client acquisition discovers.
pub struct ConnectionWitness {
    scope: PathBuf,
    input: Input,
    record: Option<Record>,
}
impl SelectedConnection {
    pub fn capture_current() -> Result<ConnectionWitness, ConnectionError> {
        let scope = crate::policy::config_dir().ok_or(ConnectionError::UnsafeStorage)?;
        Self::capture_at(scope)
    }
    fn capture_at(scope: PathBuf) -> Result<ConnectionWitness, ConnectionError> {
        let input = Input::capture(
            scope.join("team-policy/connection.json"),
            MAX_CONNECTION_BYTES,
            true,
            true,
        )?;
        let record = input.bytes().map(decode).transpose()?;
        Ok(ConnectionWitness {
            scope,
            input,
            record,
        })
    }
}
impl ConnectionWitness {
    pub fn configured(&self) -> bool {
        self.record.is_some()
    }
    pub fn connection_id(&self) -> Option<&Id> {
        self.record.as_ref().map(|r| &r.connection_id)
    }
    /// Internal configuration access. Contains private CA material; never serialize
    /// this binding in an API response, log, support bundle, or status DTO.
    pub fn binding(&self) -> Option<&AuthorityBinding> {
        self.record.as_ref().map(|r| &r.binding)
    }
    pub fn revalidate(&self) -> Result<(), ConnectionError> {
        if crate::policy::config_dir().as_ref() != Some(&self.scope) {
            return Err(ConnectionError::ChangedSelection);
        }
        self.input.revalidate()
    }
    /// Private cache/review binding, not a public hash or authorization token.
    pub fn private_selection_commitment(&self) -> Result<PrivateCommitment, ConnectionError> {
        self.revalidate()?;
        let bytes = serde_json::to_vec(&(
            self.scope.to_str().ok_or(ConnectionError::UnsafeStorage)?,
            self.input.parents.private_identity(),
            format!("{:?}", self.input.generation),
            self.input.bytes.as_deref(),
        ))
        .map_err(|_| ConnectionError::InvalidInput)?;
        Ok(PrivateCommitment::of(
            "tirith.team.selected-connection.v1",
            &bytes,
        ))
    }
    pub fn authenticate(&self) -> Result<(TeamClient, Capabilities), ConnectionError> {
        self.revalidate()?;
        let r = self.record.as_ref().ok_or(ConnectionError::NotConfigured)?;
        let response = discover(&r.binding, &r.credential);
        self.revalidate()?;
        response
    }
    pub fn client(&self) -> Result<TeamClient, ConnectionError> {
        self.authenticate().map(|x| x.0)
    }
    pub fn status(&self, refresh: bool) -> Result<ConnectionStatus, ConnectionError> {
        self.revalidate()?;
        let caps = if refresh && self.configured() {
            Some(self.authenticate()?.1)
        } else {
            None
        };
        Ok(status(self.record.as_ref(), caps.as_ref()))
    }
    /// Native persistence adapter only. Neither path nor bytes is a browser DTO.
    pub fn private_path(&self) -> &Path {
        self.input.path()
    }
    pub fn private_scope(&self) -> &Path {
        &self.scope
    }
    pub fn matches_private_bytes(&self, bytes: Option<&[u8]>) -> bool {
        self.input.bytes.as_deref() == bytes
    }
}
fn discover(
    binding: &AuthorityBinding,
    credential: &str,
) -> Result<(TeamClient, Capabilities), ConnectionError> {
    if binding.schema_version != SCHEMA_VERSION {
        return Err(ConnectionError::InvalidInput);
    }
    let (client, caps) =
        TeamClient::discover_with_options(&binding.base_url, credential, binding.transport.clone())
            .map_err(|_| ConnectionError::AuthenticationFailed)?;
    let normalized =
        url::Url::parse(&binding.base_url).map_err(|_| ConnectionError::InvalidInput)?;
    if client.binding().base_url != normalized.as_str().trim_end_matches('/')
        || client.binding().authority_id != binding.authority_id
        || client.binding().policy_id != binding.policy_id
    {
        return Err(ConnectionError::IdentityMismatch);
    }
    Ok((client, caps))
}
/// Explicit chosen input remains retained until private publication is complete.
/// This object has no network-write or Runtime-enrollment operation.
pub struct PreparedConnection {
    record: Record,
    credential: Input,
    ca: Option<Input>,
    caps: Capabilities,
}
/// Private byte wrapper. Deliberately lacks Debug and Serialize.
pub struct PrivateConnectionBytes(Vec<u8>);
impl PrivateConnectionBytes {
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}
impl PreparedConnection {
    pub fn discover(
        mut binding: AuthorityBinding,
        credential_file: &Path,
        ca_file: Option<&Path>,
    ) -> Result<Self, ConnectionError> {
        if binding.transport.additional_ca_pem.is_some() {
            return Err(ConnectionError::InvalidInput);
        }
        let absolute = |p: &Path| {
            if p.is_absolute() {
                Ok(p.to_path_buf())
            } else {
                std::env::current_dir()
                    .map(|d| d.join(p))
                    .map_err(|_| ConnectionError::UnsafeStorage)
            }
        };
        let credential = Input::capture(absolute(credential_file)?, 65, true, false)?;
        let secret = token(
            credential
                .bytes
                .as_deref()
                .ok_or(ConnectionError::InvalidInput)?,
        )?
        .to_owned();
        let ca = ca_file
            .map(|p| Input::capture(absolute(p)?, 64 * 1024, false, false))
            .transpose()?;
        if let Some(ca) = &ca {
            binding.transport.additional_ca_pem = Some(
                std::str::from_utf8(ca.bytes.as_deref().ok_or(ConnectionError::InvalidInput)?)
                    .map_err(|_| ConnectionError::InvalidInput)?
                    .to_owned(),
            );
        }
        credential.revalidate()?;
        if let Some(ca) = &ca {
            ca.revalidate()?
        }
        let (client, caps) = discover(&binding, &secret)?;
        credential.revalidate()?;
        if let Some(ca) = &ca {
            ca.revalidate()?
        }
        Ok(Self {
            record: Record {
                schema_version: SCHEMA_VERSION,
                connection_id: Id::new(),
                binding: client.binding().clone(),
                credential: secret,
            },
            credential,
            ca,
            caps,
        })
    }
    pub fn revalidate(&self) -> Result<(), ConnectionError> {
        let now: u64 = chrono::Utc::now()
            .timestamp_millis()
            .try_into()
            .map_err(|_| ConnectionError::AuthenticationFailed)?;
        self.caps
            .validate(now)
            .map_err(|_| ConnectionError::AuthenticationFailed)?;
        self.credential.revalidate()?;
        if let Some(ca) = &self.ca {
            ca.revalidate()?
        }
        Ok(())
    }
    pub fn same_selection(&self, old: &ConnectionWitness) -> bool {
        old.record.as_ref().is_some_and(|old| {
            old.credential == self.record.credential
                && serde_json::to_vec(&old.binding).ok()
                    == serde_json::to_vec(&self.record.binding).ok()
        })
    }
    pub fn private_bytes(&self) -> Result<PrivateConnectionBytes, ConnectionError> {
        self.revalidate()?;
        let bytes = serde_json::to_vec(&self.record).map_err(|_| ConnectionError::InvalidInput)?;
        if bytes.len() > MAX_CONNECTION_BYTES {
            return Err(ConnectionError::InvalidInput);
        }
        Ok(PrivateConnectionBytes(bytes))
    }
    pub fn status(&self) -> ConnectionStatus {
        status(Some(&self.record), Some(&self.caps))
    }
    pub fn authenticated_existing_status(
        &self,
        old: &ConnectionWitness,
    ) -> Result<ConnectionStatus, ConnectionError> {
        self.revalidate()?;
        old.revalidate()?;
        if !self.same_selection(old) {
            return Err(ConnectionError::ChangedSelection);
        }
        Ok(status(old.record.as_ref(), Some(&self.caps)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn record() -> Record {
        Record {
            schema_version: SCHEMA_VERSION,
            connection_id: Id::new(),
            binding: AuthorityBinding {
                schema_version: SCHEMA_VERSION,
                base_url: "https://policy.example.com/private-base".into(),
                authority_id: Id::new(),
                policy_id: Id::new(),
                transport: crate::policy_team_client::EndpointOptions {
                    pinned_addresses: vec![],
                    additional_ca_pem: Some("PRIVATE-CA-TEST-SENTINEL".into()),
                },
            },
            credential: "a".repeat(64),
        }
    }
    #[test]
    fn exact_credential_grammar_and_single_lf_only() {
        let valid = "a".repeat(64);
        assert!(token(valid.as_bytes()).is_ok());
        assert!(token(format!("{valid}\n").as_bytes()).is_ok());
        for bad in [
            format!("{valid}\n\n"),
            format!("{valid}\r\n"),
            "A".repeat(64),
            "g".repeat(64),
            "a".repeat(63),
            "a".repeat(65),
        ] {
            assert!(token(bad.as_bytes()).is_err())
        }
    }
    #[test]
    fn selected_record_refuses_unknown_duplicate_and_runtime_fields() {
        let r = record();
        let value = serde_json::to_value(&r).unwrap();
        assert!(decode(&serde_json::to_vec(&value).unwrap()).is_ok());
        for key in ["enabled", "enrolled", "runtime", "role"] {
            let mut changed = value.clone();
            changed[key] = serde_json::json!(true);
            assert!(decode(&serde_json::to_vec(&changed).unwrap()).is_err())
        }
        let raw = serde_json::to_string(&value).unwrap();
        let duplicate = format!("{{\"schema_version\":1,{}", &raw[1..]);
        assert!(decode(duplicate.as_bytes()).is_err());
    }
    #[test]
    fn record_schema_token_and_id_are_closed() {
        let value = serde_json::to_value(record()).unwrap();
        for (key, replacement) in [
            ("schema_version", serde_json::json!(2)),
            (
                "connection_id",
                serde_json::json!("00000000-0000-0000-0000-000000000000"),
            ),
            (
                "credential",
                serde_json::json!(format!("{}\n", "a".repeat(64))),
            ),
        ] {
            let mut v = value.clone();
            v[key] = replacement;
            assert!(decode(&serde_json::to_vec(&v).unwrap()).is_err())
        }
    }
    #[test]
    fn local_status_never_projects_credential_ca_path_or_private_hash() {
        let r = record();
        let public = serde_json::to_value(status(Some(&r), None)).unwrap();
        assert_eq!(public["endpoint_origin"], "https://policy.example.com");
        assert!(public["role"].is_null());
        assert!(public["credential_expires_unix_ms"].is_null());
        assert_eq!(public["authentication"], "not_requested");
        let encoded = serde_json::to_string(&public).unwrap();
        for secret in [
            &r.credential,
            "PRIVATE-CA-TEST-SENTINEL",
            "private-base",
            "private_plan_digest",
            "selection_commitment",
            "credential_file",
        ] {
            assert!(!encoded.contains(secret))
        }
    }
    #[test]
    fn missing_selection_is_distinct_from_authenticated_status() {
        let public = serde_json::to_value(status(None, None)).unwrap();
        assert_eq!(public["configured"], false);
        assert!(public["connection_id"].is_null());
        assert_eq!(public["authentication"], "not_requested")
    }
    #[test]
    fn nested_record_duplicates_are_rejected() {
        let raw = serde_json::to_string(&record()).unwrap();
        let changed = raw.replacen(
            "\"transport\":{",
            "\"transport\":{\"pinned_addresses\":[],",
            1,
        );
        assert!(decode(changed.as_bytes()).is_err());
    }
    #[test]
    fn encoded_record_bound_precedes_json_decode() {
        assert!(decode(&vec![b' '; MAX_CONNECTION_BYTES + 1]).is_err())
    }

    #[cfg(unix)]
    mod unix {
        use super::*;
        use std::os::unix::fs::{symlink, PermissionsExt};
        fn root() -> tempfile::TempDir {
            let root = tempfile::tempdir().unwrap();
            std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
            root
        }
        fn private_file(path: &Path, bytes: &[u8]) {
            std::fs::write(path, bytes).unwrap();
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).unwrap()
        }
        #[test]
        fn retained_input_detects_same_size_rewrite() {
            let root = root();
            let path = root.path().join("token");
            private_file(&path, &[b'a'; 64]);
            let input = Input::capture(path.clone(), 65, true, false).unwrap();
            std::fs::write(&path, [b'b'; 64]).unwrap();
            assert!(input.revalidate().is_err())
        }
        #[test]
        fn retained_input_detects_same_bytes_replacement() {
            let root = root();
            let path = root.path().join("token");
            private_file(&path, &[b'a'; 64]);
            let input = Input::capture(path.clone(), 65, true, false).unwrap();
            let next = root.path().join("next");
            private_file(&next, &[b'a'; 64]);
            std::fs::rename(next, &path).unwrap();
            assert!(input.revalidate().is_err())
        }
        #[test]
        fn absent_selection_does_not_create_directories_and_detects_later_record() {
            let root = root();
            let scope = root.path().join("new-scope");
            let witness = SelectedConnection::capture_at(scope.clone()).unwrap();
            assert!(!scope.exists());
            assert!(!witness.configured());
            let parent = scope.join("team-policy");
            std::fs::create_dir_all(&parent).unwrap();
            std::fs::set_permissions(&parent, std::fs::Permissions::from_mode(0o700)).unwrap();
            private_file(
                &parent.join("connection.json"),
                &serde_json::to_vec(&record()).unwrap(),
            );
            assert!(witness.input.revalidate().is_err())
        }
        #[test]
        fn private_inputs_reject_symlink_hardlink_shared_mode_fifo_and_size() {
            let root = root();
            let path = root.path().join("token");
            private_file(&path, &[b'a'; 64]);
            let link = root.path().join("link");
            symlink(&path, &link).unwrap();
            assert!(Input::capture(link, 65, true, false).is_err());
            std::fs::hard_link(&path, root.path().join("hard")).unwrap();
            assert!(Input::capture(path.clone(), 65, true, false).is_err());
            std::fs::remove_file(root.path().join("hard")).unwrap();
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
            assert!(Input::capture(path.clone(), 65, true, false).is_err());
            private_file(&path, &[b'a'; 66]);
            assert!(Input::capture(path, 65, true, false).is_err());
            let fifo = root.path().join("fifo");
            use std::os::unix::ffi::OsStrExt;
            let c = std::ffi::CString::new(fifo.as_os_str().as_bytes()).unwrap();
            assert_eq!(unsafe { libc::mkfifo(c.as_ptr(), 0o600) }, 0);
            assert!(Input::capture(fifo, 65, true, false).is_err())
        }
        #[test]
        fn private_parent_and_mutated_ancestor_refuse() {
            let root = root();
            let parent = root.path().join("team-policy");
            std::fs::create_dir(&parent).unwrap();
            std::fs::set_permissions(&parent, std::fs::Permissions::from_mode(0o755)).unwrap();
            let path = parent.join("connection.json");
            assert!(Input::capture(path.clone(), MAX_CONNECTION_BYTES, true, true).is_err());
            std::fs::set_permissions(&parent, std::fs::Permissions::from_mode(0o700)).unwrap();
            private_file(&path, &serde_json::to_vec(&record()).unwrap());
            let input = Input::capture(path, MAX_CONNECTION_BYTES, true, true).unwrap();
            std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o777)).unwrap();
            assert!(input.revalidate().is_err())
        }
    }
}

#[cfg(test)]
mod team_record_tests {
    use super::*;
    #[test]
    fn closed_names_and_caps_cannot_select_connection_or_arbitrary_path() {
        let scope = Path::new("/fixed/config/tirith");
        let id = Id::parse("11111111-1111-4111-8111-111111111111").unwrap();
        assert_eq!(
            TeamRecord::Enrollment.path_in_scope(scope),
            scope.join("team-policy/enrollment.json")
        );
        assert_eq!(
            TeamRecord::Rollout(id).path_in_scope(scope),
            scope.join("team-policy/rollouts/11111111-1111-4111-8111-111111111111.json")
        );
        assert_eq!(TeamRecord::Enrollment.cap(), 2 * 1024 * 1024);
        assert_eq!(TeamRecord::Rollout(Id::new()).cap(), 4 * 1024 * 1024);
        assert!(Id::parse("../connection").is_err());
        assert!(Id::parse("00000000-0000-0000-0000-000000000000").is_err());
    }
    #[test]
    fn absent_capture_creates_no_store_or_authority() {
        let _guard = tirith_test_support::GlobalStateGuard::new().unwrap();
        for selector in [TeamRecord::Enrollment, TeamRecord::Rollout(Id::new())] {
            let witness = selector.capture_current().unwrap();
            assert!(witness.private_bytes().is_none());
            assert!(!witness.private_path().exists());
            witness.revalidate().unwrap();
        }
        assert!(!crate::policy::config_dir()
            .unwrap()
            .join("team-policy")
            .exists());
    }
    #[cfg(unix)]
    #[test]
    fn native_private_record_bytes_are_retained_and_replacement_invalidates() {
        use std::os::unix::fs::PermissionsExt;
        let _guard = tirith_test_support::GlobalStateGuard::new().unwrap();
        let selector = TeamRecord::Enrollment;
        let scope = crate::policy::config_dir().unwrap();
        let path = selector.path_in_scope(&scope);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::set_permissions(
            path.parent().unwrap(),
            std::fs::Permissions::from_mode(0o700),
        )
        .unwrap();
        std::fs::write(&path, b"private intent only").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        let witness = selector.capture_current().unwrap();
        assert_eq!(
            witness.private_bytes(),
            Some(b"private intent only".as_slice())
        );
        let next = path.with_extension("next");
        std::fs::write(&next, b"private intent only").unwrap();
        std::fs::set_permissions(&next, std::fs::Permissions::from_mode(0o600)).unwrap();
        std::fs::rename(next, &path).unwrap();
        assert!(witness.revalidate().is_err());
    }
    #[cfg(unix)]
    #[test]
    fn selected_record_cap_and_shared_permissions_refuse() {
        use std::os::unix::fs::PermissionsExt;
        let _guard = tirith_test_support::GlobalStateGuard::new().unwrap();
        let selector = TeamRecord::Enrollment;
        let path = selector.path_in_scope(&crate::policy::config_dir().unwrap());
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::set_permissions(
            path.parent().unwrap(),
            std::fs::Permissions::from_mode(0o700),
        )
        .unwrap();
        std::fs::write(&path, vec![b'a'; selector.cap() + 1]).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        assert!(selector.capture_current().is_err());
        std::fs::write(&path, b"small").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert!(selector.capture_current().is_err());
    }
}
