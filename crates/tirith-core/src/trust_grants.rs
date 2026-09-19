//! Operator-owned trust lifecycle. The new envelope deliberately has no
//! `entries` member: 0.4.2 readers cannot interpret project grants as global.
//! Runtime consumers read this file on every resolution and check time then;
//! an accepted grant is never a cached execution permission.
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;

pub const STORE_FILE: &str = "trust-grants.json";
pub const STORE_VERSION: u32 = 1;
pub const STORE_READ_CAP: u64 = 1024 * 1024;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Expiry {
    Permanent,
    Active(DateTime<Utc>),
    Expired,
    Invalid,
}

/// Missing/null is legacy permanent trust. Every other value must be a valid
/// RFC3339 string; a number, object or malformed date never becomes permanent.
pub fn expiry_value(value: Option<&Value>, now: DateTime<Utc>) -> Expiry {
    match value {
        None | Some(Value::Null) => Expiry::Permanent,
        Some(Value::String(value)) => expiry(Some(value), now),
        Some(_) => Expiry::Invalid,
    }
}

pub fn expiry(value: Option<&str>, now: DateTime<Utc>) -> Expiry {
    match value {
        None => Expiry::Permanent,
        Some(value) => match DateTime::parse_from_rfc3339(value) {
            Ok(deadline) if deadline.with_timezone(&Utc) > now => {
                Expiry::Active(deadline.with_timezone(&Utc))
            }
            Ok(_) => Expiry::Expired,
            Err(_) => Expiry::Invalid,
        },
    }
}

/// Parse CLI durations with checked arithmetic, including Chrono's date range.
pub fn expiry_from_ttl(ttl: &str, now: DateTime<Utc>) -> Result<String, String> {
    let (number, multiplier) = if let Some(n) = ttl.strip_suffix('m') {
        (n, 60i64)
    } else if let Some(n) = ttl.strip_suffix('h') {
        (n, 3600)
    } else if let Some(n) = ttl.strip_suffix('d') {
        (n, 86400)
    } else {
        return Err("TTL must use minutes, hours or days (for example 1h or 30d)".into());
    };
    let seconds = number
        .parse::<i64>()
        .ok()
        .filter(|number| *number > 0)
        .and_then(|number| number.checked_mul(multiplier))
        .ok_or("TTL must be positive and within the supported date range")?;
    let duration =
        chrono::Duration::try_seconds(seconds).ok_or("TTL exceeds the supported date range")?;
    now.checked_add_signed(duration)
        .map(|deadline| deadline.to_rfc3339())
        .ok_or_else(|| "TTL exceeds the supported date range".into())
}

/// A checkout identity, not a repository-provided token. Canonical paths make
/// symlink aliases equivalent; handle-derived object identity rejects directory
/// replacement. Moving a checkout requires re-enrolment. Linked worktrees and
/// nested repositories have different roots even when sharing Git objects.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProjectIdentity {
    pub canonical_root: PathBuf,
    pub device: u64,
    pub inode: u64,
    pub created_seconds: u64,
    pub created_nanos: u32,
    pub operator_home: DirectoryIdentity,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DirectoryIdentity {
    pub canonical_path: PathBuf,
    pub device: u64,
    pub inode: u64,
    pub created_seconds: u64,
    pub created_nanos: u32,
}

impl DirectoryIdentity {
    fn capture(path: &Path) -> Result<Self, String> {
        let canonical_path = path
            .canonicalize()
            .map_err(|_| "directory identity is unavailable")?;
        let directory = crate::util::dirfd::DirCapability::open_root(&canonical_path)
            .map_err(|_| "cannot retain directory identity")?;
        let (device, inode) = directory
            .identity()
            .map_err(|_| "filesystem identity is unsupported")?;
        let created = directory
            .metadata()
            .and_then(|metadata| metadata.created())
            .map_err(|_| "project trust requires filesystem creation timestamps")?
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|_| "filesystem creation timestamp is unsupported")?;
        let current = crate::util::dirfd::DirCapability::open_root(&canonical_path)
            .map_err(|_| "directory changed while being identified")?;
        if current.identity().ok() != Some((device, inode))
            || current
                .metadata()
                .and_then(|metadata| metadata.created())
                .ok()
                .and_then(|time| time.duration_since(std::time::UNIX_EPOCH).ok())
                != Some(created)
        {
            return Err("directory changed while being identified".into());
        }
        Ok(Self {
            canonical_path,
            device,
            inode,
            created_seconds: created.as_secs(),
            created_nanos: created.subsec_nanos(),
        })
    }
}

impl ProjectIdentity {
    pub fn capture(cwd: Option<&str>) -> Result<Self, String> {
        let start = cwd
            .map(PathBuf::from)
            .or_else(|| std::env::current_dir().ok())
            .ok_or("cannot locate the current project directory")?
            .canonicalize()
            .map_err(|_| "cannot resolve the current project directory")?;
        let root = crate::policy::find_repo_root(start.to_str())
            .ok_or("project trust requires a Git checkout")?;
        Self::at_root(&root)
    }

    pub fn at_root(root: &Path) -> Result<Self, String> {
        let directory = DirectoryIdentity::capture(root)?;
        let operator_home = DirectoryIdentity::capture(
            &home::home_dir().ok_or("operator home identity is unavailable")?,
        )?;
        Ok(Self {
            canonical_root: directory.canonical_path,
            device: directory.device,
            inode: directory.inode,
            created_seconds: directory.created_seconds,
            created_nanos: directory.created_nanos,
            operator_home,
        })
    }

    pub fn is_current(&self) -> bool {
        Self::at_root(&self.canonical_root).as_ref() == Ok(self)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum GrantScope {
    User,
    Project { project: ProjectIdentity },
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TrustGrant {
    pub id: String,
    pub pattern: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rule_id: Option<String>,
    pub scope: GrantScope,
    pub created_at: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub revoked_at: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GrantState {
    Recorded,
    Effective,
    Overridden,
    Expired,
    Revoked,
    Invalid,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct GrantStatus {
    pub state: GrantState,
    /// Fixed protocol reason; contains no pattern, path, or policy content.
    pub reason: &'static str,
}

impl TrustGrant {
    pub fn validate(&self) -> Result<(), &'static str> {
        if uuid::Uuid::parse_str(&self.id).is_err() {
            return Err("invalid_grant_id");
        }
        if crate::policy::validate_trust_pattern(&self.pattern).is_err()
            || self
                .rule_id
                .as_ref()
                .is_some_and(|rule| crate::policy::validate_trust_pattern(rule).is_err())
        {
            return Err("invalid_pattern_or_rule");
        }
        if DateTime::parse_from_rfc3339(&self.created_at).is_err()
            || self
                .revoked_at
                .as_ref()
                .is_some_and(|value| DateTime::parse_from_rfc3339(value).is_err())
        {
            return Err("invalid_record_timestamp");
        }
        if let GrantScope::Project { project } = &self.scope {
            if !project.canonical_root.is_absolute()
                || project.inode == 0
                || project.created_nanos >= 1_000_000_000
                || !project.operator_home.canonical_path.is_absolute()
                || project.operator_home.inode == 0
                || project.operator_home.created_nanos >= 1_000_000_000
            {
                return Err("invalid_project_identity");
            }
        }
        Ok(())
    }

    pub fn status(
        &self,
        project: Option<&ProjectIdentity>,
        policy: Option<&crate::policy::Policy>,
        now: DateTime<Utc>,
    ) -> GrantStatus {
        let status = |state, reason| GrantStatus { state, reason };
        if let Err(reason) = self.validate() {
            return status(GrantState::Invalid, reason);
        }
        match expiry(self.expires_at.as_deref(), now) {
            Expiry::Invalid => return status(GrantState::Invalid, "invalid_expiry"),
            _ if self.revoked_at.is_some() => {
                return status(GrantState::Revoked, "operator_revoked");
            }
            Expiry::Expired => return status(GrantState::Expired, "deadline_reached"),
            _ => {}
        }
        if let GrantScope::Project { project: expected } = &self.scope {
            if project != Some(expected) {
                return status(GrantState::Recorded, "different_or_unavailable_project");
            }
        }
        if policy.is_some_and(|policy| policy.is_blocklisted(&self.pattern)) {
            return status(GrantState::Overridden, "target_matches_blocklist");
        }
        status(
            GrantState::Effective,
            "eligible_exception_other_blockers_may_remain",
        )
    }

    pub fn matches(&self, target: &str, rule: Option<&str>) -> bool {
        self.rule_id
            .as_deref()
            .is_none_or(|own| rule.is_some_and(|rule| own.eq_ignore_ascii_case(rule)))
            && crate::policy::allowlist_pattern_matches(&self.pattern, target)
    }
}

/// Raw records are retained during edits so a malformed, unknown-version, or
/// future record is never silently discarded by a typed round trip. A malformed
/// record is individually inactive; an invalid envelope makes the whole store
/// unavailable. Writers may replace only the selected, validated UUID record.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TrustGrantStore {
    pub schema_version: u32,
    pub grants: Vec<Value>,
}

impl Default for TrustGrantStore {
    fn default() -> Self {
        Self {
            schema_version: STORE_VERSION,
            grants: Vec::new(),
        }
    }
}

impl TrustGrantStore {
    pub fn parse(bytes: &[u8]) -> Result<Self, &'static str> {
        // Protected undo of a first publication retains an empty file rather
        // than deleting a path. Empty content grants no authority, just like an
        // absent store; every nonempty envelope remains strictly validated.
        if bytes.iter().all(u8::is_ascii_whitespace) {
            return Ok(Self::default());
        }
        let store: Self = serde_json::from_slice(bytes).map_err(|_| "invalid_trust_grant_store")?;
        if store.schema_version != STORE_VERSION {
            return Err("unsupported_trust_grant_version");
        }
        Ok(store)
    }

    pub fn duplicate_ids(&self) -> BTreeSet<String> {
        let mut seen = BTreeSet::new();
        self.grants
            .iter()
            .filter_map(|value| {
                let id = value.get("id")?.as_str()?;
                (!seen.insert(id.to_string())).then(|| id.to_string())
            })
            .collect()
    }

    pub fn decode(&self, index: usize) -> Result<TrustGrant, &'static str> {
        self.decode_with_duplicates(index, &self.duplicate_ids())
    }

    fn decode_with_duplicates(
        &self,
        index: usize,
        duplicates: &BTreeSet<String>,
    ) -> Result<TrustGrant, &'static str> {
        let value = self.grants.get(index).ok_or("grant_not_found")?;
        let grant: TrustGrant =
            serde_json::from_value(value.clone()).map_err(|_| "invalid_grant_record")?;
        grant.validate()?;
        if duplicates.contains(&grant.id) {
            return Err("duplicate_grant_id");
        }
        Ok(grant)
    }

    pub fn records(&self) -> Vec<Result<TrustGrant, &'static str>> {
        let duplicates = self.duplicate_ids();
        (0..self.grants.len())
            .map(|index| self.decode_with_duplicates(index, &duplicates))
            .collect()
    }

    pub fn find(&self, id: &str) -> Result<(usize, TrustGrant), &'static str> {
        uuid::Uuid::parse_str(id).map_err(|_| "invalid_grant_id")?;
        let index = self
            .grants
            .iter()
            .position(|value| value.get("id").and_then(Value::as_str) == Some(id))
            .ok_or("grant_not_found")?;
        self.decode(index).map(|grant| (index, grant))
    }

    pub fn replace(&mut self, index: usize, grant: &TrustGrant) -> Result<(), &'static str> {
        grant.validate()?;
        let selected = self.grants.get_mut(index).ok_or("grant_not_found")?;
        if selected.get("id").and_then(Value::as_str) != Some(&grant.id) {
            return Err("grant_identity_changed");
        }
        *selected = serde_json::to_value(grant).map_err(|_| "grant_serialization_failed")?;
        Ok(())
    }

    pub fn insert(&mut self, grant: &TrustGrant) -> Result<(), &'static str> {
        grant.validate()?;
        if self
            .grants
            .iter()
            .any(|value| value.get("id").and_then(Value::as_str) == Some(&grant.id))
        {
            return Err("duplicate_grant_id");
        }
        self.grants
            .push(serde_json::to_value(grant).map_err(|_| "grant_serialization_failed")?);
        Ok(())
    }

    pub fn applicable(
        &self,
        project: Option<&ProjectIdentity>,
        now: DateTime<Utc>,
    ) -> Vec<TrustGrant> {
        self.records()
            .into_iter()
            .filter_map(Result::ok)
            .filter(|grant| grant.status(project, None, now).state == GrantState::Effective)
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn grant() -> TrustGrant {
        TrustGrant {
            id: uuid::Uuid::new_v4().to_string(),
            pattern: "https://mirror.example/install.sh".into(),
            rule_id: Some("pipe_to_interpreter".into()),
            scope: GrantScope::User,
            created_at: "2026-01-01T00:00:00Z".into(),
            expires_at: None,
            revoked_at: None,
            reason: None,
        }
    }

    #[test]
    fn malformed_expiry_is_never_permanent_and_deadline_is_exclusive() {
        let now = DateTime::parse_from_rfc3339("2026-01-02T00:00:00Z")
            .unwrap()
            .with_timezone(&Utc);
        for value in [
            json!(1),
            json!(false),
            json!({}),
            json!("tomorrow"),
            json!(""),
        ] {
            assert_eq!(expiry_value(Some(&value), now), Expiry::Invalid);
        }
        assert_eq!(expiry_value(None, now), Expiry::Permanent);
        assert_eq!(expiry(Some("2026-01-02T00:00:00Z"), now), Expiry::Expired);
        assert!(expiry_from_ttl("9223372036854775807d", now).is_err());
        assert!(expiry_from_ttl("99999999999999h", now).is_err());
        assert!(expiry_from_ttl("0d", now).is_err());
    }

    #[test]
    fn empty_compensation_grants_nothing_without_accepting_malformed_envelopes() {
        for bytes in [b"".as_slice(), b" \n\t\r".as_slice()] {
            assert!(TrustGrantStore::parse(bytes).unwrap().grants.is_empty());
        }
        for bytes in [b"null".as_slice(), b"{}".as_slice(), b"{broken".as_slice()] {
            assert!(TrustGrantStore::parse(bytes).is_err());
        }
    }

    #[test]
    fn old_readers_cannot_globalize_new_project_grants_even_if_file_is_copied() {
        let _state = tirith_test_support::GlobalStateGuard::new().unwrap();
        let directory = tempfile::tempdir().unwrap();
        let mut grant = grant();
        grant.scope = GrantScope::Project {
            project: ProjectIdentity::at_root(directory.path()).unwrap(),
        };
        let mut store = TrustGrantStore::default();
        store.insert(&grant).unwrap();
        let bytes = serde_json::to_vec(&store).unwrap();
        // This is the 0.4.2 trust reader's exact envelope entry point.
        let old: Value = serde_json::from_slice(&bytes).unwrap();
        assert!(old.get("entries").and_then(Value::as_array).is_none());
        assert!(store.applicable(None, Utc::now()).is_empty());
    }

    #[test]
    fn expiry_update_replaces_one_stable_grant_and_revocation_stays_inactive() {
        let mut store = TrustGrantStore::default();
        let mut grant = grant();
        store.insert(&grant).unwrap();
        grant.expires_at = Some("2026-01-02T00:00:00Z".into());
        store.replace(0, &grant).unwrap();
        assert_eq!(store.grants.len(), 1);
        assert_eq!(
            store.find(&grant.id).unwrap().1.expires_at,
            grant.expires_at
        );
        assert_eq!(
            grant.status(None, None, Utc::now()).state,
            GrantState::Expired
        );
        grant.revoked_at = Some(Utc::now().to_rfc3339());
        assert_eq!(
            grant.status(None, None, Utc::now()).state,
            GrantState::Revoked
        );
    }

    #[test]
    fn invalid_records_and_duplicate_ids_do_not_suppress() {
        let mut store = TrustGrantStore::default();
        let grant = grant();
        store.insert(&grant).unwrap();
        store.grants.push(store.grants[0].clone());
        store.grants.push(json!({"pattern":"*"}));
        assert!(store.applicable(None, Utc::now()).is_empty());
        assert_eq!(store.find(&grant.id).unwrap_err(), "duplicate_grant_id");
    }

    #[test]
    fn project_identity_rejects_nested_siblings_worktrees_moved_and_replaced_roots() {
        let _state = tirith_test_support::GlobalStateGuard::new().unwrap();
        let base = tempfile::tempdir().unwrap();
        for name in ["project", "project/nested", "sibling", "linked"] {
            std::fs::create_dir_all(base.path().join(name)).unwrap();
            std::fs::write(base.path().join(name).join(".git"), "gitdir: ignored\n").unwrap();
        }
        let root = base.path().join("project");
        let expected = ProjectIdentity::capture(root.to_str()).unwrap();
        for name in ["project/nested", "sibling", "linked"] {
            assert_ne!(
                expected,
                ProjectIdentity::capture(base.path().join(name).to_str()).unwrap()
            );
        }
        #[cfg(unix)]
        {
            let alias = base.path().join("alias");
            std::os::unix::fs::symlink(&root, &alias).unwrap();
            assert_eq!(expected, ProjectIdentity::capture(alias.to_str()).unwrap());
        }
        std::fs::rename(&root, base.path().join("moved")).unwrap();
        assert!(!expected.is_current());
        std::fs::create_dir(&root).unwrap();
        assert!(!expected.is_current());
    }

    #[test]
    fn copied_configuration_and_recycled_inode_stamp_do_not_reuse_project_trust() {
        let mut state = tirith_test_support::GlobalStateGuard::new().unwrap();
        let root = tempfile::tempdir().unwrap();
        let expected = ProjectIdentity::at_root(root.path()).unwrap();
        let mut recycled = expected.clone();
        recycled.created_seconds = recycled.created_seconds.saturating_sub(1);
        assert!(!recycled.is_current());
        let other_home = tempfile::tempdir().unwrap();
        state.set_env("HOME", other_home.path());
        #[cfg(windows)]
        state.set_env("USERPROFILE", other_home.path());
        assert_ne!(expected, ProjectIdentity::at_root(root.path()).unwrap());
        assert!(!expected.is_current());
    }

    #[test]
    fn removal_exposes_broader_applicable_grant_and_blocklist_overrides_target() {
        let mut narrow = grant();
        let mut broad = grant();
        broad.pattern = "mirror.example".into();
        broad.rule_id = None;
        narrow.revoked_at = Some(Utc::now().to_rfc3339());
        assert_eq!(
            narrow.status(None, None, Utc::now()).state,
            GrantState::Revoked
        );
        assert!(broad.matches(&narrow.pattern, narrow.rule_id.as_deref()));
        let mut policy = crate::policy::Policy::default();
        policy.blocklist.push("mirror.example".into());
        assert_eq!(
            broad.status(None, Some(&policy), Utc::now()).state,
            GrantState::Overridden
        );
    }
}
