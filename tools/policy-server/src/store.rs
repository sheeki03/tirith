//! Transactional single-policy authority. Stored review commitments are publisher
//! claims; authenticated client reports are never live enforcement attestations.
use crate::private_fs::{self, Directory};
use rand_core::{OsRng, RngCore};
use rusqlite::{
    params, Connection, OpenFlags, OptionalExtension, Transaction, TransactionBehavior,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    fs::File,
    ops::Deref,
    path::Path,
    sync::{Arc, Mutex, OnceLock, Weak},
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tirith_core::policy_team::*;

type Result<T> = std::result::Result<T, ErrorCode>;
const DB: &str = "authority.sqlite3";
const MAX_CREDENTIALS: u64 = 2048;
const MAX_OPERATIONS: u64 = 4096;
const MAX_REVISIONS: u64 = 128;
pub const MAX_CREDENTIAL_AGE_MS: u64 = 90 * 24 * 60 * 60 * 1000;
const SCHEMA: &str = "
CREATE TABLE meta (singleton INTEGER PRIMARY KEY CHECK(singleton=1), authority TEXT NOT NULL, policy TEXT NOT NULL, current TEXT NOT NULL REFERENCES revisions(id), roster TEXT NOT NULL);
CREATE TABLE revisions (id TEXT PRIMARY KEY, yaml TEXT NOT NULL, created INTEGER NOT NULL);
CREATE TABLE clients (id TEXT PRIMARY KEY, active INTEGER NOT NULL CHECK(active IN (0,1)));
CREATE TABLE credentials (id TEXT PRIMARY KEY, token_hash BLOB NOT NULL UNIQUE, actor TEXT NOT NULL, role TEXT NOT NULL, client TEXT REFERENCES clients(id), expires INTEGER NOT NULL, revoked INTEGER NOT NULL CHECK(revoked IN (0,1)));
CREATE TABLE operations (id TEXT PRIMARY KEY, actor TEXT NOT NULL, intent TEXT NOT NULL, record TEXT NOT NULL);
CREATE TABLE reports (client TEXT PRIMARY KEY REFERENCES clients(id), id TEXT NOT NULL UNIQUE, sequence INTEGER NOT NULL CHECK(sequence>0), actor TEXT NOT NULL, intent TEXT NOT NULL, observed INTEGER NOT NULL, record TEXT NOT NULL);
PRAGMA user_version=1;";

pub fn unix_ms() -> Result<u64> {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| ErrorCode::StorageUnavailable)?
        .as_millis();
    u64::try_from(now)
        .ok()
        .filter(|value| *value > 0 && *value <= i64::MAX as u64)
        .ok_or(ErrorCode::StorageUnavailable)
}
fn sql<T>(result: rusqlite::Result<T>) -> Result<T> {
    result.map_err(|_| ErrorCode::StorageUnavailable)
}
fn fs<T>(result: private_fs::FsResult<T>) -> Result<T> {
    result.map_err(|_| ErrorCode::StorageUnavailable)
}
fn json<T: Serialize>(value: &T) -> Result<String> {
    serde_json::to_string(value).map_err(|_| ErrorCode::StorageUnavailable)
}
fn decode<T: serde::de::DeserializeOwned>(value: &str) -> Result<T> {
    serde_json::from_str(value).map_err(|_| ErrorCode::StorageUnavailable)
}
fn id(value: String) -> Result<Id> {
    Id::parse(&value).map_err(|_| ErrorCode::StorageUnavailable)
}
fn bounded_document(document: &PolicyDocument) -> Result<()> {
    if json(document)?.len() > MAX_RESPONSE_BYTES {
        return Err(ErrorCode::InvalidPolicy);
    }
    Ok(())
}
fn token_hash(token: &str) -> Result<Vec<u8>> {
    if token.len() != 64
        || !token
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err(ErrorCode::Unauthorized);
    }
    Ok(Sha256::digest(token.as_bytes()).to_vec())
}
fn intent<T: Serialize>(domain: &'static str, value: &T) -> Result<String> {
    Ok(PrivateCommitment::of(domain, json(value)?.as_bytes())
        .as_str()
        .to_owned())
}
#[derive(Clone)]
pub struct Identity {
    pub authority_id: Id,
    pub policy_id: Id,
    pub current_revision: Id,
    pub roster_revision: Id,
}
#[derive(Serialize)]
pub struct CredentialInfo {
    pub credential_id: Id,
    pub principal_id: Id,
    pub role: Role,
    pub client_id: Option<Id>,
    pub expires_unix_ms: u64,
    pub revoked: bool,
}
type CredentialRow = (String, String, Option<String>, u64, bool);
type ReportRow = (String, u64, String, u64, String);
#[derive(Clone)]
struct Auth {
    actor: Id,
    role: Role,
    client: Option<Id>,
    expires: u64,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Operation {
    status: OperationStatus,
    previous_revision: Option<Id>,
}

// Serialize witness descriptor admission and final teardown across every Store
// in this process. SQLite's own in-process locks cannot protect a descriptor
// opened/closed outside its VFS.
type Registry = BTreeMap<private_fs::FileIdentity, Weak<StoreState>>;
fn registry() -> &'static Mutex<Registry> {
    static REGISTRY: OnceLock<Mutex<Registry>> = OnceLock::new();
    REGISTRY.get_or_init(|| Mutex::new(BTreeMap::new()))
}

struct StoreState {
    // Field order matters: close SQLite before closing the native witness.
    connection: Mutex<Connection>,
    database: File,
    directory: Directory,
    identity: private_fs::FileIdentity,
}

#[derive(Clone)]
struct StoreHandle {
    state: Option<Arc<StoreState>>,
}
impl Deref for StoreHandle {
    type Target = StoreState;
    fn deref(&self) -> &Self::Target {
        self.state.as_deref().expect("live store handle")
    }
}
impl Drop for StoreHandle {
    fn drop(&mut self) {
        // An upgraded Weak must never race final witness closure. Holding this
        // same registry lock during Arc destruction closes that last-drop gap.
        let mut entries = registry().lock().unwrap_or_else(|error| error.into_inner());
        if let Some(state) = self.state.take() {
            let identity = state.identity;
            drop(state);
            if entries
                .get(&identity)
                .is_some_and(|entry| entry.strong_count() == 0)
            {
                entries.remove(&identity);
            }
        }
    }
}

pub struct Store {
    inner: StoreHandle,
    clock: fn() -> Result<u64>,
    deadline: Option<std::time::Instant>,
}
impl Store {
    fn from_state(state: Arc<StoreState>) -> Self {
        Self {
            inner: StoreHandle { state: Some(state) },
            clock: unix_ms,
            deadline: None,
        }
    }
    pub fn initialize(path: &Path, yaml: &str) -> Result<Self> {
        validate_policy(yaml)?;
        let now = unix_ms()?;
        let authority = Id::new();
        let policy = Id::new();
        let revision = Id::new();
        bounded_document(&PolicyDocument {
            schema_version: SCHEMA_VERSION,
            authority_id: authority.clone(),
            policy_id: policy.clone(),
            revision: revision.clone(),
            created_unix_ms: now,
            policy_semantics_version: POLICY_SEMANTICS_VERSION,
            yaml: yaml.into(),
        })?;
        let mut entries = registry()
            .lock()
            .map_err(|_| ErrorCode::StorageUnavailable)?;
        let directory = fs(Directory::create(path))?;
        let database = fs(directory.create_file(DB))?;
        let identity = fs(directory.file_identity(DB))?;
        let mut connection = Self::connect(&directory, true)?;
        let tx = sql(connection.transaction_with_behavior(TransactionBehavior::Immediate))?;
        sql(tx.execute_batch(SCHEMA))?;
        sql(tx.execute(
            "INSERT INTO revisions VALUES (?1,?2,?3)",
            params![revision.as_str(), yaml, now],
        ))?;
        sql(tx.execute(
            "INSERT INTO meta VALUES (1,?1,?2,?3,?4)",
            params![
                authority.as_str(),
                policy.as_str(),
                revision.as_str(),
                Id::new().as_str()
            ],
        ))?;
        sql(tx.commit())?;
        fs(directory.file_still_matches(DB, &database))?;
        let state = Arc::new(StoreState {
            connection: Mutex::new(connection),
            database,
            directory,
            identity,
        });
        entries.insert(identity, Arc::downgrade(&state));
        drop(entries);
        Ok(Self::from_state(state))
    }
    pub fn open(path: &Path) -> Result<Self> {
        let directory = fs(Directory::open(path))?;
        let mut entries = registry()
            .lock()
            .map_err(|_| ErrorCode::StorageUnavailable)?;
        // No DB descriptor is opened until the process registry is consulted.
        let identity = fs(directory.file_identity(DB))?;
        if let Some(state) = entries.get(&identity).and_then(Weak::upgrade) {
            // All fallible work involving this Arc happens after releasing the
            // registry lock, so error teardown cannot recursively lock it.
            drop(entries);
            let result = Self::from_state(state);
            fs(directory.file_still_matches(DB, &result.inner.database))?;
            result.check_open_contract()?;
            return Ok(result);
        }
        let database = fs(directory.open_file(DB, true))?;
        if fs(directory.file_identity(DB))? != identity {
            return Err(ErrorCode::StorageUnavailable);
        }
        if database
            .metadata()
            .map_err(|_| ErrorCode::StorageUnavailable)?
            .len()
            > 192 * 1024 * 1024
        {
            return Err(ErrorCode::CapacityExceeded);
        }
        for name in [
            "authority.sqlite3-journal",
            "authority.sqlite3-wal",
            "authority.sqlite3-shm",
        ] {
            fs(directory.inspect_optional_file(name))?;
        }
        let connection = Self::connect(&directory, false)?;
        fs(directory.file_still_matches(DB, &database))?;
        let state = Arc::new(StoreState {
            connection: Mutex::new(connection),
            database,
            directory,
            identity,
        });
        entries.insert(identity, Arc::downgrade(&state));
        drop(entries);
        let result = Self::from_state(state);
        result.check_open_contract()?;
        Ok(result)
    }
    fn check_open_contract(&self) -> Result<()> {
        self.transaction(|tx, _| {
            let version: u32 = sql(tx.pragma_query_value(None, "user_version", |row| row.get(0)))?;
            if version != SCHEMA_VERSION {
                return Err(ErrorCode::UnsupportedContract);
            }
            Self::identity_at(tx).map(|_| ())
        })
    }
    fn connect(directory: &Directory, initializing: bool) -> Result<Connection> {
        let connection = sql(Connection::open_with_flags(
            directory.path().join(DB),
            OpenFlags::SQLITE_OPEN_READ_WRITE
                | OpenFlags::SQLITE_OPEN_NO_MUTEX
                | OpenFlags::SQLITE_OPEN_NOFOLLOW,
        ))?;
        sql(connection.busy_timeout(Duration::from_millis(500)))?;
        let version: u32 =
            sql(connection.pragma_query_value(None, "user_version", |row| row.get(0)))?;
        if version != if initializing { 0 } else { SCHEMA_VERSION } {
            return Err(ErrorCode::UnsupportedContract);
        }
        if !initializing {
            let mode: String =
                sql(connection.pragma_query_value(None, "journal_mode", |row| row.get(0)))?;
            if mode != "delete" {
                return Err(ErrorCode::UnsupportedContract);
            }
        }
        sql(connection.execute_batch("PRAGMA foreign_keys=ON; PRAGMA synchronous=FULL; PRAGMA journal_mode=DELETE; PRAGMA temp_store=MEMORY; PRAGMA max_page_count=49152;"))?;
        let mode: String =
            sql(connection.pragma_query_value(None, "journal_mode", |row| row.get(0)))?;
        let synchronous: u32 =
            sql(connection.pragma_query_value(None, "synchronous", |row| row.get(0)))?;
        let foreign_keys: bool =
            sql(connection.pragma_query_value(None, "foreign_keys", |row| row.get(0)))?;
        if mode != "delete" || synchronous != 2 || !foreign_keys {
            return Err(ErrorCode::UnsupportedContract);
        }
        let page_size: u64 = sql(connection.pragma_query_value(None, "page_size", |r| r.get(0)))?;
        let pages: u64 = sql(connection.pragma_query_value(None, "page_count", |r| r.get(0)))?;
        if page_size != 4096 || pages > 49152 {
            return Err(ErrorCode::CapacityExceeded);
        }
        connection.set_limit(
            rusqlite::limits::Limit::SQLITE_LIMIT_LENGTH,
            (MAX_REQUEST_BYTES * 2) as i32,
        );
        connection.set_limit(rusqlite::limits::Limit::SQLITE_LIMIT_SQL_LENGTH, 64 * 1024);
        Ok(connection)
    }
    fn check_files(&self) -> Result<()> {
        fs(self
            .inner
            .directory
            .file_still_matches(DB, &self.inner.database))?;
        for name in [
            "authority.sqlite3-journal",
            "authority.sqlite3-wal",
            "authority.sqlite3-shm",
        ] {
            fs(self.inner.directory.inspect_optional_file(name))?;
        }
        Ok(())
    }
    /// Request-local execution budget shares the retained store, never authority.
    pub fn with_deadline(&self, deadline: std::time::Instant) -> Self {
        Self {
            inner: self.inner.clone(),
            clock: self.clock,
            deadline: Some(self.deadline.map_or(deadline, |old| old.min(deadline))),
        }
    }
    fn transaction<T>(&self, run: impl FnOnce(&Transaction<'_>, u64) -> Result<T>) -> Result<T> {
        let deadline = self
            .deadline
            .unwrap_or_else(|| std::time::Instant::now() + Duration::from_secs(10));
        let check = || {
            if std::time::Instant::now() >= deadline {
                Err(ErrorCode::StorageUnavailable)
            } else {
                Ok(())
            }
        };
        check()?;
        self.check_files()?;
        let mut connection = loop {
            check()?;
            match self.inner.connection.try_lock() {
                Ok(connection) => break connection,
                Err(std::sync::TryLockError::Poisoned(_)) => {
                    return Err(ErrorCode::StorageUnavailable)
                }
                Err(std::sync::TryLockError::WouldBlock) => {
                    std::thread::sleep(Duration::from_millis(1))
                }
            }
        };
        check()?;
        let tx = sql(connection.transaction_with_behavior(TransactionBehavior::Immediate))?;
        check()?;
        let result = run(&tx, (self.clock)()?)?;
        self.check_files()?;
        check()?;
        // A COMMIT error or a response lost after this point is unknown. Never
        // tell a caller that timeout proves the publication did not happen.
        sql(tx.commit())?;
        self.check_files()?;
        Ok(result)
    }
    fn mutate<T>(&self, run: impl FnOnce(&Transaction<'_>, u64) -> Result<T>) -> Result<T> {
        self.transaction(run).map_err(|error| {
            if error == ErrorCode::StorageUnavailable {
                ErrorCode::OutcomeUnknown
            } else {
                error
            }
        })
    }
    fn identity_at(tx: &Transaction<'_>) -> Result<Identity> {
        let values: (String, String, String, String) = sql(tx.query_row(
            "SELECT authority,policy,current,roster FROM meta WHERE singleton=1",
            [],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
        ))?;
        Ok(Identity {
            authority_id: id(values.0)?,
            policy_id: id(values.1)?,
            current_revision: id(values.2)?,
            roster_revision: id(values.3)?,
        })
    }
    pub fn identity(&self) -> Result<Identity> {
        self.transaction(|tx, _| Self::identity_at(tx))
    }
    fn scope(identity: &Identity, authority: &Id, policy: &Id) -> Result<()> {
        if &identity.authority_id != authority || &identity.policy_id != policy {
            Err(ErrorCode::AuthorityChanged)
        } else {
            Ok(())
        }
    }
    fn auth(tx: &Transaction<'_>, token: &str, now: u64) -> Result<Auth> {
        let hash = token_hash(token)?;
        let row: Option<CredentialRow> = sql(tx
            .query_row(
                "SELECT actor,role,client,expires,revoked FROM credentials WHERE token_hash=?1",
                [hash],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?)),
            )
            .optional())?;
        let (actor, role, client, expires, revoked) = row.ok_or(ErrorCode::Unauthorized)?;
        if revoked || expires <= now {
            return Err(ErrorCode::Unauthorized);
        }
        let auth = Auth {
            actor: id(actor)?,
            role: decode(&role)?,
            client: client.map(id).transpose()?,
            expires,
        };
        if auth.role == Role::Client {
            let client = auth.client.as_ref().ok_or(ErrorCode::Unauthorized)?;
            let active: Option<bool> = sql(tx
                .query_row(
                    "SELECT active FROM clients WHERE id=?1",
                    [client.as_str()],
                    |r| r.get(0),
                )
                .optional())?;
            if active != Some(true) {
                return Err(ErrorCode::Unauthorized);
            }
        } else if auth.client.is_some() {
            return Err(ErrorCode::Unauthorized);
        }
        Ok(auth)
    }
    fn role(auth: &Auth, allowed: &[Role]) -> Result<()> {
        if allowed.contains(&auth.role) {
            Ok(())
        } else {
            Err(ErrorCode::Forbidden)
        }
    }
    pub fn authorize(&self, token: &str, allowed: &[Role]) -> Result<()> {
        self.transaction(|tx, now| Self::role(&Self::auth(tx, token, now)?, allowed))
    }
    fn capacity(tx: &Transaction<'_>, table: &str, cap: u64) -> Result<()> {
        // All table names are private compile-time constants, never request data.
        let count: u64 =
            sql(tx.query_row(&format!("SELECT count(*) FROM {table}"), [], |r| r.get(0)))?;
        if count >= cap {
            Err(ErrorCode::CapacityExceeded)
        } else {
            Ok(())
        }
    }
    pub fn capabilities(&self, token: &str) -> Result<Capabilities> {
        self.transaction(|tx, now| {
            let auth = Self::auth(tx, token, now)?;
            let identity = Self::identity_at(tx)?;
            let sequence = if let Some(client) = &auth.client {
                Some(
                    sql(tx
                        .query_row(
                            "SELECT sequence FROM reports WHERE client=?1",
                            [client.as_str()],
                            |r| r.get::<_, u64>(0),
                        )
                        .optional())?
                    .unwrap_or(0),
                )
            } else {
                None
            };
            Ok(Capabilities {
                client_id: auth.client.clone(),
                client_report_sequence: sequence,
                schema_version: SCHEMA_VERSION,
                contract: CONTRACT.into(),
                authority_id: identity.authority_id,
                policy_id: identity.policy_id,
                role: auth.role,
                credential_expires_unix_ms: auth.expires,
                policy_semantics_version: POLICY_SEMANTICS_VERSION,
                limits: Limits::default(),
            })
        })
    }
    fn document(
        tx: &Transaction<'_>,
        identity: &Identity,
        revision: &Id,
    ) -> Result<PolicyDocument> {
        let row: Option<(String, u64)> = sql(tx
            .query_row(
                "SELECT yaml,created FROM revisions WHERE id=?1",
                [revision.as_str()],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional())?;
        let (yaml, created) = row.ok_or(ErrorCode::RevisionUnknown)?;
        Ok(PolicyDocument {
            schema_version: SCHEMA_VERSION,
            authority_id: identity.authority_id.clone(),
            policy_id: identity.policy_id.clone(),
            revision: revision.clone(),
            created_unix_ms: created,
            policy_semantics_version: POLICY_SEMANTICS_VERSION,
            yaml,
        })
    }
    pub fn current(&self, token: &str) -> Result<PolicyDocument> {
        self.transaction(|tx, now| {
            Self::auth(tx, token, now)?;
            let identity = Self::identity_at(tx)?;
            Self::document(tx, &identity, &identity.current_revision)
        })
    }
    fn operation(
        tx: &Transaction<'_>,
        operation_id: &Id,
    ) -> Result<Option<(Id, String, Operation)>> {
        let row: Option<(String, String, String)> = sql(tx
            .query_row(
                "SELECT actor,intent,record FROM operations WHERE id=?1",
                [operation_id.as_str()],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .optional())?;
        row.map(|(actor, commitment, record)| Ok((id(actor)?, commitment, decode(&record)?)))
            .transpose()
    }
    fn project(mut operation: Operation, identity: &Identity, now: u64) -> OperationStatus {
        operation.status.current_revision = identity.current_revision.clone();
        operation.status.rollback_eligible = operation.status.kind == OperationKind::Publication
            && operation.status.outcome == OperationOutcome::Committed
            && operation.status.published_revision.as_ref() == Some(&identity.current_revision)
            && operation
                .status
                .rollback_until_unix_ms
                .is_some_and(|until| now < until);
        operation.status
    }
    fn replay(
        tx: &Transaction<'_>,
        operation_id: &Id,
        auth: &Auth,
        commitment: &str,
        identity: &Identity,
        now: u64,
    ) -> Result<Option<OperationStatus>> {
        if let Some((actor, previous, operation)) = Self::operation(tx, operation_id)? {
            if actor != auth.actor || previous != commitment {
                return Err(ErrorCode::OperationConflict);
            }
            return Ok(Some(Self::project(operation, identity, now)));
        }
        Ok(None)
    }
    fn save_operation(
        tx: &Transaction<'_>,
        auth: &Auth,
        commitment: &str,
        operation: &Operation,
    ) -> Result<()> {
        sql(tx.execute(
            "INSERT INTO operations VALUES (?1,?2,?3,?4)",
            params![
                operation.status.operation_id.as_str(),
                auth.actor.as_str(),
                commitment,
                json(operation)?
            ],
        ))?;
        Ok(())
    }
    fn publish_revision(
        tx: &Transaction<'_>,
        identity: &Identity,
        yaml: &str,
        now: u64,
    ) -> Result<Id> {
        Self::capacity(tx, "revisions", MAX_REVISIONS)?;
        let revision = Id::new();
        bounded_document(&PolicyDocument {
            schema_version: SCHEMA_VERSION,
            authority_id: identity.authority_id.clone(),
            policy_id: identity.policy_id.clone(),
            revision: revision.clone(),
            created_unix_ms: now,
            policy_semantics_version: POLICY_SEMANTICS_VERSION,
            yaml: yaml.into(),
        })?;
        sql(tx.execute(
            "INSERT INTO revisions VALUES (?1,?2,?3)",
            params![revision.as_str(), yaml, now],
        ))?;
        if sql(tx.execute(
            "UPDATE meta SET current=?1 WHERE singleton=1 AND current=?2",
            params![revision.as_str(), identity.current_revision.as_str()],
        ))? != 1
        {
            return Err(ErrorCode::RevisionConflict);
        }
        Ok(revision)
    }
    pub fn publish(&self, token: &str, request: PublicationRequest) -> Result<OperationStatus> {
        request.validate_structure()?;
        let commitment = intent("tirith-team-publication-v1", &request)?;
        self.mutate(|tx, now| {
            let auth = Self::auth(tx, token, now)?;
            Self::role(&auth, &[Role::Publisher])?;
            let mut identity = Self::identity_at(tx)?;
            Self::scope(&identity, &request.authority_id, &request.policy_id)?;
            if let Some(previous) = Self::replay(
                tx,
                &request.operation_id,
                &auth,
                &commitment,
                &identity,
                now,
            )? {
                return Ok(previous);
            }
            // Invalid candidate policy is malformed input: no durable operation.
            validate_policy(&request.yaml)?;
            let now = (self.clock)()?;
            Self::auth(tx, token, now)?;
            Self::capacity(tx, "operations", MAX_OPERATIONS)?;
            let failure = validate_review_time(request.reviewed_unix_ms, now)
                .err()
                .or_else(|| {
                    (request.expected_revision != identity.current_revision)
                        .then_some(ErrorCode::RevisionConflict)
                });
            let previous_revision = identity.current_revision.clone();
            let published = if failure.is_none() {
                Some(Self::publish_revision(tx, &identity, &request.yaml, now)?)
            } else {
                None
            };
            if let Some(revision) = &published {
                identity.current_revision = revision.clone();
            }
            let operation = Operation {
                status: OperationStatus {
                    schema_version: SCHEMA_VERSION,
                    authority_id: identity.authority_id.clone(),
                    policy_id: identity.policy_id.clone(),
                    operation_id: request.operation_id,
                    actor_id: auth.actor.clone(),
                    kind: OperationKind::Publication,
                    outcome: if failure.is_none() {
                        OperationOutcome::Committed
                    } else {
                        OperationOutcome::Rejected
                    },
                    failure_code: failure,
                    publication_id: None,
                    expected_revision: request.expected_revision,
                    published_revision: published,
                    current_revision: identity.current_revision.clone(),
                    created_unix_ms: now,
                    rollback_until_unix_ms: if failure.is_none() {
                        Some(now + ROLLBACK_WINDOW_MS)
                    } else {
                        None
                    },
                    rollback_eligible: false,
                },
                previous_revision: if failure.is_none() {
                    Some(previous_revision)
                } else {
                    None
                },
            };
            Self::save_operation(tx, &auth, &commitment, &operation)?;
            Ok(Self::project(operation, &identity, now))
        })
    }
    pub fn operation_status(&self, token: &str, operation_id: &Id) -> Result<OperationStatus> {
        self.transaction(|tx, now| {
            Self::role(
                &Self::auth(tx, token, now)?,
                &[Role::Publisher, Role::Observer],
            )?;
            let identity = Self::identity_at(tx)?;
            let (_, _, operation) =
                Self::operation(tx, operation_id)?.ok_or(ErrorCode::OperationNotFound)?;
            Ok(Self::project(operation, &identity, now))
        })
    }
    /// Read-only exact-intent reconciliation. UUID lookup alone cannot prove
    /// that another publisher submitted the candidate reviewed by this client.
    pub fn reconcile(&self, token: &str, request: OperationRequest) -> Result<OperationStatus> {
        let (id, authority, policy, commitment) = match &request {
            OperationRequest::Publication(r) => {
                r.validate_structure()?;
                (
                    &r.operation_id,
                    &r.authority_id,
                    &r.policy_id,
                    intent("tirith-team-publication-v1", r)?,
                )
            }
            OperationRequest::Rollback(r) => {
                schema(r.schema_version)?;
                (
                    &r.operation_id,
                    &r.authority_id,
                    &r.policy_id,
                    intent("tirith-team-rollback-v1", r)?,
                )
            }
        };
        self.transaction(|tx, now| {
            let auth = Self::auth(tx, token, now)?;
            Self::role(&auth, &[Role::Publisher])?;
            let identity = Self::identity_at(tx)?;
            Self::scope(&identity, authority, policy)?;
            Self::replay(tx, id, &auth, &commitment, &identity, now)?
                .ok_or(ErrorCode::OperationNotFound)
        })
    }
    pub fn rollback(&self, token: &str, request: RollbackRequest) -> Result<OperationStatus> {
        schema(request.schema_version)?;
        let commitment = intent("tirith-team-rollback-v1", &request)?;
        self.mutate(|tx, now| {
            let auth = Self::auth(tx, token, now)?;
            Self::role(&auth, &[Role::Publisher])?;
            let mut identity = Self::identity_at(tx)?;
            Self::scope(&identity, &request.authority_id, &request.policy_id)?;
            if let Some(previous) = Self::replay(
                tx,
                &request.operation_id,
                &auth,
                &commitment,
                &identity,
                now,
            )? {
                return Ok(previous);
            }
            Self::capacity(tx, "operations", MAX_OPERATIONS)?;
            let original =
                Self::operation(tx, &request.publication_id)?.map(|(_, _, operation)| operation);
            let failure = if request.expected_revision != identity.current_revision {
                Some(ErrorCode::RevisionConflict)
            } else {
                match &original {
                    Some(op)
                        if op.status.kind == OperationKind::Publication
                            && op.status.outcome == OperationOutcome::Committed
                            && op.previous_revision.is_some() =>
                    {
                        if op.status.published_revision.as_ref() != Some(&identity.current_revision)
                        {
                            Some(ErrorCode::RevisionConflict)
                        } else if op
                            .status
                            .rollback_until_unix_ms
                            .is_none_or(|until| now >= until)
                        {
                            Some(ErrorCode::RollbackExpired)
                        } else {
                            None
                        }
                    }
                    _ => Some(ErrorCode::RollbackUnavailable),
                }
            };
            let published = if failure.is_none() {
                let previous = original
                    .as_ref()
                    .and_then(|op| op.previous_revision.as_ref())
                    .ok_or(ErrorCode::StorageUnavailable)?;
                let document = Self::document(tx, &identity, previous)?;
                Some(Self::publish_revision(tx, &identity, &document.yaml, now)?)
            } else {
                None
            };
            if let Some(revision) = &published {
                identity.current_revision = revision.clone();
            }
            let operation = Operation {
                status: OperationStatus {
                    schema_version: SCHEMA_VERSION,
                    authority_id: identity.authority_id.clone(),
                    policy_id: identity.policy_id.clone(),
                    operation_id: request.operation_id,
                    actor_id: auth.actor.clone(),
                    kind: OperationKind::Rollback,
                    outcome: if failure.is_none() {
                        OperationOutcome::Committed
                    } else {
                        OperationOutcome::Rejected
                    },
                    failure_code: failure,
                    publication_id: Some(request.publication_id),
                    expected_revision: request.expected_revision,
                    published_revision: published,
                    current_revision: identity.current_revision.clone(),
                    created_unix_ms: now,
                    rollback_until_unix_ms: None,
                    rollback_eligible: false,
                },
                previous_revision: None,
            };
            Self::save_operation(tx, &auth, &commitment, &operation)?;
            Ok(Self::project(operation, &identity, now))
        })
    }
    pub fn report(&self, token: &str, request: ClientReportRequest) -> Result<ReportReceipt> {
        request.validate_structure()?;
        let commitment = intent("tirith-team-report-v1", &request)?;
        self.mutate(|tx,now| {
            let auth=Self::auth(tx,token,now)?;Self::role(&auth,&[Role::Client])?;
            let client=auth.client.as_ref().ok_or(ErrorCode::Unauthorized)?;
            let identity=Self::identity_at(tx)?;Self::scope(&identity,&request.authority_id,&request.policy_id)?;
            if report_id(&identity.authority_id,client,request.report_sequence)?!=request.report_id {return Err(ErrorCode::InvalidRequest);}
            let previous:Option<ReportRow>=sql(tx.query_row("SELECT actor,sequence,intent,observed,record FROM reports WHERE client=?1",[client.as_str()],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?,r.get(4)?))).optional())?;
            let highwater=previous.as_ref().map_or(0,|row|row.1);
            let received=if request.report_sequence==highwater {
                let (actor,_,old_intent,_,record)=previous.as_ref().ok_or(ErrorCode::ReportOutOfOrder)?;
                if actor!=auth.actor.as_str() || old_intent!=&commitment {return Err(ErrorCode::OperationConflict);}
                decode::<RecordedClientReport>(record)?.received_unix_ms
            }else {
                if highwater.checked_add(1)!=Some(request.report_sequence){return Err(ErrorCode::ReportOutOfOrder);}
                request.validate_time(now)?;
                let exists:bool=sql(tx.query_row("SELECT EXISTS(SELECT 1 FROM revisions WHERE id=?1)",[request.applied_revision.as_str()],|r|r.get(0)))?;
                if !exists{return Err(ErrorCode::RevisionUnknown);}
                if previous.as_ref().is_some_and(|row|request.observed_unix_ms<=row.3){return Err(ErrorCode::ReportOutOfOrder);}
                let record=RecordedClientReport {report_sequence:request.report_sequence,report_id:request.report_id.clone(),applied_revision:request.applied_revision,observed_unix_ms:request.observed_unix_ms,received_unix_ms:now,client_version:request.client_version,state:request.state,failure_reason:request.failure_reason};
                sql(tx.execute("INSERT INTO reports VALUES (?1,?2,?3,?4,?5,?6,?7) ON CONFLICT(client) DO UPDATE SET id=excluded.id,sequence=excluded.sequence,actor=excluded.actor,intent=excluded.intent,observed=excluded.observed,record=excluded.record",params![client.as_str(),request.report_id.as_str(),request.report_sequence,auth.actor.as_str(),commitment,record.observed_unix_ms,json(&record)?]))?;now
            };
            Ok(ReportReceipt {report_sequence:request.report_sequence,schema_version:SCHEMA_VERSION,authority_id:identity.authority_id,policy_id:identity.policy_id,report_id:request.report_id,client_id:client.clone(),received_unix_ms:received})
        })
    }
    /// Recover an exact latest receipt without submitting an old Applied
    /// observation again. Superseded reports are outside bounded retention.
    pub fn reconcile_report(
        &self,
        token: &str,
        request: ClientReportRequest,
    ) -> Result<ReportReceipt> {
        request.validate_structure()?;
        let commitment = intent("tirith-team-report-v1", &request)?;
        self.transaction(|tx, now| {
            let auth = Self::auth(tx, token, now)?;
            Self::role(&auth, &[Role::Client])?;
            let client = auth.client.as_ref().ok_or(ErrorCode::Unauthorized)?;
            let identity = Self::identity_at(tx)?;
            Self::scope(&identity, &request.authority_id, &request.policy_id)?;
            if report_id(&identity.authority_id, client, request.report_sequence)?
                != request.report_id
            {
                return Err(ErrorCode::InvalidRequest);
            }
            let previous: Option<ReportRow> = sql(tx
                .query_row(
                    "SELECT actor,sequence,intent,observed,record FROM reports WHERE client=?1",
                    [client.as_str()],
                    |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?)),
                )
                .optional())?;
            let (actor, sequence, previous_intent, _, record) =
                previous.ok_or(ErrorCode::OperationNotFound)?;
            if sequence != request.report_sequence {
                return Err(ErrorCode::OperationNotFound);
            }
            if actor != auth.actor.as_str() || previous_intent != commitment {
                return Err(ErrorCode::OperationConflict);
            }
            let record: RecordedClientReport = decode(&record)?;
            Ok(ReportReceipt {
                schema_version: SCHEMA_VERSION,
                authority_id: identity.authority_id,
                policy_id: identity.policy_id,
                client_id: client.clone(),
                report_id: request.report_id,
                report_sequence: request.report_sequence,
                received_unix_ms: record.received_unix_ms,
            })
        })
    }
    pub fn status(&self, token: &str) -> Result<FleetStatus> {
        self.transaction(|tx, now| {
            Self::role(
                &Self::auth(tx, token, now)?,
                &[Role::Publisher, Role::Observer],
            )?;
            let identity = Self::identity_at(tx)?;
            let mut statement =
                sql(tx.prepare("SELECT id FROM clients WHERE active=1 ORDER BY id LIMIT 1025"))?;
            let ids = sql(statement.query_map([], |r| r.get::<_, String>(0)))?
                .collect::<rusqlite::Result<Vec<_>>>();
            let ids = sql(ids)?;
            if ids.len() > MAX_CLIENTS {
                return Err(ErrorCode::CapacityExceeded);
            }
            let mut clients = Vec::with_capacity(ids.len());
            for client_id in ids {
                let record: Option<String> = sql(tx
                    .query_row(
                        "SELECT record FROM reports WHERE client=?1 ORDER BY observed DESC LIMIT 1",
                        [&client_id],
                        |r| r.get(0),
                    )
                    .optional())?;
                let report: Option<RecordedClientReport> =
                    record.as_deref().map(decode).transpose()?;
                clients.push(ClientStatusEntry {
                    client_id: id(client_id)?,
                    status: classify_client(report.as_ref(), &identity.current_revision, now),
                    report,
                });
            }
            Ok(FleetStatus {
                schema_version: SCHEMA_VERSION,
                authority_id: identity.authority_id,
                policy_id: identity.policy_id,
                roster_revision: identity.roster_revision,
                sampled_unix_ms: now,
                current_revision: identity.current_revision,
                clients,
                roster_complete: true,
                fleet_adoption_verified: false,
            })
        })
    }
    pub fn issue_credential(
        &self,
        authority: &Id,
        role: Role,
        actor: &Id,
        client: Option<&Id>,
        expires: u64,
        output: &Path,
    ) -> Result<Id> {
        self.mutate(|tx, now| {
            let identity = Self::identity_at(tx)?;
            if &identity.authority_id != authority {
                return Err(ErrorCode::AuthorityChanged);
            }
            if expires <= now || expires > now.saturating_add(MAX_CREDENTIAL_AGE_MS) {
                return Err(ErrorCode::InvalidRequest);
            }
            if (role == Role::Client) != client.is_some() {
                return Err(ErrorCode::InvalidRequest);
            }
            if let Some(client) = client {
                let active: Option<bool> = sql(tx
                    .query_row(
                        "SELECT active FROM clients WHERE id=?1",
                        [client.as_str()],
                        |r| r.get(0),
                    )
                    .optional())?;
                if active != Some(true) {
                    return Err(ErrorCode::ClientUnknown);
                }
            }
            Self::capacity(tx, "credentials", MAX_CREDENTIALS)?;
            let mut entropy = [0u8; 32];
            OsRng
                .try_fill_bytes(&mut entropy)
                .map_err(|_| ErrorCode::StorageUnavailable)?;
            let token: String = entropy.iter().map(|byte| format!("{byte:02x}")).collect();
            let credential = Id::new();
            let hash = token_hash(&token)?;
            fs(private_fs::write_new_secret(
                output,
                format!("{token}\n").as_bytes(),
            ))?;
            sql(tx.execute(
                "INSERT INTO credentials VALUES (?1,?2,?3,?4,?5,?6,0)",
                params![
                    credential.as_str(),
                    hash,
                    actor.as_str(),
                    json(&role)?,
                    client.map(Id::as_str),
                    expires
                ],
            ))?;
            Ok(credential)
        })
    }
    /// Local-owner recovery inventory only; never expose hashes or token text.
    pub fn credentials(&self, authority: &Id) -> Result<Vec<CredentialInfo>> {
        self.transaction(|tx,_| {
            if Self::identity_at(tx)?.authority_id!=*authority {return Err(ErrorCode::AuthorityChanged);}
            let mut statement=sql(tx.prepare("SELECT id,actor,role,client,expires,revoked FROM credentials ORDER BY id LIMIT 2049"))?;
            let mut rows=sql(statement.query([]))?;let mut output=Vec::new();
            while let Some(row)=sql(rows.next())? {
                if output.len()>=MAX_CREDENTIALS as usize{return Err(ErrorCode::CapacityExceeded);}
                output.push(CredentialInfo {credential_id:id(sql(row.get(0))?)?,principal_id:id(sql(row.get(1))?)?,role:decode(&sql(row.get::<_,String>(2))?)?,client_id:sql(row.get::<_,Option<String>>(3))?.map(id).transpose()?,expires_unix_ms:sql(row.get(4))?,revoked:sql(row.get(5))?});
            }Ok(output)
        })
    }
    pub fn revoke(&self, authority: &Id, credential: &Id) -> Result<()> {
        self.mutate(|tx, _| {
            if Self::identity_at(tx)?.authority_id != *authority {
                return Err(ErrorCode::AuthorityChanged);
            }
            if sql(tx.execute(
                "UPDATE credentials SET revoked=1 WHERE id=?1",
                [credential.as_str()],
            ))? != 1
            {
                return Err(ErrorCode::InvalidRequest);
            }
            Ok(())
        })
    }
    pub fn register_client(&self, authority: &Id, expected_roster: &Id) -> Result<Id> {
        self.mutate(|tx, _| {
            let identity = Self::identity_at(tx)?;
            if identity.authority_id != *authority {
                return Err(ErrorCode::AuthorityChanged);
            }
            if identity.roster_revision != *expected_roster {
                return Err(ErrorCode::RevisionConflict);
            }
            Self::capacity(tx, "clients", MAX_CLIENTS as u64)?;
            let client = Id::new();
            sql(tx.execute("INSERT INTO clients VALUES (?1,1)", [client.as_str()]))?;
            sql(tx.execute(
                "UPDATE meta SET roster=?1 WHERE singleton=1",
                [Id::new().as_str()],
            ))?;
            Ok(client)
        })
    }
    pub fn deactivate_client(
        &self,
        authority: &Id,
        expected_roster: &Id,
        client: &Id,
    ) -> Result<()> {
        self.mutate(|tx, _| {
            let identity = Self::identity_at(tx)?;
            if identity.authority_id != *authority {
                return Err(ErrorCode::AuthorityChanged);
            }
            if identity.roster_revision != *expected_roster {
                return Err(ErrorCode::RevisionConflict);
            }
            if sql(tx.execute(
                "UPDATE clients SET active=0 WHERE id=?1 AND active=1",
                [client.as_str()],
            ))? != 1
            {
                return Err(ErrorCode::ClientUnknown);
            }
            sql(tx.execute(
                "UPDATE meta SET roster=?1 WHERE singleton=1",
                [Id::new().as_str()],
            ))?;
            Ok(())
        })
    }
    /// Explicit owner administration, with the same revision retention and CAS.
    /// This is a local import, never a fabricated reviewed HTTP publication.
    pub fn import(&self, authority: &Id, expected: &Id, yaml: &str) -> Result<Id> {
        validate_policy(yaml)?;
        self.mutate(|tx, now| {
            let identity = Self::identity_at(tx)?;
            if identity.authority_id != *authority {
                return Err(ErrorCode::AuthorityChanged);
            }
            if identity.current_revision != *expected {
                return Err(ErrorCode::RevisionConflict);
            }
            Self::publish_revision(tx, &identity, yaml, now)
        })
    }
}

#[cfg(test)]
#[path = "store_tests.rs"]
mod tests;
