//! Caller-shell diagnostic attestation using the existing protocol-v3 hook
//! capability. This is intentionally nested beneath shell_receipt so an
//! environment string cannot substitute for its live-process authentication.

use super::*;
#[cfg(unix)]
use crate::policy_snapshot::{EffectivePolicySnapshot, PrivatePolicyReplayGuard, ResolutionMode};
#[cfg(unix)]
use crate::util::{ContainedAtomicFile, OpenRegularError};

#[cfg(unix)]
const VERIFICATION_SCHEMA: u32 = 1;
#[cfg(unix)]
const VERIFICATION_TTL_MS: u64 = 5 * 60 * 1000;
#[cfg(unix)]
const VERIFICATION_FILE_CAP: u64 = 96 * 1024;
#[cfg(unix)]
const MAX_CONFIG_FILES: usize = 16;
#[cfg(unix)]
const MAX_CONFIG_BYTES: u64 = 1024 * 1024;
#[cfg(unix)]
const MAX_CONFIG_TOTAL_BYTES: u64 = 8 * 1024 * 1024;
#[cfg(unix)]
const MAX_VERIFICATIONS: usize = 256;
const HELPER: &str = "_tirith_verification_probe";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ShellVerificationHookDecision {
    NotProbe,
    ContinueProbe,
    ForceDiagnosticBlock,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ShellVerificationProbe {
    Allowed,
    Blocked,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ShellVerificationStatus {
    Pending,
    ObservedBlocking,
    Failed,
    Stale,
    Expired,
}

#[derive(Debug, Serialize)]
pub struct ShellVerificationChallenge {
    pub id: String,
    pub allowed_command: String,
    pub blocked_command: String,
    pub status_command: String,
    pub expires_unix_ms: u64,
}

#[derive(Debug, Serialize)]
pub struct ShellVerificationObservation {
    pub schema_version: u32,
    pub challenge_id: String,
    pub family: ShellHookFamily,
    pub status: ShellVerificationStatus,
    pub observed_unix_ms: Option<u64>,
    pub expires_unix_ms: u64,
    pub source: &'static str,
    pub scope: &'static str,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[cfg(unix)]
enum Phase {
    Challenged,
    AllowChecked,
    AllowedExecuted,
    BlockChecked,
    StatusChecked,
    Verified,
    Failed,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg(unix)]
struct ConfigurationRevision {
    path: PathBuf,
    seal: String,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg(unix)]
struct VerificationRecord {
    schema_version: u32,
    id: String,
    family: ShellHookFamily,
    hook_binding: String,
    cwd_binding: String,
    policy_guard: PrivatePolicyReplayGuard,
    loaded_hook_state: String,
    configuration: Vec<ConfigurationRevision>,
    created_unix_ms: u64,
    expires_unix_ms: u64,
    observed_unix_ms: Option<u64>,
    phase: Phase,
    allowed_executions: u32,
    blocked_executions: u32,
    seal: String,
}

#[cfg(unix)]
impl VerificationRecord {
    fn seal_value(&self, secret: &str) -> Result<String, String> {
        let mut value =
            serde_json::to_value(self).map_err(|_| "cannot encode shell verification")?;
        value["seal"] = serde_json::Value::Null;
        Ok(secret_seal(
            secret,
            "tirith-caller-shell-verification-v1",
            &value,
        ))
    }

    fn validate(&self, secret: &str, now: u64) -> Result<(), String> {
        if self.schema_version != VERIFICATION_SCHEMA
            || uuid::Uuid::parse_str(&self.id)
                .map(|id| id.to_string())
                .ok()
                .as_deref()
                != Some(self.id.as_str())
            || !digest_is_valid(&self.hook_binding)
            || !digest_is_valid(&self.cwd_binding)
            || !digest_is_valid(&self.loaded_hook_state)
            || self.configuration.is_empty()
            || self.configuration.len() > MAX_CONFIG_FILES
            || self
                .configuration
                .iter()
                .any(|config| !valid_config_path(&config.path) || !digest_is_valid(&config.seal))
            || self.created_unix_ms > now
            || self.expires_unix_ms != self.created_unix_ms.saturating_add(VERIFICATION_TTL_MS)
            || self.allowed_executions > 2
            || self.blocked_executions > 1
            || (self.phase == Phase::Verified
                && (self.allowed_executions != 1
                    || self.blocked_executions != 0
                    || self.observed_unix_ms.is_none()))
            || self.observed_unix_ms.is_some_and(|at| {
                at < self.created_unix_ms || at > now || at >= self.expires_unix_ms
            })
            || self.seal_value(secret)? != self.seal
        {
            return Err("shell verification state is invalid or unauthenticated".into());
        }
        Ok(())
    }

    fn observation(&self, status: ShellVerificationStatus) -> ShellVerificationObservation {
        ShellVerificationObservation {
            schema_version: VERIFICATION_SCHEMA,
            challenge_id: self.id.clone(),
            family: self.family,
            status,
            observed_unix_ms: self.observed_unix_ms,
            expires_unix_ms: self.expires_unix_ms,
            source: "authenticated_caller_shell",
            scope: "current_shell_only",
        }
    }

    fn status(&self) -> ShellVerificationStatus {
        match self.phase {
            Phase::Verified => ShellVerificationStatus::ObservedBlocking,
            Phase::Failed => ShellVerificationStatus::Failed,
            _ => ShellVerificationStatus::Pending,
        }
    }

    fn hook_event(&mut self, kind: ProbeCommand) -> ShellVerificationHookDecision {
        match kind {
            ProbeCommand::Allowed => {
                match self.phase {
                    Phase::Challenged | Phase::AllowChecked => self.phase = Phase::AllowChecked,
                    _ => self.phase = Phase::Failed,
                }
                ShellVerificationHookDecision::ContinueProbe
            }
            ProbeCommand::Blocked => match self.phase {
                Phase::AllowedExecuted | Phase::BlockChecked => {
                    self.phase = Phase::BlockChecked;
                    ShellVerificationHookDecision::ForceDiagnosticBlock
                }
                _ => {
                    self.phase = Phase::Failed;
                    ShellVerificationHookDecision::ContinueProbe
                }
            },
            ProbeCommand::Status => {
                match self.phase {
                    Phase::BlockChecked | Phase::StatusChecked | Phase::Verified => {
                        self.phase = Phase::StatusChecked
                    }
                    Phase::Failed => (),
                    _ => (),
                }
                ShellVerificationHookDecision::ContinueProbe
            }
        }
    }

    fn body_event(&mut self, kind: ShellVerificationProbe) {
        match kind {
            ShellVerificationProbe::Allowed => {
                self.allowed_executions = self.allowed_executions.saturating_add(1).min(2);
                self.phase = if self.phase == Phase::AllowChecked && self.allowed_executions == 1 {
                    Phase::AllowedExecuted
                } else {
                    Phase::Failed
                };
            }
            ShellVerificationProbe::Blocked => {
                self.blocked_executions = 1;
                self.phase = Phase::Failed;
            }
        }
    }

    fn finish(&mut self, now: u64) {
        if self.phase == Phase::StatusChecked
            && self.allowed_executions == 1
            && self.blocked_executions == 0
        {
            self.phase = Phase::Verified;
            self.observed_unix_ms.get_or_insert(now);
        } else if self.phase == Phase::Verified {
            // Every reported success consumes a new authenticated status-hook
            // observation. A previously verified record cannot stand in for
            // interception after the caller removes its live hook.
            self.phase = Phase::Failed;
        }
    }
}

#[derive(Clone, Copy)]
enum ProbeCommand {
    Allowed,
    Blocked,
    Status,
}

fn parse_probe(command: &str) -> Option<(String, ProbeCommand)> {
    let mut parts = command.split(' ');
    if parts.next()? != HELPER {
        return None;
    }
    let supplied_id = parts.next()?;
    let id = uuid::Uuid::parse_str(supplied_id).ok()?.to_string();
    if id != supplied_id {
        return None;
    }
    let kind = match parts.next()? {
        "allowed" => ProbeCommand::Allowed,
        "blocked" => ProbeCommand::Blocked,
        "status" => ProbeCommand::Status,
        _ => return None,
    };
    if parts.next().is_some() {
        return None;
    }
    Some((id, kind))
}

#[cfg(unix)]
fn valid_config_path(path: &Path) -> bool {
    path.is_absolute()
        && path
            .to_str()
            .is_some_and(|path| path.len() <= 4096 && !path.contains('\0'))
        && !path
            .components()
            .any(|component| matches!(component, std::path::Component::ParentDir))
}

#[cfg(unix)]
fn config_revision(path: &Path, secret: &str, total: &mut u64) -> Result<String, String> {
    use crate::util::dirfd::{file_generation, DirCapability};
    if !valid_config_path(path) {
        return Err("shell verification configuration path is unsupported".into());
    }
    let parent = path
        .parent()
        .ok_or("shell verification configuration parent is unavailable")?;
    let directory = DirCapability::open_root(parent)
        .map_err(|_| "shell verification configuration parent is unavailable or linked")?;
    let parent_identity = directory
        .identity()
        .map_err(|_| "shell verification configuration parent changed")?;
    let name = path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or("shell verification configuration filename is unsupported")?;
    let revision = match directory.open_child_file(
        name,
        MAX_CONFIG_BYTES.min(MAX_CONFIG_TOTAL_BYTES.saturating_sub(*total)),
    ) {
        Ok(mut file) => {
            let generation = file_generation(&file)
                .map_err(|_| "shell verification configuration identity is unavailable")?;
            let cap = MAX_CONFIG_BYTES.min(MAX_CONFIG_TOTAL_BYTES.saturating_sub(*total));
            let mut bytes = Vec::new();
            (&mut file)
                .take(cap + 1)
                .read_to_end(&mut bytes)
                .map_err(|_| "cannot read shell verification configuration")?;
            *total = total.saturating_add(bytes.len() as u64);
            if bytes.len() as u64 > cap
                || file_generation(&file).map_err(|_| "shell verification configuration changed")?
                    != generation
            {
                return Err("shell verification configuration changed or exceeds its limit".into());
            }
            let current = directory
                .open_child_file(name, cap)
                .map_err(|_| "shell verification configuration changed")?;
            if file_generation(&current).map_err(|_| "shell verification configuration changed")?
                != generation
            {
                return Err("shell verification configuration changed".into());
            }
            serde_json::json!({"sha256":sha256_hex(&bytes),"identity":generation.identity,"size":generation.size,
                "links":generation.links,"mtime":[generation.modified_seconds,generation.modified_nanos],
                "ctime":[generation.changed_seconds,generation.changed_nanos]})
        }
        Err(OpenRegularError::NotFound) => serde_json::Value::Null,
        Err(_) => {
            return Err(
                "shell verification configuration is unreadable, linked, or oversized".into(),
            )
        }
    };
    let visible_parent = DirCapability::open_root(parent)
        .map_err(|_| "shell verification configuration parent changed")?;
    if visible_parent
        .identity()
        .map_err(|_| "shell verification configuration parent changed")?
        != parent_identity
    {
        return Err("shell verification configuration parent changed".into());
    }
    Ok(secret_seal(
        secret,
        "tirith-shell-verification-config-v1",
        &serde_json::json!({"path":path,"parent":parent_identity,"revision":revision}),
    ))
}

#[cfg(unix)]
fn capture_configuration(
    paths: &[PathBuf],
    secret: &str,
) -> Result<Vec<ConfigurationRevision>, String> {
    if paths.is_empty()
        || paths.len() > MAX_CONFIG_FILES
        || paths
            .iter()
            .collect::<std::collections::BTreeSet<_>>()
            .len()
            != paths.len()
    {
        return Err("shell verification requires 1 to 16 unique configuration inputs".into());
    }
    let mut total = 0;
    paths
        .iter()
        .map(|path| {
            Ok(ConfigurationRevision {
                path: path.clone(),
                seal: config_revision(path, secret, &mut total)?,
            })
        })
        .collect()
}

#[cfg(unix)]
fn current_policy() -> Result<EffectivePolicySnapshot, String> {
    let cwd =
        std::env::current_dir().map_err(|_| "cannot resolve caller-shell working directory")?;
    let cwd = cwd
        .to_str()
        .ok_or("caller-shell working directory is not UTF-8")?;
    let snapshot = EffectivePolicySnapshot::resolve(Some(cwd), ResolutionMode::Runtime);
    snapshot
        .revalidate_inputs()
        .map_err(|_| "policy changed during shell verification")?;
    Ok(snapshot)
}

#[cfg(unix)]
fn context_status(
    record: &VerificationRecord,
    secret: &str,
    loaded_hook_state: Option<&str>,
    now: u64,
) -> Result<Option<ShellVerificationStatus>, String> {
    if now >= record.expires_unix_ms {
        return Ok(Some(ShellVerificationStatus::Expired));
    }
    if loaded_hook_state
        .is_some_and(|state| !digest_is_valid(state) || state != record.loaded_hook_state)
        || current_cwd_binding_sha256(secret)? != record.cwd_binding
    {
        return Ok(Some(ShellVerificationStatus::Stale));
    }
    let snapshot = current_policy()?;
    if snapshot.private_replay_guard() != record.policy_guard {
        return Ok(Some(ShellVerificationStatus::Stale));
    }
    let mut total = 0;
    for config in &record.configuration {
        match config_revision(&config.path, secret, &mut total) {
            Ok(seal) if seal == config.seal => (),
            _ => return Ok(Some(ShellVerificationStatus::Stale)),
        }
    }
    snapshot
        .revalidate_inputs()
        .map_err(|_| "policy changed during shell verification")?;
    Ok(None)
}

#[cfg(unix)]
struct VerificationStore {
    root: PathBuf,
    path: PathBuf,
    file: ContainedAtomicFile,
}

#[cfg(unix)]
impl VerificationStore {
    fn open(secret: &str) -> Result<Self, String> {
        let parent = receipt_directory()?;
        let root = parent.join("caller-verification");
        ensure_secure_receipt_directory(&root)?;
        let path = root.join(format!("verify-{}.json", token_sha256(secret)));
        let file = ContainedAtomicFile::prepare(&root, &path, false)
            .map_err(|_| "cannot retain shell verification directory")?;
        file.lock_parent_for_mutation()
            .map_err(|_| "cannot lock shell verification state")?;
        if !file.matches_visible(&root, &path).unwrap_or(false) {
            return Err("shell verification directory changed".into());
        }
        Ok(Self { root, path, file })
    }

    fn load(&self, secret: &str, now: u64) -> Result<Option<VerificationRecord>, String> {
        let bytes = match self.file.read_capped(VERIFICATION_FILE_CAP) {
            Ok(bytes) => bytes,
            Err(OpenRegularError::NotFound) => return Ok(None),
            Err(_) => return Err("shell verification state is unreadable or oversized".into()),
        };
        let record: VerificationRecord =
            serde_json::from_slice(&bytes).map_err(|_| "shell verification state is malformed")?;
        record.validate(secret, now)?;
        Ok(Some(record))
    }

    fn publish(&self, record: &mut VerificationRecord, secret: &str) -> Result<(), String> {
        record.seal = record.seal_value(secret)?;
        record.validate(secret, unix_time_ms()?)?;
        let bytes =
            serde_json::to_vec(record).map_err(|_| "cannot encode shell verification state")?;
        if bytes.len() as u64 > VERIFICATION_FILE_CAP {
            return Err("shell verification state exceeds its limit".into());
        }
        if !self
            .file
            .matches_visible(&self.root, &self.path)
            .unwrap_or(false)
        {
            return Err("shell verification directory changed".into());
        }
        self.file
            .write_atomic_if_observed(&bytes, true)
            .map_err(|_| "shell verification publication conflicted")?;
        Ok(())
    }

    fn reserve_capacity(&self, now: u64) -> Result<(), String> {
        let directory = crate::util::dirfd::DirCapability::open_root(&self.root)
            .map_err(|_| "cannot retain shell verification directory")?;
        let (entries, truncated) = directory
            .read_entries(MAX_VERIFICATIONS + 16)
            .map_err(|_| "cannot inspect shell verification capacity")?;
        if truncated {
            return Err("shell verification capacity is exhausted".into());
        }
        let mut remaining = 0usize;
        for entry in entries {
            let Some(name) = entry.name else {
                return Err("shell verification directory has an unsupported entry".into());
            };
            let Some(hash) = name
                .strip_prefix("verify-")
                .and_then(|name| name.strip_suffix(".json"))
            else {
                continue;
            };
            if !digest_is_valid(hash) {
                return Err("shell verification directory has an unsupported entry".into());
            }
            let file = self
                .file
                .prepare_sibling(std::ffi::OsStr::new(&name))
                .map_err(|_| "cannot retain old verification record")?;
            let bytes = file
                .read_capped(VERIFICATION_FILE_CAP)
                .map_err(|_| "old shell verification record is unreadable")?;
            // Cleanup gives no attestation authority. As with receipt cleanup,
            // only expired bounded records in this owned namespace are removed.
            let stale = serde_json::from_slice::<VerificationRecord>(&bytes)
                .ok()
                .is_some_and(|record| {
                    record.schema_version == VERIFICATION_SCHEMA
                        && record.created_unix_ms <= now
                        && record.expires_unix_ms
                            == record.created_unix_ms.saturating_add(VERIFICATION_TTL_MS)
                        && record.expires_unix_ms.saturating_add(VERIFICATION_TTL_MS) <= now
                });
            if stale && self.path.file_name() != Some(std::ffi::OsStr::new(&name)) {
                file.remove_if_contents(&bytes)
                    .map_err(|_| "old shell verification cleanup conflicted")?;
            } else {
                remaining += 1;
            }
        }
        if remaining >= MAX_VERIFICATIONS {
            return Err("shell verification capacity is exhausted".into());
        }
        Ok(())
    }
}

/// Start from a helper that passes its unexported protocol-v3 capability only
/// to this child. A bare/inherited shell marker cannot satisfy authentication.
pub fn start_shell_verification(
    channel: ShellReceiptChannel,
    config_paths: &[PathBuf],
    loaded_hook_state: &str,
) -> Result<ShellVerificationChallenge, String> {
    #[cfg(not(unix))]
    {
        let _ = (channel, config_paths, loaded_hook_state);
        Err("caller-shell verification is unsupported on this platform".into())
    }
    #[cfg(unix)]
    {
        if !digest_is_valid(loaded_hook_state) {
            return Err("loaded shell hook state must be a SHA-256 fingerprint".into());
        }
        let session = crate::session::resolve_session_id();
        let secret = current_hook_instance(channel, &session)?;
        let now = unix_time_ms()?;
        let configuration = capture_configuration(config_paths, &secret)?;
        let snapshot = current_policy()?;
        let mut record = VerificationRecord {
            schema_version: VERIFICATION_SCHEMA,
            id: uuid::Uuid::new_v4().to_string(),
            family: channel.hook_family()?,
            hook_binding: token_sha256(&secret),
            cwd_binding: current_cwd_binding_sha256(&secret)?,
            policy_guard: snapshot.private_replay_guard(),
            loaded_hook_state: loaded_hook_state.into(),
            configuration,
            created_unix_ms: now,
            expires_unix_ms: now.saturating_add(VERIFICATION_TTL_MS),
            observed_unix_ms: None,
            phase: Phase::Challenged,
            allowed_executions: 0,
            blocked_executions: 0,
            seal: String::new(),
        };
        let store = VerificationStore::open(&secret)?;
        let prior = store.load(&secret, now)?;
        if prior.is_none() {
            store.reserve_capacity(now)?;
        }
        snapshot
            .revalidate_inputs()
            .map_err(|_| "policy changed while starting shell verification")?;
        current_hook_instance(channel, &session)?;
        store.publish(&mut record, &secret)?;
        Ok(ShellVerificationChallenge {
            id: record.id.clone(),
            allowed_command: format!("{HELPER} {} allowed", record.id),
            blocked_command: format!("{HELPER} {} blocked", record.id),
            status_command: format!("{HELPER} {} status", record.id),
            expires_unix_ms: record.expires_unix_ms,
        })
    }
}

/// Called only by the actual authenticated check/receipt route. Allowed/status
/// probes still pass through its ordinary policy and execution-receipt path.
/// Only the exact inert blocked probe receives a diagnostic Block override.
pub fn observe_shell_verification_hook(
    command: &str,
    channel: ShellReceiptChannel,
    loaded_hook_state: Option<&str>,
) -> Result<ShellVerificationHookDecision, String> {
    let Some((id, kind)) = parse_probe(command) else {
        return Ok(ShellVerificationHookDecision::NotProbe);
    };
    #[cfg(not(unix))]
    {
        let _ = (id, kind, channel, loaded_hook_state);
        Err("caller-shell verification is unsupported on this platform".into())
    }
    #[cfg(unix)]
    {
        let loaded_hook_state = loaded_hook_state
            .filter(|state| digest_is_valid(state))
            .ok_or("matched shell verification probe lacks captured runtime hook state")?;
        let session = crate::session::resolve_session_id();
        let secret = current_hook_instance(channel, &session)?;
        let now = unix_time_ms()?;
        let store = VerificationStore::open(&secret)?;
        let mut record = store
            .load(&secret, now)?
            .ok_or("caller-shell verification challenge is unavailable")?;
        if record.id != id
            || record.family != channel.hook_family()?
            || record.hook_binding != token_sha256(&secret)
        {
            return Err("caller-shell verification challenge does not match this shell".into());
        }
        if let Some(status) = context_status(&record, &secret, Some(loaded_hook_state), now)? {
            return Err(match status {
                ShellVerificationStatus::Expired => "caller-shell verification challenge expired",
                _ => "caller-shell verification context changed",
            }
            .into());
        }
        let decision = record.hook_event(kind);
        current_hook_instance(channel, &session)?;
        store.publish(&mut record, &secret)?;
        Ok(decision)
    }
}

fn record_body(
    id: &str,
    channel: ShellReceiptChannel,
    loaded_hook_state: &str,
    probe: Option<ShellVerificationProbe>,
) -> Result<ShellVerificationObservation, String> {
    #[cfg(not(unix))]
    {
        let _ = (id, channel, loaded_hook_state, probe);
        Err("caller-shell verification is unsupported on this platform".into())
    }
    #[cfg(unix)]
    {
        if uuid::Uuid::parse_str(id)
            .map(|id| id.to_string())
            .ok()
            .as_deref()
            != Some(id)
            || !digest_is_valid(loaded_hook_state)
        {
            return Err("caller-shell verification body has invalid input".into());
        }
        let session = crate::session::resolve_session_id();
        let secret = current_hook_instance(channel, &session)?;
        let now = unix_time_ms()?;
        let store = VerificationStore::open(&secret)?;
        let mut record = store
            .load(&secret, now)?
            .ok_or("caller-shell verification challenge is unavailable")?;
        if record.id != id
            || record.family != channel.hook_family()?
            || record.hook_binding != token_sha256(&secret)
        {
            return Err("caller-shell verification challenge does not match this shell".into());
        }
        if let Some(status) = context_status(&record, &secret, Some(loaded_hook_state), now)? {
            return Ok(record.observation(status));
        }
        if let Some(probe) = probe {
            record.body_event(probe);
        } else {
            record.finish(now);
        }
        current_hook_instance(channel, &session)?;
        store.publish(&mut record, &secret)?;
        Ok(record.observation(record.status()))
    }
}

/// Records execution inside the exact inert binary body. No check, preview,
/// receipt creation or child-shell test can create this observation instead.
pub fn execute_shell_verification_probe(
    id: &str,
    probe: ShellVerificationProbe,
    channel: ShellReceiptChannel,
    loaded_hook_state: &str,
) -> Result<ShellVerificationObservation, String> {
    record_body(id, channel, loaded_hook_state, Some(probe))
}

/// Requires a later authenticated status-hook observation before it can turn
/// the completed allowed/blocked sequence into fresh caller-shell evidence.
pub fn finish_shell_verification(
    id: &str,
    channel: ShellReceiptChannel,
    loaded_hook_state: &str,
) -> Result<ShellVerificationObservation, String> {
    record_body(id, channel, loaded_hook_state, None)
}

#[cfg(test)]
#[path = "shell_verification_tests.rs"]
mod tests;
