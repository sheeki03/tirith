//! Hook load records for shells without a protocol-v3 receipt capability.
//!
//! PowerShell and Nushell have no strict receipt channel, so their hooks never
//! register a bearer capability. To still say whether the hook loaded in such a
//! terminal came from this Tirith executable, the hook records that it loaded:
//! the live shell process identity and the executable that wrote the record.
//! A load record carries no secret, never satisfies a capability lookup and
//! grants nothing. It is loaded-hook evidence for hook freshness only, never
//! interception or blocking proof.
//!
//! Records live beside the capability records in the private receipt
//! directory as `.hook-presence-<key>.record`. That name is outside every
//! receipt (`*.json`) and capability (`.hook-*.capability`) pattern, so 0.4.2
//! and current receipt and capability scans skip it.

use super::*;

/// Shell families whose hooks write a load record instead of a capability.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum HookPresenceFamily {
    #[serde(rename = "powershell")]
    PowerShell,
    #[serde(rename = "nushell")]
    Nushell,
}

#[cfg(unix)]
const HOOK_PRESENCE_SCHEMA_VERSION: u32 = 1;
#[cfg(unix)]
const HOOK_PRESENCE_FILE_CAP: u64 = 8 * 1024;
#[cfg(unix)]
const HOOK_PRESENCE_PREFIX: &str = ".hook-presence-";

#[cfg(unix)]
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct HookPresence {
    schema_version: u32,
    effective_uid: u32,
    shell_pid: u32,
    shell_start_fingerprint: String,
    family: HookPresenceFamily,
    tirith_executable: TirithExecutableIdentity,
    created_unix_ms: u64,
}

#[cfg(unix)]
pub(super) fn presence_key(
    effective_uid: u32,
    shell_pid: u32,
    shell_start_fingerprint: &str,
) -> String {
    sha256_hex(
        format!(
            "tirith-shell-hook-presence-v1\0{effective_uid}\0{shell_pid}\0{shell_start_fingerprint}"
        )
        .as_bytes(),
    )
}

#[cfg(unix)]
pub(super) fn presence_path(directory: &Path, key: &str) -> PathBuf {
    directory.join(format!("{HOOK_PRESENCE_PREFIX}{key}.record"))
}

/// The key of a load-record file name, or `None` for any other entry.
#[cfg(unix)]
pub(super) fn hook_presence_key(name: &str) -> Option<&str> {
    let key = name
        .strip_prefix(HOOK_PRESENCE_PREFIX)?
        .strip_suffix(".record")?;
    digest_is_valid(key).then_some(key)
}

#[cfg(unix)]
fn presence_temp_name(name: &str) -> bool {
    name.strip_prefix(HOOK_PRESENCE_PREFIX)
        .and_then(|rest| rest.strip_suffix(".tmp"))
        .is_some_and(|stem| {
            stem.len() == 32
                && stem
                    .bytes()
                    .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
        })
}

#[cfg(unix)]
fn presence_key_matches(key: &str, record: &HookPresence) -> bool {
    record.schema_version == HOOK_PRESENCE_SCHEMA_VERSION
        && key
            == presence_key(
                record.effective_uid,
                record.shell_pid,
                &record.shell_start_fingerprint,
            )
}

#[cfg(unix)]
fn read_presence(path: &Path) -> Result<(HookPresence, FileIdentity), String> {
    use std::os::unix::fs::OpenOptionsExt as _;

    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
        .open(path)
        .map_err(|error| format!("open hook load record: {error}"))?;
    let identity = secure_regular_identity(&file, "hook load record")?;
    let length = file
        .metadata()
        .map_err(|error| format!("inspect hook load record: {error}"))?
        .len();
    if length == 0 || length > HOOK_PRESENCE_FILE_CAP {
        return Err("hook load record is empty or oversized".to_string());
    }
    let mut bytes = Vec::with_capacity(length as usize);
    file.take(HOOK_PRESENCE_FILE_CAP + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| format!("read hook load record: {error}"))?;
    if bytes.len() as u64 > HOOK_PRESENCE_FILE_CAP {
        return Err("hook load record grew beyond its size limit".to_string());
    }
    let record = serde_json::from_slice(&bytes)
        .map_err(|error| format!("parse hook load record: {error}"))?;
    Ok((record, identity))
}

/// Atomically publish (or replace) the record for one live shell process.
#[cfg(unix)]
fn publish_presence(path: &Path, record: &HookPresence) -> Result<(), String> {
    use std::os::unix::fs::OpenOptionsExt as _;

    let bytes = serde_json::to_vec(record)
        .map_err(|error| format!("serialize hook load record: {error}"))?;
    if bytes.is_empty() || bytes.len() as u64 > HOOK_PRESENCE_FILE_CAP {
        return Err("serialized hook load record exceeds its size limit".to_string());
    }
    let parent = path
        .parent()
        .ok_or_else(|| "hook load record path has no parent".to_string())?;
    let temporary = parent.join(format!(
        "{HOOK_PRESENCE_PREFIX}{}.tmp",
        uuid::Uuid::new_v4().simple()
    ));
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(&temporary)
        .map_err(|error| format!("create hook load record temp file: {error}"))?;
    let result = (|| {
        let identity = secure_regular_identity(&file, "hook load record temp file")?;
        file.write_all(&bytes)
            .map_err(|error| format!("write hook load record temp file: {error}"))?;
        file.sync_all()
            .map_err(|error| format!("sync hook load record temp file: {error}"))?;
        fs::rename(&temporary, path)
            .map_err(|error| format!("publish hook load record: {error}"))?;
        if path_identity(path, "hook load record")? != identity {
            return Err("published hook load record does not identify its temp file".to_string());
        }
        crate::util::fsync_parent_dir(path)
            .map_err(|error| format!("sync hook load record directory: {error}"))
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    result
}

/// Remove records whose shell process is definitely gone and crash-stranded
/// temp files, then bound the number of records. Callers hold the capability
/// registry lock. Unreadable or malformed records are retained (and counted),
/// as capability cleanup does.
#[cfg(unix)]
fn cleanup_hook_presence_locked(directory: &Path) -> Result<(), String> {
    let now = unix_time_ms()?;
    let retention_ms = u64::try_from(TERMINAL_RETENTION.as_millis()).unwrap_or(u64::MAX);
    let mut retained = 0usize;
    let entries =
        fs::read_dir(directory).map_err(|error| format!("scan hook load records: {error}"))?;
    for entry in entries {
        let entry = entry.map_err(|error| format!("read hook load record entry: {error}"))?;
        let path = entry.path();
        let Some(name) = path.file_name().and_then(|name| name.to_str()) else {
            continue;
        };
        if presence_temp_name(name) {
            if stale_private_regular_file(&path, now, retention_ms) {
                fs::remove_file(&path)
                    .map_err(|error| format!("remove stale hook load record temp file: {error}"))?;
                crate::util::fsync_parent_dir(&path).map_err(|error| {
                    format!("sync stale hook load record temp-file removal: {error}")
                })?;
            }
            continue;
        }
        let Some(key) = hook_presence_key(name) else {
            continue;
        };
        let removable = match read_presence(&path) {
            Ok((record, identity)) => {
                presence_key_matches(key, &record)
                    && capability_process_binding_is_stale(
                        record.effective_uid,
                        record.shell_pid,
                        &record.shell_start_fingerprint,
                    )
                    && path_identity(&path, "stale hook load record")
                        .is_ok_and(|current| current == identity)
            }
            Err(_) => false,
        };
        if removable {
            fs::remove_file(&path)
                .map_err(|error| format!("remove stale hook load record: {error}"))?;
            crate::util::fsync_parent_dir(&path)
                .map_err(|error| format!("sync stale hook load record removal: {error}"))?;
        } else {
            retained = retained.saturating_add(1);
        }
    }
    if retained >= MAX_HOOK_CAPABILITIES {
        return Err("live hook load record capacity is exhausted".to_string());
    }
    Ok(())
}

/// Record that a PowerShell or Nushell hook loaded in the live shell
/// `shell_pid`, naming this Tirith executable. The caller establishes that
/// `shell_pid` is the calling shell. A later registration for the same live
/// process replaces its record.
pub fn register_hook_presence(shell_pid: u32, family: HookPresenceFamily) -> Result<(), String> {
    #[cfg(not(unix))]
    {
        let _ = (shell_pid, family);
        Err("hook load records are unsupported on this platform".to_string())
    }

    #[cfg(unix)]
    {
        let lookup = |pid| {
            shell_process_identity(pid).map_err(|error| match error {
                ShellProcessLookupError::Missing => {
                    "hook load record target is not a live process".to_string()
                }
                ShellProcessLookupError::Rejected(detail) => detail,
            })
        };
        let shell_identity = lookup(shell_pid)?;
        let effective_uid = unsafe { libc::geteuid() };
        if shell_identity.effective_uid != effective_uid {
            return Err("hook load record target has a different effective UID".to_string());
        }
        let executable = current_tirith_executable_identity()?;
        let directory = receipt_directory()?;
        let _registry = open_capability_registry_lock(&directory)?;
        cleanup_hook_presence_locked(&directory)?;
        let record = HookPresence {
            schema_version: HOOK_PRESENCE_SCHEMA_VERSION,
            effective_uid,
            shell_pid,
            shell_start_fingerprint: shell_identity.start_fingerprint.clone(),
            family,
            tirith_executable: executable,
            created_unix_ms: unix_time_ms()?,
        };
        if lookup(shell_pid)? != shell_identity {
            return Err("hook load record target changed identity".to_string());
        }
        let key = presence_key(effective_uid, shell_pid, &shell_identity.start_fingerprint);
        publish_presence(&presence_path(&directory, &key), &record)
    }
}

/// Classify the load record stored under `key`. `family`, when given, must
/// match the record. Records of exited or reused processes are invalid.
#[cfg(unix)]
pub(super) fn registered_presence(
    directory: &Path,
    key: &str,
    effective_uid: u32,
    executable: &TirithExecutableIdentity,
    family: Option<HookPresenceFamily>,
) -> RegisteredHook {
    let path = presence_path(directory, key);
    let record = match fs::symlink_metadata(&path) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return RegisteredHook::Absent
        }
        Err(_) => return RegisteredHook::Invalid,
        Ok(_) => match read_presence(&path) {
            Ok((record, _)) => record,
            Err(_) => return RegisteredHook::Invalid,
        },
    };
    let live = matches!(
        shell_process_identity(record.shell_pid),
        Ok(identity) if identity.effective_uid == record.effective_uid
            && identity.start_fingerprint == record.shell_start_fingerprint
    );
    if !presence_key_matches(key, &record)
        || record.effective_uid != effective_uid
        || family.is_some_and(|family| family != record.family)
        || !live
    {
        return RegisteredHook::Invalid;
    }
    RegisteredHook::Live {
        current: record.tirith_executable == *executable,
    }
}
