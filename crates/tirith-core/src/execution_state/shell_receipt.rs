use super::*;

use std::fs::File;
#[cfg(unix)]
use std::fs::{self, OpenOptions};
use std::path::{Path, PathBuf};
use std::time::Duration;
#[cfg(unix)]
use std::time::Instant;

use serde::{Deserialize, Serialize};

const RECEIPT_SCHEMA_VERSION: u32 = 3;
const LEGACY_RAW_COMMAND_RECEIPT_SCHEMA_VERSION: u32 = 1;
const LEGACY_RAW_CWD_RECEIPT_SCHEMA_VERSION: u32 = 2;
const HOOK_CAPABILITY_SCHEMA_VERSION: u32 = 3;
const HOOK_CAPABILITY_ANCHOR_SCHEMA_VERSION: u32 = 1;
const RECEIPT_FILE_CAP: u64 = 64 * 1024;
const HOOK_CAPABILITY_FILE_CAP: u64 = 16 * 1024;
const HOOK_CAPABILITY_ANCHOR_FILE_CAP: u64 = 8 * 1024;
const RECEIPT_LOCK_TIMEOUT: Duration = Duration::from_secs(2);
const MAX_RECEIPT_TTL: Duration = Duration::from_secs(60 * 60);
const TERMINAL_RETENTION: Duration = Duration::from_secs(10 * 60);
const CONSUMING_RETRY_WINDOW: Duration = Duration::from_secs(30);
const MAX_RECEIPTS: usize = 256;
const MAX_HOOK_CAPABILITIES: usize = 256;

/// The hook boundary that created a receipt. POSIX tokenization is shared by
/// zsh and bash, so the concrete hook is frozen separately to prevent a token
/// from being replayed through a different delivery mechanism.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ShellReceiptChannel {
    Zsh,
    Fish,
    BashEnter,
    BashPreexec,
    PowerShell,
}

/// Shell implementation that owns a registered receipt capability. This is
/// intentionally narrower than [`ShellType`]: PowerShell history and mutable
/// globals are not a trusted execution boundary, and the two Bash observation
/// channels share one long-lived shell capability.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ShellHookFamily {
    Zsh,
    Fish,
    Bash,
}

impl ShellHookFamily {
    fn parse(value: &str) -> Result<Self, String> {
        match value {
            "zsh" => Ok(Self::Zsh),
            "fish" => Ok(Self::Fish),
            "bash" => Ok(Self::Bash),
            _ => Err("shell receipt hook family is unsupported".to_string()),
        }
    }
}

impl ShellReceiptChannel {
    fn expected_shell(self) -> ShellType {
        match self {
            Self::Zsh | Self::BashEnter | Self::BashPreexec => ShellType::Posix,
            Self::Fish => ShellType::Fish,
            Self::PowerShell => ShellType::PowerShell,
        }
    }

    fn observation_tag(self) -> &'static str {
        match self {
            Self::Zsh => "zsh_accept_line",
            Self::Fish => "fish_accept_line",
            Self::BashEnter => "bash_enter_preexec",
            Self::BashPreexec => "bash_line_start",
            Self::PowerShell => "powershell_history",
        }
    }

    fn hook_family(self) -> Result<ShellHookFamily, String> {
        match self {
            Self::Zsh => Ok(ShellHookFamily::Zsh),
            Self::Fish => Ok(ShellHookFamily::Fish),
            Self::BashEnter | Self::BashPreexec => Ok(ShellHookFamily::Bash),
            Self::PowerShell => Err(
                "strict PowerShell execution receipts are unsupported because mutable history cannot prove execution"
                    .to_string(),
            ),
        }
    }
}

/// Resolution reported by a trusted hook after presenting the frozen approval
/// interaction. Proof hashes are generated inside core; callers never supply
/// them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ShellApprovalOutcome {
    Granted,
    Rejected,
    TimedOut,
}

#[derive(Debug, Clone)]
pub struct ShellReceiptContext {
    session_id: String,
    shell: ShellType,
    channel: ShellReceiptChannel,
    interactive: bool,
    strict_warn_override: bool,
}

impl ShellReceiptContext {
    pub fn session_id(&self) -> &str {
        &self.session_id
    }

    pub fn shell(&self) -> ShellType {
        self.shell
    }

    pub fn channel(&self) -> ShellReceiptChannel {
        self.channel
    }

    pub fn interactive(&self) -> bool {
        self.interactive
    }

    pub fn strict_warn_override(&self) -> bool {
        self.strict_warn_override
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum StoredApprovalResolution {
    Granted { proof_sha256: String },
    FallbackAllow { proof_sha256: String },
    FallbackWarn { proof_sha256: String },
}

impl StoredApprovalResolution {
    fn proof_sha256(&self) -> &str {
        match self {
            Self::Granted { proof_sha256 }
            | Self::FallbackAllow { proof_sha256 }
            | Self::FallbackWarn { proof_sha256 } => proof_sha256,
        }
    }

    fn to_verified(&self) -> VerifiedApprovalResolution {
        match self {
            Self::Granted { proof_sha256 } => {
                VerifiedApprovalResolution::Granted(proof_sha256.clone())
            }
            Self::FallbackAllow { proof_sha256 } => {
                VerifiedApprovalResolution::FallbackAllow(proof_sha256.clone())
            }
            Self::FallbackWarn { proof_sha256 } => {
                VerifiedApprovalResolution::FallbackWarn(proof_sha256.clone())
            }
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case", deny_unknown_fields)]
enum ReceiptState {
    Prepared,
    Armed {
        approval: Option<StoredApprovalResolution>,
        warn_ack_proof_sha256: Option<String>,
        armed_unix_ms: u64,
    },
    Consuming {
        approval: Option<StoredApprovalResolution>,
        warn_ack_proof_sha256: Option<String>,
        observation: String,
        evidence_id: String,
        draft_identity_sha256: String,
        committed_policy_basis_sha256: String,
        committed_verdict_basis_sha256: String,
        consuming_unix_ms: u64,
    },
    Committed {
        observation: String,
        evidence_id: String,
        generation: u64,
        finished_unix_ms: u64,
    },
    Conflict {
        observation: String,
        evidence_id: String,
        generation: Option<u64>,
        finished_unix_ms: u64,
    },
    Discarded {
        finished_unix_ms: u64,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ShellReceipt {
    schema_version: u32,
    token_sha256: String,
    immutable_seal_sha256: String,
    state_seal_sha256: String,
    execution_id: String,
    session_id: String,
    shell: ShellType,
    channel: ShellReceiptChannel,
    /// Schema-v1/v2 raw working-directory digest. Parsed only so an
    /// authenticated legacy receipt can be retired; schema-v3 forbids it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    cwd_sha256: Option<String>,
    /// Token-keyed exact working-directory binding. The bearer token is never
    /// persisted, so this verifies context without leaving a stable raw-path
    /// oracle. Required by schema-v3 and absent from legacy receipts.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    cwd_binding_sha256: Option<String>,
    hook_instance_sha256: String,
    /// Compatibility field name: schema-v2/v3 receipts store the mandatory
    /// privacy-projected command digest.
    command_sha256: String,
    /// Token-keyed binding of the exact raw command. The token is never
    /// persisted, so this closes same-projection substitution without creating a
    /// durable offline oracle. Optional only so schema-v1 receipts can be parsed
    /// and retired; schema-v2/v3 validation requires it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    command_binding_sha256: Option<String>,
    command_redacted_preview: String,
    decision_binding_sha256: String,
    policy_basis_sha256: String,
    semantic_verdict_basis_sha256: String,
    action: Action,
    bypass_honored: bool,
    requires_approval: bool,
    requires_warn_ack: bool,
    approval_fallback: Option<String>,
    interactive: bool,
    strict_warn_override: bool,
    created_unix_ms: u64,
    expires_unix_ms: u64,
    state: ReceiptState,
}

#[cfg(unix)]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ShellProcessIdentity {
    effective_uid: u32,
    start_fingerprint: String,
}

#[cfg(unix)]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct TirithExecutableIdentity {
    device: u64,
    inode: u64,
    size: u64,
    owner_uid: u32,
    mode: u32,
    modified_seconds: i64,
    modified_nanoseconds: i64,
    changed_seconds: i64,
    changed_nanoseconds: i64,
}

#[cfg(unix)]
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ShellHookCapability {
    schema_version: u32,
    effective_uid: u32,
    shell_pid: u32,
    shell_start_fingerprint: String,
    family: ShellHookFamily,
    session_id: String,
    tirith_executable: TirithExecutableIdentity,
    secret_sha256: String,
    capability_seal_sha256: String,
    created_unix_ms: u64,
}

#[cfg(unix)]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case", deny_unknown_fields)]
enum ShellHookCapabilityAnchorState {
    Prepared {
        created_unix_ms: u64,
    },
    Issued {
        capability_binding_sha256: String,
        capability_device: u64,
        capability_inode: u64,
        issued_unix_ms: u64,
    },
}

#[cfg(unix)]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ShellHookCapabilityAnchor {
    schema_version: u32,
    effective_uid: u32,
    shell_pid: u32,
    shell_start_fingerprint: String,
    state: ShellHookCapabilityAnchorState,
}

struct LockedReceipt {
    _lock_file: File,
    token: String,
    receipt_path: PathBuf,
    receipt_identity: FileIdentity,
    receipt: ShellReceipt,
}

#[cfg(not(unix))]
fn path_identity(_path: &Path, _label: &str) -> Result<FileIdentity, String> {
    Err("strict shell execution receipts are unsupported on this platform".to_string())
}

#[cfg(not(unix))]
fn secure_regular_identity(_file: &File, _label: &str) -> Result<FileIdentity, String> {
    Err("strict shell execution receipts are unsupported on this platform".to_string())
}

impl LockedReceipt {
    fn publish(&mut self) -> Result<(), String> {
        refresh_receipt_seals(&mut self.receipt, &self.token)?;
        validate_receipt(&self.receipt, &self.token)?;
        publish_receipt(
            &self.receipt_path,
            Some(self.receipt_identity),
            &self.receipt,
        )?;
        self.receipt_identity = path_identity(&self.receipt_path, "shell receipt")?;
        Ok(())
    }
}

fn digest_is_valid(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

fn validate_token(token: &str) -> Result<(), String> {
    if !digest_is_valid(token) {
        return Err("shell execution receipt token must be 256-bit lowercase hex".to_string());
    }
    Ok(())
}

fn token_sha256(token: &str) -> String {
    sha256_hex(token.as_bytes())
}

fn hex_lower(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        encoded.push(HEX[(byte >> 4) as usize] as char);
        encoded.push(HEX[(byte & 0x0f) as usize] as char);
    }
    encoded
}

fn current_hook_instance(
    expected_channel: ShellReceiptChannel,
    expected_session_id: &str,
) -> Result<String, String> {
    let instance = std::env::var("_TIRITH_RECEIPT_INSTANCE")
        .map_err(|_| "shell receipt invocation lacks its hook instance".to_string())?;
    validate_token(&instance)
        .map_err(|_| "shell receipt hook instance must be 256-bit lowercase hex".to_string())?;
    let shell_pid = std::env::var("_TIRITH_RECEIPT_SHELL_PID")
        .map_err(|_| "shell receipt invocation lacks its registered shell PID".to_string())?
        .parse::<u32>()
        .map_err(|_| "shell receipt shell PID is invalid".to_string())?;
    let family =
        ShellHookFamily::parse(&std::env::var("_TIRITH_RECEIPT_FAMILY").map_err(|_| {
            "shell receipt invocation lacks its registered shell family".to_string()
        })?)?;
    if family != expected_channel.hook_family()? {
        return Err("shell receipt hook family does not match its channel".to_string());
    }
    validate_shell_hook_instance(&instance, shell_pid, family, expected_session_id)?;
    Ok(instance)
}

#[cfg(unix)]
fn current_cwd_binding_sha256(token: &str) -> Result<String, String> {
    use std::os::unix::ffi::OsStrExt as _;

    let cwd = std::env::current_dir()
        .map_err(|error| format!("resolve shell receipt working directory: {error}"))?;
    Ok(secret_seal(
        token,
        "tirith-shell-cwd-binding-v1",
        &serde_json::Value::String(hex::encode(cwd.as_os_str().as_bytes())),
    ))
}

#[cfg(not(unix))]
fn current_cwd_binding_sha256(token: &str) -> Result<String, String> {
    let cwd = std::env::current_dir()
        .map_err(|error| format!("resolve shell receipt working directory: {error}"))?;
    Ok(secret_seal(
        token,
        "tirith-shell-cwd-binding-v1",
        &serde_json::Value::String(cwd.to_string_lossy().into_owned()),
    ))
}

fn immutable_receipt_identity(receipt: &ShellReceipt) -> serde_json::Value {
    let mut identity = serde_json::json!({
        "schema_version": receipt.schema_version,
        "token_sha256": receipt.token_sha256,
        "execution_id": receipt.execution_id,
        "session_id": receipt.session_id,
        "shell": receipt.shell,
        "channel": receipt.channel,
        "hook_instance_sha256": receipt.hook_instance_sha256,
        "command_sha256": receipt.command_sha256,
        "command_redacted_preview": receipt.command_redacted_preview,
        "decision_binding_sha256": receipt.decision_binding_sha256,
        "policy_basis_sha256": receipt.policy_basis_sha256,
        "semantic_verdict_basis_sha256": receipt.semantic_verdict_basis_sha256,
        "action": receipt.action,
        "bypass_honored": receipt.bypass_honored,
        "requires_approval": receipt.requires_approval,
        "requires_warn_ack": receipt.requires_warn_ack,
        "approval_fallback": receipt.approval_fallback,
        "interactive": receipt.interactive,
        "strict_warn_override": receipt.strict_warn_override,
        "created_unix_ms": receipt.created_unix_ms,
        "expires_unix_ms": receipt.expires_unix_ms,
    });
    let identity_object = identity
        .as_object_mut()
        .expect("static receipt identity is an object");
    if let Some(digest) = &receipt.cwd_sha256 {
        identity_object.insert(
            "cwd_sha256".to_string(),
            serde_json::Value::String(digest.clone()),
        );
    }
    if let Some(binding) = &receipt.cwd_binding_sha256 {
        identity_object.insert(
            "cwd_binding_sha256".to_string(),
            serde_json::Value::String(binding.clone()),
        );
    }
    if let Some(binding) = &receipt.command_binding_sha256 {
        identity_object.insert(
            "command_binding_sha256".to_string(),
            serde_json::Value::String(binding.clone()),
        );
    }
    identity
}

fn secret_seal(token: &str, domain: &str, value: &serde_json::Value) -> String {
    let canonical = crate::audit::canonical_json_for_hash(value);
    sha256_hex(format!("{domain}\0{token}\0{canonical}").as_bytes())
}

#[cfg(unix)]
#[derive(Debug)]
enum ShellProcessLookupError {
    Missing,
    Rejected(String),
}

#[cfg(unix)]
fn validate_shell_pid(shell_pid: u32) -> Result<libc::pid_t, String> {
    if shell_pid <= 1 || shell_pid > libc::pid_t::MAX as u32 {
        return Err("shell receipt registration has an invalid shell PID".to_string());
    }
    Ok(shell_pid as libc::pid_t)
}

#[cfg(target_os = "linux")]
fn read_linux_process_file(path: &Path, cap: u64) -> Result<String, ShellProcessLookupError> {
    use std::os::unix::fs::OpenOptionsExt as _;

    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
        .open(path)
        .map_err(|error| {
            if error.kind() == std::io::ErrorKind::NotFound {
                ShellProcessLookupError::Missing
            } else {
                ShellProcessLookupError::Rejected(format!(
                    "inspect registered shell process: {error}"
                ))
            }
        })?;
    let mut bytes = Vec::new();
    file.take(cap + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| {
            ShellProcessLookupError::Rejected(format!("read registered shell process: {error}"))
        })?;
    if bytes.is_empty() || bytes.len() as u64 > cap {
        return Err(ShellProcessLookupError::Rejected(
            "registered shell process identity is empty or oversized".to_string(),
        ));
    }
    String::from_utf8(bytes).map_err(|_| {
        ShellProcessLookupError::Rejected(
            "registered shell process identity is not UTF-8".to_string(),
        )
    })
}

#[cfg(target_os = "linux")]
fn linux_process_start(path: &Path) -> Result<(char, String), ShellProcessLookupError> {
    let stat = read_linux_process_file(path, 8 * 1024)?;
    let command_end = stat.rfind(')').ok_or_else(|| {
        ShellProcessLookupError::Rejected(
            "registered shell process stat record is malformed".to_string(),
        )
    })?;
    let fields: Vec<&str> = stat[command_end + 1..].split_whitespace().collect();
    if fields.len() <= 19 {
        return Err(ShellProcessLookupError::Rejected(
            "registered shell process stat record is truncated".to_string(),
        ));
    }
    let state = fields[0].chars().next().ok_or_else(|| {
        ShellProcessLookupError::Rejected("registered shell process state is missing".to_string())
    })?;
    let start_ticks = fields[19];
    if start_ticks.is_empty() || !start_ticks.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(ShellProcessLookupError::Rejected(
            "registered shell process start identity is malformed".to_string(),
        ));
    }
    Ok((state, start_ticks.to_string()))
}

#[cfg(target_os = "linux")]
fn shell_process_identity(shell_pid: u32) -> Result<ShellProcessIdentity, ShellProcessLookupError> {
    validate_shell_pid(shell_pid).map_err(ShellProcessLookupError::Rejected)?;
    let process_root = PathBuf::from(format!("/proc/{shell_pid}"));
    let stat_path = process_root.join("stat");
    let (first_state, first_start) = linux_process_start(&stat_path)?;
    if first_state == 'Z' || first_state == 'X' {
        return Err(ShellProcessLookupError::Missing);
    }

    let status = read_linux_process_file(&process_root.join("status"), 64 * 1024)?;
    let effective_uid = status
        .lines()
        .find_map(|line| line.strip_prefix("Uid:"))
        .and_then(|uids| uids.split_whitespace().nth(1))
        .and_then(|uid| uid.parse::<u32>().ok())
        .ok_or_else(|| {
            ShellProcessLookupError::Rejected(
                "registered shell process effective UID is malformed".to_string(),
            )
        })?;

    let boot_id = read_linux_process_file(Path::new("/proc/sys/kernel/random/boot_id"), 256)?;
    let boot_id = boot_id.trim();
    if boot_id.is_empty()
        || boot_id.len() > 64
        || !boot_id
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() || byte == b'-')
    {
        return Err(ShellProcessLookupError::Rejected(
            "Linux boot identity is malformed".to_string(),
        ));
    }

    let (second_state, second_start) = linux_process_start(&stat_path)?;
    if second_state == 'Z' || second_state == 'X' || second_start != first_start {
        return Err(ShellProcessLookupError::Missing);
    }
    Ok(ShellProcessIdentity {
        effective_uid,
        start_fingerprint: format!("linux:{boot_id}:{first_start}"),
    })
}

#[cfg(target_os = "macos")]
fn shell_process_identity(shell_pid: u32) -> Result<ShellProcessIdentity, ShellProcessLookupError> {
    let pid = validate_shell_pid(shell_pid).map_err(ShellProcessLookupError::Rejected)?;
    let mut info = std::mem::MaybeUninit::<libc::proc_bsdinfo>::zeroed();
    let expected = std::mem::size_of::<libc::proc_bsdinfo>();
    let read = unsafe {
        libc::proc_pidinfo(
            pid,
            libc::PROC_PIDTBSDINFO,
            0,
            info.as_mut_ptr().cast(),
            expected as libc::c_int,
        )
    };
    if read == 0 {
        let error = std::io::Error::last_os_error();
        return if error.raw_os_error() == Some(libc::ESRCH)
            || error.kind() == std::io::ErrorKind::NotFound
        {
            Err(ShellProcessLookupError::Missing)
        } else {
            Err(ShellProcessLookupError::Rejected(format!(
                "inspect registered shell process: {error}"
            )))
        };
    }
    if read != expected as libc::c_int {
        return Err(ShellProcessLookupError::Rejected(
            "registered shell process identity is truncated".to_string(),
        ));
    }
    let info = unsafe { info.assume_init() };
    if info.pbi_pid != shell_pid || info.pbi_status == libc::SZOMB {
        return Err(ShellProcessLookupError::Missing);
    }
    Ok(ShellProcessIdentity {
        effective_uid: info.pbi_uid,
        start_fingerprint: format!("macos:{}:{}", info.pbi_start_tvsec, info.pbi_start_tvusec),
    })
}

#[cfg(all(unix, not(any(target_os = "linux", target_os = "macos"))))]
fn shell_process_identity(
    _shell_pid: u32,
) -> Result<ShellProcessIdentity, ShellProcessLookupError> {
    Err(ShellProcessLookupError::Rejected(
        "protocol-v3 shell receipt registration is unsupported on this Unix platform".to_string(),
    ))
}

#[cfg(unix)]
fn current_tirith_executable_identity() -> Result<TirithExecutableIdentity, String> {
    use std::os::unix::fs::{MetadataExt as _, OpenOptionsExt as _};

    let path = std::env::current_exe()
        .map_err(|error| format!("resolve current Tirith executable: {error}"))?;
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
        .open(&path)
        .map_err(|error| format!("open current Tirith executable: {error}"))?;
    let metadata = file
        .metadata()
        .map_err(|error| format!("inspect current Tirith executable: {error}"))?;
    if !metadata.is_file() {
        return Err("current Tirith executable is not a regular file".to_string());
    }
    let euid = unsafe { libc::geteuid() };
    if metadata.uid() != euid && metadata.uid() != 0 {
        return Err("current Tirith executable has an untrusted owner".to_string());
    }
    if metadata.mode() & 0o022 != 0 || metadata.mode() & 0o111 == 0 {
        return Err(
            "current Tirith executable is writable by group/other or is not executable".to_string(),
        );
    }
    let path_metadata = fs::symlink_metadata(&path)
        .map_err(|error| format!("inspect current Tirith executable path: {error}"))?;
    if path_metadata.file_type().is_symlink()
        || !path_metadata.is_file()
        || path_metadata.dev() != metadata.dev()
        || path_metadata.ino() != metadata.ino()
    {
        return Err("current Tirith executable path changed while inspected".to_string());
    }
    Ok(TirithExecutableIdentity {
        device: metadata.dev(),
        inode: metadata.ino(),
        size: metadata.size(),
        owner_uid: metadata.uid(),
        mode: metadata.mode(),
        modified_seconds: metadata.mtime(),
        modified_nanoseconds: metadata.mtime_nsec(),
        changed_seconds: metadata.ctime(),
        changed_nanoseconds: metadata.ctime_nsec(),
    })
}

#[cfg(unix)]
fn capability_identity(capability: &ShellHookCapability) -> serde_json::Value {
    serde_json::json!({
        "schema_version": capability.schema_version,
        "effective_uid": capability.effective_uid,
        "shell_pid": capability.shell_pid,
        "shell_start_fingerprint": capability.shell_start_fingerprint,
        "family": capability.family,
        "session_id": capability.session_id,
        "tirith_executable": capability.tirith_executable,
        "secret_sha256": capability.secret_sha256,
        "created_unix_ms": capability.created_unix_ms,
    })
}

#[cfg(unix)]
fn refresh_capability_seal(capability: &mut ShellHookCapability, secret: &str) {
    capability.capability_seal_sha256 = secret_seal(
        secret,
        "tirith-shell-hook-capability-v3",
        &capability_identity(capability),
    );
}

#[cfg(unix)]
fn capability_record_binding_sha256(capability: &ShellHookCapability) -> String {
    let canonical = crate::audit::canonical_json_for_hash(&serde_json::json!({
        "identity": capability_identity(capability),
        "capability_seal_sha256": capability.capability_seal_sha256,
    }));
    sha256_hex(canonical.as_bytes())
}

#[cfg(unix)]
fn prepared_capability_anchor(
    effective_uid: u32,
    shell_pid: u32,
    shell_start_fingerprint: &str,
) -> Result<ShellHookCapabilityAnchor, String> {
    Ok(ShellHookCapabilityAnchor {
        schema_version: HOOK_CAPABILITY_ANCHOR_SCHEMA_VERSION,
        effective_uid,
        shell_pid,
        shell_start_fingerprint: shell_start_fingerprint.to_string(),
        state: ShellHookCapabilityAnchorState::Prepared {
            created_unix_ms: unix_time_ms()?,
        },
    })
}

#[cfg(unix)]
fn validate_capability_anchor_process(
    anchor: &ShellHookCapabilityAnchor,
    effective_uid: u32,
    shell_pid: u32,
    shell_start_fingerprint: &str,
) -> Result<(), String> {
    if anchor.schema_version != HOOK_CAPABILITY_ANCHOR_SCHEMA_VERSION {
        return Err("shell hook capability anchor schema is unsupported".to_string());
    }
    if anchor.effective_uid != effective_uid
        || anchor.shell_pid != shell_pid
        || anchor.shell_start_fingerprint != shell_start_fingerprint
    {
        return Err("shell hook capability anchor process identity changed".to_string());
    }
    Ok(())
}

#[cfg(unix)]
fn issued_capability_anchor(
    prepared: &ShellHookCapabilityAnchor,
    capability: &ShellHookCapability,
    capability_file_identity: FileIdentity,
) -> Result<ShellHookCapabilityAnchor, String> {
    validate_capability_anchor_process(
        prepared,
        capability.effective_uid,
        capability.shell_pid,
        &capability.shell_start_fingerprint,
    )?;
    if !matches!(
        &prepared.state,
        ShellHookCapabilityAnchorState::Prepared { .. }
    ) {
        return Err("shell hook capability anchor was already issued".to_string());
    }
    Ok(ShellHookCapabilityAnchor {
        schema_version: HOOK_CAPABILITY_ANCHOR_SCHEMA_VERSION,
        effective_uid: prepared.effective_uid,
        shell_pid: prepared.shell_pid,
        shell_start_fingerprint: prepared.shell_start_fingerprint.clone(),
        state: ShellHookCapabilityAnchorState::Issued {
            capability_binding_sha256: capability_record_binding_sha256(capability),
            capability_device: capability_file_identity.device,
            capability_inode: capability_file_identity.inode,
            issued_unix_ms: unix_time_ms()?,
        },
    })
}

#[cfg(unix)]
fn validate_issued_capability_anchor(
    anchor: &ShellHookCapabilityAnchor,
    capability: &ShellHookCapability,
    capability_file_identity: FileIdentity,
) -> Result<(), String> {
    validate_capability_anchor_process(
        anchor,
        capability.effective_uid,
        capability.shell_pid,
        &capability.shell_start_fingerprint,
    )?;
    let ShellHookCapabilityAnchorState::Issued {
        capability_binding_sha256,
        capability_device,
        capability_inode,
        ..
    } = &anchor.state
    else {
        return Err("shell hook capability anchor was not durably issued".to_string());
    };
    if !digest_is_valid(capability_binding_sha256)
        || capability_binding_sha256 != &capability_record_binding_sha256(capability)
        || *capability_device != capability_file_identity.device
        || *capability_inode != capability_file_identity.inode
    {
        return Err("shell hook capability anchor does not match its issued record".to_string());
    }
    Ok(())
}

#[cfg(unix)]
fn capability_key(effective_uid: u32, shell_pid: u32, shell_start_fingerprint: &str) -> String {
    sha256_hex(
        format!(
            "tirith-shell-hook-process-v3\0{effective_uid}\0{shell_pid}\0{shell_start_fingerprint}"
        )
        .as_bytes(),
    )
}

#[cfg(unix)]
fn capability_paths(
    effective_uid: u32,
    shell_pid: u32,
    shell_start_fingerprint: &str,
) -> Result<(PathBuf, PathBuf), String> {
    let directory = receipt_directory()?;
    // The anchor is intentionally process-scoped, rather than session-scoped.
    // A nested interactive shell normally inherits TIRITH_SESSION_ID, but it
    // has a different PID/start identity and therefore receives an independent
    // one-time bearer. Family, session, and executable remain sealed inside the
    // single record for this process so changing any of them cannot mint a
    // second bearer for the same live shell. An in-place `exec` deliberately
    // remains the same one-time identity: because the bearer is non-exported,
    // replacing a shell must use a new process rather than `exec $SHELL`.
    let key = capability_key(effective_uid, shell_pid, shell_start_fingerprint);
    Ok((
        directory.join(format!(".hook-{key}.capability")),
        directory.join(format!(".hook-{key}.capability.lock")),
    ))
}

#[cfg(unix)]
fn lock_capability_file_for(file: &File, timeout: Duration) -> Result<(), String> {
    let deadline = Instant::now()
        .checked_add(timeout)
        .ok_or_else(|| "shell hook capability lock deadline overflowed".to_string())?;
    loop {
        match file.try_lock_exclusive() {
            Ok(()) => return Ok(()),
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                if Instant::now() >= deadline {
                    return Err("timed out acquiring shell hook capability lock".to_string());
                }
                std::thread::sleep(Duration::from_millis(5));
            }
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(format!("lock shell hook capability: {error}")),
        }
    }
}

#[cfg(unix)]
fn lock_capability_file(file: &File) -> Result<(), String> {
    lock_capability_file_for(file, RECEIPT_LOCK_TIMEOUT)
}

#[cfg(unix)]
fn read_capability_anchor(file: &File) -> Result<ShellHookCapabilityAnchor, String> {
    let length = file
        .metadata()
        .map_err(|error| format!("inspect shell hook capability anchor: {error}"))?
        .len();
    if length == 0 || length > HOOK_CAPABILITY_ANCHOR_FILE_CAP {
        return Err("shell hook capability anchor is empty or oversized".to_string());
    }
    let mut reader = file;
    reader
        .seek(SeekFrom::Start(0))
        .map_err(|error| format!("seek shell hook capability anchor: {error}"))?;
    let mut bytes = Vec::with_capacity(length as usize);
    reader
        .take(HOOK_CAPABILITY_ANCHOR_FILE_CAP + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| format!("read shell hook capability anchor: {error}"))?;
    if bytes.len() as u64 > HOOK_CAPABILITY_ANCHOR_FILE_CAP {
        return Err("shell hook capability anchor grew beyond its size limit".to_string());
    }
    serde_json::from_slice(&bytes)
        .map_err(|error| format!("parse shell hook capability anchor: {error}"))
}

#[cfg(unix)]
fn publish_capability_anchor(
    path: &Path,
    file: &File,
    expected_identity: FileIdentity,
    anchor: &ShellHookCapabilityAnchor,
) -> Result<(), String> {
    let bytes = serde_json::to_vec(anchor)
        .map_err(|error| format!("serialize shell hook capability anchor: {error}"))?;
    if bytes.is_empty() || bytes.len() as u64 > HOOK_CAPABILITY_ANCHOR_FILE_CAP {
        return Err("serialized shell hook capability anchor exceeds its size limit".to_string());
    }
    if path_identity(path, "shell hook capability anchor")? != expected_identity
        || secure_regular_identity(file, "shell hook capability anchor")? != expected_identity
    {
        return Err("shell hook capability anchor changed before publication".to_string());
    }
    file.set_len(0)
        .map_err(|error| format!("truncate shell hook capability anchor: {error}"))?;
    let mut writer = file;
    writer
        .seek(SeekFrom::Start(0))
        .map_err(|error| format!("seek shell hook capability anchor: {error}"))?;
    writer
        .write_all(&bytes)
        .map_err(|error| format!("write shell hook capability anchor: {error}"))?;
    file.sync_all()
        .map_err(|error| format!("sync shell hook capability anchor: {error}"))?;
    if path_identity(path, "shell hook capability anchor")? != expected_identity
        || secure_regular_identity(file, "shell hook capability anchor")? != expected_identity
    {
        return Err("shell hook capability anchor changed during publication".to_string());
    }
    Ok(())
}

#[cfg(unix)]
fn create_capability_anchor(
    path: &Path,
    prepared: &ShellHookCapabilityAnchor,
) -> Result<File, String> {
    use std::os::unix::fs::OpenOptionsExt as _;

    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)
        .map_err(|error| {
            if error.kind() == std::io::ErrorKind::AlreadyExists {
                "shell hook process already has a protocol-v3 registration".to_string()
            } else {
                format!("create shell hook capability anchor: {error}")
            }
        })?;
    let identity = secure_regular_identity(&file, "shell hook capability anchor")?;
    lock_capability_file(&file)?;
    if path_identity(path, "shell hook capability anchor")? != identity {
        return Err("shell hook capability anchor changed while locked".to_string());
    }
    publish_capability_anchor(path, &file, identity, prepared)?;
    crate::util::fsync_parent_dir(path)
        .map_err(|error| format!("sync shell hook capability anchor directory: {error}"))?;
    Ok(file)
}

#[cfg(unix)]
fn open_capability_anchor(path: &Path) -> Result<File, String> {
    open_capability_anchor_for(path, RECEIPT_LOCK_TIMEOUT)
}

#[cfg(unix)]
fn open_capability_anchor_for(path: &Path, timeout: Duration) -> Result<File, String> {
    use std::os::unix::fs::OpenOptionsExt as _;

    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)
        .map_err(|error| format!("open shell hook capability anchor: {error}"))?;
    secure_regular_identity(&file, "shell hook capability anchor")?;
    lock_capability_file_for(&file, timeout)?;
    if path_identity(path, "shell hook capability anchor")?
        != secure_regular_identity(&file, "shell hook capability anchor")?
    {
        return Err("shell hook capability anchor changed while locked".to_string());
    }
    Ok(file)
}

#[cfg(unix)]
fn open_or_create_capability_anchor(
    path: &Path,
    prepared: &ShellHookCapabilityAnchor,
) -> Result<(File, ShellHookCapabilityAnchor), String> {
    match create_capability_anchor(path, prepared) {
        Ok(file) => Ok((file, prepared.clone())),
        Err(error) if error.contains("already has a protocol-v3 registration") => {
            // Registry locking prevents a concurrent creator from reaching this
            // branch. A surviving Prepared marker is therefore a registration
            // that failed before returning a bearer and can be resumed under
            // the same inode lock. Issued and malformed markers stay terminal.
            let file = open_capability_anchor(path)?;
            let anchor = read_capability_anchor(&file)?;
            validate_capability_anchor_process(
                &anchor,
                prepared.effective_uid,
                prepared.shell_pid,
                &prepared.shell_start_fingerprint,
            )?;
            Ok((file, anchor))
        }
        Err(error) => Err(error),
    }
}

#[cfg(unix)]
fn open_capability_registry_lock(directory: &Path) -> Result<File, String> {
    use std::os::unix::fs::{MetadataExt as _, OpenOptionsExt as _};

    // The receipt directory is already a durable, owner-only identity shared
    // by every capability operation. Lock that inode directly instead of
    // creating a persistent registry-lock pathname before any bearer has been
    // delivered. Invalid bearer lookups can therefore remain entirely
    // non-mutating while registration keeps the same cross-process exclusion.
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(directory)
        .map_err(|error| format!("open shell hook capability registry directory: {error}"))?;
    let metadata = file
        .metadata()
        .map_err(|error| format!("inspect shell hook capability registry directory: {error}"))?;
    if !metadata.is_dir()
        || metadata.uid() != unsafe { libc::geteuid() }
        || metadata.mode() & 0o777 != 0o700
    {
        return Err(
            "shell hook capability registry directory is not owner-only mode 0700".to_string(),
        );
    }
    let identity = FileIdentity {
        device: metadata.dev(),
        inode: metadata.ino(),
    };
    lock_capability_file(&file)?;
    let path_metadata = fs::symlink_metadata(directory).map_err(|error| {
        format!("inspect shell hook capability registry directory path: {error}")
    })?;
    if path_metadata.file_type().is_symlink()
        || !path_metadata.is_dir()
        || path_metadata.uid() != unsafe { libc::geteuid() }
        || path_metadata.mode() & 0o777 != 0o700
        || path_metadata.dev() != identity.device
        || path_metadata.ino() != identity.inode
    {
        return Err("shell hook capability registry directory changed while locked".to_string());
    }
    Ok(file)
}

#[cfg(unix)]
fn read_capability(path: &Path) -> Result<(ShellHookCapability, FileIdentity), String> {
    use std::os::unix::fs::OpenOptionsExt as _;

    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
        .open(path)
        .map_err(|error| format!("open shell hook capability: {error}"))?;
    let identity = secure_regular_identity(&file, "shell hook capability")?;
    let length = file
        .metadata()
        .map_err(|error| format!("inspect shell hook capability: {error}"))?
        .len();
    if length == 0 || length > HOOK_CAPABILITY_FILE_CAP {
        return Err("shell hook capability is empty or oversized".to_string());
    }
    let mut bytes = Vec::with_capacity(length as usize);
    file.take(HOOK_CAPABILITY_FILE_CAP + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| format!("read shell hook capability: {error}"))?;
    if bytes.len() as u64 > HOOK_CAPABILITY_FILE_CAP {
        return Err("shell hook capability grew beyond its size limit".to_string());
    }
    let capability = serde_json::from_slice(&bytes)
        .map_err(|error| format!("parse shell hook capability: {error}"))?;
    Ok((capability, identity))
}

#[cfg(unix)]
fn publish_capability(path: &Path, capability: &ShellHookCapability) -> Result<(), String> {
    use std::os::unix::fs::OpenOptionsExt as _;

    match fs::symlink_metadata(path) {
        Ok(_) => return Err("shell hook capability path already exists".to_string()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(format!("inspect shell hook capability path: {error}")),
    }
    let bytes = serde_json::to_vec(capability)
        .map_err(|error| format!("serialize shell hook capability: {error}"))?;
    if bytes.is_empty() || bytes.len() as u64 > HOOK_CAPABILITY_FILE_CAP {
        return Err("serialized shell hook capability exceeds its size limit".to_string());
    }
    let parent = path
        .parent()
        .ok_or_else(|| "shell hook capability path has no parent".to_string())?;
    let temporary = parent.join(format!(
        ".hook-capability-{}.tmp",
        uuid::Uuid::new_v4().simple()
    ));
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(&temporary)
        .map_err(|error| format!("create shell hook capability temp file: {error}"))?;
    let result = (|| {
        let identity = secure_regular_identity(&file, "shell hook capability temp file")?;
        file.write_all(&bytes)
            .map_err(|error| format!("write shell hook capability temp file: {error}"))?;
        file.sync_all()
            .map_err(|error| format!("sync shell hook capability temp file: {error}"))?;
        fs::rename(&temporary, path)
            .map_err(|error| format!("publish shell hook capability: {error}"))?;
        if path_identity(path, "shell hook capability")? != identity {
            return Err(
                "published shell hook capability does not identify its temp file".to_string(),
            );
        }
        crate::util::fsync_parent_dir(path)
            .map_err(|error| format!("sync shell hook capability directory: {error}"))
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    result
}

#[cfg(unix)]
fn validate_capability_session(session_id: &str) -> Result<(), String> {
    if crate::session_warnings::session_state_path(session_id).is_none() {
        return Err("shell hook capability has an invalid session id".to_string());
    }
    if crate::session::resolve_session_id() != session_id {
        return Err("shell hook capability belongs to a different session".to_string());
    }
    Ok(())
}

#[cfg(unix)]
fn validate_capability_record(
    capability: &ShellHookCapability,
    secret: &str,
    shell_pid: u32,
    family: ShellHookFamily,
    session_id: &str,
    shell_identity: &ShellProcessIdentity,
    executable_identity: &TirithExecutableIdentity,
) -> Result<(), String> {
    if capability.schema_version != HOOK_CAPABILITY_SCHEMA_VERSION {
        return Err("shell hook capability schema is unsupported".to_string());
    }
    if capability.effective_uid != unsafe { libc::geteuid() }
        || capability.effective_uid != shell_identity.effective_uid
        || capability.shell_pid != shell_pid
        || capability.shell_start_fingerprint != shell_identity.start_fingerprint
    {
        return Err("shell hook capability process identity changed".to_string());
    }
    if capability.family != family {
        return Err("shell hook capability belongs to a different shell family".to_string());
    }
    if capability.session_id != session_id {
        return Err("shell hook capability belongs to a different session".to_string());
    }
    if &capability.tirith_executable != executable_identity {
        return Err("shell hook capability belongs to a different Tirith executable".to_string());
    }
    if !digest_is_valid(&capability.secret_sha256)
        || !digest_is_valid(&capability.capability_seal_sha256)
        || capability.secret_sha256 != sha256_hex(secret.as_bytes())
    {
        return Err("shell hook capability secret is invalid".to_string());
    }
    let expected_seal = secret_seal(
        secret,
        "tirith-shell-hook-capability-v3",
        &capability_identity(capability),
    );
    if capability.capability_seal_sha256 != expected_seal {
        return Err("shell hook capability seal is invalid".to_string());
    }
    Ok(())
}

#[cfg(unix)]
fn hook_capability_key(name: &str) -> Option<&str> {
    let key = name.strip_prefix(".hook-")?.strip_suffix(".capability")?;
    (key.len() == 64
        && key
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase()))
    .then_some(key)
}

#[cfg(unix)]
fn hook_capability_lock_key(name: &str) -> Option<&str> {
    let key = name
        .strip_prefix(".hook-")?
        .strip_suffix(".capability.lock")?;
    (key.len() == 64
        && key
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase()))
    .then_some(key)
}

#[cfg(unix)]
fn capability_process_is_stale(capability: &ShellHookCapability) -> bool {
    capability_process_binding_is_stale(
        capability.effective_uid,
        capability.shell_pid,
        &capability.shell_start_fingerprint,
    )
}

#[cfg(unix)]
fn capability_anchor_process_is_stale(anchor: &ShellHookCapabilityAnchor) -> bool {
    capability_process_binding_is_stale(
        anchor.effective_uid,
        anchor.shell_pid,
        &anchor.shell_start_fingerprint,
    )
}

#[cfg(unix)]
fn capability_process_binding_is_stale(
    effective_uid: u32,
    shell_pid: u32,
    shell_start_fingerprint: &str,
) -> bool {
    match shell_process_identity(shell_pid) {
        Err(ShellProcessLookupError::Missing) => true,
        Err(ShellProcessLookupError::Rejected(_)) => false,
        Ok(identity) => {
            identity.effective_uid != effective_uid
                || identity.start_fingerprint != shell_start_fingerprint
        }
    }
}

#[cfg(unix)]
fn capability_key_matches_record(key: &str, capability: &ShellHookCapability) -> bool {
    capability.schema_version == HOOK_CAPABILITY_SCHEMA_VERSION
        && key
            == capability_key(
                capability.effective_uid,
                capability.shell_pid,
                &capability.shell_start_fingerprint,
            )
}

#[cfg(unix)]
fn capability_key_matches_anchor(key: &str, anchor: &ShellHookCapabilityAnchor) -> bool {
    anchor.schema_version == HOOK_CAPABILITY_ANCHOR_SCHEMA_VERSION
        && key
            == capability_key(
                anchor.effective_uid,
                anchor.shell_pid,
                &anchor.shell_start_fingerprint,
            )
}

#[cfg(unix)]
fn remove_capability_pair_locked(
    capability_path: &Path,
    capability_identity: FileIdentity,
    anchor_path: &Path,
    anchor: &File,
) -> Result<(), String> {
    if path_identity(capability_path, "stale shell hook capability")? != capability_identity {
        return Err("stale shell hook capability changed while locked".to_string());
    }
    let anchor_identity = secure_regular_identity(anchor, "stale shell hook capability anchor")?;
    if path_identity(anchor_path, "stale shell hook capability anchor")? != anchor_identity {
        return Err("stale shell hook capability anchor changed while locked".to_string());
    }
    fs::remove_file(capability_path)
        .map_err(|error| format!("remove stale shell hook capability: {error}"))?;
    fs::remove_file(anchor_path)
        .map_err(|error| format!("remove stale shell hook capability anchor: {error}"))?;
    crate::util::fsync_parent_dir(anchor_path)
        .map_err(|error| format!("sync stale shell hook capability removal: {error}"))
}

#[cfg(unix)]
fn remove_orphan_capability_anchor(anchor_path: &Path, anchor: &File) -> Result<(), String> {
    let anchor_identity = secure_regular_identity(anchor, "orphan shell hook capability anchor")?;
    if path_identity(anchor_path, "orphan shell hook capability anchor")? != anchor_identity {
        return Err("orphan shell hook capability anchor changed while locked".to_string());
    }
    fs::remove_file(anchor_path)
        .map_err(|error| format!("remove orphan shell hook capability anchor: {error}"))?;
    crate::util::fsync_parent_dir(anchor_path)
        .map_err(|error| format!("sync orphan shell hook capability anchor removal: {error}"))
}

#[cfg(unix)]
fn cleanup_hook_capabilities_locked(directory: &Path) -> Result<(), String> {
    // Callers hold the registry lock before this function takes any process
    // anchor. This fixed registry -> process-anchor order is also used by
    // registration, so cleanup cannot deadlock a concurrent publisher.
    // Unreadable or malformed state is retained fail-closed.
    let entries = fs::read_dir(directory)
        .map_err(|error| format!("scan shell hook capabilities: {error}"))?;
    for entry in entries {
        let entry = entry.map_err(|error| format!("read shell hook capability entry: {error}"))?;
        let path = entry.path();
        let Some(name) = path.file_name().and_then(|name| name.to_str()) else {
            continue;
        };
        let Some(key) = hook_capability_key(name) else {
            continue;
        };
        let anchor_path = directory.join(format!(".hook-{key}.capability.lock"));
        let Ok((capability, capability_identity)) = read_capability(&path) else {
            continue;
        };
        if path_identity(&path, "shell hook capability cleanup")? != capability_identity
            || !capability_key_matches_record(key, &capability)
        {
            continue;
        }
        let anchor_missing = match fs::symlink_metadata(&anchor_path) {
            Ok(_) => false,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => true,
            Err(_) => continue,
        };
        if anchor_missing {
            // A published capability without its anchor cannot be validated by
            // any caller. Remove it only when its self-consistent path identity
            // names a process that is now definitely stale.
            if !capability_process_is_stale(&capability) {
                continue;
            }
            if path_identity(&path, "orphan stale shell hook capability")? != capability_identity {
                continue;
            }
            fs::remove_file(&path)
                .map_err(|error| format!("remove orphan stale shell hook capability: {error}"))?;
            crate::util::fsync_parent_dir(&path).map_err(|error| {
                format!("sync orphan stale shell hook capability removal: {error}")
            })?;
            continue;
        }
        let Ok(anchor) = open_capability_anchor_for(&anchor_path, Duration::from_millis(1)) else {
            continue;
        };
        let Ok(anchor_record) = read_capability_anchor(&anchor) else {
            continue;
        };
        if !capability_key_matches_anchor(key, &anchor_record) {
            continue;
        }
        let Ok((current, current_identity)) = read_capability(&path) else {
            continue;
        };
        if current_identity != capability_identity
            || path_identity(&path, "shell hook capability cleanup")? != current_identity
            || !capability_key_matches_record(key, &current)
        {
            continue;
        }
        let remove = match &anchor_record.state {
            ShellHookCapabilityAnchorState::Prepared { .. } => {
                // Publication may have completed, but a bearer is returned only
                // after this marker is durably advanced to Issued.
                validate_capability_anchor_process(
                    &anchor_record,
                    current.effective_uid,
                    current.shell_pid,
                    &current.shell_start_fingerprint,
                )
                .is_ok()
            }
            ShellHookCapabilityAnchorState::Issued { .. } => {
                validate_issued_capability_anchor(&anchor_record, &current, current_identity)
                    .is_ok()
                    && capability_process_is_stale(&current)
            }
        };
        if remove {
            remove_capability_pair_locked(&path, current_identity, &anchor_path, &anchor)?;
        }
        drop(anchor);
    }

    // An orphan Prepared marker proves no bearer was returned, but remains while
    // its process is live so that registration can resume under the same inode.
    // Issued is the durable one-time tombstone. Either marker is retired only
    // once its exact process identity is definitely stale; missing/malformed
    // markers are retained fail-closed.
    let entries = fs::read_dir(directory)
        .map_err(|error| format!("scan shell hook capability anchors: {error}"))?;
    for entry in entries {
        let entry =
            entry.map_err(|error| format!("read shell hook capability anchor entry: {error}"))?;
        let anchor_path = entry.path();
        let Some(name) = anchor_path.file_name().and_then(|name| name.to_str()) else {
            continue;
        };
        let Some(key) = hook_capability_lock_key(name) else {
            continue;
        };
        let capability_path = directory.join(format!(".hook-{key}.capability"));
        if fs::symlink_metadata(&capability_path).is_ok() {
            continue;
        }
        let Ok(anchor) = open_capability_anchor_for(&anchor_path, Duration::from_millis(1)) else {
            continue;
        };
        if fs::symlink_metadata(&capability_path).is_ok() {
            continue;
        }
        let Ok(anchor_record) = read_capability_anchor(&anchor) else {
            continue;
        };
        if !capability_key_matches_anchor(key, &anchor_record) {
            continue;
        }
        let removable = capability_anchor_process_is_stale(&anchor_record);
        if removable {
            remove_orphan_capability_anchor(&anchor_path, &anchor)?;
        }
        drop(anchor);
    }

    // Atomic publication can strand a random temp file. It carries no bearer
    // and is never a valid lookup target, so the existing private-file and age
    // checks are sufficient to bound crash debris without touching live work.
    let now = unix_time_ms()?;
    let retention_ms = u64::try_from(TERMINAL_RETENTION.as_millis()).unwrap_or(u64::MAX);
    let entries = fs::read_dir(directory)
        .map_err(|error| format!("scan shell hook capability temp files: {error}"))?;
    for entry in entries {
        let entry = entry
            .map_err(|error| format!("read shell hook capability temp-file entry: {error}"))?;
        let path = entry.path();
        let Some(name) = path.file_name().and_then(|name| name.to_str()) else {
            continue;
        };
        let temporary_key = name
            .strip_prefix(".hook-capability-")
            .and_then(|value| value.strip_suffix(".tmp"));
        if temporary_key.is_some_and(|key| {
            key.len() == 32
                && key
                    .bytes()
                    .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
        }) && stale_private_regular_file(&path, now, retention_ms)
        {
            fs::remove_file(&path).map_err(|error| {
                format!("remove stale shell hook capability temp file: {error}")
            })?;
            crate::util::fsync_parent_dir(&path).map_err(|error| {
                format!("sync stale shell hook capability temp-file removal: {error}")
            })?;
        }
    }

    let mut capabilities = 0usize;
    let mut anchors = 0usize;
    let mut temporary_files = 0usize;
    for entry in fs::read_dir(directory)
        .map_err(|error| format!("rescan shell hook capability artifacts: {error}"))?
    {
        let entry =
            entry.map_err(|error| format!("read shell hook capability artifact: {error}"))?;
        let name = entry.file_name();
        let Some(name) = name.to_str() else {
            continue;
        };
        if hook_capability_key(name).is_some() {
            capabilities = capabilities.saturating_add(1);
        } else if hook_capability_lock_key(name).is_some() {
            anchors = anchors.saturating_add(1);
        } else if name.starts_with(".hook-capability-") && name.ends_with(".tmp") {
            temporary_files = temporary_files.saturating_add(1);
        }
    }
    if capabilities >= MAX_HOOK_CAPABILITIES
        || anchors >= MAX_HOOK_CAPABILITIES
        || temporary_files >= MAX_HOOK_CAPABILITIES
    {
        return Err("live shell hook capability capacity is exhausted".to_string());
    }
    Ok(())
}

#[cfg(all(unix, test))]
fn cleanup_hook_capabilities(directory: &Path) -> Result<(), String> {
    let _registry = open_capability_registry_lock(directory)?;
    cleanup_hook_capabilities_locked(directory)
}

/// Register exactly one capability for a live shell process identity and
/// return its bearer only after the durable issued marker is complete.
pub fn register_shell_hook_instance(
    shell_pid: u32,
    family: ShellHookFamily,
    session_id: &str,
) -> Result<String, String> {
    register_shell_hook_instance_with_delivery(shell_pid, family, session_id, |secret| {
        Ok(secret.to_string())
    })
}

/// Register a capability and synchronously deliver its bearer before making
/// it usable. `deliver` runs while the registry and process-anchor locks are
/// held and must return `Ok` only after its output is durably handed off (for
/// example, after writing and flushing stdout). It must not re-enter shell
/// capability APIs. A delivery failure removes the still-Prepared capability
/// pair when possible; any retained Prepared state remains unusable and is
/// recovered by a later registration attempt.
pub fn register_shell_hook_instance_with_delivery<T, F>(
    shell_pid: u32,
    family: ShellHookFamily,
    session_id: &str,
    deliver: F,
) -> Result<T, String>
where
    F: FnOnce(&str) -> Result<T, String>,
{
    #[cfg(not(unix))]
    {
        let _ = (shell_pid, family, session_id, deliver);
        return Err("strict shell execution receipts are unsupported on this platform".to_string());
    }

    #[cfg(unix)]
    {
        validate_capability_session(session_id)?;
        let actual_parent_pid = unsafe { libc::getppid() };
        if actual_parent_pid <= 1 || shell_pid != actual_parent_pid as u32 {
            return Err(
                "shell hook registration target is not the Tirith process's actual parent"
                    .to_string(),
            );
        }
        let shell_identity = shell_process_identity(shell_pid).map_err(|error| match error {
            ShellProcessLookupError::Missing => {
                "shell hook registration target is not a live process".to_string()
            }
            ShellProcessLookupError::Rejected(detail) => detail,
        })?;
        let effective_uid = unsafe { libc::geteuid() };
        if shell_identity.effective_uid != effective_uid {
            return Err("shell hook registration target has a different effective UID".to_string());
        }
        let executable_identity = current_tirith_executable_identity()?;
        let directory = receipt_directory()?;
        // A new shell registration is an early post-upgrade maintenance
        // boundary. Cleanup can remove expired current receipts, but legacy
        // receipts require bearer-token authentication and are retired only on
        // direct access. Never nest the independent registries.
        {
            let receipt_registry = open_receipt_registry_lock(&directory)?;
            cleanup_receipts_locked(&directory)?;
            drop(receipt_registry);
        }
        // Lock order is global registry -> process anchor. Holding the registry
        // through count, publication, and the issued-marker fsync turns the
        // capacity limit into a real bound across different shell processes.
        let _registry = open_capability_registry_lock(&directory)?;
        cleanup_hook_capabilities_locked(&directory)?;
        let (capability_path, anchor_path) =
            capability_paths(effective_uid, shell_pid, &shell_identity.start_fingerprint)?;
        match fs::symlink_metadata(&capability_path) {
            Ok(_) => {
                return Err("shell hook process already has a protocol-v3 registration".to_string())
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => {
                return Err(format!("inspect shell hook capability path: {error}"));
            }
        }
        let prepared_anchor = prepared_capability_anchor(
            effective_uid,
            shell_pid,
            &shell_identity.start_fingerprint,
        )?;
        let (_anchor, anchor_record) =
            open_or_create_capability_anchor(&anchor_path, &prepared_anchor)?;
        let anchor_identity = secure_regular_identity(&_anchor, "shell hook capability anchor")?;
        if matches!(
            &anchor_record.state,
            ShellHookCapabilityAnchorState::Issued { .. }
        ) {
            return Err("shell hook process already has a protocol-v3 registration".to_string());
        }
        match fs::symlink_metadata(&capability_path) {
            Ok(_) => {
                return Err("shell hook process already has a protocol-v3 registration".to_string())
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => {
                return Err(format!("inspect shell hook capability path: {error}"));
            }
        }

        let confirmed_identity =
            shell_process_identity(shell_pid).map_err(|error| match error {
                ShellProcessLookupError::Missing => {
                    "shell hook registration target exited during registration".to_string()
                }
                ShellProcessLookupError::Rejected(detail) => detail,
            })?;
        if confirmed_identity != shell_identity {
            return Err("shell hook registration target changed identity".to_string());
        }

        let mut random = [0u8; 32];
        getrandom::fill(&mut random)
            .map_err(|error| format!("generate shell hook capability: {error}"))?;
        let secret = hex_lower(&random);
        let mut capability = ShellHookCapability {
            schema_version: HOOK_CAPABILITY_SCHEMA_VERSION,
            effective_uid,
            shell_pid,
            shell_start_fingerprint: shell_identity.start_fingerprint.clone(),
            family,
            session_id: session_id.to_string(),
            tirith_executable: executable_identity.clone(),
            secret_sha256: sha256_hex(secret.as_bytes()),
            capability_seal_sha256: String::new(),
            created_unix_ms: unix_time_ms()?,
        };
        refresh_capability_seal(&mut capability, &secret);
        publish_capability(&capability_path, &capability)?;

        let (durable_capability, capability_file_identity) = read_capability(&capability_path)?;
        validate_capability_record(
            &durable_capability,
            &secret,
            shell_pid,
            family,
            session_id,
            &shell_identity,
            &executable_identity,
        )?;

        let final_identity = shell_process_identity(shell_pid).map_err(|error| match error {
            ShellProcessLookupError::Missing => {
                "shell hook registration target exited before registration completed".to_string()
            }
            ShellProcessLookupError::Rejected(detail) => detail,
        })?;
        if final_identity != shell_identity {
            return Err("shell hook registration target changed before completion".to_string());
        }
        if path_identity(&anchor_path, "shell hook capability anchor")? != anchor_identity
            || path_identity(&capability_path, "shell hook capability")? != capability_file_identity
        {
            return Err("shell hook capability changed before registration completed".to_string());
        }
        let delivered = match deliver(&secret) {
            Ok(delivered) => delivered,
            Err(delivery_error) => {
                return match remove_capability_pair_locked(
                    &capability_path,
                    capability_file_identity,
                    &anchor_path,
                    &_anchor,
                ) {
                    Ok(()) => Err(format!(
                        "deliver shell hook capability bearer: {delivery_error}"
                    )),
                    Err(rollback_error) => Err(format!(
                        "deliver shell hook capability bearer: {delivery_error}; rollback of the Prepared capability failed: {rollback_error}"
                    )),
                };
            }
        };
        let issued_anchor = issued_capability_anchor(
            &anchor_record,
            &durable_capability,
            capability_file_identity,
        )?;
        publish_capability_anchor(&anchor_path, &_anchor, anchor_identity, &issued_anchor)?;
        let durable_anchor = read_capability_anchor(&_anchor)?;
        let (completed_capability, completed_capability_identity) =
            read_capability(&capability_path)?;
        if completed_capability_identity != capability_file_identity {
            return Err("shell hook capability changed after bearer delivery".to_string());
        }
        validate_capability_record(
            &completed_capability,
            &secret,
            shell_pid,
            family,
            session_id,
            &shell_identity,
            &executable_identity,
        )?;
        validate_issued_capability_anchor(
            &durable_anchor,
            &completed_capability,
            completed_capability_identity,
        )?;

        let completed_identity =
            shell_process_identity(shell_pid).map_err(|error| match error {
                ShellProcessLookupError::Missing => {
                    "shell hook registration target exited after bearer delivery".to_string()
                }
                ShellProcessLookupError::Rejected(detail) => detail,
            })?;
        if completed_identity != shell_identity
            || path_identity(&anchor_path, "shell hook capability anchor")? != anchor_identity
            || path_identity(&capability_path, "shell hook capability")? != capability_file_identity
        {
            return Err("shell hook capability changed after bearer delivery".to_string());
        }
        Ok(delivered)
    }
}

/// Validate a protocol-v3 bearer against its live shell and executable
/// identities. Receipt operations call this for every use; possession of an
/// unregistered 64-hex string is never sufficient.
pub fn validate_shell_hook_instance(
    secret: &str,
    shell_pid: u32,
    family: ShellHookFamily,
    session_id: &str,
) -> Result<(), String> {
    #[cfg(not(unix))]
    {
        let _ = (secret, shell_pid, family, session_id);
        return Err("strict shell execution receipts are unsupported on this platform".to_string());
    }

    #[cfg(unix)]
    {
        validate_token(secret)
            .map_err(|_| "shell hook capability must be 256-bit lowercase hex".to_string())?;
        validate_capability_session(session_id)?;
        let actual_parent_pid = unsafe { libc::getppid() };
        if actual_parent_pid <= 1 || shell_pid != actual_parent_pid as u32 {
            return Err(
                "shell hook capability is not being used by a direct child of its registered shell"
                    .to_string(),
            );
        }
        let shell_identity = shell_process_identity(shell_pid).map_err(|error| match error {
            ShellProcessLookupError::Missing => {
                "registered shell process is no longer live".to_string()
            }
            ShellProcessLookupError::Rejected(detail) => detail,
        })?;
        let effective_uid = unsafe { libc::geteuid() };
        if shell_identity.effective_uid != effective_uid {
            return Err("registered shell process has a different effective UID".to_string());
        }
        let executable_identity = current_tirith_executable_identity()?;
        let (capability_path, anchor_path) =
            capability_paths(effective_uid, shell_pid, &shell_identity.start_fingerprint)?;
        let _anchor = open_capability_anchor(&anchor_path)?;
        let anchor_identity = secure_regular_identity(&_anchor, "shell hook capability anchor")?;
        let anchor_record = read_capability_anchor(&_anchor)?;
        let (capability, capability_file_identity) = read_capability(&capability_path)?;
        if path_identity(&capability_path, "shell hook capability")? != capability_file_identity {
            return Err("shell hook capability path changed while locked".to_string());
        }
        validate_capability_record(
            &capability,
            secret,
            shell_pid,
            family,
            session_id,
            &shell_identity,
            &executable_identity,
        )?;
        validate_issued_capability_anchor(&anchor_record, &capability, capability_file_identity)?;
        let final_identity = shell_process_identity(shell_pid).map_err(|error| match error {
            ShellProcessLookupError::Missing => {
                "registered shell process exited during capability validation".to_string()
            }
            ShellProcessLookupError::Rejected(detail) => detail,
        })?;
        if final_identity != shell_identity {
            return Err(
                "registered shell process changed during capability validation".to_string(),
            );
        }
        if path_identity(&anchor_path, "shell hook capability anchor")? != anchor_identity
            || path_identity(&capability_path, "shell hook capability")? != capability_file_identity
        {
            return Err("shell hook capability changed during validation".to_string());
        }
        Ok(())
    }
}

fn refresh_receipt_seals(receipt: &mut ShellReceipt, token: &str) -> Result<(), String> {
    validate_token(token)?;
    receipt.immutable_seal_sha256 = secret_seal(
        token,
        "tirith-shell-receipt-immutable-v1",
        &immutable_receipt_identity(receipt),
    );
    let state = serde_json::to_value(&receipt.state)
        .map_err(|error| format!("serialize shell receipt state seal: {error}"))?;
    receipt.state_seal_sha256 = secret_seal(
        token,
        "tirith-shell-receipt-state-v1",
        &serde_json::json!({
            "immutable_seal_sha256": receipt.immutable_seal_sha256,
            "state": state,
        }),
    );
    Ok(())
}

fn validate_receipt_seals(receipt: &ShellReceipt, token: &str) -> Result<(), String> {
    let immutable = secret_seal(
        token,
        "tirith-shell-receipt-immutable-v1",
        &immutable_receipt_identity(receipt),
    );
    if receipt.immutable_seal_sha256 != immutable {
        return Err("shell receipt immutable seal is invalid".to_string());
    }
    let state = serde_json::to_value(&receipt.state)
        .map_err(|error| format!("serialize shell receipt state seal: {error}"))?;
    let expected_state = secret_seal(
        token,
        "tirith-shell-receipt-state-v1",
        &serde_json::json!({
            "immutable_seal_sha256": receipt.immutable_seal_sha256,
            "state": state,
        }),
    );
    if receipt.state_seal_sha256 != expected_state {
        return Err("shell receipt state seal is invalid".to_string());
    }
    Ok(())
}

fn receipt_paths(token: &str) -> Result<(PathBuf, PathBuf, PathBuf), String> {
    validate_token(token)?;
    let directory = receipt_directory()?;
    let stem = token_sha256(token);
    Ok((
        directory.clone(),
        directory.join(format!("{stem}.json")),
        directory.join(format!("{stem}.lock")),
    ))
}

#[cfg(unix)]
fn receipt_directory() -> Result<PathBuf, String> {
    let root = crate::policy::state_dir()
        .ok_or_else(|| "cannot resolve Tirith state directory for shell receipts".to_string())?;
    let sessions = root.join("sessions");
    ensure_secure_session_directory(&sessions)?;
    let receipts = sessions.join("execution-receipts");
    ensure_secure_receipt_directory(&receipts)?;
    Ok(receipts)
}

#[cfg(unix)]
fn ensure_secure_receipt_directory(directory: &Path) -> Result<(), String> {
    use std::os::unix::fs::{DirBuilderExt as _, MetadataExt as _};

    match fs::symlink_metadata(directory) {
        Ok(_) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            let mut builder = fs::DirBuilder::new();
            builder.mode(0o700);
            match builder.create(directory) {
                Ok(()) => crate::util::fsync_parent_dir(directory)
                    .map_err(|error| format!("durably create shell receipt directory: {error}"))?,
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(error) => {
                    return Err(format!("create shell receipt directory: {error}"));
                }
            }
        }
        Err(error) => return Err(format!("inspect shell receipt directory: {error}")),
    }
    let metadata = fs::symlink_metadata(directory)
        .map_err(|error| format!("inspect shell receipt directory: {error}"))?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err("shell receipt directory is not a real directory".to_string());
    }
    if metadata.uid() != unsafe { libc::geteuid() } {
        return Err("shell receipt directory has the wrong owner".to_string());
    }
    if metadata.mode() & 0o777 != 0o700 {
        return Err("shell receipt directory must already have mode 0700".to_string());
    }
    Ok(())
}

#[cfg(not(unix))]
fn receipt_directory() -> Result<PathBuf, String> {
    Err("strict shell execution receipts are unsupported on this platform".to_string())
}

#[cfg(unix)]
fn open_receipt_lock(path: &Path, timeout: Duration, create: bool) -> Result<File, String> {
    use std::os::unix::fs::OpenOptionsExt as _;

    let mut options = OpenOptions::new();
    options
        .read(true)
        .write(true)
        .create_new(create)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
    let file = options
        .open(path)
        .map_err(|error| format!("open shell receipt lock: {error}"))?;
    secure_regular_identity(&file, "shell receipt lock")?;
    let deadline = Instant::now()
        .checked_add(timeout)
        .ok_or_else(|| "shell receipt lock deadline overflowed".to_string())?;
    loop {
        match file.try_lock_exclusive() {
            Ok(()) => return Ok(file),
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                if Instant::now() >= deadline {
                    return Err("timed out acquiring shell receipt lock".to_string());
                }
                std::thread::sleep(Duration::from_millis(5));
            }
            Err(error) => return Err(format!("lock shell receipt: {error}")),
        }
    }
}

#[cfg(unix)]
fn receipt_registry_lock_path(directory: &Path) -> PathBuf {
    directory.join(".receipt-registry.lock")
}

#[cfg(unix)]
fn open_receipt_registry_lock(directory: &Path) -> Result<File, String> {
    use std::os::unix::fs::OpenOptionsExt as _;

    let path = receipt_registry_lock_path(directory);
    let file = match OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(&path)
    {
        Ok(file) => {
            file.sync_all()
                .map_err(|error| format!("sync shell receipt registry lock: {error}"))?;
            crate::util::fsync_parent_dir(&path)
                .map_err(|error| format!("sync shell receipt registry lock directory: {error}"))?;
            file
        }
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => OpenOptions::new()
            .read(true)
            .write(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(&path)
            .map_err(|error| format!("open shell receipt registry lock: {error}"))?,
        Err(error) => return Err(format!("create shell receipt registry lock: {error}")),
    };
    let identity = secure_regular_identity(&file, "shell receipt registry lock")?;
    let deadline = Instant::now()
        .checked_add(RECEIPT_LOCK_TIMEOUT)
        .ok_or_else(|| "shell receipt registry lock deadline overflowed".to_string())?;
    loop {
        match file.try_lock_exclusive() {
            Ok(()) => break,
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                if Instant::now() >= deadline {
                    return Err("timed out acquiring shell receipt registry lock".to_string());
                }
                std::thread::sleep(Duration::from_millis(5));
            }
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(format!("lock shell receipt registry: {error}")),
        }
    }
    if path_identity(&path, "shell receipt registry lock")? != identity {
        return Err("shell receipt registry lock changed while locked".to_string());
    }
    Ok(file)
}

#[cfg(not(unix))]
fn open_receipt_lock(_path: &Path, _timeout: Duration, _create: bool) -> Result<File, String> {
    Err("strict shell execution receipts are unsupported on this platform".to_string())
}

#[cfg(unix)]
fn read_receipt(path: &Path) -> Result<(ShellReceipt, FileIdentity), String> {
    use std::os::unix::fs::OpenOptionsExt as _;

    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
        .open(path)
        .map_err(|error| format!("open shell receipt: {error}"))?;
    let identity = secure_regular_identity(&file, "shell receipt")?;
    let length = file
        .metadata()
        .map_err(|error| format!("inspect shell receipt: {error}"))?
        .len();
    if length == 0 || length > RECEIPT_FILE_CAP {
        return Err("shell receipt is empty or oversized".to_string());
    }
    let mut bytes = Vec::with_capacity(length as usize);
    file.take(RECEIPT_FILE_CAP + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| format!("read shell receipt: {error}"))?;
    if bytes.len() as u64 > RECEIPT_FILE_CAP {
        return Err("shell receipt grew beyond its size limit".to_string());
    }
    let receipt: ShellReceipt =
        serde_json::from_slice(&bytes).map_err(|error| format!("parse shell receipt: {error}"))?;
    Ok((receipt, identity))
}

#[cfg(not(unix))]
fn read_receipt(_path: &Path) -> Result<(ShellReceipt, FileIdentity), String> {
    Err("strict shell execution receipts are unsupported on this platform".to_string())
}

fn validate_receipt(receipt: &ShellReceipt, token: &str) -> Result<(), String> {
    if receipt.schema_version != RECEIPT_SCHEMA_VERSION {
        return Err("shell receipt schema is unsupported".to_string());
    }
    validate_receipt_common(receipt, token)
}

/// Authenticate a privacy-unsafe receipt before deleting it.  Schema alone is
/// attacker-mutable, so retirement is authorized only when the exact legacy
/// immutable/state seals validate under the caller-supplied bearer token and
/// the wire-shape matches the declared historical schema.
fn validate_legacy_receipt_for_retirement(
    receipt: &ShellReceipt,
    token: &str,
) -> Result<(), String> {
    if !matches!(
        receipt.schema_version,
        LEGACY_RAW_COMMAND_RECEIPT_SCHEMA_VERSION | LEGACY_RAW_CWD_RECEIPT_SCHEMA_VERSION
    ) {
        return Err("shell receipt schema is not a supported legacy schema".to_string());
    }
    validate_receipt_common(receipt, token)
}

fn validate_receipt_common(receipt: &ShellReceipt, token: &str) -> Result<(), String> {
    if receipt.token_sha256 != token_sha256(token) {
        return Err("shell receipt token does not match its durable identity".to_string());
    }
    for (label, digest) in [
        ("immutable seal", receipt.immutable_seal_sha256.as_str()),
        ("state seal", receipt.state_seal_sha256.as_str()),
        ("hook instance", receipt.hook_instance_sha256.as_str()),
    ] {
        if !digest_is_valid(digest) {
            return Err(format!("shell receipt {label} digest is invalid"));
        }
    }
    match receipt.schema_version {
        RECEIPT_SCHEMA_VERSION => {
            if receipt.cwd_sha256.is_some() {
                return Err("current shell receipt retains a legacy raw-cwd digest".to_string());
            }
            let cwd_binding = receipt.cwd_binding_sha256.as_deref().ok_or_else(|| {
                "shell receipt lacks its exact working-directory binding".to_string()
            })?;
            if !digest_is_valid(cwd_binding) {
                return Err("shell receipt working-directory binding is invalid".to_string());
            }
        }
        LEGACY_RAW_COMMAND_RECEIPT_SCHEMA_VERSION | LEGACY_RAW_CWD_RECEIPT_SCHEMA_VERSION => {
            if receipt.cwd_binding_sha256.is_some() {
                return Err("legacy shell receipt contains a future cwd binding".to_string());
            }
            let cwd_digest = receipt
                .cwd_sha256
                .as_deref()
                .ok_or_else(|| "legacy shell receipt lacks its raw-cwd digest".to_string())?;
            if !digest_is_valid(cwd_digest) {
                return Err("legacy shell receipt working-directory digest is invalid".to_string());
            }
        }
        _ => return Err("shell receipt schema is unsupported".to_string()),
    }
    match receipt.schema_version {
        LEGACY_RAW_COMMAND_RECEIPT_SCHEMA_VERSION => {
            if receipt.command_binding_sha256.is_some() {
                return Err("schema-v1 shell receipt contains a future command binding".to_string());
            }
        }
        LEGACY_RAW_CWD_RECEIPT_SCHEMA_VERSION | RECEIPT_SCHEMA_VERSION => {
            let command_binding = receipt
                .command_binding_sha256
                .as_deref()
                .ok_or_else(|| "shell receipt lacks its exact command binding".to_string())?;
            if !digest_is_valid(command_binding) {
                return Err("shell receipt command binding digest is invalid".to_string());
            }
        }
        _ => return Err("shell receipt schema is unsupported".to_string()),
    }
    // This is the authentication boundary for legacy retirement. Keep it
    // before all semantic acceptance and, critically, before every unlink.
    validate_receipt_seals(receipt, token)?;
    validate_stable_id("shell receipt execution", &receipt.execution_id)?;
    if crate::session_warnings::session_state_path(&receipt.session_id).is_none() {
        return Err("shell receipt contains an invalid session id".to_string());
    }
    if receipt.shell != receipt.channel.expected_shell() {
        return Err("shell receipt channel does not match its tokenizer".to_string());
    }
    receipt.channel.hook_family()?;
    for (label, digest) in [
        ("command", receipt.command_sha256.as_str()),
        ("decision binding", receipt.decision_binding_sha256.as_str()),
        ("policy basis", receipt.policy_basis_sha256.as_str()),
        (
            "semantic verdict basis",
            receipt.semantic_verdict_basis_sha256.as_str(),
        ),
    ] {
        if !digest_is_valid(digest) {
            return Err(format!("shell receipt {label} digest is invalid"));
        }
    }
    if receipt.command_redacted_preview.len() > 120 {
        return Err("shell receipt preview exceeds its privacy bound".to_string());
    }
    if receipt.created_unix_ms >= receipt.expires_unix_ms
        || receipt
            .expires_unix_ms
            .saturating_sub(receipt.created_unix_ms)
            > u64::try_from(MAX_RECEIPT_TTL.as_millis()).unwrap_or(u64::MAX)
    {
        return Err("shell receipt expiry is invalid".to_string());
    }
    if !receipt.requires_approval && receipt.approval_fallback.is_some() {
        return Err("shell receipt has an approval fallback without approval".to_string());
    }
    if !receipt.interactive {
        return Err("shell receipt was not prepared in an interactive context".to_string());
    }
    if receipt.strict_warn_override && receipt.action == Action::Warn && !receipt.requires_warn_ack
    {
        return Err(
            "strict-warn shell receipt lacks its frozen warning acknowledgement".to_string(),
        );
    }
    if let Some(fallback) = receipt.approval_fallback.as_deref() {
        if !matches!(fallback, "allow" | "warn" | "block") {
            return Err("shell receipt approval fallback is invalid".to_string());
        }
    }
    validate_receipt_state(receipt, token)?;
    Ok(())
}

fn validate_receipt_state(receipt: &ShellReceipt, token: &str) -> Result<(), String> {
    let validate_interactions = |approval: &Option<StoredApprovalResolution>,
                                 warn_ack: &Option<String>|
     -> Result<(), String> {
        if receipt.requires_approval != approval.is_some() {
            return Err(
                "shell receipt approval proof does not match its frozen requirement".to_string(),
            );
        }
        if receipt.requires_warn_ack != warn_ack.is_some() {
            return Err(
                "shell receipt warning proof does not match its frozen requirement".to_string(),
            );
        }
        if let Some(approval) = approval {
            if !digest_is_valid(approval.proof_sha256()) {
                return Err("shell receipt approval proof digest is invalid".to_string());
            }
            match approval {
                StoredApprovalResolution::FallbackAllow { .. }
                    if receipt.approval_fallback.as_deref() != Some("allow") =>
                {
                    return Err("shell receipt allow fallback is not frozen in policy".to_string())
                }
                StoredApprovalResolution::FallbackWarn { .. }
                    if receipt.approval_fallback.as_deref() != Some("warn") =>
                {
                    return Err("shell receipt warn fallback is not frozen in policy".to_string())
                }
                _ => {}
            }
            let tag = match approval {
                StoredApprovalResolution::Granted { .. } => "approval_granted",
                StoredApprovalResolution::FallbackAllow { .. } => "fallback_allow",
                StoredApprovalResolution::FallbackWarn { .. } => "fallback_warn",
            };
            if approval.proof_sha256() != interaction_proof_sha256(token, receipt, tag) {
                return Err(
                    "shell receipt approval proof does not match its bearer token".to_string(),
                );
            }
        }
        if warn_ack
            .as_deref()
            .is_some_and(|proof| !digest_is_valid(proof))
        {
            return Err("shell receipt warning proof digest is invalid".to_string());
        }
        if let Some(proof) = warn_ack {
            if proof != &interaction_proof_sha256(token, receipt, "warn_acknowledged") {
                return Err(
                    "shell receipt warning proof does not match its bearer token".to_string(),
                );
            }
        }
        Ok(())
    };

    match &receipt.state {
        ReceiptState::Prepared | ReceiptState::Discarded { .. } => Ok(()),
        ReceiptState::Armed {
            approval,
            warn_ack_proof_sha256,
            ..
        } => validate_interactions(approval, warn_ack_proof_sha256),
        ReceiptState::Consuming {
            approval,
            warn_ack_proof_sha256,
            observation,
            evidence_id,
            draft_identity_sha256,
            committed_policy_basis_sha256,
            committed_verdict_basis_sha256,
            ..
        } => {
            validate_interactions(approval, warn_ack_proof_sha256)?;
            if observation != receipt.channel.observation_tag()
                || !digest_is_valid(draft_identity_sha256)
                || !digest_is_valid(committed_policy_basis_sha256)
                || !digest_is_valid(committed_verdict_basis_sha256)
            {
                return Err("shell receipt consuming identity is invalid".to_string());
            }
            validate_stable_id("shell receipt evidence", evidence_id)
        }
        ReceiptState::Committed {
            observation,
            evidence_id,
            ..
        }
        | ReceiptState::Conflict {
            observation,
            evidence_id,
            ..
        } => {
            if observation != receipt.channel.observation_tag() {
                return Err("shell receipt committed observation changed".to_string());
            }
            validate_stable_id("shell receipt evidence", evidence_id)
        }
    }
}

fn legacy_receipt_retirement_error(state: &ReceiptState) -> String {
    if matches!(state, ReceiptState::Consuming { .. }) {
        "legacy shell receipt was retired for privacy with an indeterminate consumption outcome; never replay it automatically"
            .to_string()
    } else {
        "legacy shell receipt was retired for privacy; rerun the command through fresh analysis"
            .to_string()
    }
}

#[cfg(unix)]
fn remove_receipt_artifacts_locked(
    receipt_path: &Path,
    receipt_identity: FileIdentity,
    lock_path: &Path,
    lock_file: &File,
) -> Result<(), String> {
    if path_identity(receipt_path, "shell receipt cleanup")? != receipt_identity {
        return Err("shell receipt changed before cleanup".to_string());
    }
    let lock_identity = secure_regular_identity(lock_file, "shell receipt cleanup lock")?;
    if path_identity(lock_path, "shell receipt cleanup lock")? != lock_identity {
        return Err("shell receipt lock changed before cleanup".to_string());
    }
    // JSON first: a crash can leave only an inert lock, which the existing
    // orphan cleanup removes later. Removing the lock first could expose a live
    // privacy-unsafe receipt without serialization.
    fs::remove_file(receipt_path)
        .map_err(|error| format!("remove privacy-unsafe shell receipt: {error}"))?;
    crate::util::fsync_parent_dir(receipt_path)
        .map_err(|error| format!("sync privacy-unsafe shell-receipt removal: {error}"))?;
    if path_identity(lock_path, "shell receipt cleanup lock")? != lock_identity {
        return Err("shell receipt lock changed during cleanup".to_string());
    }
    fs::remove_file(lock_path)
        .map_err(|error| format!("remove privacy-unsafe shell receipt lock: {error}"))?;
    crate::util::fsync_parent_dir(lock_path)
        .map_err(|error| format!("sync privacy-unsafe shell-receipt lock removal: {error}"))?;
    Ok(())
}

#[cfg(not(unix))]
fn remove_receipt_artifacts_locked(
    _receipt_path: &Path,
    _receipt_identity: FileIdentity,
    _lock_path: &Path,
    _lock_file: &File,
) -> Result<(), String> {
    Err("strict shell execution receipts are unsupported on this platform".to_string())
}

fn lock_receipt(token: &str) -> Result<LockedReceipt, String> {
    let (_, receipt_path, lock_path) = receipt_paths(token)?;
    let lock_file = open_receipt_lock(&lock_path, RECEIPT_LOCK_TIMEOUT, false)?;
    let (receipt, receipt_identity) = read_receipt(&receipt_path)?;
    if matches!(
        receipt.schema_version,
        LEGACY_RAW_COMMAND_RECEIPT_SCHEMA_VERSION | LEGACY_RAW_CWD_RECEIPT_SCHEMA_VERSION
    ) {
        validate_legacy_receipt_for_retirement(&receipt, token).map_err(|error| {
            format!("legacy shell receipt failed authentication and was preserved: {error}")
        })?;
        let retirement_error = legacy_receipt_retirement_error(&receipt.state);
        remove_receipt_artifacts_locked(&receipt_path, receipt_identity, &lock_path, &lock_file)?;
        return Err(retirement_error);
    }
    validate_receipt(&receipt, token)?;
    if path_identity(&lock_path, "shell receipt lock")?
        != secure_regular_identity(&lock_file, "shell receipt lock")?
    {
        return Err("shell receipt lock path changed while locked".to_string());
    }
    Ok(LockedReceipt {
        _lock_file: lock_file,
        token: token.to_string(),
        receipt_path,
        receipt_identity,
        receipt,
    })
}

#[cfg(unix)]
fn publish_receipt(
    path: &Path,
    expected_identity: Option<FileIdentity>,
    receipt: &ShellReceipt,
) -> Result<(), String> {
    use std::os::unix::fs::OpenOptionsExt as _;

    let bytes =
        serde_json::to_vec(receipt).map_err(|error| format!("serialize shell receipt: {error}"))?;
    if bytes.is_empty() || bytes.len() as u64 > RECEIPT_FILE_CAP {
        return Err("serialized shell receipt exceeds its size limit".to_string());
    }
    match expected_identity {
        Some(expected) if path_identity(path, "shell receipt")? != expected => {
            return Err("shell receipt path changed before publication".to_string())
        }
        Some(_) => {}
        None => match fs::symlink_metadata(path) {
            Ok(_) => return Err("new shell receipt path already exists".to_string()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(format!("inspect new shell receipt path: {error}")),
        },
    }
    let parent = path
        .parent()
        .ok_or_else(|| "shell receipt path has no parent".to_string())?;
    let temporary = parent.join(format!(".receipt-{}.tmp", uuid::Uuid::new_v4().simple()));
    let mut options = OpenOptions::new();
    options
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
    let mut file = options
        .open(&temporary)
        .map_err(|error| format!("create shell receipt temp file: {error}"))?;
    let result = (|| {
        let temporary_identity = secure_regular_identity(&file, "shell receipt temp file")?;
        file.write_all(&bytes)
            .map_err(|error| format!("write shell receipt temp file: {error}"))?;
        file.sync_all()
            .map_err(|error| format!("sync shell receipt temp file: {error}"))?;
        if let Some(expected) = expected_identity {
            if path_identity(path, "shell receipt")? != expected {
                return Err("shell receipt path changed during publication".to_string());
            }
        }
        fs::rename(&temporary, path).map_err(|error| format!("publish shell receipt: {error}"))?;
        if path_identity(path, "shell receipt")? != temporary_identity {
            return Err("published shell receipt path does not identify its temp file".to_string());
        }
        crate::util::fsync_parent_dir(path)
            .map_err(|error| format!("sync shell receipt directory: {error}"))?;
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    result
}

#[cfg(not(unix))]
fn publish_receipt(
    _path: &Path,
    _expected_identity: Option<FileIdentity>,
    _receipt: &ShellReceipt,
) -> Result<(), String> {
    Err("strict shell execution receipts are unsupported on this platform".to_string())
}

fn receipt_binding_sha256(
    draft: &ExecutionDraft,
    command_sha256: &str,
    channel: ShellReceiptChannel,
    strict_warn_override: bool,
    cwd_binding_sha256: &str,
    hook_instance_sha256: &str,
) -> Result<String, String> {
    let caller = match draft.caller {
        CallerContext::Cli => "cli",
        CallerContext::Gateway => "gateway",
        CallerContext::McpServer => "mcp_server",
        CallerContext::Daemon => "daemon",
    };
    let raw_verdict_sha256 = semantic_verdict_sha256(&draft.raw_verdict)?;
    let effective_verdict_sha256 = semantic_verdict_sha256(&draft.effective_verdict)?;
    let identity = serde_json::json!({
        "schema": RECEIPT_SCHEMA_VERSION,
        "session_id": draft.session_id,
        "command_sha256": command_sha256,
        "command_redacted_preview": draft.command_redacted_preview,
        "caller": caller,
        "shell": draft.shell,
        "channel": channel,
        "cwd_binding_sha256": cwd_binding_sha256,
        "hook_instance_sha256": hook_instance_sha256,
        "strict_warn_override": strict_warn_override,
        "retention_duration_ms": draft
            .retention_until_unix_ms
            .saturating_sub(draft.created_unix_ms),
        "origin": draft.origin,
        "bypass": {
            "requested": draft.bypass.requested,
            "available": draft.bypass.available,
            "honored": draft.bypass.honored,
        },
        "action": draft.decision.action,
        "requires_approval": draft.decision.requires_approval,
        "requires_warn_ack": draft.decision.requires_warn_ack,
        "policy_basis_sha256": draft.decision.policy_basis_sha256,
        "semantic_effective_verdict_sha256": effective_verdict_sha256,
        "semantic_raw_verdict_sha256": raw_verdict_sha256,
        "provisional_events": draft.provisional_events,
        "warning_prototypes": draft.warning_prototypes,
        "escalation_hits": draft.escalation_hits,
    });
    Ok(sha256_hex(
        crate::audit::canonical_json_for_hash(&identity).as_bytes(),
    ))
}

/// Runtime timings are intentionally excluded: a receipt consumption performs
/// a fresh local analysis, and timing measurements are nondeterministic while
/// every security-relevant verdict field must remain byte-for-byte semantic.
fn semantic_verdict_sha256(verdict: &Verdict) -> Result<String, String> {
    super::privacy_projected_verdict_sha256(verdict, false)
}

fn interaction_proof_sha256(token: &str, receipt: &ShellReceipt, tag: &str) -> String {
    let identity = format!(
        "tirith-shell-interaction-v1\0{}\0{}\0{}\0{}\0{}",
        token, receipt.execution_id, receipt.decision_binding_sha256, receipt.command_sha256, tag
    );
    sha256_hex(identity.as_bytes())
}

fn evidence_id(receipt: &ShellReceipt) -> String {
    format!(
        "shell-{}-{}",
        receipt.channel.observation_tag(),
        &sha256_hex(
            format!(
                "tirith-shell-evidence-v1\0{}\0{}",
                receipt.token_sha256, receipt.decision_binding_sha256
            )
            .as_bytes()
        )[..32]
    )
}

fn is_terminal_execution_replay_conflict(error: &str) -> bool {
    matches!(
        error,
        "execution id replay changed its identity or evidence"
            | "execution id replay changed its immutable identity"
            | "unresolved execution replay changed its evidence"
    )
}

fn current_session_matches(receipt: &ShellReceipt) -> bool {
    crate::session::resolve_session_id() == receipt.session_id
}

fn ensure_live(
    receipt: &ShellReceipt,
    token: &str,
    expected_channel: ShellReceiptChannel,
) -> Result<(), String> {
    ensure_receipt_context(receipt, token, expected_channel)?;
    if unix_time_ms()? >= receipt.expires_unix_ms {
        return Err("shell execution receipt expired".to_string());
    }
    Ok(())
}

fn ensure_receipt_context(
    receipt: &ShellReceipt,
    token: &str,
    expected_channel: ShellReceiptChannel,
) -> Result<(), String> {
    expected_channel.hook_family()?;
    if !current_session_matches(receipt) {
        return Err("shell execution receipt belongs to a different shell session".to_string());
    }
    if receipt.channel != expected_channel {
        return Err("shell execution receipt belongs to a different hook channel".to_string());
    }
    let expected_cwd_binding = receipt
        .cwd_binding_sha256
        .as_deref()
        .ok_or_else(|| "shell receipt lacks its exact working-directory binding".to_string())?;
    if current_cwd_binding_sha256(token)? != expected_cwd_binding {
        return Err("shell execution receipt belongs to a different working directory".to_string());
    }
    let instance = current_hook_instance(expected_channel, &receipt.session_id)?;
    if sha256_hex(instance.as_bytes()) != receipt.hook_instance_sha256 {
        return Err("shell execution receipt belongs to a different hook instance".to_string());
    }
    Ok(())
}

fn receipt_is_cleanup_eligible(
    receipt: &ShellReceipt,
    now: u64,
    terminal_retention_ms: u64,
) -> bool {
    // Legacy seals are token-keyed, while background cleanup has only the
    // token hash encoded in the filename. Never delete an unauthenticated
    // legacy payload merely because its mutable schema field says "old";
    // direct bearer-token access performs authenticated retirement instead.
    if matches!(
        receipt.schema_version,
        LEGACY_RAW_COMMAND_RECEIPT_SCHEMA_VERSION | LEGACY_RAW_CWD_RECEIPT_SCHEMA_VERSION
    ) {
        return false;
    }
    if receipt.schema_version != RECEIPT_SCHEMA_VERSION {
        return false;
    }
    match receipt.state {
        ReceiptState::Prepared | ReceiptState::Armed { .. } => receipt.expires_unix_ms <= now,
        ReceiptState::Consuming { .. } => {
            receipt
                .expires_unix_ms
                .saturating_add(terminal_retention_ms)
                <= now
        }
        ReceiptState::Committed {
            finished_unix_ms, ..
        }
        | ReceiptState::Conflict {
            finished_unix_ms, ..
        }
        | ReceiptState::Discarded { finished_unix_ms } => {
            finished_unix_ms.saturating_add(terminal_retention_ms) <= now
        }
    }
}

#[cfg(unix)]
fn stale_private_regular_file(path: &Path, now: u64, minimum_age_ms: u64) -> bool {
    use std::os::unix::fs::OpenOptionsExt as _;

    let Ok(metadata) = fs::symlink_metadata(path) else {
        return false;
    };
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return false;
    }
    let Ok(modified) = metadata.modified() else {
        return false;
    };
    let Ok(since_epoch) = modified.duration_since(std::time::UNIX_EPOCH) else {
        return false;
    };
    let modified_unix_ms = u64::try_from(since_epoch.as_millis()).unwrap_or(u64::MAX);
    if modified_unix_ms.saturating_add(minimum_age_ms) > now {
        return false;
    }
    let Ok(file) = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
        .open(path)
    else {
        return false;
    };
    let Ok(identity) = secure_regular_identity(&file, "stale shell receipt artifact") else {
        return false;
    };
    path_identity(path, "stale shell receipt artifact").is_ok_and(|path_id| path_id == identity)
}

#[cfg(unix)]
fn enforce_receipt_capacity<I>(entries: I) -> Result<(), String>
where
    I: IntoIterator<Item = std::io::Result<std::ffi::OsString>>,
{
    let mut remaining = 0usize;
    for name in entries {
        let name = name.map_err(|error| format!("read shell receipt capacity entry: {error}"))?;
        if !name.to_str().is_some_and(|name| name.ends_with(".json")) {
            continue;
        }
        remaining += 1;
        if remaining >= MAX_RECEIPTS {
            return Err("live shell receipt capacity is exhausted".to_string());
        }
    }
    Ok(())
}

#[cfg(unix)]
fn cleanup_receipts_locked(directory: &Path) -> Result<(), String> {
    // Callers hold the registry lock before this function takes any per-receipt
    // lock. Creation uses the same registry -> receipt order and holds both
    // through publication, so distinct tokens cannot race the capacity count.
    let now = unix_time_ms()?;
    let terminal_retention_ms = u64::try_from(TERMINAL_RETENTION.as_millis()).unwrap_or(u64::MAX);
    let entries = fs::read_dir(directory)
        .map_err(|error| format!("scan shell receipt directory: {error}"))?;
    for entry in entries {
        let entry = entry.map_err(|error| format!("read shell receipt entry: {error}"))?;
        let path = entry.path();
        let Some(name) = path.file_name().and_then(|name| name.to_str()) else {
            continue;
        };
        if !name.ends_with(".json") {
            continue;
        }
        let Ok((receipt, _)) = read_receipt(&path) else {
            continue;
        };
        if !receipt_is_cleanup_eligible(&receipt, now, terminal_retention_ms) {
            continue;
        }
        let stem = name.trim_end_matches(".json");
        let lock_path = directory.join(format!("{stem}.lock"));
        let Ok(lock) = open_receipt_lock(&lock_path, Duration::from_millis(1), false) else {
            continue;
        };
        // Publication uses rename while holding this lock. Re-read and recheck
        // the exact current inode under the lock so a receipt that was refreshed
        // between the directory scan and lock acquisition is never deleted.
        let Ok((current, current_identity)) = read_receipt(&path) else {
            continue;
        };
        if !receipt_is_cleanup_eligible(&current, now, terminal_retention_ms)
            || path_identity(&path, "shell receipt cleanup")? != current_identity
        {
            continue;
        }
        remove_receipt_artifacts_locked(&path, current_identity, &lock_path, &lock)?;
        drop(lock);
    }

    // A crash can leave an unpublished random temp file or a token-hash lock
    // whose JSON was never created. Delete only private regular files older
    // than the full terminal-retention window; live publications are younger
    // and lock removal is serialized on the lock itself.
    let entries =
        fs::read_dir(directory).map_err(|error| format!("scan shell receipt orphans: {error}"))?;
    for entry in entries {
        let entry = entry.map_err(|error| format!("read shell receipt orphan: {error}"))?;
        let path = entry.path();
        let Some(name) = path.file_name().and_then(|name| name.to_str()) else {
            continue;
        };
        let temporary_stem = name
            .strip_prefix(".receipt-")
            .and_then(|value| value.strip_suffix(".tmp"));
        if temporary_stem.is_some_and(|stem| {
            stem.len() == 32
                && stem
                    .bytes()
                    .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
        }) && stale_private_regular_file(&path, now, terminal_retention_ms)
        {
            fs::remove_file(&path)
                .map_err(|error| format!("remove stale shell receipt temp file: {error}"))?;
            crate::util::fsync_parent_dir(&path)
                .map_err(|error| format!("sync stale shell receipt temp removal: {error}"))?;
            continue;
        }

        let Some(lock_stem) = name.strip_suffix(".lock") else {
            continue;
        };
        if lock_stem.len() != 64
            || !lock_stem
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
            || directory.join(format!("{lock_stem}.json")).exists()
            || !stale_private_regular_file(&path, now, terminal_retention_ms)
        {
            continue;
        }
        let Ok(lock) = open_receipt_lock(&path, Duration::from_millis(1), false) else {
            continue;
        };
        if directory.join(format!("{lock_stem}.json")).exists() {
            continue;
        }
        let lock_identity = secure_regular_identity(&lock, "orphan shell receipt lock")?;
        if path_identity(&path, "orphan shell receipt lock")? != lock_identity {
            continue;
        }
        fs::remove_file(&path)
            .map_err(|error| format!("remove orphan shell receipt lock: {error}"))?;
        crate::util::fsync_parent_dir(&path)
            .map_err(|error| format!("sync orphan shell receipt lock removal: {error}"))?;
        drop(lock);
    }
    let entries = fs::read_dir(directory)
        .map_err(|error| format!("rescan shell receipt directory: {error}"))?;
    enforce_receipt_capacity(entries.map(|entry| entry.map(|entry| entry.file_name())))
}

#[cfg(all(test, unix))]
#[derive(Default)]
struct ReceiptCreationTestCheckpoint {
    state: std::sync::Mutex<(usize, usize)>,
    changed: std::sync::Condvar,
}

#[cfg(all(test, unix))]
impl ReceiptCreationTestCheckpoint {
    fn wait_while_capacity_is_reserved(&self) {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        state.0 = state.0.saturating_add(1);
        let ticket = state.0;
        self.changed.notify_all();
        while state.1 < ticket {
            state = self
                .changed
                .wait(state)
                .unwrap_or_else(std::sync::PoisonError::into_inner);
        }
    }
}

#[cfg(all(test, unix))]
static RECEIPT_CREATION_TEST_CHECKPOINT: std::sync::Mutex<
    Option<std::sync::Arc<ReceiptCreationTestCheckpoint>>,
> = std::sync::Mutex::new(None);

#[cfg(all(test, unix))]
fn wait_at_receipt_creation_test_checkpoint() {
    let checkpoint = RECEIPT_CREATION_TEST_CHECKPOINT
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .clone();
    if let Some(checkpoint) = checkpoint {
        checkpoint.wait_while_capacity_is_reserved();
    }
}

pub fn create_shell_execution_receipt(
    prepared: &PreparedExecution,
    channel: ShellReceiptChannel,
    interactive: bool,
    strict_warn_override: bool,
    ttl: Duration,
) -> Result<String, String> {
    #[cfg(not(unix))]
    {
        let _ = (prepared, channel, interactive, strict_warn_override, ttl);
        return Err("strict shell execution receipts are unsupported on this platform".to_string());
    }

    #[cfg(unix)]
    {
        channel.hook_family()?;
        if prepared.draft.caller() != CallerContext::Cli {
            return Err("shell receipt requires a CLI execution decision".to_string());
        }
        if prepared.draft.shell() != channel.expected_shell() {
            return Err("shell receipt channel does not match the prepared tokenizer".to_string());
        }
        if !interactive {
            return Err("shell receipts require an interactive shell boundary".to_string());
        }
        if strict_warn_override
            && prepared.draft.decision.action == Action::Warn
            && !prepared.draft.decision.requires_warn_ack
        {
            return Err(
                "strict-warn shell decision lacks a warning acknowledgement requirement"
                    .to_string(),
            );
        }
        if ttl.is_zero() || ttl > MAX_RECEIPT_TTL {
            return Err("shell receipt TTL is outside the supported range".to_string());
        }
        let directory = receipt_directory()?;
        let registry_path = receipt_registry_lock_path(&directory);
        let registry_lock = open_receipt_registry_lock(&directory)?;
        cleanup_receipts_locked(&directory)?;
        #[cfg(test)]
        wait_at_receipt_creation_test_checkpoint();
        let now = unix_time_ms()?;
        let ttl_ms = u64::try_from(ttl.as_millis())
            .map_err(|_| "shell receipt TTL is outside the supported range".to_string())?;
        let expires_unix_ms = now
            .checked_add(ttl_ms)
            .ok_or_else(|| "shell receipt expiry overflowed".to_string())?;
        let mut random = [0u8; 32];
        getrandom::fill(&mut random)
            .map_err(|error| format!("generate shell receipt token: {error}"))?;
        let token = hex_lower(&random);
        let hook_instance = current_hook_instance(channel, &prepared.draft.session_id)?;
        let hook_instance_sha256 = sha256_hex(hook_instance.as_bytes());
        let cwd_binding_sha256 = current_cwd_binding_sha256(&token)?;
        let command_binding_sha256 = secret_seal(
            &token,
            "tirith-shell-command-binding-v1",
            &serde_json::Value::String(prepared.draft.command.clone()),
        );
        let binding = receipt_binding_sha256(
            &prepared.draft,
            &prepared.draft.command_sha256,
            channel,
            strict_warn_override,
            &cwd_binding_sha256,
            &hook_instance_sha256,
        )?;
        let (_, receipt_path, lock_path) = receipt_paths(&token)?;
        let lock_file = open_receipt_lock(&lock_path, RECEIPT_LOCK_TIMEOUT, true)?;
        let mut receipt = ShellReceipt {
            schema_version: RECEIPT_SCHEMA_VERSION,
            token_sha256: token_sha256(&token),
            immutable_seal_sha256: String::new(),
            state_seal_sha256: String::new(),
            execution_id: uuid::Uuid::new_v4().simple().to_string(),
            session_id: prepared.draft.session_id.clone(),
            shell: prepared.draft.shell,
            channel,
            cwd_sha256: None,
            cwd_binding_sha256: Some(cwd_binding_sha256),
            hook_instance_sha256,
            command_sha256: prepared.draft.command_sha256.clone(),
            command_binding_sha256: Some(command_binding_sha256),
            command_redacted_preview: prepared.draft.command_redacted_preview.clone(),
            decision_binding_sha256: binding,
            policy_basis_sha256: prepared.draft.decision.policy_basis_sha256.clone(),
            semantic_verdict_basis_sha256: semantic_verdict_sha256(
                &prepared.draft.effective_verdict,
            )?,
            action: prepared.draft.decision.action,
            bypass_honored: prepared.draft.bypass.honored,
            requires_approval: prepared.draft.decision.requires_approval,
            requires_warn_ack: prepared.draft.decision.requires_warn_ack,
            approval_fallback: if prepared.draft.decision.requires_approval {
                prepared.draft.effective_verdict.approval_fallback.clone()
            } else {
                None
            },
            interactive,
            strict_warn_override,
            created_unix_ms: now,
            expires_unix_ms,
            state: ReceiptState::Prepared,
        };
        refresh_receipt_seals(&mut receipt, &token)?;
        validate_receipt(&receipt, &token)?;
        publish_receipt(&receipt_path, None, &receipt)?;
        if path_identity(&lock_path, "shell receipt lock")?
            != secure_regular_identity(&lock_file, "shell receipt lock")?
        {
            return Err("shell receipt lock path changed during creation".to_string());
        }
        if path_identity(&registry_path, "shell receipt registry lock")?
            != secure_regular_identity(&registry_lock, "shell receipt registry lock")?
        {
            return Err("shell receipt registry lock changed during creation".to_string());
        }
        drop(lock_file);
        drop(registry_lock);
        Ok(token)
    }
}

pub fn shell_execution_receipt_context(
    token: &str,
    expected_channel: ShellReceiptChannel,
) -> Result<ShellReceiptContext, String> {
    let locked = lock_receipt(token)?;
    ensure_live(&locked.receipt, token, expected_channel)?;
    match locked.receipt.state {
        ReceiptState::Armed { .. } | ReceiptState::Consuming { .. } => Ok(ShellReceiptContext {
            session_id: locked.receipt.session_id.clone(),
            shell: locked.receipt.shell,
            channel: locked.receipt.channel,
            interactive: locked.receipt.interactive,
            strict_warn_override: locked.receipt.strict_warn_override,
        }),
        ReceiptState::Prepared => Err("shell execution receipt is not armed".to_string()),
        ReceiptState::Committed { .. } => {
            Err("shell execution receipt was already consumed".to_string())
        }
        ReceiptState::Conflict { .. } => {
            Err("shell execution receipt ended in a durable identity conflict".to_string())
        }
        ReceiptState::Discarded { .. } => Err("shell execution receipt was discarded".to_string()),
    }
}

pub fn arm_shell_execution_receipt(
    token: &str,
    expected_channel: ShellReceiptChannel,
    approval_outcome: Option<ShellApprovalOutcome>,
    warn_acknowledged: bool,
) -> Result<(), String> {
    let mut locked = lock_receipt(token)?;
    ensure_live(&locked.receipt, token, expected_channel)?;
    if locked.receipt.action == Action::Block && !locked.receipt.bypass_honored {
        return Err("blocked shell decision cannot be armed for execution".to_string());
    }
    let approval = match (locked.receipt.requires_approval, approval_outcome) {
        (false, None) => None,
        (false, Some(_)) => {
            return Err(
                "approval outcome supplied for a receipt that does not require it".to_string(),
            )
        }
        (true, None) => return Err("shell receipt still requires approval".to_string()),
        (true, Some(ShellApprovalOutcome::Granted)) => Some(StoredApprovalResolution::Granted {
            proof_sha256: interaction_proof_sha256(token, &locked.receipt, "approval_granted"),
        }),
        (true, Some(ShellApprovalOutcome::Rejected | ShellApprovalOutcome::TimedOut)) => {
            match locked.receipt.approval_fallback.as_deref() {
                Some("allow") => Some(StoredApprovalResolution::FallbackAllow {
                    proof_sha256: interaction_proof_sha256(
                        token,
                        &locked.receipt,
                        "fallback_allow",
                    ),
                }),
                Some("warn") => Some(StoredApprovalResolution::FallbackWarn {
                    proof_sha256: interaction_proof_sha256(token, &locked.receipt, "fallback_warn"),
                }),
                _ => return Err("shell receipt approval fallback blocks execution".to_string()),
            }
        }
    };
    let warn_ack_proof_sha256 = match (locked.receipt.requires_warn_ack, warn_acknowledged) {
        (false, false) => None,
        (false, true) => {
            return Err(
                "warning acknowledgement supplied for a receipt that does not require it"
                    .to_string(),
            )
        }
        (true, false) => {
            return Err("shell receipt still requires warning acknowledgement".to_string())
        }
        (true, true) => Some(interaction_proof_sha256(
            token,
            &locked.receipt,
            "warn_acknowledged",
        )),
    };
    let next = ReceiptState::Armed {
        approval,
        warn_ack_proof_sha256,
        armed_unix_ms: unix_time_ms()?,
    };
    match &locked.receipt.state {
        ReceiptState::Prepared => {
            locked.receipt.state = next;
            locked.publish()
        }
        ReceiptState::Armed {
            approval: existing_approval,
            warn_ack_proof_sha256: existing_warn_ack,
            ..
        } if existing_approval
            == match &next {
                ReceiptState::Armed { approval, .. } => approval,
                _ => unreachable!(),
            }
            && existing_warn_ack
                == match &next {
                    ReceiptState::Armed {
                        warn_ack_proof_sha256,
                        ..
                    } => warn_ack_proof_sha256,
                    _ => unreachable!(),
                } =>
        {
            Ok(())
        }
        ReceiptState::Armed { .. } => {
            Err("shell receipt retry changed its interaction outcome".to_string())
        }
        ReceiptState::Consuming { .. }
        | ReceiptState::Committed { .. }
        | ReceiptState::Conflict { .. } => {
            Err("shell receipt cannot be armed after consumption began".to_string())
        }
        ReceiptState::Discarded { .. } => Err("shell receipt was discarded".to_string()),
    }
}

pub fn discard_shell_execution_receipt(
    token: &str,
    expected_channel: ShellReceiptChannel,
) -> Result<(), String> {
    let mut locked = lock_receipt(token)?;
    // Discard is non-authorizing cleanup. Permit a context-bound expired
    // Prepared/Armed receipt to become terminal instead of wedging its hook.
    ensure_receipt_context(&locked.receipt, token, expected_channel)?;
    match locked.receipt.state {
        ReceiptState::Prepared | ReceiptState::Armed { .. } => {
            locked.receipt.state = ReceiptState::Discarded {
                finished_unix_ms: unix_time_ms()?,
            };
            locked.publish()
        }
        ReceiptState::Discarded { .. } => Ok(()),
        ReceiptState::Consuming { .. } => {
            Err("shell receipt cannot be discarded after consumption began".to_string())
        }
        ReceiptState::Committed { .. } => {
            Err("shell receipt was already durably consumed".to_string())
        }
        ReceiptState::Conflict { .. } => {
            Err("shell receipt ended in a durable identity conflict".to_string())
        }
    }
}

/// Reconcile a prior consume attempt without authorizing or promoting any new
/// execution. `true` means the exact immutable transition was already durable;
/// `false` means no committed transition exists yet. This is deliberately
/// separate from `consume`: a hook may clear old recovery state after a lost
/// acknowledgement, but can never use reconciliation to authorize a replay.
pub fn reconcile_shell_execution_receipt(
    token: &str,
    expected_channel: ShellReceiptChannel,
    lock_timeout: Duration,
) -> Result<bool, String> {
    let mut locked = lock_receipt(token)?;
    // Reconciliation never authorizes a transition. It may inspect an expired
    // Consuming/Committed receipt through the bounded recovery-retention window
    // so a lost acknowledgement cannot wedge the shell forever.
    ensure_receipt_context(&locked.receipt, token, expected_channel)?;
    let (
        observation,
        evidence_id,
        draft_identity_sha256,
        committed_policy_basis_sha256,
        committed_verdict_basis_sha256,
        consuming_unix_ms,
    ) = match &locked.receipt.state {
        ReceiptState::Committed { .. } => return Ok(true),
        ReceiptState::Conflict { .. } => {
            return Err(
                "shell receipt ended in a durable identity conflict; refusing reconciliation"
                    .to_string(),
            )
        }
        ReceiptState::Prepared | ReceiptState::Armed { .. } | ReceiptState::Discarded { .. } => {
            return Ok(false);
        }
        ReceiptState::Consuming {
            observation,
            evidence_id,
            draft_identity_sha256,
            committed_policy_basis_sha256,
            committed_verdict_basis_sha256,
            consuming_unix_ms,
            ..
        } => (
            observation.clone(),
            evidence_id.clone(),
            draft_identity_sha256.clone(),
            committed_policy_basis_sha256.clone(),
            committed_verdict_basis_sha256.clone(),
            *consuming_unix_ms,
        ),
    };
    match recover_shell_receipt_transition(
        &locked.receipt.session_id,
        &locked.receipt.execution_id,
        &draft_identity_sha256,
        &locked.receipt.command_sha256,
        &committed_policy_basis_sha256,
        &committed_verdict_basis_sha256,
        &evidence_id,
        lock_timeout,
    )? {
        ShellReceiptRecovery::Committed { generation } => {
            locked.receipt.state = ReceiptState::Committed {
                observation,
                evidence_id,
                generation,
                finished_unix_ms: unix_time_ms()?,
            };
            locked.publish()?;
            Ok(true)
        }
        ShellReceiptRecovery::Missing => {
            let retry_window_ms =
                u64::try_from(CONSUMING_RETRY_WINDOW.as_millis()).unwrap_or(u64::MAX);
            if unix_time_ms()? >= consuming_unix_ms.saturating_add(retry_window_ms) {
                locked.receipt.state = ReceiptState::Discarded {
                    finished_unix_ms: unix_time_ms()?,
                };
                locked.publish()?;
            }
            Ok(false)
        }
    }
}

pub fn consume_shell_execution_receipt(
    token: &str,
    expected_channel: ShellReceiptChannel,
    command: &str,
    mut prepared: PreparedExecution,
    lock_timeout: Duration,
) -> Result<PromotionOutcome, String> {
    let mut locked = lock_receipt(token)?;
    ensure_live(&locked.receipt, token, expected_channel)?;
    let (approval, warn_ack_proof_sha256, prior_consuming) = match &locked.receipt.state {
        ReceiptState::Armed {
            approval,
            warn_ack_proof_sha256,
            ..
        } => (approval.clone(), warn_ack_proof_sha256.clone(), None),
        ReceiptState::Consuming {
            approval,
            warn_ack_proof_sha256,
            observation,
            evidence_id,
            draft_identity_sha256,
            committed_policy_basis_sha256,
            committed_verdict_basis_sha256,
            consuming_unix_ms,
        } => (
            approval.clone(),
            warn_ack_proof_sha256.clone(),
            Some((
                observation.clone(),
                evidence_id.clone(),
                draft_identity_sha256.clone(),
                committed_policy_basis_sha256.clone(),
                committed_verdict_basis_sha256.clone(),
                *consuming_unix_ms,
            )),
        ),
        ReceiptState::Prepared => return Err("shell execution receipt is not armed".to_string()),
        ReceiptState::Committed { .. } => {
            return Err("shell execution receipt was already consumed".to_string())
        }
        ReceiptState::Conflict { .. } => {
            return Err("shell receipt ended in a durable identity conflict".to_string())
        }
        ReceiptState::Discarded { .. } => {
            return Err("shell execution receipt was discarded".to_string())
        }
    };

    let mut consuming_started_unix_ms = None;
    if let Some((
        observation,
        prior_evidence_id,
        prior_identity,
        prior_policy_basis,
        prior_verdict_basis,
        prior_consuming_unix_ms,
    )) = prior_consuming
    {
        consuming_started_unix_ms = Some(prior_consuming_unix_ms);
        if observation != locked.receipt.channel.observation_tag() {
            return Err("shell receipt retry changed its observation boundary".to_string());
        }
        match recover_shell_receipt_transition(
            &locked.receipt.session_id,
            &locked.receipt.execution_id,
            &prior_identity,
            &locked.receipt.command_sha256,
            &prior_policy_basis,
            &prior_verdict_basis,
            &prior_evidence_id,
            lock_timeout,
        )? {
            ShellReceiptRecovery::Committed { generation } => {
                locked.receipt.state = ReceiptState::Committed {
                    observation,
                    evidence_id: prior_evidence_id,
                    generation,
                    finished_unix_ms: unix_time_ms()?,
                };
                locked.publish()?;
                return Err(
                    "shell receipt recovery found a prior durable consumption; refusing replay"
                        .to_string(),
                );
            }
            ShellReceiptRecovery::Missing => {}
        }
        let retry_window_ms = u64::try_from(CONSUMING_RETRY_WINDOW.as_millis()).unwrap_or(u64::MAX);
        if unix_time_ms()? >= prior_consuming_unix_ms.saturating_add(retry_window_ms) {
            locked.receipt.state = ReceiptState::Discarded {
                finished_unix_ms: unix_time_ms()?,
            };
            locked.publish()?;
            return Err("shell receipt consumption outcome is too old to retry safely".to_string());
        }
    }

    // Once a receipt reached Consuming, first reconcile its exact immutable
    // transition against the durable ledger. A policy change after a crash must
    // not prevent an already-committed receipt from becoming terminal.
    if prepared.draft.caller() != CallerContext::Cli
        || prepared.draft.session_id() != locked.receipt.session_id
        || prepared.draft.shell() != locked.receipt.shell
        || prepared.draft.shell() != locked.receipt.channel.expected_shell()
    {
        return Err("fresh shell decision does not match the receipt context".to_string());
    }
    let expected_command_binding = locked
        .receipt
        .command_binding_sha256
        .as_ref()
        .ok_or_else(|| "shell receipt lacks its exact command binding".to_string())?;
    let command_matches = secret_seal(
        token,
        "tirith-shell-command-binding-v1",
        &serde_json::Value::String(command.to_string()),
    ) == *expected_command_binding
        && super::privacy_projected_command_sha256(command) == locked.receipt.command_sha256
        && prepared.draft.command_sha256() == locked.receipt.command_sha256;
    if !command_matches || prepared.draft.command() != command {
        return Err("shell command changed after receipt preparation".to_string());
    }
    if locked.receipt.strict_warn_override
        && prepared.draft.decision.action == Action::Warn
        && !prepared.draft.decision.requires_warn_ack
    {
        return Err(
            "fresh strict-warn decision lacks a warning acknowledgement requirement".to_string(),
        );
    }
    let binding = receipt_binding_sha256(
        &prepared.draft,
        &locked.receipt.command_sha256,
        locked.receipt.channel,
        locked.receipt.strict_warn_override,
        locked
            .receipt
            .cwd_binding_sha256
            .as_deref()
            .ok_or_else(|| "shell receipt lacks its exact working-directory binding".to_string())?,
        &locked.receipt.hook_instance_sha256,
    )?;
    if binding != locked.receipt.decision_binding_sha256
        || prepared.draft.decision.policy_basis_sha256 != locked.receipt.policy_basis_sha256
        || semantic_verdict_sha256(&prepared.draft.effective_verdict)?
            != locked.receipt.semantic_verdict_basis_sha256
    {
        return Err("fresh shell decision changed after receipt preparation".to_string());
    }
    prepared
        .draft
        .replace_execution_id(locked.receipt.execution_id.clone())?;
    prepared
        .draft
        .resolve_verified_interactions(VerifiedInteractions {
            approval: approval.as_ref().map(StoredApprovalResolution::to_verified),
            warn_ack_proof_sha256,
        })?;
    validate_draft(&prepared.draft)?;
    let evidence_id = evidence_id(&locked.receipt);
    locked.receipt.state = ReceiptState::Consuming {
        approval,
        warn_ack_proof_sha256: prepared
            .draft
            .interaction
            .warn_ack_proof_sha256()
            .map(str::to_string),
        observation: locked.receipt.channel.observation_tag().to_string(),
        evidence_id: evidence_id.clone(),
        draft_identity_sha256: prepared.draft.draft_identity_sha256.clone(),
        committed_policy_basis_sha256: prepared.draft.decision.policy_basis_sha256.clone(),
        committed_verdict_basis_sha256: prepared.draft.decision.verdict_basis_sha256.clone(),
        consuming_unix_ms: match consuming_started_unix_ms {
            Some(started) => started,
            None => unix_time_ms()?,
        },
    };
    locked.publish()?;

    let gate = ExecutionGate::acquire(prepared.into_authorizable_draft()?, lock_timeout)?;
    let outcome = match gate.promote_shell_unresolved(evidence_id.clone()) {
        Ok(outcome) => outcome,
        Err(error) if is_terminal_execution_replay_conflict(&error) => {
            // The strict ledger refused this execution ID before publication,
            // so committed history remains unchanged. Make the receipt itself
            // terminal: otherwise a freshly armed replay could remain in
            // Consuming and repeatedly probe the same conflicting identity.
            locked.receipt.state = ReceiptState::Conflict {
                observation: locked.receipt.channel.observation_tag().to_string(),
                evidence_id,
                generation: None,
                finished_unix_ms: unix_time_ms()?,
            };
            locked.publish()?;
            return Err(format!(
                "shell receipt durable identity conflict; refusing replay: {error}"
            ));
        }
        Err(error) => return Err(error),
    };
    let generation = match outcome {
        PromotionOutcome::Committed { generation } => generation,
        PromotionOutcome::Upgraded { generation } | PromotionOutcome::Idempotent { generation } => {
            locked.receipt.state = ReceiptState::Conflict {
                observation: locked.receipt.channel.observation_tag().to_string(),
                evidence_id,
                generation: Some(generation),
                finished_unix_ms: unix_time_ms()?,
            };
            locked.publish()?;
            return Err(
                "newly armed shell receipt matched a prior transition; refusing replay".to_string(),
            );
        }
    };
    locked.receipt.state = ReceiptState::Committed {
        observation: locked.receipt.channel.observation_tag().to_string(),
        evidence_id,
        generation,
        finished_unix_ms: unix_time_ms()?,
    };
    locked.publish()?;
    Ok(outcome)
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use crate::verdict::{Evidence, Finding, RuleId, Severity, Timings, Verdict};
    use std::ffi::OsString;
    use std::os::unix::fs::{symlink, PermissionsExt as _};
    use tirith_test_support::GlobalStateGuard;

    const OTHER_HOOK_INSTANCE: &str =
        "2222222222222222222222222222222222222222222222222222222222222222";

    struct ReceiptCreationTestCheckpointGuard;

    impl Drop for ReceiptCreationTestCheckpointGuard {
        fn drop(&mut self) {
            *RECEIPT_CREATION_TEST_CHECKPOINT
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner) = None;
        }
    }

    fn isolated_unregistered_state_with_guard(
        test: impl FnOnce(&tempfile::TempDir, &str, &mut GlobalStateGuard),
    ) {
        let mut environment = GlobalStateGuard::new().expect("isolate shell receipt state");
        let temporary = tempfile::tempdir().expect("isolated shell receipt state");
        environment.set_env("XDG_STATE_HOME", temporary.path());
        let session_id = crate::session::resolve_session_id();
        assert!(crate::session_warnings::session_state_path(&session_id).is_some());
        test(&temporary, &session_id, &mut environment);
    }

    fn isolated_unregistered_state(test: impl FnOnce(&tempfile::TempDir, &str)) {
        isolated_unregistered_state_with_guard(|temporary, session_id, _| {
            test(temporary, session_id);
        });
    }

    fn isolated_state_with_guard(
        test: impl FnOnce(&tempfile::TempDir, &str, &mut GlobalStateGuard),
    ) {
        isolated_unregistered_state_with_guard(|temporary, session_id, environment| {
            let shell_pid = unsafe { libc::getppid() } as u32;
            let hook_instance =
                register_shell_hook_instance(shell_pid, ShellHookFamily::Zsh, session_id)
                    .expect("register isolated shell hook capability");
            environment.set_env("_TIRITH_RECEIPT_INSTANCE", &hook_instance);
            environment.set_env("_TIRITH_RECEIPT_SHELL_PID", shell_pid.to_string());
            environment.set_env("_TIRITH_RECEIPT_FAMILY", "zsh");
            test(temporary, session_id, environment);
        });
    }

    fn isolated_state(test: impl FnOnce(&tempfile::TempDir, &str)) {
        isolated_state_with_guard(|temporary, session_id, _| {
            test(temporary, session_id);
        });
    }

    fn allow_verdict() -> Verdict {
        Verdict::allow_fast(3, Timings::default())
    }

    fn risk_finding(rule_id: RuleId, severity: Severity) -> Finding {
        Finding {
            rule_id,
            severity,
            title: "shell receipt fixture".to_string(),
            description: "shell receipt fixture".to_string(),
            evidence: vec![Evidence::Text {
                detail: "shell receipt fixture".to_string(),
            }],
            human_view: None,
            agent_view: None,
            mitre_id: None,
            custom_rule_id: None,
        }
    }

    fn warning_verdict(requires_approval: bool, fallback: Option<&str>) -> Verdict {
        let mut verdict = Verdict::from_findings(
            vec![risk_finding(RuleId::NonAsciiHostname, Severity::Medium)],
            3,
            Timings::default(),
        );
        verdict.requires_approval = requires_approval.then_some(true);
        verdict.approval_fallback = fallback.map(str::to_string);
        verdict
    }

    fn block_verdict_with_allow_fallback() -> Verdict {
        let mut verdict = Verdict::from_findings(
            vec![risk_finding(RuleId::CurlPipeShell, Severity::High)],
            3,
            Timings::default(),
        );
        verdict.requires_approval = Some(true);
        verdict.approval_fallback = Some("allow".to_string());
        verdict
    }

    fn prepare(
        verdict: &Verdict,
        policy: &Policy,
        command: &str,
        session_id: &str,
    ) -> PreparedExecution {
        prepare_execution(
            verdict,
            policy,
            command,
            session_id,
            CallerContext::Cli,
            ShellType::Posix,
            Duration::from_secs(2 * 60),
            Duration::from_secs(1),
        )
        .expect("prepare shell execution")
    }

    fn create(
        verdict: &Verdict,
        policy: &Policy,
        command: &str,
        session_id: &str,
        strict_warn_override: bool,
    ) -> String {
        let prepared = prepare(verdict, policy, command, session_id);
        assert_eq!(
            prepared.draft.decision.action, verdict.action,
            "receipt test fixture action changed during preparation"
        );
        assert_eq!(
            prepared.draft.decision.requires_approval,
            verdict.requires_approval == Some(true),
            "receipt test fixture approval requirement changed during preparation"
        );
        create_shell_execution_receipt(
            &prepared,
            ShellReceiptChannel::Zsh,
            true,
            strict_warn_override,
            Duration::from_secs(60),
        )
        .expect("create shell execution receipt")
    }

    fn arm_allow(token: &str) {
        arm_shell_execution_receipt(token, ShellReceiptChannel::Zsh, None, false)
            .expect("arm allow receipt");
    }

    fn receipt_path(token: &str) -> PathBuf {
        receipt_paths(token).expect("receipt paths").1
    }

    fn receipt_lock_path(token: &str) -> PathBuf {
        receipt_paths(token).expect("receipt paths").2
    }

    fn replace_receipt_bytes(token: &str, bytes: &[u8]) {
        let path = receipt_path(token);
        fs::write(&path, bytes).expect("replace shell receipt bytes");
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600))
            .expect("restore private receipt mode");
    }

    fn legacy_raw_cwd_sha256() -> String {
        use std::os::unix::ffi::OsStrExt as _;

        sha256_hex(
            std::env::current_dir()
                .expect("legacy cwd")
                .as_os_str()
                .as_bytes(),
        )
    }

    fn rewrite_as_legacy_v1(token: &str, raw_command_sha256: &str) {
        let mut receipt: ShellReceipt = serde_json::from_slice(
            &fs::read(receipt_path(token)).expect("read current receipt fixture"),
        )
        .expect("parse current receipt fixture");
        receipt.schema_version = LEGACY_RAW_COMMAND_RECEIPT_SCHEMA_VERSION;
        receipt.cwd_sha256 = Some(legacy_raw_cwd_sha256());
        receipt.cwd_binding_sha256 = None;
        receipt.command_sha256 = raw_command_sha256.to_string();
        receipt.command_binding_sha256 = None;
        refresh_receipt_seals(&mut receipt, token).expect("seal authenticated schema-v1 receipt");
        replace_receipt_bytes(
            token,
            &serde_json::to_vec(&receipt).expect("serialize legacy receipt fixture"),
        );
    }

    fn rewrite_as_legacy_v2(token: &str) {
        let mut receipt: ShellReceipt = serde_json::from_slice(
            &fs::read(receipt_path(token)).expect("read current receipt fixture"),
        )
        .expect("parse current receipt fixture");
        receipt.schema_version = LEGACY_RAW_CWD_RECEIPT_SCHEMA_VERSION;
        receipt.cwd_sha256 = Some(legacy_raw_cwd_sha256());
        receipt.cwd_binding_sha256 = None;
        refresh_receipt_seals(&mut receipt, token).expect("seal authenticated schema-v2 receipt");
        replace_receipt_bytes(
            token,
            &serde_json::to_vec(&receipt).expect("serialize schema-v2 receipt fixture"),
        );
    }

    fn strict_generation(session_id: &str) -> u64 {
        let state = crate::session_warnings::session_state_path(session_id).expect("state path");
        let (file, ledger, _, _, _) = open_or_initialize_strict_state(
            state.parent().expect("state parent"),
            session_id,
            None,
            None,
        )
        .expect("strict receipt-test ledger");
        drop(file);
        ledger.generation
    }

    fn active_capability_paths() -> (PathBuf, PathBuf) {
        let shell_pid = std::env::var("_TIRITH_RECEIPT_SHELL_PID")
            .expect("registered test shell PID")
            .parse::<u32>()
            .expect("numeric test shell PID");
        let shell_identity =
            shell_process_identity(shell_pid).expect("live registered test shell identity");
        capability_paths(
            unsafe { libc::geteuid() },
            shell_pid,
            &shell_identity.start_fingerprint,
        )
        .expect("test capability paths")
    }

    fn active_capability_path() -> PathBuf {
        active_capability_paths().0
    }

    fn replace_capability(capability: &mut ShellHookCapability, secret: &str) {
        refresh_capability_seal(capability, secret);
        let path = active_capability_path();
        fs::write(
            &path,
            serde_json::to_vec(capability).expect("serialize test capability"),
        )
        .expect("replace test capability");
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600))
            .expect("restore private capability mode");
    }

    /// Put an armed allow receipt into the exact durable state that exists
    /// after the receipt journal is published but before ledger promotion.
    fn force_consuming(token: &str, prepared: &mut PreparedExecution) -> String {
        let mut locked = lock_receipt(token).expect("lock armed receipt");
        let (approval, warn_ack_proof_sha256) = match &locked.receipt.state {
            ReceiptState::Armed {
                approval,
                warn_ack_proof_sha256,
                ..
            } => (approval.clone(), warn_ack_proof_sha256.clone()),
            state => panic!("expected armed receipt, got {state:?}"),
        };
        assert!(approval.is_none());
        assert!(warn_ack_proof_sha256.is_none());

        prepared
            .draft
            .replace_execution_id(locked.receipt.execution_id.clone())
            .expect("bind execution id");
        prepared
            .draft
            .resolve_verified_interactions(VerifiedInteractions {
                approval: None,
                warn_ack_proof_sha256: None,
            })
            .expect("resolve allow interactions");
        validate_draft(&prepared.draft).expect("validate consuming draft");

        let evidence_id = evidence_id(&locked.receipt);
        locked.receipt.state = ReceiptState::Consuming {
            approval,
            warn_ack_proof_sha256,
            observation: ShellReceiptChannel::Zsh.observation_tag().to_string(),
            evidence_id: evidence_id.clone(),
            draft_identity_sha256: prepared.draft.draft_identity_sha256.clone(),
            committed_policy_basis_sha256: prepared.draft.decision.policy_basis_sha256.clone(),
            committed_verdict_basis_sha256: prepared.draft.decision.verdict_basis_sha256.clone(),
            consuming_unix_ms: unix_time_ms().expect("current receipt time"),
        };
        locked.publish().expect("publish consuming receipt");
        evidence_id
    }

    #[test]
    fn allow_receipt_consumes_once_and_durable_json_excludes_bearer_and_raw_command() {
        isolated_state(|_, session_id| {
            let command = "curl -H 'Authorization: Bearer sk-proj-receipt-secret-never-persist' https://example.invalid/really-long-private-command";
            let policy = Policy::default();
            let verdict = allow_verdict();
            let raw_command_sha256 = sha256_hex(command.as_bytes());
            let token = create(&verdict, &policy, command, session_id, false);
            let durable = fs::read_to_string(receipt_path(&token)).expect("read receipt JSON");
            assert!(
                !durable.contains(command),
                "raw command reached durable receipt"
            );
            assert!(
                !durable.contains(&token),
                "bearer token reached durable receipt"
            );
            assert!(
                !durable.contains("sk-proj-receipt"),
                "a stable secret prefix reached durable receipt: {durable}"
            );
            assert!(
                !durable.contains(&raw_command_sha256),
                "the raw-command digest remained an offline oracle: {durable}"
            );

            arm_allow(&token);
            let fresh = prepare(&verdict, &policy, command, session_id);
            let outcome = consume_shell_execution_receipt(
                &token,
                ShellReceiptChannel::Zsh,
                command,
                fresh,
                Duration::from_secs(1),
            )
            .expect("consume allow receipt");
            assert!(matches!(outcome, PromotionOutcome::Committed { .. }));

            let replay = prepare(&verdict, &policy, command, session_id);
            let error = consume_shell_execution_receipt(
                &token,
                ShellReceiptChannel::Zsh,
                command,
                replay,
                Duration::from_secs(1),
            )
            .expect_err("committed receipt must not replay");
            assert!(
                error.contains("already consumed"),
                "unexpected error: {error}"
            );
        });
    }

    #[test]
    fn protocol_v3_registration_is_one_time_per_process_and_bound_to_family_session_and_secret() {
        isolated_state(|_, session_id| {
            let secret =
                std::env::var("_TIRITH_RECEIPT_INSTANCE").expect("registered test capability");
            let shell_pid = std::env::var("_TIRITH_RECEIPT_SHELL_PID")
                .expect("registered test shell PID")
                .parse::<u32>()
                .expect("numeric test shell PID");
            validate_shell_hook_instance(&secret, shell_pid, ShellHookFamily::Zsh, session_id)
                .expect("validate the registered capability");

            let durable = fs::read_to_string(active_capability_path())
                .expect("read durable shell capability");
            assert!(
                !durable.contains(&secret),
                "capability bearer reached durable storage"
            );
            let durable_anchor = fs::read_to_string(active_capability_paths().1)
                .expect("read durable shell capability anchor");
            assert!(
                !durable_anchor.contains(&secret),
                "capability bearer reached durable anchor storage"
            );
            let duplicate =
                register_shell_hook_instance(shell_pid, ShellHookFamily::Zsh, session_id)
                    .expect_err("a live shell identity must not register twice");
            assert!(
                duplicate.contains("already has"),
                "unexpected duplicate error: {duplicate}"
            );
            let second_family =
                register_shell_hook_instance(shell_pid, ShellHookFamily::Fish, session_id)
                    .expect_err("a live process must not register a second shell family");
            assert!(
                second_family.contains("already has"),
                "unexpected second-family error: {second_family}"
            );

            let wrong_secret = validate_shell_hook_instance(
                OTHER_HOOK_INSTANCE,
                shell_pid,
                ShellHookFamily::Zsh,
                session_id,
            )
            .expect_err("an unregistered bearer must fail");
            assert!(
                wrong_secret.contains("secret"),
                "unexpected bearer error: {wrong_secret}"
            );
            let wrong_family =
                validate_shell_hook_instance(&secret, shell_pid, ShellHookFamily::Fish, session_id)
                    .expect_err("a registered bearer must not cross shell families");
            assert!(
                wrong_family.contains("shell family"),
                "unexpected family error: {wrong_family}"
            );
            let other_session = uuid::Uuid::new_v4().to_string();
            let wrong_session = validate_shell_hook_instance(
                &secret,
                shell_pid,
                ShellHookFamily::Zsh,
                &other_session,
            )
            .expect_err("a registered bearer must not cross sessions");
            assert!(
                wrong_session.contains("different session"),
                "unexpected session error: {wrong_session}"
            );
        });
    }

    #[test]
    fn failed_bearer_delivery_never_issues_and_allows_same_process_retry() {
        isolated_unregistered_state(|_, session_id| {
            let shell_pid = unsafe { libc::getppid() } as u32;
            let shell_identity =
                shell_process_identity(shell_pid).expect("live registration target");
            let (capability_path, anchor_path) = capability_paths(
                unsafe { libc::geteuid() },
                shell_pid,
                &shell_identity.start_fingerprint,
            )
            .expect("delivery-failure capability paths");
            let mut partially_delivered = None;

            let error = register_shell_hook_instance_with_delivery(
                shell_pid,
                ShellHookFamily::Zsh,
                session_id,
                |secret| {
                    partially_delivered = Some(secret.to_string());
                    assert!(
                        capability_path.exists(),
                        "the sealed capability must precede delivery"
                    );
                    let anchor: ShellHookCapabilityAnchor = serde_json::from_slice(
                        &fs::read(&anchor_path).expect("read anchor during failed delivery"),
                    )
                    .expect("parse anchor during failed delivery");
                    assert!(
                        matches!(
                            anchor.state,
                            ShellHookCapabilityAnchorState::Prepared { .. }
                        ),
                        "the bearer must remain unusable until delivery succeeds"
                    );
                    Err::<(), String>("simulated stdout delivery failure".to_string())
                },
            )
            .expect_err("failed delivery must fail registration");
            assert!(
                error.contains("simulated stdout delivery failure"),
                "unexpected delivery error: {error}"
            );

            let partially_delivered =
                partially_delivered.expect("delivery callback must receive a bearer");
            assert!(
                !capability_path.exists() && !anchor_path.exists(),
                "a failed delivery must roll back its Prepared capability pair"
            );
            assert!(
                validate_shell_hook_instance(
                    &partially_delivered,
                    shell_pid,
                    ShellHookFamily::Zsh,
                    session_id,
                )
                .is_err(),
                "a partially delivered bearer must never validate"
            );

            let retry = register_shell_hook_instance(shell_pid, ShellHookFamily::Zsh, session_id)
                .expect("same-process retry after failed delivery");
            assert_ne!(retry, partially_delivered);
            validate_shell_hook_instance(&retry, shell_pid, ShellHookFamily::Zsh, session_id)
                .expect("validate retry bearer");
        });
    }

    #[test]
    fn incomplete_process_anchor_is_recovered_without_issuing_two_bearers() {
        isolated_unregistered_state(|_, session_id| {
            let shell_pid = unsafe { libc::getppid() } as u32;
            let shell_identity =
                shell_process_identity(shell_pid).expect("live registration target");
            let (capability_path, anchor_path) = capability_paths(
                unsafe { libc::geteuid() },
                shell_pid,
                &shell_identity.start_fingerprint,
            )
            .expect("process-scoped capability paths");

            let prepared = prepared_capability_anchor(
                unsafe { libc::geteuid() },
                shell_pid,
                &shell_identity.start_fingerprint,
            )
            .expect("prepare interrupted registration marker");
            let incomplete = create_capability_anchor(&anchor_path, &prepared)
                .expect("create interrupted registration anchor");
            let incomplete_identity =
                secure_regular_identity(&incomplete, "interrupted registration anchor")
                    .expect("inspect interrupted registration anchor");
            drop(incomplete);
            assert!(!capability_path.exists());

            let secret = register_shell_hook_instance(shell_pid, ShellHookFamily::Zsh, session_id)
                .expect("recover incomplete registration");
            validate_shell_hook_instance(&secret, shell_pid, ShellHookFamily::Zsh, session_id)
                .expect("validate recovered registration");
            assert!(capability_path.exists());
            let recovered =
                open_capability_anchor(&anchor_path).expect("open recovered registration anchor");
            assert_eq!(
                secure_regular_identity(&recovered, "recovered registration anchor")
                    .expect("inspect recovered registration anchor"),
                incomplete_identity,
                "incomplete registration must resume under the same anchor inode"
            );
            drop(recovered);

            let duplicate =
                register_shell_hook_instance(shell_pid, ShellHookFamily::Zsh, session_id)
                    .expect_err("sealed recovery must remain one-time");
            assert!(
                duplicate.contains("already has"),
                "unexpected duplicate error: {duplicate}"
            );
        });
    }

    #[test]
    fn issued_anchor_survives_record_deletion_and_never_reissues_a_bearer() {
        isolated_unregistered_state(|_, session_id| {
            let shell_pid = unsafe { libc::getppid() } as u32;
            let secret = register_shell_hook_instance(shell_pid, ShellHookFamily::Zsh, session_id)
                .expect("register shell capability");
            let shell_identity =
                shell_process_identity(shell_pid).expect("live registered shell identity");
            let (capability_path, anchor_path) = capability_paths(
                unsafe { libc::geteuid() },
                shell_pid,
                &shell_identity.start_fingerprint,
            )
            .expect("issued capability paths");

            fs::remove_file(&capability_path).expect("delete issued capability record");
            crate::util::fsync_parent_dir(&capability_path)
                .expect("sync issued capability deletion");
            assert!(
                validate_shell_hook_instance(&secret, shell_pid, ShellHookFamily::Zsh, session_id,)
                    .is_err(),
                "a missing issued record must invalidate its old bearer"
            );

            let error = register_shell_hook_instance(shell_pid, ShellHookFamily::Zsh, session_id)
                .expect_err("record deletion must not reset one-time registration");
            assert!(
                error.contains("already has"),
                "unexpected deleted-record retry error: {error}"
            );
            assert!(!capability_path.exists());

            let anchor = open_capability_anchor(&anchor_path)
                .expect("issued tombstone must remain while its process is live");
            let marker = read_capability_anchor(&anchor).expect("read issued tombstone");
            assert!(matches!(
                marker.state,
                ShellHookCapabilityAnchorState::Issued { .. }
            ));
        });
    }

    const CAPABILITY_PROCESS_HELPER: &str =
        "execution_state::shell_receipt::tests::protocol_v3_capability_process_helper";

    fn run_capability_process_helper(
        mode: &str,
        temporary: &tempfile::TempDir,
        session_id: &str,
    ) -> std::process::Output {
        std::process::Command::new(std::env::current_exe().expect("test executable path"))
            .args([
                "--ignored",
                "--exact",
                CAPABILITY_PROCESS_HELPER,
                "--nocapture",
            ])
            .env("TIRITH_CAPABILITY_PROCESS_HELPER", mode)
            .env("TIRITH_SESSION_ID", session_id)
            .env("XDG_STATE_HOME", temporary.path())
            .output()
            .expect("run capability process helper")
    }

    fn capability_artifact_count(directory: &Path, lock: bool) -> usize {
        fs::read_dir(directory)
            .expect("scan capability artifacts")
            .filter_map(Result::ok)
            .filter(|entry| {
                let name = entry.file_name();
                let Some(name) = name.to_str() else {
                    return false;
                };
                if lock {
                    hook_capability_lock_key(name).is_some()
                } else {
                    hook_capability_key(name).is_some()
                }
            })
            .count()
    }

    fn receipt_artifact_count(directory: &Path) -> usize {
        fs::read_dir(directory)
            .expect("scan receipt artifacts")
            .filter_map(Result::ok)
            .filter(|entry| {
                entry
                    .file_name()
                    .to_str()
                    .is_some_and(|name| name.ends_with(".json"))
            })
            .count()
    }

    #[test]
    fn receipt_capacity_enumeration_fails_closed_on_entry_error() {
        let below_capacity = vec![
            Ok(OsString::from("one.json")),
            Ok(OsString::from("one.lock")),
        ];
        assert!(enforce_receipt_capacity(below_capacity).is_ok());

        let interrupted = vec![
            Ok(OsString::from("one.json")),
            Err(std::io::Error::other("simulated readdir failure")),
            Ok(OsString::from("two.json")),
        ];
        let error = enforce_receipt_capacity(interrupted)
            .expect_err("an unreadable directory entry must make capacity unknown");
        assert!(error.contains("read shell receipt capacity entry"));
        assert!(error.contains("simulated readdir failure"));
    }

    #[test]
    fn receipt_registry_serializes_capacity_check_through_publication() {
        isolated_state(|_, session_id| {
            let directory = receipt_directory().expect("receipt directory");
            for index in 0..MAX_RECEIPTS - 1 {
                let stem = sha256_hex(format!("receipt-capacity-fixture-{index}").as_bytes());
                let path = directory.join(format!("{stem}.json"));
                fs::write(&path, b"{}").expect("write retained receipt capacity fixture");
                fs::set_permissions(&path, fs::Permissions::from_mode(0o600))
                    .expect("secure retained receipt capacity fixture");
            }

            let policy = Policy::default();
            let verdict = allow_verdict();
            let first_prepared = prepare(&verdict, &policy, "echo capacity-first", session_id);
            let second_prepared = prepare(&verdict, &policy, "echo capacity-second", session_id);
            let checkpoint = std::sync::Arc::new(ReceiptCreationTestCheckpoint::default());
            {
                let mut installed = RECEIPT_CREATION_TEST_CHECKPOINT
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                assert!(installed.is_none(), "receipt creation checkpoint leaked");
                *installed = Some(std::sync::Arc::clone(&checkpoint));
            }
            let _checkpoint_guard = ReceiptCreationTestCheckpointGuard;
            let start = std::sync::Arc::new(std::sync::Barrier::new(3));

            let first_start = std::sync::Arc::clone(&start);
            let first = std::thread::spawn(move || {
                first_start.wait();
                create_shell_execution_receipt(
                    &first_prepared,
                    ShellReceiptChannel::Zsh,
                    true,
                    false,
                    Duration::from_secs(60),
                )
            });
            let second_start = std::sync::Arc::clone(&start);
            let second = std::thread::spawn(move || {
                second_start.wait();
                create_shell_execution_receipt(
                    &second_prepared,
                    ShellReceiptChannel::Zsh,
                    true,
                    false,
                    Duration::from_secs(60),
                )
            });
            start.wait();

            let mut checkpoint_state = checkpoint
                .state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            while checkpoint_state.0 == 0 {
                checkpoint_state = checkpoint
                    .changed
                    .wait(checkpoint_state)
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
            }
            let (mut checkpoint_state, timeout) = checkpoint
                .changed
                .wait_timeout_while(checkpoint_state, Duration::from_millis(500), |state| {
                    state.0 < 2
                })
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let serialized = timeout.timed_out() && checkpoint_state.0 == 1;
            checkpoint_state.1 = usize::MAX;
            checkpoint.changed.notify_all();
            drop(checkpoint_state);

            let outcomes = [
                first.join().expect("join first receipt creator"),
                second.join().expect("join second receipt creator"),
            ];
            assert!(
                serialized,
                "two creators passed the capacity check before either publication"
            );
            assert_eq!(
                outcomes.iter().filter(|result| result.is_ok()).count(),
                1,
                "exactly one final receipt slot must be published"
            );
            let capacity_error = outcomes
                .iter()
                .find_map(|result| result.as_ref().err())
                .expect("one creator must be rejected at capacity");
            assert!(
                capacity_error.contains("capacity is exhausted"),
                "unexpected capacity error: {capacity_error}"
            );
            assert_eq!(receipt_artifact_count(&directory), MAX_RECEIPTS);
        });
    }

    #[test]
    fn capability_registry_enforces_the_capacity_threshold_before_publication() {
        isolated_unregistered_state(|_, session_id| {
            let directory = receipt_directory().expect("receipt directory");
            for index in 0..MAX_HOOK_CAPABILITIES - 1 {
                let key = sha256_hex(format!("capacity-fixture-{index}").as_bytes());
                let path = directory.join(format!(".hook-{key}.capability"));
                fs::write(&path, b"{}").expect("write retained capacity fixture");
                fs::set_permissions(&path, fs::Permissions::from_mode(0o600))
                    .expect("secure retained capacity fixture");
            }

            let shell_pid = unsafe { libc::getppid() } as u32;
            let secret = register_shell_hook_instance(shell_pid, ShellHookFamily::Zsh, session_id)
                .expect("the final available capability slot must be usable");
            assert_eq!(
                capability_artifact_count(&directory, false),
                MAX_HOOK_CAPABILITIES
            );
            validate_shell_hook_instance(&secret, shell_pid, ShellHookFamily::Zsh, session_id)
                .expect("capacity-edge capability must validate");

            let error = register_shell_hook_instance(shell_pid, ShellHookFamily::Zsh, session_id)
                .expect_err("a full registry must reject publication");
            assert!(
                error.contains("capacity is exhausted"),
                "unexpected full-registry error: {error}"
            );
            assert_eq!(
                capability_artifact_count(&directory, false),
                MAX_HOOK_CAPABILITIES
            );
        });
    }

    #[test]
    fn nested_process_registration_does_not_collide_with_parent_session_slot() {
        isolated_state(|temporary, session_id| {
            let output = run_capability_process_helper("register", temporary, session_id);
            assert!(
                output.status.success(),
                "nested registration failed: stdout={} stderr={}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
            let directory = receipt_directory().expect("receipt directory");
            assert_eq!(capability_artifact_count(&directory, false), 2);
            assert_eq!(capability_artifact_count(&directory, true), 2);
        });
    }

    #[test]
    fn dead_nested_process_capability_and_anchor_are_cleaned_as_a_pair() {
        isolated_state(|temporary, session_id| {
            let output = run_capability_process_helper("coordinate", temporary, session_id);
            assert!(
                output.status.success(),
                "stale registration fixture failed: stdout={} stderr={}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
            let directory = receipt_directory().expect("receipt directory");
            assert_eq!(capability_artifact_count(&directory, false), 2);
            assert_eq!(capability_artifact_count(&directory, true), 2);

            cleanup_hook_capabilities(&directory).expect("clean stale capability pair");
            assert_eq!(capability_artifact_count(&directory, false), 1);
            assert_eq!(capability_artifact_count(&directory, true), 1);
        });
    }

    #[test]
    #[ignore = "subprocess helper for process-scoped capability tests"]
    fn protocol_v3_capability_process_helper() {
        match std::env::var("TIRITH_CAPABILITY_PROCESS_HELPER").as_deref() {
            Ok("register") => {
                let session_id = crate::session::resolve_session_id();
                let shell_pid = unsafe { libc::getppid() } as u32;
                let secret =
                    register_shell_hook_instance(shell_pid, ShellHookFamily::Fish, &session_id)
                        .expect("register subprocess shell capability");
                validate_shell_hook_instance(
                    &secret,
                    shell_pid,
                    ShellHookFamily::Fish,
                    &session_id,
                )
                .expect("validate subprocess shell capability");
            }
            Ok("coordinate") => {
                let output = std::process::Command::new(
                    std::env::current_exe().expect("test executable path"),
                )
                .args([
                    "--ignored",
                    "--exact",
                    CAPABILITY_PROCESS_HELPER,
                    "--nocapture",
                ])
                .env("TIRITH_CAPABILITY_PROCESS_HELPER", "register")
                .output()
                .expect("run nested registration child");
                assert!(
                    output.status.success(),
                    "nested child failed: stdout={} stderr={}",
                    String::from_utf8_lossy(&output.stdout),
                    String::from_utf8_lossy(&output.stderr)
                );
            }
            mode => panic!("unexpected subprocess-helper mode: {mode:?}"),
        }
    }

    #[test]
    fn capability_validation_rejects_reused_process_or_changed_executable_identity() {
        isolated_state(|_, session_id| {
            let secret =
                std::env::var("_TIRITH_RECEIPT_INSTANCE").expect("registered test capability");
            let shell_pid = std::env::var("_TIRITH_RECEIPT_SHELL_PID")
                .expect("registered test shell PID")
                .parse::<u32>()
                .expect("numeric test shell PID");
            let (mut capability, _) =
                read_capability(&active_capability_path()).expect("read test capability");
            capability.shell_start_fingerprint.push_str(":reused");
            replace_capability(&mut capability, &secret);
            let error =
                validate_shell_hook_instance(&secret, shell_pid, ShellHookFamily::Zsh, session_id)
                    .expect_err("a reused shell identity must fail closed");
            assert!(
                error.contains("process identity"),
                "unexpected process identity error: {error}"
            );
        });

        isolated_state(|_, session_id| {
            let secret =
                std::env::var("_TIRITH_RECEIPT_INSTANCE").expect("registered test capability");
            let shell_pid = std::env::var("_TIRITH_RECEIPT_SHELL_PID")
                .expect("registered test shell PID")
                .parse::<u32>()
                .expect("numeric test shell PID");
            let (mut capability, _) =
                read_capability(&active_capability_path()).expect("read test capability");
            capability.tirith_executable.inode ^= 1;
            replace_capability(&mut capability, &secret);
            let error =
                validate_shell_hook_instance(&secret, shell_pid, ShellHookFamily::Zsh, session_id)
                    .expect_err("an executable identity change must fail closed");
            assert!(
                error.contains("different Tirith executable"),
                "unexpected executable identity error: {error}"
            );
        });
    }

    #[test]
    fn capability_anchor_and_record_fail_closed_on_link_mode_and_size_attacks() {
        isolated_state(|temporary, session_id| {
            let secret =
                std::env::var("_TIRITH_RECEIPT_INSTANCE").expect("registered test capability");
            let shell_pid = std::env::var("_TIRITH_RECEIPT_SHELL_PID")
                .expect("registered test shell PID")
                .parse::<u32>()
                .expect("numeric test shell PID");
            let (_, anchor_path) = active_capability_paths();
            let linked_target = temporary.path().join("linked-capability-anchor");
            fs::write(&linked_target, b"{}").expect("write anchor symlink target");
            fs::set_permissions(&linked_target, fs::Permissions::from_mode(0o600))
                .expect("secure anchor symlink target");
            fs::remove_file(&anchor_path).expect("remove capability anchor");
            symlink(&linked_target, &anchor_path).expect("replace capability anchor with symlink");
            assert!(
                validate_shell_hook_instance(&secret, shell_pid, ShellHookFamily::Zsh, session_id,)
                    .is_err(),
                "a symlinked capability anchor must fail closed"
            );
        });

        isolated_state(|_, session_id| {
            let secret =
                std::env::var("_TIRITH_RECEIPT_INSTANCE").expect("registered test capability");
            let shell_pid = std::env::var("_TIRITH_RECEIPT_SHELL_PID")
                .expect("registered test shell PID")
                .parse::<u32>()
                .expect("numeric test shell PID");
            let (_, anchor_path) = active_capability_paths();
            fs::set_permissions(&anchor_path, fs::Permissions::from_mode(0o644))
                .expect("make capability anchor insecure");
            assert!(
                validate_shell_hook_instance(&secret, shell_pid, ShellHookFamily::Zsh, session_id,)
                    .is_err(),
                "an insecure capability anchor mode must fail closed"
            );
        });

        isolated_state(|_, session_id| {
            let secret =
                std::env::var("_TIRITH_RECEIPT_INSTANCE").expect("registered test capability");
            let shell_pid = std::env::var("_TIRITH_RECEIPT_SHELL_PID")
                .expect("registered test shell PID")
                .parse::<u32>()
                .expect("numeric test shell PID");
            let (_, anchor_path) = active_capability_paths();
            fs::write(
                &anchor_path,
                vec![b'x'; HOOK_CAPABILITY_ANCHOR_FILE_CAP as usize + 1],
            )
            .expect("oversize capability anchor");
            fs::set_permissions(&anchor_path, fs::Permissions::from_mode(0o600))
                .expect("restore private anchor mode");
            assert!(
                validate_shell_hook_instance(&secret, shell_pid, ShellHookFamily::Zsh, session_id,)
                    .is_err(),
                "an oversized capability anchor must fail closed"
            );
        });

        isolated_state(|temporary, session_id| {
            let secret =
                std::env::var("_TIRITH_RECEIPT_INSTANCE").expect("registered test capability");
            let shell_pid = std::env::var("_TIRITH_RECEIPT_SHELL_PID")
                .expect("registered test shell PID")
                .parse::<u32>()
                .expect("numeric test shell PID");
            let capability_path = active_capability_path();
            let linked_target = temporary.path().join("linked-capability-record");
            fs::write(&linked_target, b"{}").expect("write capability symlink target");
            fs::set_permissions(&linked_target, fs::Permissions::from_mode(0o600))
                .expect("secure capability symlink target");
            fs::remove_file(&capability_path).expect("remove capability record");
            symlink(&linked_target, &capability_path)
                .expect("replace capability record with symlink");
            assert!(
                validate_shell_hook_instance(&secret, shell_pid, ShellHookFamily::Zsh, session_id,)
                    .is_err(),
                "a symlinked capability record must fail closed"
            );
        });

        isolated_state(|_, session_id| {
            let secret =
                std::env::var("_TIRITH_RECEIPT_INSTANCE").expect("registered test capability");
            let shell_pid = std::env::var("_TIRITH_RECEIPT_SHELL_PID")
                .expect("registered test shell PID")
                .parse::<u32>()
                .expect("numeric test shell PID");
            let capability_path = active_capability_path();
            fs::set_permissions(&capability_path, fs::Permissions::from_mode(0o644))
                .expect("make capability record insecure");
            assert!(
                validate_shell_hook_instance(&secret, shell_pid, ShellHookFamily::Zsh, session_id,)
                    .is_err(),
                "an insecure capability record mode must fail closed"
            );
        });

        isolated_state(|_, session_id| {
            let secret =
                std::env::var("_TIRITH_RECEIPT_INSTANCE").expect("registered test capability");
            let shell_pid = std::env::var("_TIRITH_RECEIPT_SHELL_PID")
                .expect("registered test shell PID")
                .parse::<u32>()
                .expect("numeric test shell PID");
            let capability_path = active_capability_path();
            fs::write(
                &capability_path,
                vec![b'x'; HOOK_CAPABILITY_FILE_CAP as usize + 1],
            )
            .expect("oversize capability record");
            fs::set_permissions(&capability_path, fs::Permissions::from_mode(0o600))
                .expect("restore private capability mode");
            assert!(
                validate_shell_hook_instance(&secret, shell_pid, ShellHookFamily::Zsh, session_id,)
                    .is_err(),
                "an oversized capability record must fail closed"
            );
        });
    }

    #[test]
    fn registration_rejects_a_non_parent_process() {
        isolated_state(|_, session_id| {
            let mut child = std::process::Command::new("/bin/sleep")
                .arg("60")
                .spawn()
                .expect("spawn non-parent identity fixture");
            let error = register_shell_hook_instance(child.id(), ShellHookFamily::Bash, session_id)
                .expect_err("a non-parent process must not be registered as the shell");
            assert!(
                error.contains("actual parent"),
                "unexpected non-parent error: {error}"
            );
            child.kill().expect("terminate child identity fixture");
            child.wait().expect("reap child identity fixture");
        });
    }

    #[test]
    fn powershell_is_not_a_strict_receipt_boundary() {
        isolated_state(|_, session_id| {
            let command = "Write-Output receipt-boundary";
            let policy = Policy::default();
            let verdict = allow_verdict();
            let prepared = prepare_execution(
                &verdict,
                &policy,
                command,
                session_id,
                CallerContext::Cli,
                ShellType::PowerShell,
                Duration::from_secs(2 * 60),
                Duration::from_secs(1),
            )
            .expect("prepare PowerShell decision");
            let error = create_shell_execution_receipt(
                &prepared,
                ShellReceiptChannel::PowerShell,
                true,
                false,
                Duration::from_secs(60),
            )
            .expect_err("PowerShell must not create strict execution receipts");
            assert!(
                error.contains("strict PowerShell execution receipts are unsupported"),
                "unexpected PowerShell boundary error: {error}"
            );
            assert!(ShellReceiptChannel::PowerShell.hook_family().is_err());
        });
    }

    #[test]
    fn invalid_bearer_token_creates_no_lock_file() {
        isolated_state(|_, _| {
            let directory = receipt_directory().expect("receipt directory");
            let durable_names = || {
                fs::read_dir(&directory)
                    .expect("read receipt directory")
                    .filter_map(Result::ok)
                    .map(|entry| entry.file_name())
                    .collect::<std::collections::BTreeSet<_>>()
            };
            assert_eq!(
                fs::read_dir(&directory)
                    .expect("empty receipt directory")
                    .filter_map(Result::ok)
                    .filter(|entry| entry
                        .file_name()
                        .to_str()
                        .is_some_and(|name| name.ends_with(".json")))
                    .count(),
                0
            );
            // Shell registration intentionally creates persistent global
            // registry/capability lock inodes before this test reaches the
            // invalid receipt bearer. Snapshot that authorized baseline: the
            // invariant is that the invalid token creates NOTHING new, not that
            // the shared receipt directory contains no protocol locks at all.
            let before = durable_names();
            let error = shell_execution_receipt_context(
                "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
                ShellReceiptChannel::Zsh,
            )
            .expect_err("uppercase bearer must be rejected");
            assert!(error.contains("lowercase hex"), "unexpected error: {error}");
            assert_eq!(
                durable_names(),
                before,
                "invalid bearer changed the durable receipt directory"
            );
        });
    }

    #[test]
    fn receipt_is_bound_to_channel_hook_instance_and_exact_command() {
        isolated_state_with_guard(|_, session_id, environment| {
            let command = "printf receipt-boundary";
            let policy = Policy::default();
            let verdict = allow_verdict();
            let token = create(&verdict, &policy, command, session_id, false);
            let hook_instance = std::env::var_os("_TIRITH_RECEIPT_INSTANCE")
                .expect("active hook instance was installed");

            assert!(
                shell_execution_receipt_context(&token, ShellReceiptChannel::BashPreexec,).is_err()
            );
            environment.set_env("_TIRITH_RECEIPT_INSTANCE", OTHER_HOOK_INSTANCE);
            assert!(shell_execution_receipt_context(&token, ShellReceiptChannel::Zsh).is_err());
            environment.set_env("_TIRITH_RECEIPT_INSTANCE", hook_instance);

            arm_allow(&token);
            let changed_command = "printf receipt-boundary-changed";
            let fresh = prepare(&verdict, &policy, changed_command, session_id);
            let error = consume_shell_execution_receipt(
                &token,
                ShellReceiptChannel::Zsh,
                changed_command,
                fresh,
                Duration::from_secs(1),
            )
            .expect_err("changed command must not consume receipt");
            assert!(
                error.contains("command changed"),
                "unexpected error: {error}"
            );
        });
    }

    #[test]
    fn token_keyed_binding_rejects_same_projection_different_secret() {
        isolated_state(|_, session_id| {
            let first_secret = format!("0x{}", "11".repeat(32));
            let second_secret = format!("0x{}", "22".repeat(32));
            let original = format!("PRIVATE_KEY={first_secret} cast block-number");
            let changed = format!("PRIVATE_KEY={second_secret} cast block-number");
            assert_eq!(
                crate::execution_state::privacy_projected_command_sha256(&original),
                crate::execution_state::privacy_projected_command_sha256(&changed),
                "fixture must differ only inside the privacy projection"
            );
            let policy = Policy::default();
            let verdict = allow_verdict();
            let token = create(&verdict, &policy, &original, session_id, false);
            arm_allow(&token);
            let fresh = prepare(&verdict, &policy, &changed, session_id);
            let error = consume_shell_execution_receipt(
                &token,
                ShellReceiptChannel::Zsh,
                &changed,
                fresh,
                Duration::from_secs(1),
            )
            .expect_err("a different raw secret must not consume the receipt");
            assert!(error.contains("command changed"), "{error}");
            let durable = fs::read_to_string(receipt_path(&token)).expect("durable receipt");
            assert!(!durable.contains(&first_secret), "{durable}");
            assert!(
                !durable.contains(&sha256_hex(original.as_bytes())),
                "{durable}"
            );
        });
    }

    #[test]
    fn legacy_v1_armed_receipt_is_deleted_without_promotion() {
        isolated_state(|_, session_id| {
            let secret = format!("0x{}", "11".repeat(32));
            let command = format!("PRIVATE_KEY={secret} cast block-number");
            let raw_digest = sha256_hex(command.as_bytes());
            let policy = Policy::default();
            let verdict = allow_verdict();
            let token = create(&verdict, &policy, &command, session_id, false);
            arm_allow(&token);
            rewrite_as_legacy_v1(&token, &raw_digest);
            let durable = fs::read_to_string(receipt_path(&token)).expect("legacy armed receipt");
            assert!(
                durable.contains(&raw_digest),
                "legacy fixture lacks raw digest"
            );
            let generation = strict_generation(session_id);
            let fresh = prepare(&verdict, &policy, &command, session_id);
            let error = consume_shell_execution_receipt(
                &token,
                ShellReceiptChannel::Zsh,
                &command,
                fresh,
                Duration::from_secs(1),
            )
            .expect_err("legacy armed receipt must retire, not execute");
            assert!(
                error.contains("rerun the command through fresh analysis"),
                "{error}"
            );
            assert!(
                !receipt_path(&token).exists(),
                "legacy receipt JSON survived"
            );
            assert!(
                !receipt_lock_path(&token).exists(),
                "legacy receipt lock survived"
            );
            assert_eq!(
                strict_generation(session_id),
                generation,
                "legacy receipt promoted"
            );
        });
    }

    #[test]
    fn legacy_v1_consuming_receipt_is_deleted_as_indeterminate_without_promotion() {
        isolated_state(|_, session_id| {
            let secret = format!("0x{}", "22".repeat(32));
            let command = format!("PRIVATE_KEY={secret} cast block-number");
            let raw_digest = sha256_hex(command.as_bytes());
            let policy = Policy::default();
            let verdict = allow_verdict();
            let token = create(&verdict, &policy, &command, session_id, false);
            arm_allow(&token);
            let mut prepared = prepare(&verdict, &policy, &command, session_id);
            force_consuming(&token, &mut prepared);
            rewrite_as_legacy_v1(&token, &raw_digest);
            let durable =
                fs::read_to_string(receipt_path(&token)).expect("legacy consuming receipt");
            assert!(
                durable.contains(&raw_digest),
                "legacy fixture lacks raw digest"
            );
            let generation = strict_generation(session_id);
            let error = reconcile_shell_execution_receipt(
                &token,
                ShellReceiptChannel::Zsh,
                Duration::from_secs(1),
            )
            .expect_err("legacy consuming outcome must be terminally indeterminate");
            assert!(
                error.contains("indeterminate consumption outcome"),
                "{error}"
            );
            assert!(error.contains("never replay"), "{error}");
            assert!(
                !receipt_path(&token).exists(),
                "legacy receipt JSON survived"
            );
            assert!(
                !receipt_lock_path(&token).exists(),
                "legacy receipt lock survived"
            );
            assert_eq!(
                strict_generation(session_id),
                generation,
                "legacy receipt promoted"
            );
        });
    }

    #[test]
    fn authenticated_schema_v2_raw_cwd_receipt_is_retired() {
        isolated_state(|_, session_id| {
            let policy = Policy::default();
            let verdict = allow_verdict();
            let token = create(&verdict, &policy, "printf legacy-v2", session_id, false);
            arm_allow(&token);
            let raw_cwd_digest = legacy_raw_cwd_sha256();
            rewrite_as_legacy_v2(&token);
            let durable = fs::read_to_string(receipt_path(&token)).expect("schema-v2 receipt");
            assert!(
                durable.contains(&raw_cwd_digest),
                "legacy fixture lacks cwd oracle"
            );

            let error = shell_execution_receipt_context(&token, ShellReceiptChannel::Zsh)
                .expect_err("authenticated schema-v2 receipt must retire");
            assert!(error.contains("retired for privacy"), "{error}");
            assert!(!receipt_path(&token).exists());
            assert!(!receipt_lock_path(&token).exists());
        });
    }

    #[test]
    fn downgraded_current_receipt_failing_legacy_seal_is_preserved() {
        isolated_state(|_, session_id| {
            let command = "printf downgrade-attack";
            let policy = Policy::default();
            let verdict = allow_verdict();
            let token = create(&verdict, &policy, command, session_id, false);
            let mut receipt: ShellReceipt = serde_json::from_slice(
                &fs::read(receipt_path(&token)).expect("read current receipt"),
            )
            .expect("parse current receipt");
            receipt.schema_version = LEGACY_RAW_COMMAND_RECEIPT_SCHEMA_VERSION;
            receipt.cwd_sha256 = Some(legacy_raw_cwd_sha256());
            receipt.cwd_binding_sha256 = None;
            receipt.command_sha256 = sha256_hex(command.as_bytes());
            receipt.command_binding_sha256 = None;
            // Deliberately do not refresh either token-keyed seal: changing a
            // mutable discriminator and making the JSON look historical must
            // never authorize deletion.
            replace_receipt_bytes(
                &token,
                &serde_json::to_vec(&receipt).expect("serialize downgraded receipt"),
            );

            let error = shell_execution_receipt_context(&token, ShellReceiptChannel::Zsh)
                .expect_err("downgraded current receipt must fail authentication");
            assert!(error.contains("failed authentication"), "{error}");
            assert!(
                receipt_path(&token).exists(),
                "tampered receipt was deleted"
            );
            assert!(
                receipt_lock_path(&token).exists(),
                "tampered receipt lock was deleted"
            );
        });
    }

    #[test]
    fn current_receipts_use_token_keyed_non_oracle_cwd_bindings() {
        isolated_state(|_, session_id| {
            let policy = Policy::default();
            let verdict = allow_verdict();
            let first = create(&verdict, &policy, "printf cwd-one", session_id, false);
            let second = create(&verdict, &policy, "printf cwd-two", session_id, false);
            let read = |token: &str| -> ShellReceipt {
                serde_json::from_slice(&fs::read(receipt_path(token)).expect("read receipt"))
                    .expect("parse receipt")
            };
            let first_receipt = read(&first);
            let second_receipt = read(&second);
            assert!(first_receipt.cwd_sha256.is_none());
            assert!(second_receipt.cwd_sha256.is_none());
            assert_ne!(
                first_receipt.cwd_binding_sha256, second_receipt.cwd_binding_sha256,
                "the same cwd must not have a stable durable verifier"
            );
            let raw_cwd_digest = legacy_raw_cwd_sha256();
            for token in [&first, &second] {
                let durable = fs::read_to_string(receipt_path(token)).expect("durable receipt");
                assert!(!durable.contains(&raw_cwd_digest), "{durable}");
                assert!(!durable.contains("\"cwd_sha256\""), "{durable}");
                assert!(durable.contains("\"cwd_binding_sha256\""), "{durable}");
            }
        });
    }

    #[test]
    fn schema_v3_receipt_without_exact_binding_fails_closed_without_retirement() {
        isolated_state(|_, session_id| {
            let command = "printf missing-binding";
            let policy = Policy::default();
            let verdict = allow_verdict();
            let token = create(&verdict, &policy, command, session_id, false);
            let mut receipt: ShellReceipt = serde_json::from_slice(
                &fs::read(receipt_path(&token)).expect("read current receipt"),
            )
            .expect("parse current receipt");
            receipt.command_binding_sha256 = None;
            replace_receipt_bytes(
                &token,
                &serde_json::to_vec(&receipt).expect("serialize missing-binding receipt"),
            );
            let error = shell_execution_receipt_context(&token, ShellReceiptChannel::Zsh)
                .expect_err("schema-v3 receipt without binding must fail closed");
            assert!(error.contains("lacks its exact command binding"), "{error}");
            assert!(
                receipt_path(&token).exists(),
                "current corrupt receipt was downgraded"
            );
            assert!(
                receipt_lock_path(&token).exists(),
                "current corrupt lock was deleted"
            );
        });
    }

    #[test]
    fn approval_and_strict_warning_acknowledgement_are_independent_requirements() {
        isolated_state(|_, session_id| {
            let command = "printf approval-and-warning";
            let policy = Policy {
                strict_warn: true,
                ..Policy::default()
            };
            let verdict = warning_verdict(true, Some("block"));
            let token = create(&verdict, &policy, command, session_id, true);

            let error = arm_shell_execution_receipt(
                &token,
                ShellReceiptChannel::Zsh,
                Some(ShellApprovalOutcome::Granted),
                false,
            )
            .expect_err("approval must not satisfy warning acknowledgement");
            assert!(error.contains("warning acknowledgement"));

            arm_shell_execution_receipt(
                &token,
                ShellReceiptChannel::Zsh,
                Some(ShellApprovalOutcome::Granted),
                true,
            )
            .expect("arm with both independent proofs");
            let fresh = prepare(&verdict, &policy, command, session_id);
            assert!(consume_shell_execution_receipt(
                &token,
                ShellReceiptChannel::Zsh,
                command,
                fresh,
                Duration::from_secs(1),
            )
            .is_ok());
        });
    }

    #[test]
    fn strict_override_cannot_create_warn_receipt_without_frozen_ack_requirement() {
        isolated_state(|_, session_id| {
            let command = "printf strict-override";
            let policy = Policy::default();
            let verdict = warning_verdict(false, None);
            let prepared = prepare(&verdict, &policy, command, session_id);
            let error = create_shell_execution_receipt(
                &prepared,
                ShellReceiptChannel::Zsh,
                true,
                true,
                Duration::from_secs(60),
            )
            .expect_err("strict override must require a frozen warning acknowledgement");
            assert!(error.contains("acknowledgement requirement"));
        });
    }

    #[test]
    fn block_receipt_is_never_armable_by_approval_or_allow_fallback() {
        isolated_state(|_, session_id| {
            let command = "printf blocked";
            let policy = Policy::default();
            let verdict = block_verdict_with_allow_fallback();
            let prepared = prepare(&verdict, &policy, command, session_id);
            assert_eq!(prepared.draft.decision.action, Action::Block);
            assert!(
                !prepared.draft.decision.requires_approval,
                "final approval normalization must make Block terminal"
            );
            assert!(prepared.draft.effective_verdict.approval_fallback.is_none());
            let token = create_shell_execution_receipt(
                &prepared,
                ShellReceiptChannel::Zsh,
                true,
                false,
                Duration::from_secs(60),
            )
            .expect("create normalized block receipt");

            for outcome in [
                ShellApprovalOutcome::Granted,
                ShellApprovalOutcome::TimedOut,
            ] {
                let error = arm_shell_execution_receipt(
                    &token,
                    ShellReceiptChannel::Zsh,
                    Some(outcome),
                    false,
                )
                .expect_err("unbypassed block must remain terminal");
                assert!(error.contains("blocked shell decision"));
            }
        });
    }

    #[test]
    fn fresh_analysis_allows_only_timing_drift() {
        isolated_state(|_, session_id| {
            let command = "printf timing-drift";
            let policy = Policy::default();
            let original = allow_verdict();
            let token = create(&original, &policy, command, session_id, false);
            arm_allow(&token);

            let mut timing_only = original.clone();
            timing_only.timings_ms = Timings {
                tier0_ms: 1.25,
                tier1_ms: 2.5,
                tier2_ms: Some(3.75),
                tier3_ms: Some(4.0),
                total_ms: 11.5,
            };
            let fresh = prepare(&timing_only, &policy, command, session_id);
            assert!(consume_shell_execution_receipt(
                &token,
                ShellReceiptChannel::Zsh,
                command,
                fresh,
                Duration::from_secs(1),
            )
            .is_ok());

            let changed_token = create(&original, &policy, command, session_id, false);
            arm_allow(&changed_token);
            let mut semantic_change = original;
            semantic_change.tier_reached = 2;
            let fresh = prepare(&semantic_change, &policy, command, session_id);
            let error = consume_shell_execution_receipt(
                &changed_token,
                ShellReceiptChannel::Zsh,
                command,
                fresh,
                Duration::from_secs(1),
            )
            .expect_err("security-relevant verdict drift must fail closed");
            assert!(
                error.contains("decision changed"),
                "unexpected error: {error}"
            );
        });
    }

    #[test]
    fn receipt_files_fail_closed_on_seal_json_shape_mode_link_and_size_attacks() {
        isolated_state(|_, session_id| {
            let command = "printf tamper-fixture";
            let policy = Policy::default();
            let verdict = allow_verdict();

            let immutable_tamper = create(&verdict, &policy, command, session_id, false);
            let mut value: serde_json::Value = serde_json::from_slice(
                &fs::read(receipt_path(&immutable_tamper)).expect("read tamper receipt"),
            )
            .expect("parse tamper receipt");
            value["command_redacted_preview"] = serde_json::Value::String("changed".to_string());
            replace_receipt_bytes(
                &immutable_tamper,
                &serde_json::to_vec(&value).expect("serialize tampered receipt"),
            );
            assert!(
                shell_execution_receipt_context(&immutable_tamper, ShellReceiptChannel::Zsh,)
                    .is_err()
            );

            let state_tamper = create(&verdict, &policy, command, session_id, false);
            let mut value: serde_json::Value = serde_json::from_slice(
                &fs::read(receipt_path(&state_tamper)).expect("read state receipt"),
            )
            .expect("parse state receipt");
            value["state"] = serde_json::json!({
                "status": "discarded",
                "finished_unix_ms": 1,
            });
            replace_receipt_bytes(
                &state_tamper,
                &serde_json::to_vec(&value).expect("serialize state-tampered receipt"),
            );
            assert!(
                shell_execution_receipt_context(&state_tamper, ShellReceiptChannel::Zsh).is_err()
            );

            let duplicate = create(&verdict, &policy, command, session_id, false);
            let json =
                fs::read_to_string(receipt_path(&duplicate)).expect("read duplicate receipt");
            replace_receipt_bytes(
                &duplicate,
                format!("{{\"schema_version\":1,{}", &json[1..]).as_bytes(),
            );
            assert!(shell_execution_receipt_context(&duplicate, ShellReceiptChannel::Zsh).is_err());

            let unknown = create(&verdict, &policy, command, session_id, false);
            let json = fs::read_to_string(receipt_path(&unknown)).expect("read unknown receipt");
            replace_receipt_bytes(
                &unknown,
                format!("{{\"unexpected_member\":true,{}", &json[1..]).as_bytes(),
            );
            assert!(shell_execution_receipt_context(&unknown, ShellReceiptChannel::Zsh).is_err());

            let insecure_mode = create(&verdict, &policy, command, session_id, false);
            fs::set_permissions(
                receipt_path(&insecure_mode),
                fs::Permissions::from_mode(0o644),
            )
            .expect("make receipt mode insecure");
            assert!(
                shell_execution_receipt_context(&insecure_mode, ShellReceiptChannel::Zsh).is_err()
            );

            let linked = create(&verdict, &policy, command, session_id, false);
            let linked_path = receipt_path(&linked);
            let linked_target = linked_path.with_extension("target");
            fs::write(&linked_target, b"{}").expect("write symlink target");
            fs::set_permissions(&linked_target, fs::Permissions::from_mode(0o600))
                .expect("secure symlink target");
            fs::remove_file(&linked_path).expect("remove receipt before symlink replacement");
            symlink(&linked_target, &linked_path).expect("replace receipt with symlink");
            assert!(shell_execution_receipt_context(&linked, ShellReceiptChannel::Zsh).is_err());

            let oversized = create(&verdict, &policy, command, session_id, false);
            replace_receipt_bytes(&oversized, &vec![b'x'; RECEIPT_FILE_CAP as usize + 1]);
            assert!(shell_execution_receipt_context(&oversized, ShellReceiptChannel::Zsh).is_err());
        });
    }

    #[test]
    fn consuming_crash_reconciles_durable_commit_without_authorizing_replay() {
        isolated_state(|_, session_id| {
            let command = "printf durable-consuming-crash";
            let policy = Policy::default();
            let verdict = allow_verdict();
            let token = create(&verdict, &policy, command, session_id, false);
            arm_allow(&token);
            let mut prepared = prepare(&verdict, &policy, command, session_id);
            let evidence_id = force_consuming(&token, &mut prepared);

            let gate = ExecutionGate::acquire(
                prepared
                    .into_authorizable_draft()
                    .expect("authorizable crash draft"),
                Duration::from_secs(1),
            )
            .expect("acquire crash-simulation gate");
            assert!(matches!(
                gate.promote_shell_unresolved(evidence_id)
                    .expect("durably promote before simulated crash"),
                PromotionOutcome::Committed { .. }
            ));

            assert!(reconcile_shell_execution_receipt(
                &token,
                ShellReceiptChannel::Zsh,
                Duration::from_secs(1),
            )
            .expect("reconcile committed receipt"));
            assert!(reconcile_shell_execution_receipt(
                &token,
                ShellReceiptChannel::Zsh,
                Duration::from_secs(1),
            )
            .expect("idempotently reconcile terminal receipt"));
            assert!(shell_execution_receipt_context(&token, ShellReceiptChannel::Zsh).is_err());
        });
    }

    #[test]
    fn missing_consuming_transition_retries_only_inside_bounded_window() {
        isolated_state(|_, session_id| {
            let command = "printf missing-consuming-transition";
            let policy = Policy::default();
            let verdict = allow_verdict();
            let token = create(&verdict, &policy, command, session_id, false);
            arm_allow(&token);
            let mut prepared = prepare(&verdict, &policy, command, session_id);
            force_consuming(&token, &mut prepared);

            assert!(!reconcile_shell_execution_receipt(
                &token,
                ShellReceiptChannel::Zsh,
                Duration::from_secs(1),
            )
            .expect("missing transition is recoverably absent"));

            let mut locked = lock_receipt(&token).expect("lock consuming receipt for aging");
            match &mut locked.receipt.state {
                ReceiptState::Consuming {
                    consuming_unix_ms, ..
                } => {
                    let retry_window_ms =
                        u64::try_from(CONSUMING_RETRY_WINDOW.as_millis()).unwrap_or(u64::MAX);
                    *consuming_unix_ms = unix_time_ms()
                        .expect("current time")
                        .saturating_sub(retry_window_ms.saturating_add(1));
                }
                state => panic!("expected consuming receipt, got {state:?}"),
            }
            locked.publish().expect("publish aged consuming receipt");
            drop(locked);

            let fresh = prepare(&verdict, &policy, command, session_id);
            let error = consume_shell_execution_receipt(
                &token,
                ShellReceiptChannel::Zsh,
                command,
                fresh,
                Duration::from_secs(1),
            )
            .expect_err("stale missing transition must not reauthorize execution");
            assert!(
                error.contains("too old to retry safely"),
                "unexpected error: {error}"
            );
            let error = shell_execution_receipt_context(&token, ShellReceiptChannel::Zsh)
                .expect_err("stale consuming receipt must become terminal");
            assert!(error.contains("discarded"), "unexpected error: {error}");
        });
    }

    #[test]
    fn in_window_retry_does_not_refresh_consuming_deadline() {
        isolated_state(|_, session_id| {
            let command = "printf bounded-consuming-retry";
            let policy = Policy::default();
            let verdict = allow_verdict();
            let token = create(&verdict, &policy, command, session_id, false);
            arm_allow(&token);
            let mut prepared = prepare(&verdict, &policy, command, session_id);
            force_consuming(&token, &mut prepared);
            let original_started = match lock_receipt(&token)
                .expect("read original consuming receipt")
                .receipt
                .state
            {
                ReceiptState::Consuming {
                    consuming_unix_ms, ..
                } => consuming_unix_ms,
                state => panic!("expected consuming receipt, got {state:?}"),
            };

            let state_lock_path = crate::session_warnings::session_lock_path(session_id)
                .expect("strict session lock path");
            let state_lock = OpenOptions::new()
                .read(true)
                .write(true)
                .open(&state_lock_path)
                .expect("open strict session lock");
            // Preparation now snapshots strict state under this same stable
            // lock. Prepare first, then hold the lock only across the consume
            // retry whose deadline this test exercises.
            let fresh = prepare(&verdict, &policy, command, session_id);
            fs2::FileExt::lock_exclusive(&state_lock).expect("hold strict session lock");
            let error = consume_shell_execution_receipt(
                &token,
                ShellReceiptChannel::Zsh,
                command,
                fresh,
                Duration::from_millis(20),
            )
            .expect_err("held session lock must interrupt retry promotion");
            assert!(error.contains("timed out"), "unexpected error: {error}");
            fs2::FileExt::unlock(&state_lock).expect("release strict session lock");

            let retry_started = match lock_receipt(&token)
                .expect("read retried consuming receipt")
                .receipt
                .state
            {
                ReceiptState::Consuming {
                    consuming_unix_ms, ..
                } => consuming_unix_ms,
                state => panic!("expected consuming receipt, got {state:?}"),
            };
            assert_eq!(
                retry_started, original_started,
                "a failed retry extended its one-shot recovery window"
            );
        });
    }

    #[test]
    fn durable_replay_conflict_cannot_reconcile_as_success() {
        isolated_state(|_, session_id| {
            let command = "printf durable-replay-conflict";
            let policy = Policy::default();
            let verdict = allow_verdict();
            let token = create(&verdict, &policy, command, session_id, false);
            arm_allow(&token);
            let (execution_id, evidence_id) = {
                let locked = lock_receipt(&token).expect("read armed conflict receipt");
                (
                    locked.receipt.execution_id.clone(),
                    evidence_id(&locked.receipt),
                )
            };

            // Simulate a transition that became durable while the receipt's
            // journal acknowledgement was lost before it entered Consuming.
            let mut prior = prepare(&verdict, &policy, command, session_id);
            prior
                .draft
                .replace_execution_id(execution_id)
                .expect("bind prior transition to receipt");
            let gate = ExecutionGate::acquire(
                prior
                    .into_authorizable_draft()
                    .expect("authorizable prior transition"),
                Duration::from_secs(1),
            )
            .expect("acquire prior transition gate");
            assert!(matches!(
                gate.promote_shell_unresolved(evidence_id)
                    .expect("publish prior transition"),
                PromotionOutcome::Committed { .. }
            ));

            let fresh = prepare(&verdict, &policy, command, session_id);
            let error = consume_shell_execution_receipt(
                &token,
                ShellReceiptChannel::Zsh,
                command,
                fresh,
                Duration::from_secs(1),
            )
            .expect_err("idempotent durable transition must refuse a newly armed replay");
            assert!(
                error.contains("refusing replay"),
                "unexpected error: {error}"
            );
            assert!(matches!(
                lock_receipt(&token)
                    .expect("read terminal conflict")
                    .receipt
                    .state,
                ReceiptState::Conflict { .. }
            ));
            let retry = prepare(&verdict, &policy, command, session_id);
            let retry_error = consume_shell_execution_receipt(
                &token,
                ShellReceiptChannel::Zsh,
                command,
                retry,
                Duration::from_secs(1),
            )
            .expect_err("terminal conflict must refuse every later retry");
            assert!(
                retry_error.contains("identity conflict"),
                "unexpected terminal retry error: {retry_error}"
            );
            let reconcile_error = reconcile_shell_execution_receipt(
                &token,
                ShellReceiptChannel::Zsh,
                Duration::from_secs(1),
            )
            .expect_err("terminal conflict must never become committed success");
            assert!(
                reconcile_error.contains("identity conflict"),
                "unexpected error: {reconcile_error}"
            );
        });
    }
}
