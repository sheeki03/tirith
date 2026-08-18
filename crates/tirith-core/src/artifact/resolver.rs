//! Hash-locked Python wheel resolver for the package firewall (PR D2).
//!
//! This is the controlled-network step of the package firewall. Given a set of
//! requirement specs, it produces a fully hash-pinned lock and downloads the
//! exact, binary-only wheels named by that lock into the D1 quarantine blob
//! store, verifying each download against the locked hash. It does **no**
//! inspection and **no** verdict: D3 ([`crate::artifact::inspect`] +
//! `firewall.rs`) inspects the quarantined blobs, and D4 installs only the
//! re-verified bytes. The resolver's sole job is to turn "what the user asked
//! for" into "these exact verified bytes, and nothing else."
//!
//! # The pipeline (plan reuse decision, Python is the only enforced ecosystem)
//!
//! ```text
//! uv pip compile --generate-hashes --no-build    -> a hash-pinned lock (locked.txt)
//! python -I -m pip download --only-binary=:all:                                    \
//!        --require-hashes -r locked.txt          -> wheels in a staging dir
//! ingest each wheel into the D1 quarantine        -> content-addressed blobs
//! ```
//!
//! `uv pip download` does not exist, so the two tools split the work: `uv`
//! resolves and emits the hash-pinned lock; `python -I -m pip download` fetches it
//! under `--require-hashes`, which makes pip refuse any artifact whose hash is
//! not in the lock. We then re-hash every downloaded file ourselves on the way
//! into the quarantine (D1's [`QuarantineStore::ingest_file`]), so the bytes that
//! reach inspection are provably the bytes the lock pinned, independent of pip.
//!
//! # Hardening (every item in the D2 plan entry)
//!
//! 1. **`python -m pip`, never a PATH `pip`.** A PATH `pip` is a shim an attacker
//!    can shadow; `python -m pip` runs the module of the interpreter we resolved.
//! 2. **No automatic Python downloads.** `uv` is told `--no-python-downloads`
//!    (reinforced by `UV_PYTHON_DOWNLOADS=never`) and `python -m pip` cannot fetch
//!    an interpreter anyway, so neither tool may silently pull a toolchain off the
//!    network.
//! 3. **sdist / VCS / editable / local-path / direct-URL refused** unless a
//!    future policy ([`ResolverAllowances`]) opts in. `uv pip compile --no-build`
//!    resolves binary-only and `python -m pip download --only-binary :all:`
//!    fetches wheels only (uv rejects the two flags together, so each lives on its
//!    own step); [`validate_requirement`] rejects the `-e` / `git+` / `file:` /
//!    direct-URL / local-path forms before we ever shell out, so a build backend
//!    never runs (cross-cutting invariant 4).
//! 4. **Isolated config; repo-local pip/uv config ignored.** The child runs with
//!    a scrubbed environment ([`isolated_env`]) that points every pip/uv config
//!    knob at an empty temp dir, sets `PIP_ISOLATED` / passes `--isolated`, and
//!    strips `PIP_*` / `UV_*` / index / token variables, so a `pip.conf`,
//!    `uv.toml`, `.netrc`, or `PIP_INDEX_URL` planted in the repo or environment
//!    cannot redirect the resolve.
//! 5. **Explicit approved resolver origins only.** The default index is dropped
//!    (`--no-index` unless indexes are supplied). Every uv/pip HTTPS connection
//!    is routed through an authenticated loopback broker that permits only the
//!    canonical host/port origins explicitly approved by the request. Custom
//!    artifact/CDN origins are broker-only (never extra indexes); the sole built-in
//!    compatibility alias is exact PyPI -> exact files.pythonhosted.org.
//! 6. **Credentials in an index URL refused.** [`validate_index_url`] rejects a
//!    `user:pass@host` index outright (no secret on a command line / in a lock).
//! 7. **Connect-time SSRF and redirect enforcement.** The broker resolves each
//!    CONNECT host once, rejects non-public/metadata addresses, connects to the
//!    approved IP directly, and pins TLS SNI. Redirect and artifact hosts create
//!    fresh CONNECT requests and therefore cannot escape the origin allow-set.
//! 8. **`uv` / `python` resolved by executable provenance, not blind PATH.**
//!    [`resolve_tool`] uses [`crate::trusted_child`] to canonicalize, reject
//!    project/temp and writable/foreign-owned paths, bind file identity, and
//!    require a root-managed, non-writable system hierarchy for the enforcing
//!    package path. On Linux, explicit enrollment may additionally authorize an
//!    exact static native `uv` image: it is digest-pinned and launched from a
//!    sealed descriptor. Python enrollment cannot authorize enforcement because
//!    its mutable runtime/pip dependency tree cannot be sealed with the image.
//!    Identity is revalidated before each spawn.
//!
//! npm / cargo resolution is intentionally absent here: the engine is wheel-only,
//! and the plan keeps `.tgz` / `.crate` / vendored-source behind hidden
//! experimental, resolve-and-inspect-metadata-only commands that **cannot
//! install** until hardened analyzers exist. This module enforces Python.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::time::Duration;

use crate::artifact::quarantine::{QuarantineError, QuarantineStore, QuarantineTransaction};
use crate::artifact::resolver_broker::{PermittedOrigins, ResolverBroker};
use crate::trusted_child::{
    ChildLimits, ChildOutcome, ChildSpec, TrustedExecutable, TrustedExecutableError,
};

/// Wall-clock ceiling for a single resolver child (`uv` compile or `pip`
/// download). A resolve that hangs past this is killed; the firewall never waits
/// unbounded on a network operation.
pub const RESOLVER_CHILD_TIMEOUT: Duration = Duration::from_secs(180);

/// Hard cap on requirement specs in one request, so a pathological input cannot
/// turn into an unbounded command line / lock.
const MAX_REQUIREMENTS: usize = 4096;

/// Hard cap on approved index URLs in one request.
const MAX_INDEX_URLS: usize = 64;

/// Per-stream diagnostic cap for resolver children. The trusted-child
/// supervisor kills the process tree if either stream exceeds this bound.
const RESOLVER_CHILD_OUTPUT_MAX: usize = 4 * 1024 * 1024;

/// Maximum terminal-safe diagnostic text retained from a failed resolver
/// child. Raw child streams stay in [`ChildOutput`] for in-process decisions;
/// only this bounded display projection may enter a [`ResolverError`].
const RESOLVER_DIAGNOSTIC_MAX_BYTES: usize = 4000;

/// What the resolver is permitted to accept beyond the secure default. Every
/// field defaults to the *refusing* stance, so [`ResolverAllowances::default`] is
/// the locked-down resolver the plan calls for. A future policy layer (D3 / D7)
/// populates these from operator config; nothing here reads policy itself, and a
/// repo-scoped policy must never be able to flip one on (the policy field that
/// drives these is neutralized in `sanitize_repo_scoped`, where it is introduced).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ResolverAllowances {
    /// Permit source distributions / building from source. Default `false`:
    /// `--only-binary=:all:` + `--no-build`, and an sdist-only requirement is
    /// refused. Building a backend off the network is exactly what containment
    /// exists to stop, so this stays off without an explicit operator opt-in.
    pub allow_sdist: bool,
    /// Permit `git+` / other VCS requirement forms. Default `false`.
    pub allow_vcs: bool,
    /// Permit `-e` / `--editable` requirement forms. Default `false`.
    pub allow_editable: bool,
    /// Permit a local-path requirement (`./pkg`, `/abs/pkg`, a bare existing
    /// path). Default `false`.
    pub allow_local_path: bool,
    /// Permit a direct-URL requirement (`name @ https://.../x.whl`). Default
    /// `false`. Even when permitted the URL still passes [`validate_index_url`].
    pub allow_direct_url: bool,
    /// Legacy compatibility field. Resolver execution now always requires the
    /// trusted-child canonical ownership/identity contract; an unsafe PATH hit
    /// cannot bypass that boundary. The field remains so serialized/operator
    /// policy compiled against the older API does not change shape.
    pub allow_untrusted_tool: bool,
}

/// Why a resolve could not complete. Every variant is fail-closed: the caller is
/// left with no installable artifact, never a partially trusted one.
#[derive(Debug)]
pub enum ResolverError {
    /// A requirement spec was rejected by [`validate_requirement`] (sdist / VCS /
    /// editable / local-path / direct-URL / embedded credential / malformed),
    /// and the governing allowance was not set.
    RejectedRequirement { spec: String, reason: String },
    /// An index URL was rejected (not HTTPS, embedded credentials, or a
    /// non-public / metadata destination per the SSRF policy).
    RejectedIndexUrl { url: String, reason: String },
    /// More requirement specs or index URLs than the bound allows.
    TooManyInputs(String),
    /// A required tool (`uv` or `python`) was not found on `PATH`.
    ToolNotFound(String),
    /// A tool was found but failed canonical ownership, path hierarchy, stable
    /// identity, or trusted installation-root provenance.
    ToolUntrusted { tool: String, reason: String },
    /// `uv pip compile` failed, did not produce a usable lock, or emitted a lock
    /// that was not fully hash-pinned.
    CompileFailed(String),
    /// The pinned lock contained no hashes (refusing to download without
    /// `--require-hashes` coverage) or an entry without a sha256 hash.
    LockNotHashPinned(String),
    /// `python -m pip download` failed or timed out.
    DownloadFailed(String),
    /// pip downloaded something other than a wheel (an sdist slipped through, or
    /// no artifact landed at all).
    UnexpectedDownload(String),
    /// A child process timed out and was killed.
    Timeout(String),
    /// Ingesting a downloaded wheel into the D1 quarantine failed (including a
    /// hash mismatch between the download and the lock).
    Quarantine(QuarantineError),
    /// An underlying filesystem / process error.
    Io(std::io::Error),
}

impl std::fmt::Display for ResolverError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ResolverError::RejectedRequirement { spec, reason } => {
                write!(f, "refusing requirement {spec:?}: {reason}")
            }
            ResolverError::RejectedIndexUrl { url, reason } => {
                write!(f, "refusing index url {url:?}: {reason}")
            }
            ResolverError::TooManyInputs(m) => write!(f, "too many resolver inputs: {m}"),
            ResolverError::ToolNotFound(t) => {
                write!(f, "required resolver tool not found on PATH: {t}")
            }
            ResolverError::ToolUntrusted { tool, reason } => {
                write!(f, "refusing to use resolver tool {tool:?}: {reason}")
            }
            ResolverError::CompileFailed(m) => write!(f, "uv pip compile failed: {m}"),
            ResolverError::LockNotHashPinned(m) => {
                write!(f, "resolved lock is not fully hash-pinned: {m}")
            }
            ResolverError::DownloadFailed(m) => write!(f, "pip download failed: {m}"),
            ResolverError::UnexpectedDownload(m) => write!(f, "unexpected download artifact: {m}"),
            ResolverError::Timeout(m) => write!(f, "resolver step timed out: {m}"),
            ResolverError::Quarantine(e) => write!(f, "quarantine ingest failed: {e}"),
            ResolverError::Io(e) => write!(f, "resolver I/O error: {e}"),
        }
    }
}

impl std::error::Error for ResolverError {}

impl From<std::io::Error> for ResolverError {
    fn from(e: std::io::Error) -> Self {
        ResolverError::Io(e)
    }
}

impl From<QuarantineError> for ResolverError {
    fn from(e: QuarantineError) -> Self {
        ResolverError::Quarantine(e)
    }
}

/// One wheel the resolver locked and landed in the quarantine, ready for D3 to
/// inspect and D4 to install. Every field is post-verification: the `sha256` is
/// the digest the lock pinned AND the digest the bytes hashed to on ingest.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedArtifact {
    /// The validated wheel filename pip produced (a single `*.whl` component).
    pub wheel_filename: String,
    /// The lowercase-hex SHA-256 of the wheel content, which is also the
    /// quarantine blob digest (the two are identical by construction).
    pub sha256: String,
}

/// The outcome of a successful resolve: the hash-pinned lock and the set of
/// quarantined wheels it produced. D3 consumes `artifacts` (by blob digest); the
/// `locked_requirements` text is recorded in the D6 receipt (redacted there).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedSet {
    /// The exact `uv pip compile --generate-hashes` output used for the download.
    pub locked_requirements: String,
    /// The wheels landed in the quarantine, one per resolved distribution.
    pub artifacts: Vec<ResolvedArtifact>,
}

/// A resolve request. Construct it from operator input; the resolver validates
/// every field before shelling out.
#[derive(Debug, Clone)]
pub struct ResolverRequest {
    /// Requirement specs (`requests==2.31.0`, `flask>=3,<4`, ...). Each is
    /// validated by [`validate_requirement`]; the dangerous forms are refused.
    pub requirements: Vec<String>,
    /// Approved index URLs. Empty means `--no-index` (offline / lock-only).
    /// Every URL passes [`validate_index_url`].
    pub index_urls: Vec<String>,
    /// What to permit beyond the secure default. Defaults to refusing everything
    /// dangerous.
    pub allowances: ResolverAllowances,
}

impl ResolverRequest {
    /// A request for a single requirement spec with no extra index and the
    /// locked-down default allowances. Convenience for callers and tests.
    pub fn single(requirement: impl Into<String>) -> Self {
        ResolverRequest {
            requirements: vec![requirement.into()],
            index_urls: Vec::new(),
            allowances: ResolverAllowances::default(),
        }
    }
}

/// How `uv` and `python` were located, so the resolve uses provenance-checked
/// absolute paths rather than re-resolving a bare name in the child's `PATH`.
#[derive(Debug, Clone)]
pub struct ResolverTools {
    /// Canonical, ownership-validated `uv` used for `uv pip compile`.
    pub uv: PathBuf,
    /// Canonical, ownership-validated interpreter used for `python -m pip`.
    pub python: PathBuf,
}

impl ResolverTools {
    /// Resolve `uv` and `python` (in that order) from `PATH`, applying executable
    /// provenance. Unsafe PATH hits cannot bypass this with the legacy allowance.
    /// The interpreter name tried is `python3` then `python`.
    pub fn discover(allowances: &ResolverAllowances) -> Result<Self, ResolverError> {
        let uv = resolve_tool("uv", &["uv"], allowances)?;
        let python = resolve_tool("python", &["python3", "python"], allowances)?;
        Ok(ResolverTools { uv, python })
    }
}

/// Resolve a tool by trying each candidate name on `PATH`, returning a canonical
/// trusted-child handle. The first executable hit is fail-closed: a project,
/// temp, foreign-owned, group/world-writable, or otherwise untrusted shadow is
/// reported instead of silently falling through to a later system binary.
pub fn resolve_tool(
    label: &str,
    candidates: &[&str],
    _allowances: &ResolverAllowances,
) -> Result<PathBuf, ResolverError> {
    let Some(path_value) = std::env::var_os("PATH") else {
        return Err(ResolverError::ToolNotFound(label.to_string()));
    };
    let denied_roots = crate::trusted_child::ambient_denied_roots();
    resolve_tool_on_path(label, candidates, &path_value, &denied_roots)
}

fn resolve_tool_on_path(
    label: &str,
    candidates: &[&str],
    path_value: &std::ffi::OsStr,
    denied_roots: &[PathBuf],
) -> Result<PathBuf, ResolverError> {
    for name in candidates {
        match TrustedExecutable::resolve_on_path(name, path_value, denied_roots) {
            Ok(executable) => {
                validate_resolver_tool_provenance(label, &executable).map_err(|reason| {
                    ResolverError::ToolUntrusted {
                        tool: executable.path().display().to_string(),
                        reason: format!(
                            "resolved {label} failed installation provenance: {reason}"
                        ),
                    }
                })?;
                remember_discovered_tool(&executable).map_err(|reason| {
                    ResolverError::ToolUntrusted {
                        tool: executable.path().display().to_string(),
                        reason,
                    }
                })?;
                return Ok(executable.path().to_path_buf());
            }
            Err(TrustedExecutableError::NotFound(_)) => continue,
            Err(error) => {
                return Err(ResolverError::ToolUntrusted {
                    tool: name.to_string(),
                    reason: format!("resolved {label} failed canonical provenance: {error}"),
                })
            }
        }
    }
    Err(ResolverError::ToolNotFound(label.to_string()))
}

#[cfg(unix)]
fn validate_resolver_tool_provenance(
    label: &str,
    executable: &TrustedExecutable,
) -> Result<(), String> {
    use std::os::unix::fs::MetadataExt as _;

    validate_resolver_tool_name(label, executable.path())?;
    let metadata = std::fs::metadata(executable.path())
        .map_err(|error| format!("cannot stat canonical executable: {error}"))?;
    if metadata.uid() == 0 && root_owned_hierarchy(executable.path())? {
        return Ok(());
    }
    if resolver_tool_pin_matches(executable.path())? {
        return Ok(());
    }
    Err(
        "user-writable resolver tools require explicit `tirith pkg trust-tool <absolute-path>` \
         enrollment; no matching canonical path + SHA-256 pin was found"
            .to_string(),
    )
}

#[cfg(windows)]
fn validate_resolver_tool_provenance(
    label: &str,
    executable: &TrustedExecutable,
) -> Result<(), String> {
    validate_resolver_tool_name(label, executable.path())?;
    let canonical = executable.path();
    // Do not infer system provenance from ProgramFiles/SystemRoot environment
    // variables: an invoking process can forge them. Stable std does not expose
    // the Windows owner/DACL identity needed to prove an arbitrary installation
    // hierarchy immutable, so Windows is explicit-enrollment-only. The pin file
    // itself is current-user-owned with a mutation-restricted DACL, and both the
    // enrolled digest and TrustedExecutable's pre-spawn digest are revalidated.
    windows_trust_acl::validate_executable_hierarchy(canonical)?;
    if resolver_tool_pin_matches(canonical)? {
        Ok(())
    } else {
        Err(
            "Windows resolver tools require explicit `tirith pkg trust-tool <absolute-path>` \
             enrollment; no matching canonical path + SHA-256 pin was found"
                .to_string(),
        )
    }
}

#[cfg(not(any(unix, windows)))]
fn validate_resolver_tool_provenance(
    _label: &str,
    _executable: &TrustedExecutable,
) -> Result<(), String> {
    Err("this platform has no resolver executable ownership verifier".to_string())
}

fn validate_resolver_tool_name(label: &str, path: &Path) -> Result<(), String> {
    // Resolver paths are later carried through uv/pip string argv and PATH.
    // Reject the whole canonical path, not merely its file name, when that
    // round-trip would be lossy. Otherwise distinct non-UTF-8 parent paths can
    // collapse to the same U+FFFD-containing child argument.
    resolver_tool_unicode_path(path)?;
    let Some(name) = path.file_name().and_then(|name| name.to_str()) else {
        return Err("canonical executable has no UTF-8 file name".to_string());
    };
    let name = name
        .strip_suffix(".exe")
        .or_else(|| name.strip_suffix(".EXE"))
        .unwrap_or(name)
        .to_ascii_lowercase();
    let matches = match label {
        "uv" => name == "uv",
        "python" => {
            name == "python"
                || name.strip_prefix("python").is_some_and(|suffix| {
                    !suffix.is_empty()
                        && suffix
                            .chars()
                            .all(|character| character.is_ascii_digit() || character == '.')
                })
        }
        _ => true,
    };
    if matches {
        Ok(())
    } else {
        Err(format!(
            "canonical executable name {name:?} does not identify the requested {label} tool"
        ))
    }
}

#[cfg(unix)]
fn root_owned_hierarchy(path: &Path) -> Result<bool, String> {
    use std::os::unix::fs::MetadataExt as _;

    for component in path.ancestors() {
        let metadata = std::fs::metadata(component)
            .map_err(|error| format!("cannot stat {}: {error}", component.display()))?;
        if metadata.uid() != 0 {
            return Ok(false);
        }
    }
    Ok(true)
}

const RESOLVER_TOOL_MAX_BYTES: u64 = 512 * 1024 * 1024;
const RESOLVER_TOOL_TRUST_MAX_BYTES: u64 = 1024 * 1024;
type DiscoveredResolverTools = std::sync::Mutex<BTreeMap<PathBuf, String>>;
static DISCOVERED_RESOLVER_TOOLS: std::sync::OnceLock<DiscoveredResolverTools> =
    std::sync::OnceLock::new();

#[cfg(windows)]
mod windows_trust_acl {
    use std::ffi::c_void;
    use std::mem::{size_of, size_of_val};
    use std::os::windows::ffi::OsStrExt as _;
    use std::path::Path;

    use windows::core::PCWSTR;
    use windows::Win32::Foundation::{CloseHandle, LocalFree, HANDLE, HLOCAL};
    use windows::Win32::Security::Authorization::{
        ConvertStringSidToSidW, GetNamedSecurityInfoW, SE_FILE_OBJECT,
    };
    use windows::Win32::Security::{
        AclSizeInformation, EqualSid, GetAce, GetAclInformation, GetTokenInformation,
        IsWellKnownSid, TokenUser, WinBuiltinAdministratorsSid, WinLocalSystemSid,
        ACCESS_ALLOWED_ACE, ACE_HEADER, ACL, ACL_SIZE_INFORMATION, DACL_SECURITY_INFORMATION,
        INHERIT_ONLY_ACE, OWNER_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR, PSID, TOKEN_QUERY,
        TOKEN_USER,
    };
    use windows::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

    const EXISTING_FILE_MUTATION: u32 = 0x0000_0002
        | 0x0000_0004
        | 0x0000_0010
        | 0x0000_0100
        | 0x0001_0000
        | 0x0004_0000
        | 0x0008_0000
        | 0x1000_0000
        | 0x4000_0000;
    // A non-owner with add-file/add-directory rights on the resolver-tools
    // directory can preplant pins.json, and DELETE_CHILD can replace it.
    const TRUST_DIRECTORY_MUTATION: u32 = EXISTING_FILE_MUTATION | 0x0000_0040;
    // On a higher ancestor, add-file/add-directory creates only a sibling and
    // cannot replace the already-existing next component. Reject authority that
    // can delete that child or take control of the ancestor, while preserving
    // normal default C:\ usability for unprivileged Windows users.
    const ANCESTOR_IDENTITY_MUTATION: u32 =
        0x0000_0040 | 0x0001_0000 | 0x0004_0000 | 0x0008_0000 | 0x1000_0000;
    const ACCESS_ALLOWED_ACE_TYPE: u8 = 0;
    const ACCESS_ALLOWED_COMPOUND_ACE_TYPE: u8 = 4;
    const ACCESS_ALLOWED_OBJECT_ACE_TYPE: u8 = 5;
    const ACCESS_ALLOWED_CALLBACK_ACE_TYPE: u8 = 9;
    const ACCESS_ALLOWED_CALLBACK_OBJECT_ACE_TYPE: u8 = 11;

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum ComponentRole {
        ExistingFile,
        ExecutableDirectory,
        TrustDirectory,
        Ancestor,
    }

    impl ComponentRole {
        fn mutation_mask(self) -> u32 {
            match self {
                Self::ExistingFile => EXISTING_FILE_MUTATION,
                Self::ExecutableDirectory | Self::TrustDirectory => TRUST_DIRECTORY_MUTATION,
                Self::Ancestor => ANCESTOR_IDENTITY_MUTATION,
            }
        }
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum HierarchyKind {
        Executable,
        TrustDirectory,
    }

    fn component_role(kind: HierarchyKind, index: usize) -> ComponentRole {
        match (kind, index) {
            (HierarchyKind::Executable, 0) => ComponentRole::ExistingFile,
            // The application directory participates in the Windows DLL search
            // order. Reject untrusted file/subdirectory creation here so an
            // enrolled uv/python cannot be paired with a planted dependency.
            (HierarchyKind::Executable, 1) => ComponentRole::ExecutableDirectory,
            (HierarchyKind::TrustDirectory, 0) => ComponentRole::TrustDirectory,
            _ => ComponentRole::Ancestor,
        }
    }

    struct OwnedHandle(HANDLE);

    impl Drop for OwnedHandle {
        fn drop(&mut self) {
            // SAFETY: this wrapper owns the handle returned by OpenProcessToken.
            unsafe {
                let _ = CloseHandle(self.0);
            }
        }
    }

    struct LocalSecurityDescriptor(PSECURITY_DESCRIPTOR);

    impl Drop for LocalSecurityDescriptor {
        fn drop(&mut self) {
            // SAFETY: GetNamedSecurityInfoW allocated this descriptor with LocalAlloc.
            unsafe {
                let _ = LocalFree(Some(HLOCAL(self.0 .0)));
            }
        }
    }

    struct LocalSid(PSID);

    impl Drop for LocalSid {
        fn drop(&mut self) {
            // SAFETY: ConvertStringSidToSidW allocated this SID with LocalAlloc.
            unsafe {
                let _ = LocalFree(Some(HLOCAL(self.0 .0)));
            }
        }
    }

    struct SecurityContext {
        current_user_storage: Vec<usize>,
        trusted_installer: LocalSid,
    }

    impl SecurityContext {
        fn load() -> Result<Self, String> {
            let current_user_storage = current_user_sid_buffer()?;
            let sid_text: Vec<u16> =
                "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464"
                    .encode_utf16()
                    .chain(std::iter::once(0))
                    .collect();
            let mut trusted_installer = PSID::default();
            // SAFETY: sid_text is NUL-terminated and trusted_installer is a
            // valid out-pointer. The returned SID is owned by LocalSid.
            unsafe { ConvertStringSidToSidW(PCWSTR(sid_text.as_ptr()), &mut trusted_installer) }
                .map_err(|error| format!("cannot initialize TrustedInstaller SID: {error}"))?;
            Ok(Self {
                current_user_storage,
                trusted_installer: LocalSid(trusted_installer),
            })
        }

        fn current_user(&self) -> PSID {
            token_user_sid(&self.current_user_storage)
        }
    }

    fn current_user_sid_buffer() -> Result<Vec<usize>, String> {
        let mut raw_token = HANDLE::default();
        // SAFETY: raw_token is a valid out-pointer and the pseudo process handle
        // remains valid for the duration of the call.
        unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut raw_token) }
            .map_err(|error| format!("cannot open current process token: {error}"))?;
        let token = OwnedHandle(raw_token);

        let mut needed = 0_u32;
        // The sizing call is expected to fail with insufficient buffer; `needed`
        // is the authoritative allocation size.
        let _ = unsafe { GetTokenInformation(token.0, TokenUser, None, 0, &mut needed) };
        if needed < size_of::<TOKEN_USER>() as u32 {
            return Err("current process token returned no usable user SID".to_string());
        }
        let words = (needed as usize).div_ceil(size_of::<usize>());
        let mut buffer = vec![0_usize; words];
        // SAFETY: Vec<usize> provides sufficient alignment and `needed` bytes;
        // the API initializes a TOKEN_USER whose SID remains inside this buffer.
        unsafe {
            GetTokenInformation(
                token.0,
                TokenUser,
                Some(buffer.as_mut_ptr().cast::<c_void>()),
                needed,
                &mut needed,
            )
        }
        .map_err(|error| format!("cannot read current process user SID: {error}"))?;
        Ok(buffer)
    }

    fn token_user_sid(buffer: &[usize]) -> PSID {
        // SAFETY: current_user_sid_buffer stores a successfully initialized,
        // suitably aligned TOKEN_USER at the start of the allocation.
        unsafe { (*(buffer.as_ptr().cast::<TOKEN_USER>())).User.Sid }
    }

    fn sid_is_privileged(sid: PSID, context: &SecurityContext) -> bool {
        let current_user = context.current_user();
        // SAFETY: all SID pointers originate from validated token/security
        // descriptor storage that outlives these calls.
        unsafe {
            EqualSid(sid, current_user).is_ok()
                || IsWellKnownSid(sid, WinLocalSystemSid).as_bool()
                || IsWellKnownSid(sid, WinBuiltinAdministratorsSid).as_bool()
                || EqualSid(sid, context.trusted_installer.0).is_ok()
        }
    }

    fn ace_applies_to_component(flags: u8) -> bool {
        flags & INHERIT_ONLY_ACE.0 as u8 == 0
    }

    fn validate_component(
        path: &Path,
        context: &SecurityContext,
        require_current_user_owner: bool,
        role: ComponentRole,
    ) -> Result<(), String> {
        let current_user = context.current_user();
        let mut wide: Vec<u16> = path.as_os_str().encode_wide().collect();
        if wide.contains(&0) {
            return Err("resolver trust path contains an interior NUL".to_string());
        }
        wide.push(0);

        let mut owner = PSID::default();
        let mut dacl: *mut ACL = std::ptr::null_mut();
        let mut raw_descriptor = PSECURITY_DESCRIPTOR::default();
        // SAFETY: wide is NUL-terminated and each output pointer is valid.
        let status = unsafe {
            GetNamedSecurityInfoW(
                PCWSTR(wide.as_ptr()),
                SE_FILE_OBJECT,
                OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
                Some(&mut owner),
                None,
                Some(&mut dacl),
                None,
                &mut raw_descriptor,
            )
        };
        if status.is_err() {
            return Err(format!(
                "cannot read resolver trust path owner/DACL for {}: {status:?}",
                path.display()
            ));
        }
        let _descriptor = LocalSecurityDescriptor(raw_descriptor);
        let owner_is_current_user =
            !owner.is_invalid() && unsafe { EqualSid(owner, current_user) }.is_ok();
        let owner_is_protected = !owner.is_invalid() && sid_is_privileged(owner, context);
        if !owner_is_current_user && (require_current_user_owner || !owner_is_protected) {
            return Err(format!(
                "resolver trust path {} is not owned by the current user or a protected Windows principal",
                path.display(),
            ));
        }
        if dacl.is_null() {
            return Err(format!(
                "resolver trust path {} has an unrestricted null DACL",
                path.display()
            ));
        }

        let mut acl_info = ACL_SIZE_INFORMATION::default();
        // SAFETY: dacl points into the live security descriptor and acl_info is a
        // correctly sized output buffer for AclSizeInformation.
        unsafe {
            GetAclInformation(
                dacl,
                (&mut acl_info as *mut ACL_SIZE_INFORMATION).cast::<c_void>(),
                size_of_val(&acl_info) as u32,
                AclSizeInformation,
            )
        }
        .map_err(|error| format!("cannot inspect resolver trust DACL: {error}"))?;

        for index in 0..acl_info.AceCount {
            let mut raw_ace: *mut c_void = std::ptr::null_mut();
            // SAFETY: index is within the AceCount reported for this live ACL.
            unsafe { GetAce(dacl, index, &mut raw_ace) }
                .map_err(|error| format!("cannot inspect resolver trust ACE {index}: {error}"))?;
            if raw_ace.is_null() {
                return Err(format!("resolver trust ACE {index} is null"));
            }
            // SAFETY: GetAce returned a pointer to at least an ACE_HEADER.
            let header = unsafe { &*raw_ace.cast::<ACE_HEADER>() };
            // An INHERIT_ONLY ACE is a template for descendants and grants no
            // access to this component. Any effective inherited copy is checked
            // when the traversal reaches the descendant itself.
            if !ace_applies_to_component(header.AceFlags) {
                continue;
            }
            match header.AceType {
                ACCESS_ALLOWED_ACE_TYPE => {
                    if usize::from(header.AceSize) < size_of::<ACCESS_ALLOWED_ACE>() {
                        return Err(format!("resolver trust ACE {index} is truncated"));
                    }
                    // SAFETY: the size check covers ACCESS_ALLOWED_ACE, whose
                    // SidStart is the first byte of the variable-length SID.
                    let ace = unsafe { &*raw_ace.cast::<ACCESS_ALLOWED_ACE>() };
                    if ace.Mask & role.mutation_mask() == 0 {
                        continue;
                    }
                    let sid = PSID(std::ptr::addr_of!(ace.SidStart).cast_mut().cast::<c_void>());
                    if !sid_is_privileged(sid, context) {
                        return Err(format!(
                            "resolver trust path {} grants mutation rights to a non-owner principal",
                            path.display()
                        ));
                    }
                }
                ACCESS_ALLOWED_COMPOUND_ACE_TYPE
                | ACCESS_ALLOWED_OBJECT_ACE_TYPE
                | ACCESS_ALLOWED_CALLBACK_ACE_TYPE
                | ACCESS_ALLOWED_CALLBACK_OBJECT_ACE_TYPE => {
                    // These layouts carry a variable SID offset and conditions.
                    // Enrollment fails closed instead of guessing whether they
                    // grant a non-owner mutation authority.
                    return Err(format!(
                        "resolver trust path {} uses an unsupported conditional/object allow ACE",
                        path.display()
                    ));
                }
                _ => {}
            }
        }
        Ok(())
    }

    pub(super) fn validate_owner_only(path: &Path) -> Result<(), String> {
        let context = SecurityContext::load()?;
        validate_component(path, &context, true, ComponentRole::ExistingFile)
    }

    fn validate_hierarchy(
        path: &Path,
        require_current_user_leaf: bool,
        kind: HierarchyKind,
    ) -> Result<(), String> {
        let canonical = path
            .canonicalize()
            .map_err(|error| format!("cannot canonicalize Windows trust path: {error}"))?;
        let context = SecurityContext::load()?;
        for (index, component) in canonical.ancestors().enumerate() {
            validate_component(
                component,
                &context,
                require_current_user_leaf && index == 0,
                component_role(kind, index),
            )?;
        }
        Ok(())
    }

    /// Validate an already-existing enrolled executable and every canonical
    /// ancestor. Higher ancestors may allow sibling creation, but not deletion
    /// or security-control of the existing next path component. The immediate
    /// application directory also rejects child creation because Windows may
    /// load dependent DLLs from beside the executable.
    pub(super) fn validate_executable_hierarchy(path: &Path) -> Result<(), String> {
        validate_hierarchy(path, false, HierarchyKind::Executable)
    }

    /// Validate the resolver-tools directory and every canonical ancestor. The
    /// leaf is current-user-owned and rejects untrusted child creation so an
    /// attacker cannot preplant or replace pins.json.
    pub(super) fn validate_trust_directory_hierarchy(path: &Path) -> Result<(), String> {
        validate_hierarchy(path, true, HierarchyKind::TrustDirectory)
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn inheritance_only_ace_is_not_effective_on_current_component() {
            assert!(!ace_applies_to_component(INHERIT_ONLY_ACE.0 as u8));
            assert!(ace_applies_to_component(0));
        }

        #[test]
        fn role_selection_protects_executable_directory_but_not_distant_siblings() {
            assert_eq!(
                component_role(HierarchyKind::Executable, 0),
                ComponentRole::ExistingFile
            );
            assert_eq!(
                component_role(HierarchyKind::Executable, 1),
                ComponentRole::ExecutableDirectory
            );
            assert_eq!(
                component_role(HierarchyKind::Executable, 2),
                ComponentRole::Ancestor
            );
            assert_ne!(
                ComponentRole::ExecutableDirectory.mutation_mask() & 0x0000_0002,
                0
            );
            assert_eq!(ComponentRole::Ancestor.mutation_mask() & 0x0000_0002, 0);
            assert_eq!(
                component_role(HierarchyKind::TrustDirectory, 0),
                ComponentRole::TrustDirectory
            );
            assert_eq!(
                component_role(HierarchyKind::TrustDirectory, 1),
                ComponentRole::Ancestor
            );
        }

        #[test]
        fn normal_windows_test_executable_hierarchy_is_usable() {
            let executable = std::env::current_exe().unwrap();
            match validate_executable_hierarchy(&executable) {
                Ok(()) => {}
                // Hosted Windows runners build under a tree whose DACL grants
                // mutation rights to a non-owner principal (the runner's admin
                // group), so the running test binary legitimately fails this
                // check and there is nothing left to assert. Any OTHER refusal
                // is a real regression and still fails.
                Err(reason) if reason.contains("non-owner principal") => {
                    eprintln!("skipping: {reason}");
                }
                Err(reason) => panic!("unexpected hierarchy refusal: {reason}"),
            }
        }
    }
}

#[derive(Debug, Default, serde::Deserialize, serde::Serialize)]
struct ResolverToolTrustStore {
    #[serde(default)]
    pins: BTreeMap<String, String>,
}

fn resolver_tool_unicode_path(path: &Path) -> Result<&str, String> {
    path.to_str().ok_or_else(|| {
        "canonical resolver executable path is not valid Unicode; non-Unicode resolver paths are refused because enrollment, argv, and PATH must preserve the exact path"
            .to_string()
    })
}

/// Versioned, injective JSON-map key for a canonical resolver path. Legacy
/// display-string keys are intentionally not consulted: `Path::display` is
/// lossy, so silently accepting those entries would preserve path collisions.
fn resolver_tool_store_key(path: &Path) -> Result<String, String> {
    let exact = resolver_tool_unicode_path(path)?;
    Ok(format!("utf8-hex-v1:{}", hex::encode(exact.as_bytes())))
}

fn resolver_tool_trust_file() -> Result<PathBuf, String> {
    let base = crate::policy::config_dir()
        .ok_or_else(|| "cannot determine the operator config directory".to_string())?;
    Ok(base.join("resolver-tools").join("pins.json"))
}

fn resolver_tool_digest(path: &Path) -> Result<String, String> {
    let handle = crate::util::open_read_no_follow_capped(path, RESOLVER_TOOL_MAX_BYTES).map_err(
        |error| format!("cannot open enrolled resolver tool without following links: {error:?}"),
    )?;
    match crate::util::sha256_from_handle(handle, RESOLVER_TOOL_MAX_BYTES)
        .map_err(|error| format!("cannot hash resolver tool: {error}"))?
    {
        crate::util::HashOutcome::Digest(digest) => Ok(digest),
        crate::util::HashOutcome::BudgetExceeded => Err(format!(
            "resolver tool exceeds the {} byte enrollment cap",
            RESOLVER_TOOL_MAX_BYTES
        )),
    }
}

/// Enrollment is deliberately narrower than ordinary executable trust. A
/// user-writable `uv` can participate in enforcement only when Linux can seal
/// the exact enrolled bytes and the image has no interpreter or dynamic-loader
/// dependency that could remain mutable outside that seal.
#[cfg(target_os = "linux")]
fn validate_static_linux_uv(path: &Path) -> Result<(), String> {
    use std::os::unix::fs::FileExt as _;

    const ELF_MAGIC: &[u8; 4] = b"\x7fELF";
    const ELFCLASS32: u8 = 1;
    const ELFCLASS64: u8 = 2;
    const ELFDATA2LSB: u8 = 1;
    const ELFDATA2MSB: u8 = 2;
    const PT_LOAD: u32 = 1;
    const PT_DYNAMIC: u32 = 2;
    const PT_INTERP: u32 = 3;
    const MAX_PROGRAM_HEADERS: u64 = 4096;

    let file = crate::util::open_read_no_follow_capped(path, RESOLVER_TOOL_MAX_BYTES)
        .map_err(|error| format!("cannot inspect enrolled uv image: {error:?}"))?;
    let mut ident = [0_u8; 16];
    file.read_exact_at(&mut ident, 0)
        .map_err(|error| format!("cannot read enrolled uv ELF identity: {error}"))?;
    if &ident[..4] != ELF_MAGIC {
        return Err(
            "user-writable uv enrollment requires a static native Linux ELF image; scripts and wrapper launchers are refused"
                .to_string(),
        );
    }
    let (header_len, phoff_offset, phentsize_offset, phnum_offset) = match ident[4] {
        ELFCLASS32 => (52_usize, 28_usize, 42_usize, 44_usize),
        ELFCLASS64 => (64_usize, 32_usize, 54_usize, 56_usize),
        other => return Err(format!("enrolled uv uses unsupported ELF class {other}")),
    };
    let little_endian = match ident[5] {
        ELFDATA2LSB => true,
        ELFDATA2MSB => false,
        other => {
            return Err(format!(
                "enrolled uv uses unsupported ELF byte order {other}"
            ))
        }
    };
    let mut header = vec![0_u8; header_len];
    file.read_exact_at(&mut header, 0)
        .map_err(|error| format!("cannot read enrolled uv ELF header: {error}"))?;
    let read_u16 = |offset: usize| {
        let bytes: [u8; 2] = header[offset..offset + 2]
            .try_into()
            .expect("fixed ELF header offsets are in bounds");
        if little_endian {
            u16::from_le_bytes(bytes)
        } else {
            u16::from_be_bytes(bytes)
        }
    };
    let read_u32 = |offset: usize| {
        let bytes: [u8; 4] = header[offset..offset + 4]
            .try_into()
            .expect("fixed ELF header offsets are in bounds");
        if little_endian {
            u32::from_le_bytes(bytes)
        } else {
            u32::from_be_bytes(bytes)
        }
    };
    let read_u64 = |offset: usize| {
        let bytes: [u8; 8] = header[offset..offset + 8]
            .try_into()
            .expect("fixed ELF header offsets are in bounds");
        if little_endian {
            u64::from_le_bytes(bytes)
        } else {
            u64::from_be_bytes(bytes)
        }
    };
    let phoff = if ident[4] == ELFCLASS32 {
        u64::from(read_u32(phoff_offset))
    } else {
        read_u64(phoff_offset)
    };
    let phentsize = u64::from(read_u16(phentsize_offset));
    let phnum = u64::from(read_u16(phnum_offset));
    if phnum == 0 || phnum > MAX_PROGRAM_HEADERS || !(4..=256).contains(&phentsize) {
        return Err("enrolled uv has an invalid or unbounded ELF program-header table".to_string());
    }
    let table_bytes = phentsize
        .checked_mul(phnum)
        .and_then(|bytes| phoff.checked_add(bytes))
        .ok_or_else(|| "enrolled uv ELF program-header table overflows".to_string())?;
    if table_bytes > file.metadata().map_err(|error| error.to_string())?.len() {
        return Err("enrolled uv ELF program-header table is truncated".to_string());
    }

    let mut saw_load = false;
    for index in 0..phnum {
        let offset = phoff + index * phentsize;
        let mut kind = [0_u8; 4];
        file.read_exact_at(&mut kind, offset)
            .map_err(|error| format!("cannot read enrolled uv program header: {error}"))?;
        let kind = if little_endian {
            u32::from_le_bytes(kind)
        } else {
            u32::from_be_bytes(kind)
        };
        match kind {
            PT_LOAD => saw_load = true,
            PT_DYNAMIC | PT_INTERP => {
                return Err(
                    "user-writable uv enrollment requires a fully static ELF with no interpreter or dynamic-loader dependency"
                        .to_string(),
                )
            }
            _ => {}
        }
    }
    if !saw_load {
        return Err("enrolled uv ELF has no loadable segment".to_string());
    }
    Ok(())
}

fn remember_discovered_tool(executable: &TrustedExecutable) -> Result<(), String> {
    let digest = resolver_tool_digest(executable.path())?;
    executable
        .revalidate()
        .map_err(|error| format!("resolver tool changed while binding discovery: {error}"))?;
    DISCOVERED_RESOLVER_TOOLS
        .get_or_init(Default::default)
        .lock()
        .map_err(|_| "discovered resolver-tool registry was poisoned".to_string())?
        .insert(executable.path().to_path_buf(), digest);
    Ok(())
}

#[cfg(any(unix, test))]
fn revalidate_discovered_tool(executable: &TrustedExecutable) -> Result<(), String> {
    let expected = DISCOVERED_RESOLVER_TOOLS
        .get_or_init(Default::default)
        .lock()
        .map_err(|_| "discovered resolver-tool registry was poisoned".to_string())?
        .get(executable.path())
        .cloned();
    let Some(expected) = expected else {
        // Public callers may construct ResolverTools directly, so there may be
        // no process-local discovery digest. Persisted installation provenance
        // is enforced separately by BoundResolverTools::bind; still
        // revalidate the freshly captured identity here instead of treating a
        // missing discovery entry as an operator-trust bypass.
        return executable
            .revalidate()
            .map_err(|error| format!("resolver tool changed during validation: {error}"));
    };
    let current = resolver_tool_digest(executable.path())?;
    executable
        .revalidate()
        .map_err(|error| format!("resolver tool changed after discovery: {error}"))?;
    if constant_time_hex_eq(expected.as_bytes(), current.as_bytes()) {
        Ok(())
    } else {
        Err("resolver tool digest changed after PATH discovery".to_string())
    }
}

fn read_resolver_tool_trust_store(
    trust_file: &Path,
) -> Result<Option<ResolverToolTrustStore>, String> {
    let metadata = match std::fs::symlink_metadata(trust_file) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(format!("cannot inspect resolver-tool trust store: {error}")),
    };
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err("resolver-tool trust store is not a regular non-symlink file".to_string());
    }
    validate_resolver_trust_directory(
        trust_file
            .parent()
            .ok_or_else(|| "resolver-tool trust store has no parent".to_string())?,
    )?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt as _;
        let effective_uid = unsafe { libc::geteuid() };
        if metadata.uid() != effective_uid || metadata.mode() & 0o077 != 0 {
            return Err(
                "resolver-tool trust store must be owned by the current user and mode 0600"
                    .to_string(),
            );
        }
        crate::trusted_child::reject_unix_extended_acl(trust_file, false)?;
    }
    #[cfg(windows)]
    windows_trust_acl::validate_owner_only(trust_file)?;
    let bytes = crate::util::read_text_no_follow_capped(trust_file, RESOLVER_TOOL_TRUST_MAX_BYTES)
        .map_err(|error| format!("cannot read resolver-tool trust store: {error:?}"))?;
    let store: ResolverToolTrustStore = serde_json::from_slice(&bytes)
        .map_err(|error| format!("resolver-tool trust store is corrupt: {error}"))?;
    Ok(Some(store))
}

fn resolver_tool_pin_matches(path: &Path) -> Result<bool, String> {
    let trust_file = resolver_tool_trust_file()?;
    let Some(store) = read_resolver_tool_trust_store(&trust_file)? else {
        return Ok(false);
    };
    let canonical = path
        .canonicalize()
        .map_err(|error| format!("cannot canonicalize resolver tool: {error}"))?;
    #[cfg(windows)]
    windows_trust_acl::validate_executable_hierarchy(&canonical)?;
    let key = resolver_tool_store_key(&canonical)?;
    let Some(expected) = store.pins.get(&key) else {
        return Ok(false);
    };
    Ok(constant_time_hex_eq(
        expected.as_bytes(),
        resolver_tool_digest(&canonical)?.as_bytes(),
    ))
}

fn constant_time_hex_eq(left: &[u8], right: &[u8]) -> bool {
    let mut difference = left.len() ^ right.len();
    for index in 0..left.len().max(right.len()) {
        difference |= usize::from(
            left.get(index).copied().unwrap_or(0) ^ right.get(index).copied().unwrap_or(0),
        );
    }
    difference == 0
}

/// Explicitly enroll a fully static, native Linux `uv` executable by canonical
/// absolute path and SHA-256 in Tirith's owner-only operator trust store. A
/// user-writable Python runtime cannot be made trustworthy by pinning only its
/// launcher, so it is rejected before any trust-store side effect. PATH
/// discovery never creates a pin implicitly.
pub fn enroll_resolver_tool(path: &Path) -> Result<PathBuf, ResolverError> {
    let executable =
        TrustedExecutable::from_absolute(path, &crate::trusted_child::ambient_denied_roots())
            .map_err(|error| ResolverError::ToolUntrusted {
                tool: path.display().to_string(),
                reason: error.to_string(),
            })?;
    let canonical = executable.path().to_path_buf();
    #[cfg(windows)]
    windows_trust_acl::validate_executable_hierarchy(&canonical).map_err(resolver_io_error)?;
    if !executable.has_system_helper_provenance() {
        #[cfg(target_os = "linux")]
        {
            validate_resolver_tool_name("uv", &canonical).map_err(|reason| {
                ResolverError::ToolUntrusted {
                    tool: canonical.display().to_string(),
                    reason: format!(
                        "user-writable enrollment can authorize only uv; Python and its runtime tree must be root-managed: {reason}"
                    ),
                }
            })?;
            validate_static_linux_uv(&canonical).map_err(|reason| {
                ResolverError::ToolUntrusted {
                    tool: canonical.display().to_string(),
                    reason,
                }
            })?;
        }
        #[cfg(not(target_os = "linux"))]
        return Err(ResolverError::ToolUntrusted {
            tool: canonical.display().to_string(),
            reason: "user-writable resolver enrollment is enforceable only for a static native uv image on Linux; this platform cannot seal the enrolled executable bytes"
                .to_string(),
        });
    }
    let store_key =
        resolver_tool_store_key(&canonical).map_err(|reason| ResolverError::ToolUntrusted {
            tool: canonical.display().to_string(),
            reason,
        })?;
    let digest = resolver_tool_digest(&canonical).map_err(resolver_io_error)?;
    executable
        .revalidate()
        .map_err(|error| ResolverError::ToolUntrusted {
            tool: canonical.display().to_string(),
            reason: format!("resolver tool changed during enrollment: {error}"),
        })?;
    let trust_file = resolver_tool_trust_file().map_err(resolver_io_error)?;
    let trust_dir = trust_file
        .parent()
        .ok_or_else(|| resolver_io_error("resolver-tool trust file has no parent"))?;
    crate::util::create_dir_durable(trust_dir).map_err(ResolverError::Io)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(trust_dir, std::fs::Permissions::from_mode(0o700))
            .map_err(ResolverError::Io)?;
    }
    validate_resolver_trust_directory(trust_dir).map_err(resolver_io_error)?;
    // Never merge an unvalidated pre-existing file: doing so and then replacing
    // it with a fresh 0600 file would launder attacker-selected pins into trusted
    // enrollment state.
    let mut store = read_resolver_tool_trust_store(&trust_file)
        .map_err(resolver_io_error)?
        .unwrap_or_default();
    store.pins.insert(store_key, digest);
    let body = serde_json::to_vec_pretty(&store).map_err(|error| {
        resolver_io_error(format!(
            "cannot serialize resolver-tool trust store: {error}"
        ))
    })?;
    crate::util::write_file_atomic_0600(&trust_file, &body).map_err(ResolverError::Io)?;
    if !resolver_tool_pin_matches(&canonical).map_err(resolver_io_error)? {
        return Err(ResolverError::ToolUntrusted {
            tool: canonical.display().to_string(),
            reason: "resolver tool changed while validating the written enrollment pin".to_string(),
        });
    }
    Ok(canonical)
}

fn validate_resolver_trust_directory(directory: &Path) -> Result<(), String> {
    let canonical = directory
        .canonicalize()
        .map_err(|error| format!("cannot canonicalize resolver trust directory: {error}"))?;
    for denied in crate::trusted_child::ambient_denied_roots() {
        let denied = denied.canonicalize().unwrap_or(denied);
        if canonical == denied || canonical.starts_with(&denied) {
            return Err(format!(
                "resolver trust directory {} is inside denied project/temp root {}",
                canonical.display(),
                denied.display()
            ));
        }
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt as _;
        let effective_uid = unsafe { libc::geteuid() };
        for component in canonical.ancestors() {
            let metadata = std::fs::metadata(component)
                .map_err(|error| format!("cannot stat {}: {error}", component.display()))?;
            if metadata.uid() != 0 && metadata.uid() != effective_uid {
                return Err(format!(
                    "resolver trust directory ancestor {} has foreign owner uid {}",
                    component.display(),
                    metadata.uid()
                ));
            }
            if metadata.mode() & 0o022 != 0 {
                return Err(format!(
                    "resolver trust directory ancestor {} is group/world writable",
                    component.display()
                ));
            }
            crate::trusted_child::reject_unix_extended_acl(component, true)?;
        }
    }
    #[cfg(windows)]
    windows_trust_acl::validate_trust_directory_hierarchy(&canonical)?;
    Ok(())
}

fn resolver_io_error(reason: impl Into<String>) -> ResolverError {
    ResolverError::Io(std::io::Error::other(reason.into()))
}

/// Find `name` on the process `PATH`, returning the first directory entry that is
/// an executable regular file. On Windows the `PATHEXT` extensions are tried.
/// This is the only PATH lookup; the resolved absolute path is what the child
/// runs, so the child never re-resolves a bare name in an attacker-influenced
/// `PATH`.
#[cfg(test)]
fn find_on_path(name: &str) -> Option<PathBuf> {
    let path_var = std::env::var_os("PATH")?;
    for dir in std::env::split_paths(&path_var) {
        if dir.as_os_str().is_empty() {
            continue;
        }
        let direct = dir.join(name);
        if crate::path_audit::is_executable_file(&direct) {
            return Some(direct);
        }
        #[cfg(windows)]
        {
            for ext in windows_path_exts() {
                let candidate = dir.join(format!("{name}{ext}"));
                if crate::path_audit::is_executable_file(&candidate) {
                    return Some(candidate);
                }
            }
        }
    }
    None
}

/// Windows executable extensions from `PATHEXT`, lowercased, falling back to the
/// usual default set when `PATHEXT` is unset.
#[cfg(all(windows, test))]
fn windows_path_exts() -> Vec<String> {
    match std::env::var("PATHEXT") {
        Ok(v) => v
            .split(';')
            .filter(|e| !e.is_empty())
            .map(|e| e.to_ascii_lowercase())
            .collect(),
        Err(_) => vec![
            ".com".to_string(),
            ".exe".to_string(),
            ".bat".to_string(),
            ".cmd".to_string(),
        ],
    }
}

/// Split an editable-requirement option from its target.
///
/// One helper for both classifiers so they cannot drift apart. The target may
/// be attached (`-e./pkg`), joined with `=`, or the next token: pip's
/// requirements parser is optparse-backed, where the attached `-eVALUE` form is
/// standard, so an option-shaped token like `-editable-pkg` genuinely means
/// `-e ditable-pkg` to the resolver child. Tirith models what the child does,
/// so this deliberately does NOT require a delimiter — demanding one would
/// refuse `-e./pkg`, which pip accepts. The extracted target is re-validated by
/// the caller, so the VCS, direct-URL, and local-path controls still apply.
fn editable_requirement_target(trimmed: &str) -> Option<&str> {
    let lower = trimmed.to_ascii_lowercase();
    for flag in ["--editable", "-e"] {
        if lower.starts_with(flag) {
            return Some(&trimmed[flag.len()..]);
        }
    }
    None
}

/// Classify a requirement spec, refusing the forms that would build from source
/// or pull bytes from outside the approved indexes, unless the governing
/// allowance is set. Returns `Ok(())` for an acceptable
/// `name[extras][version-specifiers][; marker]` spec.
///
/// This is a *pre-flight* gate: it runs before any subprocess, so a refused
/// requirement never reaches `uv` / `pip` and a build backend never executes
/// (cross-cutting invariant 4). It is deliberately conservative; an acceptable
/// spec still goes through `uv` for full PEP 508 resolution.
pub fn validate_requirement(
    spec: &str,
    allowances: &ResolverAllowances,
) -> Result<(), ResolverError> {
    let reject = |reason: &str| {
        Err(ResolverError::RejectedRequirement {
            spec: spec.to_string(),
            reason: reason.to_string(),
        })
    };
    let trimmed = spec.trim();
    if trimmed.is_empty() {
        return reject("empty requirement");
    }
    // A control character (newline / CR / NUL / etc.) could smuggle a second
    // requirement or break the lock file; refuse outright. Horizontal tab is
    // the sole exception because PEP 508 explicitly includes it in `wsp` and
    // the lexical parser treats it exactly like a space.
    if trimmed.chars().any(|c| c != '\t' && c.is_control()) {
        return reject("requirement contains a control character");
    }
    // A requirements-file include (`-r other.txt`) or any other dashed option is
    // refused: callers pass concrete specs, and a `-r` could pull an
    // attacker-controlled file of further requirements past these checks.
    if trimmed.starts_with('-') {
        if let Some(target) = editable_requirement_target(trimmed) {
            if !allowances.allow_editable {
                return reject("editable installs (-e/--editable) are not permitted");
            }
            let target = target.trim_start_matches('=').trim();
            if target.is_empty() {
                return reject("editable requirement has no target");
            }
            // An editable allowance does not bypass the independent VCS, direct
            // URL, and local-path controls.
            return validate_requirement(target, allowances);
        }
        return reject("option-form requirements (leading '-') are not permitted");
    }

    match classify_requirement_location(trimmed).map_err(|reason| {
        ResolverError::RejectedRequirement {
            spec: spec.to_string(),
            reason,
        }
    })? {
        RequirementLocation::Named => {}
        RequirementLocation::Vcs(target) => {
            if !allowances.allow_vcs {
                return reject("VCS requirements (git+/hg+/svn+/bzr+) are not permitted");
            }
            parse_vcs_url(target).map_err(|reason| ResolverError::RejectedRequirement {
                spec: spec.to_string(),
                reason: format!("VCS URL rejected: {reason}"),
            })?;
        }
        RequirementLocation::Direct(target) => {
            if !allowances.allow_direct_url {
                return reject("direct-URL requirements (name @ url / bare url) are not permitted");
            }
            parse_network_url(target).map_err(|reason| ResolverError::RejectedRequirement {
                spec: spec.to_string(),
                reason: format!("direct URL rejected: {reason}"),
            })?;
        }
        RequirementLocation::Local => {
            if !allowances.allow_local_path {
                return reject("local-path requirements are not permitted");
            }
        }
    }
    // sdist-only requirements cannot be expressed by name alone (a `.tar.gz`
    // target is caught as a local path or direct URL above); source *building*
    // is blocked by `--no-build` / `--only-binary=:all:` at download time, and a
    // resolve that can only satisfy a name from an sdist is refused there.
    // Nothing further to gate here for a plain name spec.
    let _ = &allowances.allow_sdist;
    Ok(())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RequirementLocation<'a> {
    Named,
    Vcs(&'a str),
    Direct(&'a str),
    Local,
}

/// Canonically classify the PEP 508 location portion of a requirement. The `@`
/// token has optional surrounding whitespace in PEP 508, so classification is
/// structural and never relies on the old exact `" @ "` spelling.
fn classify_requirement_location(spec: &str) -> Result<RequirementLocation<'_>, String> {
    let trimmed = spec.trim();
    let lower = trimmed.to_ascii_lowercase();

    // Packaging tools accept platform path extensions in addition to strict PEP
    // 508. Classify them before `Url::parse`, which otherwise treats `C:/pkg`
    // as a URL with scheme `c` and could bypass the local-path allowance.
    if is_local_path_requirement(trimmed)
        && (!trimmed.contains("://") || lower.starts_with("file:"))
    {
        return Ok(RequirementLocation::Local);
    }
    if is_vcs_target(&lower) {
        return Ok(RequirementLocation::Vcs(trimmed));
    }
    if let Ok(parsed) = url::Url::parse(trimmed) {
        return if parsed.scheme().eq_ignore_ascii_case("file") {
            Ok(RequirementLocation::Local)
        } else {
            Ok(RequirementLocation::Direct(trimmed))
        };
    }

    let after_name = pep508_after_name_and_extras(trimmed)?;
    if let Some(raw_target) = after_name.strip_prefix('@') {
        let raw_target = raw_target.trim();
        if raw_target.is_empty() {
            return Err("malformed PEP 508 direct reference".to_string());
        }
        let target = strip_pep508_marker(raw_target);
        if target.is_empty() {
            return Err("malformed PEP 508 direct reference".to_string());
        }
        let target_lower = target.to_ascii_lowercase();
        if is_vcs_target(&target_lower) {
            return Ok(RequirementLocation::Vcs(target));
        }
        if is_local_path_requirement(target)
            && (!target.contains("://") || target_lower.starts_with("file:"))
        {
            return Ok(RequirementLocation::Local);
        }
        if url::Url::parse(target).is_ok() {
            return Ok(RequirementLocation::Direct(target));
        }
        return Err("malformed or unsupported PEP 508 direct reference".to_string());
    }

    // `@` inside an arbitrary-equality version (`===foo@bar`) or a quoted
    // environment marker is data, not a direct-reference delimiter. Requiring
    // the delimiter immediately after the parsed name/extras is the PEP 508
    // grammar distinction the old substring matcher lacked.
    let named_tail = after_name.trim_start();
    if named_tail.is_empty()
        || named_tail.starts_with(';')
        || named_tail.starts_with('(')
        || ["===", "~=", "==", "!=", "<=", ">=", "<", ">"]
            .iter()
            .any(|operator| named_tail.starts_with(operator))
    {
        Ok(RequirementLocation::Named)
    } else {
        Err("malformed or unsupported PEP 508 requirement".to_string())
    }
}

/// Return the slice immediately after a syntactically valid PEP 508
/// distribution name and optional extras list. This is deliberately lexical:
/// it performs no filesystem or network access and preserves the remaining
/// version/direct-reference/marker text for policy classification.
fn pep508_after_name_and_extras(spec: &str) -> Result<&str, String> {
    let bytes = spec.as_bytes();
    let Some(first) = bytes.first().copied() else {
        return Err("empty requirement".to_string());
    };
    if !first.is_ascii_alphanumeric() {
        return Err("requirement has no valid distribution name".to_string());
    }
    let mut cursor = 1usize;
    while cursor < bytes.len()
        && (bytes[cursor].is_ascii_alphanumeric() || matches!(bytes[cursor], b'-' | b'_' | b'.'))
    {
        cursor += 1;
    }
    while cursor < bytes.len() && bytes[cursor].is_ascii_whitespace() {
        cursor += 1;
    }
    if bytes.get(cursor) == Some(&b'[') {
        cursor += 1;
        let extras_start = cursor;
        while cursor < bytes.len() && bytes[cursor] != b']' {
            let byte = bytes[cursor];
            if !(byte.is_ascii_alphanumeric()
                || matches!(byte, b'-' | b'_' | b'.' | b',' | b' ' | b'\t'))
            {
                return Err("requirement extras contain an invalid character".to_string());
            }
            cursor += 1;
        }
        if cursor == extras_start || bytes.get(cursor) != Some(&b']') {
            return Err("requirement has malformed extras".to_string());
        }
        cursor += 1;
        while cursor < bytes.len() && bytes[cursor].is_ascii_whitespace() {
            cursor += 1;
        }
    }
    Ok(&spec[cursor..])
}

fn is_vcs_target(lower: &str) -> bool {
    ["git+", "hg+", "svn+", "bzr+"]
        .iter()
        .any(|prefix| lower.starts_with(prefix))
}

/// A PEP 508 marker follows a direct URL after whitespace and `;`. Semicolons
/// within a URL path remain part of the URL because they are not preceded by
/// whitespace.
fn strip_pep508_marker(target: &str) -> &str {
    target
        .char_indices()
        .find_map(|(index, character)| {
            if character != ';' {
                return None;
            }
            target[..index]
                .chars()
                .next_back()
                .filter(|c| c.is_ascii_whitespace())
                .map(|_| target[..index].trim_end())
        })
        .unwrap_or(target)
}

/// Whether `spec` denotes a local path rather than a named distribution.
fn is_local_path_requirement(spec: &str) -> bool {
    let lower = spec.to_ascii_lowercase();
    if lower.starts_with("file:") {
        return true;
    }
    // Explicit relative / absolute prefixes.
    if spec.starts_with("./")
        || spec.starts_with("../")
        || spec.starts_with(".\\")
        || spec.starts_with("..\\")
        || spec == "."
        || spec == ".."
        || spec.starts_with('/')
        || spec.starts_with('~')
    {
        return true;
    }
    // Windows drive-absolute (`C:\...` / `C:/...`). A bare distribution name
    // never contains a backslash or a drive colon.
    if spec.contains('\\') {
        return true;
    }
    let bytes = spec.as_bytes();
    if bytes.len() >= 2 && bytes[0].is_ascii_alphabetic() && bytes[1] == b':' {
        // `C:` drive prefix. (A PEP 508 name cannot contain a colon, so any
        // colon here is suspicious; the drive form is the concrete local case.)
        return true;
    }
    // Packaging-tool extensions for bare archives are local even though strict
    // PEP 508 would require a `file:` URL. Keep this lexical so validation is
    // effect-free and cannot probe attacker-chosen filesystem names.
    if [".whl", ".tar.gz", ".zip", ".tar.bz2", ".tgz"]
        .iter()
        .any(|suffix| lower.ends_with(suffix))
    {
        return true;
    }
    false
}

/// Validate and canonicalize an index URL. DNS and address checks intentionally
/// do not happen here: the resolver broker performs them on the exact socket
/// destination immediately before connect, which closes validation/connect DNS
/// rebinding and applies equally to redirects and artifact links.
pub fn validate_index_url(url: &str) -> Result<(), ResolverError> {
    parse_network_url(url)
        .map(|_| ())
        .map_err(|reason| ResolverError::RejectedIndexUrl {
            url: url.to_string(),
            reason,
        })
}

fn parse_network_url(raw: &str) -> Result<url::Url, String> {
    let mut parsed = url::Url::parse(raw).map_err(|e| format!("invalid URL: {e}"))?;
    if parsed.scheme() != "https" {
        return Err("resolver destinations must use HTTPS".to_string());
    }
    let Some(host) = parsed.host().map(|host| host.to_owned()) else {
        return Err("resolver destination must have a host and port".to_string());
    };
    let Some(port) = parsed.port_or_known_default() else {
        return Err("resolver destination must have a host and port".to_string());
    };
    match host {
        url::Host::Domain(domain) => {
            let domain = domain.trim_end_matches('.').to_ascii_lowercase();
            if domain == "localhost" || domain.ends_with(".localhost") {
                return Err("resolver destination is local-only".to_string());
            }
            parsed
                .set_host(Some(&domain))
                .map_err(|_| "resolver destination host could not be canonicalized".to_string())?;
        }
        url::Host::Ipv4(address) => {
            let address = std::net::SocketAddr::new(address.into(), port);
            if !crate::url_validate::is_public_addr(&address) {
                return Err("resolver destination is not globally reachable".to_string());
            }
        }
        url::Host::Ipv6(address) => {
            let socket = std::net::SocketAddr::new(address.into(), port);
            if !crate::url_validate::is_public_addr(&socket) {
                return Err("resolver destination is not globally reachable".to_string());
            }
        }
    }
    if !parsed.username().is_empty() || parsed.password().is_some() {
        return Err("resolver URL carries embedded credentials".to_string());
    }
    Ok(parsed)
}

fn parse_vcs_url(raw: &str) -> Result<url::Url, String> {
    let (_, network_url) = raw
        .split_once('+')
        .ok_or_else(|| "VCS reference has no transport".to_string())?;
    parse_network_url(network_url)
}

#[cfg(windows)]
fn windows_directory_from_os(getter: unsafe fn(Option<&mut [u16]>) -> u32) -> Option<PathBuf> {
    use std::os::windows::ffi::OsStringExt as _;

    // Windows directory paths are bounded well below the extended-path maximum;
    // use one fixed buffer and fail closed if the API reports truncation.
    let mut buffer = vec![0_u16; 32 * 1024];
    // SAFETY: the Win32 getter writes at most the supplied slice length and
    // returns the number of UTF-16 code units excluding the terminating NUL.
    let length = unsafe { getter(Some(&mut buffer)) } as usize;
    if length == 0 || length >= buffer.len() {
        return None;
    }
    Some(PathBuf::from(std::ffi::OsString::from_wide(
        &buffer[..length],
    )))
}

#[cfg(windows)]
fn trusted_windows_directories() -> Option<(PathBuf, PathBuf)> {
    use windows::Win32::System::SystemInformation::{GetSystemDirectoryW, GetWindowsDirectoryW};

    let windows = windows_directory_from_os(GetWindowsDirectoryW)?;
    let system = windows_directory_from_os(GetSystemDirectoryW)?;
    Some((windows, system))
}

/// Build the scrubbed environment for a resolver child. Returns the
/// `(key, value)` pairs to set after `env_clear`, given a `config_home` (an
/// empty temp dir the child should treat as its only config root) and the
/// resolved `python` path. The child inherits NOTHING from the parent
/// environment except what this returns, so a planted `PIP_INDEX_URL`,
/// `UV_INDEX`, `pip.conf`, `uv.toml`, or `.netrc` cannot influence the resolve.
///
/// Concretely it: points `HOME` / `XDG_CONFIG_HOME` / `XDG_DATA_HOME` /
/// `XDG_CACHE_HOME` / `APPDATA` / `USERPROFILE` at `config_home` (so a discovered
/// `~/.config/pip/pip.conf` or `~/.netrc` is the empty temp dir's, i.e. absent),
/// and pins every standard temporary-directory variable to the same private
/// absolute directory;
/// sets `PIP_ISOLATED=1`, `PIP_NO_INPUT=1`, `PIP_DISABLE_PIP_VERSION_CHECK=1`,
/// `PIP_CONFIG_FILE` to an absent file, `UV_NO_CONFIG=1`,
/// `UV_PYTHON_DOWNLOADS=never`, `UV_NO_PROGRESS=1`; and carries a minimal `PATH`
/// plus a deterministic `LC_ALL=C` / `LANG=C`. It does **not** carry any `*_TOKEN`
/// / `*_API_KEY` / `PIP_*` / `UV_*` / `NETRC` from the parent.
pub fn isolated_env(config_home: &Path, python: &Path) -> Vec<(String, String)> {
    let home = config_home.display().to_string();
    // pip treats the platform null device as an explicit request to load no
    // configuration files, including system/global configuration. An absent
    // custom file is insufficient because pip may still merge global pip.conf.
    #[cfg(windows)]
    let disabled_pip_conf = "nul".to_string();
    #[cfg(not(windows))]
    let disabled_pip_conf = "/dev/null".to_string();
    #[cfg(windows)]
    let windows_directories = trusted_windows_directories();
    // A minimal PATH so the child can still find shared libraries' helpers if it
    // must, but containing only the resolved python's own directory plus the
    // standard system bins. We do NOT forward the parent PATH wholesale.
    let mut path_dirs: Vec<String> = Vec::new();
    if let Some(py_dir) = python.parent() {
        path_dirs.push(py_dir.display().to_string());
    }
    #[cfg(windows)]
    {
        if let Some((windows, system)) = &windows_directories {
            path_dirs.push(system.display().to_string());
            path_dirs.push(windows.display().to_string());
        }
    }
    #[cfg(not(windows))]
    {
        for d in ["/usr/bin", "/bin", "/usr/sbin", "/sbin"] {
            path_dirs.push(d.to_string());
        }
    }
    let path_sep = if cfg!(windows) { ";" } else { ":" };
    let path_value = path_dirs.join(path_sep);

    // `mut` is used only by the Windows-gated push below; on other targets the
    // vec is complete after the literal, so silence the unused-mut lint there.
    #[cfg_attr(not(windows), allow(unused_mut))]
    let mut env: Vec<(String, String)> = vec![
        ("HOME".to_string(), home.clone()),
        ("XDG_CONFIG_HOME".to_string(), home.clone()),
        ("XDG_DATA_HOME".to_string(), home.clone()),
        ("XDG_CACHE_HOME".to_string(), home.clone()),
        ("XDG_STATE_HOME".to_string(), home.clone()),
        // Windows config roots.
        ("APPDATA".to_string(), home.clone()),
        ("LOCALAPPDATA".to_string(), home.clone()),
        ("USERPROFILE".to_string(), home.clone()),
        // Do not let Python/pip fall back to a shared system temp directory or,
        // on Windows, the executable directory selected as the safe DLL cwd.
        ("TEMP".to_string(), home.clone()),
        ("TMP".to_string(), home.clone()),
        ("TMPDIR".to_string(), home.clone()),
        // pip isolation.
        ("PIP_ISOLATED".to_string(), "1".to_string()),
        ("PIP_NO_INPUT".to_string(), "1".to_string()),
        ("PIP_DISABLE_PIP_VERSION_CHECK".to_string(), "1".to_string()),
        ("PIP_CONFIG_FILE".to_string(), disabled_pip_conf),
        ("PIP_NO_CACHE_DIR".to_string(), "1".to_string()),
        // uv isolation.
        ("UV_NO_CONFIG".to_string(), "1".to_string()),
        ("UV_PYTHON_DOWNLOADS".to_string(), "never".to_string()),
        ("UV_NO_PROGRESS".to_string(), "1".to_string()),
        // Deterministic, non-interactive.
        ("LC_ALL".to_string(), "C".to_string()),
        ("LANG".to_string(), "C".to_string()),
        ("PATH".to_string(), path_value),
    ];
    // Keep authentic system-root variables on Windows so DLL resolution works
    // even though we scrubbed the rest of the environment. Never copy the
    // forgeable ambient SystemRoot/windir values.
    #[cfg(windows)]
    {
        if let Some((windows, _)) = &windows_directories {
            let windows = windows.display().to_string();
            env.push(("SystemRoot".to_string(), windows.clone()));
            env.push(("windir".to_string(), windows));
        }
    }
    env
}

/// Add the enforcing broker as every standard proxy spelling. These values are
/// generated inside Tirith after input validation; ambient proxy and NO_PROXY
/// values were discarded by [`isolated_env`]. Empty NO_PROXY prevents a host
/// alias or inherited bypass from routing around the broker.
fn isolated_env_with_proxy(
    config_home: &Path,
    python: &Path,
    proxy_url: &str,
) -> Vec<(String, String)> {
    let mut env = isolated_env(config_home, python);
    for key in [
        "HTTP_PROXY",
        "HTTPS_PROXY",
        "ALL_PROXY",
        "http_proxy",
        "https_proxy",
        "all_proxy",
    ] {
        env.push((key.to_string(), proxy_url.to_string()));
    }
    env.push(("NO_PROXY".to_string(), String::new()));
    env.push(("no_proxy".to_string(), String::new()));
    env
}

/// Build the `uv pip compile` argument vector for `requirements_in` ->
/// `locked_out`, given the request. The flags are exactly the plan's pin:
/// `--generate-hashes` (hash-pinned lock) `--no-build` (never build a backend) +
/// `--no-annotate` for a clean lock, `--no-python-downloads`, `--no-config`,
/// and either `--no-index` (no indexes supplied) or the approved `--index-url` /
/// `--extra-index-url` set. `--python <path>` pins the interpreter so uv targets
/// the exact tool we resolved.
fn uv_compile_args(
    requirements_in: &Path,
    locked_out: &Path,
    python: &Path,
    index_urls: &[String],
    allowances: &ResolverAllowances,
) -> Vec<String> {
    let mut args: Vec<String> = vec![
        "pip".to_string(),
        "compile".to_string(),
        "--generate-hashes".to_string(),
        "--no-annotate".to_string(),
        "--no-header".to_string(),
        "--no-config".to_string(),
        // Boolean flag: uv must never fetch an interpreter off the network. The
        // `UV_PYTHON_DOWNLOADS=never` env var in `isolated_env` reinforces this.
        "--no-python-downloads".to_string(),
        "--python".to_string(),
        python.display().to_string(),
    ];
    if !allowances.allow_sdist {
        // Binary-only resolution: `--no-build` forbids building any source
        // distribution, so uv resolves only to pre-built wheels. uv rejects
        // `--no-build` together with `--only-binary`, so `--only-binary :all:`
        // lives on the `pip download` step alone (where it is the right flag);
        // here `--no-build` is the binary-only knob.
        args.push("--no-build".to_string());
    }
    push_index_args(&mut args, index_urls);
    args.push("--output-file".to_string());
    args.push(locked_out.display().to_string());
    args.push(requirements_in.display().to_string());
    args
}

/// Build the `python -m pip download` argument vector for `locked` -> `dest_dir`.
/// Flags are the plan's pin: `--only-binary :all:` (wheels only, the right flag
/// on the pip side) `--require-hashes` (refuse anything not pinned in the lock),
/// plus `--no-deps` because the lock is already transitively complete,
/// `--isolated`, `--no-cache-dir`, and the approved indexes (or `--no-index`).
fn pip_download_args(
    locked: &Path,
    dest_dir: &Path,
    index_urls: &[String],
    proxy_url: &str,
) -> Vec<String> {
    let mut args: Vec<String> = vec![
        "-I".to_string(),
        "-m".to_string(),
        "pip".to_string(),
        "download".to_string(),
        "--only-binary".to_string(),
        ":all:".to_string(),
        "--require-hashes".to_string(),
        "--no-deps".to_string(),
        "--isolated".to_string(),
        "--no-cache-dir".to_string(),
        "--disable-pip-version-check".to_string(),
        // Standard proxy env is set for both tools; pip also gets an explicit
        // highest-precedence option so no global/config setting can replace it.
        "--proxy".to_string(),
        proxy_url.to_string(),
        "--dest".to_string(),
        dest_dir.display().to_string(),
    ];
    push_index_args(&mut args, index_urls);
    args.push("-r".to_string());
    args.push(locked.display().to_string());
    args
}

/// Append index arguments shared by the compile and download steps: `--no-index`
/// when none are approved, else `--index-url <first>` and
/// `--extra-index-url <rest>`. The first approved URL is the primary index; the
/// default PyPI index is never added implicitly.
fn push_index_args(args: &mut Vec<String>, index_urls: &[String]) {
    if index_urls.is_empty() {
        args.push("--no-index".to_string());
        return;
    }
    let mut it = index_urls.iter();
    if let Some(first) = it.next() {
        args.push("--index-url".to_string());
        args.push(first.clone());
    }
    for extra in it {
        args.push("--extra-index-url".to_string());
        args.push(extra.clone());
    }
}

/// Verify a `uv pip compile --generate-hashes` lock is fully hash-pinned: every
/// non-comment, non-option requirement line is followed by at least one
/// `--hash=sha256:<64hex>` continuation. Returns the number of pinned
/// requirements (>= 1 on success). This is belt-and-braces over pip's own
/// `--require-hashes`: we refuse to even start the download if the lock is not
/// fully pinned, so a malformed or partial lock never reaches the network.
pub fn verify_lock_hash_pinned(lock: &str) -> Result<usize, ResolverError> {
    let mut pinned = 0usize;
    let mut current_has_hash = false;
    let mut current_is_req = false;
    let mut saw_any_req = false;

    let flush = |pinned: &mut usize, is_req: bool, has_hash: bool| -> Result<(), ResolverError> {
        if is_req {
            if has_hash {
                *pinned += 1;
                Ok(())
            } else {
                Err(ResolverError::LockNotHashPinned(
                    "a requirement in the lock has no sha256 hash".to_string(),
                ))
            }
        } else {
            Ok(())
        }
    };

    for raw in lock.lines() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if line.starts_with("--hash") || line.starts_with("--hash=") {
            if is_sha256_hash_line(line) {
                current_has_hash = true;
            }
            continue;
        }
        // A bare `--hash` may also appear after a trailing backslash on the
        // requirement line; treat any line that is purely a continuation hash as
        // above. Other option lines (e.g. `--index-url`) are skipped.
        if line.starts_with("--") {
            continue;
        }
        // A new requirement line: flush the previous one's state.
        flush(&mut pinned, current_is_req, current_has_hash)?;
        // Strip an inline trailing ` \` continuation and an inline `--hash` that
        // some lock formats place on the same line.
        current_is_req = true;
        current_has_hash = line.contains("--hash=sha256:") && line_inline_hash_ok(line);
        saw_any_req = true;
    }
    flush(&mut pinned, current_is_req, current_has_hash)?;

    if !saw_any_req || pinned == 0 {
        return Err(ResolverError::LockNotHashPinned(
            "the lock pinned no requirements".to_string(),
        ));
    }
    Ok(pinned)
}

/// Whether a `--hash=...` continuation line names a sha256 with a 64-hex digest.
fn is_sha256_hash_line(line: &str) -> bool {
    // Accept `--hash sha256:<hex>` and `--hash=sha256:<hex>`.
    let rest = line
        .strip_prefix("--hash=")
        .or_else(|| line.strip_prefix("--hash"))
        .map(|s| s.trim_start())
        .unwrap_or(line);
    let rest = rest.trim();
    let Some(hex) = rest.strip_prefix("sha256:") else {
        return false;
    };
    let hex = hex.split_whitespace().next().unwrap_or("");
    hex.len() == 64 && hex.bytes().all(|b| b.is_ascii_hexdigit())
}

/// Whether an inline `--hash=sha256:` on a requirement line names a valid digest.
fn line_inline_hash_ok(line: &str) -> bool {
    if let Some(idx) = line.find("--hash=sha256:") {
        let after = &line[idx + "--hash=sha256:".len()..];
        let hex = after.split_whitespace().next().unwrap_or("");
        let hex = hex.trim_end_matches('\\');
        return hex.len() == 64 && hex.bytes().all(|b| b.is_ascii_hexdigit());
    }
    false
}

/// Run a resolver child with a wall-clock deadline, returning its exit status and
/// captured stdout+stderr (merged for diagnostics). The program is an absolute
/// path; `args` are passed as an array (no shell). The child's environment and
/// cwd are configured through a [`ChildSpec`] with the broker-only environment.
fn run_child_capped(
    program: &TrustedExecutable,
    args: &[String],
    config_home: &Path,
    python: &TrustedExecutable,
    proxy_url: &str,
    timeout: Duration,
) -> Result<ChildOutput, ResolverError> {
    let mut spec = ChildSpec::new(
        args,
        ChildLimits::new(
            timeout,
            RESOLVER_CHILD_OUTPUT_MAX,
            RESOLVER_CHILD_OUTPUT_MAX,
        ),
    );
    // The Windows trusted-child launcher deliberately fixes the working
    // directory to the executable's validated parent. Windows searches cwd
    // while loading DLLs, so passing the writable resolver config directory
    // there would undo the executable provenance boundary.
    #[cfg(not(windows))]
    {
        spec = spec.cwd(config_home);
    }
    for (key, value) in isolated_env_with_proxy(config_home, python.path(), proxy_url) {
        spec = spec.env(key, value);
    }
    #[cfg(target_os = "linux")]
    {
        let python_fd = python
            .bound_launch_fd()
            .ok_or_else(|| resolver_io_error("resolver Python has no sealed launch capability"))?;
        // uv receives `/proc/self/fd/N`, never `/proc/<parent>/fd/N`: opening a
        // parent's procfs fd is ptrace-policy gated and commonly denied by Yama or
        // hidepid. Explicit inheritance makes N name this exact sealed file in uv.
        spec = spec.inherit_fd(python_fd);
    }
    // `uv` consumes this interpreter path through `--python` before Python is
    // itself the pip-stage program. Bind its identity at the uv boundary too;
    // validating only `program` would leave an auxiliary-executable swap gap.
    python.revalidate().map_err(|error| {
        resolver_io_error(format!(
            "resolver Python identity changed before {} spawn: {error}",
            program.path().display()
        ))
    })?;
    match crate::trusted_child::run(program, &spec) {
        ChildOutcome::Completed {
            status,
            stdout,
            stderr,
        } => Ok(ChildOutput {
            success: status.success(),
            stdout,
            stderr,
        }),
        ChildOutcome::Timeout { .. } => Err(ResolverError::Timeout(format!(
            "{} exceeded {}s",
            program.path().display(),
            timeout.as_secs()
        ))),
        ChildOutcome::OutputLimitExceeded { stream, .. } => Err(resolver_io_error(format!(
            "{} exceeded the {:?} capture limit",
            program.path().display(),
            stream
        ))),
        ChildOutcome::SpawnError(reason)
        | ChildOutcome::WaitError(reason)
        | ChildOutcome::CleanupError(reason) => Err(resolver_io_error(format!(
            "{}: {reason}",
            program.path().display()
        ))),
    }
}

/// Captured output of a resolver child.
#[derive(Debug)]
struct ChildOutput {
    success: bool,
    stdout: Vec<u8>,
    stderr: Vec<u8>,
}

impl ChildOutput {
    /// Merge stdout+stderr into one bounded, terminal-safe physical line.
    ///
    /// Resolver tools process registry-controlled text, so their diagnostics are
    /// hostile even though the executable itself is trusted. Strip terminal and
    /// deceptive-Unicode controls before the value enters `ResolverError`, then
    /// collapse line boundaries so the CLI's eventual `eprintln!` cannot be made
    /// to forge a second Tirith row. The raw buffers remain available on this
    /// private value and are never interpolated into human output directly.
    fn diagnostics(&self) -> String {
        let mut raw = String::new();
        raw.push_str(&String::from_utf8_lossy(&self.stdout));
        if !self.stderr.is_empty() {
            raw.push('\n');
            raw.push_str(&String::from_utf8_lossy(&self.stderr));
        }
        let cleaned = crate::mcp::output_filter::sanitize_for_display(raw.trim());
        let single_line = cleaned
            .split(['\n', '\r'])
            .map(str::trim)
            .filter(|line| !line.is_empty())
            .collect::<Vec<_>>()
            .join(" | ");
        crate::util::truncate_bytes(&single_line, RESOLVER_DIAGNOSTIC_MAX_BYTES)
    }
}

struct ValidatedResolverInputs {
    canonical_index_urls: Vec<String>,
    permitted_urls: Vec<url::Url>,
}

/// Validate the complete request without starting a process, binding a socket,
/// resolving DNS, or writing resolver files. The returned canonical URLs drive
/// both argv and the broker allow-set, so validation and enforcement cannot
/// disagree about aliases, case, or default ports.
fn validate_resolver_inputs(
    request: &ResolverRequest,
    artifact_origins: &[String],
) -> Result<ValidatedResolverInputs, ResolverError> {
    if request.requirements.len() > MAX_REQUIREMENTS {
        return Err(ResolverError::TooManyInputs(format!(
            "{} requirements exceeds the {MAX_REQUIREMENTS} cap",
            request.requirements.len()
        )));
    }
    if request.index_urls.len() > MAX_INDEX_URLS {
        return Err(ResolverError::TooManyInputs(format!(
            "{} index URLs exceeds the {MAX_INDEX_URLS} cap",
            request.index_urls.len()
        )));
    }
    if artifact_origins.len() > MAX_INDEX_URLS {
        return Err(ResolverError::TooManyInputs(format!(
            "{} artifact origins exceeds the {MAX_INDEX_URLS} cap",
            artifact_origins.len()
        )));
    }
    let mut permitted_urls = Vec::new();
    for spec in &request.requirements {
        validate_requirement(spec, &request.allowances)?;
        if let Some(url) = permitted_requirement_url(spec, &request.allowances)? {
            permitted_urls.push(url);
        }
    }

    let mut canonical_index_urls = Vec::with_capacity(request.index_urls.len());
    for raw in &request.index_urls {
        let parsed = parse_network_url(raw).map_err(|reason| ResolverError::RejectedIndexUrl {
            url: raw.clone(),
            reason,
        })?;
        canonical_index_urls.push(parsed.as_str().to_string());
        permitted_urls.push(parsed);
    }
    // Custom artifact origins are broker policy only: they never become index
    // argv, so approving a CDN cannot make it a dependency source.
    for raw in artifact_origins {
        let parsed = parse_network_url(raw).map_err(|reason| ResolverError::RejectedIndexUrl {
            url: raw.clone(),
            reason: format!("artifact origin rejected: {reason}"),
        })?;
        permitted_urls.push(parsed);
    }
    Ok(ValidatedResolverInputs {
        canonical_index_urls,
        permitted_urls,
    })
}

/// Validate a resolver request without discovering tools, opening quarantine,
/// binding sockets, resolving DNS, spawning children, or probing local paths.
pub fn validate_resolver_request(request: &ResolverRequest) -> Result<(), ResolverError> {
    validate_resolver_inputs(request, &[]).map(|_| ())
}

/// Validate a resolver request plus explicit artifact/CDN origins. Artifact
/// origins authorize broker CONNECT destinations only and are never forwarded
/// to uv or pip as indexes.
pub fn validate_resolver_request_with_artifact_origins(
    request: &ResolverRequest,
    artifact_origins: &[String],
) -> Result<(), ResolverError> {
    validate_resolver_inputs(request, artifact_origins).map(|_| ())
}

/// Resolver executables after installation-provenance validation and digest
/// binding. Linux additionally binds each executable to immutable sealed bytes;
/// other Unix hosts admit only root-managed, non-writable executable/runtime
/// trees and re-attest their path identities and digests before every child.
/// The same value must outlive resolve and installation.
#[derive(Debug, Clone)]
pub struct BoundResolverTools {
    uv: TrustedExecutable,
    python: TrustedExecutable,
    uv_sha256: String,
    python_sha256: String,
    uv_version: String,
    pip_version: String,
    pip_tree: PipTreeBinding,
}

/// Versioned, bounded attestation over the exact root-managed pip package and
/// matching dist-info trees that `python -I -m pip` will import.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PipTreeBinding {
    root: PathBuf,
    metadata_root: PathBuf,
    sha256: String,
    files: u64,
    bytes: u64,
}

pub const PIP_TREE_BINDING_VERSION: u32 = 1;
pub const PIP_TREE_MAX_FILES: u64 = 20_000;
pub const PIP_TREE_MAX_BYTES: u64 = 256 * 1024 * 1024;

#[cfg(target_os = "linux")]
fn authorize_uv_for_enforcing_resolution(
    uv: TrustedExecutable,
) -> Result<TrustedExecutable, ResolverError> {
    if uv.has_system_helper_provenance() {
        return Ok(uv);
    }
    if !resolver_tool_pin_matches(uv.path()).map_err(resolver_io_error)? {
        return Err(ResolverError::ToolUntrusted {
            tool: uv.path().display().to_string(),
            reason: "uv is neither root-managed nor covered by an explicit enrollment pin"
                .to_string(),
        });
    }
    validate_static_linux_uv(uv.path()).map_err(|reason| ResolverError::ToolUntrusted {
        tool: uv.path().display().to_string(),
        reason,
    })?;
    Ok(uv)
}

#[cfg(all(unix, not(target_os = "linux")))]
fn authorize_uv_for_enforcing_resolution(
    uv: TrustedExecutable,
) -> Result<TrustedExecutable, ResolverError> {
    let tool = uv.path().display().to_string();
    uv.require_system_helper_provenance()
        .map_err(|error| ResolverError::ToolUntrusted {
            tool,
            reason: format!(
                "enforcing resolution requires root-managed uv on this Unix platform: {error}"
            ),
        })
}

impl BoundResolverTools {
    pub fn bind(tools: &ResolverTools) -> Result<Self, ResolverError> {
        #[cfg(not(unix))]
        {
            let _ = tools;
            return Err(ResolverError::ToolUntrusted {
                tool: "package resolver toolchain".to_string(),
                reason: "enforcing package resolution requires a platform with a verified immutable-or-root-managed executable and Python/pip dependency-tree binding"
                    .to_string(),
            });
        }

        #[cfg(unix)]
        {
            // Public fields are compatibility surface, not an alternate trust
            // channel. Reconstruct trusted handles, apply the same installation
            // provenance policy as PATH discovery, then carry a discovery digest
            // forward when one exists.
            let denied_roots = crate::trusted_child::ambient_denied_roots();
            let uv =
                TrustedExecutable::from_absolute(&tools.uv, &denied_roots).map_err(|error| {
                    ResolverError::ToolUntrusted {
                        tool: tools.uv.display().to_string(),
                        reason: error.to_string(),
                    }
                })?;
            validate_resolver_tool_provenance("uv", &uv).map_err(|reason| {
                ResolverError::ToolUntrusted {
                    tool: tools.uv.display().to_string(),
                    reason,
                }
            })?;
            revalidate_discovered_tool(&uv).map_err(|reason| ResolverError::ToolUntrusted {
                tool: tools.uv.display().to_string(),
                reason,
            })?;
            let uv = authorize_uv_for_enforcing_resolution(uv)?;
            let python = TrustedExecutable::from_absolute(&tools.python, &denied_roots).map_err(
                |error| ResolverError::ToolUntrusted {
                    tool: tools.python.display().to_string(),
                    reason: error.to_string(),
                },
            )?;
            validate_resolver_tool_provenance("python", &python).map_err(|reason| {
                ResolverError::ToolUntrusted {
                    tool: tools.python.display().to_string(),
                    reason,
                }
            })?;
            revalidate_discovered_tool(&python).map_err(|reason| ResolverError::ToolUntrusted {
                tool: tools.python.display().to_string(),
                reason,
            })?;
            let python = python
            .require_system_helper_provenance()
            .map_err(|error| ResolverError::ToolUntrusted {
                tool: tools.python.display().to_string(),
                reason: format!(
                    "enforcing resolution refuses user-writable/enrollment-only Python dependency origins: {error}"
                ),
            })?;

            // Check the conventional install prefix before executing even a constant
            // no-site Python probe. A sealed ELF is not sufficient when a same-user
            // process can replace its loader, stdlib, or adjacent sitecustomize.
            let python_prefix = python
                .path()
                .parent()
                .and_then(Path::parent)
                .map(Path::to_path_buf)
                .ok_or_else(|| ResolverError::ToolUntrusted {
                    tool: tools.python.display().to_string(),
                    reason: "Python executable has no stable installation prefix".to_string(),
                })?;
            if !resolver_root_managed_path_chain_is_secure(&python_prefix) {
                return Err(ResolverError::ToolUntrusted {
                    tool: tools.python.display().to_string(),
                    reason: format!(
                        "Python installation prefix {} is not root-managed and non-writable",
                        python_prefix.display()
                    ),
                });
            }
            let python_version = python_version_from_executable(python.path()).ok_or(
                ResolverError::ToolUntrusted {
                    tool: tools.python.display().to_string(),
                    reason: "canonical Python executable name does not bind an exact major.minor runtime (expected pythonX.Y)"
                        .to_string(),
                },
            )?;
            let expected_stdlib = python_prefix
                .join("lib")
                .join(format!("python{python_version}"))
                .canonicalize()
                .map_err(|error| ResolverError::ToolUntrusted {
                    tool: tools.python.display().to_string(),
                    reason: format!(
                        "cannot resolve conventional Python stdlib before execution: {error}"
                    ),
                })?;
            // This type-state token can only be constructed after validating the
            // complete conventional runtime tree. CPython loads encodings/codecs
            // before evaluating `-c`, even under `-I -S`, so every Python probe
            // below requires the token rather than a bare path.
            let validated_runtime =
                ValidatedPythonRuntime::validate(python_prefix, python_version, expected_stdlib)?;

            // Linux can close the final validation-to-exec pathname race with a
            // sealed anonymous descriptor. Other Unix hosts retain the already
            // validated canonical path, but only after the complete executable,
            // runtime, and pip hierarchies have proven root-managed and therefore
            // immutable to the invoking (unprivileged) user.
            #[cfg(target_os = "linux")]
            let uv = uv
                .bind_content()
                .map_err(|error| ResolverError::ToolUntrusted {
                    tool: tools.uv.display().to_string(),
                    reason: format!(
                        "could not content-bind resolver before network access: {error}"
                    ),
                })?;
            #[cfg(target_os = "linux")]
            let python = python
                .bind_content()
                .map_err(|error| ResolverError::ToolUntrusted {
                    tool: tools.python.display().to_string(),
                    reason: format!(
                        "could not content-bind interpreter before network access: {error}"
                    ),
                })?;

            let uv_sha256 = resolver_tool_digest(uv.launch_path()).map_err(|reason| {
                ResolverError::ToolUntrusted {
                    tool: uv.path().display().to_string(),
                    reason,
                }
            })?;
            let python_sha256 = resolver_tool_digest(python.launch_path()).map_err(|reason| {
                ResolverError::ToolUntrusted {
                    tool: python.path().display().to_string(),
                    reason,
                }
            })?;

            let uv_version = capture_bound_tool_version(&uv, ["--version"], "uv")?;
            let runtime = attest_python_runtime_and_pip(&python, &validated_runtime)?;

            Ok(Self {
                uv,
                python,
                uv_sha256,
                python_sha256,
                uv_version,
                pip_version: runtime.0,
                pip_tree: runtime.1,
            })
        }
    }

    pub fn uv(&self) -> &TrustedExecutable {
        &self.uv
    }

    pub fn python(&self) -> &TrustedExecutable {
        &self.python
    }

    pub fn uv_sha256(&self) -> &str {
        &self.uv_sha256
    }

    pub fn python_sha256(&self) -> &str {
        &self.python_sha256
    }

    pub fn uv_version(&self) -> &str {
        &self.uv_version
    }

    pub fn pip_version(&self) -> &str {
        &self.pip_version
    }

    pub fn pip_tree(&self) -> &PipTreeBinding {
        &self.pip_tree
    }

    /// Revalidate every retained executable digest and the bounded root-managed
    /// pip tree immediately before uv or pip execution.
    pub fn revalidate_install_authority(&self) -> Result<(), ResolverError> {
        #[cfg(not(unix))]
        {
            let _ = self;
            return Err(ResolverError::ToolUntrusted {
                tool: "package resolver toolchain".to_string(),
                reason: "enforcing package execution authority is unavailable on this platform"
                    .to_string(),
            });
        }

        #[cfg(unix)]
        {
            self.uv
                .revalidate()
                .map_err(|error| resolver_io_error(format!("bound uv changed: {error}")))?;
            self.python
                .revalidate()
                .map_err(|error| resolver_io_error(format!("bound Python changed: {error}")))?;
            revalidate_bound_tool_digest(&self.uv, &self.uv_sha256, "uv")?;
            revalidate_bound_tool_digest(&self.python, &self.python_sha256, "Python")?;
            let current = attest_pip_trees(&self.pip_tree.root, &self.pip_tree.metadata_root)?;
            if current != self.pip_tree {
                return Err(resolver_io_error(
                    "root-managed pip package or metadata tree changed after approval binding",
                ));
            }
            Ok(())
        }
    }

    /// A procfs capability path that names the exact sealed interpreter fd inherited
    /// by uv. [`run_child_capped`] clears CLOEXEC for the same fd in the uv child;
    /// no cross-process procfs dereference or mutable source path is involved.
    #[cfg(target_os = "linux")]
    fn python_capability_path(&self) -> Result<PathBuf, ResolverError> {
        let fd = self
            .python
            .bound_launch_fd()
            .ok_or_else(|| resolver_io_error("bound Python has no sealed launch descriptor"))?;
        Ok(self_fd_capability_path(fd))
    }
}

#[cfg(unix)]
fn revalidate_bound_tool_digest(
    executable: &TrustedExecutable,
    expected: &str,
    label: &str,
) -> Result<(), ResolverError> {
    let current = resolver_tool_digest(executable.launch_path()).map_err(resolver_io_error)?;
    if !constant_time_hex_eq(expected.as_bytes(), current.as_bytes()) {
        return Err(resolver_io_error(format!(
            "bound {label} content changed after approval binding"
        )));
    }
    executable.revalidate().map_err(|error| {
        resolver_io_error(format!(
            "bound {label} identity changed while revalidating content: {error}"
        ))
    })
}

/// Resolver dependency trees need the same root-managed guarantee as the
/// executable itself. Keep this local rather than weakening the general
/// trusted-child API: every component must be root-owned, non-group/world
/// writable, and free of mutating extended ACLs.
#[cfg(unix)]
fn resolver_component_is_root_managed(component: &Path) -> bool {
    use std::os::unix::fs::MetadataExt as _;

    let Ok(metadata) = std::fs::metadata(component) else {
        return false;
    };
    metadata.uid() == 0
        && metadata.mode() & 0o022 == 0
        && crate::trusted_child::reject_unix_extended_acl(component, metadata.is_dir()).is_ok()
}

/// Directories already proven root-managed and non-writable during ONE
/// validation pass.
///
/// The chain check costs a `stat` plus an extended-ACL read per component, and
/// the runtime walk runs it once per entry, so a CPython stdlib near
/// `PYTHON_RUNTIME_MAX_FILES` re-proved the same handful of directories
/// hundreds of thousands of times — repeated again on every
/// `revalidate_install_authority`. The security property is that each distinct
/// component is proven during the pass, which this preserves: it only skips
/// re-proving a directory this same pass already accepted. A caller that needs
/// a fresh proof starts a new `ProvenChain`.
#[cfg(unix)]
#[derive(Default)]
struct ProvenChain {
    proven: std::collections::BTreeSet<PathBuf>,
}

#[cfg(unix)]
impl ProvenChain {
    fn path_chain_is_secure(&mut self, path: &Path) -> bool {
        let mut pending: Vec<&Path> = Vec::new();
        for component in path.ancestors() {
            if self.proven.contains(component) {
                break;
            }
            pending.push(component);
        }
        // Root-downward, so a failure is reported at the outermost component
        // that broke rather than at the leaf.
        for component in pending.iter().rev() {
            if !resolver_component_is_root_managed(component) {
                return false;
            }
        }
        for component in pending {
            // Only directories are worth remembering: a leaf file never
            // reappears as another entry's ancestor.
            if component.is_dir() {
                self.proven.insert(component.to_path_buf());
            }
        }
        true
    }
}

#[cfg(unix)]
fn resolver_root_managed_path_chain_is_secure(path: &Path) -> bool {
    ProvenChain::default().path_chain_is_secure(path)
}

impl PipTreeBinding {
    pub fn root(&self) -> &Path {
        &self.root
    }

    pub fn sha256(&self) -> &str {
        &self.sha256
    }

    pub fn files(&self) -> u64 {
        self.files
    }

    pub fn bytes(&self) -> u64 {
        self.bytes
    }
}

#[cfg(unix)]
const PYTHON_RUNTIME_MAX_FILES: u64 = 100_000;
#[cfg(unix)]
const PYTHON_RUNTIME_MAX_BYTES: u64 = 2 * 1024 * 1024 * 1024;
pub const PIP_TREE_MAX_FILE_BYTES: u64 = 64 * 1024 * 1024;
pub const PIP_TREE_MAX_PATH_BYTES: u64 = 4096;

/// Proof that the conventional CPython prefix/version/stdlib tuple has passed a
/// complete bounded root-managed-tree validation before any Python process runs.
/// The private fields prevent callers outside this module from fabricating the
/// proof, and Python attestation accepts this token instead of unchecked paths.
#[cfg(unix)]
struct ValidatedPythonRuntime {
    prefix: PathBuf,
    version: String,
    stdlib: PathBuf,
}

#[cfg(unix)]
impl ValidatedPythonRuntime {
    fn validate(prefix: PathBuf, version: String, stdlib: PathBuf) -> Result<Self, ResolverError> {
        validate_root_managed_runtime_tree(&stdlib)?;
        Ok(Self {
            prefix,
            version,
            stdlib,
        })
    }
}

#[cfg(target_os = "linux")]
fn self_fd_capability_path(fd: std::os::fd::RawFd) -> PathBuf {
    PathBuf::from(format!("/proc/self/fd/{fd}"))
}

#[cfg(unix)]
fn python_version_from_executable(path: &Path) -> Option<String> {
    let name = path.file_name()?.to_str()?;
    let suffix = name.strip_prefix("python")?;
    let (major, minor) = suffix.split_once('.')?;
    if major.is_empty()
        || minor.is_empty()
        || !major.bytes().all(|byte| byte.is_ascii_digit())
        || !minor.bytes().all(|byte| byte.is_ascii_digit())
    {
        return None;
    }
    Some(format!("{major}.{minor}"))
}

/// Interpreter version string plus the pip-tree binding proven alongside it.
#[cfg(unix)]
type AttestPythonRuntimeResult = Result<(String, PipTreeBinding), ResolverError>;

/// Locate and attest pip without importing or executing pip. Only the built-in
/// `sys` module is used for the first `-I -S` probe. The returned stdlib is then
/// checked as a bounded root-managed tree before a second no-site probe imports
/// the now-proven system `site` module to enumerate system site roots.
#[cfg(unix)]
fn attest_python_runtime_and_pip(
    python: &TrustedExecutable,
    runtime: &ValidatedPythonRuntime,
) -> AttestPythonRuntimeResult {
    const RUNTIME_PROBE: &str =
        "import sys; print(sys.base_prefix); print(f'{sys.version_info[0]}.{sys.version_info[1]}')";
    let output =
        capture_bound_tool_version(python, ["-I", "-S", "-c", RUNTIME_PROBE], "Python runtime")?;
    let lines = output.lines().collect::<Vec<_>>();
    if lines.len() != 2 || lines.iter().any(|line| line.trim().is_empty()) {
        return Err(resolver_io_error(
            "Python no-site runtime probe returned an invalid base-prefix/version tuple",
        ));
    }
    let base_prefix = PathBuf::from(lines[0]);
    let base_prefix = base_prefix.canonicalize().map_err(|error| {
        resolver_io_error(format!(
            "cannot canonicalize Python base prefix {}: {error}",
            base_prefix.display()
        ))
    })?;
    if base_prefix != runtime.prefix
        || !python.path().starts_with(&base_prefix)
        || !resolver_root_managed_path_chain_is_secure(&base_prefix)
    {
        return Err(ResolverError::ToolUntrusted {
            tool: python.path().display().to_string(),
            reason: format!(
                "Python reported base prefix {} outside its root-managed executable origin",
                base_prefix.display()
            ),
        });
    }
    if lines[1] != runtime.version {
        return Err(resolver_io_error(format!(
            "Python runtime reported version {} but executable/stdlib binding selected {}",
            lines[1], runtime.version
        )));
    }
    let reported_stdlib = base_prefix
        .join("lib")
        .join(format!("python{}", lines[1]))
        .canonicalize()
        .map_err(ResolverError::Io)?;
    if reported_stdlib != runtime.stdlib {
        return Err(resolver_io_error(format!(
            "Python runtime selected stdlib {} instead of prevalidated {}",
            reported_stdlib.display(),
            runtime.stdlib.display()
        )));
    }

    const SITE_PROBE: &str = "import site; [print(path) for path in site.getsitepackages()]";
    let site_output =
        capture_bound_tool_version(python, ["-I", "-S", "-c", SITE_PROBE], "Python system-site")?;
    let mut site_roots = Vec::new();
    for raw in site_output.lines() {
        if raw.trim().is_empty() {
            continue;
        }
        let path = PathBuf::from(raw);
        let path = match path.canonicalize() {
            Ok(path) => path,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
            Err(error) => {
                return Err(resolver_io_error(format!(
                    "cannot canonicalize Python system-site root {}: {error}",
                    path.display()
                )))
            }
        };
        if !resolver_root_managed_path_chain_is_secure(&path) {
            return Err(ResolverError::ToolUntrusted {
                tool: python.path().display().to_string(),
                reason: format!(
                    "Python system-site root {} is not root-managed and non-writable",
                    path.display()
                ),
            });
        }
        validate_site_startup_controls(&path)?;
        if !site_roots.contains(&path) {
            site_roots.push(path);
        }
    }
    if site_roots.is_empty() {
        return Err(resolver_io_error(
            "Python reported no existing root-managed system-site directory containing pip",
        ));
    }

    let mut pip_roots = Vec::new();
    for site in &site_roots {
        let candidate = site.join("pip");
        match candidate.canonicalize() {
            Ok(candidate) if candidate.is_dir() => {
                if !resolver_root_managed_path_chain_is_secure(&candidate) {
                    return Err(ResolverError::ToolUntrusted {
                        tool: candidate.display().to_string(),
                        reason: "pip package tree is not root-managed and non-writable".to_string(),
                    });
                }
                if !pip_roots.contains(&candidate) {
                    pip_roots.push(candidate);
                }
            }
            Ok(_) => {
                return Err(resolver_io_error(format!(
                    "pip import root {} is not a directory",
                    candidate.display()
                )))
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(ResolverError::Io(error)),
        }
    }
    if pip_roots.len() != 1 {
        return Err(resolver_io_error(format!(
            "expected exactly one root-managed pip package tree, found {}",
            pip_roots.len()
        )));
    }
    let pip_root = pip_roots.pop().expect("length checked");
    let site_root = pip_root
        .parent()
        .ok_or_else(|| resolver_io_error("pip package tree has no site parent"))?;
    let metadata_root = locate_exact_pip_dist_info(site_root)?;
    let version = read_pip_metadata_version(&metadata_root)?;
    let binding = attest_pip_trees(&pip_root, &metadata_root)?;
    Ok((version, binding))
}

#[cfg(unix)]
fn validate_root_managed_runtime_tree(root: &Path) -> Result<(), ResolverError> {
    let mut files = 0_u64;
    let mut bytes = 0_u64;
    // One pass over a stdlib re-walks the same ancestors for every entry, so
    // share the proof across the walk instead of re-stat'ing them per file.
    let mut chain = ProvenChain::default();
    let mut walk = walkdir::WalkDir::new(root).follow_links(false).into_iter();
    while let Some(entry) = walk.next() {
        let entry = entry.map_err(|error| resolver_io_error(error.to_string()))?;
        if entry.file_type().is_symlink() {
            return Err(resolver_io_error(format!(
                "Python runtime tree contains symlinked dependency {}",
                entry.path().display()
            )));
        }
        if entry.depth() == 1
            && matches!(
                entry.file_name().to_str(),
                Some("site-packages" | "dist-packages")
            )
            && entry.file_type().is_dir()
        {
            // Site trees are enumerated and constrained separately below; skipping
            // them here keeps an unrelated global package set from becoming the
            // runtime-binding cost.
            walk.skip_current_dir();
            continue;
        }
        if !chain.path_chain_is_secure(entry.path()) {
            return Err(ResolverError::ToolUntrusted {
                tool: entry.path().display().to_string(),
                reason: "Python runtime dependency is not root-managed and non-writable"
                    .to_string(),
            });
        }
        let metadata = std::fs::metadata(entry.path()).map_err(ResolverError::Io)?;
        if metadata.is_file() {
            files = files.saturating_add(1);
            bytes = bytes.saturating_add(metadata.len());
            if files > PYTHON_RUNTIME_MAX_FILES || bytes > PYTHON_RUNTIME_MAX_BYTES {
                return Err(resolver_io_error(format!(
                    "Python runtime tree exceeds binding limits ({files} files, {bytes} bytes)"
                )));
            }
        } else if !metadata.is_dir() {
            return Err(resolver_io_error(format!(
                "Python runtime tree contains unsupported entry {}",
                entry.path().display()
            )));
        }
    }
    Ok(())
}

#[cfg(unix)]
fn validate_site_startup_controls(site_root: &Path) -> Result<(), ResolverError> {
    let mut chain = ProvenChain::default();
    for entry in std::fs::read_dir(site_root).map_err(ResolverError::Io)? {
        let entry = entry.map_err(ResolverError::Io)?;
        let name = entry.file_name();
        let is_control = name.to_str().is_some_and(|name| {
            name.ends_with(".pth") || name == "sitecustomize.py" || name == "usercustomize.py"
        });
        if is_control && !chain.path_chain_is_secure(&entry.path()) {
            return Err(ResolverError::ToolUntrusted {
                tool: entry.path().display().to_string(),
                reason: "Python startup control file is user-writable".to_string(),
            });
        }
    }
    Ok(())
}

#[cfg(unix)]
fn locate_exact_pip_dist_info(site_root: &Path) -> Result<PathBuf, ResolverError> {
    let mut matches = Vec::new();
    for entry in std::fs::read_dir(site_root).map_err(ResolverError::Io)? {
        let entry = entry.map_err(ResolverError::Io)?;
        let name = entry.file_name();
        let Some(name) = name.to_str() else {
            continue;
        };
        let lower = name.to_ascii_lowercase();
        if lower.starts_with("pip-") && lower.ends_with(".dist-info") {
            let path = entry.path().canonicalize().map_err(ResolverError::Io)?;
            if !path.is_dir() || !resolver_root_managed_path_chain_is_secure(&path) {
                return Err(ResolverError::ToolUntrusted {
                    tool: path.display().to_string(),
                    reason: "pip dist-info tree is not a root-managed directory".to_string(),
                });
            }
            matches.push(path);
        }
    }
    if matches.len() != 1 {
        return Err(resolver_io_error(format!(
            "expected exactly one pip dist-info tree beside the selected package, found {}",
            matches.len()
        )));
    }
    Ok(matches.pop().expect("length checked"))
}

#[cfg(unix)]
fn read_pip_metadata_version(metadata_root: &Path) -> Result<String, ResolverError> {
    const MAX_METADATA_BYTES: u64 = 1024 * 1024;
    let metadata_path = metadata_root.join("METADATA");
    if !resolver_root_managed_path_chain_is_secure(&metadata_path) {
        return Err(ResolverError::ToolUntrusted {
            tool: metadata_path.display().to_string(),
            reason: "pip METADATA is not root-managed and non-writable".to_string(),
        });
    }
    let bytes = crate::util::read_text_no_follow_capped(&metadata_path, MAX_METADATA_BYTES)
        .map_err(|error| resolver_io_error(format!("cannot read pip METADATA: {error:?}")))?;
    let text = std::str::from_utf8(&bytes)
        .map_err(|_| resolver_io_error("pip METADATA is not valid UTF-8"))?;
    let mut name = None;
    let mut version = None;
    for line in text.lines() {
        if let Some(value) = line.strip_prefix("Name:") {
            name = Some(value.trim());
        } else if let Some(value) = line.strip_prefix("Version:") {
            version = Some(value.trim());
        }
        if name.is_some() && version.is_some() {
            break;
        }
    }
    if !name.is_some_and(|name| name.eq_ignore_ascii_case("pip")) {
        return Err(resolver_io_error(
            "selected pip METADATA has a non-pip Name",
        ));
    }
    let version = version.filter(|value| {
        !value.is_empty()
            && value.len() <= 128
            && value
                .bytes()
                .all(|byte| byte.is_ascii_graphic() && !byte.is_ascii_control())
    });
    version
        .map(str::to_string)
        .ok_or_else(|| resolver_io_error("selected pip METADATA has no bounded version"))
}

#[cfg(unix)]
fn attest_pip_trees(
    pip_root: &Path,
    metadata_root: &Path,
) -> Result<PipTreeBinding, ResolverError> {
    use sha2::{Digest as _, Sha256};
    use std::io::Read as _;
    use std::os::unix::fs::{OpenOptionsExt as _, PermissionsExt as _};

    struct Entry {
        label: &'static str,
        relative: String,
        path: PathBuf,
        directory: bool,
    }

    let mut entries = Vec::new();
    for (label, root) in [("package", pip_root), ("metadata", metadata_root)] {
        if !resolver_root_managed_path_chain_is_secure(root) {
            return Err(ResolverError::ToolUntrusted {
                tool: root.display().to_string(),
                reason: "pip attestation root is not root-managed and non-writable".to_string(),
            });
        }
        for entry in walkdir::WalkDir::new(root).follow_links(false) {
            let entry = entry.map_err(|error| resolver_io_error(error.to_string()))?;
            if entry.file_type().is_symlink() {
                return Err(resolver_io_error(format!(
                    "pip attestation rejects symlink {}",
                    entry.path().display()
                )));
            }
            if !entry.file_type().is_dir() && !entry.file_type().is_file() {
                return Err(resolver_io_error(format!(
                    "pip attestation rejects non-regular entry {}",
                    entry.path().display()
                )));
            }
            if !resolver_root_managed_path_chain_is_secure(entry.path()) {
                return Err(ResolverError::ToolUntrusted {
                    tool: entry.path().display().to_string(),
                    reason: "pip tree entry is not root-managed and non-writable".to_string(),
                });
            }
            let relative = entry
                .path()
                .strip_prefix(root)
                .map_err(|error| resolver_io_error(error.to_string()))?
                .to_str()
                .ok_or_else(|| resolver_io_error("pip tree contains a non-UTF-8 path"))?
                .replace(std::path::MAIN_SEPARATOR, "/");
            if relative.len() as u64 > PIP_TREE_MAX_PATH_BYTES {
                return Err(resolver_io_error(format!(
                    "pip tree path exceeds {PIP_TREE_MAX_PATH_BYTES} bytes"
                )));
            }
            entries.push(Entry {
                label,
                relative,
                path: entry.path().to_path_buf(),
                directory: entry.file_type().is_dir(),
            });
        }
    }
    entries.sort_by(|left, right| {
        (left.label, left.relative.as_bytes()).cmp(&(right.label, right.relative.as_bytes()))
    });

    let mut hasher = Sha256::new();
    hasher.update(b"tirith-pip-tree-v1\0");
    hasher.update(PIP_TREE_MAX_FILES.to_be_bytes());
    hasher.update(PIP_TREE_MAX_BYTES.to_be_bytes());
    hasher.update(PIP_TREE_MAX_FILE_BYTES.to_be_bytes());
    hasher.update(PIP_TREE_MAX_PATH_BYTES.to_be_bytes());
    let mut files = 0_u64;
    let mut bytes = 0_u64;
    for entry in entries {
        let metadata = std::fs::metadata(&entry.path).map_err(ResolverError::Io)?;
        hasher.update(if entry.directory { b"D" } else { b"F" });
        hasher.update((entry.label.len() as u64).to_be_bytes());
        hasher.update(entry.label.as_bytes());
        hasher.update((entry.relative.len() as u64).to_be_bytes());
        hasher.update(entry.relative.as_bytes());
        hasher.update((metadata.permissions().mode() & 0o7777).to_be_bytes());
        if entry.directory {
            continue;
        }
        if !metadata.is_file() || metadata.len() > PIP_TREE_MAX_FILE_BYTES {
            return Err(resolver_io_error(format!(
                "pip tree file {} exceeds the per-file binding limit or is not regular",
                entry.path.display()
            )));
        }
        files = files.saturating_add(1);
        bytes = bytes.saturating_add(metadata.len());
        if files > PIP_TREE_MAX_FILES || bytes > PIP_TREE_MAX_BYTES {
            return Err(resolver_io_error(format!(
                "pip tree exceeds binding limits ({files} files, {bytes} bytes)"
            )));
        }
        hasher.update(metadata.len().to_be_bytes());
        let mut file = std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(&entry.path)
            .map_err(ResolverError::Io)?;
        let opened = file.metadata().map_err(ResolverError::Io)?;
        if !opened.is_file()
            || opened.len() != metadata.len()
            || (opened.permissions().mode() & 0o7777) != (metadata.permissions().mode() & 0o7777)
        {
            return Err(resolver_io_error(format!(
                "pip tree file {} changed while being attested",
                entry.path.display()
            )));
        }
        let mut remaining = opened.len();
        let mut buffer = [0_u8; 64 * 1024];
        while remaining > 0 {
            let count = file.read(&mut buffer).map_err(ResolverError::Io)?;
            if count == 0 {
                return Err(resolver_io_error(format!(
                    "pip tree file {} was truncated during attestation",
                    entry.path.display()
                )));
            }
            let take = count.min(remaining as usize);
            hasher.update(&buffer[..take]);
            remaining -= take as u64;
            if take != count {
                return Err(resolver_io_error(format!(
                    "pip tree file {} grew during attestation",
                    entry.path.display()
                )));
            }
        }
        let mut extra = [0_u8; 1];
        if file.read(&mut extra).map_err(ResolverError::Io)? != 0 {
            return Err(resolver_io_error(format!(
                "pip tree file {} grew during attestation",
                entry.path.display()
            )));
        }
    }
    Ok(PipTreeBinding {
        root: pip_root.to_path_buf(),
        metadata_root: metadata_root.to_path_buf(),
        sha256: hex::encode(hasher.finalize()),
        files,
        bytes,
    })
}

#[cfg(unix)]
fn capture_bound_tool_version<const N: usize>(
    executable: &TrustedExecutable,
    args: [&str; N],
    label: &str,
) -> Result<String, ResolverError> {
    let spec = ChildSpec::new(
        args,
        ChildLimits::new(Duration::from_secs(10), 16 * 1024, 16 * 1024),
    );
    match crate::trusted_child::run(executable, &spec) {
        ChildOutcome::Completed { status, stdout, .. } if status.success() => {
            let text = String::from_utf8_lossy(&stdout).trim().to_string();
            if text.is_empty() || text.len() > 4096 {
                return Err(resolver_io_error(format!(
                    "{label} version probe returned no bounded version text"
                )));
            }
            Ok(text)
        }
        ChildOutcome::Completed { status, stderr, .. } => Err(resolver_io_error(format!(
            "{label} version probe failed with {:?}: {}",
            status.code(),
            crate::util::truncate_bytes(&String::from_utf8_lossy(&stderr), 1024)
        ))),
        ChildOutcome::Timeout { .. } => Err(ResolverError::Timeout(format!(
            "{label} version probe exceeded 10s"
        ))),
        ChildOutcome::OutputLimitExceeded { .. } => Err(resolver_io_error(format!(
            "{label} version probe exceeded its output limit"
        ))),
        ChildOutcome::SpawnError(reason)
        | ChildOutcome::WaitError(reason)
        | ChildOutcome::CleanupError(reason) => Err(resolver_io_error(format!(
            "{label} version probe failed: {reason}"
        ))),
    }
}

fn permitted_requirement_url(
    spec: &str,
    allowances: &ResolverAllowances,
) -> Result<Option<url::Url>, ResolverError> {
    let trimmed = spec.trim();
    if trimmed.starts_with('-') && allowances.allow_editable {
        let Some(target) = editable_requirement_target(trimmed) else {
            return Ok(None);
        };
        return permitted_requirement_url(target.trim_start_matches('=').trim(), allowances);
    }

    let location = classify_requirement_location(trimmed).map_err(|reason| {
        ResolverError::RejectedRequirement {
            spec: spec.to_string(),
            reason,
        }
    })?;
    let parsed = match location {
        RequirementLocation::Direct(target) if allowances.allow_direct_url => {
            Some(parse_network_url(target).map_err(|reason| {
                ResolverError::RejectedRequirement {
                    spec: spec.to_string(),
                    reason: format!("direct URL rejected: {reason}"),
                }
            })?)
        }
        RequirementLocation::Vcs(target) if allowances.allow_vcs => Some(
            parse_vcs_url(target).map_err(|reason| ResolverError::RejectedRequirement {
                spec: spec.to_string(),
                reason: format!("VCS URL rejected: {reason}"),
            })?,
        ),
        _ => None,
    };
    Ok(parsed)
}

/// Resolve `request` end to end into the quarantine `txn`, using `tools`.
///
/// Steps, each fail-closed:
/// 1. Validate every requirement and index URL up front (no subprocess on a
///    refused input).
/// 2. Write the requirements to an isolated temp `requirements.in`.
/// 3. `uv pip compile --generate-hashes --no-build` -> `locked.txt`; verify the
///    lock is fully hash-pinned.
/// 4. `python -m pip download --only-binary=:all: --require-hashes` into an
///    isolated staging dir.
/// 5. Ingest every downloaded wheel into the D1 quarantine (re-hashing on the
///    way in); refuse any non-wheel artifact.
///
/// The returned [`ResolvedSet`] carries the lock text (for the receipt) and the
/// quarantined wheels (for D3 inspection). On any failure nothing is left
/// installable: the staging dir is a temp that drops, and a partial set is never
/// returned.
pub fn resolve_into_quarantine(
    request: &ResolverRequest,
    tools: &ResolverTools,
    txn: &QuarantineTransaction,
) -> Result<ResolvedSet, ResolverError> {
    resolve_into_quarantine_with_artifact_origins(request, tools, txn, &[])
}

/// Resolve with additional operator-approved artifact/CDN origins. These hosts
/// are admitted by the enforcing broker but never become package indexes.
pub fn resolve_into_quarantine_with_artifact_origins(
    request: &ResolverRequest,
    tools: &ResolverTools,
    txn: &QuarantineTransaction,
    artifact_origins: &[String],
) -> Result<ResolvedSet, ResolverError> {
    // 1. Effect-free validation of every attacker-controlled input. Only after
    // this succeeds do we stat tools, bind the broker, or write temp files.
    let validated = validate_resolver_inputs(request, artifact_origins)?;
    let tools = BoundResolverTools::bind(tools)?;
    resolve_validated_with_bound_tools(request, &tools, txn, validated)
}

/// Resolve with caller-retained, content-bound tools. Package install uses this
/// seam so the exact Python image remains alive through the later offline install.
pub fn resolve_into_quarantine_with_bound_tools(
    request: &ResolverRequest,
    tools: &BoundResolverTools,
    txn: &QuarantineTransaction,
    artifact_origins: &[String],
) -> Result<ResolvedSet, ResolverError> {
    let validated = validate_resolver_inputs(request, artifact_origins)?;
    resolve_validated_with_bound_tools(request, tools, txn, validated)
}

fn resolve_validated_with_bound_tools(
    request: &ResolverRequest,
    tools: &BoundResolverTools,
    txn: &QuarantineTransaction,
    validated: ValidatedResolverInputs,
) -> Result<ResolvedSet, ResolverError> {
    let permitted =
        PermittedOrigins::from_urls(&validated.permitted_urls).map_err(resolver_io_error)?;
    let broker = ResolverBroker::start(permitted).map_err(resolver_io_error)?;
    let proxy_url = broker.proxy_url();

    // 2. An isolated working tree: a temp dir that is the child's config_home,
    //    holds requirements.in / locked.txt, and a staging subdir for downloads.
    //    It drops (and is removed) when this function returns, success or not.
    let work = tempfile::tempdir().map_err(ResolverError::Io)?;
    let config_home = work.path().join("home");
    crate::util::create_dir_durable(&config_home).map_err(ResolverError::Io)?;
    let staging = work.path().join("staging");
    crate::util::create_dir_durable(&staging).map_err(ResolverError::Io)?;

    let requirements_in = work.path().join("requirements.in");
    let lock_path = work.path().join("locked.txt");
    let requirements_blob = request
        .requirements
        .iter()
        .map(|s| s.trim())
        .collect::<Vec<_>>()
        .join("\n");
    crate::util::write_file_atomic_0600(&requirements_in, requirements_blob.as_bytes())
        .map_err(ResolverError::Io)?;

    // 3. Compile a hash-pinned lock.
    tools.revalidate_install_authority()?;
    #[cfg(target_os = "linux")]
    let python_for_uv = tools.python_capability_path()?;
    #[cfg(not(target_os = "linux"))]
    let python_for_uv = tools.python.path().to_path_buf();
    let compile_args = uv_compile_args(
        &requirements_in,
        &lock_path,
        &python_for_uv,
        &validated.canonical_index_urls,
        &request.allowances,
    );
    let compile = run_child_capped(
        &tools.uv,
        &compile_args,
        &config_home,
        &tools.python,
        &proxy_url,
        RESOLVER_CHILD_TIMEOUT,
    )?;
    if !compile.success {
        return Err(ResolverError::CompileFailed(compile.diagnostics()));
    }
    // uv writes the lock to --output-file; read it (no-follow, bounded).
    let lock_bytes = crate::util::read_text_no_follow_capped(
        &lock_path,
        crate::artifact::inspect::ARTIFACT_MAX_FILE_SIZE,
    )
    .map_err(|e| ResolverError::CompileFailed(format!("could not read lock: {e:?}")))?;
    let locked_requirements = String::from_utf8_lossy(&lock_bytes).into_owned();
    verify_lock_hash_pinned(&locked_requirements)?;

    // 4. Download the pinned wheels under --require-hashes.
    tools.revalidate_install_authority()?;
    let download_args = pip_download_args(
        &lock_path,
        &staging,
        &validated.canonical_index_urls,
        &proxy_url,
    );
    let download = run_child_capped(
        &tools.python,
        &download_args,
        &config_home,
        &tools.python,
        &proxy_url,
        RESOLVER_CHILD_TIMEOUT,
    )?;
    if !download.success {
        return Err(ResolverError::DownloadFailed(download.diagnostics()));
    }

    // 5. Ingest every wheel in the staging dir into the quarantine. The locked
    //    hashes are the source of truth: we ingest each file under the digest the
    //    lock pinned for it, and D1's ingest re-hashes and rejects a mismatch.
    let locked_hashes = parse_locked_wheel_hashes(&locked_requirements);
    let artifacts = ingest_staged_wheels(txn.store(), &staging, &locked_hashes)?;
    if artifacts.is_empty() {
        return Err(ResolverError::UnexpectedDownload(
            "pip download produced no wheel artifacts".to_string(),
        ));
    }

    Ok(ResolvedSet {
        locked_requirements,
        artifacts,
    })
}

/// Parse the `--generate-hashes` lock into a map of wheel-filename-stem hints to
/// the set of sha256 hashes pinned for that requirement. We do not rely on the
/// mapping being filename-exact (the lock keys by distribution, the download
/// names files by wheel tag); instead we collect EVERY pinned sha256 into a flat
/// set the ingest checks against, so a downloaded file's own hash must be one the
/// lock pinned. The map keying is retained for diagnostics only.
fn parse_locked_wheel_hashes(lock: &str) -> LockedHashes {
    let mut all: Vec<String> = Vec::new();
    let mut by_req: BTreeMap<String, Vec<String>> = BTreeMap::new();
    let mut current_req: Option<String> = None;
    for raw in lock.lines() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if let Some(hash) = extract_sha256(line) {
            all.push(hash.clone());
            if let Some(req) = &current_req {
                by_req.entry(req.clone()).or_default().push(hash);
            }
            continue;
        }
        if line.starts_with("--") {
            continue;
        }
        // A requirement line: remember its leading name==version token.
        let name = line
            .split([' ', ';', '\\'])
            .next()
            .unwrap_or(line)
            .to_string();
        current_req = Some(name);
        if let Some(hash) = extract_sha256(line) {
            all.push(hash.clone());
            by_req.entry(current_req.clone().unwrap()).or_default();
            if let Some(req) = &current_req {
                by_req.entry(req.clone()).or_default().push(hash);
            }
        }
    }
    LockedHashes {
        all,
        _by_req: by_req,
    }
}

/// The sha256 hashes a lock pinned. `all` is the flat allow-set the ingest checks
/// each download against; `_by_req` is retained for future diagnostics.
struct LockedHashes {
    all: Vec<String>,
    _by_req: BTreeMap<String, Vec<String>>,
}

/// Extract the first `sha256:<64hex>` from a line (in `--hash=sha256:...` or a
/// bare `sha256:...` form), lowercased.
fn extract_sha256(line: &str) -> Option<String> {
    let idx = line.find("sha256:")?;
    let after = &line[idx + "sha256:".len()..];
    let hex: String = after
        .chars()
        .take_while(|c| c.is_ascii_hexdigit())
        .collect();
    if hex.len() == 64 {
        Some(hex.to_ascii_lowercase())
    } else {
        None
    }
}

/// Ingest every `*.whl` in `staging` into the quarantine blob store, matching each
/// file's own content hash to one the lock pinned. A non-wheel file in the
/// staging dir is refused ([`ResolverError::UnexpectedDownload`]); a wheel whose
/// hash the lock did not pin is refused; a wheel whose stored bytes do not match
/// (caught by D1's re-hash on ingest) is refused. Returns the resolved artifacts
/// sorted by filename for determinism.
fn ingest_staged_wheels(
    store: &QuarantineStore,
    staging: &Path,
    locked: &LockedHashes,
) -> Result<Vec<ResolvedArtifact>, ResolverError> {
    let allow: std::collections::BTreeSet<&str> = locked.all.iter().map(|s| s.as_str()).collect();
    let mut out: Vec<ResolvedArtifact> = Vec::new();
    let entries = std::fs::read_dir(staging).map_err(ResolverError::Io)?;
    for entry in entries {
        let entry = entry.map_err(ResolverError::Io)?;
        let path = entry.path();
        if !path.is_file() {
            // A non-file in the staging dir (a directory pip created for an
            // unpacked sdist would be one) is refused: only wheels are expected.
            return Err(ResolverError::UnexpectedDownload(format!(
                "non-file artifact in download staging: {}",
                path.display()
            )));
        }
        let Some(name) = path.file_name().and_then(|n| n.to_str()) else {
            return Err(ResolverError::UnexpectedDownload(
                "download artifact has a non-UTF-8 name".to_string(),
            ));
        };
        if !crate::artifact::archive::is_wheel_filename(name) {
            // An sdist (`.tar.gz` / `.zip`) or anything not a wheel slipped past
            // the only-binary flags: refuse, fail-closed.
            return Err(ResolverError::UnexpectedDownload(format!(
                "non-wheel artifact downloaded: {name}"
            )));
        }
        // Hash the downloaded file, confirm the lock pinned this exact content,
        // then ingest it under that digest (D1 re-hashes and would reject any
        // drift between this hash and the bytes it stores).
        let digest = hash_download(&path)?;
        if !allow.contains(digest.as_str()) {
            return Err(ResolverError::UnexpectedDownload(format!(
                "downloaded wheel {name} (sha256 {digest}) was not pinned by the lock"
            )));
        }
        store.ingest_file(&path, &digest)?;
        out.push(ResolvedArtifact {
            wheel_filename: name.to_string(),
            sha256: digest,
        });
    }
    out.sort_by(|a, b| a.wheel_filename.cmp(&b.wheel_filename));
    Ok(out)
}

/// Hash a downloaded file from a no-follow, fstat'd handle (the single-handle
/// TOCTOU-safe pattern shared with D1). Returns the lowercase-hex SHA-256.
fn hash_download(path: &Path) -> Result<String, ResolverError> {
    use crate::util::{
        open_read_no_follow_capped, sha256_from_handle, HashOutcome, OpenRegularError,
    };
    let cap = crate::artifact::inspect::ARTIFACT_MAX_FILE_SIZE;
    let handle = match open_read_no_follow_capped(path, cap) {
        Ok(f) => f,
        Err(OpenRegularError::TooLarge) => {
            return Err(ResolverError::UnexpectedDownload(format!(
                "downloaded artifact exceeds the size ceiling: {}",
                path.display()
            )))
        }
        Err(OpenRegularError::NotFound) | Err(OpenRegularError::NotRegularFile) => {
            return Err(ResolverError::UnexpectedDownload(format!(
                "downloaded artifact vanished or is not a regular file: {}",
                path.display()
            )))
        }
        Err(OpenRegularError::Io(e)) => return Err(ResolverError::Io(e)),
    };
    match sha256_from_handle(handle, cap) {
        Ok(HashOutcome::Digest(hex)) => Ok(hex),
        Ok(HashOutcome::BudgetExceeded) => Err(ResolverError::UnexpectedDownload(format!(
            "downloaded artifact exceeds the hash budget: {}",
            path.display()
        ))),
        Err(e) => Err(ResolverError::Io(e)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tirith_test_support::GlobalStateGuard;

    fn allow_all() -> ResolverAllowances {
        ResolverAllowances {
            allow_sdist: true,
            allow_vcs: true,
            allow_editable: true,
            allow_local_path: true,
            allow_direct_url: true,
            allow_untrusted_tool: true,
        }
    }

    #[test]
    fn failed_uv_and_pip_diagnostics_are_terminal_safe_and_bounded() {
        let mut uv_stderr =
            "\x1b]52;c;Zm9yZ2Vk\x07\rFORGED UV ROW\nname\u{202e}txt\u{200b}: conflict"
                .as_bytes()
                .to_vec();
        uv_stderr.extend(std::iter::repeat_n(
            b'x',
            RESOLVER_DIAGNOSTIC_MAX_BYTES + 100,
        ));
        let uv_diagnostic = ChildOutput {
            success: false,
            stdout: b"uv: no solution".to_vec(),
            stderr: uv_stderr,
        }
        .diagnostics();
        let uv_error = ResolverError::CompileFailed(uv_diagnostic.clone()).to_string();

        let pip_diagnostic = ChildOutput {
            success: false,
            stdout: Vec::new(),
            stderr: b"\x1b[2Jpip failure\nFORGED PIP ROW\x1b[31m".to_vec(),
        }
        .diagnostics();
        let pip_error = ResolverError::DownloadFailed(pip_diagnostic.clone()).to_string();

        for diagnostic in [&uv_diagnostic, &pip_diagnostic] {
            assert!(diagnostic.len() <= RESOLVER_DIAGNOSTIC_MAX_BYTES);
            assert!(!diagnostic
                .chars()
                .any(|ch| matches!(ch, '\n' | '\r' | '\x1b' | '\x07')));
            assert_eq!(
                crate::mcp::output_filter::sanitize_for_display(diagnostic),
                diagnostic.as_str(),
                "diagnostic must already be a terminal-safe display projection"
            );
        }
        assert!(uv_error.contains("uv pip compile failed: uv: no solution | FORGED UV ROW"));
        assert!(pip_error.contains("pip download failed: pip failure | FORGED PIP ROW"));
    }

    #[test]
    fn legitimate_multiline_resolver_diagnostic_remains_readable() {
        let diagnostic = ChildOutput {
            success: false,
            stdout: b"resolved 12 packages".to_vec(),
            stderr: "ERROR: no matching distribution for café\nretry with another version"
                .as_bytes()
                .to_vec(),
        }
        .diagnostics();

        assert_eq!(
            diagnostic,
            "resolved 12 packages | ERROR: no matching distribution for café | retry with another version"
        );
    }

    // ---- requirement validation -------------------------------------------

    #[test]
    fn plain_named_requirements_accepted() {
        let a = ResolverAllowances::default();
        for spec in [
            "requests",
            "requests==2.31.0",
            "flask>=3,<4",
            "django[argon2]==5.0",
            "numpy==1.26.4 ; python_version >= '3.9'",
        ] {
            assert!(
                validate_requirement(spec, &a).is_ok(),
                "{spec:?} should be accepted"
            );
        }
    }

    #[test]
    fn editable_requirement_refused_by_default_allowed_with_flag() {
        let def = ResolverAllowances::default();
        for spec in ["-e .", "--editable ./pkg", "-e git+https://x/y.git"] {
            assert!(
                matches!(
                    validate_requirement(spec, &def),
                    Err(ResolverError::RejectedRequirement { .. })
                ),
                "{spec:?} should be refused by default"
            );
        }
        // With the editable allowance, the `-e` forms pass the pre-flight gate.
        assert!(validate_requirement("-e .", &allow_all()).is_ok());
    }

    #[test]
    fn vcs_requirement_refused_by_default() {
        let def = ResolverAllowances::default();
        for spec in [
            "git+https://github.com/psf/requests.git",
            "requests @ git+https://github.com/psf/requests.git",
            "svn+https://example.invalid/repo",
        ] {
            assert!(
                matches!(
                    validate_requirement(spec, &def),
                    Err(ResolverError::RejectedRequirement { .. })
                ),
                "{spec:?} should be refused"
            );
        }
        let a = ResolverAllowances {
            allow_vcs: true,
            ..Default::default()
        };
        assert!(validate_requirement("git+https://example.invalid/x.git", &a).is_ok());
    }

    #[test]
    fn direct_url_requirement_refused_by_default() {
        let def = ResolverAllowances::default();
        for spec in [
            "requests @ https://example.invalid/requests-2.31.0-py3-none-any.whl",
            "requests@https://example.invalid/requests-2.31.0-py3-none-any.whl",
            "requests @https://example.invalid/requests-2.31.0-py3-none-any.whl",
            "requests@ https://example.invalid/requests-2.31.0-py3-none-any.whl",
            "requests\t@\thttps://example.invalid/requests-2.31.0-py3-none-any.whl",
            "https://example.invalid/x-1.0-py3-none-any.whl",
        ] {
            let error = validate_requirement(spec, &def).unwrap_err();
            let ResolverError::RejectedRequirement { reason, .. } = error else {
                panic!("{spec:?} produced the wrong error: {error:?}");
            };
            assert!(
                reason.contains("direct-URL requirements"),
                "{spec:?} must be classified as a direct URL, got: {reason}"
            );
        }
    }

    #[test]
    fn malformed_at_reference_fails_closed() {
        let error =
            validate_requirement("requests@not a url", &ResolverAllowances::default()).unwrap_err();
        assert!(matches!(error, ResolverError::RejectedRequirement { .. }));
    }

    #[test]
    fn pep508_at_inside_version_or_marker_is_not_a_direct_reference() {
        let allowances = ResolverAllowances::default();
        for requirement in [
            "pkg===foo@bar",
            "pkg; implementation_name == 'a@b'",
            "pkg[security, socks]>=1.0; python_version >= '3.11'",
        ] {
            assert!(
                validate_requirement(requirement, &allowances).is_ok(),
                "{requirement:?}"
            );
        }
    }

    #[test]
    fn direct_url_allowed_still_passes_ssrf() {
        let a = ResolverAllowances {
            allow_direct_url: true,
            ..Default::default()
        };
        // A loopback / private direct URL is rejected even when direct URLs are
        // allowed. Literal addresses fail preflight; DNS names are rechecked at
        // the broker's exact connect boundary.
        let err =
            validate_requirement("x @ http://127.0.0.1/x-1.0-py3-none-any.whl", &a).unwrap_err();
        assert!(
            matches!(err, ResolverError::RejectedRequirement { .. }),
            "loopback direct URL must be refused: {err:?}"
        );
        // Plain HTTP is always rejected for resolver traffic.
        let err =
            validate_requirement("x @ http://example.com/x-1.0-py3-none-any.whl", &a).unwrap_err();
        assert!(matches!(err, ResolverError::RejectedRequirement { .. }));
    }

    #[test]
    fn local_path_requirement_refused_by_default() {
        let def = ResolverAllowances::default();
        for spec in [
            "./pkg",
            "../pkg",
            "/abs/pkg",
            "file:///abs/pkg",
            "~/pkg",
            "C:\\pkg",
            "C:/pkg",
        ] {
            assert!(
                matches!(
                    validate_requirement(spec, &def),
                    Err(ResolverError::RejectedRequirement { .. })
                ),
                "{spec:?} should be refused as a local path"
            );
        }
    }

    #[test]
    fn windows_local_path_allowance_is_applied_before_url_parsing() {
        let allowances = ResolverAllowances {
            allow_local_path: true,
            ..Default::default()
        };
        assert!(validate_requirement("C:/pkg", &allowances).is_ok());
        assert!(validate_requirement("C:\\pkg", &allowances).is_ok());
    }

    #[test]
    fn existing_cwd_path_treated_as_local() {
        let dir = tempfile::tempdir().unwrap();
        let archive = dir.path().join("evil-1.0.tar.gz");
        std::fs::write(&archive, b"sdist").unwrap();
        let def = ResolverAllowances::default();
        // The absolute path to an existing file is a local path -> refused.
        let spec = archive.display().to_string();
        assert!(matches!(
            validate_requirement(&spec, &def),
            Err(ResolverError::RejectedRequirement { .. })
        ));
    }

    #[test]
    fn control_chars_and_options_refused() {
        let def = ResolverAllowances::default();
        assert!(validate_requirement("requests\n--index-url http://evil", &def).is_err());
        assert!(validate_requirement("-r other.txt", &def).is_err());
        assert!(validate_requirement("--pre", &def).is_err());
        assert!(validate_requirement("", &def).is_err());
    }

    // ---- index url validation ---------------------------------------------

    #[test]
    fn index_url_requires_https_and_public() {
        // Plain HTTP refused.
        assert!(validate_index_url("http://example.com/simple").is_err());
        // Loopback refused.
        assert!(validate_index_url("https://127.0.0.1/simple").is_err());
        assert!(validate_index_url("https://localhost/simple").is_err());
        // Cloud metadata refused.
        assert!(validate_index_url("https://169.254.169.254/simple").is_err());
        // Embedded credentials refused with the precise message.
        let err = validate_index_url("https://user:pass@example.com/simple").unwrap_err();
        match err {
            ResolverError::RejectedIndexUrl { reason, .. } => {
                assert!(reason.contains("credentials"), "{reason}");
            }
            other => panic!("expected RejectedIndexUrl, got {other:?}"),
        }
    }

    #[test]
    fn index_url_public_https_accepted() {
        // Syntax preflight performs no DNS or network I/O. Connect-time public
        // address validation belongs exclusively to the broker.
        assert!(validate_index_url("https://pypi.org/simple").is_ok());
    }

    // ---- isolated env ------------------------------------------------------

    #[test]
    fn isolated_env_strips_tokens_and_pins_config() {
        let dir = tempfile::tempdir().unwrap();
        let py = Path::new("/usr/bin/python3");
        let env = isolated_env(dir.path(), py);
        let map: BTreeMap<&str, &str> = env.iter().map(|(k, v)| (k.as_str(), v.as_str())).collect();
        // Config roots point at the empty temp home.
        assert_eq!(
            map.get("HOME").copied(),
            Some(dir.path().display().to_string().as_str())
        );
        assert_eq!(
            map.get("XDG_CONFIG_HOME").copied(),
            Some(dir.path().display().to_string().as_str())
        );
        for key in ["TEMP", "TMP", "TMPDIR"] {
            assert_eq!(
                map.get(key).copied(),
                Some(dir.path().display().to_string().as_str()),
                "{key} must remain inside the isolated resolver directory"
            );
        }
        // Isolation flags present.
        assert_eq!(map.get("PIP_ISOLATED").copied(), Some("1"));
        assert_eq!(map.get("UV_NO_CONFIG").copied(), Some("1"));
        assert_eq!(map.get("UV_PYTHON_DOWNLOADS").copied(), Some("never"));
        // No token / index leakage: none of these keys appear.
        for forbidden in [
            "PIP_INDEX_URL",
            "UV_INDEX",
            "UV_INDEX_URL",
            "PIP_EXTRA_INDEX_URL",
            "TWINE_PASSWORD",
            "OPENAI_API_KEY",
            "GITHUB_TOKEN",
            "NETRC",
        ] {
            assert!(
                !map.contains_key(forbidden),
                "isolated env must not carry {forbidden}"
            );
        }
        // The pip config file is the platform null device, which suppresses even
        // system/global configuration rather than merely adding an absent file.
        let cfg = map.get("PIP_CONFIG_FILE").copied().unwrap();
        assert_eq!(cfg, if cfg!(windows) { "nul" } else { "/dev/null" });
    }

    #[cfg(windows)]
    #[test]
    fn isolated_env_ignores_forged_windows_directory_variables() {
        let mut environment = GlobalStateGuard::new().expect("isolate resolver environment");
        environment.set_env("SystemRoot", r"C:\attacker-root");
        environment.set_env("windir", r"C:\attacker-windir");
        let directory = tempfile::tempdir().unwrap();
        let env = isolated_env(directory.path(), Path::new(r"C:\Python\python.exe"));

        let map: BTreeMap<&str, &str> = env.iter().map(|(k, v)| (k.as_str(), v.as_str())).collect();
        assert_ne!(map.get("SystemRoot").copied(), Some(r"C:\attacker-root"));
        assert_ne!(map.get("windir").copied(), Some(r"C:\attacker-windir"));
        assert!(
            !map.get("PATH")
                .copied()
                .unwrap_or_default()
                .contains("attacker-"),
            "resolver PATH must be built from Win32 directory APIs, not ambient variables"
        );
    }

    #[test]
    fn broker_env_replaces_all_proxy_and_bypass_aliases() {
        let dir = tempfile::tempdir().unwrap();
        let proxy = "http://tirith:token@127.0.0.1:43123";
        let env = isolated_env_with_proxy(dir.path(), Path::new("/usr/bin/python3"), proxy);
        let map: BTreeMap<&str, &str> = env.iter().map(|(k, v)| (k.as_str(), v.as_str())).collect();
        for key in [
            "HTTP_PROXY",
            "HTTPS_PROXY",
            "ALL_PROXY",
            "http_proxy",
            "https_proxy",
            "all_proxy",
        ] {
            assert_eq!(map.get(key).copied(), Some(proxy), "{key}");
        }
        assert_eq!(map.get("NO_PROXY").copied(), Some(""));
        assert_eq!(map.get("no_proxy").copied(), Some(""));
        assert!(!map.contains_key("PIP_INDEX_URL"));
        assert!(!map.contains_key("UV_INDEX_URL"));
    }

    #[test]
    fn canonical_index_alias_drives_argv_and_broker_policy() {
        let request = ResolverRequest {
            requirements: vec!["example==1.0".to_string()],
            index_urls: vec!["https://INDEX.Example.:443/simple".to_string()],
            allowances: ResolverAllowances::default(),
        };
        let validated = validate_resolver_inputs(&request, &[]).unwrap();
        assert_eq!(
            validated.canonical_index_urls,
            vec!["https://index.example/simple".to_string()]
        );
        let permitted = PermittedOrigins::from_urls(&validated.permitted_urls).unwrap();
        assert!(permitted.permits("INDEX.EXAMPLE.", 443));
        assert!(!permitted.permits("redirect.attacker.example", 443));
    }

    #[test]
    fn custom_artifact_origin_is_broker_only() {
        let request = ResolverRequest {
            requirements: vec!["example==1.0".to_string()],
            index_urls: vec!["https://index.example/simple".to_string()],
            allowances: ResolverAllowances::default(),
        };
        let artifact_origins = vec!["https://cdn.example/wheels".to_string()];
        let validated = validate_resolver_inputs(&request, &artifact_origins).unwrap();
        assert_eq!(
            validated.canonical_index_urls,
            vec!["https://index.example/simple".to_string()]
        );
        let permitted = PermittedOrigins::from_urls(&validated.permitted_urls).unwrap();
        assert!(permitted.permits("cdn.example", 443));
        let args = uv_compile_args(
            Path::new("/w/in"),
            Path::new("/w/out"),
            Path::new("/usr/bin/python3"),
            &validated.canonical_index_urls,
            &request.allowances,
        );
        assert!(!args.join(" ").contains("cdn.example"));
    }

    #[test]
    fn private_ipv6_literal_is_rejected_in_effect_free_preflight() {
        let request = ResolverRequest {
            requirements: vec!["example==1.0".to_string()],
            index_urls: vec!["https://[::1]/simple".to_string()],
            allowances: ResolverAllowances::default(),
        };
        assert!(matches!(
            validate_resolver_request(&request),
            Err(ResolverError::RejectedIndexUrl { .. })
        ));
    }

    #[test]
    fn isolated_env_path_does_not_inherit_parent_path() {
        let dir = tempfile::tempdir().unwrap();
        let py = dir.path().join("venv/bin/python3");
        std::fs::create_dir_all(py.parent().unwrap()).unwrap();
        let env = isolated_env(dir.path(), &py);
        let path = env
            .iter()
            .find(|(k, _)| k == "PATH")
            .map(|(_, v)| v)
            .unwrap();
        // The python's own dir leads; the parent PATH is not present wholesale
        // (we only add system dirs after it).
        assert!(
            path.starts_with(&py.parent().unwrap().display().to_string()),
            "PATH should lead with the interpreter dir, got {path}"
        );
    }

    // ---- uv / pip argument construction ------------------------------------

    #[test]
    fn uv_compile_args_pin_hashes_no_build_no_index() {
        let req = Path::new("/w/requirements.in");
        let lock = Path::new("/w/locked.txt");
        let py = Path::new("/usr/bin/python3");
        let args = uv_compile_args(req, lock, py, &[], &ResolverAllowances::default());
        let joined = args.join(" ");
        assert!(joined.contains("pip compile"), "{joined}");
        assert!(joined.contains("--generate-hashes"), "{joined}");
        // Binary-only resolution via --no-build (uv rejects --no-build WITH
        // --only-binary, so --only-binary belongs on the download step only).
        assert!(joined.contains("--no-build"), "{joined}");
        assert!(!joined.contains("--only-binary"), "{joined}");
        assert!(joined.contains("--no-config"), "{joined}");
        assert!(joined.contains("--no-python-downloads"), "{joined}");
        // No indexes -> --no-index, default PyPI never added.
        assert!(joined.contains("--no-index"), "{joined}");
        assert!(!joined.contains("--index-url"), "{joined}");
    }

    #[test]
    fn uv_compile_args_use_approved_indexes() {
        let req = Path::new("/w/requirements.in");
        let lock = Path::new("/w/locked.txt");
        let py = Path::new("/usr/bin/python3");
        let indexes = vec![
            "https://primary.example.com/simple".to_string(),
            "https://extra.example.com/simple".to_string(),
        ];
        let args = uv_compile_args(req, lock, py, &indexes, &ResolverAllowances::default());
        let joined = args.join(" ");
        assert!(
            joined.contains("--index-url https://primary.example.com/simple"),
            "{joined}"
        );
        assert!(
            joined.contains("--extra-index-url https://extra.example.com/simple"),
            "{joined}"
        );
        assert!(!joined.contains("--no-index"), "{joined}");
    }

    #[test]
    fn pip_download_args_require_hashes_only_binary() {
        let lock = Path::new("/w/locked.txt");
        let dest = Path::new("/w/staging");
        let proxy = "http://tirith:token@127.0.0.1:43123";
        let args = pip_download_args(lock, dest, &[], proxy);
        let joined = args.join(" ");
        assert!(joined.starts_with("-I -m pip download"), "{joined}");
        assert!(joined.contains("--only-binary :all:"), "{joined}");
        assert!(joined.contains("--require-hashes"), "{joined}");
        assert!(joined.contains("--no-deps"), "{joined}");
        assert!(joined.contains("--isolated"), "{joined}");
        assert!(joined.contains("--no-cache-dir"), "{joined}");
        assert!(joined.contains(&format!("--proxy {proxy}")), "{joined}");
        assert!(joined.contains("--no-index"), "{joined}");
        assert!(joined.contains("--dest /w/staging"), "{joined}");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn sealed_python_capability_is_child_local_not_parent_procfs() {
        assert_eq!(
            self_fd_capability_path(37),
            PathBuf::from("/proc/self/fd/37")
        );
        assert!(
            !self_fd_capability_path(37)
                .to_string_lossy()
                .contains(&std::process::id().to_string()),
            "uv must not depend on permission to dereference its parent's procfs fd table"
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn writable_encodings_tree_refuses_before_python_probe_marker() {
        let directory = tempfile::tempdir().unwrap();
        let stdlib = directory.path().join("lib/python9.9");
        let encodings = stdlib.join("encodings");
        std::fs::create_dir_all(&encodings).unwrap();
        let marker = directory.path().join("python-probe-ran");
        std::fs::write(
            encodings.join("__init__.py"),
            format!(
                "from pathlib import Path; Path({:?}).write_text('ran')\n",
                marker
            ),
        )
        .unwrap();

        // Compile-time API guard: the process-running attestation function cannot
        // be called with unchecked paths; it requires the validation token.
        type AttestFn =
            fn(&TrustedExecutable, &ValidatedPythonRuntime) -> AttestPythonRuntimeResult;
        let _attest_requires_validated_runtime: AttestFn = attest_python_runtime_and_pip;

        let result: Result<(), ResolverError> = (|| {
            let _validated = ValidatedPythonRuntime::validate(
                directory.path().to_path_buf(),
                "9.9".to_string(),
                stdlib,
            )?;
            // This marker stands in for the first Python spawn. It is unreachable
            // when even `encodings` lives in a user-writable runtime tree.
            std::fs::write(&marker, b"ran").map_err(ResolverError::Io)?;
            Ok(())
        })();
        assert!(matches!(result, Err(ResolverError::ToolUntrusted { .. })));
        assert!(
            !marker.exists(),
            "Python probe must not run before validation"
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn python_executable_name_binds_exact_major_minor() {
        assert_eq!(
            python_version_from_executable(Path::new("/usr/bin/python3.12")).as_deref(),
            Some("3.12")
        );
        for path in [
            "/usr/bin/python3",
            "/usr/bin/python",
            "/usr/bin/python3.12.1",
            "/usr/bin/python3.x",
        ] {
            assert!(
                python_version_from_executable(Path::new(path)).is_none(),
                "{path}"
            );
        }
    }

    // ---- lock hash-pin verification ----------------------------------------

    #[test]
    fn verify_lock_accepts_fully_pinned() {
        let lock = "\
requests==2.31.0 \\
    --hash=sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
certifi==2024.2.2 \\
    --hash=sha256:fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210
";
        let n = verify_lock_hash_pinned(lock).unwrap();
        assert_eq!(n, 2);
    }

    #[test]
    fn verify_lock_rejects_unpinned_requirement() {
        // The second requirement has no hash continuation.
        let lock = "\
requests==2.31.0 \\
    --hash=sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
certifi==2024.2.2
";
        assert!(matches!(
            verify_lock_hash_pinned(lock),
            Err(ResolverError::LockNotHashPinned(_))
        ));
    }

    #[test]
    fn verify_lock_rejects_empty() {
        assert!(matches!(
            verify_lock_hash_pinned("# just a comment\n"),
            Err(ResolverError::LockNotHashPinned(_))
        ));
    }

    #[test]
    fn extract_sha256_parses_hash_lines() {
        assert_eq!(
            extract_sha256(
                "--hash=sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
            )
            .as_deref(),
            Some("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
        );
        assert_eq!(extract_sha256("requests==2.31.0").as_deref(), None);
        // Too-short hex is not accepted.
        assert_eq!(extract_sha256("--hash=sha256:abcd").as_deref(), None);
    }

    #[test]
    fn parse_locked_wheel_hashes_collects_all() {
        let lock = "\
requests==2.31.0 \\
    --hash=sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
certifi==2024.2.2 \\
    --hash=sha256:fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210 \\
    --hash=sha256:1111111111111111111111111111111111111111111111111111111111111111
";
        let hashes = parse_locked_wheel_hashes(lock);
        assert_eq!(hashes.all.len(), 3);
        assert!(hashes.all.contains(
            &"1111111111111111111111111111111111111111111111111111111111111111".to_string()
        ));
    }

    // ---- staged-wheel ingest -----------------------------------------------

    fn sha256_hex(bytes: &[u8]) -> String {
        use sha2::{Digest, Sha256};
        hex::encode(Sha256::new().chain_update(bytes).finalize())
    }

    #[test]
    fn ingest_rejects_non_wheel_artifact() {
        let qroot = tempfile::tempdir().unwrap();
        let store = QuarantineStore::with_root(qroot.path().join("q")).unwrap();
        let staging = tempfile::tempdir().unwrap();
        // pip "downloaded" an sdist tarball, not a wheel.
        let sdist = staging.path().join("evil-1.0.tar.gz");
        std::fs::write(&sdist, b"sdist bytes").unwrap();
        let locked = LockedHashes {
            all: vec![sha256_hex(b"sdist bytes")],
            _by_req: BTreeMap::new(),
        };
        let err = ingest_staged_wheels(&store, staging.path(), &locked).unwrap_err();
        assert!(
            matches!(err, ResolverError::UnexpectedDownload(_)),
            "non-wheel must be refused: {err:?}"
        );
    }

    #[test]
    fn ingest_rejects_wheel_not_in_lock() {
        let qroot = tempfile::tempdir().unwrap();
        let store = QuarantineStore::with_root(qroot.path().join("q")).unwrap();
        let staging = tempfile::tempdir().unwrap();
        let wheel = staging.path().join("pkg-1.0-py3-none-any.whl");
        std::fs::write(&wheel, b"PK\x03\x04 wheel bytes").unwrap();
        // The lock pinned a DIFFERENT hash than the wheel's content.
        let locked = LockedHashes {
            all: vec![sha256_hex(b"some other content")],
            _by_req: BTreeMap::new(),
        };
        let err = ingest_staged_wheels(&store, staging.path(), &locked).unwrap_err();
        assert!(
            matches!(err, ResolverError::UnexpectedDownload(_)),
            "an unpinned wheel hash must be refused: {err:?}"
        );
    }

    #[test]
    fn ingest_accepts_pinned_wheel_and_quarantines_it() {
        let qroot = tempfile::tempdir().unwrap();
        let store = QuarantineStore::with_root(qroot.path().join("q")).unwrap();
        let staging = tempfile::tempdir().unwrap();
        let body = b"PK\x03\x04 a real-enough wheel body";
        let wheel = staging.path().join("pkg-1.0-py3-none-any.whl");
        std::fs::write(&wheel, body).unwrap();
        let digest = sha256_hex(body);
        let locked = LockedHashes {
            all: vec![digest.clone()],
            _by_req: BTreeMap::new(),
        };
        let arts = ingest_staged_wheels(&store, staging.path(), &locked).unwrap();
        assert_eq!(arts.len(), 1);
        assert_eq!(arts[0].sha256, digest);
        assert_eq!(arts[0].wheel_filename, "pkg-1.0-py3-none-any.whl");
        // The wheel is now a content-addressed blob in the quarantine.
        assert!(store.has_blob(&digest));
    }

    #[test]
    fn ingest_rejects_subdirectory_in_staging() {
        let qroot = tempfile::tempdir().unwrap();
        let store = QuarantineStore::with_root(qroot.path().join("q")).unwrap();
        let staging = tempfile::tempdir().unwrap();
        // pip unpacked an sdist into a subdir (a directory, not a file).
        std::fs::create_dir(staging.path().join("unpacked-sdist")).unwrap();
        let locked = LockedHashes {
            all: vec![],
            _by_req: BTreeMap::new(),
        };
        let err = ingest_staged_wheels(&store, staging.path(), &locked).unwrap_err();
        assert!(
            matches!(err, ResolverError::UnexpectedDownload(_)),
            "{err:?}"
        );
    }

    // ---- tool resolution ---------------------------------------------------

    #[cfg(all(unix, not(target_os = "linux")))]
    #[test]
    fn non_linux_unix_binding_reaches_tool_provenance_validation() {
        let missing_uv = PathBuf::from("/definitely-not-a-tirith-resolver/uv");
        let missing_python = PathBuf::from("/definitely-not-a-tirith-resolver/python3.12");
        let error = BoundResolverTools::bind(&ResolverTools {
            uv: missing_uv.clone(),
            python: missing_python,
        })
        .unwrap_err();

        assert!(
            matches!(error, ResolverError::ToolUntrusted { .. }),
            "invalid tool selection must fail closed: {error:?}"
        );
        assert!(
            error.to_string().contains(&missing_uv.display().to_string()),
            "Unix binding must validate the selected tool instead of rejecting the platform: {error}"
        );
        assert!(
            !error.to_string().contains("requires Linux"),
            "non-Linux Unix hosts must use the root-managed binding contract: {error}"
        );
    }

    #[cfg(unix)]
    #[test]
    fn bound_tool_digest_revalidation_detects_post_binding_mutation() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("uv");
        write_fake_bin(&path, "#!/bin/sh\nexit 0\n");
        let executable = TrustedExecutable::from_absolute(&path, &[]).unwrap();
        let expected = resolver_tool_digest(executable.launch_path()).unwrap();
        revalidate_bound_tool_digest(&executable, &expected, "uv").unwrap();

        write_fake_bin(&path, "#!/bin/sh\nexit 7\n");
        let error = revalidate_bound_tool_digest(&executable, &expected, "uv").unwrap_err();
        assert!(
            error.to_string().contains("bound uv"),
            "digest drift must be attributed to the bound tool: {error}"
        );
    }

    #[test]
    fn resolve_tool_missing_is_not_found() {
        let a = ResolverAllowances::default();
        let err = resolve_tool(
            "definitely-not-a-real-tool",
            &["definitely-not-a-real-tool-xyz123"],
            &a,
        )
        .unwrap_err();
        assert!(matches!(err, ResolverError::ToolNotFound(_)), "{err:?}");
    }

    #[cfg(unix)]
    #[test]
    fn resolve_tool_refuses_untrusted_first_path_hit_even_with_legacy_override() {
        use std::os::unix::fs::PermissionsExt as _;
        let dir = tempfile::tempdir().unwrap();
        let bin = dir.path().join("uv");
        std::fs::write(&bin, b"#!/bin/sh\nexit 0\n").unwrap();
        // A normal-looking 0755 file still fails because its PATH entry is under
        // the denied project/temp root. The legacy override is intentionally not
        // able to bypass canonical trusted-child provenance.
        std::fs::set_permissions(&bin, std::fs::Permissions::from_mode(0o755)).unwrap();
        let path = std::env::join_paths([dir.path()]).unwrap();
        let allowances = ResolverAllowances {
            allow_untrusted_tool: true,
            ..Default::default()
        };
        let res = resolve_tool_on_path("uv", &["uv"], &path, &[dir.path().to_path_buf()]);
        assert!(
            matches!(res, Err(ResolverError::ToolUntrusted { .. })),
            "untrusted PATH shadow must be refused: {res:?}; allowances={allowances:?}"
        );
    }

    #[cfg(unix)]
    #[test]
    fn resolve_tool_refuses_unowned_install_location_outside_denied_roots() {
        let dir = tempfile::tempdir().unwrap();
        let bin = dir.path().join("uv");
        write_fake_bin(&bin, "#!/bin/sh\nexit 0\n");
        let path = std::env::join_paths([dir.path()]).unwrap();

        let result = resolve_tool_on_path("uv", &["uv"], &path, &[]);
        assert!(
            matches!(result, Err(ResolverError::ToolUntrusted { .. })),
            "arbitrary user-owned PATH location must not establish install provenance: {result:?}"
        );
    }

    #[cfg(windows)]
    #[test]
    fn forged_windows_system_roots_cannot_auto_trust_path_tools() {
        let mut environment = GlobalStateGuard::new().expect("isolate resolver environment");
        let directory = tempfile::tempdir().unwrap();
        std::fs::write(directory.path().join("uv.exe"), b"not a trusted uv").unwrap();
        std::fs::write(directory.path().join("python.exe"), b"not a trusted python").unwrap();
        let path = std::env::join_paths([directory.path()]).unwrap();
        environment.set_env("ProgramFiles", directory.path());
        environment.set_env("ProgramFiles(x86)", directory.path());
        environment.set_env("SystemRoot", directory.path());
        environment.set_env("PATHEXT", ".EXE");

        let uv = resolve_tool_on_path("uv", &["uv"], &path, &[]);
        let python = resolve_tool_on_path("python", &["python3", "python"], &path, &[]);

        for result in [uv, python] {
            let error = result.unwrap_err();
            assert!(
                matches!(error, ResolverError::ToolUntrusted { .. }),
                "forged Windows system-root variables must not bypass enrollment: {error:?}"
            );
            assert!(
                error
                    .to_string()
                    .contains("explicit `tirith pkg trust-tool"),
                "the refusal must direct the operator to explicit enrollment: {error}"
            );
        }
    }

    #[cfg(unix)]
    #[test]
    fn resolver_tool_enrollment_pin_binds_canonical_path_and_digest() {
        let mut environment = GlobalStateGuard::new().expect("isolate resolver enrollment");
        let root = tempfile::Builder::new()
            .prefix("tirith-resolver-enrollment-")
            .tempdir_in(home::home_dir().expect("test home"))
            .unwrap();
        environment.set_env("XDG_CONFIG_HOME", root.path());

        let tool_dir = root.path().join("tools");
        std::fs::create_dir(&tool_dir).unwrap();
        let tool = tool_dir.join("uv");
        write_fake_bin(&tool, "#!/bin/sh\nexit 0\n");
        let canonical = tool.canonicalize().unwrap();
        let digest = resolver_tool_digest(&canonical).unwrap();
        let trust_file = resolver_tool_trust_file().unwrap();
        std::fs::create_dir_all(trust_file.parent().unwrap()).unwrap();
        let mut store = ResolverToolTrustStore::default();
        store
            .pins
            .insert(resolver_tool_store_key(&canonical).unwrap(), digest);
        crate::util::write_file_atomic_0600(&trust_file, &serde_json::to_vec(&store).unwrap())
            .unwrap();

        assert!(resolver_tool_pin_matches(&canonical).unwrap());
        write_fake_bin(&canonical, "#!/bin/sh\nexit 7\n");
        assert!(!resolver_tool_pin_matches(&canonical).unwrap());
    }

    #[cfg(unix)]
    #[test]
    fn resolver_tool_admission_rejects_colliding_non_unicode_parent_paths() {
        use std::ffi::OsString;
        use std::os::unix::ffi::OsStringExt as _;

        // Synthetic paths keep this regression portable to macOS filesystems
        // that reject invalid byte sequences at create-time. Linux and other
        // Unix filesystems can represent both paths exactly.
        let first = PathBuf::from(OsString::from_vec(b"/opt/install-\x80/python3".to_vec()));
        let second = PathBuf::from(OsString::from_vec(b"/opt/install-\x81/python3".to_vec()));

        assert_ne!(first, second);
        assert_eq!(
            first.display().to_string(),
            second.display().to_string(),
            "the regression requires two distinct paths that collide under Path::display"
        );
        for path in [&first, &second] {
            assert!(resolver_tool_store_key(path).is_err());
            let error = validate_resolver_tool_name("python", path).unwrap_err();
            assert!(error.contains("not valid Unicode"), "{error}");
        }
    }

    #[cfg(unix)]
    #[test]
    fn enrollment_rejects_insecure_existing_store_without_laundering_pins() {
        use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};

        let _environment = ResolverEnrollmentTestEnv::new();
        // A root-managed helper reaches the trust-store validation seam on every
        // Unix platform. User-owned script uv fixtures are intentionally rejected
        // earlier by the executable-eligibility gate.
        let tool = PathBuf::from("/bin/sh");

        let trust_file = resolver_tool_trust_file().unwrap();
        std::fs::create_dir_all(trust_file.parent().unwrap()).unwrap();
        let mut attacker_store = ResolverToolTrustStore::default();
        attacker_store
            .pins
            .insert("/attacker/uv".to_string(), "00".repeat(32));
        let attacker_bytes = serde_json::to_vec_pretty(&attacker_store).unwrap();
        std::fs::write(&trust_file, &attacker_bytes).unwrap();
        std::fs::set_permissions(&trust_file, std::fs::Permissions::from_mode(0o666)).unwrap();

        let error = enroll_resolver_tool(&tool).unwrap_err();
        assert!(
            error
                .to_string()
                .contains("owned by the current user and mode 0600"),
            "insecure pre-existing enrollment state must fail closed: {error}"
        );
        assert_eq!(
            std::fs::read(&trust_file).unwrap(),
            attacker_bytes,
            "rejected state must not be rewritten into a trusted file"
        );
        assert_ne!(
            std::fs::metadata(&trust_file).unwrap().mode() & 0o077,
            0,
            "rejected state must not be laundered to owner-only permissions"
        );
    }

    #[cfg(target_vendor = "apple")]
    #[test]
    fn resolver_trust_directory_rejects_mutating_macos_acl() {
        let directory = tempfile::Builder::new()
            .prefix("tirith-resolver-acl-")
            .tempdir_in(home::home_dir().expect("test home"))
            .unwrap();
        let status = std::process::Command::new("/bin/chmod")
            .args(["+a", "everyone allow write"])
            .arg(directory.path())
            .status()
            .unwrap();
        assert!(status.success(), "test must install a macOS extended ACL");

        let error = validate_resolver_trust_directory(directory.path()).unwrap_err();
        assert!(error.contains("ACL grants mutation"), "{error}");
    }

    #[cfg(unix)]
    #[test]
    fn path_discovery_digest_survives_public_path_shaped_api() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("uv");
        write_fake_bin(&path, "#!/bin/sh\nexit 0\n");
        let discovered = TrustedExecutable::from_absolute(&path, &[]).unwrap();
        remember_discovered_tool(&discovered).unwrap();

        write_fake_bin(&path, "#!/bin/sh\nexit 7\n");
        let rebound = TrustedExecutable::from_absolute(&path, &[]).unwrap();
        let error = revalidate_discovered_tool(&rebound).unwrap_err();
        assert!(error.contains("digest changed"), "{error}");
    }

    // ---- full pipeline with fake uv/python (unix) --------------------------

    /// Write a `0o755` shell-script "binary" at `path`. Mirrors the
    /// fake-binary pattern used elsewhere in the crate's subprocess tests.
    #[cfg(unix)]
    fn write_fake_bin(path: &Path, body: &str) {
        use std::os::unix::fs::PermissionsExt as _;
        let version_probe = match path.file_name().and_then(|name| name.to_str()) {
            Some("uv") => "if [ \"$1\" = \"--version\" ]; then echo 'uv 0.test'; exit 0; fi\n",
            Some(name) if name.starts_with("python") => {
                "if [ \"$1\" = \"-I\" ] && [ \"$2\" = \"-m\" ] && [ \"$3\" = \"pip\" ] && [ \"$4\" = \"--version\" ]; then echo 'pip 0.test'; exit 0; fi\n"
            }
            _ => "",
        };
        let rendered = match body.split_once('\n') {
            Some((shebang, rest)) if shebang.starts_with("#!") => {
                format!("{shebang}\n{version_probe}{rest}")
            }
            _ => format!("{version_probe}{body}"),
        };
        std::fs::write(path, rendered).unwrap();
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755)).unwrap();
    }

    #[cfg(unix)]
    struct ResolverEnrollmentTestEnv {
        root: tempfile::TempDir,
        _environment: GlobalStateGuard,
    }

    #[cfg(unix)]
    impl ResolverEnrollmentTestEnv {
        fn new() -> Self {
            let mut environment =
                GlobalStateGuard::new().expect("isolate resolver public API environment");
            let root = tempfile::Builder::new()
                .prefix("tirith-resolver-public-api-")
                .tempdir_in(home::home_dir().expect("test home"))
                .unwrap();
            environment.set_env("XDG_CONFIG_HOME", root.path().join("config"));
            Self {
                root,
                _environment: environment,
            }
        }

        fn tool_directory(&self) -> PathBuf {
            let directory = self.root.path().join("tools");
            std::fs::create_dir_all(&directory).unwrap();
            directory
        }

        fn enroll(&self, path: &Path) {
            // Install a legacy/raw pin directly. The enforcing tests below need
            // to prove that even a persisted pin cannot authorize script uv or
            // user-owned Python; the public enrollment API now rejects those
            // shapes before writing them.
            use std::os::unix::fs::PermissionsExt as _;

            let canonical = path.canonicalize().unwrap();
            let trust_file = resolver_tool_trust_file().unwrap();
            let trust_dir = trust_file.parent().unwrap();
            std::fs::create_dir_all(trust_dir).unwrap();
            std::fs::set_permissions(trust_dir, std::fs::Permissions::from_mode(0o700)).unwrap();
            let mut store = read_resolver_tool_trust_store(&trust_file)
                .unwrap()
                .unwrap_or_default();
            store.pins.insert(
                resolver_tool_store_key(&canonical).unwrap(),
                resolver_tool_digest(&canonical).unwrap(),
            );
            crate::util::write_file_atomic_0600(
                &trust_file,
                &serde_json::to_vec_pretty(&store).unwrap(),
            )
            .unwrap();
        }
    }

    #[cfg(unix)]
    #[test]
    fn public_resolver_tools_cannot_bypass_persisted_enrollment() {
        let environment = ResolverEnrollmentTestEnv::new();
        let bindir = environment.tool_directory();
        let uv = bindir.join("uv");
        let python = bindir.join("python3");
        write_fake_bin(&uv, "#!/bin/sh\nexit 0\n");
        write_fake_bin(&python, "#!/bin/sh\nexit 0\n");

        let error = BoundResolverTools::bind(&ResolverTools { uv, python }).unwrap_err();
        assert!(matches!(error, ResolverError::ToolUntrusted { .. }));
        assert!(
            error
                .to_string()
                .contains("explicit `tirith pkg trust-tool"),
            "public absolute paths must pass the same persisted provenance gate: {error}"
        );
    }

    #[cfg(unix)]
    #[test]
    fn whitespace_free_direct_url_is_rejected_before_any_child_io() {
        let bindir = tempfile::tempdir().unwrap();
        let marker = bindir.path().join("resolver-ran");
        let uv = bindir.path().join("uv");
        let python = bindir.path().join("python3");
        let body = format!("#!/bin/sh\nprintf ran > '{}'\nexit 99\n", marker.display());
        write_fake_bin(&uv, &body);
        write_fake_bin(&python, &body);
        let tools = ResolverTools { uv, python };

        let qroot = tempfile::tempdir().unwrap();
        let store = QuarantineStore::with_root(qroot.path().join("q")).unwrap();
        let txn = store.begin_transaction("d2-preflight").unwrap();
        let request = ResolverRequest::single(
            "examplepkg@https://unapproved.example/pkg-1.0-py3-none-any.whl",
        );
        let error = resolve_into_quarantine(&request, &tools, &txn).unwrap_err();
        assert!(
            matches!(error, ResolverError::RejectedRequirement { .. }),
            "{error:?}"
        );
        assert!(
            !marker.exists(),
            "input validation must complete before uv/python can execute"
        );
    }

    #[cfg(unix)]
    #[test]
    fn uv_stage_revalidates_auxiliary_python_before_spawn() {
        let directory = tempfile::tempdir().unwrap();
        let marker = directory.path().join("uv-ran");
        let uv_path = directory.path().join("uv");
        let python_path = directory.path().join("python3");
        write_fake_bin(
            &uv_path,
            &format!("#!/bin/sh\nprintf ran > '{}'\n", marker.display()),
        );
        write_fake_bin(&python_path, "#!/bin/sh\nexit 0\n");
        let uv = TrustedExecutable::from_absolute(&uv_path, &[]).unwrap();
        let python = TrustedExecutable::from_absolute(&python_path, &[]).unwrap();
        write_fake_bin(&python_path, "#!/bin/sh\nexit 9\n");

        let result = run_child_capped(
            &uv,
            &[],
            directory.path(),
            &python,
            "http://tirith:token@127.0.0.1:9",
            Duration::from_secs(1),
        );
        assert!(matches!(result, Err(ResolverError::Io(_))), "{result:?}");
        assert!(
            !marker.exists(),
            "uv must not run after Python identity drift"
        );
    }

    /// Even explicitly enrolled same-user fake tools cannot reach the compile or
    /// download stages of the enforcing resolver. Enrollment is analysis authority,
    /// not authority to supply uv/Python runtime dependencies to an install.
    #[cfg(unix)]
    #[test]
    fn enrolled_fake_pipeline_is_refused_before_execution() {
        let wheel_body = b"PK\x03\x04 fake but content-addressed wheel body for D2";
        let wheel_name = "examplepkg-1.0.0-py3-none-any.whl";
        let digest = sha256_hex(wheel_body);

        let environment = ResolverEnrollmentTestEnv::new();
        let bindir = environment.tool_directory();
        let uv = bindir.join("uv");
        let python = bindir.join("python3");

        // Fake uv: ignores everything except writing the lock to the path that
        // follows --output-file. The lock pins the wheel's known digest.
        let uv_script = format!(
            "#!/bin/sh\n\
             out=\"\"\n\
             while [ $# -gt 0 ]; do\n\
               if [ \"$1\" = \"--output-file\" ]; then shift; out=\"$1\"; fi\n\
               shift\n\
             done\n\
             if [ -z \"$out\" ]; then echo 'no --output-file' >&2; exit 2; fi\n\
             printf '%s\\n' 'examplepkg==1.0.0 \\' > \"$out\"\n\
             printf '    --hash=sha256:%s\\n' '{digest}' >> \"$out\"\n\
             exit 0\n"
        );
        write_fake_bin(&uv, &uv_script);

        // Fake python: only handles `-m pip download ... --dest <dir>` by writing
        // the wheel into <dir>. Other invocations exit 0 (no-op).
        let py_wheel_path = format!("/{wheel_name}");
        let py_script = format!(
            "#!/bin/sh\n\
             dest=\"\"\n\
             while [ $# -gt 0 ]; do\n\
               if [ \"$1\" = \"--dest\" ]; then shift; dest=\"$1\"; fi\n\
               shift\n\
             done\n\
             if [ -n \"$dest\" ]; then\n\
               printf 'PK\\003\\004 fake but content-addressed wheel body for D2' > \"$dest{py_wheel_path}\"\n\
             fi\n\
             exit 0\n"
        );
        write_fake_bin(&python, &py_script);
        environment.enroll(&uv);
        environment.enroll(&python);

        let qroot = tempfile::tempdir().unwrap();
        let store = QuarantineStore::with_root(qroot.path().join("q")).unwrap();
        let txn = store.begin_transaction("d2-pipeline").unwrap();

        let tools = ResolverTools { uv, python };
        let request = ResolverRequest::single("examplepkg==1.0.0");

        let error = resolve_into_quarantine(&request, &tools, &txn).unwrap_err();
        assert!(
            matches!(error, ResolverError::ToolUntrusted { .. }),
            "{error:?}"
        );
        assert!(
            !store.has_blob(&digest),
            "untrusted resolver scripts must not create a quarantined artifact"
        );
    }

    /// An enrolled user-writable toolchain is refused before an attacker can use
    /// even a nominally hash-pinned lock to reach the ingest stage.
    #[cfg(unix)]
    #[test]
    fn enrolled_fake_unpinned_pipeline_is_refused_before_execution() {
        let environment = ResolverEnrollmentTestEnv::new();
        let bindir = environment.tool_directory();
        let uv = bindir.join("uv");
        let python = bindir.join("python3");

        // uv pins a hash for content that the python step will NOT produce.
        let pinned = sha256_hex(b"the content the lock expects");
        let uv_script = format!(
            "#!/bin/sh\n\
             out=\"\"\n\
             while [ $# -gt 0 ]; do\n\
               if [ \"$1\" = \"--output-file\" ]; then shift; out=\"$1\"; fi\n\
               shift\n\
             done\n\
             printf '%s\\n' 'examplepkg==1.0.0 \\' > \"$out\"\n\
             printf '    --hash=sha256:%s\\n' '{pinned}' >> \"$out\"\n\
             exit 0\n"
        );
        write_fake_bin(&uv, &uv_script);

        // python drops a wheel with DIFFERENT bytes than the lock pinned.
        let py_script = "#!/bin/sh\n\
             dest=\"\"\n\
             while [ $# -gt 0 ]; do\n\
               if [ \"$1\" = \"--dest\" ]; then shift; dest=\"$1\"; fi\n\
               shift\n\
             done\n\
             if [ -n \"$dest\" ]; then\n\
               printf 'totally different wheel bytes' > \"$dest/examplepkg-1.0.0-py3-none-any.whl\"\n\
             fi\n\
             exit 0\n";
        write_fake_bin(&python, py_script);
        environment.enroll(&uv);
        environment.enroll(&python);

        let qroot = tempfile::tempdir().unwrap();
        let store = QuarantineStore::with_root(qroot.path().join("q")).unwrap();
        let txn = store.begin_transaction("d2-mismatch").unwrap();
        let tools = ResolverTools { uv, python };
        let request = ResolverRequest::single("examplepkg==1.0.0");

        let err = resolve_into_quarantine(&request, &tools, &txn).unwrap_err();
        assert!(
            matches!(err, ResolverError::ToolUntrusted { .. }),
            "{err:?}"
        );
    }

    /// The strict system-helper gate precedes execution, so an enrolled failing
    /// fake uv cannot run far enough to manufacture a compile diagnostic.
    #[cfg(unix)]
    #[test]
    fn enrolled_failing_uv_is_refused_before_execution() {
        let environment = ResolverEnrollmentTestEnv::new();
        let bindir = environment.tool_directory();
        let uv = bindir.join("uv");
        let python = bindir.join("python3");
        write_fake_bin(&uv, "#!/bin/sh\necho 'resolution failed' >&2\nexit 1\n");
        write_fake_bin(&python, "#!/bin/sh\nexit 0\n");
        environment.enroll(&uv);
        environment.enroll(&python);

        let qroot = tempfile::tempdir().unwrap();
        let store = QuarantineStore::with_root(qroot.path().join("q")).unwrap();
        let txn = store.begin_transaction("d2-compile-fail").unwrap();
        let tools = ResolverTools { uv, python };
        let request = ResolverRequest::single("examplepkg==1.0.0");

        let err = resolve_into_quarantine(&request, &tools, &txn).unwrap_err();
        assert!(
            matches!(err, ResolverError::ToolUntrusted { .. }),
            "{err:?}"
        );
    }

    /// Flag-drift guard: if a real `uv` is on PATH, the exact `uv_compile_args`
    /// we build must be ACCEPTED by it (parsed without an "unexpected argument"),
    /// run offline against an empty requirements file with `--no-index`. This
    /// catches a renamed/removed uv flag that the fake-binary pipeline tests
    /// cannot, while skipping cleanly where `uv` is absent (CI without uv). It
    /// asserts only that the flags parse, not resolution behavior.
    #[cfg(unix)]
    #[test]
    fn uv_compile_flags_accepted_by_real_uv() {
        let Some(uv) = find_on_path("uv") else {
            eprintln!("skipping: no uv on PATH");
            return;
        };
        let work = tempfile::tempdir().unwrap();
        let req = work.path().join("requirements.in");
        let lock = work.path().join("locked.txt");
        // Empty requirements -> uv resolves to nothing, but the FLAGS must parse.
        std::fs::write(&req, b"").unwrap();
        // Use the host's own python if present; otherwise a placeholder path is
        // fine because uv only fails on resolution, not on --python parsing, and
        // we are not asserting success, only the absence of a flag-parse error.
        let python = find_on_path("python3").unwrap_or_else(|| PathBuf::from("/usr/bin/python3"));
        let args = uv_compile_args(&req, &lock, &python, &[], &ResolverAllowances::default());
        let out = std::process::Command::new(&uv)
            .args(&args)
            .output()
            .expect("spawn uv");
        let stderr = String::from_utf8_lossy(&out.stderr);
        // Reject the three ways uv signals a bad argument set: an unknown flag, an
        // unrecognized form, and a mutually-exclusive flag combination (the last
        // is what `--no-build` + `--only-binary` would trigger).
        assert!(
            !stderr.contains("unexpected argument")
                && !stderr.contains("unrecognized")
                && !stderr.contains("cannot be used with"),
            "real uv rejected the argument set we build: {stderr}"
        );
    }

    #[test]
    fn resolver_request_single_is_locked_down() {
        let r = ResolverRequest::single("requests==2.31.0");
        assert_eq!(r.requirements, vec!["requests==2.31.0".to_string()]);
        assert!(r.index_urls.is_empty());
        assert_eq!(r.allowances, ResolverAllowances::default());
        // The default allowances refuse everything dangerous.
        assert!(!r.allowances.allow_sdist);
        assert!(!r.allowances.allow_vcs);
        assert!(!r.allowances.allow_editable);
        assert!(!r.allowances.allow_local_path);
        assert!(!r.allowances.allow_direct_url);
        assert!(!r.allowances.allow_untrusted_tool);
    }

    #[cfg(unix)]
    #[test]
    fn proven_chain_reuses_a_directory_but_still_refuses_a_bad_one() {
        // A directory proven once this pass is not re-proved, and a component
        // that fails is still refused even after its parent was accepted.
        let mut chain = ProvenChain::default();
        assert!(
            chain.path_chain_is_secure(std::path::Path::new("/usr")),
            "a root-managed system directory must pass"
        );
        assert!(
            chain.proven.contains(std::path::Path::new("/usr")),
            "a passing directory is remembered for this pass"
        );

        let writable = tempfile::tempdir().unwrap();
        let mut fresh = ProvenChain::default();
        assert!(
            !fresh.path_chain_is_secure(writable.path()),
            "a user-owned temp directory is not root-managed"
        );
        assert!(
            !fresh.proven.contains(writable.path()),
            "a refused component must never be remembered"
        );
    }

    #[test]
    fn editable_target_extraction_matches_pips_attached_form() {
        // pip's requirements parser is optparse-backed, so the attached form is
        // standard and `-e./pkg` is legitimate input. Both classifiers share one
        // helper so they cannot disagree about what the resolver child will do.
        assert_eq!(editable_requirement_target("-e"), Some(""));
        assert_eq!(editable_requirement_target("-e demo"), Some(" demo"));
        assert_eq!(editable_requirement_target("-e=demo"), Some("=demo"));
        assert_eq!(editable_requirement_target("-e./pkg"), Some("./pkg"));
        assert_eq!(
            editable_requirement_target("--editable=demo"),
            Some("=demo")
        );
        assert_eq!(editable_requirement_target("-r other.txt"), None);
        assert_eq!(editable_requirement_target("--index-url x"), None);

        // The extracted target is still re-validated, so an editable allowance
        // does not bypass the direct-URL / local-path controls.
        let denied = ResolverAllowances::default();
        assert!(
            validate_requirement("-e ./pkg", &denied).is_err(),
            "without allow_editable every -e form is refused"
        );
    }
}
