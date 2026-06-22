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
//! python -m pip download --only-binary=:all:                                       \
//!        --require-hashes -r locked.txt          -> wheels in a staging dir
//! ingest each wheel into the D1 quarantine        -> content-addressed blobs
//! ```
//!
//! `uv pip download` does not exist, so the two tools split the work: `uv`
//! resolves and emits the hash-pinned lock; `python -m pip download` fetches it
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
//! 5. **Explicit approved index URLs only.** The default index is dropped
//!    (`--no-index` unless indexes are supplied); any supplied index is the only
//!    place wheels may come from.
//! 6. **Credentials in an index URL refused.** [`validate_index_url`] rejects a
//!    `user:pass@host` index outright (no secret on a command line / in a lock).
//! 7. **Indexes pass through tirith's SSRF / domain policy.**
//!    [`validate_index_url`] runs each index through
//!    [`crate::url_validate::validate_server_url`] (HTTPS, no private / loopback /
//!    link-local / cloud-metadata destination).
//! 8. **`uv` / `python` resolved by executable provenance, not blind PATH.**
//!    [`resolve_tool`] finds the binary on `PATH`, then gathers
//!    [`crate::exec_provenance::provenance_of`] and refuses a world-writable
//!    target (anyone could swap it) unless policy permits an untrusted tool.
//!
//! npm / cargo resolution is intentionally absent here: the engine is wheel-only,
//! and the plan keeps `.tgz` / `.crate` / vendored-source behind hidden
//! experimental, resolve-and-inspect-metadata-only commands that **cannot
//! install** until hardened analyzers exist. This module enforces Python.

use std::collections::BTreeMap;
use std::ffi::OsStr;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use crate::artifact::quarantine::{QuarantineError, QuarantineStore, QuarantineTransaction};
use crate::exec_provenance::provenance_of;

/// Wall-clock ceiling for a single resolver child (`uv` compile or `pip`
/// download). A resolve that hangs past this is killed; the firewall never waits
/// unbounded on a network operation.
pub const RESOLVER_CHILD_TIMEOUT: Duration = Duration::from_secs(180);

/// Poll cadence while waiting on a resolver child.
const RESOLVER_POLL: Duration = Duration::from_millis(50);

/// Hard cap on requirement specs in one request, so a pathological input cannot
/// turn into an unbounded command line / lock.
const MAX_REQUIREMENTS: usize = 4096;

/// Hard cap on approved index URLs in one request.
const MAX_INDEX_URLS: usize = 64;

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
    /// Permit resolving with a tool binary that failed provenance (e.g.
    /// world-writable). Default `false`: a world-writable `uv` / `python` is
    /// refused, since anyone could replace it between resolution and exec.
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
    /// A tool was found but failed executable-provenance (world-writable) and
    /// [`ResolverAllowances::allow_untrusted_tool`] was not set.
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
    /// Absolute path to the `uv` binary used for `uv pip compile`.
    pub uv: PathBuf,
    /// Absolute path to the `python` interpreter used for `python -m pip`.
    pub python: PathBuf,
}

impl ResolverTools {
    /// Resolve `uv` and `python` (in that order) from `PATH`, applying executable
    /// provenance. Honors `allow_untrusted_tool`. The interpreter name tried is
    /// `python3` then `python`.
    pub fn discover(allowances: &ResolverAllowances) -> Result<Self, ResolverError> {
        let uv = resolve_tool("uv", &["uv"], allowances)?;
        let python = resolve_tool("python", &["python3", "python"], allowances)?;
        Ok(ResolverTools { uv, python })
    }
}

/// Resolve a tool by trying each candidate name on `PATH`, returning the first
/// existing executable whose provenance is acceptable. `label` names the tool in
/// errors. A world-writable binary is refused unless
/// [`ResolverAllowances::allow_untrusted_tool`] is set, since anyone could swap
/// it between resolution and exec (plan: resolve by executable provenance, not
/// blind PATH).
pub fn resolve_tool(
    label: &str,
    candidates: &[&str],
    allowances: &ResolverAllowances,
) -> Result<PathBuf, ResolverError> {
    for name in candidates {
        let Some(path) = find_on_path(name) else {
            continue;
        };
        let prov = provenance_of(&path);
        if !prov.exists {
            continue;
        }
        if prov.world_writable && !allowances.allow_untrusted_tool {
            return Err(ResolverError::ToolUntrusted {
                tool: path.display().to_string(),
                reason: format!(
                    "resolved {label} is world-writable (mode {}); anyone could replace it before \
                     it runs. Set the untrusted-tool allowance to override.",
                    prov.mode.as_deref().unwrap_or("?")
                ),
            });
        }
        return Ok(path);
    }
    Err(ResolverError::ToolNotFound(label.to_string()))
}

/// Find `name` on the process `PATH`, returning the first directory entry that is
/// an executable regular file. On Windows the `PATHEXT` extensions are tried.
/// This is the only PATH lookup; the resolved absolute path is what the child
/// runs, so the child never re-resolves a bare name in an attacker-influenced
/// `PATH`.
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
#[cfg(windows)]
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
    // A requirements-file include (`-r other.txt`) or any other dashed option is
    // refused: callers pass concrete specs, and a `-r` could pull an
    // attacker-controlled file of further requirements past these checks.
    if trimmed.starts_with('-') {
        // `-e` / `--editable` get a precise message; any other option is refused.
        let lower = trimmed.to_ascii_lowercase();
        if lower.starts_with("-e") || lower.starts_with("--editable") {
            if allowances.allow_editable {
                return Ok(());
            }
            return reject("editable installs (-e/--editable) are not permitted");
        }
        return reject("option-form requirements (leading '-') are not permitted");
    }
    // A control character (newline / CR / NUL / etc.) could smuggle a second
    // requirement or break the lock file; refuse outright.
    if trimmed.chars().any(|c| c.is_control()) {
        return reject("requirement contains a control character");
    }
    // VCS forms: `git+...`, `hg+`, `svn+`, `bzr+`, or a `name @ git+...` direct
    // reference.
    if is_vcs_requirement(trimmed) {
        if allowances.allow_vcs {
            return Ok(());
        }
        return reject("VCS requirements (git+/hg+/svn+/bzr+) are not permitted");
    }
    // Direct URL reference: `name @ https://.../x.whl` or a bare URL.
    if let Some(url) = direct_url_target(trimmed) {
        if allowances.allow_direct_url {
            // Even when permitted, a direct URL must still pass the SSRF / creds
            // policy applied to indexes.
            return validate_index_url(url).map_err(|e| match e {
                ResolverError::RejectedIndexUrl { reason, .. } => {
                    ResolverError::RejectedRequirement {
                        spec: spec.to_string(),
                        reason: format!("direct URL rejected: {reason}"),
                    }
                }
                other => other,
            });
        }
        return reject("direct-URL requirements (name @ url / bare url) are not permitted");
    }
    // Local path: an existing path, an explicit `./` or `../` prefix, an absolute
    // path, a `file:` scheme, or a Windows drive form. A bare distribution name
    // never looks like any of these.
    if is_local_path_requirement(trimmed) {
        if allowances.allow_local_path {
            return Ok(());
        }
        return reject("local-path requirements are not permitted");
    }
    // sdist-only requirements cannot be expressed by name alone (a `.tar.gz`
    // target is caught as a local path or direct URL above); source *building*
    // is blocked by `--no-build` / `--only-binary=:all:` at download time, and a
    // resolve that can only satisfy a name from an sdist is refused there.
    // Nothing further to gate here for a plain name spec.
    let _ = &allowances.allow_sdist;
    Ok(())
}

/// Whether `spec` is a VCS requirement (`git+`, `hg+`, `svn+`, `bzr+`), either as
/// a leading scheme or after a `name @ ` direct-reference marker.
fn is_vcs_requirement(spec: &str) -> bool {
    let candidate = match spec.split_once(" @ ") {
        Some((_, rest)) => rest.trim(),
        None => spec,
    };
    let lower = candidate.to_ascii_lowercase();
    ["git+", "hg+", "svn+", "bzr+"]
        .iter()
        .any(|p| lower.starts_with(p))
}

/// If `spec` is a direct-URL reference, return the URL. Matches a `name @ url`
/// direct reference and a bare `http(s)://` / `file://` requirement.
fn direct_url_target(spec: &str) -> Option<&str> {
    if let Some((_, rest)) = spec.split_once(" @ ") {
        let rest = rest.trim();
        let lower = rest.to_ascii_lowercase();
        if lower.starts_with("http://")
            || lower.starts_with("https://")
            || lower.starts_with("file://")
        {
            return Some(rest);
        }
    }
    let lower = spec.to_ascii_lowercase();
    if lower.starts_with("http://") || lower.starts_with("https://") {
        return Some(spec);
    }
    None
}

/// Whether `spec` denotes a local path rather than a named distribution.
fn is_local_path_requirement(spec: &str) -> bool {
    let lower = spec.to_ascii_lowercase();
    if lower.starts_with("file://") {
        return true;
    }
    // Explicit relative / absolute prefixes.
    if spec.starts_with("./")
        || spec.starts_with("../")
        || spec.starts_with(".\\")
        || spec.starts_with("..\\")
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
    // A path that exists on disk as given (a bare directory or archive name the
    // user dropped in cwd) is treated as a local path. A real distribution name
    // colliding with a cwd entry is vanishingly rare and erring toward refusal is
    // the safe default; the operator can pin a version to disambiguate.
    if Path::new(spec).exists() {
        return true;
    }
    false
}

/// Validate an index URL: HTTPS, no embedded credentials, and a public,
/// non-metadata destination, by delegating to the shared SSRF policy. The HTTP
/// override env var that [`crate::url_validate::validate_server_url`] honors is
/// the operator's to set; an attacker controlling the requirement input does not
/// control it.
pub fn validate_index_url(url: &str) -> Result<(), ResolverError> {
    // Reject embedded credentials explicitly first, with a precise message
    // (validate_server_url also rejects them, but the dedicated message makes the
    // "no secret in a URL" rule unambiguous in receipts / logs).
    if let Ok(parsed) = url::Url::parse(url) {
        if !parsed.username().is_empty() || parsed.password().is_some() {
            return Err(ResolverError::RejectedIndexUrl {
                url: url.to_string(),
                reason: "index URL carries embedded credentials".to_string(),
            });
        }
    }
    crate::url_validate::validate_server_url(url).map_err(|reason| {
        ResolverError::RejectedIndexUrl {
            url: url.to_string(),
            reason,
        }
    })
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
/// `~/.config/pip/pip.conf` or `~/.netrc` is the empty temp dir's, i.e. absent);
/// sets `PIP_ISOLATED=1`, `PIP_NO_INPUT=1`, `PIP_DISABLE_PIP_VERSION_CHECK=1`,
/// `PIP_CONFIG_FILE` to an absent file, `UV_NO_CONFIG=1`,
/// `UV_PYTHON_DOWNLOADS=never`, `UV_NO_PROGRESS=1`; and carries a minimal `PATH`
/// plus a deterministic `LC_ALL=C` / `LANG=C`. It does **not** carry any `*_TOKEN`
/// / `*_API_KEY` / `PIP_*` / `UV_*` / `NETRC` from the parent.
pub fn isolated_env(config_home: &Path, python: &Path) -> Vec<(String, String)> {
    let home = config_home.display().to_string();
    // A config file path inside the empty config home that does not exist, so any
    // tool consulting PIP_CONFIG_FILE finds nothing.
    let absent_pip_conf = config_home.join("no-such-pip.conf").display().to_string();
    // A minimal PATH so the child can still find shared libraries' helpers if it
    // must, but containing only the resolved python's own directory plus the
    // standard system bins. We do NOT forward the parent PATH wholesale.
    let mut path_dirs: Vec<String> = Vec::new();
    if let Some(py_dir) = python.parent() {
        path_dirs.push(py_dir.display().to_string());
    }
    #[cfg(windows)]
    {
        if let Ok(sysroot) = std::env::var("SystemRoot") {
            path_dirs.push(format!("{sysroot}\\System32"));
            path_dirs.push(sysroot);
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
        // pip isolation.
        ("PIP_ISOLATED".to_string(), "1".to_string()),
        ("PIP_NO_INPUT".to_string(), "1".to_string()),
        ("PIP_DISABLE_PIP_VERSION_CHECK".to_string(), "1".to_string()),
        ("PIP_CONFIG_FILE".to_string(), absent_pip_conf),
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
    // Keep a system-root variable on Windows so DLL resolution works even though
    // we scrubbed the rest of the environment.
    #[cfg(windows)]
    {
        if let Ok(sysroot) = std::env::var("SystemRoot") {
            env.push(("SystemRoot".to_string(), sysroot));
        }
        if let Ok(windir) = std::env::var("windir") {
            env.push(("windir".to_string(), windir));
        }
    }
    env
}

/// Apply [`isolated_env`] to a [`Command`]: `env_clear` then set exactly the
/// scrubbed pairs, plus a working directory of `config_home` so a tool that
/// reads a cwd-relative `pip.conf` / `setup.cfg` sees only the empty temp dir.
fn apply_isolation(cmd: &mut Command, config_home: &Path, python: &Path) {
    cmd.env_clear();
    for (k, v) in isolated_env(config_home, python) {
        cmd.env(k, v);
    }
    cmd.current_dir(config_home);
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
fn pip_download_args(locked: &Path, dest_dir: &Path, index_urls: &[String]) -> Vec<String> {
    let mut args: Vec<String> = vec![
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
/// cwd are already configured by the caller via [`apply_isolation`].
fn run_child_capped(
    program: &Path,
    args: &[String],
    config_home: &Path,
    python: &Path,
    timeout: Duration,
) -> Result<ChildOutput, ResolverError> {
    let mut cmd = Command::new(program);
    cmd.args(args.iter().map(OsStr::new))
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    apply_isolation(&mut cmd, config_home, python);

    let mut child = cmd.spawn().map_err(ResolverError::Io)?;
    // Drain both pipes on helper threads so a chatty child cannot deadlock on a
    // full pipe buffer while we poll.
    let stdout = child.stdout.take();
    let stderr = child.stderr.take();
    let out_handle = stdout.map(|mut s| {
        std::thread::spawn(move || {
            use std::io::Read as _;
            let mut buf = Vec::new();
            let _ = s.read_to_end(&mut buf);
            buf
        })
    });
    let err_handle = stderr.map(|mut s| {
        std::thread::spawn(move || {
            use std::io::Read as _;
            let mut buf = Vec::new();
            let _ = s.read_to_end(&mut buf);
            buf
        })
    });

    let deadline = Instant::now() + timeout;
    loop {
        match child.try_wait() {
            Ok(Some(status)) => {
                let stdout = out_handle.and_then(|h| h.join().ok()).unwrap_or_default();
                let stderr = err_handle.and_then(|h| h.join().ok()).unwrap_or_default();
                return Ok(ChildOutput {
                    success: status.success(),
                    stdout,
                    stderr,
                });
            }
            Ok(None) => {
                if Instant::now() >= deadline {
                    let _ = child.kill();
                    let _ = child.wait();
                    if let Some(h) = out_handle {
                        let _ = h.join();
                    }
                    if let Some(h) = err_handle {
                        let _ = h.join();
                    }
                    return Err(ResolverError::Timeout(format!(
                        "{} exceeded {}s",
                        program.display(),
                        timeout.as_secs()
                    )));
                }
                std::thread::sleep(RESOLVER_POLL);
            }
            Err(e) => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(ResolverError::Io(e));
            }
        }
    }
}

/// Captured output of a resolver child.
struct ChildOutput {
    success: bool,
    stdout: Vec<u8>,
    stderr: Vec<u8>,
}

impl ChildOutput {
    /// Merged stdout+stderr as a lossy string, truncated for an error message so
    /// a verbose tool cannot blow up a log line.
    fn diagnostics(&self) -> String {
        let mut s = String::new();
        s.push_str(&String::from_utf8_lossy(&self.stdout));
        if !self.stderr.is_empty() {
            s.push('\n');
            s.push_str(&String::from_utf8_lossy(&self.stderr));
        }
        crate::util::truncate_bytes(s.trim(), 4000)
    }
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
    // 1. Pre-flight validation of every input BEFORE any subprocess runs.
    for spec in &request.requirements {
        validate_requirement(spec, &request.allowances)?;
    }
    for url in &request.index_urls {
        validate_index_url(url)?;
    }

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
    let compile_args = uv_compile_args(
        &requirements_in,
        &lock_path,
        &tools.python,
        &request.index_urls,
        &request.allowances,
    );
    let compile = run_child_capped(
        &tools.uv,
        &compile_args,
        &config_home,
        &tools.python,
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
    let download_args = pip_download_args(&lock_path, &staging, &request.index_urls);
    let download = run_child_capped(
        &tools.python,
        &download_args,
        &config_home,
        &tools.python,
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
            "https://example.invalid/x-1.0-py3-none-any.whl",
        ] {
            assert!(
                matches!(
                    validate_requirement(spec, &def),
                    Err(ResolverError::RejectedRequirement { .. })
                ),
                "{spec:?} should be refused"
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
        // allowed, because it still flows through validate_index_url -> SSRF.
        let err =
            validate_requirement("x @ http://127.0.0.1/x-1.0-py3-none-any.whl", &a).unwrap_err();
        assert!(
            matches!(err, ResolverError::RejectedRequirement { .. }),
            "loopback direct URL must be refused: {err:?}"
        );
        // A plain-HTTP public URL is rejected (validate_server_url requires HTTPS
        // unless TIRITH_ALLOW_HTTP is set, which it is not here).
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
        // A public HTTPS index passes. This resolves a real public host, so on a
        // fully offline runner DNS fails; that is an environment limitation, not a
        // policy rejection, so we only assert the *shape* of an offline failure
        // (a resolution error, never a scheme/creds/SSRF rejection).
        match validate_index_url("https://pypi.org/simple") {
            Ok(()) => {}
            Err(ResolverError::RejectedIndexUrl { reason, .. }) => {
                assert!(
                    reason.contains("resolve"),
                    "a public HTTPS index must only fail on DNS resolution offline, got: {reason}"
                );
            }
            other => panic!("unexpected error for a public HTTPS index: {other:?}"),
        }
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
        // The pip config file points at a non-existent path inside the temp home.
        let cfg = map.get("PIP_CONFIG_FILE").copied().unwrap();
        assert!(cfg.starts_with(&dir.path().display().to_string()));
        assert!(!Path::new(cfg).exists());
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
        let args = pip_download_args(lock, dest, &[]);
        let joined = args.join(" ");
        assert!(joined.starts_with("-m pip download"), "{joined}");
        assert!(joined.contains("--only-binary :all:"), "{joined}");
        assert!(joined.contains("--require-hashes"), "{joined}");
        assert!(joined.contains("--no-deps"), "{joined}");
        assert!(joined.contains("--isolated"), "{joined}");
        assert!(joined.contains("--no-cache-dir"), "{joined}");
        assert!(joined.contains("--no-index"), "{joined}");
        assert!(joined.contains("--dest /w/staging"), "{joined}");
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
    fn resolve_tool_refuses_world_writable_by_default() {
        use std::os::unix::fs::PermissionsExt as _;
        let dir = tempfile::tempdir().unwrap();
        let bin = dir.path().join("uv");
        std::fs::write(&bin, b"#!/bin/sh\nexit 0\n").unwrap();
        // World-writable + executable.
        std::fs::set_permissions(&bin, std::fs::Permissions::from_mode(0o777)).unwrap();
        // Put the dir on PATH for the lookup.
        let orig = std::env::var_os("PATH");
        let new_path = match &orig {
            Some(p) => {
                let mut v = std::ffi::OsString::from(dir.path());
                v.push(":");
                v.push(p);
                v
            }
            None => std::ffi::OsString::from(dir.path()),
        };
        // SAFETY: single-threaded test; restored immediately after.
        std::env::set_var("PATH", &new_path);
        let def = ResolverAllowances::default();
        let res = resolve_tool("uv", &["uv"], &def);
        // Restore PATH before asserting.
        match orig {
            Some(p) => std::env::set_var("PATH", p),
            None => std::env::remove_var("PATH"),
        }
        assert!(
            matches!(res, Err(ResolverError::ToolUntrusted { .. })),
            "world-writable tool must be refused by default: {res:?}"
        );
    }

    // ---- full pipeline with fake uv/python (unix) --------------------------

    /// Write a `0o755` shell-script "binary" at `path`. Mirrors the
    /// fake-binary pattern used elsewhere in the crate's subprocess tests.
    #[cfg(unix)]
    fn write_fake_bin(path: &Path, body: &str) {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::write(path, body).unwrap();
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755)).unwrap();
    }

    /// End to end: a fake `uv` emits a hash-pinned lock for one wheel, a fake
    /// `python -m pip download` drops that exact wheel into `--dest`, and the
    /// resolver ingests it into the quarantine. Proves the compile -> verify ->
    /// download -> ingest pipeline and that the locked hash governs the ingest.
    #[cfg(unix)]
    #[test]
    fn resolve_into_quarantine_full_pipeline_with_fakes() {
        let wheel_body = b"PK\x03\x04 fake but content-addressed wheel body for D2";
        let wheel_name = "examplepkg-1.0.0-py3-none-any.whl";
        let digest = sha256_hex(wheel_body);

        let bindir = tempfile::tempdir().unwrap();
        let uv = bindir.path().join("uv");
        let python = bindir.path().join("python3");

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

        let qroot = tempfile::tempdir().unwrap();
        let store = QuarantineStore::with_root(qroot.path().join("q")).unwrap();
        let txn = store.begin_transaction("d2-pipeline").unwrap();

        let tools = ResolverTools {
            uv: uv.clone(),
            python: python.clone(),
        };
        let request = ResolverRequest::single("examplepkg==1.0.0");

        let resolved = resolve_into_quarantine(&request, &tools, &txn)
            .expect("the fake pipeline should resolve and quarantine one wheel");
        assert_eq!(resolved.artifacts.len(), 1);
        assert_eq!(resolved.artifacts[0].sha256, digest);
        assert_eq!(resolved.artifacts[0].wheel_filename, wheel_name);
        assert!(
            resolved.locked_requirements.contains(&digest),
            "the returned lock must carry the pinned hash"
        );
        // The wheel is a content-addressed blob in the quarantine now.
        assert!(store.has_blob(&digest));
    }

    /// If the fake `python` drops a wheel whose content the lock did NOT pin, the
    /// resolver refuses it (the lock's hash set is the allow-list for the ingest).
    #[cfg(unix)]
    #[test]
    fn resolve_into_quarantine_refuses_unpinned_download() {
        let bindir = tempfile::tempdir().unwrap();
        let uv = bindir.path().join("uv");
        let python = bindir.path().join("python3");

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

        let qroot = tempfile::tempdir().unwrap();
        let store = QuarantineStore::with_root(qroot.path().join("q")).unwrap();
        let txn = store.begin_transaction("d2-mismatch").unwrap();
        let tools = ResolverTools { uv, python };
        let request = ResolverRequest::single("examplepkg==1.0.0");

        let err = resolve_into_quarantine(&request, &tools, &txn).unwrap_err();
        assert!(
            matches!(err, ResolverError::UnexpectedDownload(_)),
            "an unpinned download must be refused: {err:?}"
        );
    }

    /// A failing `uv` (non-zero exit) surfaces as `CompileFailed`, never a silent
    /// proceed.
    #[cfg(unix)]
    #[test]
    fn resolve_into_quarantine_compile_failure_is_fail_closed() {
        let bindir = tempfile::tempdir().unwrap();
        let uv = bindir.path().join("uv");
        let python = bindir.path().join("python3");
        write_fake_bin(&uv, "#!/bin/sh\necho 'resolution failed' >&2\nexit 1\n");
        write_fake_bin(&python, "#!/bin/sh\nexit 0\n");

        let qroot = tempfile::tempdir().unwrap();
        let store = QuarantineStore::with_root(qroot.path().join("q")).unwrap();
        let txn = store.begin_transaction("d2-compile-fail").unwrap();
        let tools = ResolverTools { uv, python };
        let request = ResolverRequest::single("examplepkg==1.0.0");

        let err = resolve_into_quarantine(&request, &tools, &txn).unwrap_err();
        assert!(
            matches!(err, ResolverError::CompileFailed(_)),
            "a failing uv must fail closed: {err:?}"
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
}
