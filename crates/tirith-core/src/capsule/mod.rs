//! Runtime containment capsule — portable type layer (Stack E, unit E1).
//!
//! This module holds the portable policy layer: the [`Capsule`] trait, the
//! [`CapsuleSpec`] that describes what to contain, the per-capability
//! [`CapsuleCoverage`] honesty ledger, the policy sub-structs ([`NetworkPolicy`],
//! [`FilesystemPolicy`], [`EnvironmentPolicy`], [`ResourceLimits`],
//! [`HandlePolicy`]), authenticated/canonical filesystem-root validation, the
//! [`deny_default_paths`] baseline, and the always-degraded [`NoOpCapsule`]. The
//! OS-specific backends (Landlock/seccomp on Linux, Seatbelt on macOS,
//! AppContainer/Job Objects on Windows) arrive in E2-E4; the async egress broker
//! that funnels allow-listed traffic lives in the CLI crate
//! (`tirith::cli::capsule_proxy`) because it needs `tokio`/`hyper`, and
//! `tirith-core` stays async-free.
//!
//! The Windows backend (E4) is split: the portable, host-testable planning layer
//! (the `AppContainerCapsule`, coverage derivation, the AppContainer profile /
//! SID-name derivation, Job Object limits, ACL grants, and the assembled launch
//! plan) lives here in [`windows`]; the `windows`-crate Win32 calls that *apply* it
//! (`CreateAppContainerProfile`, `SetEntriesInAclW`, `STARTUPINFOEXW` +
//! `CreateProcessW`, Job Objects) live in the CLI crate
//! (`tirith::cli::capsule_windows`), because the `windows` crate is a CLI-crate
//! dependency and `tirith-core` stays free of OS-API bindings.
//!
//! ## Containment honesty + fail-closed (cross-cutting invariant 2)
//!
//! A backend NEVER reports a capability it did not actually enforce.
//! [`CapsuleCoverage`] carries an explicit boolean per capability; a backend sets
//! a flag to `true` only after the OS mechanism that enforces it is in place. A
//! surface that *promises* containment (e.g. `tirith pkg install`) consults
//! [`CapsuleCoverage::is_degraded`] / the specific flags and **fails closed**
//! under degraded coverage unless policy explicitly permits degraded operation.
//! [`NoOpCapsule`] reports everything `false` and, critically, never claims
//! egress — so a missing backend can never be mistaken for a working one.
//!
//! ## The egress proxy is a broker, not the boundary (cross-cutting invariant 3)
//!
//! [`NetworkPolicy::AllowListedDomains`] only describes *intent*. Domain-egress
//! enforcement (`domain_proxy_enforced = true`) may be claimed ONLY where the OS
//! backend blocks raw outbound sockets except to the loopback broker. The broker
//! itself (in the CLI crate) re-resolves once, validates every IP against the
//! same public/non-public classifier the URL validators use, pins the TLS SNI to
//! the approved CONNECT host, and caps connections/bytes/handshake/idle. These
//! types only carry the policy; they assert nothing about enforcement.

use std::collections::BTreeSet;
use std::ffi::{OsStr, OsString};
use std::path::{Component, Path, PathBuf};

use serde::{Deserialize, Serialize};

/// Stable compatibility constant. Runtime classification queries the typed
/// registry through [`crate::sensitive_assets`].
pub const SENSITIVE_ENV_EXACT: &[&str] = &[
    "GITHUB_TOKEN",
    "GH_TOKEN",
    "NPM_TOKEN",
    "NODE_AUTH_TOKEN",
    "OPENAI_API_KEY",
    "ANTHROPIC_API_KEY",
    "DOCKER_CONFIG",
    "KUBECONFIG",
    "SSH_AUTH_SOCK",
    "GPG_AGENT_INFO",
];

/// Stable compatibility constant. Runtime classification queries the typed
/// registry through [`crate::sensitive_assets`].
pub const SENSITIVE_ENV_PREFIXES: &[&str] = &[
    "AWS_",
    "AZURE_",
    "GOOGLE_",
    "UV_INDEX",
    "PIP_INDEX",
    "TWINE_",
];

/// Linux runtime-containment backend (Stack E, unit E2): the
/// `LandlockSeccompCapsule` and the internal-launcher containment primitive that
/// applies rlimits -> `PR_SET_NO_NEW_PRIVS` -> Landlock -> seccomp -> env cleanup
/// in a freshly-`exec`'d single-threaded child, NOT inside `pre_exec`. Gated to
/// Linux so macOS / Windows targets compile without `landlock` / `extrasafe`.
#[cfg(target_os = "linux")]
pub mod linux;

/// macOS runtime-containment backend (Stack E, unit E3): the `SeatbeltCapsule`,
/// which builds an SBPL profile (`(deny default)` + the spec's grants, `(deny
/// network*)` except the loopback broker) and probes the system `sandbox-exec`
/// wrapper, reporting honest [`CapsuleCoverage`] (an absent/removed
/// `sandbox-exec` yields degraded coverage, never a silent NoOp success). Gated
/// to macOS; it needs no extra crates (Seatbelt is driven through the OS
/// `sandbox-exec` binary), so the profile/argv builders are pure and the other
/// targets compile without it.
#[cfg(target_os = "macos")]
pub mod macos;

/// Windows runtime-containment backend (Stack E, unit E4): the
/// [`windows::AppContainerCapsule`] plus the **pure, host-testable** planning layer
/// it hands the CLI executor — the AppContainer profile / package-SID-name
/// derivation, the Job Object resource ceilings, the ACL grant list, and the
/// assembled launch plan (program + `CreateProcessW` command line, `bInheritHandles
/// = FALSE`). The `windows`-crate Win32 calls that apply the plan live in the CLI
/// crate (`tirith::cli::capsule_windows`), so this module needs no `windows`
/// dependency and compiles + tests on every target (the dev host as well as the
/// Windows runner). `available_coverage` reports honest [`CapsuleCoverage`] (no
/// AppContainer support -> degraded, never a silent NoOp success), and an
/// allow-listed-domains spec is degraded on `domain_proxy_enforced` until E5 wires
/// the broker. Declared unconditionally (it pulls in no OS-specific crate); the
/// runtime probe reports support only on the `windows` target.
pub mod windows;

// Sensitive environment variables stripped from a contained child whenever
// `EnvironmentPolicy::deny_sensitive` is set are classified by the typed central
// exact/prefix registry. Public RPC endpoint names are deliberately not
// credentials, while token/key/password kinds remain denied.

/// Per-capability containment ledger. **The honesty contract of the whole
/// capsule layer (cross-cutting invariant 2).**
///
/// Each field is `true` ONLY when the backend put a real OS mechanism in place
/// that enforces that capability for the spawned child. A field left `false`
/// means "not enforced" — never "assumed". Enforcing surfaces read these flags
/// and fail closed when the coverage they require is missing.
///
/// Coverage is *descriptive*: producing a `CapsuleCoverage` does not contain
/// anything; a backend constructs it to report what it actually achieved.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct CapsuleCoverage {
    /// Filesystem **read** access is confined to the allow-listed roots.
    pub fs_read_enforced: bool,
    /// Filesystem **write** access is confined to the allow-listed roots.
    pub fs_write_enforced: bool,
    /// Process spawning / `exec` is restricted (e.g. seccomp denies `execve`
    /// outside the launcher, or no new privileges via `PR_SET_NO_NEW_PRIVS`).
    pub exec_limited: bool,
    /// Raw outbound sockets are denied at the OS layer (the precondition for any
    /// domain-egress claim). When this is `false`, the broker is NOT a boundary.
    pub network_raw_denied: bool,
    /// Domain egress is enforced *through the broker*. May be `true` ONLY when
    /// [`Self::network_raw_denied`] is also `true` (invariant 3).
    pub domain_proxy_enforced: bool,
    /// At least one resource limit was requested, and **every populated** CPU /
    /// memory / process-count / open-files / output-size / wall-clock dimension
    /// from [`ResourceLimits`] is enforced by the selected backend and wrapper.
    pub resource_limits_enforced: bool,
    /// The child's environment was scrubbed of sensitive variables and given an
    /// isolated HOME/TMPDIR per [`EnvironmentPolicy`].
    pub env_isolated: bool,
    /// Inherited handles/file descriptors were closed down to the explicit
    /// allow-list (Unix: stdio + broker FDs only; Windows: `bInheritHandles=FALSE`
    /// or an explicit allow-list) per [`HandlePolicy`].
    pub handles_isolated: bool,
}

impl CapsuleCoverage {
    /// A coverage ledger with every capability **unenforced**. The honest
    /// starting point for any backend (it raises flags as it applies mechanisms)
    /// and the permanent state of [`NoOpCapsule`].
    pub const NONE: CapsuleCoverage = CapsuleCoverage {
        fs_read_enforced: false,
        fs_write_enforced: false,
        exec_limited: false,
        network_raw_denied: false,
        domain_proxy_enforced: false,
        resource_limits_enforced: false,
        env_isolated: false,
        handles_isolated: false,
    };

    /// True when ANY capability the spec asked for is not enforced. Enforcing
    /// surfaces use this (against the spec's requirements) to decide whether to
    /// fail closed. Pure NoOp coverage is always degraded.
    ///
    /// `required` is the coverage the calling surface *demands*; this returns
    /// `true` if any required flag is not satisfied by `self`.
    pub fn is_degraded_against(&self, required: &CapsuleCoverage) -> bool {
        (required.fs_read_enforced && !self.fs_read_enforced)
            || (required.fs_write_enforced && !self.fs_write_enforced)
            || (required.exec_limited && !self.exec_limited)
            || (required.network_raw_denied && !self.network_raw_denied)
            || (required.domain_proxy_enforced && !self.domain_proxy_enforced)
            || (required.resource_limits_enforced && !self.resource_limits_enforced)
            || (required.env_isolated && !self.env_isolated)
            || (required.handles_isolated && !self.handles_isolated)
    }

    /// True when no capability at all is enforced (the NoOp / total-degradation
    /// signal). A convenience for surfaces that demand *some* containment.
    pub fn is_fully_unenforced(&self) -> bool {
        *self == CapsuleCoverage::NONE
    }

    /// Invariant 3 self-check: a coverage ledger is **incoherent** if it claims
    /// domain-egress enforcement without also denying raw sockets. A backend must
    /// never emit such a ledger; the broker is not a boundary on its own.
    pub fn egress_claim_is_coherent(&self) -> bool {
        !self.domain_proxy_enforced || self.network_raw_denied
    }
}

/// Network containment intent for the child.
///
/// This is *policy*, not enforcement. Whether `AllowListedDomains` is actually
/// honored depends on the backend setting
/// [`CapsuleCoverage::domain_proxy_enforced`] (which itself requires
/// [`CapsuleCoverage::network_raw_denied`]).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "mode", rename_all = "snake_case")]
pub enum NetworkPolicy {
    /// No network capability at all. The target for `pkg install` (installs never
    /// need outbound traffic once the artifacts are quarantined).
    DenyAll,
    /// Outbound traffic is permitted ONLY to the listed domains, and ONLY through
    /// the loopback broker. The `ports` set bounds which CONNECT ports the broker
    /// will honor. Claiming this is *enforced* requires a backend that blocks raw
    /// sockets (invariant 3); otherwise the surface degrades and (for enforcing
    /// commands) fails closed.
    AllowListedDomains {
        /// Lower-cased, trailing-dot-stripped domain names the child may reach.
        domains: BTreeSet<String>,
        /// CONNECT ports the broker may honor (typically `{443}`). Empty means
        /// "no port permitted" — a deliberately useless policy the caller should
        /// not construct.
        ports: BTreeSet<u16>,
    },
}

impl Default for NetworkPolicy {
    /// Deny-all by default: a capsule that does not opt into egress gets none.
    fn default() -> Self {
        NetworkPolicy::DenyAll
    }
}

impl NetworkPolicy {
    /// Whether this policy permits the broker to reach `host` on `port`. The
    /// broker re-checks this on every CONNECT in addition to its IP validation;
    /// this is the *policy* gate, not the SSRF gate.
    pub fn permits(&self, host: &str, port: u16) -> bool {
        match self {
            NetworkPolicy::DenyAll => false,
            NetworkPolicy::AllowListedDomains { domains, ports } => {
                let host_norm = host.trim_end_matches('.').to_ascii_lowercase();
                ports.contains(&port) && domains.contains(&host_norm)
            }
        }
    }

    /// True when the policy permits no egress at all.
    pub fn is_deny_all(&self) -> bool {
        matches!(self, NetworkPolicy::DenyAll)
    }
}

/// Filesystem containment intent: the read/write roots the child is confined to.
///
/// Paths are additive allow-lists layered over [`deny_default_paths`]. Backends
/// that cannot prove a deny rule overrides a covering allow MUST reject an
/// overlapping policy through [`canonicalize_and_validate_filesystem_policy`]
/// before launch; an allow root is never an implicit re-grant of a denied root.
/// The backend turns validated roots into Landlock rules / Seatbelt allow clauses
/// / AppContainer ACLs.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct FilesystemPolicy {
    /// Roots the child may read from (recursively).
    #[serde(default)]
    pub read_roots: Vec<PathBuf>,
    /// Roots the child may write to (recursively). A write root implies read.
    #[serde(default)]
    pub write_roots: Vec<PathBuf>,
    /// Sensitive subtrees to deny even if a broader read/write root would cover
    /// them. Seeded from [`deny_default_paths`]; callers may extend it.
    #[serde(default)]
    pub deny_roots: Vec<PathBuf>,
}

impl FilesystemPolicy {
    /// A policy that grants nothing beyond the implicit baseline and denies the
    /// default sensitive subtrees. Callers add the specific roots a task needs.
    pub fn deny_by_default() -> Self {
        FilesystemPolicy {
            read_roots: Vec::new(),
            write_roots: Vec::new(),
            deny_roots: deny_default_paths(),
        }
    }
}

/// A filesystem policy could not be canonicalized into an unambiguous set of
/// allow and deny roots. Capsule backends surface this as degraded filesystem
/// coverage and refuse an enforcing launch before changing process state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FilesystemPolicyError {
    message: String,
}

impl FilesystemPolicyError {
    fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}

impl std::fmt::Display for FilesystemPolicyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for FilesystemPolicyError {}

/// Canonicalize every filesystem-policy root and reject any allow/deny overlap.
///
/// Landlock v1, the emitted Seatbelt profile, and the AppContainer ACL grant plan
/// all express positive recursive grants but have no independently-proven deny
/// carve-out that overrides a covering grant. For those backends, accepting an
/// allowed parent of a denied credential path would silently erase the deny.
/// This shared gate therefore:
///
/// - resolves relative paths against the current directory;
/// - lexically removes `.` / `..` without permitting traversal above a root;
/// - canonicalizes the longest existing prefix, resolving symlinks and junctions
///   even when the final requested path does not exist yet;
/// - deduplicates equivalent roots; and
/// - rejects equal roots or containment in either direction between an allow root
///   and a deny root.
///
/// The returned policy, rather than the caller's original spelling, is what a
/// backend must apply. This closes a validate-one-path/use-an-alias gap.
pub fn canonicalize_and_validate_filesystem_policy(
    policy: &FilesystemPolicy,
) -> Result<FilesystemPolicy, FilesystemPolicyError> {
    let read_roots = canonicalize_root_set(&policy.read_roots, "read")?;
    let write_roots = canonicalize_root_set(&policy.write_roots, "write")?;
    let deny_roots = canonicalize_root_set(&policy.deny_roots, "deny")?;

    for (allow_kind, allow_roots) in [("read", &read_roots), ("write", &write_roots)] {
        for allow in allow_roots {
            for deny in &deny_roots {
                if paths_overlap(allow, deny) {
                    return Err(FilesystemPolicyError::new(format!(
                        "{allow_kind} allow root {} overlaps deny root {}; this backend cannot prove an explicit deny carve-out",
                        allow.display(),
                        deny.display()
                    )));
                }
            }
        }
    }

    Ok(FilesystemPolicy {
        read_roots,
        write_roots,
        deny_roots,
    })
}

fn canonicalize_root_set(
    roots: &[PathBuf],
    root_kind: &str,
) -> Result<Vec<PathBuf>, FilesystemPolicyError> {
    let mut canonical: Vec<PathBuf> = Vec::with_capacity(roots.len());
    for (index, root) in roots.iter().enumerate() {
        let root = canonicalize_policy_root(root, root_kind, index)?;
        if !canonical
            .iter()
            .any(|existing| paths_equivalent(existing, &root))
        {
            canonical.push(root);
        }
    }
    Ok(canonical)
}

fn canonicalize_policy_root(
    root: &Path,
    root_kind: &str,
    index: usize,
) -> Result<PathBuf, FilesystemPolicyError> {
    if root.as_os_str().is_empty() {
        return Err(FilesystemPolicyError::new(format!(
            "{root_kind} root #{index} is empty; a required root could not be resolved"
        )));
    }
    if root.as_os_str().to_string_lossy().contains('\0') {
        return Err(FilesystemPolicyError::new(format!(
            "{root_kind} root #{index} contains an interior NUL"
        )));
    }

    let absolute = if root.is_absolute() {
        root.to_path_buf()
    } else {
        std::env::current_dir()
            .map_err(|error| {
                FilesystemPolicyError::new(format!(
                    "cannot resolve relative {root_kind} root {}: current directory is unavailable ({error})",
                    root.display()
                ))
            })?
            .join(root)
    };
    let absolute = lexically_normalize_absolute(&absolute, root_kind, index)?;

    // The policy frequently names credential files/directories that do not exist
    // yet. Resolve the closest existing ancestor so aliases in any existing prefix
    // are still collapsed, then append the missing suffix verbatim.
    let mut probe = absolute.clone();
    let mut missing_suffix: Vec<OsString> = Vec::new();
    loop {
        match std::fs::symlink_metadata(&probe) {
            Ok(metadata) => {
                if !missing_suffix.is_empty() && !metadata.is_dir() {
                    return Err(FilesystemPolicyError::new(format!(
                        "{root_kind} root {} descends through non-directory {}",
                        root.display(),
                        probe.display()
                    )));
                }
                let mut resolved = std::fs::canonicalize(&probe).map_err(|error| {
                    FilesystemPolicyError::new(format!(
                        "cannot canonicalize {root_kind} root {} at existing prefix {}: {error}",
                        root.display(),
                        probe.display()
                    ))
                })?;
                for component in missing_suffix.iter().rev() {
                    resolved.push(component);
                }
                return lexically_normalize_absolute(&resolved, root_kind, index);
            }
            Err(error)
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::NotFound | std::io::ErrorKind::NotADirectory
                ) =>
            {
                let Some(component) = probe.file_name().map(OsStr::to_os_string) else {
                    return Err(FilesystemPolicyError::new(format!(
                        "cannot find an existing ancestor for {root_kind} root {}",
                        root.display()
                    )));
                };
                missing_suffix.push(component);
                if !probe.pop() {
                    return Err(FilesystemPolicyError::new(format!(
                        "cannot find an existing ancestor for {root_kind} root {}",
                        root.display()
                    )));
                }
            }
            Err(error) => {
                return Err(FilesystemPolicyError::new(format!(
                    "cannot inspect {root_kind} root {} at {}: {error}",
                    root.display(),
                    probe.display()
                )));
            }
        }
    }
}

fn lexically_normalize_absolute(
    path: &Path,
    root_kind: &str,
    index: usize,
) -> Result<PathBuf, FilesystemPolicyError> {
    if !path.is_absolute() {
        return Err(FilesystemPolicyError::new(format!(
            "{root_kind} root #{index} did not resolve to an absolute path: {}",
            path.display()
        )));
    }

    let mut normalized = PathBuf::new();
    for component in path.components() {
        match component {
            Component::Prefix(prefix) => normalized.push(prefix.as_os_str()),
            Component::RootDir => normalized.push(component.as_os_str()),
            Component::CurDir => {}
            Component::ParentDir => {
                if !normalized.pop() {
                    return Err(FilesystemPolicyError::new(format!(
                        "{root_kind} root #{index} traverses above its filesystem root: {}",
                        path.display()
                    )));
                }
            }
            Component::Normal(segment) => normalized.push(segment),
        }
    }
    Ok(normalized)
}

fn paths_overlap(left: &Path, right: &Path) -> bool {
    path_is_within(left, right) || path_is_within(right, left)
}

fn paths_equivalent(left: &Path, right: &Path) -> bool {
    path_is_within(left, right) && path_is_within(right, left)
}

fn path_is_within(path: &Path, root: &Path) -> bool {
    let mut path_components = path.components();
    for root_component in root.components() {
        let Some(path_component) = path_components.next() else {
            return false;
        };
        if !policy_component_eq(path_component.as_os_str(), root_component.as_os_str()) {
            return false;
        }
    }
    true
}

#[cfg(not(windows))]
fn policy_component_eq(left: &OsStr, right: &OsStr) -> bool {
    left == right
}

#[cfg(windows)]
fn policy_component_eq(left: &OsStr, right: &OsStr) -> bool {
    use std::os::windows::ffi::OsStrExt as _;
    use windows_sys::Win32::Globalization::{CompareStringOrdinal, CSTR_EQUAL};

    let left: Vec<u16> = left.encode_wide().collect();
    let right: Vec<u16> = right.encode_wide().collect();
    let (Ok(left_len), Ok(right_len)) = (i32::try_from(left.len()), i32::try_from(right.len()))
    else {
        return false;
    };
    // SAFETY: both buffers remain live for their explicit lengths and the API does
    // not require NUL termination when a non-negative length is supplied.
    unsafe {
        CompareStringOrdinal(left.as_ptr(), left_len, right.as_ptr(), right_len, 1) == CSTR_EQUAL
    }
}

/// Environment containment for the child (cross-cutting invariant 2: env
/// isolation is a tracked coverage flag).
///
/// By default the child does **not** inherit the parent environment
/// (`inherit = false`), sensitive variables are stripped even from anything
/// explicitly re-added, and HOME/XDG_*/TMPDIR are pointed at a temporary
/// directory so a contained process cannot read or poison the real user config.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EnvironmentPolicy {
    /// Whether to start from the parent's environment. **Defaults to `false`** —
    /// a contained child gets only what is explicitly allowed.
    #[serde(default)]
    pub inherit: bool,
    /// Variables explicitly passed through (by exact name). Even a name listed
    /// here is dropped if [`Self::deny_sensitive`] is set and it matches the
    /// sensitive set, so an allow entry can never re-expose a credential.
    #[serde(default)]
    pub allow: Vec<String>,
    /// Strip variables classified as secret-bearing by the central typed
    /// registry. **Defaults to `true`.**
    #[serde(default = "default_true")]
    pub deny_sensitive: bool,
    /// Replace HOME / XDG_* / TMPDIR with an isolated temporary directory so the
    /// child cannot reach the real user config tree. **Defaults to `true`.**
    #[serde(default = "default_true")]
    pub temporary_home: bool,
}

impl Default for EnvironmentPolicy {
    fn default() -> Self {
        EnvironmentPolicy {
            inherit: false,
            allow: Vec::new(),
            deny_sensitive: true,
            temporary_home: true,
        }
    }
}

impl EnvironmentPolicy {
    /// Whether `name` is a sensitive variable that [`Self::deny_sensitive`]
    /// strips. Exact aliases and prefix families use one kind-aware central
    /// matcher; public RPC endpoint variables are preserved.
    pub fn is_sensitive(name: &str) -> bool {
        crate::sensitive_assets::is_capsule_sensitive_env_name(name)
    }

    /// Value-aware form used by real launchers. Public RPC endpoints survive,
    /// while userinfo/query/fragment/provider-token endpoint values are denied.
    pub fn is_sensitive_assignment(name: &str, value: &str) -> bool {
        if crate::sensitive_assets::is_capsule_sensitive_env_name(name) {
            !value.trim().is_empty()
        } else {
            crate::sensitive_assets::is_sensitive_env_assignment(name, value)
        }
    }

    /// Whether one concrete assignment may enter a child environment after
    /// the name-level survivor decision. This is the shared value-aware gate
    /// used by every OS launcher.
    pub fn assignment_survives(&self, name: &str, value: &str) -> bool {
        !self.deny_sensitive || !Self::is_sensitive_assignment(name, value)
    }

    /// Compute the variable names that should survive into the child, given the
    /// parent environment's variable names. This is the testable core of env
    /// isolation: a backend applies the result, but the decision is pure.
    ///
    /// - When [`Self::inherit`] is false, start from `allow`; otherwise start
    ///   from every parent name.
    /// - When [`Self::deny_sensitive`] is true, drop every sensitive name from
    ///   the surviving set (even ones named in `allow`).
    ///
    /// HOME/TMPDIR replacement (from [`Self::temporary_home`]) is applied by the
    /// backend on top of this and is not reflected here.
    pub fn surviving_vars<'a, I>(&'a self, parent_names: I) -> BTreeSet<String>
    where
        I: IntoIterator<Item = &'a str>,
    {
        let mut survivors: BTreeSet<String> = if self.inherit {
            parent_names.into_iter().map(|s| s.to_owned()).collect()
        } else {
            self.allow.iter().cloned().collect()
        };
        if self.deny_sensitive {
            survivors.retain(|name| !Self::is_sensitive(name));
        }
        survivors
    }
}

/// Inherited-handle / file-descriptor closure policy.
///
/// A contained child must not inherit handles to the parent's open files,
/// sockets, or pipes beyond a minimal allow-list. On Unix this is "stdio (0/1/2)
/// plus any broker FD"; on Windows it is `bInheritHandles = FALSE` (or an
/// explicit `STARTUPINFOEX` handle allow-list).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HandlePolicy {
    /// Keep the standard streams (stdin/stdout/stderr) open in the child.
    /// **Defaults to `true`** — a contained process still needs its own stdio.
    #[serde(default = "default_true")]
    pub keep_stdio: bool,
    /// Extra Unix file descriptors the child is permitted to inherit (e.g. a
    /// broker socket FD). Everything not in `{0,1,2} ∪ extra_unix_fds` is closed.
    #[serde(default)]
    pub extra_unix_fds: Vec<i32>,
}

impl Default for HandlePolicy {
    fn default() -> Self {
        HandlePolicy {
            keep_stdio: true,
            extra_unix_fds: Vec::new(),
        }
    }
}

impl HandlePolicy {
    /// The complete set of Unix FDs the child may inherit: stdio (when
    /// [`Self::keep_stdio`]) plus the explicit extras. A Unix backend closes
    /// every other open descriptor down to this set.
    pub fn allowed_unix_fds(&self) -> BTreeSet<i32> {
        let mut fds: BTreeSet<i32> = BTreeSet::new();
        if self.keep_stdio {
            fds.insert(0);
            fds.insert(1);
            fds.insert(2);
        }
        for fd in &self.extra_unix_fds {
            fds.insert(*fd);
        }
        fds
    }
}

/// Resource ceilings requested from a capsule backend (cross-cutting invariant
/// 2: resource limits are a tracked coverage flag).
///
/// `None` means "do not impose a tirith limit for this dimension" (the OS / cgroup
/// default applies). A backend sets
/// [`CapsuleCoverage::resource_limits_enforced`] only when at least one limit was
/// requested and it successfully applies **every** populated dimension. One
/// supported dimension must never mask another unsupported dimension.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResourceLimits {
    /// Max CPU time in seconds (rlimit `RLIMIT_CPU` on Unix; Job Object on Windows).
    #[serde(default)]
    pub cpu_seconds: Option<u64>,
    /// Max address-space / committed memory in bytes.
    #[serde(default)]
    pub memory_bytes: Option<u64>,
    /// Max number of processes/threads the child tree may create.
    #[serde(default)]
    pub max_processes: Option<u32>,
    /// Max number of simultaneously open file descriptors / handles.
    #[serde(default)]
    pub max_open_files: Option<u32>,
    /// Max bytes the child may write to its captured stdout/stderr before it is
    /// cut off (output containment, enforced by the launcher/broker, not the OS).
    #[serde(default)]
    pub max_output_bytes: Option<u64>,
    /// Wall-clock deadline in seconds, after which the child tree is killed.
    #[serde(default)]
    pub wall_clock_seconds: Option<u64>,
}

impl ResourceLimits {
    /// A conservative default ceiling suitable for an install hook / MCP server:
    /// bounded CPU, memory, process count, open files, output, and wall-clock.
    /// Callers may relax individual dimensions; the point is that *something* is
    /// always set so a contained process cannot fork-bomb or exhaust memory.
    pub fn conservative() -> Self {
        ResourceLimits {
            cpu_seconds: Some(120),
            memory_bytes: Some(2 * 1024 * 1024 * 1024),
            max_processes: Some(256),
            max_open_files: Some(256),
            max_output_bytes: Some(16 * 1024 * 1024),
            wall_clock_seconds: Some(300),
        }
    }

    /// Whether any dimension is populated (used to decide if the
    /// `resource_limits_enforced` flag is even applicable).
    pub fn any_set(&self) -> bool {
        self.cpu_seconds.is_some()
            || self.memory_bytes.is_some()
            || self.max_processes.is_some()
            || self.max_open_files.is_some()
            || self.max_output_bytes.is_some()
            || self.wall_clock_seconds.is_some()
    }

    /// Whether at least one limit is requested and every requested dimension is
    /// enforced by `support`.
    ///
    /// This is deliberately all-or-nothing because [`CapsuleCoverage`] exposes a
    /// single aggregate resource bit. Treating "any supported limit" as full
    /// coverage lets a supported CPU or memory limit hide an unsupported wall,
    /// output, process-count, or open-file limit and defeats fail-closed checks.
    pub(crate) fn all_requested_enforced_by(&self, support: ResourceLimitSupport) -> bool {
        self.any_set()
            && (self.cpu_seconds.is_none() || support.cpu_seconds)
            && (self.memory_bytes.is_none() || support.memory_bytes)
            && (self.max_processes.is_none() || support.max_processes)
            && (self.max_open_files.is_none() || support.max_open_files)
            && (self.max_output_bytes.is_none() || support.max_output_bytes)
            && (self.wall_clock_seconds.is_none() || support.wall_clock_seconds)
    }
}

/// Resource-limit dimensions a concrete backend + launch wrapper can enforce.
/// Kept crate-private so every backend derives the aggregate coverage bit from
/// the same all-requested invariant without expanding the serialized API.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ResourceLimitSupport {
    pub(crate) cpu_seconds: bool,
    pub(crate) memory_bytes: bool,
    pub(crate) max_processes: bool,
    pub(crate) max_open_files: bool,
    pub(crate) max_output_bytes: bool,
    pub(crate) wall_clock_seconds: bool,
}

/// Environment names the `untrusted-project` preset lets through by NAME. The
/// values are supplied explicitly by the launching parent, never inherited, and
/// each still passes the value-aware sensitive gate.
///
/// `HOME`, `TMPDIR`, and the `XDG_*` bases are absent on purpose: the launcher
/// sets them to the temporary HOME after the survivor set is computed, so
/// listing them here would only invite a caller to point them somewhere else.
pub const UNTRUSTED_PROJECT_ENV_ALLOW: &[&str] = &["PATH", "LANG", "LC_ALL", "TERM", "TZ"];

/// Everything a backend needs to contain one child process. Constructed by the
/// caller (install, MCP spawn, `tirith run`) and handed to a [`Capsule`].
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct CapsuleSpec {
    /// Filesystem confinement.
    #[serde(default)]
    pub filesystem: FilesystemPolicy,
    /// Network confinement (default deny-all).
    #[serde(default)]
    pub network: NetworkPolicy,
    /// Environment scrubbing.
    #[serde(default)]
    pub environment: EnvironmentPolicy,
    /// Inherited-handle closure.
    #[serde(default)]
    pub handles: HandlePolicy,
    /// Resource ceilings.
    #[serde(default)]
    pub resources: ResourceLimits,
}

impl CapsuleSpec {
    /// A maximally-locked spec: deny-all network, no inherited environment with
    /// the sensitive set stripped and a temporary HOME, default sensitive-subtree
    /// denies, minimal handle inheritance, and conservative resource limits. The
    /// baseline for `pkg install` (the caller then adds the specific read/write
    /// roots the install needs).
    pub fn locked_down() -> Self {
        CapsuleSpec {
            filesystem: FilesystemPolicy::deny_by_default(),
            network: NetworkPolicy::DenyAll,
            environment: EnvironmentPolicy::default(),
            handles: HandlePolicy::default(),
            resources: ResourceLimits::conservative(),
        }
    }

    /// The `untrusted-project` preset (C14): [`Self::locked_down`] plus write
    /// authority over exactly one held project copy and read authority over the
    /// interpreter roots the child needs to `exec` at all.
    ///
    /// Everything else is inherited on purpose. `locked_down` already gives
    /// deny-all network, a non-inheriting environment with the sensitive set
    /// stripped, a temporary HOME, [`ResourceLimits::conservative`] (which is
    /// already exactly the preset's CPU 120 / memory 2 GiB / processes 256 /
    /// open files 256 / output 16 MiB / wall 300 s ceiling), and
    /// [`deny_default_paths`] seeded from
    /// [`crate::sensitive_assets::capsule_deny_relative_paths`] (credential
    /// stores, `.ethereum/keystore`, `.config/solana`, the Electrum / Exodus /
    /// Atomic / Ledger Live wallet roots, and every browser user-data root).
    /// Re-declaring any of that here would silently drift from the shared
    /// catalogue the first time a wallet root is added to it.
    ///
    /// `project_root` MUST already be the canonical path of the held ephemeral
    /// COPY, never the operator's own tree: the preset's entire point is that
    /// the untrusted project cannot write to the real working directory.
    ///
    /// The network policy is [`NetworkPolicy::DenyAll`] and there is no
    /// allow-listed-domain variant, because no backend in this tree can claim
    /// `domain_proxy_enforced` (it is hard-coded `false` in all three), so an
    /// allow-list preset would fail closed on every host while implying a
    /// capability the product does not have.
    pub fn untrusted_project(project_root: &Path, interpreter_read_roots: &[PathBuf]) -> Self {
        let mut spec = Self::locked_down();
        spec.filesystem.write_roots.push(project_root.to_path_buf());
        for root in interpreter_read_roots {
            if !spec.filesystem.read_roots.contains(root) {
                spec.filesystem.read_roots.push(root.clone());
            }
        }
        // A contained child still needs to find its interpreter and speak the
        // host's locale. Every name here is checked against the sensitive
        // registry by `surviving_vars`, so an allow entry can never re-expose a
        // credential.
        spec.environment.allow = UNTRUSTED_PROJECT_ENV_ALLOW
            .iter()
            .map(|name| (*name).to_string())
            .collect();
        spec
    }

    /// The coverage an enforcing surface should *require* given this spec: every
    /// capability the spec actually constrains. Surfaces compare a backend's
    /// achieved [`CapsuleCoverage`] against this via
    /// [`CapsuleCoverage::is_degraded_against`] and fail closed on a shortfall.
    pub fn required_coverage(&self) -> CapsuleCoverage {
        let wants_egress = !self.network.is_deny_all();
        CapsuleCoverage {
            // A locked filesystem (any deny root or any constrained grant) means
            // we require FS read/write enforcement.
            fs_read_enforced: true,
            fs_write_enforced: true,
            // Always require exec limiting for a contained child.
            exec_limited: true,
            // Deny-all network requires raw sockets blocked; an allow-list also
            // requires raw-deny (the broker is the only path) plus the proxy.
            network_raw_denied: true,
            domain_proxy_enforced: wants_egress,
            resource_limits_enforced: self.resources.any_set(),
            env_isolated: true,
            handles_isolated: true,
        }
    }

    /// The containment level a spec asks a backend to deliver, derived purely from
    /// its [`NetworkPolicy`]. This is the host-independent classifier the OS
    /// backends branch on (so the decision is unit-testable on any platform, not
    /// just where the backend compiles).
    pub fn capability_level(&self) -> CapabilityLevel {
        if self.network.is_deny_all() {
            CapabilityLevel::DenyAll
        } else {
            CapabilityLevel::AllowListedDomains
        }
    }
}

/// The two containment levels an OS backend distinguishes (cross-cutting the E2-E4
/// units). Kept platform-independent so callers and tests can reason about the
/// level a [`CapsuleSpec`] requires without a working backend.
///
/// - [`DenyAll`](Self::DenyAll): no network capability at all. A Linux backend can
///   satisfy this *natively* with Landlock filesystem confinement + a seccomp
///   policy that grants no socket-creation syscalls, the target for
///   `tirith pkg install` (installs never need outbound traffic).
/// - [`AllowListedDomains`](Self::AllowListedDomains): outbound traffic only to
///   policy domains, only through the loopback broker. Claiming this is *enforced*
///   requires a backend that blocks every raw outbound socket except the broker
///   (cross-cutting invariant 3). E2's Linux backend has no such verified
///   raw-socket-blocking path yet (a complete netns+veth/slirp broker or a proven
///   `srt`/bubblewrap launcher), so it reports this level as **degraded** and an
///   enforcing command fails closed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CapabilityLevel {
    /// No network capability; satisfiable natively by an OS sandbox backend.
    DenyAll,
    /// Egress restricted to allow-listed domains via the broker; only honestly
    /// enforceable behind a verified raw-socket-blocking backend.
    AllowListedDomains,
}

/// The containment backend interface. Implemented by the OS backends (E2-E4) and
/// by [`NoOpCapsule`]. The trait is intentionally tiny and synchronous: it
/// reports its *static* capability ([`Self::available_coverage`]) so a caller can
/// decide, before spawning anything, whether the platform can satisfy the spec.
///
/// The actual process launch (which on Linux re-execs `tirith __capsule-child`)
/// lives in the CLI crate and is added in E2-E5; keeping the trait here lets
/// `tirith-core` reason about coverage without depending on the launcher.
pub trait Capsule {
    /// A stable identifier for the backend (e.g. `"landlock-seccomp"`,
    /// `"seatbelt"`, `"appcontainer"`, `"noop"`). Used in receipts and
    /// `tirith doctor` output.
    fn backend_id(&self) -> &'static str;

    /// The coverage this backend can achieve for `spec` on the current host
    /// *right now*, without launching anything. A backend probes for its OS
    /// mechanism (Landlock ABI, `sandbox-exec` presence, AppContainer support)
    /// and reports honestly: capabilities it cannot enforce are `false`.
    ///
    /// This is the value enforcing surfaces compare against
    /// [`CapsuleSpec::required_coverage`] to decide whether to proceed or fail
    /// closed. It must NEVER over-report.
    fn available_coverage(&self, spec: &CapsuleSpec) -> CapsuleCoverage;
}

/// The always-degraded backend. It contains **nothing** and, by contract, never
/// claims any coverage — in particular it never claims egress enforcement, so a
/// platform with no working sandbox can never be mistaken for one that contains.
///
/// Enforcing surfaces that receive a `NoOpCapsule` must fail closed (the spec's
/// required coverage will always be unsatisfied). Analysis-only surfaces may use
/// it to run uncontained while still emitting an honest "degraded" banner.
#[derive(Debug, Clone, Copy, Default)]
pub struct NoOpCapsule;

impl Capsule for NoOpCapsule {
    fn backend_id(&self) -> &'static str {
        "noop"
    }

    fn available_coverage(&self, _spec: &CapsuleSpec) -> CapsuleCoverage {
        // Honest: nothing is enforced, ever. Notably `domain_proxy_enforced` and
        // `network_raw_denied` stay false, so `egress_claim_is_coherent` holds and
        // no caller can read an egress promise out of a NoOp.
        CapsuleCoverage::NONE
    }
}

/// The sensitive subtrees a contained child is denied by default, even when a
/// broader read/write root would otherwise cover them. **Deliberately a curated
/// set of known-sensitive paths, NOT all of `~/.config`** — over-denying breaks
/// legitimate tools, so the policy targets the high-value credential / key
/// stores specifically.
///
/// Paths are anchored under the authenticated process user's OS account home, not
/// mutable `HOME` / `USERPROFILE`. Unix resolves the effective UID with
/// `getpwuid_r`; Windows asks the Known Folder API for `FOLDERID_Profile` using the
/// current process token. The home and every deny root are canonicalized before
/// they enter the policy so a symlink/junction alias cannot bypass overlap checks.
///
/// This compatibility wrapper cannot return an error. If the authenticated home
/// cannot be resolved, it returns one empty poison root; the shared policy validator
/// rejects that marker, making every enforcing backend fail closed instead of
/// silently dropping the credential denies. New fallible callers may use
/// [`try_deny_default_paths`] to retain the lookup error.
pub fn deny_default_paths() -> Vec<PathBuf> {
    try_deny_default_paths().unwrap_or_else(|_| vec![PathBuf::new()])
}

/// Fallible form of [`deny_default_paths`], preserving authenticated-home lookup
/// and canonicalization errors for callers that can propagate them directly.
pub fn try_deny_default_paths() -> Result<Vec<PathBuf>, FilesystemPolicyError> {
    let home = authenticated_home_dir()?;
    // Known credential / key / token stores. Kept tight on purpose.
    canonicalize_root_set(
        &crate::sensitive_assets::capsule_deny_relative_paths()
            .map(|relative| home.join(relative))
            .collect::<Vec<_>>(),
        "deny",
    )
}

#[cfg(unix)]
fn authenticated_home_dir() -> Result<PathBuf, FilesystemPolicyError> {
    use std::ffi::CStr;
    use std::os::unix::ffi::OsStrExt as _;

    const FALLBACK_BUFFER_BYTES: usize = 16 * 1024;
    const MAX_BUFFER_BYTES: usize = 1024 * 1024;

    // SAFETY: sysconf and geteuid take no pointers and have no preconditions.
    let suggested = unsafe { libc::sysconf(libc::_SC_GETPW_R_SIZE_MAX) };
    let mut capacity = if suggested > 0 {
        usize::try_from(suggested)
            .unwrap_or(FALLBACK_BUFFER_BYTES)
            .clamp(FALLBACK_BUFFER_BYTES, MAX_BUFFER_BYTES)
    } else {
        FALLBACK_BUFFER_BYTES
    };
    // SAFETY: geteuid has no preconditions and identifies the process credentials
    // that the capsule launch will actually run under.
    let effective_uid = unsafe { libc::geteuid() };

    loop {
        let mut record = std::mem::MaybeUninit::<libc::passwd>::uninit();
        let mut result = std::ptr::null_mut();
        let mut buffer = vec![0_u8; capacity];
        // SAFETY: all output pointers and the writable buffer live for the call;
        // getpwuid_r writes at most buffer.len() bytes and initializes `record` only
        // on a successful lookup with a non-null result pointer.
        let status = unsafe {
            libc::getpwuid_r(
                effective_uid,
                record.as_mut_ptr(),
                buffer.as_mut_ptr().cast(),
                buffer.len(),
                &mut result,
            )
        };
        if status == libc::ERANGE && capacity < MAX_BUFFER_BYTES {
            capacity = capacity.saturating_mul(2).min(MAX_BUFFER_BYTES);
            continue;
        }
        if status != 0 {
            return Err(FilesystemPolicyError::new(format!(
                "cannot resolve effective UID {effective_uid} home with getpwuid_r: OS error {status}"
            )));
        }
        if result.is_null() {
            return Err(FilesystemPolicyError::new(format!(
                "effective UID {effective_uid} has no account database entry"
            )));
        }
        // SAFETY: successful non-null getpwuid_r initialized `record`; pw_dir points
        // into `buffer`, which remains alive through the copy below.
        let record = unsafe { record.assume_init() };
        if record.pw_dir.is_null() {
            return Err(FilesystemPolicyError::new(format!(
                "effective UID {effective_uid} account entry has no home directory"
            )));
        }
        // SAFETY: POSIX specifies a NUL-terminated pw_dir on successful lookup.
        let bytes = unsafe { CStr::from_ptr(record.pw_dir) }.to_bytes();
        if bytes.is_empty() {
            return Err(FilesystemPolicyError::new(format!(
                "effective UID {effective_uid} account entry has an empty home directory"
            )));
        }
        return canonicalize_authenticated_home(Path::new(OsStr::from_bytes(bytes)));
    }
}

#[cfg(windows)]
fn authenticated_home_dir() -> Result<PathBuf, FilesystemPolicyError> {
    use ::windows::Win32::Foundation::{CloseHandle, HANDLE};
    use ::windows::Win32::Security::TOKEN_QUERY;
    use ::windows::Win32::System::Com::CoTaskMemFree;
    use ::windows::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};
    use ::windows::Win32::UI::Shell::{FOLDERID_Profile, SHGetKnownFolderPath, KF_FLAG_DEFAULT};
    use std::os::windows::ffi::OsStringExt as _;

    struct ProcessToken(HANDLE);

    impl Drop for ProcessToken {
        fn drop(&mut self) {
            // SAFETY: this wrapper owns the handle returned by OpenProcessToken.
            unsafe {
                let _ = CloseHandle(self.0);
            }
        }
    }

    let mut token = HANDLE::default();
    // SAFETY: `token` is a valid out-pointer and the pseudo process handle remains
    // valid for the duration of the call.
    unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) }.map_err(|error| {
        FilesystemPolicyError::new(format!("cannot open current process token: {error}"))
    })?;
    let token = ProcessToken(token);

    // SAFETY: the fixed known-folder ID and owned process token are valid, and
    // Windows owns the returned allocation until CoTaskMemFree below.
    let raw = unsafe { SHGetKnownFolderPath(&FOLDERID_Profile, KF_FLAG_DEFAULT, Some(token.0)) }
        .map_err(|error| {
            FilesystemPolicyError::new(format!(
                "cannot resolve the process-token profile directory: {error}"
            ))
        })?;
    // SAFETY: a successful call returned a valid NUL-terminated allocation.
    let home = OsString::from_wide(unsafe { raw.as_wide() });
    // SAFETY: SHGetKnownFolderPath transfers exactly one COM task allocation.
    unsafe { CoTaskMemFree(Some(raw.as_ptr().cast())) };
    canonicalize_authenticated_home(Path::new(&home))
}

#[cfg(not(any(unix, windows)))]
fn authenticated_home_dir() -> Result<PathBuf, FilesystemPolicyError> {
    Err(FilesystemPolicyError::new(
        "authenticated home lookup is unsupported on this platform",
    ))
}

fn canonicalize_authenticated_home(home: &Path) -> Result<PathBuf, FilesystemPolicyError> {
    if home.as_os_str().is_empty() || !home.is_absolute() {
        return Err(FilesystemPolicyError::new(
            "the OS account database returned an empty or relative home directory",
        ));
    }
    let canonical = std::fs::canonicalize(home).map_err(|error| {
        FilesystemPolicyError::new(format!(
            "cannot canonicalize authenticated home {}: {error}",
            home.display()
        ))
    })?;
    let metadata = std::fs::metadata(&canonical).map_err(|error| {
        FilesystemPolicyError::new(format!(
            "cannot inspect authenticated home {}: {error}",
            canonical.display()
        ))
    })?;
    if !metadata.is_dir() {
        return Err(FilesystemPolicyError::new(format!(
            "authenticated home {} is not a directory",
            canonical.display()
        )));
    }
    Ok(canonical)
}

fn default_true() -> bool {
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn noop_capsule_never_claims_any_coverage() {
        // Invariant 2: a missing backend can never be mistaken for a working one.
        let cap = NoOpCapsule;
        let cov = cap.available_coverage(&CapsuleSpec::locked_down());
        assert_eq!(cov, CapsuleCoverage::NONE);
        assert!(cov.is_fully_unenforced());
        assert_eq!(cap.backend_id(), "noop");
    }

    #[test]
    fn noop_capsule_never_claims_egress() {
        // The single most important NoOp property: it must never report egress.
        let cap = NoOpCapsule;
        let cov = cap.available_coverage(&CapsuleSpec::locked_down());
        assert!(!cov.domain_proxy_enforced);
        assert!(!cov.network_raw_denied);
        assert!(cov.egress_claim_is_coherent());
    }

    #[test]
    fn egress_claim_requires_raw_deny() {
        // Invariant 3: a coherent ledger cannot claim the proxy without raw-deny.
        let incoherent = CapsuleCoverage {
            domain_proxy_enforced: true,
            network_raw_denied: false,
            ..CapsuleCoverage::NONE
        };
        assert!(!incoherent.egress_claim_is_coherent());

        let coherent = CapsuleCoverage {
            domain_proxy_enforced: true,
            network_raw_denied: true,
            ..CapsuleCoverage::NONE
        };
        assert!(coherent.egress_claim_is_coherent());
    }

    #[test]
    fn degraded_against_detects_shortfall() {
        let required = CapsuleSpec::locked_down().required_coverage();
        // NoOp coverage satisfies nothing required -> degraded.
        assert!(CapsuleCoverage::NONE.is_degraded_against(&required));

        // A ledger that meets every required flag is NOT degraded.
        let full = CapsuleCoverage {
            fs_read_enforced: true,
            fs_write_enforced: true,
            exec_limited: true,
            network_raw_denied: true,
            // locked_down is deny-all, so domain_proxy is NOT required.
            domain_proxy_enforced: false,
            resource_limits_enforced: true,
            env_isolated: true,
            handles_isolated: true,
        };
        assert!(!full.is_degraded_against(&required));
    }

    #[test]
    fn locked_down_spec_requires_egress_only_when_allowlisted() {
        // Deny-all spec must NOT require the proxy flag.
        let deny = CapsuleSpec::locked_down();
        assert!(!deny.required_coverage().domain_proxy_enforced);
        assert!(deny.required_coverage().network_raw_denied);

        // An allow-listed-domains spec DOES require the proxy flag (and raw-deny).
        let mut allow = CapsuleSpec::locked_down();
        allow.network = NetworkPolicy::AllowListedDomains {
            domains: ["pypi.org".to_string()].into_iter().collect(),
            ports: [443u16].into_iter().collect(),
        };
        let req = allow.required_coverage();
        assert!(req.domain_proxy_enforced);
        assert!(req.network_raw_denied);
    }

    #[test]
    fn capability_level_follows_network_policy() {
        // Deny-all network -> DenyAll level (natively satisfiable).
        assert_eq!(
            CapsuleSpec::locked_down().capability_level(),
            CapabilityLevel::DenyAll
        );
        // An allow-list -> AllowListedDomains level (broker-only egress).
        let mut allow = CapsuleSpec::locked_down();
        allow.network = NetworkPolicy::AllowListedDomains {
            domains: ["pypi.org".to_string()].into_iter().collect(),
            ports: [443u16].into_iter().collect(),
        };
        assert_eq!(
            allow.capability_level(),
            CapabilityLevel::AllowListedDomains
        );
    }

    #[test]
    fn the_untrusted_project_preset_inherits_the_locked_down_baseline() {
        let base = tempfile::tempdir().expect("tempdir");
        let project = base.path().join("held-copy");
        std::fs::create_dir(&project).expect("create held copy");

        let preset = CapsuleSpec::untrusted_project(&project, &[]);
        assert!(preset.network.is_deny_all());
        assert!(!preset.environment.inherit);
        assert!(preset.environment.deny_sensitive);
        assert!(preset.environment.temporary_home);
        // Reused verbatim, never restated: a drift here would mean the preset
        // stopped tracking the shared conservative ceiling.
        assert_eq!(preset.resources, ResourceLimits::conservative());
        assert_eq!(preset.filesystem.write_roots, vec![project.clone()]);
        assert!(preset.required_coverage().network_raw_denied);
        assert!(!preset.required_coverage().domain_proxy_enforced);
    }

    #[test]
    fn the_untrusted_project_preset_denies_every_shared_sensitive_root() {
        let base = tempfile::tempdir().expect("tempdir");
        let project = base.path().join("held-copy");
        std::fs::create_dir(&project).expect("create held copy");
        let preset = CapsuleSpec::untrusted_project(&project, &[]);

        // The deny set is seeded from the shared catalogue, so it can never be
        // empty on a host whose authenticated home resolved; when it did not,
        // `deny_default_paths` emits the empty poison root and the validator
        // below fails closed instead.
        assert!(!preset.filesystem.deny_roots.is_empty());
        let poisoned = preset
            .filesystem
            .deny_roots
            .iter()
            .any(|root| root.as_os_str().is_empty());
        if !poisoned {
            let names: Vec<String> = preset
                .filesystem
                .deny_roots
                .iter()
                .map(|root| root.display().to_string())
                .collect();
            for expected in [".ssh", ".aws", ".gnupg"] {
                assert!(
                    names.iter().any(|root| root.ends_with(expected)),
                    "preset deny roots lost {expected}"
                );
            }
        }
    }

    #[test]
    fn the_untrusted_project_preset_refuses_a_project_over_a_denied_root() {
        // The negative half of the deny contract, and the reason `--project ~`
        // and `--project ~/.ssh` must never be accepted: the validator rejects
        // an allow root that overlaps a deny root in either direction.
        let Ok(home) = authenticated_home_dir() else {
            return;
        };
        let preset = CapsuleSpec::untrusted_project(&home.join(".ssh"), &[]);
        assert!(canonicalize_and_validate_filesystem_policy(&preset.filesystem).is_err());

        let whole_home = CapsuleSpec::untrusted_project(&home, &[]);
        assert!(canonicalize_and_validate_filesystem_policy(&whole_home.filesystem).is_err());
    }

    #[test]
    fn the_untrusted_project_env_allowlist_cannot_re_expose_a_credential() {
        let base = tempfile::tempdir().expect("tempdir");
        let project = base.path().join("held-copy");
        std::fs::create_dir(&project).expect("create held copy");
        let mut preset = CapsuleSpec::untrusted_project(&project, &[]);
        preset.environment.allow.push("GITHUB_TOKEN".to_string());
        preset
            .environment
            .allow
            .push("AWS_SECRET_ACCESS_KEY".to_string());

        let survivors = preset.environment.surviving_vars(std::iter::empty());
        assert!(survivors.contains("PATH"));
        assert!(survivors.contains("TERM"));
        assert!(!survivors.contains("GITHUB_TOKEN"));
        assert!(!survivors.contains("AWS_SECRET_ACCESS_KEY"));
    }

    #[test]
    fn network_policy_permits_only_listed_domain_and_port() {
        let policy = NetworkPolicy::AllowListedDomains {
            domains: ["pypi.org".to_string(), "files.pythonhosted.org".to_string()]
                .into_iter()
                .collect(),
            ports: [443u16].into_iter().collect(),
        };
        assert!(policy.permits("pypi.org", 443));
        // Trailing dot + case are normalized.
        assert!(policy.permits("PyPI.org.", 443));
        // Wrong port rejected.
        assert!(!policy.permits("pypi.org", 80));
        // Unlisted domain rejected.
        assert!(!policy.permits("evil.example", 443));
        // Deny-all permits nothing.
        assert!(!NetworkPolicy::DenyAll.permits("pypi.org", 443));
    }

    #[test]
    fn env_policy_default_is_locked() {
        let env = EnvironmentPolicy::default();
        assert!(!env.inherit);
        assert!(env.deny_sensitive);
        assert!(env.temporary_home);
        assert!(env.allow.is_empty());
    }

    #[test]
    fn env_policy_strips_sensitive_even_when_allowed() {
        // Exact and prefix sensitive names are dropped even from the allow-list.
        let env = EnvironmentPolicy {
            inherit: false,
            allow: vec![
                "PATH".to_string(),
                "GITHUB_TOKEN".to_string(),
                "AWS_SECRET_ACCESS_KEY".to_string(),
                "PIP_INDEX_URL".to_string(),
                "RPC_URL".to_string(),
                "RPC_API_KEY".to_string(),
                "LANG".to_string(),
            ],
            deny_sensitive: true,
            temporary_home: true,
        };
        let survivors = env.surviving_vars(std::iter::empty());
        assert!(survivors.contains("PATH"));
        assert!(survivors.contains("LANG"));
        assert!(survivors.contains("RPC_URL"));
        assert!(!survivors.contains("GITHUB_TOKEN"));
        assert!(!survivors.contains("AWS_SECRET_ACCESS_KEY"));
        assert!(!survivors.contains("PIP_INDEX_URL"));
        assert!(!survivors.contains("RPC_API_KEY"));
    }

    #[test]
    fn env_policy_rpc_assignment_gate_is_value_aware() {
        let env = EnvironmentPolicy::default();
        assert!(env.assignment_survives("RPC_URL", "https://rpc.example/rpc"));
        for secret in [
            "https://user:pass@rpc.example/rpc",
            "https://rpc.example/rpc?api_key=hunter2",
            "https://rpc.example/v3/providerToken123456789",
        ] {
            assert!(!env.assignment_survives("RPC_URL", secret), "{secret}");
        }
        assert!(!env.assignment_survives("RPC_API_KEY", "hunter2"));
        for alias in [
            "wallet_private_key",
            "wallet-private-key",
            "walletPrivateKey",
            "WalletPrivateKey",
        ] {
            assert!(!env.assignment_survives(alias, "hunter2"), "{alias}");
        }
        for alias in ["rpc_url", "rpc-url", "rpcUrl", "RpcUrl"] {
            assert!(
                env.assignment_survives(alias, "https://rpc.example/rpc"),
                "{alias}"
            );
            assert!(
                !env.assignment_survives(alias, "https://rpc.example/v3/providerToken123456789"),
                "{alias}"
            );
        }
    }

    #[test]
    fn compatibility_env_catalog_aliases_keep_original_values() {
        assert_eq!(SENSITIVE_ENV_EXACT.len(), 10);
        assert_eq!(SENSITIVE_ENV_EXACT[0], "GITHUB_TOKEN");
        assert_eq!(SENSITIVE_ENV_EXACT[9], "GPG_AGENT_INFO");
        assert_eq!(
            SENSITIVE_ENV_PREFIXES,
            &[
                "AWS_",
                "AZURE_",
                "GOOGLE_",
                "UV_INDEX",
                "PIP_INDEX",
                "TWINE_"
            ]
        );
        let signature: fn() -> &'static [&'static str] = crate::safe_command::sensitive_env_vars;
        assert_eq!(signature(), crate::sensitive_assets::secret_env_names());
        let env_guard_signature: fn() -> &'static [&'static str] =
            crate::env_guard::sensitive_env_vars;
        assert_eq!(
            env_guard_signature(),
            crate::sensitive_assets::secret_env_names()
        );
    }

    #[test]
    fn env_policy_inherit_drops_sensitive_from_parent() {
        let env = EnvironmentPolicy {
            inherit: true,
            allow: Vec::new(),
            deny_sensitive: true,
            temporary_home: true,
        };
        let parent = [
            "PATH",
            "HOME",
            "ANTHROPIC_API_KEY",
            "AZURE_CLIENT_SECRET",
            "TWINE_PASSWORD",
        ];
        let survivors = env.surviving_vars(parent.iter().copied());
        assert!(survivors.contains("PATH"));
        assert!(survivors.contains("HOME"));
        assert!(!survivors.contains("ANTHROPIC_API_KEY"));
        assert!(!survivors.contains("AZURE_CLIENT_SECRET"));
        assert!(!survivors.contains("TWINE_PASSWORD"));
    }

    #[test]
    fn env_policy_no_inherit_no_allow_yields_nothing() {
        let env = EnvironmentPolicy::default();
        let parent = ["PATH", "HOME", "GITHUB_TOKEN"];
        let survivors = env.surviving_vars(parent.iter().copied());
        assert!(survivors.is_empty());
    }

    #[test]
    fn is_sensitive_matches_exact_and_prefix() {
        assert!(EnvironmentPolicy::is_sensitive("GITHUB_TOKEN"));
        assert!(EnvironmentPolicy::is_sensitive("AWS_SECRET_ACCESS_KEY"));
        assert!(EnvironmentPolicy::is_sensitive("UV_INDEX_URL"));
        assert!(EnvironmentPolicy::is_sensitive("TWINE_USERNAME"));
        assert!(EnvironmentPolicy::is_sensitive("RPC_API_KEY"));
        assert!(!EnvironmentPolicy::is_sensitive("RPC_URL"));
        assert!(!EnvironmentPolicy::is_sensitive("PATH"));
        assert!(!EnvironmentPolicy::is_sensitive("HOME"));
        // A var that merely contains a sensitive substring but doesn't match by
        // exact name or prefix is NOT stripped.
        assert!(!EnvironmentPolicy::is_sensitive("MY_GITHUB_TOKEN"));
    }

    #[test]
    fn capsule_restores_provider_control_and_container_credential_denies() {
        let env = EnvironmentPolicy {
            inherit: true,
            allow: Vec::new(),
            deny_sensitive: true,
            temporary_home: true,
        };
        let denied = [
            "AWS_PROFILE",
            "AWS_REGION",
            "AWS_CUSTOM_CONTROL",
            "AWS_SHARED_CREDENTIALS_FILE",
            "AWS_CONTAINER_CREDENTIALS_FULL_URI",
            "AWS_CONTAINER_CREDENTIALS_RELATIVE_URI",
            "AWS_CONTAINER_AUTHORIZATION_TOKEN",
            "DOCKER_AUTH_CONFIG",
            "AZURE_CONFIG_DIR",
            "AZURE_CUSTOM_CONTROL",
            "GOOGLE_APPLICATION_CREDENTIALS",
            "GOOGLE_CUSTOM_CONTROL",
            "UV_INDEX_CUSTOM",
            "PIP_INDEX_URL",
            "PIP_INDEX_CUSTOM",
            "TWINE_REPOSITORY_URL",
            "TWINE_CUSTOM_CONTROL",
        ];
        for name in denied {
            assert!(EnvironmentPolicy::is_sensitive(name), "{name}");
        }
        let survivors = env.surviving_vars(denied.iter().copied().chain(["PATH", "LANG"]));
        assert_eq!(
            survivors,
            ["LANG".to_string(), "PATH".to_string()]
                .into_iter()
                .collect()
        );
        assert!(
            crate::sensitive_assets::CAPSULE_SENSITIVE_ENV_EXACT.contains(&"DOCKER_AUTH_CONFIG")
        );
        assert!(crate::sensitive_assets::CAPSULE_SENSITIVE_ENV_EXACT.contains(&"AWS_PROFILE"));
    }

    #[test]
    fn handle_policy_default_keeps_stdio_only() {
        let h = HandlePolicy::default();
        let fds = h.allowed_unix_fds();
        assert_eq!(fds, [0, 1, 2].into_iter().collect());
    }

    #[test]
    fn handle_policy_extra_fds_are_allowed() {
        let h = HandlePolicy {
            keep_stdio: true,
            extra_unix_fds: vec![7, 9],
        };
        let fds = h.allowed_unix_fds();
        assert!(fds.contains(&0));
        assert!(fds.contains(&7));
        assert!(fds.contains(&9));
        assert_eq!(fds.len(), 5);
    }

    #[test]
    fn resource_limits_conservative_sets_every_dimension() {
        let r = ResourceLimits::conservative();
        assert!(r.any_set());
        assert!(r.cpu_seconds.is_some());
        assert!(r.memory_bytes.is_some());
        assert!(r.max_processes.is_some());
        assert!(r.max_open_files.is_some());
        assert!(r.max_output_bytes.is_some());
        assert!(r.wall_clock_seconds.is_some());

        let empty = ResourceLimits::default();
        assert!(!empty.any_set());
    }

    #[test]
    fn filesystem_deny_by_default_seeds_deny_roots() {
        // The OS-authenticated account home, not HOME, seeds the sensitive roots.
        // A lookup failure produces a poison root that every backend rejects.
        let fs = FilesystemPolicy::deny_by_default();
        assert!(fs.read_roots.is_empty());
        assert!(fs.write_roots.is_empty());
        // deny_roots mirrors deny_default_paths().
        assert_eq!(fs.deny_roots, deny_default_paths());
    }

    #[test]
    fn filesystem_policy_rejects_exact_equivalent_allow_and_deny_roots() {
        let temp = tempfile::tempdir().expect("tempdir");
        let sensitive = temp.path().join("sensitive");
        std::fs::create_dir(&sensitive).expect("create sensitive directory");
        let equivalent = temp.path().join("unused").join("..").join("sensitive");
        let policy = FilesystemPolicy {
            read_roots: vec![equivalent],
            write_roots: Vec::new(),
            deny_roots: vec![sensitive],
        };

        let error = canonicalize_and_validate_filesystem_policy(&policy)
            .expect_err("equivalent allow and deny roots must be rejected");
        assert!(error.to_string().contains("overlaps deny root"));
    }

    #[test]
    fn filesystem_policy_rejects_allow_parent_of_deny_root() {
        let temp = tempfile::tempdir().expect("tempdir");
        let denied = temp.path().join("credentials");
        std::fs::create_dir(&denied).expect("create denied directory");
        let policy = FilesystemPolicy {
            read_roots: vec![temp.path().to_path_buf()],
            write_roots: Vec::new(),
            deny_roots: vec![denied],
        };

        assert!(canonicalize_and_validate_filesystem_policy(&policy).is_err());
    }

    #[test]
    fn filesystem_policy_rejects_unresolved_empty_deny_root() {
        let policy = FilesystemPolicy {
            read_roots: Vec::new(),
            write_roots: Vec::new(),
            deny_roots: vec![PathBuf::new()],
        };

        let error = canonicalize_and_validate_filesystem_policy(&policy)
            .expect_err("unresolved deny marker must fail closed");
        assert!(error.to_string().contains("deny root #0 is empty"));
    }

    #[test]
    fn filesystem_policy_rejects_deny_parent_of_allow_root() {
        let temp = tempfile::tempdir().expect("tempdir");
        let allowed = temp.path().join("credentials").join("public");
        std::fs::create_dir_all(&allowed).expect("create allowed directory");
        let policy = FilesystemPolicy {
            read_roots: Vec::new(),
            write_roots: vec![allowed],
            deny_roots: vec![temp.path().join("credentials")],
        };

        assert!(canonicalize_and_validate_filesystem_policy(&policy).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn filesystem_policy_rejects_symlink_alias_of_covering_allow_root() {
        use std::os::unix::fs::symlink;

        let temp = tempfile::tempdir().expect("tempdir");
        let real = temp.path().join("real-home");
        let denied = real.join(".ssh");
        std::fs::create_dir_all(&denied).expect("create denied directory");
        let alias = temp.path().join("home-alias");
        symlink(&real, &alias).expect("create home symlink");
        let policy = FilesystemPolicy {
            read_roots: vec![alias],
            write_roots: Vec::new(),
            deny_roots: vec![denied],
        };

        assert!(canonicalize_and_validate_filesystem_policy(&policy).is_err());
    }

    #[test]
    fn filesystem_policy_preserves_canonical_disjoint_roots() {
        let temp = tempfile::tempdir().expect("tempdir");
        let allowed = temp.path().join("allowed");
        let denied = temp.path().join("denied");
        std::fs::create_dir(&allowed).expect("create allowed directory");
        std::fs::create_dir(&denied).expect("create denied directory");
        let policy = FilesystemPolicy {
            read_roots: vec![allowed.clone(), allowed.clone()],
            write_roots: Vec::new(),
            deny_roots: vec![denied.clone()],
        };

        let validated = canonicalize_and_validate_filesystem_policy(&policy)
            .expect("disjoint roots must remain representable");
        assert_eq!(
            validated.read_roots,
            vec![std::fs::canonicalize(allowed).expect("canonical allowed")]
        );
        assert_eq!(
            validated.deny_roots,
            vec![std::fs::canonicalize(denied).expect("canonical denied")]
        );
    }

    #[cfg(windows)]
    #[test]
    fn filesystem_policy_compares_missing_windows_suffixes_case_insensitively() {
        let temp = tempfile::tempdir().expect("tempdir");
        let policy = FilesystemPolicy {
            read_roots: vec![temp.path().join("CREDENTIALS")],
            write_roots: Vec::new(),
            deny_roots: vec![temp.path().join("credentials")],
        };

        assert!(
            canonicalize_and_validate_filesystem_policy(&policy).is_err(),
            "Windows path aliases that differ only in case must overlap"
        );
    }

    const AUTH_HOME_CHILD_MARKER: &str = "TIRITH_TEST_AUTH_HOME_CHILD";
    const AUTH_HOME_EXPECTED: &str = "TIRITH_TEST_AUTH_HOME_EXPECTED";
    const AUTH_HOME_SPOOF: &str = "TIRITH_TEST_AUTH_HOME_SPOOF";

    #[cfg(any(unix, windows))]
    #[test]
    fn authenticated_home_spoof_probe_child() {
        let Some(expected) = std::env::var_os(AUTH_HOME_EXPECTED) else {
            return;
        };
        if std::env::var_os(AUTH_HOME_CHILD_MARKER).is_none() {
            return;
        }
        let spoof = PathBuf::from(
            std::env::var_os(AUTH_HOME_SPOOF).expect("child spoof path must be provided"),
        );
        let resolved = authenticated_home_dir().expect("authenticated home must resolve");
        assert_eq!(resolved, PathBuf::from(expected));
        assert_ne!(resolved, spoof);
        for denied in try_deny_default_paths().expect("default denies must resolve") {
            assert!(
                !denied.starts_with(&spoof),
                "deny root followed spoofed HOME/USERPROFILE: {}",
                denied.display()
            );
        }
        eprintln!("tirith-authenticated-home-spoof-probe-ran");
    }

    #[cfg(any(unix, windows))]
    #[test]
    fn authenticated_home_ignores_environment_spoof() {
        let expected = authenticated_home_dir().expect("authenticated home must resolve");
        let temp = tempfile::tempdir().expect("tempdir");
        let spoof = std::fs::canonicalize(temp.path()).expect("canonical spoof directory");
        assert_ne!(expected, spoof, "test spoof must differ from account home");

        let output = std::process::Command::new(std::env::current_exe().expect("test executable"))
            .args([
                "--exact",
                "capsule::tests::authenticated_home_spoof_probe_child",
                "--nocapture",
            ])
            .env(AUTH_HOME_CHILD_MARKER, "1")
            .env(AUTH_HOME_EXPECTED, &expected)
            .env(AUTH_HOME_SPOOF, &spoof)
            .env("HOME", &spoof)
            .env("USERPROFILE", &spoof)
            .output()
            .expect("run isolated environment-spoof probe");
        let combined = format!(
            "{}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(output.status.success(), "child probe failed: {combined}");
        assert!(
            combined.contains("tirith-authenticated-home-spoof-probe-ran"),
            "child probe did not execute: {combined}"
        );
    }

    #[test]
    fn capsule_spec_roundtrips_through_json() {
        // The spec is serde-serializable (receipts / capsule-child handoff).
        let mut spec = CapsuleSpec::locked_down();
        spec.filesystem.read_roots.push(PathBuf::from("/tmp/work"));
        spec.network = NetworkPolicy::AllowListedDomains {
            domains: ["pypi.org".to_string()].into_iter().collect(),
            ports: [443u16].into_iter().collect(),
        };
        let json = serde_json::to_string(&spec).expect("serialize");
        let back: CapsuleSpec = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(spec, back);
    }

    #[test]
    fn default_spec_is_deny_all_network() {
        let spec = CapsuleSpec::default();
        assert!(spec.network.is_deny_all());
        assert!(!spec.environment.inherit);
    }
}
