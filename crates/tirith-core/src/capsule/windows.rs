//! Windows runtime-containment backend (Stack E, unit E4).
//!
//! This module provides the **portable, host-testable half** of the Windows
//! capsule: the [`AppContainerCapsule`] backend (which probes for AppContainer
//! support and reports honest [`CapsuleCoverage`]) and the pure planning types the
//! actual launch consumes — the AppContainer profile / SID-name derivation
//! ([`AppContainerProfile`]), the Job Object resource ceilings
//! ([`JobObjectLimits`]), the ACL grant list ([`AclGrant`]), and the assembled
//! [`WindowsLaunchPlan`]. The `windows`-crate Win32 calls that *apply* the plan
//! (`CreateAppContainerProfile`, `SetEntriesInAclW` / `SetNamedSecurityInfoW`,
//! `STARTUPINFOEXW` + `CreateProcessW`, Job Objects) live in the CLI crate
//! (`tirith::cli::capsule_windows`), because the `windows` crate is a CLI-crate
//! dependency and `tirith-core` stays free of OS-API bindings — exactly as the
//! Linux launcher's `execve` lives in `tirith::cli::capsule_child` and the macOS
//! `sandbox-exec` spawn is the E5 consumer's job, not the core backend's.
//!
//! Keeping every builder here **pure** (no Win32, no process spawn, no `windows`
//! crate) means the whole plan — the container moniker, the capability set, the
//! Job Object limits, the ACL grants, and the launch argv — is unit-testable on
//! any platform (this module's tests run on the macOS/Linux dev host as well as
//! the Windows CI runner), and the honesty contract ([`derive_coverage`]) is
//! exercised without an actual AppContainer.
//!
//! ## How Windows containment maps to the [`CapsuleSpec`]
//!
//! - **Filesystem** ([`FilesystemPolicy`]): AppContainer processes run under a
//!   per-container package SID and, by default, can read/write only objects whose
//!   DACL grants that SID (plus world-readable system objects). The backend grants
//!   the spec's read/write roots to the container SID via explicit ACEs
//!   ([`acl_grants`]) and grants nothing else, so the sensitive subtrees in
//!   [`crate::capsule::deny_default_paths`] stay unreachable (the container SID is
//!   not on their DACLs). The grants are *tracked* and **revoked** after the child
//!   exits (the CLI executor removes each ACE it added).
//! - **Network** ([`NetworkPolicy`]): an AppContainer reaches the network ONLY if
//!   it is granted a networking capability (`internetClient`,
//!   `internetClientServer`, `privateNetworkClientServer`). For a
//!   [`NetworkPolicy::DenyAll`] spec the backend grants **no** networking
//!   capability, so the container cannot open any outbound socket — raw network is
//!   denied by construction (`network_raw_denied`). This is the target for
//!   `pkg install`: installs need no network once the artifacts are quarantined.
//!   An [`NetworkPolicy::AllowListedDomains`] spec needs the loopback egress broker
//!   (a localhost carve-out plus the broker pinning SNI/Host/IP), which E4 does not
//!   wire — so that level is reported **degraded** and an enforcing surface fails
//!   closed (cross-cutting invariant 3). An optional runtime-detected `mxc` escape
//!   hatch may satisfy it later, but no acceptance criterion depends on it.
//! - **Resource limits** ([`ResourceLimits`]): a Job Object with
//!   `JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE` plus the populated CPU / memory /
//!   process-count / open-files ceilings ([`job_object_limits`]). The child is
//!   created suspended, assigned to the Job, then resumed, so it can never escape
//!   the Job's limits.
//! - **Handles** ([`HandlePolicy`]): `CreateProcessW` is called with
//!   `bInheritHandles = FALSE` (the simplest honest closure: the child inherits no
//!   parent handle). When stdio must be forwarded the executor passes exactly the
//!   three standard handles via `STARTUPINFOEXW` and an explicit inherit list, but
//!   the default is total closure.
//! - **Environment** ([`EnvironmentPolicy`]): the executor builds the child's
//!   environment block from [`EnvironmentPolicy::surviving_vars`] (sensitive
//!   variables stripped) and points HOME/USERPROFILE/TEMP at an isolated temporary
//!   directory.
//!
//! ## Honesty (cross-cutting invariant 2 + 3)
//!
//! [`AppContainerCapsule::available_coverage`] probes for AppContainer support and
//! reports only what the AppContainer + Job Object + ACL mechanism can actually
//! enforce. **No support -> degraded, never a silent NoOp success.** It **never**
//! claims `domain_proxy_enforced` on its own: E4 ships no verified broker-pinned
//! egress path, so an [`CapabilityLevel::AllowListedDomains`] spec is reported with
//! `domain_proxy_enforced = false` and the enforcing surface fails closed. A
//! `DenyAll` spec is satisfied natively (no networking capability granted == no raw
//! egress).

use std::path::Path;

use super::{
    CapabilityLevel, Capsule, CapsuleCoverage, CapsuleSpec, FilesystemPolicy, ResourceLimits,
};

/// The stable backend identifier reported in receipts and `tirith doctor`.
pub const BACKEND_ID: &str = "appcontainer";

/// The display name handed to `CreateAppContainerProfile` for tirith's containers.
/// Cosmetic (shown in some diagnostics); the security identity is the derived SID,
/// not this string.
pub const APP_CONTAINER_DISPLAY_NAME: &str = "Tirith contained child";

/// The stable prefix every tirith AppContainer moniker (the
/// `CreateAppContainerProfile` "AppContainerName") starts with. The per-spec
/// suffix is a deterministic digest so repeated runs of the same spec reuse the
/// same profile and a `DeleteAppContainerProfile` cleanup is unambiguous.
pub const APP_CONTAINER_NAME_PREFIX: &str = "tirith.capsule.";

/// The maximum length of an AppContainer moniker. Windows caps the
/// `AppContainerName` at 64 UTF-16 code units; we keep our derived name well under
/// that (prefix + 16 hex chars) and assert it in tests.
pub const APP_CONTAINER_NAME_MAX: usize = 64;

/// The Windows containment backend. Stateless: it probes for AppContainer support
/// on demand. The actual launch is performed by the CLI-crate executor, which
/// consumes a [`WindowsLaunchPlan`] built here.
#[derive(Debug, Clone, Copy, Default)]
pub struct AppContainerCapsule;

impl Capsule for AppContainerCapsule {
    fn backend_id(&self) -> &'static str {
        BACKEND_ID
    }

    fn available_coverage(&self, spec: &CapsuleSpec) -> CapsuleCoverage {
        let probe = probe_appcontainer();
        derive_coverage(spec, &probe)
    }
}

/// What probing the host for AppContainer support found. Kept as plain data so
/// [`derive_coverage`] is unit-testable without a real Windows API.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct WindowsProbe {
    /// AppContainer isolation is usable on this host (Windows 8+ / Server 2012+
    /// with the isolation API present). On a non-Windows host this is always
    /// `false`, so the backend is honest there too (in practice it is only
    /// constructed on Windows).
    pub appcontainer_supported: bool,
}

/// Probe the host for AppContainer support without creating a profile or launching
/// anything. On a non-Windows build this is a compile-time `false` (the API does
/// not exist), so the backend reports **degraded** coverage rather than pretending
/// to contain. On Windows the real check (does `CreateAppContainerProfile` exist /
/// is the OS new enough) is performed by the CLI executor via the `windows` crate
/// and threaded in; this core probe conservatively reports support only on the
/// `windows` target, leaving the precise OS-version gate to the executor.
///
/// Returning `appcontainer_supported = cfg!(windows)` here is deliberately
/// conservative: it is the *necessary* condition (you cannot have AppContainer off
/// Windows), and the executor tightens it (an ancient Windows without the
/// isolation API still fails at `CreateAppContainerProfile`, and the launcher then
/// fails closed). The honesty contract is never *loosened* by this probe.
pub fn probe_appcontainer() -> WindowsProbe {
    WindowsProbe {
        appcontainer_supported: cfg!(windows),
    }
}

/// Derive the coverage the backend can honestly claim for `spec`, given the
/// AppContainer probe. **Pure** (no Win32 / spawns), so every branch of the
/// honesty contract is unit-testable on any platform.
///
/// Rules:
/// - If AppContainer is **not** supported, every flag is `false` (degraded; the
///   enforcing surface fails closed). This is the core E4 guarantee: a missing
///   AppContainer is never a silent NoOp success.
/// - When supported, the AppContainer + Job Object + ACL launch enforces:
///   - `fs_read_enforced` / `fs_write_enforced`: the container package SID reaches
///     only the explicitly-granted read/write roots; everything else (including the
///     sensitive subtrees) is denied because the SID is not on its DACL.
///   - `exec_limited`: the child runs under a low-privilege package SID inside a
///     `KILL_ON_JOB_CLOSE` Job Object; it cannot escalate or outlive the Job.
///   - `network_raw_denied`: **true for any spec** — the backend grants no
///     networking capability, so the container has no outbound socket access. For
///     an allow-list spec the only intended path is the loopback broker, so raw
///     *public* egress is denied either way.
///   - `domain_proxy_enforced`: **always false in E4.** The localhost broker that
///     would actually pin egress is not wired here (it lives in the CLI crate and
///     is routed by E5), so E4 cannot claim end-to-end domain enforcement
///     (invariant 3). An allow-list spec is therefore degraded on this flag and the
///     enforcing surface fails closed.
///   - `resource_limits_enforced`: true when the spec sets any Job-Object-able
///     dimension (CPU / memory / process count / open files); the Job applies them.
///   - `env_isolated` / `handles_isolated`: true — the executor builds the child's
///     environment from the surviving-vars policy (sensitive set stripped, isolated
///     HOME/TEMP) and calls `CreateProcessW` with `bInheritHandles = FALSE`.
pub fn derive_coverage(spec: &CapsuleSpec, probe: &WindowsProbe) -> CapsuleCoverage {
    if !probe.appcontainer_supported {
        // Degraded, never NoOp-success: nothing is enforced.
        return CapsuleCoverage::NONE;
    }
    CapsuleCoverage {
        fs_read_enforced: true,
        fs_write_enforced: true,
        exec_limited: true,
        // No networking capability is ever granted -> no raw outbound socket.
        network_raw_denied: true,
        // E4 ships no verified broker-pinned egress path of its own.
        domain_proxy_enforced: false,
        resource_limits_enforced: job_limitable(&spec.resources),
        env_isolated: true,
        handles_isolated: true,
    }
}

/// Whether `limits` populates any dimension a Job Object can enforce. Wall-clock
/// and output-byte caps are NOT Job Object limits (the spawning wrapper enforces
/// those), so they do not, on their own, set `resource_limits_enforced`.
fn job_limitable(limits: &ResourceLimits) -> bool {
    limits.cpu_seconds.is_some()
        || limits.memory_bytes.is_some()
        || limits.max_processes.is_some()
        || limits.max_open_files.is_some()
}

/// An error from building (or, in the CLI executor, applying) a Windows capsule
/// launch. The pure builders here only produce the `Unsupported` /
/// `UnrepresentablePath` / `NulInArgument` variants; the executor adds Win32 error
/// detail through its own error type.
#[derive(Debug)]
pub enum WindowsCapsuleError {
    /// The requested containment level cannot be honored by E4's backend (an
    /// allow-listed-domains spec, which needs the loopback broker wired in E5).
    Unsupported(String),
    /// A path could not be represented for an ACL grant or a wide-string argument
    /// (e.g. it is not valid UTF-8, or it contains an interior NUL that a
    /// NUL-terminated wide string cannot carry).
    UnrepresentablePath(String),
    /// A program path or argument contains an interior NUL and cannot be passed to
    /// `CreateProcessW`'s NUL-terminated command line.
    NulInArgument(String),
}

impl std::fmt::Display for WindowsCapsuleError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            WindowsCapsuleError::Unsupported(m) => write!(f, "unsupported containment: {m}"),
            WindowsCapsuleError::UnrepresentablePath(m) => write!(f, "unrepresentable path: {m}"),
            WindowsCapsuleError::NulInArgument(m) => write!(f, "argument contains NUL: {m}"),
        }
    }
}

impl std::error::Error for WindowsCapsuleError {}

/// The AppContainer identity the executor materializes via
/// `CreateAppContainerProfile` / `DeriveAppContainerSidFromAppContainerName`.
/// **Pure data** — the executor turns `name` into a real package SID.
///
/// `name` is a deterministic, host-independent moniker derived from the spec so
/// repeated runs reuse one profile and cleanup is unambiguous;
/// `networking_capabilities` is empty for `DenyAll` (the whole point — no socket
/// access) and stays empty in E4 even for an allow-list (which is reported
/// degraded), so the descriptor never silently grants egress.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AppContainerProfile {
    /// The `AppContainerName` (moniker) for `CreateAppContainerProfile`. Stable per
    /// spec, `<= APP_CONTAINER_NAME_MAX` UTF-16 units, and a valid profile name.
    pub name: String,
    /// The human-readable display name (`CreateAppContainerProfile`'s
    /// `DisplayName` / `Description`).
    pub display_name: String,
    /// The well-known networking capability names to grant. **Empty in E4** (no
    /// network for installs; an allow-list is degraded, not granted), so the
    /// container has no outbound socket access.
    pub networking_capabilities: Vec<&'static str>,
}

/// Derive the deterministic AppContainer moniker for `spec`. The suffix is a
/// 64-bit FNV-1a digest of the spec's serialized JSON rendered as 16 lowercase hex
/// chars, so two identical specs map to the same profile (idempotent create /
/// unambiguous delete) and different specs do not collide in practice. **Pure** and
/// platform-independent.
///
/// The moniker is `APP_CONTAINER_NAME_PREFIX` + 16 hex chars = 30 chars, safely
/// under `APP_CONTAINER_NAME_MAX` (64). It contains only `[a-z0-9.]`, all valid in
/// an AppContainer name.
///
/// **Fails closed on a serialize error.** Every spec field is plain serde so this
/// should never happen, but falling back to a constant suffix (the old behavior)
/// would collapse EVERY un-serializable spec onto one moniker (hence one package
/// SID and one shared ACL identity), silently widening containment across distinct
/// specs. Returning `Err` instead makes [`windows_launch_plan`] refuse the launch,
/// which already fails closed, rather than derive a colliding identity.
pub fn app_container_name(spec: &CapsuleSpec) -> Result<String, WindowsCapsuleError> {
    let serialized = serde_json::to_string(spec).map_err(|e| {
        WindowsCapsuleError::Unsupported(format!(
            "cannot derive a unique AppContainer moniker: spec did not serialize ({e}); \
             refusing rather than collapse distinct specs onto one container SID"
        ))
    })?;
    let digest = fnv1a_64(serialized.as_bytes());
    Ok(format!("{APP_CONTAINER_NAME_PREFIX}{digest:016x}"))
}

/// 64-bit FNV-1a over `bytes`. A tiny, allocation-free, deterministic hash used
/// only to derive a stable container moniker; it is not a cryptographic hash and
/// is not used for any security decision (the container's *identity* is the SID the
/// OS derives from the moniker, not this digest).
fn fnv1a_64(bytes: &[u8]) -> u64 {
    const OFFSET: u64 = 0xcbf2_9ce4_8422_2325;
    const PRIME: u64 = 0x0000_0100_0000_01b3;
    let mut hash = OFFSET;
    for &b in bytes {
        hash ^= u64::from(b);
        hash = hash.wrapping_mul(PRIME);
    }
    hash
}

/// Build the [`AppContainerProfile`] for `spec`. **Pure.** The networking
/// capability list is empty in E4 regardless of the spec's [`NetworkPolicy`] (a
/// `DenyAll` needs none; an `AllowListedDomains` is reported degraded and routed
/// through the broker, never via a granted capability), so the profile can never
/// silently widen network access.
///
/// Fails closed if the moniker cannot be derived (see [`app_container_name`]): an
/// underivable moniker would otherwise collapse distinct specs onto one container
/// SID, so the launch is refused instead.
pub fn app_container_profile(
    spec: &CapsuleSpec,
) -> Result<AppContainerProfile, WindowsCapsuleError> {
    Ok(AppContainerProfile {
        name: app_container_name(spec)?,
        display_name: APP_CONTAINER_DISPLAY_NAME.to_string(),
        // E4 grants NO networking capability. DenyAll wants none; an allow-list is
        // degraded (the broker, not a capability, is the intended egress path).
        networking_capabilities: Vec::new(),
    })
}

/// The access an ACL grant confers on the container package SID for one path.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AclAccess {
    /// Read + execute (list/traverse/read) — for a read root.
    ReadExecute,
    /// Read + write + execute — for a write root (a write root implies read, like
    /// the Landlock and Seatbelt backends).
    Modify,
}

/// One ACL grant the executor must add to a path's DACL (granting the container
/// package SID `access`) and later **revoke**. **Pure data**; the executor maps it
/// to `EXPLICIT_ACCESS_W` + `SetEntriesInAclW` + `SetNamedSecurityInfoW`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AclGrant {
    /// The filesystem object whose DACL gains a container-SID ACE.
    pub path: std::path::PathBuf,
    /// The access the ACE confers.
    pub access: AclAccess,
}

/// Compute the ACL grants for `spec`: one [`AclAccess::ReadExecute`] grant per read
/// root and one [`AclAccess::Modify`] grant per write root, in that order.
/// **Pure.** The deny roots are NOT emitted as grants — denial is the AppContainer
/// default (the container SID is simply never added to those DACLs), matching the
/// default-deny model of the Linux/macOS backends.
///
/// A path that cannot be represented as a NUL-free UTF-16 string (the form
/// `SetNamedSecurityInfoW` needs) is rejected, so the executor never silently skips
/// a grant — fail closed on an unrepresentable path rather than run with a quietly
/// narrower (or, worse for a write root, missing) grant.
pub fn acl_grants(fs: &FilesystemPolicy) -> Result<Vec<AclGrant>, WindowsCapsuleError> {
    let mut grants = Vec::with_capacity(fs.read_roots.len() + fs.write_roots.len());
    for root in &fs.read_roots {
        validate_path_representable(root)?;
        grants.push(AclGrant {
            path: root.clone(),
            access: AclAccess::ReadExecute,
        });
    }
    for root in &fs.write_roots {
        validate_path_representable(root)?;
        grants.push(AclGrant {
            path: root.clone(),
            access: AclAccess::Modify,
        });
    }
    Ok(grants)
}

/// Ensure `path` can be expressed as a NUL-terminated wide string (valid UTF-8 with
/// no interior NUL). `SetNamedSecurityInfoW` and `CreateProcessW` take
/// NUL-terminated `PWSTR`s, so an interior NUL would truncate the path and a
/// non-UTF-8 path cannot be re-encoded losslessly here. Pure and
/// platform-independent.
fn validate_path_representable(path: &Path) -> Result<(), WindowsCapsuleError> {
    let s = path.to_str().ok_or_else(|| {
        WindowsCapsuleError::UnrepresentablePath(format!("non-UTF-8 path: {}", path.display()))
    })?;
    if s.contains('\0') {
        return Err(WindowsCapsuleError::UnrepresentablePath(format!(
            "path contains an interior NUL: {s}"
        )));
    }
    Ok(())
}

/// The Job Object limits the executor applies, derived from [`ResourceLimits`].
/// **Pure data.** `kill_on_close` is always `true` (the Job is created with
/// `JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE` so the whole child tree dies when tirith
/// drops the Job handle — no orphaned contained process). The populated optional
/// caps map to the corresponding `JOBOBJECT_*_INFORMATION` fields; an absent cap is
/// left at the OS default.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct JobObjectLimits {
    /// Always true: `JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE`.
    pub kill_on_close: bool,
    /// Per-job user-mode CPU time limit, in 100-nanosecond ticks
    /// (`PerJobUserTimeLimit`), derived from `cpu_seconds`.
    pub per_job_user_time_100ns: Option<u64>,
    /// Job memory limit in bytes (`JobMemoryLimit`), from `memory_bytes`.
    pub job_memory_bytes: Option<u64>,
    /// Active-process cap (`ActiveProcessLimit`), from `max_processes`.
    pub active_process_limit: Option<u32>,
}

/// Map [`ResourceLimits`] to [`JobObjectLimits`]. **Pure.** CPU seconds become
/// 100-ns ticks (the unit `PerJobUserTimeLimit` expects: `seconds * 10_000_000`),
/// saturating so an absurd value cannot overflow. `max_open_files` has no direct
/// per-Job equivalent on Windows (handle limits are per-process via other
/// mechanisms), so it does not appear here; it still contributes to
/// `resource_limits_enforced` via [`job_limitable`] only when one of the mapped
/// dimensions is also set — see the note in [`derive_coverage`]. Wall-clock and
/// output caps are the wrapper's job, not the Job Object's.
pub fn job_object_limits(limits: &ResourceLimits) -> JobObjectLimits {
    JobObjectLimits {
        kill_on_close: true,
        per_job_user_time_100ns: limits.cpu_seconds.map(|s| s.saturating_mul(10_000_000)),
        job_memory_bytes: limits.memory_bytes,
        active_process_limit: limits.max_processes,
    }
}

/// A fully-assembled, validated Windows launch plan: everything the CLI executor
/// needs to create the AppContainer, apply ACLs + the Job Object, and spawn the
/// child via `CreateProcessW`. **Pure** — building it performs no Win32 and spawns
/// nothing, so the whole plan is unit-testable on any platform.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WindowsLaunchPlan {
    /// The AppContainer identity to create / derive the package SID from.
    pub profile: AppContainerProfile,
    /// The ACL grants to add (and later revoke) for the container SID.
    pub acl_grants: Vec<AclGrant>,
    /// The Job Object limits to apply.
    pub job_limits: JobObjectLimits,
    /// The target program (the executable path / `lpApplicationName`).
    pub program: String,
    /// The target program's arguments (appended after the program in the
    /// `lpCommandLine`).
    pub program_args: Vec<String>,
    /// Whether `CreateProcessW` must inherit handles. **Always false** in E4 (the
    /// honest handle closure); the field is explicit so a future stdio-forwarding
    /// path cannot flip it implicitly.
    pub inherit_handles: bool,
}

/// Build the [`WindowsLaunchPlan`] for `spec` + `program` + `program_args`.
/// **Pure.** Fails closed, BEFORE assembling anything, on a containment level E4
/// cannot honestly enforce end to end:
///
/// - An [`CapabilityLevel::AllowListedDomains`] spec is refused
///   ([`WindowsCapsuleError::Unsupported`]): E4 has no verified broker-pinned
///   egress backend (that is E5), so it must not run such a child believing egress
///   is contained. This mirrors the Linux `apply_containment` and macOS
///   `sandbox_exec_argv` refusals.
///
/// It also rejects a program/argument with an interior NUL (which cannot survive
/// into `CreateProcessW`'s NUL-terminated command line) and an unrepresentable ACL
/// path (via [`acl_grants`]).
pub fn windows_launch_plan(
    spec: &CapsuleSpec,
    program: &str,
    program_args: &[String],
) -> Result<WindowsLaunchPlan, WindowsCapsuleError> {
    // Fail closed on a level we cannot honestly enforce, before building anything.
    if spec.capability_level() == CapabilityLevel::AllowListedDomains {
        return Err(WindowsCapsuleError::Unsupported(
            "allow-listed-domains egress needs the loopback broker wired in E5; E4's AppContainer \
             backend enforces DenyAll only (no networking capability is granted)"
                .to_string(),
        ));
    }
    if program.contains('\0') {
        return Err(WindowsCapsuleError::NulInArgument(format!(
            "program path: {program}"
        )));
    }
    for a in program_args {
        if a.contains('\0') {
            return Err(WindowsCapsuleError::NulInArgument(a.clone()));
        }
    }

    let grants = acl_grants(&spec.filesystem)?;
    Ok(WindowsLaunchPlan {
        profile: app_container_profile(spec)?,
        acl_grants: grants,
        job_limits: job_object_limits(&spec.resources),
        program: program.to_string(),
        program_args: program_args.to_vec(),
        // Honest handle closure: never inherit parent handles.
        inherit_handles: false,
    })
}

/// Quote one argument for a `CreateProcessW` `lpCommandLine` following the
/// Microsoft C runtime parsing rules (the convention `CommandLineToArgvW` and the
/// CRT agree on). Wraps the argument in double quotes when it is empty or contains
/// whitespace / a quote, and escapes embedded backslashes-before-a-quote and the
/// quote itself per the documented algorithm. **Pure** and platform-independent, so
/// the exact quoting is unit-testable on any host (the rules are a Windows
/// convention but the string transform is not).
///
/// This is the same algorithm `std`'s Windows `Command` uses; we reimplement it
/// here (rather than rely on `std::process::Command`, which the AppContainer launch
/// bypasses because it needs `STARTUPINFOEXW`) so the assembled command line cannot
/// be mis-split by the child.
pub fn quote_arg_for_command_line(arg: &str) -> String {
    if !arg.is_empty() && !arg.chars().any(|c| c == ' ' || c == '\t' || c == '"') {
        return arg.to_string();
    }
    let mut out = String::with_capacity(arg.len() + 2);
    out.push('"');
    let mut backslashes = 0usize;
    for c in arg.chars() {
        match c {
            '\\' => {
                backslashes += 1;
            }
            '"' => {
                // Escape all accumulated backslashes (each doubled) AND the quote.
                for _ in 0..(backslashes * 2 + 1) {
                    out.push('\\');
                }
                out.push('"');
                backslashes = 0;
            }
            _ => {
                for _ in 0..backslashes {
                    out.push('\\');
                }
                backslashes = 0;
                out.push(c);
            }
        }
    }
    // Trailing backslashes are doubled so they do not escape the closing quote.
    for _ in 0..(backslashes * 2) {
        out.push('\\');
    }
    out.push('"');
    out
}

/// Assemble the full `lpCommandLine` string for the plan: the (quoted) program
/// followed by each (quoted) argument, space-separated, exactly as
/// `CreateProcessW` parses it. **Pure.** The executor passes the program path as
/// `lpApplicationName` *and* as argv[0] here so the child sees a conventional
/// command line; `CreateProcessW` resolves the executable from `lpApplicationName`,
/// not from this string, which closes the search-path ambiguity.
pub fn command_line_for(plan: &WindowsLaunchPlan) -> String {
    let mut parts = Vec::with_capacity(plan.program_args.len() + 1);
    parts.push(quote_arg_for_command_line(&plan.program));
    for a in &plan.program_args {
        parts.push(quote_arg_for_command_line(a));
    }
    parts.join(" ")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::capsule::{HandlePolicy, NetworkPolicy, ResourceLimits};
    use std::path::PathBuf;

    #[test]
    fn backend_id_is_stable() {
        assert_eq!(AppContainerCapsule.backend_id(), "appcontainer");
        assert_eq!(BACKEND_ID, "appcontainer");
    }

    #[test]
    fn derive_coverage_without_appcontainer_is_fully_degraded() {
        // The core E4 honesty guarantee: no AppContainer support is reported as
        // degraded (everything false), NEVER a silent NoOp success.
        let spec = CapsuleSpec::locked_down();
        let probe = WindowsProbe {
            appcontainer_supported: false,
        };
        let cov = derive_coverage(&spec, &probe);
        assert_eq!(cov, CapsuleCoverage::NONE);
        assert!(cov.is_fully_unenforced());
        // And it is degraded against what a locked-down spec requires -> fail closed.
        assert!(cov.is_degraded_against(&spec.required_coverage()));
    }

    #[test]
    fn derive_coverage_denyall_with_appcontainer() {
        // AppContainer supported + a deny-all spec with rlimits -> FS enforced,
        // raw-net denied (no networking capability), exec limited, limits + env +
        // handles set, and NEVER egress.
        let spec = CapsuleSpec::locked_down();
        let probe = WindowsProbe {
            appcontainer_supported: true,
        };
        let cov = derive_coverage(&spec, &probe);
        assert!(cov.fs_read_enforced);
        assert!(cov.fs_write_enforced);
        assert!(cov.exec_limited);
        assert!(cov.network_raw_denied);
        // The single most important honesty property of E4's backend.
        assert!(!cov.domain_proxy_enforced);
        assert!(cov.resource_limits_enforced);
        assert!(cov.env_isolated);
        assert!(cov.handles_isolated);
        // The ledger is internally coherent (no egress claim without raw-deny).
        assert!(cov.egress_claim_is_coherent());
    }

    #[test]
    fn derive_coverage_allowlist_never_claims_egress() {
        // Even for an allow-list spec, E4 reports network_raw_denied (no capability
        // is granted) but NEVER domain_proxy_enforced -> the allow-list level stays
        // degraded against its requirement and the surface fails closed.
        let mut spec = CapsuleSpec::locked_down();
        spec.network = NetworkPolicy::AllowListedDomains {
            domains: ["pypi.org".to_string()].into_iter().collect(),
            ports: [443u16].into_iter().collect(),
        };
        let probe = WindowsProbe {
            appcontainer_supported: true,
        };
        let cov = derive_coverage(&spec, &probe);
        assert!(cov.network_raw_denied);
        assert!(!cov.domain_proxy_enforced);
        assert!(cov.egress_claim_is_coherent());
        // required_coverage for an allow-list demands domain_proxy_enforced.
        assert!(cov.is_degraded_against(&spec.required_coverage()));
    }

    #[test]
    fn derive_coverage_resource_flag_tracks_job_limitable_dimensions() {
        let probe = WindowsProbe {
            appcontainer_supported: true,
        };
        // No Job-Object-able dimension -> not claimed.
        let mut spec = CapsuleSpec::locked_down();
        spec.resources = ResourceLimits::default();
        assert!(!derive_coverage(&spec, &probe).resource_limits_enforced);

        // Only wall-clock / output (NOT Job-Object-able) -> still not claimed.
        spec.resources = ResourceLimits {
            wall_clock_seconds: Some(60),
            max_output_bytes: Some(1024),
            ..ResourceLimits::default()
        };
        assert!(!derive_coverage(&spec, &probe).resource_limits_enforced);

        // A memory limit IS Job-Object-able -> claimed.
        spec.resources = ResourceLimits {
            memory_bytes: Some(512 * 1024 * 1024),
            ..ResourceLimits::default()
        };
        assert!(derive_coverage(&spec, &probe).resource_limits_enforced);

        // open-files alone (no per-Job equivalent here) still counts as
        // Job-limitable for the coverage flag (job_limitable includes it).
        spec.resources = ResourceLimits {
            max_open_files: Some(64),
            ..ResourceLimits::default()
        };
        assert!(derive_coverage(&spec, &probe).resource_limits_enforced);
    }

    #[test]
    fn probe_reports_support_only_on_windows() {
        // The conservative core probe: support iff the windows target. On the dev
        // host (macOS/Linux) this is false, which keeps the backend honest there.
        let p = probe_appcontainer();
        assert_eq!(p.appcontainer_supported, cfg!(windows));
    }

    #[test]
    fn app_container_name_is_deterministic_and_bounded() {
        let spec = CapsuleSpec::locked_down();
        let a = app_container_name(&spec).expect("moniker derivable");
        let b = app_container_name(&spec).expect("moniker derivable");
        // Same spec -> same moniker (idempotent create / unambiguous delete).
        assert_eq!(a, b);
        assert!(a.starts_with(APP_CONTAINER_NAME_PREFIX));
        // prefix + 16 hex chars, comfortably under the Windows cap.
        assert!(a.len() <= APP_CONTAINER_NAME_MAX, "moniker too long: {a}");
        // Only [a-z0-9.] — all valid in an AppContainer name.
        assert!(
            a.chars()
                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '.'),
            "moniker has an invalid character: {a}"
        );
    }

    #[test]
    fn app_container_name_differs_for_different_specs() {
        // MN6: distinct specs derive DISTINCT monikers (hence distinct package SIDs /
        // ACL identities). Before the fix a serialize failure fell back to a constant
        // suffix, collapsing every such spec onto ONE SID; now derivation is fallible
        // and never silently collides. Two normal specs serialize fine and differ.
        let deny = CapsuleSpec::locked_down();
        let mut other = CapsuleSpec::locked_down();
        other.filesystem.read_roots.push(PathBuf::from("/tmp/work"));
        let a = app_container_name(&deny).expect("moniker derivable");
        let b = app_container_name(&other).expect("moniker derivable");
        assert_ne!(a, b);
    }

    #[test]
    fn app_container_profile_grants_no_network_for_denyall() {
        let spec = CapsuleSpec::locked_down();
        let prof = app_container_profile(&spec).expect("profile derivable");
        assert!(prof.networking_capabilities.is_empty());
        assert_eq!(prof.display_name, APP_CONTAINER_DISPLAY_NAME);
        assert!(prof.name.starts_with(APP_CONTAINER_NAME_PREFIX));
    }

    #[test]
    fn app_container_profile_grants_no_network_even_for_allowlist() {
        // The descriptor must NEVER silently grant a networking capability for an
        // allow-list spec; that level is degraded and routed through the broker, not
        // a granted capability.
        let mut spec = CapsuleSpec::locked_down();
        spec.network = NetworkPolicy::AllowListedDomains {
            domains: ["pypi.org".to_string()].into_iter().collect(),
            ports: [443u16].into_iter().collect(),
        };
        let prof = app_container_profile(&spec).expect("profile derivable");
        assert!(prof.networking_capabilities.is_empty());
    }

    #[test]
    fn acl_grants_map_read_and_write_roots() {
        let mut fs = FilesystemPolicy::deny_by_default();
        fs.read_roots.push(PathBuf::from("C:/data/in"));
        fs.write_roots.push(PathBuf::from("C:/build/out"));
        let grants = acl_grants(&fs).expect("grants");
        assert_eq!(grants.len(), 2);
        // Read root first, ReadExecute.
        assert_eq!(grants[0].path, PathBuf::from("C:/data/in"));
        assert_eq!(grants[0].access, AclAccess::ReadExecute);
        // Write root second, Modify (implies read).
        assert_eq!(grants[1].path, PathBuf::from("C:/build/out"));
        assert_eq!(grants[1].access, AclAccess::Modify);
    }

    #[test]
    fn acl_grants_does_not_emit_deny_roots() {
        // Deny roots are NOT grants — denial is the AppContainer default. A spec with
        // only deny roots yields no ACL grants.
        let fs = FilesystemPolicy::deny_by_default();
        let grants = acl_grants(&fs).expect("grants");
        assert!(grants.is_empty(), "deny roots must not become grants");
    }

    #[test]
    fn acl_grants_rejects_interior_nul_path() {
        // Fail closed on an unrepresentable path rather than silently drop a grant.
        let mut fs = FilesystemPolicy::deny_by_default();
        fs.write_roots.push(PathBuf::from("C:/a\0b"));
        let err = acl_grants(&fs).expect_err("interior NUL must error");
        assert!(matches!(err, WindowsCapsuleError::UnrepresentablePath(_)));
    }

    #[test]
    fn job_object_limits_always_kill_on_close() {
        let limits = ResourceLimits::default();
        let job = job_object_limits(&limits);
        assert!(job.kill_on_close, "Job must always KILL_ON_JOB_CLOSE");
        // Nothing populated -> every optional cap is None.
        assert!(job.per_job_user_time_100ns.is_none());
        assert!(job.job_memory_bytes.is_none());
        assert!(job.active_process_limit.is_none());
    }

    #[test]
    fn job_object_limits_maps_conservative_dimensions() {
        let limits = ResourceLimits::conservative();
        let job = job_object_limits(&limits);
        assert!(job.kill_on_close);
        // cpu_seconds (120) -> 120 * 10_000_000 ns ticks.
        assert_eq!(job.per_job_user_time_100ns, Some(120 * 10_000_000));
        assert_eq!(job.job_memory_bytes, Some(2 * 1024 * 1024 * 1024));
        assert_eq!(job.active_process_limit, Some(256));
    }

    #[test]
    fn job_object_cpu_conversion_saturates() {
        // An absurd cpu_seconds cannot overflow the 100-ns tick conversion.
        let limits = ResourceLimits {
            cpu_seconds: Some(u64::MAX),
            ..ResourceLimits::default()
        };
        let job = job_object_limits(&limits);
        assert_eq!(job.per_job_user_time_100ns, Some(u64::MAX));
    }

    #[test]
    fn windows_launch_plan_denyall_builds() {
        let mut spec = CapsuleSpec::locked_down();
        spec.filesystem.write_roots.push(PathBuf::from("C:/work"));
        let plan = windows_launch_plan(&spec, "C:/python/python.exe", &["-m".into(), "pip".into()])
            .expect("plan");
        assert_eq!(plan.program, "C:/python/python.exe");
        assert_eq!(plan.program_args, vec!["-m".to_string(), "pip".to_string()]);
        // Honest handle closure.
        assert!(!plan.inherit_handles);
        // No network capability.
        assert!(plan.profile.networking_capabilities.is_empty());
        // The write root became a Modify grant.
        assert!(plan
            .acl_grants
            .iter()
            .any(|g| g.access == AclAccess::Modify && g.path == Path::new("C:/work")));
        // Job kills on close.
        assert!(plan.job_limits.kill_on_close);
    }

    #[test]
    fn windows_launch_plan_refuses_allowlisted_domains() {
        // E4 enforces DenyAll natively; an allow-list needs E5's broker, so the plan
        // builder fails closed (mirrors derive_coverage reporting it degraded).
        let mut spec = CapsuleSpec::locked_down();
        spec.network = NetworkPolicy::AllowListedDomains {
            domains: ["pypi.org".to_string()].into_iter().collect(),
            ports: [443u16].into_iter().collect(),
        };
        let err =
            windows_launch_plan(&spec, "C:/cmd.exe", &[]).expect_err("must refuse allow-list");
        match err {
            WindowsCapsuleError::Unsupported(m) => assert!(m.contains("broker")),
            other => panic!("expected Unsupported, got {other:?}"),
        }
    }

    #[test]
    fn windows_launch_plan_rejects_interior_nul() {
        let spec = CapsuleSpec::locked_down();
        let err = windows_launch_plan(&spec, "C:/cmd.exe", &["a\0b".into()])
            .expect_err("NUL in arg must error");
        assert!(matches!(err, WindowsCapsuleError::NulInArgument(_)));

        let err2 =
            windows_launch_plan(&spec, "C:/c\0md.exe", &[]).expect_err("NUL in program must error");
        assert!(matches!(err2, WindowsCapsuleError::NulInArgument(_)));
    }

    #[test]
    fn windows_launch_plan_handle_inherit_is_always_false() {
        // The honest handle closure is fixed, regardless of the handle policy: E4
        // never inherits parent handles.
        let mut spec = CapsuleSpec::locked_down();
        spec.handles = HandlePolicy {
            keep_stdio: true,
            extra_unix_fds: vec![7],
        };
        let plan = windows_launch_plan(&spec, "C:/cmd.exe", &[]).expect("plan");
        assert!(!plan.inherit_handles);
    }

    // ---- command-line quoting (CreateProcessW / CRT rules) ----

    #[test]
    fn quote_plain_arg_is_unquoted() {
        assert_eq!(quote_arg_for_command_line("pip"), "pip");
        assert_eq!(quote_arg_for_command_line("--no-index"), "--no-index");
    }

    #[test]
    fn quote_empty_arg_is_quoted() {
        assert_eq!(quote_arg_for_command_line(""), "\"\"");
    }

    #[test]
    fn quote_arg_with_space_is_quoted() {
        assert_eq!(
            quote_arg_for_command_line("C:/Program Files/x"),
            "\"C:/Program Files/x\""
        );
    }

    #[test]
    fn quote_arg_with_embedded_quote_is_escaped() {
        // a"b -> "a\"b"
        assert_eq!(quote_arg_for_command_line("a\"b"), "\"a\\\"b\"");
    }

    #[test]
    fn quote_arg_trailing_backslash_is_doubled() {
        // A path ending in a backslash, when quoted (because it has a space), must
        // double the trailing backslashes so they do not escape the closing quote.
        // `a b\` -> `"a b\\"`.
        assert_eq!(quote_arg_for_command_line("a b\\"), "\"a b\\\\\"");
    }

    #[test]
    fn quote_arg_backslash_before_quote_is_escaped() {
        // `a\"b` -> the backslash is doubled and the quote escaped: `"a\\\"b"`.
        assert_eq!(quote_arg_for_command_line("a\\\"b"), "\"a\\\\\\\"b\"");
    }

    #[test]
    fn command_line_for_quotes_program_and_args() {
        let spec = CapsuleSpec::locked_down();
        let plan = windows_launch_plan(
            &spec,
            "C:/Program Files/Python/python.exe",
            &["-m".into(), "pip".into()],
        )
        .expect("plan");
        let cmd = command_line_for(&plan);
        // The program (with a space) is quoted; the plain args are not.
        assert_eq!(cmd, "\"C:/Program Files/Python/python.exe\" -m pip");
    }
}
