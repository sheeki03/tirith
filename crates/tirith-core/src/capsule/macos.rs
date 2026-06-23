//! macOS runtime-containment backend (Stack E, unit E3).
//!
//! This module provides the macOS half of the capsule: the [`SeatbeltCapsule`]
//! backend (which probes for `sandbox-exec` and reports honest
//! [`CapsuleCoverage`]) and the pure SBPL-profile / argv builders the E5
//! consumers use to launch a contained child through Apple's Seatbelt sandbox.
//!
//! ## Why `sandbox-exec`, not a re-exec launcher
//!
//! Unlike Linux (where the capsule re-execs `tirith __capsule-child` and applies
//! Landlock + seccomp to itself before `execve`), macOS containment is expressed
//! as a Seatbelt **profile** (SBPL) handed to the system `sandbox-exec(1)`
//! wrapper:
//!
//! ```text
//! /usr/bin/sandbox-exec -p '<profile>' -- <prog> <arg>...
//! ```
//!
//! `sandbox-exec` compiles the profile, applies it to itself, and then `execve`s
//! the target, so the profile binds the real program. The backend therefore does
//! NOT need an in-process launcher; it produces the profile and the argv, and an
//! E5 consumer spawns `sandbox-exec`. Keeping the profile/argv builders **pure**
//! (no process spawn) means the SBPL contents are unit-testable on any platform.
//!
//! ## The profile (cross-cutting invariant 2 + the E3 spec)
//!
//! [`sandbox_profile`] emits an SBPL profile that starts with `(deny default)`
//! and then opens exactly what the [`CapsuleSpec`] grants:
//!
//! - filesystem: `(allow file-read* (subpath "<root>"))` for each read root and
//!   `(allow file-read* file-write* (subpath "<root>"))` for each write root,
//!   over the `(deny default)` base. The sensitive subtrees in
//!   [`crate::capsule::deny_default_paths`] are denied for free by the default
//!   deny unless a grant explicitly covers them (the locked-down default grants
//!   nothing, so they stay denied).
//! - network: `(deny network*)` for a [`NetworkPolicy::DenyAll`] spec; for an
//!   [`NetworkPolicy::AllowListedDomains`] spec, `(deny network*)` with a single
//!   carve-out `(allow network-outbound (remote ip "localhost:*"))` so the child
//!   can only reach the loopback egress broker, never the public internet
//!   directly.
//!
//! ## Honesty (cross-cutting invariant 2 + 3)
//!
//! [`SeatbeltCapsule::available_coverage`] probes for `sandbox-exec`. **Absent or
//! non-executable -> degraded, never a silent NoOp success** (the whole point of
//! the E3 spec): the FS/exec/network/env/handle flags are all reported `false`,
//! so an enforcing surface fails closed rather than running the child unconfined
//! while believing it is contained.
//!
//! As with E2, the backend **never** claims `domain_proxy_enforced` on its own.
//! Even though a Seatbelt `(deny network*)` with a localhost carve-out denies
//! every raw outbound socket except the loopback broker (so `network_raw_denied`
//! holds for an allow-list spec), domain-egress *enforcement* additionally
//! requires the broker itself to be running and pinning SNI/Host/IP — and the
//! broker lives in the CLI crate and is wired by E5. So an
//! [`CapabilityLevel::AllowListedDomains`] spec is reported with
//! `domain_proxy_enforced = false`; the enforcing surface fails closed until the
//! broker is verified (cross-cutting invariant 3). A `DenyAll` spec is satisfied
//! natively.

use std::path::Path;

use super::{
    CapabilityLevel, Capsule, CapsuleCoverage, CapsuleSpec, FilesystemPolicy, NetworkPolicy,
};

/// The stable backend identifier reported in receipts and `tirith doctor`.
pub const BACKEND_ID: &str = "seatbelt";

/// The system Seatbelt wrapper the backend drives. An absolute path on purpose:
/// the backend must not resolve `sandbox-exec` from a caller-controlled `PATH`
/// (that would let a planted binary masquerade as the sandbox). macOS ships it
/// here.
pub const SANDBOX_EXEC_PATH: &str = "/usr/bin/sandbox-exec";

/// The macOS containment backend. Stateless: it probes for `sandbox-exec` on
/// demand.
#[derive(Debug, Clone, Copy, Default)]
pub struct SeatbeltCapsule;

impl Capsule for SeatbeltCapsule {
    fn backend_id(&self) -> &'static str {
        BACKEND_ID
    }

    fn available_coverage(&self, spec: &CapsuleSpec) -> CapsuleCoverage {
        let probe = probe_sandbox_exec();
        derive_coverage(spec, &probe)
    }
}

/// What probing for the Seatbelt wrapper found: whether `sandbox-exec` exists and
/// is an executable regular file at [`SANDBOX_EXEC_PATH`]. Kept as plain data so
/// [`derive_coverage`] is unit-testable without touching the filesystem.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct SeatbeltProbe {
    /// `/usr/bin/sandbox-exec` exists and is an executable regular file.
    pub sandbox_exec_usable: bool,
}

/// Probe the host for a usable `sandbox-exec`, without launching anything. A
/// macOS install that has had `sandbox-exec` removed or replaced with something
/// non-executable yields `sandbox_exec_usable = false`; the backend then reports
/// **degraded** coverage (all flags false) rather than pretending to contain.
/// This is the honest precondition for every Seatbelt coverage claim.
///
/// On a non-macOS host this always returns `false` (the path does not exist), so
/// the backend is honest there too; in practice the backend is only constructed
/// on macOS.
pub fn probe_sandbox_exec() -> SeatbeltProbe {
    SeatbeltProbe {
        sandbox_exec_usable: path_is_executable_file(Path::new(SANDBOX_EXEC_PATH)),
    }
}

/// Whether `path` is a regular file with at least one execute bit set. Used to
/// validate `sandbox-exec` is genuinely runnable, not merely present. A symlink to
/// a regular executable file resolves (we follow it via `metadata`). On a
/// non-Unix build this falls back to "is a regular file" (the execute-bit check is
/// Unix-only), which keeps the function compiling everywhere; the backend is
/// macOS-gated anyway.
fn path_is_executable_file(path: &Path) -> bool {
    let meta = match std::fs::metadata(path) {
        Ok(m) => m,
        Err(_) => return false,
    };
    if !meta.is_file() {
        return false;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        // Any of the user/group/other execute bits.
        meta.permissions().mode() & 0o111 != 0
    }
    #[cfg(not(unix))]
    {
        true
    }
}

/// Derive the coverage the backend can honestly claim for `spec`, given the
/// `sandbox-exec` probe. **Pure** (no syscalls / spawns), so every branch of the
/// honesty contract is unit-testable on any platform.
///
/// Rules:
/// - If `sandbox-exec` is **not** usable, every flag is `false` (degraded; the
///   enforcing surface fails closed). This is the core E3 guarantee: a missing
///   sandbox is never a silent NoOp success.
/// - When usable, Seatbelt enforces, from the `(deny default)` profile:
///   - `fs_read_enforced` / `fs_write_enforced`: confined to the granted subpaths.
///   - `exec_limited`: the profile governs `process-exec*`; a contained child
///     cannot escape the profile (it is inherited across `exec`).
///   - `network_raw_denied`: `(deny network*)` denies every raw outbound socket.
///     For an allow-list spec the only carve-out is the loopback broker, so raw
///     *public* sockets are still denied — `network_raw_denied` holds either way.
///   - `domain_proxy_enforced`: **always false in E3.** The localhost carve-out
///     only lets the child reach the broker; the broker that actually pins egress
///     lives in the CLI crate and is wired by E5, so E3 cannot claim end-to-end
///     domain enforcement (invariant 3). An allow-list spec is therefore degraded
///     on this flag and the enforcing surface fails closed.
///   - `resource_limits_enforced`: the SBPL profile alone imposes no rlimit, but
///     on macOS the capsule is always launched through the E5 wrapper
///     (`tirith::cli::capsule::macos_contained_command`), which applies the
///     CPU/memory/open-files rlimits in a `pre_exec` hook before `sandbox-exec`
///     execs the target. The backend + wrapper are inseparable on macOS (there is
///     no Seatbelt launch that bypasses the wrapper), so this reports `true`
///     whenever the spec sets a dimension the wrapper enforces. Honest: it
///     describes what a contained macOS launch actually delivers, not the profile
///     in isolation.
///
///     **macOS gap (do NOT over-report): `max_processes` is not enforced.** Unlike
///     Linux (`RLIMIT_NPROC`) and Windows (Job Object `ActiveProcessLimit`), macOS
///     has no per-process process-count cap: `RLIMIT_NPROC` is per real UID, so
///     applying it would throttle the whole user (and could lock the user's own
///     shell out of forking) without bounding the contained child's subtree, a
///     false fork-bomb cap, not a real one. The wrapper therefore does NOT apply it
///     (see `apply_macos_rlimits`), and `max_processes` is deliberately excluded
///     from `rlimitable` below. Consequence, kept honest by construction: a spec
///     whose ONLY resource limit is `max_processes` reports
///     `resource_limits_enforced = false` here, so `required_coverage` (which
///     demands the flag whenever any dimension is set) is degraded and an enforcing
///     surface fails closed rather than running believing the fork-bomb cap holds.
///     When other macOS-enforceable dimensions are ALSO set (the conservative
///     locked-down spec sets CPU+memory), the flag is `true` for THOSE dimensions;
///     it never promised a per-dimension fork-bomb guarantee (just as
///     `wall_clock`/`max_output` are launcher-enforced, not setrlimit). The absence
///     of a macOS process-tree cap is a documented limitation, not a silent `true`.
///   - `env_isolated` / `handles_isolated`: likewise applied by the E5 wrapper,
///     not the SBPL profile. The wrapper `env_clear`s and re-adds only the
///     surviving (sensitive-stripped) variables, points HOME/TMPDIR/XDG_* at a
///     fresh temp dir, and closes inherited fds above the handle allow-list in
///     `pre_exec`. Because every macOS contained launch goes through that wrapper,
///     the backend reports these `true` (matching what the launch delivers) rather
///     than describing the bare profile — which would make a locked-down spec
///     spuriously degraded and refuse every enforcing surface on macOS.
///
/// This honestly reflects the backend+wrapper as a unit, mirroring how the Linux
/// backend reports `env_isolated`/`handles_isolated`/`resource_limits_enforced`
/// from its launcher. It does NOT claim `domain_proxy_enforced` (E3 ships no
/// broker), so an allow-list spec still fails closed.
pub fn derive_coverage(spec: &CapsuleSpec, probe: &SeatbeltProbe) -> CapsuleCoverage {
    if !probe.sandbox_exec_usable {
        // Degraded, never NoOp-success: nothing is enforced.
        return CapsuleCoverage::NONE;
    }
    // The wrapper applies CPU/memory/open-files rlimits; report the flag when the
    // spec sets any dimension it actually enforces. `wall_clock`/`max_output` are
    // launcher-enforced (not setrlimit), so they do not raise this alone. CRUCIALLY,
    // `max_processes` is EXCLUDED: macOS has no per-process process-count cap
    // (RLIMIT_NPROC is per-UID; see the doc above and `apply_macos_rlimits`), so the
    // fork-bomb dimension is enforced by nothing here. Excluding it keeps the flag
    // honest: a `max_processes`-only spec then reports false and an enforcing
    // surface degrades/fails closed instead of trusting an absent cap. (Linux's
    // `rlimitable` includes max_processes because RLIMIT_NPROC there is per-process;
    // macOS genuinely cannot, so the two backends legitimately differ on this one.)
    let rlimitable = spec.resources.cpu_seconds.is_some()
        || spec.resources.memory_bytes.is_some()
        || spec.resources.max_open_files.is_some();
    CapsuleCoverage {
        fs_read_enforced: true,
        fs_write_enforced: true,
        exec_limited: true,
        // `(deny network*)` denies raw sockets; the allow-list carve-out is
        // localhost-only, so raw public egress is denied in both modes.
        network_raw_denied: true,
        // E3 ships no verified broker-pinned egress path of its own.
        domain_proxy_enforced: false,
        // The E5 wrapper applies the rlimit / env / handle policy that the profile
        // alone does not; a macOS contained launch always goes through it.
        resource_limits_enforced: rlimitable,
        env_isolated: true,
        handles_isolated: true,
    }
}

/// An error from building the Seatbelt launch for a child.
#[derive(Debug)]
pub enum SeatbeltError {
    /// The requested containment level cannot be honored by E3's backend (an
    /// allow-listed-domains spec, which needs the CLI-crate broker wired in E5).
    Unsupported(String),
    /// A path could not be represented safely in an SBPL string (e.g. it is not
    /// valid UTF-8, or contains a character the profile cannot quote).
    UnrepresentablePath(String),
    /// A program path or argument contains an interior NUL and cannot be passed
    /// to `exec`.
    NulInArgument(String),
}

impl std::fmt::Display for SeatbeltError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SeatbeltError::Unsupported(m) => write!(f, "unsupported containment: {m}"),
            SeatbeltError::UnrepresentablePath(m) => write!(f, "unrepresentable path: {m}"),
            SeatbeltError::NulInArgument(m) => write!(f, "argument contains NUL: {m}"),
        }
    }
}

impl std::error::Error for SeatbeltError {}

/// Build the Seatbelt SBPL profile for `spec`. **Pure** — returns the profile text
/// the E5 wrapper hands to `sandbox-exec -p`. The profile is `(deny default)` plus
/// the spec's grants; see the module docs for the exact shape.
///
/// Errors when a read/write root cannot be represented as an SBPL `subpath` string
/// (non-UTF-8 path or a path containing a double-quote / backslash that SBPL string
/// literals cannot carry — Seatbelt has no escape for those, so we refuse rather
/// than emit a profile that would silently widen access).
///
/// This does NOT refuse an allow-list spec (it emits the localhost carve-out the
/// E3 spec calls for); whether that level is *honestly enforced* is a separate
/// question answered by [`derive_coverage`] / [`available_coverage`], which keep
/// `domain_proxy_enforced` false until E5 wires the broker.
pub fn sandbox_profile(spec: &CapsuleSpec) -> Result<String, SeatbeltError> {
    let mut p = String::new();
    // SBPL version header + default-deny. `(version 1)` is the stable SBPL dialect
    // `sandbox-exec` accepts.
    p.push_str("(version 1)\n");
    p.push_str("(deny default)\n");
    // Allow the child to read its own dynamic-linker / shared caches and resolve
    // its program. Without this even a fully-allowed binary cannot start, because
    // `(deny default)` denies the loader's reads. These are read-only system paths,
    // not user data, and are required for ANY process to exec under Seatbelt.
    p.push_str(SANDBOX_BASE_EXEC_ALLOW);

    // Filesystem grants over the default deny.
    push_filesystem_rules(&mut p, &spec.filesystem)?;

    // Network policy.
    match &spec.network {
        NetworkPolicy::DenyAll => {
            // Belt-and-suspenders: default already denies, but state it explicitly
            // so the profile reads as "network is denied" and a future edit cannot
            // accidentally open it by adding an allow above the implicit deny.
            p.push_str("(deny network*)\n");
        }
        NetworkPolicy::AllowListedDomains { .. } => {
            // Deny all network, then carve out ONLY the loopback broker. The child
            // can reach 127.0.0.1 / ::1 (the broker), never a public address; the
            // broker is what actually validates the destination domain/IP. Ports
            // are enforced by the broker (it only honors CONNECT to configured
            // ports), not in the profile, because Seatbelt's `local`/`remote`
            // filters are address-oriented and the broker is the policy gate.
            p.push_str("(deny network*)\n");
            p.push_str(SANDBOX_LOOPBACK_BROKER_ALLOW);
        }
    }

    Ok(p)
}

/// The minimal read-only system allowances every contained child needs just to
/// `exec` and run under `(deny default)`: the dynamic linker, the shared dyld
/// cache, and system frameworks/libraries. Read-only, system-owned paths only — no
/// user data, no write. Without these, `(deny default)` blocks the loader and the
/// child cannot start at all.
const SANDBOX_BASE_EXEC_ALLOW: &str = "\
(allow process-fork)
(allow process-exec*)
(allow sysctl-read)
(allow mach-lookup)
(allow file-read* (subpath \"/usr/lib\"))
(allow file-read* (subpath \"/usr/share\"))
(allow file-read* (subpath \"/System/Library\"))
(allow file-read* (subpath \"/Library/Frameworks\"))
(allow file-read* (literal \"/dev/null\") (literal \"/dev/zero\") (literal \"/dev/random\") (literal \"/dev/urandom\"))
(allow file-read-metadata)
";

/// The single network carve-out for an allow-list spec: outbound to the loopback
/// broker only. Public egress stays denied by the preceding `(deny network*)`.
const SANDBOX_LOOPBACK_BROKER_ALLOW: &str = "\
(allow network-outbound (remote ip \"localhost:*\"))
(allow network-outbound (remote ip \"127.0.0.1:*\"))
(allow network-outbound (remote ip \"[::1]:*\"))
";

/// Append the filesystem `allow` rules for `fs` to the profile. Read roots get
/// `file-read*`; write roots get `file-read* file-write*` (a write root implies
/// read, matching the Landlock backend). Every path is emitted as an SBPL
/// `subpath` string literal; an unrepresentable path is an error (we never silently
/// widen).
fn push_filesystem_rules(p: &mut String, fs: &FilesystemPolicy) -> Result<(), SeatbeltError> {
    for root in &fs.read_roots {
        let lit = sbpl_path_literal(root)?;
        p.push_str("(allow file-read* (subpath ");
        p.push_str(&lit);
        p.push_str("))\n");
    }
    for root in &fs.write_roots {
        let lit = sbpl_path_literal(root)?;
        p.push_str("(allow file-read* file-write* (subpath ");
        p.push_str(&lit);
        p.push_str("))\n");
    }
    Ok(())
}

/// Render `path` as a quoted SBPL string literal (e.g. `"/tmp/work"`). SBPL string
/// literals are double-quoted and have **no escape mechanism** for an embedded
/// double-quote or backslash, so a path containing either is rejected rather than
/// emitted (an unescaped `"` would terminate the literal early and change the
/// profile's meaning — a containment-widening bug). Non-UTF-8 paths are likewise
/// rejected. Pure and platform-independent.
fn sbpl_path_literal(path: &Path) -> Result<String, SeatbeltError> {
    let s = path.to_str().ok_or_else(|| {
        SeatbeltError::UnrepresentablePath(format!("non-UTF-8 path: {}", path.display()))
    })?;
    if s.contains('"') || s.contains('\\') {
        return Err(SeatbeltError::UnrepresentablePath(format!(
            "path contains a quote or backslash SBPL cannot escape: {s}"
        )));
    }
    let mut lit = String::with_capacity(s.len() + 2);
    lit.push('"');
    lit.push_str(s);
    lit.push('"');
    Ok(lit)
}

/// Build the full `sandbox-exec` argv for a contained launch:
/// `[/usr/bin/sandbox-exec, -p, <profile>, --, <prog>, <arg>...]`. **Pure** — the
/// E5 wrapper feeds this to a `Command`/`posix_spawn`. Refuses an allow-listed
/// spec (E3 has no verified broker-pinned egress backend; consistent with
/// [`derive_coverage`] reporting that level degraded) and rejects a program/arg
/// with an interior NUL.
///
/// The profile is passed inline via `-p` rather than a `-f <file>` so the caller
/// does not have to manage a temp profile file; `sandbox-exec` accepts a profile
/// literal there.
pub fn sandbox_exec_argv(
    spec: &CapsuleSpec,
    program: &str,
    program_args: &[String],
) -> Result<Vec<String>, SeatbeltError> {
    // Fail closed on a level we cannot honestly enforce end-to-end, BEFORE building
    // anything. E3 enforces DenyAll natively; an allow-list needs E5's broker.
    if spec.capability_level() == CapabilityLevel::AllowListedDomains {
        return Err(SeatbeltError::Unsupported(
            "allow-listed-domains egress needs the loopback broker wired in E5; E3's Seatbelt \
             backend enforces DenyAll only"
                .to_string(),
        ));
    }
    if program.contains('\0') {
        return Err(SeatbeltError::NulInArgument(format!(
            "program path: {program}"
        )));
    }
    for a in program_args {
        if a.contains('\0') {
            return Err(SeatbeltError::NulInArgument(a.clone()));
        }
    }
    let profile = sandbox_profile(spec)?;
    let mut argv = Vec::with_capacity(program_args.len() + 5);
    argv.push(SANDBOX_EXEC_PATH.to_string());
    argv.push("-p".to_string());
    argv.push(profile);
    argv.push("--".to_string());
    argv.push(program.to_string());
    argv.extend(program_args.iter().cloned());
    Ok(argv)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::capsule::{NetworkPolicy, ResourceLimits};
    use std::path::PathBuf;

    #[test]
    fn backend_id_is_stable() {
        assert_eq!(SeatbeltCapsule.backend_id(), "seatbelt");
        assert_eq!(BACKEND_ID, "seatbelt");
    }

    #[test]
    fn derive_coverage_without_sandbox_exec_is_fully_degraded() {
        // The core E3 honesty guarantee: a missing/removed sandbox-exec is reported
        // as degraded (everything false), NEVER a silent NoOp success.
        let spec = CapsuleSpec::locked_down();
        let probe = SeatbeltProbe {
            sandbox_exec_usable: false,
        };
        let cov = derive_coverage(&spec, &probe);
        assert_eq!(cov, CapsuleCoverage::NONE);
        assert!(cov.is_fully_unenforced());
        // And it is degraded against what a locked-down spec requires -> fail closed.
        assert!(cov.is_degraded_against(&spec.required_coverage()));
    }

    #[test]
    fn derive_coverage_denyall_with_sandbox_exec() {
        // sandbox-exec usable + a locked-down deny-all spec -> FS enforced, raw-net
        // denied, exec limited, and NEVER egress. The E5 wrapper applies the
        // rlimit/env/handle policy, so the backend+wrapper unit reports those true
        // for a spec that sets them (the conservative locked-down spec does).
        let spec = CapsuleSpec::locked_down();
        let probe = SeatbeltProbe {
            sandbox_exec_usable: true,
        };
        let cov = derive_coverage(&spec, &probe);
        assert!(cov.fs_read_enforced);
        assert!(cov.fs_write_enforced);
        assert!(cov.exec_limited);
        assert!(cov.network_raw_denied);
        // The single most important honesty property of E3's backend.
        assert!(!cov.domain_proxy_enforced);
        // The wrapper applies these; locked_down() sets conservative rlimits + a
        // sensitive-stripping env policy + a handle allow-list.
        assert!(cov.resource_limits_enforced);
        assert!(cov.env_isolated);
        assert!(cov.handles_isolated);
        // The ledger is internally coherent (no egress claim without raw-deny).
        assert!(cov.egress_claim_is_coherent());
    }

    #[test]
    fn derive_coverage_locked_down_is_not_degraded_with_sandbox_exec() {
        // C4 regression guard: a locked-down deny-all spec must NOT be degraded on
        // macOS when sandbox-exec is usable. Before the fix, env/handle/rlimit flags
        // were hard-coded false, so the backend was degraded against its own
        // required coverage and EVERY enforcing surface (pkg install, gateway
        // --capsule, run --capsule) refused on macOS even though the wrapper
        // delivers the policy.
        let spec = CapsuleSpec::locked_down();
        let probe = SeatbeltProbe {
            sandbox_exec_usable: true,
        };
        let cov = derive_coverage(&spec, &probe);
        // Deny-all does not require the proxy, and the wrapper supplies env/handle/
        // rlimit coverage, so nothing required is missing -> not degraded.
        assert!(
            !cov.is_degraded_against(&spec.required_coverage()),
            "locked-down macOS coverage must satisfy its requirement: {cov:?}"
        );
    }

    #[test]
    fn derive_coverage_resource_flag_tracks_rlimitable_dimensions() {
        // Honesty: the resource flag follows the dimensions the wrapper enforces
        // (CPU/mem/open-files), not a blanket true.
        let probe = SeatbeltProbe {
            sandbox_exec_usable: true,
        };
        // No rlimit-able dimension -> not claimed.
        let mut spec = CapsuleSpec::locked_down();
        spec.resources = ResourceLimits::default();
        assert!(!derive_coverage(&spec, &probe).resource_limits_enforced);
        // Only wall-clock / output (not setrlimit on macOS) -> still not claimed.
        spec.resources = ResourceLimits {
            wall_clock_seconds: Some(60),
            max_output_bytes: Some(1024),
            ..ResourceLimits::default()
        };
        assert!(!derive_coverage(&spec, &probe).resource_limits_enforced);
        // A CPU limit IS applied by the wrapper -> claimed.
        spec.resources = ResourceLimits {
            cpu_seconds: Some(30),
            ..ResourceLimits::default()
        };
        assert!(derive_coverage(&spec, &probe).resource_limits_enforced);
    }

    #[test]
    fn derive_coverage_allowlist_never_claims_egress() {
        // Even for an allow-list spec, E3 reports network_raw_denied (the carve-out
        // is localhost-only) but NEVER domain_proxy_enforced -> the allow-list
        // level stays degraded against its requirement and the surface fails closed.
        let mut spec = CapsuleSpec::locked_down();
        spec.network = NetworkPolicy::AllowListedDomains {
            domains: ["pypi.org".to_string()].into_iter().collect(),
            ports: [443u16].into_iter().collect(),
        };
        let probe = SeatbeltProbe {
            sandbox_exec_usable: true,
        };
        let cov = derive_coverage(&spec, &probe);
        assert!(cov.network_raw_denied);
        assert!(!cov.domain_proxy_enforced);
        assert!(cov.egress_claim_is_coherent());
        // required_coverage for an allow-list demands domain_proxy_enforced.
        assert!(cov.is_degraded_against(&spec.required_coverage()));
    }

    #[test]
    fn profile_denies_default_and_network_for_denyall() {
        let spec = CapsuleSpec::locked_down();
        let profile = sandbox_profile(&spec).expect("profile");
        assert!(profile.contains("(deny default)"));
        assert!(profile.contains("(deny network*)"));
        // No localhost carve-out for a deny-all spec.
        assert!(!profile.contains("network-outbound"));
    }

    #[test]
    fn profile_carves_out_only_loopback_for_allowlist() {
        let mut spec = CapsuleSpec::locked_down();
        spec.network = NetworkPolicy::AllowListedDomains {
            domains: ["pypi.org".to_string()].into_iter().collect(),
            ports: [443u16].into_iter().collect(),
        };
        let profile = sandbox_profile(&spec).expect("profile");
        assert!(profile.contains("(deny default)"));
        assert!(profile.contains("(deny network*)"));
        // The ONLY network allow is the loopback broker; no public address appears.
        assert!(profile.contains("(allow network-outbound (remote ip \"localhost:*\"))"));
        assert!(profile.contains("127.0.0.1"));
        assert!(profile.contains("[::1]"));
        // The allow-listed public domain must NOT appear in the profile: the broker
        // (not the SBPL) gates the destination domain.
        assert!(!profile.contains("pypi.org"));
    }

    #[test]
    fn profile_emits_read_and_write_subpaths() {
        let mut spec = CapsuleSpec::locked_down();
        spec.filesystem.read_roots.push(PathBuf::from("/opt/data"));
        spec.filesystem
            .write_roots
            .push(PathBuf::from("/tmp/build-out"));
        let profile = sandbox_profile(&spec).expect("profile");
        assert!(profile.contains("(allow file-read* (subpath \"/opt/data\"))"));
        assert!(
            profile.contains("(allow file-read* file-write* (subpath \"/tmp/build-out\"))"),
            "write root must imply read+write: {profile}"
        );
    }

    #[test]
    fn profile_rejects_path_with_quote_or_backslash() {
        // SBPL string literals have no escape; a path with a quote/backslash must be
        // refused, not emitted (an unescaped quote would widen the profile).
        let mut spec = CapsuleSpec::locked_down();
        spec.filesystem.read_roots.push(PathBuf::from("/tmp/a\"b"));
        let err = sandbox_profile(&spec).expect_err("quote in path must error");
        assert!(matches!(err, SeatbeltError::UnrepresentablePath(_)));

        let mut spec2 = CapsuleSpec::locked_down();
        spec2
            .filesystem
            .write_roots
            .push(PathBuf::from("/tmp/a\\b"));
        let err2 = sandbox_profile(&spec2).expect_err("backslash in path must error");
        assert!(matches!(err2, SeatbeltError::UnrepresentablePath(_)));
    }

    #[test]
    fn sbpl_path_literal_quotes_plain_path() {
        let lit = sbpl_path_literal(Path::new("/usr/local/lib")).expect("literal");
        assert_eq!(lit, "\"/usr/local/lib\"");
    }

    #[test]
    fn sandbox_exec_argv_denyall_builds_command() {
        let spec = CapsuleSpec::locked_down();
        let argv = sandbox_exec_argv(&spec, "/usr/bin/python3", &["-m".into(), "pip".into()])
            .expect("argv");
        assert_eq!(argv[0], "/usr/bin/sandbox-exec");
        assert_eq!(argv[1], "-p");
        // argv[2] is the profile.
        assert!(argv[2].contains("(deny default)"));
        // Then the separator, the program, and its args.
        assert_eq!(argv[3], "--");
        assert_eq!(argv[4], "/usr/bin/python3");
        assert_eq!(argv[5], "-m");
        assert_eq!(argv[6], "pip");
    }

    #[test]
    fn sandbox_exec_argv_refuses_allowlisted_domains() {
        // E3 enforces DenyAll natively; an allow-list needs E5's broker, so the
        // argv builder fails closed (mirrors derive_coverage reporting it degraded).
        let mut spec = CapsuleSpec::locked_down();
        spec.network = NetworkPolicy::AllowListedDomains {
            domains: ["pypi.org".to_string()].into_iter().collect(),
            ports: [443u16].into_iter().collect(),
        };
        let err = sandbox_exec_argv(&spec, "/bin/sh", &[]).expect_err("must refuse allow-list");
        match err {
            SeatbeltError::Unsupported(m) => assert!(m.contains("broker")),
            other => panic!("expected Unsupported, got {other:?}"),
        }
    }

    #[test]
    fn sandbox_exec_argv_rejects_interior_nul() {
        let spec = CapsuleSpec::locked_down();
        let err =
            sandbox_exec_argv(&spec, "/bin/sh", &["a\0b".into()]).expect_err("NUL must error");
        assert!(matches!(err, SeatbeltError::NulInArgument(_)));

        let err2 =
            sandbox_exec_argv(&spec, "/bin/s\0h", &[]).expect_err("NUL in program must error");
        assert!(matches!(err2, SeatbeltError::NulInArgument(_)));
    }

    #[test]
    fn probe_does_not_panic_and_is_consistent() {
        // On the macOS CI runner sandbox-exec exists; elsewhere it does not. Either
        // way the probe returns without panicking, and a usable probe means the path
        // is a real executable file.
        let p = probe_sandbox_exec();
        if p.sandbox_exec_usable {
            assert!(path_is_executable_file(Path::new(SANDBOX_EXEC_PATH)));
        }
    }

    #[test]
    fn max_processes_alone_is_not_reported_enforced_on_macos() {
        // IM4: macOS cannot enforce a per-process fork-bomb cap (RLIMIT_NPROC is
        // per-UID), so a spec whose ONLY resource limit is `max_processes` must NOT
        // claim resource_limits_enforced. Otherwise an enforcing surface would run
        // believing the fork-bomb cap holds when it does not (a DoS over-report).
        let probe = SeatbeltProbe {
            sandbox_exec_usable: true,
        };
        let mut spec = CapsuleSpec::locked_down();
        spec.resources = ResourceLimits {
            max_processes: Some(256),
            ..ResourceLimits::default()
        };
        let cov = derive_coverage(&spec, &probe);
        assert!(
            !cov.resource_limits_enforced,
            "macOS must not claim resource_limits_enforced for a max_processes-only spec \
             (it has no per-process process cap): {cov:?}"
        );
        // And because required_coverage demands the flag whenever ANY dimension is
        // set, this spec is degraded -> an enforcing surface fails closed on the gap.
        assert!(
            cov.is_degraded_against(&spec.required_coverage()),
            "a max_processes-only spec must be degraded on macOS so the surface fails closed"
        );
    }

    #[test]
    fn conservative_limits_are_reported_enforced() {
        // C4: the SBPL profile alone applies no rlimit, but the E5 wrapper (which
        // every macOS contained launch goes through) applies CPU/mem/open-files via
        // setrlimit in pre_exec. So a spec with conservative limits honestly reports
        // resource_limits_enforced = true (the backend+wrapper unit delivers them).
        let mut spec = CapsuleSpec::locked_down();
        spec.resources = ResourceLimits::conservative();
        let probe = SeatbeltProbe {
            sandbox_exec_usable: true,
        };
        let cov = derive_coverage(&spec, &probe);
        assert!(cov.resource_limits_enforced);
    }
}
