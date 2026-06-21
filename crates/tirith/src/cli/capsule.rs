//! Consumer-facing capsule launch surface (Stack E, unit E5).
//!
//! E1-E4 built the portable type layer (`tirith_core::capsule`) and the three OS
//! backends (Landlock/seccomp on Linux, Seatbelt on macOS, AppContainer + Job
//! Objects on Windows), each exposing its own primitive:
//!
//! - **Linux**: re-exec `tirith __capsule-child <spec-json> -- <prog> <args>`;
//!   the launcher ([`crate::cli::capsule_child`]) applies the full containment
//!   sequence in a single-threaded child and `execve`s the target.
//! - **macOS**: [`tirith_core::capsule::macos::sandbox_exec_argv`] builds a
//!   `sandbox-exec -p <profile> -- <prog> <args>` argv; this wrapper additionally
//!   scrubs the environment and applies the rlimits/handle closure the SBPL
//!   profile alone does not.
//! - **Windows**: [`crate::cli::capsule_windows::launch_contained`] creates the
//!   AppContainer, ACLs the roots, and runs the child in a kill-on-close Job.
//!
//! This module is the **single seam every E5 consumer goes through** — `runner.rs`
//! (`tirith run`), `temp_run.rs` (opt-in `--capsule`), the package-firewall install
//! (Stack D's D4), and the gateway upstream spawn. It picks the host backend,
//! probes the coverage it can actually deliver for the spec, and **fails closed**
//! when an enforcing surface's required coverage is not met (cross-cutting
//! invariant 2). Analysis-only surfaces may opt to run degraded with an honest
//! banner instead.
//!
//! ## Two launch shapes
//!
//! Consumers need one of two things, so this module offers both on top of the same
//! backend selection + fail-closed gate:
//!
//! - [`run_to_completion`]: build the contained child, inherit stdio, wait, return
//!   its exit code. Used by `tirith run`, `temp-run --capsule`, and D4's install.
//! - [`spawn_piped`]: build the contained child with piped stdin/stdout/stderr and
//!   hand back a [`std::process::Child`] the caller bridges (the MCP gateway needs
//!   to sit between the client and the upstream server). Linux and macOS support
//!   this directly (both are `Command`-shaped); Windows piped-stdio containment is
//!   not wired yet, so on Windows `spawn_piped` fails closed.
//!
//! ## Honesty
//!
//! [`CapsuleOutcome`] always reports the backend id and the achieved coverage, so
//! a caller and a receipt can record exactly what was (and was not) enforced. A
//! degraded run that policy permitted is flagged `degraded = true`; an enforcing
//! caller that did not permit degradation never reaches a spawn at all.

use std::process::{Child, Command, Stdio};

#[cfg_attr(
    any(target_os = "linux", target_os = "macos", target_os = "windows"),
    allow(unused_imports)
)]
use tirith_core::capsule::{Capsule, CapsuleCoverage, CapsuleSpec, NoOpCapsule};

/// The backend selected for this host, with the coverage it can deliver for a
/// given spec. Returned by [`select_backend`] so a caller can decide (before
/// spawning anything) whether to proceed, fail closed, or run degraded.
#[derive(Debug, Clone)]
pub struct SelectedBackend {
    /// Stable backend identifier (`"landlock-seccomp"`, `"seatbelt"`,
    /// `"appcontainer"`, or `"noop"`).
    pub backend_id: &'static str,
    /// The coverage this backend can achieve for the probed spec on this host
    /// *right now*. Never over-reports (invariant 2).
    pub coverage: CapsuleCoverage,
    /// The coverage the spec requires; compared against [`Self::coverage`] to
    /// decide fail-closed.
    pub required: CapsuleCoverage,
}

impl SelectedBackend {
    /// Whether the achieved coverage falls short of what the spec requires. An
    /// enforcing surface fails closed when this is true (unless policy permits
    /// degraded); an analysis surface may run anyway with a banner.
    pub fn is_degraded(&self) -> bool {
        self.coverage.is_degraded_against(&self.required)
    }
}

/// How a launch should treat a backend that cannot fully satisfy the spec.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DegradedPolicy {
    /// Enforcing surface: refuse to run if coverage is degraded (the default for
    /// `pkg install`, the contained gateway, `tirith run --require-capsule`).
    FailClosed,
    /// Analysis surface: run the program even under degraded/NoOp coverage, but
    /// the caller is expected to print an honest banner. Used by
    /// `temp-run --capsule` (a best-effort hardening over an explicitly
    /// not-a-boundary command).
    AllowDegraded,
}

/// The result of a contained run-to-completion.
#[derive(Debug, Clone)]
pub struct CapsuleOutcome {
    /// The child's exit code (or a synthesized non-zero on signal/spawn failure,
    /// matching the consumer convention of "child's code, else non-zero").
    pub exit_code: i32,
    /// The backend that ran it.
    pub backend_id: &'static str,
    /// The coverage actually achieved.
    pub coverage: CapsuleCoverage,
    /// Whether the run proceeded under degraded coverage (only possible with
    /// [`DegradedPolicy::AllowDegraded`]).
    pub degraded: bool,
}

impl CapsuleOutcome {
    /// A compact, secret-free description of the coverage actually achieved, for a
    /// receipt or an audit line (D4's `ArtifactScanReceipt` records the capsule
    /// backend + coverage). Reads the [`CapsuleCoverage`] flags into a stable
    /// string so a downstream record need not depend on the struct shape.
    pub fn coverage_summary(&self) -> String {
        let c = &self.coverage;
        format!(
            "fs_read={} fs_write={} exec={} raw_net_denied={} domain_proxy={} \
             rlimits={} env={} handles={}",
            c.fs_read_enforced,
            c.fs_write_enforced,
            c.exec_limited,
            c.network_raw_denied,
            c.domain_proxy_enforced,
            c.resource_limits_enforced,
            c.env_isolated,
            c.handles_isolated,
        )
    }
}

/// A fail-closed refusal: the host backend cannot deliver the spec's required
/// coverage and the caller demanded full containment.
#[derive(Debug, Clone)]
pub struct CapsuleRefused {
    /// The backend that was selected (its coverage was insufficient).
    pub backend_id: &'static str,
    /// A human-readable, secret-free explanation of the shortfall.
    pub reason: String,
}

impl std::fmt::Display for CapsuleRefused {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Name the backend so an audited refusal records which backend fell short.
        write!(f, "[{}] {}", self.backend_id, self.reason)
    }
}

/// Probe the host backend for `spec` WITHOUT launching anything.
///
/// Returns the backend id, the coverage it can achieve, and the coverage the spec
/// requires. The selection is purely a function of the compile target:
/// Landlock/seccomp on Linux, Seatbelt on macOS, AppContainer on Windows, and the
/// always-degraded [`NoOpCapsule`] on any other target. A backend that probes its
/// OS mechanism and finds it absent reports degraded coverage here, so the caller
/// can fail closed before any side effect.
pub fn select_backend(spec: &CapsuleSpec) -> SelectedBackend {
    let required = spec.required_coverage();

    #[cfg(target_os = "linux")]
    {
        let cap = tirith_core::capsule::linux::LandlockSeccompCapsule;
        return SelectedBackend {
            backend_id: cap.backend_id(),
            coverage: cap.available_coverage(spec),
            required,
        };
    }

    #[cfg(target_os = "macos")]
    {
        let cap = tirith_core::capsule::macos::SeatbeltCapsule;
        return SelectedBackend {
            backend_id: cap.backend_id(),
            coverage: cap.available_coverage(spec),
            required,
        };
    }

    #[cfg(target_os = "windows")]
    {
        let cap = tirith_core::capsule::windows::AppContainerCapsule;
        return SelectedBackend {
            backend_id: cap.backend_id(),
            coverage: cap.available_coverage(spec),
            required,
        };
    }

    #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
    {
        let cap = NoOpCapsule;
        SelectedBackend {
            backend_id: cap.backend_id(),
            coverage: cap.available_coverage(spec),
            required,
        }
    }
}

/// Build a secret-free description of the coverage shortfall (which required flags
/// the backend could not deliver), for a fail-closed refusal message.
fn shortfall_reason(backend_id: &str, sel: &SelectedBackend) -> String {
    let c = &sel.coverage;
    let r = &sel.required;
    let mut missing: Vec<&str> = Vec::new();
    if r.fs_read_enforced && !c.fs_read_enforced {
        missing.push("fs_read");
    }
    if r.fs_write_enforced && !c.fs_write_enforced {
        missing.push("fs_write");
    }
    if r.exec_limited && !c.exec_limited {
        missing.push("exec_limited");
    }
    if r.network_raw_denied && !c.network_raw_denied {
        missing.push("network_raw_denied");
    }
    if r.domain_proxy_enforced && !c.domain_proxy_enforced {
        missing.push("domain_proxy_enforced");
    }
    if r.resource_limits_enforced && !c.resource_limits_enforced {
        missing.push("resource_limits");
    }
    if r.env_isolated && !c.env_isolated {
        missing.push("env_isolated");
    }
    if r.handles_isolated && !c.handles_isolated {
        missing.push("handles_isolated");
    }
    format!(
        "capsule backend '{backend_id}' cannot enforce required containment on this host \
         (missing: {}); refusing to run uncontained",
        if missing.is_empty() {
            "<none>".to_string()
        } else {
            missing.join(", ")
        }
    )
}

/// Run `program` + `args` inside a capsule and wait for it, inheriting the
/// parent's stdio. This is the run-to-completion shape used by `tirith run`,
/// `temp-run --capsule`, and D4's package install.
///
/// On [`DegradedPolicy::FailClosed`] a degraded/NoOp backend returns
/// `Err(CapsuleRefused)` BEFORE spawning anything (fail-closed). On
/// [`DegradedPolicy::AllowDegraded`] a degraded backend still runs the program
/// (uncontained or partially contained) and reports `degraded = true`.
///
/// `cwd` (when `Some`) is the child's working directory. `extra_env` is applied on
/// top of the backend's environment handling (used by callers like the gateway to
/// set `TIRITH_GATEWAY_DEPTH`); on a contained Unix backend the environment is
/// otherwise scrubbed per the spec's [`tirith_core::capsule::EnvironmentPolicy`].
pub fn run_to_completion(
    spec: &CapsuleSpec,
    program: &str,
    args: &[String],
    cwd: Option<&std::path::Path>,
    extra_env: &[(String, String)],
    degraded: DegradedPolicy,
) -> Result<CapsuleOutcome, CapsuleRefused> {
    let sel = select_backend(spec);
    let is_degraded = sel.is_degraded();

    if is_degraded && degraded == DegradedPolicy::FailClosed {
        return Err(CapsuleRefused {
            backend_id: sel.backend_id,
            reason: shortfall_reason(sel.backend_id, &sel),
        });
    }

    // Windows uses its own blocking launcher (no Command shape).
    #[cfg(target_os = "windows")]
    {
        if !is_degraded {
            return windows_run_to_completion(spec, program, args, &sel);
        }
        // Degraded + AllowDegraded on Windows: run uncontained via a plain Command.
        return uncontained_run(program, args, cwd, extra_env, &sel, true);
    }

    #[cfg(not(target_os = "windows"))]
    {
        if is_degraded {
            // AllowDegraded: run uncontained but honestly flagged.
            return uncontained_run(program, args, cwd, extra_env, &sel, true);
        }
        let mut cmd = build_contained_command(spec, program, args, &sel)?;
        if let Some(dir) = cwd {
            cmd.current_dir(dir);
        }
        for (k, v) in extra_env {
            cmd.env(k, v);
        }
        let status = cmd.status().map_err(|e| CapsuleRefused {
            backend_id: sel.backend_id,
            reason: format!("capsule launch failed: {e}"),
        })?;
        Ok(CapsuleOutcome {
            exit_code: status.code().unwrap_or(128),
            backend_id: sel.backend_id,
            coverage: sel.coverage,
            degraded: false,
        })
    }
}

/// Run uncontained (degraded path) via a plain `Command`, inheriting stdio. Only
/// reached under [`DegradedPolicy::AllowDegraded`]; the outcome is flagged
/// `degraded`.
fn uncontained_run(
    program: &str,
    args: &[String],
    cwd: Option<&std::path::Path>,
    extra_env: &[(String, String)],
    sel: &SelectedBackend,
    degraded: bool,
) -> Result<CapsuleOutcome, CapsuleRefused> {
    let mut cmd = Command::new(program);
    cmd.args(args);
    if let Some(dir) = cwd {
        cmd.current_dir(dir);
    }
    for (k, v) in extra_env {
        cmd.env(k, v);
    }
    let status = cmd.status().map_err(|e| CapsuleRefused {
        backend_id: sel.backend_id,
        reason: format!("command launch failed: {e}"),
    })?;
    Ok(CapsuleOutcome {
        exit_code: status.code().unwrap_or(128),
        backend_id: sel.backend_id,
        coverage: sel.coverage,
        degraded,
    })
}

/// Spawn `program` + `args` inside a capsule with **piped** stdin/stdout/stderr and
/// return the live [`Child`] for the caller to bridge. Used by the MCP gateway,
/// which must read/write the child's stdio to proxy the protocol.
///
/// Fail-closed semantics match [`run_to_completion`]: a degraded/NoOp backend
/// under [`DegradedPolicy::FailClosed`] returns `Err` before spawning. Windows
/// piped-stdio containment is not wired (the E4 `ContainedChild` does not expose
/// piped handles), so on Windows this fails closed for an enforcing caller and, for
/// an `AllowDegraded` caller, spawns an uncontained piped child flagged degraded.
///
/// Returns the spawned child plus the [`SelectedBackend`] (so the caller can record
/// the backend/coverage and whether it ran degraded).
pub fn spawn_piped(
    spec: &CapsuleSpec,
    program: &str,
    args: &[String],
    extra_env: &[(String, String)],
    degraded: DegradedPolicy,
) -> Result<(Child, SelectedBackend, bool), CapsuleRefused> {
    let sel = select_backend(spec);
    let is_degraded = sel.is_degraded();

    // Windows: no piped-stdio contained launcher in E4/E5. Fail closed for an
    // enforcing caller; spawn uncontained-but-piped for an AllowDegraded caller.
    #[cfg(target_os = "windows")]
    {
        let _ = spec;
        if degraded == DegradedPolicy::FailClosed {
            return Err(CapsuleRefused {
                backend_id: sel.backend_id,
                reason: "contained piped-stdio launch is not available on Windows yet; \
                         refusing to run the upstream uncontained"
                    .to_string(),
            });
        }
        let child = spawn_uncontained_piped(program, args, extra_env, &sel)?;
        return Ok((child, sel, true));
    }

    #[cfg(not(target_os = "windows"))]
    {
        if is_degraded {
            if degraded == DegradedPolicy::FailClosed {
                return Err(CapsuleRefused {
                    backend_id: sel.backend_id,
                    reason: shortfall_reason(sel.backend_id, &sel),
                });
            }
            let child = spawn_uncontained_piped(program, args, extra_env, &sel)?;
            return Ok((child, sel, true));
        }
        let mut cmd = build_contained_command(spec, program, args, &sel)?;
        for (k, v) in extra_env {
            cmd.env(k, v);
        }
        cmd.stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let child = cmd.spawn().map_err(|e| CapsuleRefused {
            backend_id: sel.backend_id,
            reason: format!("capsule launch failed: {e}"),
        })?;
        Ok((child, sel, false))
    }
}

/// Spawn an uncontained piped child (degraded path). Only reached under
/// [`DegradedPolicy::AllowDegraded`].
fn spawn_uncontained_piped(
    program: &str,
    args: &[String],
    extra_env: &[(String, String)],
    sel: &SelectedBackend,
) -> Result<Child, CapsuleRefused> {
    let mut cmd = Command::new(program);
    cmd.args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    for (k, v) in extra_env {
        cmd.env(k, v);
    }
    cmd.spawn().map_err(|e| CapsuleRefused {
        backend_id: sel.backend_id,
        reason: format!("command launch failed: {e}"),
    })
}

/// Build the `Command` that launches `program` + `args` contained, for the Unix
/// backends. Linux re-execs the `__capsule-child` launcher (which applies
/// containment then `execve`s); macOS wraps in `sandbox-exec` and additionally
/// scrubs the environment + applies rlimits/fd-closure that the SBPL profile alone
/// does not.
///
/// The returned `Command` has had its environment/argv set up; the caller adds
/// `cwd`/`extra_env`/stdio. NOT used on Windows (which has its own launcher).
#[cfg(not(target_os = "windows"))]
fn build_contained_command(
    spec: &CapsuleSpec,
    program: &str,
    args: &[String],
    sel: &SelectedBackend,
) -> Result<Command, CapsuleRefused> {
    #[cfg(target_os = "linux")]
    {
        linux_contained_command(spec, program, args, sel)
    }
    #[cfg(target_os = "macos")]
    {
        macos_contained_command(spec, program, args, sel)
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        // No Unix backend on this target; the select_backend probe would have been
        // NoOp and the degraded gate already handled it. Reaching here means the
        // caller bypassed the gate, so fail closed.
        let _ = (spec, program, args);
        Err(CapsuleRefused {
            backend_id: sel.backend_id,
            reason: "no containment backend on this target".to_string(),
        })
    }
}

/// Linux: re-exec `tirith __capsule-child <spec-json> -- <program> <args>`. The
/// launcher applies the full containment sequence in a single-threaded child and
/// `execve`s the target, so the parent only has to spawn the current executable
/// with the right argv. The spec travels as JSON.
#[cfg(target_os = "linux")]
fn linux_contained_command(
    spec: &CapsuleSpec,
    program: &str,
    args: &[String],
    sel: &SelectedBackend,
) -> Result<Command, CapsuleRefused> {
    let exe = std::env::current_exe().map_err(|e| CapsuleRefused {
        backend_id: sel.backend_id,
        reason: format!("cannot resolve current executable for capsule re-exec: {e}"),
    })?;
    let spec_json = serde_json::to_string(spec).map_err(|e| CapsuleRefused {
        backend_id: sel.backend_id,
        reason: format!("cannot serialize capsule spec: {e}"),
    })?;
    let mut cmd = Command::new(exe);
    cmd.arg(crate::cli::capsule_child::SUBCOMMAND)
        .arg(spec_json)
        .arg("--")
        .arg(program)
        .args(args);
    Ok(cmd)
}

/// macOS: wrap in `sandbox-exec -p <profile> -- <program> <args>` (built by the E3
/// backend) and, in a `pre_exec` hook, apply the environment scrub + handle-closure
/// + rlimits that the SBPL profile alone does not — closing the env/resource/handle
/// coverage the E5 probe only claims because this wrapper applies them.
#[cfg(target_os = "macos")]
fn macos_contained_command(
    spec: &CapsuleSpec,
    program: &str,
    args: &[String],
    sel: &SelectedBackend,
) -> Result<Command, CapsuleRefused> {
    use std::os::unix::process::CommandExt;

    let argv =
        tirith_core::capsule::macos::sandbox_exec_argv(spec, program, args).map_err(|e| {
            CapsuleRefused {
                backend_id: sel.backend_id,
                reason: format!("cannot build sandbox-exec invocation: {e}"),
            }
        })?;
    // argv[0] is the sandbox-exec path; the rest are its args.
    let mut cmd = Command::new(&argv[0]);
    cmd.args(&argv[1..]);

    // Environment scrub: clear, then re-add the surviving names from the current
    // environment, and (when temporary_home) point HOME/TMPDIR/XDG_* at a fresh
    // temp dir. We do this on the parent `Command` (env_clear + env) so the child
    // and the sandbox-exec wrapper both see the scrubbed set.
    apply_macos_env(&mut cmd, spec);

    // rlimits + fd closure run in the child just before exec (pre_exec), so they
    // affect the sandbox-exec process and, by inheritance, the target.
    let resources = spec.resources.clone();
    let handles = spec.handles.clone();
    // SAFETY: the closure only calls async-signal-safe libc functions (setrlimit,
    // close) on values captured by move; it allocates nothing and touches no shared
    // state of the parent.
    unsafe {
        cmd.pre_exec(move || {
            apply_macos_rlimits(&resources)?;
            close_extra_fds(&handles);
            Ok(())
        });
    }
    Ok(cmd)
}

/// Apply the env policy to a macOS `Command`: clear the environment, re-add the
/// surviving variable names from the current process, then (when `temporary_home`)
/// repoint HOME/TMPDIR/XDG_* at a fresh temp directory. The temp dir intentionally
/// leaks for the child's lifetime (matching the Linux launcher).
#[cfg(target_os = "macos")]
fn apply_macos_env(cmd: &mut Command, spec: &CapsuleSpec) {
    let policy = &spec.environment;
    let present: Vec<String> = std::env::vars_os()
        .filter_map(|(k, _)| k.into_string().ok())
        .collect();
    // The same pure decision the Linux launcher uses (`EnvironmentPolicy`'s own
    // `surviving_vars`): start from the allow-list (or the parent set when
    // `inherit`), then drop every sensitive name.
    let survivors = policy.surviving_vars(present.iter().map(|s| s.as_str()));

    cmd.env_clear();
    for name in &survivors {
        if let Some(val) = std::env::var_os(name) {
            cmd.env(name, val);
        }
    }
    if policy.temporary_home {
        if let Ok(dir) = tempfile::Builder::new().prefix("tirith-capsule-").tempdir() {
            let home = dir.keep();
            cmd.env("HOME", &home);
            cmd.env("TMPDIR", &home);
            cmd.env("XDG_CONFIG_HOME", home.join(".config"));
            cmd.env("XDG_CACHE_HOME", home.join(".cache"));
            cmd.env("XDG_DATA_HOME", home.join(".local/share"));
            cmd.env("XDG_STATE_HOME", home.join(".local/state"));
        }
    }
}

/// Apply the rlimit dimensions of [`tirith_core::capsule::ResourceLimits`] via
/// `setrlimit`, async-signal-safe for a `pre_exec` hook (macOS). Mirrors the Linux
/// launcher's `apply_rlimits` but lives here because macOS containment is applied
/// by this wrapper, not a re-exec launcher.
#[cfg(target_os = "macos")]
fn apply_macos_rlimits(limits: &tirith_core::capsule::ResourceLimits) -> std::io::Result<()> {
    fn set_one(resource: libc::c_int, value: u64) -> std::io::Result<()> {
        let rl = libc::rlimit {
            rlim_cur: value as libc::rlim_t,
            rlim_max: value as libc::rlim_t,
        };
        // SAFETY: `rl` is a fully-initialized rlimit valid for the call; setrlimit
        // does not retain the pointer. On macOS `setrlimit` takes a `c_int`
        // resource (the rlimit constants are already `c_int`).
        let rc = unsafe { libc::setrlimit(resource, &rl) };
        if rc != 0 {
            return Err(std::io::Error::last_os_error());
        }
        Ok(())
    }
    if let Some(cpu) = limits.cpu_seconds {
        set_one(libc::RLIMIT_CPU, cpu)?;
    }
    if let Some(mem) = limits.memory_bytes {
        set_one(libc::RLIMIT_AS, mem)?;
    }
    if let Some(nofile) = limits.max_open_files {
        set_one(libc::RLIMIT_NOFILE, u64::from(nofile))?;
    }
    // RLIMIT_NPROC is per-user on macOS and not reliably enforceable per-process;
    // wall_clock/output bytes are the launcher/broker's job, not rlimits.
    Ok(())
}

/// Close every inherited file descriptor above stdio that is not in the handle
/// allow-list (macOS, `pre_exec`). Best-effort and async-signal-safe: it walks a
/// bounded fd range and `close()`s anything not permitted. Stdio (0/1/2) and the
/// explicit extras survive.
#[cfg(target_os = "macos")]
fn close_extra_fds(handles: &tirith_core::capsule::HandlePolicy) {
    let allowed = handles.allowed_unix_fds();
    // A conservative upper bound; the resource limit caps open files well below.
    let max_fd: i32 = 1024;
    for fd in 3..max_fd {
        if !allowed.contains(&fd) {
            // SAFETY: close on a possibly-unopened fd is harmless (returns EBADF);
            // close is async-signal-safe.
            unsafe {
                libc::close(fd);
            }
        }
    }
}

/// Windows run-to-completion: apply the AppContainer + Job launcher and wait. Only
/// reached on a non-degraded Windows backend (the degraded gate is checked first).
#[cfg(target_os = "windows")]
fn windows_run_to_completion(
    spec: &CapsuleSpec,
    program: &str,
    args: &[String],
    sel: &SelectedBackend,
) -> Result<CapsuleOutcome, CapsuleRefused> {
    let mut child =
        crate::cli::capsule_windows::launch_contained(spec, program, args).map_err(|e| {
            CapsuleRefused {
                backend_id: sel.backend_id,
                reason: format!("contained launch failed: {e}"),
            }
        })?;
    let exit_code = crate::cli::capsule_windows::wait_for(&child).map_err(|e| CapsuleRefused {
        backend_id: sel.backend_id,
        reason: format!("waiting for contained child failed: {e}"),
    })?;
    // Revert ACL grants now that the child has exited.
    let _ = child.finish();
    Ok(CapsuleOutcome {
        exit_code,
        backend_id: sel.backend_id,
        coverage: sel.coverage,
        degraded: false,
    })
}

// ─── runtime-detected escape hatches (srt / mxc) ─────────────────────────────

/// A runtime-detected external containment helper found on `$PATH`. These are the
/// optional, opt-in escape hatches the plan mentions: Anthropic `srt`
/// (Linux/macOS) and Microsoft `mxc` (Windows/WSL). **No acceptance criterion
/// depends on them** — they are reported for diagnostics so an operator can see
/// that a stronger external backend is *available*, but tirith's own backends are
/// what enforce containment. Detection is presence-on-PATH only (executable
/// provenance), never an auto-wire.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct DetectedHelper {
    /// The helper name (`"srt"` or `"mxc"`).
    pub name: &'static str,
    /// The absolute path it resolved to on `$PATH`.
    pub path: String,
}

/// Probe `$PATH` for the optional external containment helpers relevant to this
/// platform. Returns each one found (presence only). Pure w.r.t. process state:
/// reads `$PATH` and stats candidates, mutates nothing.
pub fn detect_external_helpers() -> Vec<DetectedHelper> {
    let path_value = std::env::var("PATH").unwrap_or_default();
    let mut out = Vec::new();
    // `srt` is the Anthropic sandbox runtime (Linux/macOS); `mxc` is Microsoft's
    // (Windows/WSL). We probe the names relevant to the host but tolerate either
    // being present anywhere (WSL can surface both).
    let names: &[&str] = if cfg!(target_os = "windows") {
        &["mxc", "srt"]
    } else {
        &["srt", "mxc"]
    };
    for &name in names {
        let hits = tirith_core::path_audit::which_all(name, &path_value);
        if let Some(first) = hits.first() {
            out.push(DetectedHelper {
                name,
                path: first.display().to_string(),
            });
        }
    }
    out
}

// ─── doctor info (CapsuleDoctorInfo) ─────────────────────────────────────────

/// Per-platform capsule coverage report for `tirith doctor`. Built by
/// [`gather_doctor_info`] from a representative locked-down spec so an operator
/// sees, at a glance, what containment this host can actually enforce.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct CapsuleDoctorInfo {
    /// The backend selected for this host.
    pub backend_id: &'static str,
    /// Whether the backend can fully satisfy a locked-down (deny-all) spec — i.e.
    /// an enforcing surface like `pkg install` would NOT fail closed here.
    pub deny_all_enforceable: bool,
    /// The individual coverage flags achieved for a locked-down spec.
    pub fs_read_enforced: bool,
    pub fs_write_enforced: bool,
    pub exec_limited: bool,
    pub network_raw_denied: bool,
    pub resource_limits_enforced: bool,
    pub env_isolated: bool,
    pub handles_isolated: bool,
    /// Whether allow-listed-domain egress is enforceable here (requires a
    /// raw-socket-blocking backend + the broker). False on every current backend
    /// (the broker is not yet wired to a verified raw-socket block), so egress
    /// claims always fail closed — surfaced honestly here.
    pub domain_egress_enforceable: bool,
    /// Optional external helpers detected on `$PATH` (`srt`/`mxc`); empty when none.
    pub external_helpers: Vec<DetectedHelper>,
}

/// Gather the capsule coverage `tirith doctor` reports for this host. Probes the
/// host backend against a locked-down deny-all spec (the install/MCP baseline) and
/// an allow-listed spec (to report whether domain egress is enforceable), plus the
/// optional external helpers. Touches no process state beyond reading `$PATH` and
/// probing the OS sandbox mechanism.
pub fn gather_doctor_info() -> CapsuleDoctorInfo {
    let deny_spec = CapsuleSpec::locked_down();
    let deny_sel = select_backend(&deny_spec);

    let mut egress_spec = CapsuleSpec::locked_down();
    egress_spec.network = tirith_core::capsule::NetworkPolicy::AllowListedDomains {
        domains: ["example.invalid".to_string()].into_iter().collect(),
        ports: [443u16].into_iter().collect(),
    };
    let egress_sel = select_backend(&egress_spec);

    CapsuleDoctorInfo {
        backend_id: deny_sel.backend_id,
        deny_all_enforceable: !deny_sel.is_degraded(),
        fs_read_enforced: deny_sel.coverage.fs_read_enforced,
        fs_write_enforced: deny_sel.coverage.fs_write_enforced,
        exec_limited: deny_sel.coverage.exec_limited,
        network_raw_denied: deny_sel.coverage.network_raw_denied,
        resource_limits_enforced: deny_sel.coverage.resource_limits_enforced,
        env_isolated: deny_sel.coverage.env_isolated,
        handles_isolated: deny_sel.coverage.handles_isolated,
        domain_egress_enforceable: !egress_sel.is_degraded(),
        external_helpers: detect_external_helpers(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tirith_core::capsule::NetworkPolicy;

    #[test]
    fn select_backend_reports_a_stable_id() {
        let spec = CapsuleSpec::locked_down();
        let sel = select_backend(&spec);
        // One of the four known backends, depending on the compile target.
        assert!(matches!(
            sel.backend_id,
            "landlock-seccomp" | "seatbelt" | "appcontainer" | "noop"
        ));
        // The required coverage always demands raw-net-deny for a locked-down spec.
        assert!(sel.required.network_raw_denied);
        assert!(!sel.required.domain_proxy_enforced);
    }

    #[test]
    fn fail_closed_when_backend_degraded() {
        // Force the NoOp-degraded situation by checking the gate directly: a NoOp
        // coverage against a locked-down requirement is always degraded, so an
        // enforcing run must refuse. We assert the decision logic (the gate), which
        // is host-independent, rather than spawning.
        let spec = CapsuleSpec::locked_down();
        let sel = SelectedBackend {
            backend_id: "noop",
            coverage: CapsuleCoverage::NONE,
            required: spec.required_coverage(),
        };
        assert!(sel.is_degraded());
        let reason = shortfall_reason(sel.backend_id, &sel);
        assert!(reason.contains("refusing to run uncontained"));
        // The shortfall names concrete missing capabilities, not secrets.
        assert!(reason.contains("fs_read"));
        assert!(reason.contains("network_raw_denied"));
    }

    #[test]
    fn not_degraded_when_coverage_meets_requirement() {
        let spec = CapsuleSpec::locked_down();
        let full = CapsuleCoverage {
            fs_read_enforced: true,
            fs_write_enforced: true,
            exec_limited: true,
            network_raw_denied: true,
            domain_proxy_enforced: false,
            resource_limits_enforced: true,
            env_isolated: true,
            handles_isolated: true,
        };
        let sel = SelectedBackend {
            backend_id: "test",
            coverage: full,
            required: spec.required_coverage(),
        };
        assert!(!sel.is_degraded());
    }

    #[test]
    fn allowlisted_egress_is_degraded_without_proxy() {
        // An allow-list spec requires domain_proxy_enforced; a backend that denies
        // raw sockets but does NOT prove the proxy is still degraded -> fail closed.
        let mut spec = CapsuleSpec::locked_down();
        spec.network = NetworkPolicy::AllowListedDomains {
            domains: ["pypi.org".to_string()].into_iter().collect(),
            ports: [443u16].into_iter().collect(),
        };
        let cov = CapsuleCoverage {
            fs_read_enforced: true,
            fs_write_enforced: true,
            exec_limited: true,
            network_raw_denied: true,
            domain_proxy_enforced: false,
            resource_limits_enforced: true,
            env_isolated: true,
            handles_isolated: true,
        };
        let sel = SelectedBackend {
            backend_id: "test",
            coverage: cov,
            required: spec.required_coverage(),
        };
        assert!(sel.is_degraded());
        assert!(shortfall_reason(sel.backend_id, &sel).contains("domain_proxy_enforced"));
    }

    #[test]
    fn doctor_info_is_serializable_and_consistent() {
        let info = gather_doctor_info();
        // The reported flags must be internally coherent: domain egress is never
        // enforceable on a backend that does not even enforce raw-net-deny.
        if info.domain_egress_enforceable {
            assert!(info.network_raw_denied);
        }
        // It serializes (doctor --format json).
        let json = serde_json::to_string(&info).expect("serialize");
        assert!(json.contains("backend_id"));
    }

    #[test]
    fn detect_external_helpers_does_not_panic_and_returns_known_names() {
        // On a normal CI host neither srt nor mxc is present; the call must still
        // succeed and only ever report the known helper names.
        let helpers = detect_external_helpers();
        for h in &helpers {
            assert!(matches!(h.name, "srt" | "mxc"));
            assert!(!h.path.is_empty());
        }
    }

    #[test]
    fn degraded_policy_variants_are_distinct() {
        assert_ne!(DegradedPolicy::FailClosed, DegradedPolicy::AllowDegraded);
    }

    #[test]
    fn coverage_summary_reports_every_flag() {
        let outcome = CapsuleOutcome {
            exit_code: 0,
            backend_id: "test",
            coverage: CapsuleCoverage {
                fs_read_enforced: true,
                fs_write_enforced: true,
                exec_limited: true,
                network_raw_denied: true,
                domain_proxy_enforced: false,
                resource_limits_enforced: true,
                env_isolated: true,
                handles_isolated: true,
            },
            degraded: false,
        };
        let s = outcome.coverage_summary();
        assert!(s.contains("fs_read=true"));
        assert!(s.contains("raw_net_denied=true"));
        assert!(s.contains("domain_proxy=false"));
    }

    #[test]
    fn refusal_display_names_the_backend() {
        let refused = CapsuleRefused {
            backend_id: "noop",
            reason: "no containment here".to_string(),
        };
        let shown = format!("{refused}");
        assert!(shown.contains("[noop]"));
        assert!(shown.contains("no containment here"));
    }
}
