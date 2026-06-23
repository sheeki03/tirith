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
///
/// **Invariant (enforcing surfaces must hold):** an *enforcing* surface — one that
/// promises containment (`pkg install`, the contained MCP gateway,
/// `tirith run --require-capsule`) — must ALWAYS pass [`Self::FailClosed`].
/// [`Self::AllowDegraded`] runs the program fully uncontained on a degraded host
/// and is reserved for best-effort, explicitly-not-a-boundary surfaces
/// (`temp-run --capsule`) that print an honest banner. An enforcing surface that
/// passed `AllowDegraded` would silently run an attacker's code uncontained.
/// Enforcing call sites assert this with [`Self::guard_enforcing`].
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

impl DegradedPolicy {
    /// Whether this policy fails closed (refuses to run under degraded coverage).
    /// An enforcing surface is exactly one for which this is `true`.
    pub fn is_enforcing(self) -> bool {
        matches!(self, DegradedPolicy::FailClosed)
    }
}

/// Guard the security-critical "proceed uncontained because the backend is
/// degraded" decision: reaching it with an *enforcing* policy
/// ([`DegradedPolicy::FailClosed`]) is an invariant violation (an enforcing
/// surface would have failed closed before here). In a debug build this trips a
/// `debug_assert!`; the structural fail-closed check upstream already guarantees an
/// enforcing caller never reaches a degraded run in release. Centralizing the guard
/// here means every degraded-run path (`run_to_completion` and `spawn_piped`)
/// asserts the same contract, so a future enforcing surface that mis-wires its
/// policy is caught in tests rather than silently running an attacker's code
/// uncontained.
fn assert_degraded_run_is_permitted(policy: DegradedPolicy) {
    debug_assert!(
        !policy.is_enforcing(),
        "enforcing capsule surface (FailClosed) must never reach an uncontained degraded run; \
         it would run the program uncontained on a degraded host"
    );
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
// Each target arm `return`s its backend; only the catch-all fallback is a tail
// expression. On any single platform clippy sees that platform's arm as the
// effective tail and flags `needless_return`, but the keyword is required for the
// other (cfg'd-out) arms, so keep the shape uniform rather than diverge per OS.
#[allow(clippy::needless_return)]
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
        // An enforcing surface would have failed closed above; assert it here.
        assert_degraded_run_is_permitted(degraded);
        return uncontained_run(program, args, cwd, extra_env, &sel, true);
    }

    #[cfg(not(target_os = "windows"))]
    {
        if is_degraded {
            // AllowDegraded: run uncontained but honestly flagged. An enforcing
            // surface would have failed closed above; assert it here.
            assert_degraded_run_is_permitted(degraded);
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
        // Only an AllowDegraded caller reaches here (FailClosed returned above).
        assert_degraded_run_is_permitted(degraded);
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
            // Only an AllowDegraded caller reaches here (FailClosed returned above).
            assert_degraded_run_is_permitted(degraded);
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
///   coverage the E5 probe only claims because this wrapper applies them.
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
    // and the sandbox-exec wrapper both see the scrubbed set. Fails closed if the
    // temporary HOME cannot be created for a `temporary_home` spec: skipping it
    // would leave the real `$HOME` reachable (env_clear already ran, but
    // `getpwuid()->pw_dir` still resolves it) while `env_isolated` claims true.
    apply_macos_env(&mut cmd, spec).map_err(|reason| CapsuleRefused {
        backend_id: sel.backend_id,
        reason,
    })?;

    // rlimits + fd closure run in the child just before exec (pre_exec), so they
    // affect the sandbox-exec process and, by inheritance, the target.
    let resources = spec.resources.clone();
    let handles = spec.handles.clone();
    // SAFETY: the closure only calls async-signal-safe libc functions (getrlimit,
    // setrlimit, close) on values captured by move; it allocates nothing and
    // touches no shared state of the parent.
    //
    // Order matters: close inherited fds FIRST, while `RLIMIT_NOFILE` still reflects
    // the inherited (higher) ceiling, so a high-numbered inherited fd is found and
    // closed. Lowering `RLIMIT_NOFILE` does not close already-open fds, so applying
    // rlimits first would shrink the scan ceiling and let a high fd survive.
    unsafe {
        cmd.pre_exec(move || {
            close_extra_fds(&handles);
            apply_macos_rlimits(&resources)?;
            Ok(())
        });
    }
    Ok(cmd)
}

/// Apply the env policy to a macOS `Command`: clear the environment, re-add the
/// surviving variable names from the current process, then (when `temporary_home`)
/// repoint HOME/TMPDIR/XDG_* at a fresh temp directory. The temp dir intentionally
/// leaks for the child's lifetime (matching the Linux launcher).
///
/// **Fails closed** when `temporary_home` is set but the temporary directory cannot
/// be created: returning `Err` here propagates to a [`CapsuleRefused`] so the launch
/// is refused rather than running with the real `$HOME` reachable. `env_clear`
/// alone is NOT enough to hide the home directory, because macOS `getpwuid()` (used
/// by libc / the shell to resolve `~`) reads `pw_dir` from the password database,
/// not the environment; only repointing HOME/TMPDIR/XDG_* at a fresh dir isolates
/// the child. Skipping the repoint while still reporting `env_isolated = true` would
/// be a silent over-report (the gap the Linux launcher fails closed on too).
#[cfg(target_os = "macos")]
fn apply_macos_env(cmd: &mut Command, spec: &CapsuleSpec) -> Result<(), String> {
    apply_macos_env_with(cmd, spec, || {
        // Production temp-home factory: a fresh, leaked temp dir. `keep()` detaches
        // it from the guard so it survives for the child's lifetime (the E5 wrapper
        // removes it after the child exits).
        tempfile::Builder::new()
            .prefix("tirith-capsule-")
            .tempdir()
            .map(tempfile::TempDir::keep)
    })
}

/// The env-scrub core, with the temporary-HOME directory creation injected as
/// `make_temp_home` so the fail-closed propagation is deterministically testable
/// (a test can pass a factory that returns `Err` without mutating the process-wide
/// `TMPDIR`, which would race other tests). Production passes the real tempfile
/// factory via [`apply_macos_env`].
#[cfg(target_os = "macos")]
fn apply_macos_env_with<F>(
    cmd: &mut Command,
    spec: &CapsuleSpec,
    make_temp_home: F,
) -> Result<(), String>
where
    F: FnOnce() -> std::io::Result<std::path::PathBuf>,
{
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
        // Fail closed on a temp-home error: the alternative (skip the repoint) leaves
        // the real home reachable while env_isolated would still report true.
        let home = make_temp_home().map_err(|e| {
            format!(
                "capsule env isolation requires a temporary HOME but one could not be \
                 created ({e}); refusing to run with the real HOME reachable"
            )
        })?;
        cmd.env("HOME", &home);
        cmd.env("TMPDIR", &home);
        cmd.env("XDG_CONFIG_HOME", home.join(".config"));
        cmd.env("XDG_CACHE_HOME", home.join(".cache"));
        cmd.env("XDG_DATA_HOME", home.join(".local/share"));
        cmd.env("XDG_STATE_HOME", home.join(".local/state"));
    }
    Ok(())
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
    // `max_processes` is intentionally NOT applied: RLIMIT_NPROC is per real UID on
    // macOS, so it would cap the whole user (and could deny the user's own shell a
    // fork) without bounding the contained child's subtree, a false fork-bomb cap.
    // The honesty contract handles this by EXCLUDING max_processes from the macOS
    // `resource_limits_enforced` claim (see `tirith_core::capsule::macos::
    // derive_coverage`), so a spec that relies on it degrades rather than trusting a
    // cap that is not here. `wall_clock`/`max_output` are launcher-enforced, not
    // rlimits.
    Ok(())
}

/// Close every inherited file descriptor above stdio that is not in the handle
/// allow-list (macOS, `pre_exec`). Best-effort and async-signal-safe: it walks the
/// fd range up to the process `RLIMIT_NOFILE` ceiling and `close()`s anything not
/// permitted. Stdio (0/1/2) and the explicit extras survive.
///
/// The upper bound is the current `RLIMIT_NOFILE` soft limit (an fd can never be
/// numbered at or above it), so an inherited descriptor numbered above a hardcoded
/// 1024 cannot survive. This runs BEFORE `apply_macos_rlimits` lowers
/// `RLIMIT_NOFILE`, so the ceiling reflects the inherited (higher) limit and a
/// high-numbered inherited fd is still found. It is clamped to [`MAX_FD_SCAN`] so a
/// process that raised `RLIMIT_NOFILE` to a huge value (or `RLIM_INFINITY`) does
/// not make the `pre_exec` walk run unboundedly.
#[cfg(target_os = "macos")]
fn close_extra_fds(handles: &tirith_core::capsule::HandlePolicy) {
    let allowed = handles.allowed_unix_fds();
    let max_fd = fd_scan_ceiling();
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

/// A hard upper bound on the fd-closure walk so a pathological `RLIMIT_NOFILE`
/// (e.g. `RLIM_INFINITY`) cannot make the async-signal-safe `pre_exec` loop run
/// effectively forever. 1 MiB of fds is far more than any real inherited set.
#[cfg(target_os = "macos")]
const MAX_FD_SCAN: i32 = 1 << 20;

/// The fd number to walk up to when closing inherited descriptors: the current
/// `RLIMIT_NOFILE` soft limit (no open fd can be numbered at or above it), clamped
/// to [`MAX_FD_SCAN`]. Falls back to [`MAX_FD_SCAN`] if the limit cannot be read or
/// is unbounded, so the walk is never narrower than the old hardcoded 1024.
/// Async-signal-safe: only calls `getrlimit`.
#[cfg(target_os = "macos")]
fn fd_scan_ceiling() -> i32 {
    let mut rl = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    // SAFETY: `rl` is a valid, fully-initialized rlimit for the call; getrlimit
    // does not retain the pointer.
    let rc = unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut rl) };
    if rc != 0 {
        return MAX_FD_SCAN;
    }
    clamp_fd_ceiling(rl.rlim_cur)
}

/// Clamp a raw `RLIMIT_NOFILE` soft limit to the fd-closure walk ceiling. **Pure**,
/// so the bounds (floor of 1024, cap of [`MAX_FD_SCAN`], `RLIM_INFINITY` handling)
/// are unit-testable without `getrlimit`.
///
/// - `RLIM_INFINITY`, or any value above [`MAX_FD_SCAN`], clamps DOWN to
///   `MAX_FD_SCAN` so the async-signal-safe `pre_exec` loop is always bounded.
/// - Anything below the historical hardcoded floor of 1024 is raised UP to 1024, so
///   the walk is never narrower than it used to be (a low `RLIMIT_NOFILE` must not
///   let a higher-numbered inherited fd survive the closure).
#[cfg(target_os = "macos")]
fn clamp_fd_ceiling(rlim_cur: libc::rlim_t) -> i32 {
    if rlim_cur == libc::RLIM_INFINITY || rlim_cur > MAX_FD_SCAN as libc::rlim_t {
        return MAX_FD_SCAN;
    }
    // Never scan a narrower range than the previous hardcoded floor.
    (rlim_cur as i32).max(1024)
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
    // Revert ACL grants now that the child has exited. A revert FAILURE leaves a
    // container-SID ACE on a read/write root, a residual grant that widens what a
    // future contained (or uncontained) process can reach, i.e. a containment-
    // boundary leak. Fail closed: surface it as a refusal rather than reporting a
    // clean success, so an enforcing caller (and the receipt) sees the boundary did
    // not fully revert. (`finish` already attempts ALL guards before returning the
    // first error, so the best-effort revert still happened.)
    child.finish().map_err(|e| CapsuleRefused {
        backend_id: sel.backend_id,
        reason: format!(
            "contained child exited (code {exit_code}) but reverting the capsule's ACL grants \
             failed ({e}); a residual grant may remain, refusing to report a clean run"
        ),
    })?;
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
    fn degraded_policy_enforcing_classification() {
        // S6: FailClosed is the enforcing policy; AllowDegraded is not.
        assert!(DegradedPolicy::FailClosed.is_enforcing());
        assert!(!DegradedPolicy::AllowDegraded.is_enforcing());
    }

    #[test]
    fn assert_degraded_run_permits_allow_degraded() {
        // S6: the guard at the uncontained-degraded-run path accepts AllowDegraded
        // (the only policy that should ever reach it). It must not panic for it.
        assert_degraded_run_is_permitted(DegradedPolicy::AllowDegraded);
    }

    #[cfg(debug_assertions)]
    #[test]
    #[should_panic(expected = "enforcing capsule surface")]
    fn assert_degraded_run_rejects_fail_closed_in_debug() {
        // S6: an enforcing surface (FailClosed) reaching the uncontained degraded
        // run is an invariant violation; the guard trips in a debug build so a
        // future mis-wired enforcing surface is caught by tests, never silently
        // running uncontained.
        assert_degraded_run_is_permitted(DegradedPolicy::FailClosed);
    }

    // ── C4: macOS contained launch honestly delivers env/handle/rlimit coverage ──

    /// On macOS with a usable `sandbox-exec`, a locked-down (deny-all) spec must NOT
    /// be degraded: the Seatbelt backend + this wrapper together supply FS/exec/
    /// raw-net-deny AND the env/handle/rlimit coverage the wrapper applies. Before
    /// the C4 fix the backend hard-coded env/handle/rlimit to false, so every
    /// enforcing surface (`pkg install`, `gateway --capsule`, `run --capsule`)
    /// refused on macOS. This asserts the live coverage on the host.
    #[cfg(target_os = "macos")]
    #[test]
    fn macos_locked_down_is_not_degraded_when_sandbox_exec_present() {
        // Only meaningful where sandbox-exec is actually usable (the macOS CI runner
        // and dev hosts). If it is somehow missing, the honest answer IS degraded;
        // skip rather than assert a false expectation.
        if !tirith_core::capsule::macos::probe_sandbox_exec().sandbox_exec_usable {
            eprintln!("skipping: /usr/bin/sandbox-exec not usable on this host");
            return;
        }
        let spec = CapsuleSpec::locked_down();
        let sel = select_backend(&spec);
        assert_eq!(sel.backend_id, "seatbelt");
        assert!(
            !sel.is_degraded(),
            "locked-down macOS capsule must not be degraded with sandbox-exec present: \
             coverage={:?} required={:?}",
            sel.coverage,
            sel.required
        );
        // The wrapper-supplied flags are honestly reported.
        assert!(sel.coverage.env_isolated);
        assert!(sel.coverage.handles_isolated);
        assert!(sel.coverage.resource_limits_enforced);
    }

    /// C4 env-scrub proof on macOS: the contained `Command` the wrapper builds has
    /// a planted secret (`AWS_SECRET_ACCESS_KEY`) scrubbed from the child's
    /// environment while an explicitly-allowed benign var survives. This inspects
    /// the real `Command` produced by `macos_contained_command` (via `env_clear` +
    /// `EnvironmentPolicy::surviving_vars`), which is exactly the environment the
    /// child receives — the concrete mechanism behind the `env_isolated` coverage
    /// claim. We inspect the built env rather than launch through `sandbox-exec`
    /// because exec'ing an arbitrary binary under a `(deny default)` Seatbelt
    /// profile is host/macOS-version-dependent (the dyld loader needs paths the
    /// minimal profile does not grant), which would make a CI test flaky; the env
    /// scrub itself is deterministic and is what this finding is about.
    #[cfg(target_os = "macos")]
    #[test]
    fn macos_contained_command_scrubs_planted_secret_env() {
        use tirith_core::capsule::{
            CapsuleSpec, EnvironmentPolicy, FilesystemPolicy, HandlePolicy, NetworkPolicy,
            ResourceLimits,
        };

        if !tirith_core::capsule::macos::probe_sandbox_exec().sandbox_exec_usable {
            eprintln!("skipping: /usr/bin/sandbox-exec not usable on this host");
            return;
        }

        // Uniquely-named planted vars so a parallel test never collides with these.
        let secret_name = "AWS_SECRET_ACCESS_KEY";
        let secret_val = "tirith-capsule-secret-DEADBEEF";
        let marker_name = "TIRITH_CAPSULE_C4_MARKER";
        let marker_val = "tirith-capsule-marker-OK";

        // A deny-all spec that explicitly ALLOWS the benign marker (sensitive names
        // are stripped regardless of the allow-list — the whole point). temporary_home
        // off so the only env the child gets is the surviving allow-list set.
        let spec = CapsuleSpec {
            filesystem: FilesystemPolicy::default(),
            network: NetworkPolicy::DenyAll,
            environment: EnvironmentPolicy {
                inherit: false,
                allow: vec![
                    marker_name.to_string(),
                    secret_name.to_string(), // allow-listed but still stripped
                ],
                deny_sensitive: true,
                temporary_home: false,
            },
            handles: HandlePolicy::default(),
            resources: ResourceLimits::conservative(),
        };

        let sel = select_backend(&spec);
        assert_eq!(sel.backend_id, "seatbelt");
        assert!(!sel.is_degraded(), "spec must be enforceable: {sel:?}");

        // Plant the vars, build the command (which snapshots the env via env_clear +
        // surviving_vars), then immediately remove them — keeping the global-env
        // window minimal so parallel tests are unaffected.
        std::env::set_var(secret_name, secret_val);
        std::env::set_var(marker_name, marker_val);
        let cmd = build_contained_command(&spec, "/usr/bin/printenv", &[], &sel)
            .expect("build contained command");
        // The env the child WILL receive: the Command's explicit env overrides.
        let child_env: std::collections::BTreeMap<String, Option<String>> = cmd
            .get_envs()
            .map(|(k, v)| {
                (
                    k.to_string_lossy().into_owned(),
                    v.map(|v| v.to_string_lossy().into_owned()),
                )
            })
            .collect();
        std::env::remove_var(secret_name);
        std::env::remove_var(marker_name);

        // The sensitive var must be ABSENT from the child's environment (env_clear
        // dropped the inherited copy and surviving_vars refused to re-add it).
        assert!(
            !child_env.contains_key(secret_name),
            "sensitive {secret_name} must be scrubbed from the contained child env: {child_env:?}"
        );
        // Its value must not appear anywhere in the scrubbed env either.
        assert!(
            !child_env.values().any(|v| v.as_deref() == Some(secret_val)),
            "the planted secret value leaked into the contained child env: {child_env:?}"
        );
        // The explicitly-allowed benign marker DID survive (proves selective
        // scrubbing, not a blanket wipe that drops everything).
        assert_eq!(
            child_env
                .get(marker_name)
                .and_then(|v| v.clone())
                .as_deref(),
            Some(marker_val),
            "benign allow-listed marker should survive into the child: {child_env:?}"
        );
    }

    // ── IM5: macOS env isolation fails closed on a temp-HOME creation failure ──

    /// IM5: when `temporary_home` is set and the temp-HOME factory fails,
    /// `apply_macos_env_with` returns `Err` (instead of silently skipping the
    /// repoint and leaving the real `$HOME` reachable while env_isolated claims true).
    #[cfg(target_os = "macos")]
    #[test]
    fn macos_env_fails_closed_when_temp_home_unavailable() {
        let spec = CapsuleSpec::locked_down(); // temporary_home is true by default
        assert!(spec.environment.temporary_home);
        let mut cmd = Command::new("/usr/bin/true");
        let err = apply_macos_env_with(&mut cmd, &spec, || {
            Err(std::io::Error::other("synthetic tempdir failure"))
        })
        .expect_err("must fail closed when the temp HOME cannot be created");
        assert!(
            err.contains("refusing to run with the real HOME reachable"),
            "reason must name the fail-closed cause: {err}"
        );
    }

    /// IM5: the success path repoints HOME at the created temp dir (so the child
    /// never sees the real home). Uses an injected dir so it is deterministic.
    #[cfg(target_os = "macos")]
    #[test]
    fn macos_env_repoints_home_on_success() {
        let spec = CapsuleSpec::locked_down();
        let injected = std::env::temp_dir().join("tirith-im5-success-marker");
        let mut cmd = Command::new("/usr/bin/true");
        apply_macos_env_with(&mut cmd, &spec, || Ok(injected.clone()))
            .expect("success factory must succeed");
        let envs: std::collections::BTreeMap<String, Option<String>> = cmd
            .get_envs()
            .map(|(k, v)| {
                (
                    k.to_string_lossy().into_owned(),
                    v.map(|v| v.to_string_lossy().into_owned()),
                )
            })
            .collect();
        assert_eq!(
            envs.get("HOME").and_then(|v| v.clone()).as_deref(),
            Some(injected.to_string_lossy().as_ref()),
            "HOME must be repointed at the temp dir: {envs:?}"
        );
    }

    /// IM5: the failure propagates all the way through `macos_contained_command` to a
    /// `CapsuleRefused` when the real temp-HOME creation fails. We force the failure
    /// deterministically by pointing the temp dir at an uncreatable path via
    /// `TMPDIR`, restored immediately after (the window is this test only). Only
    /// meaningful where sandbox-exec is usable (otherwise the build path differs).
    #[cfg(target_os = "macos")]
    #[test]
    fn macos_contained_command_refuses_when_temp_home_creation_fails() {
        if !tirith_core::capsule::macos::probe_sandbox_exec().sandbox_exec_usable {
            eprintln!("skipping: /usr/bin/sandbox-exec not usable on this host");
            return;
        }
        let spec = CapsuleSpec::locked_down();
        let sel = select_backend(&spec);
        assert_eq!(sel.backend_id, "seatbelt");

        // Save and repoint TMPDIR at a path that cannot be created (a component is a
        // non-existent file), so the production tempfile factory errors. Restored in
        // the guard's Drop so a panic still cleans up.
        struct TmpdirGuard(Option<std::ffi::OsString>);
        impl Drop for TmpdirGuard {
            fn drop(&mut self) {
                match &self.0 {
                    Some(v) => std::env::set_var("TMPDIR", v),
                    None => std::env::remove_var("TMPDIR"),
                }
            }
        }
        let _guard = TmpdirGuard(std::env::var_os("TMPDIR"));
        std::env::set_var(
            "TMPDIR",
            "/tirith-im5-nonexistent-base-xyz/deeper/still-missing",
        );

        let result = build_contained_command(&spec, "/usr/bin/true", &[], &sel);
        assert!(
            result.is_err(),
            "macOS contained command must refuse (CapsuleRefused) when the temp HOME \
             cannot be created"
        );
        let refused = result.err().unwrap();
        assert!(
            refused.reason.contains("real HOME reachable"),
            "refusal must carry the env-isolation fail-closed reason: {refused}"
        );
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

    // ── TG2: fd-scan ceiling clamp ──

    #[cfg(target_os = "macos")]
    #[test]
    fn clamp_fd_ceiling_applies_floor_cap_and_infinity() {
        // Below the floor -> raised to 1024 (never narrower than the old hardcoded
        // walk, so a high-numbered inherited fd cannot survive on a low NOFILE host).
        assert_eq!(clamp_fd_ceiling(256), 1024);
        assert_eq!(clamp_fd_ceiling(0), 1024);
        assert_eq!(clamp_fd_ceiling(1024), 1024);
        // A normal mid-range value passes through unchanged.
        assert_eq!(clamp_fd_ceiling(65536), 65536);
        // Exactly the cap passes through.
        assert_eq!(clamp_fd_ceiling(MAX_FD_SCAN as libc::rlim_t), MAX_FD_SCAN);
        // Just over the cap clamps DOWN to the cap (bounded pre_exec loop).
        assert_eq!(
            clamp_fd_ceiling(MAX_FD_SCAN as libc::rlim_t + 1),
            MAX_FD_SCAN
        );
        // RLIM_INFINITY clamps to the cap, never an unbounded walk.
        assert_eq!(clamp_fd_ceiling(libc::RLIM_INFINITY), MAX_FD_SCAN);
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
