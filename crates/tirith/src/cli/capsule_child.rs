//! Internal capsule launcher (`tirith __capsule-child`), Stack E, unit E2.
//!
//! This is NOT a user-facing command. It is the re-exec target the capsule
//! machinery (E5 consumers: `runner.rs`, `temp_run.rs`, the package-firewall
//! install, the gateway upstream spawn) invokes to run a program under OS
//! containment. The parent builds a [`CapsuleSpec`], serializes it to JSON, and
//! spawns:
//!
//! ```text
//! tirith __capsule-child <spec-json> -- <prog> <arg>...
//! ```
//!
//! This process then:
//! 1. Parses its own simple argv (the spec JSON, then everything after `--`).
//! 2. (Linux) creates the temporary HOME the env policy points at, applies the
//!    full containment sequence via [`tirith_core::capsule::linux::apply_containment`]
//!    (rlimits -> no-new-privs -> Landlock -> seccomp -> env cleanup), verifies the
//!    achieved coverage is not degraded against the spec's requirement, and only
//!    then `execve`s the target.
//!
//! ## Single-threaded invariant
//!
//! seccomp (`apply_to_current_thread`) filters only the calling thread, and
//! Landlock `restrict_self` is incompatible with the thread-sync (TSYNC) path, so
//! containment MUST be applied while the process is single-threaded. `tirith`'s
//! normal `main()` runs the CLI on a dedicated worker thread (for a roomy stack),
//! which would make this process multi-threaded. To avoid that, [`is_invocation`]
//! is checked at the very top of `main()` **before** the worker thread is spawned,
//! and [`run_on_main_thread`] handles the command directly on the genuinely
//! single-threaded main thread. It never returns on success (`execve` replaces the
//! image); on any failure it prints to stderr and exits non-zero. It MUST NOT
//! fall through to running the target uncontained (fail-closed).

/// The hidden subcommand name. A double-underscore prefix marks it internal and
/// keeps it clear of any real command.
pub const SUBCOMMAND: &str = "__capsule-child";

/// Whether `args` (typically `std::env::args().collect()`) is a `__capsule-child`
/// invocation. Checked at the top of `main()` so the launcher runs before the
/// worker-thread spawn (single-threaded invariant). Pure, so it is unit-testable.
pub fn is_invocation(args: &[String]) -> bool {
    args.get(1).map(|a| a == SUBCOMMAND).unwrap_or(false)
}

/// The parsed launcher argv: the spec JSON and the target program + args (the part
/// after the `--` separator).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedArgs {
    /// The serialized [`CapsuleSpec`] JSON.
    pub spec_json: String,
    /// The target program (argv[0] of the contained child).
    pub program: String,
    /// The target program's arguments.
    pub program_args: Vec<String>,
}

/// Parse `tirith __capsule-child <spec-json> -- <prog> <arg>...` from the full
/// process argv. Requires the subcommand token, then exactly one spec-JSON
/// argument, then a literal `--`, then a non-empty program. Pure and
/// platform-independent, so the argv grammar is unit-testable everywhere.
pub fn parse_args(args: &[String]) -> Result<ParsedArgs, String> {
    // args[0] = "tirith", args[1] = SUBCOMMAND.
    if args.get(1).map(String::as_str) != Some(SUBCOMMAND) {
        return Err("not a __capsule-child invocation".to_string());
    }
    let spec_json = args
        .get(2)
        .ok_or_else(|| "missing capsule spec JSON".to_string())?
        .clone();
    // Find the `--` separator.
    let sep = args
        .iter()
        .position(|a| a == "--")
        .ok_or_else(|| "missing `--` separator before the program".to_string())?;
    // The spec must be BEFORE the separator (index 2 < sep).
    if sep < 3 {
        return Err("the `--` separator must follow the spec JSON".to_string());
    }
    let rest = &args[sep + 1..];
    let program = rest
        .first()
        .ok_or_else(|| "missing program after `--`".to_string())?
        .clone();
    let program_args = rest[1..].to_vec();
    Ok(ParsedArgs {
        spec_json,
        program,
        program_args,
    })
}

/// Handle a `__capsule-child` invocation on the main thread and NEVER return on
/// success: it `execve`s the contained target (replacing this image) or exits the
/// process non-zero on any failure. Call this at the top of `main()` only when
/// [`is_invocation`] is true and the process is still single-threaded.
///
/// On a non-Linux host this exits non-zero: the launcher is the Linux backend's
/// entry point; macOS/Windows use their own containment mechanisms (E3/E4), not a
/// re-exec launcher.
pub fn run_on_main_thread(args: &[String]) -> ! {
    let parsed = match parse_args(args) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("tirith __capsule-child: {e}");
            std::process::exit(2);
        }
    };
    #[cfg(target_os = "linux")]
    {
        linux_launch(&parsed)
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = &parsed;
        eprintln!(
            "tirith __capsule-child: the re-exec launcher is Linux-only; this platform uses a \
             different containment backend"
        );
        std::process::exit(2);
    }
}

/// Linux launch path: deserialize the spec, create the temporary HOME, apply
/// containment, verify coverage is not degraded against the spec's requirement,
/// then `execve` the target. Diverges (never returns): `execvp` replaces the
/// image on success and every failure path exits non-zero.
#[cfg(target_os = "linux")]
fn linux_launch(parsed: &ParsedArgs) -> ! {
    use std::ffi::CString;
    use tirith_core::capsule::linux::{apply_containment, exec_cstrings};
    use tirith_core::capsule::CapsuleSpec;

    let spec: CapsuleSpec = match serde_json::from_str(&parsed.spec_json) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("tirith __capsule-child: invalid capsule spec JSON: {e}");
            std::process::exit(2);
        }
    };

    // Defense in depth: refuse to apply containment unless we can CONFIRM the
    // process is single-threaded. Applying a per-thread seccomp filter + Landlock
    // in a multi-threaded process is unsound (the filter binds only the calling
    // thread), so this must fail CLOSED: if we cannot read the thread count, we
    // cannot prove single-threadedness and must not proceed. This should never trip
    // because the caller invokes us before the worker-thread spawn, but a hard
    // fail-closed check here means neither a future refactor nor an unreadable
    // `/proc` can silently weaken the guarantee.
    match current_thread_count() {
        Some(1) => {}
        Some(threads) => {
            eprintln!(
                "tirith __capsule-child: refusing to contain a multi-threaded process \
                 ({threads} threads); this is an internal invariant violation"
            );
            std::process::exit(2);
        }
        None => {
            eprintln!(
                "tirith __capsule-child: refusing to apply containment; could not confirm the \
                 process is single-threaded (unable to read /proc/self/stat). Failing closed \
                 rather than risk an unsound multi-threaded seccomp/Landlock apply."
            );
            std::process::exit(2);
        }
    }

    // Build the argv for execve BEFORE we lock down, so a bad arg fails early.
    let argv: Vec<CString> = match exec_cstrings(&parsed.program, &parsed.program_args) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("tirith __capsule-child: {e}");
            std::process::exit(2);
        }
    };

    // Create the temporary HOME the env policy will point at (when temporary_home).
    // Held in a guard so it is cleaned up if we exit before execve; on a successful
    // execve the directory leaks intentionally (the contained child owns it for its
    // lifetime, and the parent's wrapper removes it after the child exits in E5).
    let temp_home = if spec.environment.temporary_home {
        match tempfile::Builder::new().prefix("tirith-capsule-").tempdir() {
            Ok(dir) => Some(dir),
            Err(e) => {
                eprintln!("tirith __capsule-child: could not create temporary HOME: {e}");
                std::process::exit(2);
            }
        }
    } else {
        None
    };
    let temp_home_path: Option<std::path::PathBuf> =
        temp_home.as_ref().map(|d| d.path().to_path_buf());

    // Apply the full containment sequence. On ANY error we exit non-zero and never
    // exec the target (fail-closed).
    let coverage = match apply_containment(&spec, temp_home_path.as_deref()) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("tirith __capsule-child: containment failed: {e}");
            std::process::exit(2);
        }
    };

    // Honesty gate: the coverage we actually achieved must satisfy what the spec
    // requires, or we refuse to run the target. This is the in-launcher half of the
    // fail-closed contract (the parent also checks available_coverage before
    // spawning, but checking the ACHIEVED coverage here closes the gap where the
    // probe over-reported relative to what the apply actually managed).
    let required = spec.required_coverage();
    if coverage.is_degraded_against(&required) {
        eprintln!(
            "tirith __capsule-child: refusing to run uncontained; achieved coverage is \
             degraded against the spec's requirement (fs_read={} fs_write={} exec={} \
             raw_net_denied={} resources={} env={} handles={})",
            coverage.fs_read_enforced,
            coverage.fs_write_enforced,
            coverage.exec_limited,
            coverage.network_raw_denied,
            coverage.resource_limits_enforced,
            coverage.env_isolated,
            coverage.handles_isolated,
        );
        std::process::exit(13);
    }

    // We must NOT drop the tempdir here: execvp replaces the process image, so the
    // child needs HOME to keep existing. Leak the guard intentionally.
    std::mem::forget(temp_home);

    // execvp searches PATH for a bare program name, matching how a user would run
    // it; an absolute/relative path is used as-is. On success this never returns.
    let prog_c = argv[0].clone();
    let mut ptrs: Vec<*const libc::c_char> = argv.iter().map(|c| c.as_ptr()).collect();
    ptrs.push(std::ptr::null());
    // SAFETY: `prog_c` and every pointer in `ptrs` are valid, NUL-terminated C
    // strings that outlive the call (owned by `argv`/`prog_c`), and `ptrs` is
    // NULL-terminated as execvp requires.
    unsafe {
        libc::execvp(prog_c.as_ptr(), ptrs.as_ptr());
    }
    // execvp only returns on error.
    let err = std::io::Error::last_os_error();
    eprintln!(
        "tirith __capsule-child: exec of {:?} failed: {err}",
        parsed.program
    );
    std::process::exit(127);
}

/// The number of threads in the current process, read from `/proc/self/stat`
/// (field 20). `None` if it cannot be determined; the caller treats `None` as
/// fail-closed (it cannot confirm single-threadedness, so it refuses to apply
/// containment) rather than proceeding on an unverified assumption. Linux-only.
#[cfg(target_os = "linux")]
fn current_thread_count() -> Option<usize> {
    let stat = std::fs::read_to_string("/proc/self/stat").ok()?;
    // /proc/self/stat: the comm field (2nd) is in parens and may contain spaces, so
    // split AFTER the closing paren to keep the remaining fields aligned.
    let after = stat.rsplit_once(") ")?.1;
    // After the ") ", fields are: state(1) ppid(2) ... num_threads is field 18
    // counting from `state` as field 1 (i.e. the 20th overall field).
    let num_threads = after.split_whitespace().nth(17)?;
    num_threads.parse::<usize>().ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn argv(parts: &[&str]) -> Vec<String> {
        parts.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn is_invocation_detects_subcommand() {
        assert!(is_invocation(&argv(&[
            "tirith",
            "__capsule-child",
            "{}",
            "--",
            "ls"
        ])));
        assert!(!is_invocation(&argv(&["tirith", "scan", "."])));
        assert!(!is_invocation(&argv(&["tirith"])));
        assert!(!is_invocation(&argv(&[])));
    }

    #[test]
    fn parse_args_happy_path() {
        let a = argv(&[
            "tirith",
            "__capsule-child",
            "{\"network\":{\"mode\":\"deny_all\"}}",
            "--",
            "/usr/bin/python3",
            "-m",
            "pip",
        ]);
        let p = parse_args(&a).expect("parse");
        assert_eq!(p.spec_json, "{\"network\":{\"mode\":\"deny_all\"}}");
        assert_eq!(p.program, "/usr/bin/python3");
        assert_eq!(p.program_args, vec!["-m".to_string(), "pip".to_string()]);
    }

    #[test]
    fn parse_args_program_with_no_args() {
        let a = argv(&["tirith", "__capsule-child", "{}", "--", "ls"]);
        let p = parse_args(&a).expect("parse");
        assert_eq!(p.program, "ls");
        assert!(p.program_args.is_empty());
    }

    #[test]
    fn parse_args_requires_separator() {
        let a = argv(&["tirith", "__capsule-child", "{}", "ls"]);
        assert!(parse_args(&a).is_err());
    }

    #[test]
    fn parse_args_requires_program_after_separator() {
        let a = argv(&["tirith", "__capsule-child", "{}", "--"]);
        assert!(parse_args(&a).is_err());
    }

    #[test]
    fn parse_args_requires_spec_before_separator() {
        // `--` immediately after the subcommand: no spec JSON slot.
        let a = argv(&["tirith", "__capsule-child", "--", "ls"]);
        assert!(parse_args(&a).is_err());
    }

    #[test]
    fn parse_args_rejects_non_capsule_invocation() {
        let a = argv(&["tirith", "scan", "{}", "--", "ls"]);
        assert!(parse_args(&a).is_err());
    }

    /// The spec JSON round-trips into a `CapsuleSpec` so the launcher and the
    /// parent agree on the wire format. Uses the locked-down spec the install
    /// surface will hand it.
    #[test]
    fn spec_json_roundtrips_for_launcher() {
        use tirith_core::capsule::CapsuleSpec;
        let spec = CapsuleSpec::locked_down();
        let json = serde_json::to_string(&spec).unwrap();
        let a = argv(&["tirith", "__capsule-child", &json, "--", "ls"]);
        let p = parse_args(&a).unwrap();
        let back: CapsuleSpec = serde_json::from_str(&p.spec_json).unwrap();
        assert_eq!(back, spec);
    }
}
