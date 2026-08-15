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
//! 2. On Linux, validates the parent-owned, policy-granted temporary HOME and applies the
//!    full containment sequence via [`tirith_core::capsule::linux::apply_containment`]
//!    (inherited-FD closure -> rlimits -> no-new-privs -> Landlock -> seccomp ->
//!    env cleanup), verifies the achieved coverage is not degraded against the
//!    spec's requirement, and only then forks the target. The original launcher
//!    remains as a contained process-group leader while its child executes the
//!    target (a content-bound launch uses `execveat(AT_EMPTY_PATH)` on its sealed
//!    inherited descriptor).
//! 3. On macOS, builds the native `sandbox-exec` argv, closes unrelated inherited
//!    descriptors, applies supported rlimits, and `execve`s `sandbox-exec`. This
//!    second exec occurs only after Rust's private parent/child exec-status pipe
//!    has closed normally on the first exec.
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
//! single-threaded main thread. It never returns: the fork child `exec`s the
//! target while the original process waits as its contained guard, then exits
//! with the target status. On any failure it prints to stderr and exits non-zero.
//! It MUST NOT fall through to running the target uncontained (fail-closed).

use std::ffi::{OsStr, OsString};

#[cfg(target_os = "linux")]
use tirith_core::runner::{
    TARGET_ACK_RESUME, TARGET_EXEC_OBSERVED, TARGET_LAUNCH_ERROR, TARGET_LAUNCH_RESUMED,
};

/// The hidden subcommand name. A double-underscore prefix marks it internal and
/// keeps it clear of any real command.
pub const SUBCOMMAND: &str = "__capsule-child";
#[cfg(target_os = "linux")]
pub(crate) const ACHIEVED_COVERAGE_VERSION: u8 = 1;

/// Whether `args` (typically `std::env::args().collect()`) is a `__capsule-child`
/// invocation. Checked at the top of `main()` so the launcher runs before the
/// worker-thread spawn (single-threaded invariant). Pure, so it is unit-testable.
pub fn is_invocation(args: &[OsString]) -> bool {
    args.get(1)
        .is_some_and(|arg| arg.as_os_str() == OsStr::new(SUBCOMMAND))
}

/// The parsed launcher argv: the spec JSON and the target program + args (the part
/// after the `--` separator).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedArgs {
    /// The serialized [`CapsuleSpec`] JSON.
    pub spec_json: String,
    /// The executable path/name passed to `execvp` for an ordinary launch, or a
    /// diagnostic label when `target_fd` selects held-descriptor execution.
    pub program: OsString,
    /// Optional explicit `argv[0]` for alias-sensitive or multicall targets.
    /// When absent, [`Self::program`] is used, preserving the legacy launcher
    /// contract.
    pub target_argv0: Option<OsString>,
    /// Optional inherited, fully sealed Linux executable descriptor. When set,
    /// the launcher executes this descriptor with `execveat(AT_EMPTY_PATH)` and
    /// treats `program` as a diagnostic label only.
    pub target_fd: Option<i32>,
    /// Optional inherited, fully sealed reviewed-script descriptor. It is
    /// carried into the target interpreter and named in argv via /proc/self/fd.
    pub script_fd: Option<i32>,
    /// Guard-owned status descriptor for proving the actual target crossed
    /// exec. Linux only: the guard reports OBSERVED while the tracee is stopped,
    /// then RESUMED only after exact parent authorization and successful detach.
    pub launch_status_fd: Option<i32>,
    /// Guard-owned read endpoint for the parent's one-shot ACK_RESUME. The
    /// tracee remains stopped at PTRACE_EVENT_EXEC until this exact byte and EOF
    /// are observed.
    pub launch_ack_fd: Option<i32>,
    /// One-shot writer used to report the exact coverage returned by the applied
    /// backend. The launcher writes a versioned two-byte record only after the
    /// achieved-coverage gate succeeds, then closes it before target fork.
    pub coverage_status_fd: Option<i32>,
    /// Optional parent-owned temporary HOME. The parent keeps the directory
    /// guard alive until the complete child tree has exited and grants this
    /// exact path in the finalized filesystem policy before launch.
    pub temp_home: Option<OsString>,
    /// Retained directory capability for `temp_home`. The target environment
    /// uses `/proc/self/fd/<n>` so a later visible-path replacement cannot
    /// redirect HOME/XDG authority.
    pub temp_home_fd: Option<i32>,
    /// Optional inherited directory descriptor used as the exact target cwd.
    /// The launcher validates it against `cwd_root`, enters it with `fchdir`,
    /// and keeps artifact operands strictly relative to that vnode.
    pub cwd_fd: Option<i32>,
    /// The single read-root placeholder paired with `cwd_fd`. The launcher
    /// replaces it with the held directory's observed canonical location before
    /// building the OS sandbox policy.
    pub cwd_root: Option<OsString>,
    /// Optional inherited directory descriptor that is BOTH the target's working
    /// directory and its single writable grant. The launcher enters it with
    /// `fchdir` and sources the Landlock write rule from this descriptor, so no
    /// pathname is resolved a second time after the parent proved its identity.
    pub work_fd: Option<i32>,
    /// The write-root pathname paired with `work_fd`, used to locate the exact
    /// policy grant and as a diagnostic. Authority is the descriptor's.
    pub work_root: Option<OsString>,
    /// Parent-owned mountpoint used for the private sealed-input view.
    pub staging_root: Option<OsString>,
    /// Exact inherited mountpoint capability paired with `staging_root`.
    pub staging_fd: Option<i32>,
    /// Ordered sealed input descriptors and their safe visible filenames.
    pub inputs: Vec<(i32, OsString)>,
    /// Retained package target directory capability and its diagnostic path.
    pub target_dir_fd: Option<i32>,
    pub target_dir_root: Option<OsString>,
    pub target_dir_visible_root: Option<OsString>,
    /// The target program's arguments.
    pub program_args: Vec<OsString>,
}

/// Parse `tirith __capsule-child <spec-json> [internal options] -- <prog>
/// <arg>...` from the full process argv. Internal options are closed and may
/// appear at most once: `--target-argv0 <value>`, `--target-fd <number>`,
/// `--script-fd <number>`, `--launch-status-fd <number>`,
/// `--launch-ack-fd <number>`, `--coverage-status-fd <number>`, and
/// `--temp-home <absolute>`, `--cwd-fd <number>`, and
/// `--cwd-root <absolute>`. Sealed-input mode additionally accepts paired
/// `--input-fd`/`--input-name` operands plus one staging and target directory.
/// Pure and platform-independent, so the argv grammar is unit-testable
/// everywhere.
pub fn parse_args(args: &[OsString]) -> Result<ParsedArgs, String> {
    // args[0] = "tirith", args[1] = SUBCOMMAND.
    if args.get(1).map(OsString::as_os_str) != Some(OsStr::new(SUBCOMMAND)) {
        return Err("not a __capsule-child invocation".to_string());
    }
    let spec_json = args
        .get(2)
        .ok_or_else(|| "missing capsule spec JSON".to_string())?
        .clone()
        .into_string()
        .map_err(|_| "capsule spec JSON is not valid UTF-8".to_string())?;
    // Find the `--` separator.
    let sep = args
        .iter()
        .position(|a| a.as_os_str() == OsStr::new("--"))
        .ok_or_else(|| "missing `--` separator before the program".to_string())?;
    // The spec must be BEFORE the separator (index 2 < sep).
    if sep < 3 {
        return Err("the `--` separator must follow the spec JSON".to_string());
    }
    let mut target_argv0 = None;
    let mut target_fd = None;
    let mut script_fd = None;
    let mut launch_status_fd = None;
    let mut launch_ack_fd = None;
    let mut coverage_status_fd = None;
    let mut temp_home = None;
    let mut temp_home_fd = None;
    let mut cwd_fd = None;
    let mut cwd_root = None;
    let mut work_fd = None;
    let mut work_root = None;
    let mut staging_root = None;
    let mut staging_fd = None;
    let mut input_fds = Vec::new();
    let mut input_names = Vec::new();
    let mut target_dir_fd = None;
    let mut target_dir_root = None;
    let mut target_dir_visible_root = None;
    let mut option_index = 3usize;
    while option_index < sep {
        let option = &args[option_index];
        let value = args
            .get(option_index + 1)
            .filter(|_| option_index + 1 < sep)
            .ok_or_else(|| format!("missing value for internal launcher option {option:?}"))?
            .clone();
        if option == "--target-argv0" {
            if target_argv0.replace(value).is_some() {
                return Err("duplicate `--target-argv0` launcher option".to_string());
            }
        } else if option == "--target-fd" {
            if target_fd.is_some() {
                return Err("duplicate `--target-fd` launcher option".to_string());
            }
            let raw = value
                .to_str()
                .ok_or_else(|| "`--target-fd` is not valid UTF-8".to_string())?;
            let parsed = raw
                .parse::<i32>()
                .map_err(|_| "`--target-fd` must be a decimal descriptor".to_string())?;
            if parsed < 3 {
                return Err("`--target-fd` must not overlap standard I/O".to_string());
            }
            target_fd = Some(parsed);
        } else if option == "--launch-status-fd" {
            if launch_status_fd.is_some() {
                return Err("duplicate `--launch-status-fd` launcher option".to_string());
            }
            let raw = value
                .to_str()
                .ok_or_else(|| "`--launch-status-fd` is not valid UTF-8".to_string())?;
            let parsed = raw
                .parse::<i32>()
                .map_err(|_| "`--launch-status-fd` must be a decimal descriptor".to_string())?;
            if parsed < 3 {
                return Err("`--launch-status-fd` must not overlap standard I/O".to_string());
            }
            launch_status_fd = Some(parsed);
        } else if option == "--script-fd" {
            if script_fd.is_some() {
                return Err("duplicate `--script-fd` launcher option".to_string());
            }
            let raw = value
                .to_str()
                .ok_or_else(|| "`--script-fd` is not valid UTF-8".to_string())?;
            let parsed = raw
                .parse::<i32>()
                .map_err(|_| "`--script-fd` must be a decimal descriptor".to_string())?;
            if parsed < 3 {
                return Err("`--script-fd` must not overlap standard I/O".to_string());
            }
            script_fd = Some(parsed);
        } else if option == "--launch-ack-fd" {
            if launch_ack_fd.is_some() {
                return Err("duplicate `--launch-ack-fd` launcher option".to_string());
            }
            let raw = value
                .to_str()
                .ok_or_else(|| "`--launch-ack-fd` is not valid UTF-8".to_string())?;
            let parsed = raw
                .parse::<i32>()
                .map_err(|_| "`--launch-ack-fd` must be a decimal descriptor".to_string())?;
            if parsed < 3 {
                return Err("`--launch-ack-fd` must not overlap standard I/O".to_string());
            }
            launch_ack_fd = Some(parsed);
        } else if option == "--coverage-status-fd" {
            if coverage_status_fd.is_some() {
                return Err("duplicate `--coverage-status-fd` launcher option".to_string());
            }
            let raw = value
                .to_str()
                .ok_or_else(|| "`--coverage-status-fd` is not valid UTF-8".to_string())?;
            let parsed = raw
                .parse::<i32>()
                .map_err(|_| "`--coverage-status-fd` must be a decimal descriptor".to_string())?;
            if parsed < 3 {
                return Err("`--coverage-status-fd` must not overlap standard I/O".to_string());
            }
            coverage_status_fd = Some(parsed);
        } else if option == "--temp-home" {
            if temp_home.replace(value).is_some() {
                return Err("duplicate `--temp-home` launcher option".to_string());
            }
        } else if option == "--temp-home-fd" {
            if temp_home_fd.is_some() {
                return Err("duplicate `--temp-home-fd` launcher option".to_string());
            }
            let raw = value
                .to_str()
                .ok_or_else(|| "`--temp-home-fd` is not valid UTF-8".to_string())?;
            let parsed = raw
                .parse::<i32>()
                .map_err(|_| "`--temp-home-fd` must be a decimal descriptor".to_string())?;
            if parsed < 3 {
                return Err("`--temp-home-fd` must not overlap standard I/O".to_string());
            }
            temp_home_fd = Some(parsed);
        } else if option == "--cwd-fd" {
            if cwd_fd.is_some() {
                return Err("duplicate `--cwd-fd` launcher option".to_string());
            }
            let raw = value
                .to_str()
                .ok_or_else(|| "`--cwd-fd` is not valid UTF-8".to_string())?;
            let parsed = raw
                .parse::<i32>()
                .map_err(|_| "`--cwd-fd` must be a decimal descriptor".to_string())?;
            if parsed < 3 {
                return Err("`--cwd-fd` must not overlap standard I/O".to_string());
            }
            cwd_fd = Some(parsed);
        } else if option == "--cwd-root" {
            if cwd_root.replace(value).is_some() {
                return Err("duplicate `--cwd-root` launcher option".to_string());
            }
        } else if option == "--work-fd" {
            if work_fd.is_some() {
                return Err("duplicate `--work-fd` launcher option".to_string());
            }
            let raw = value
                .to_str()
                .ok_or_else(|| "`--work-fd` is not valid UTF-8".to_string())?;
            let parsed = raw
                .parse::<i32>()
                .map_err(|_| "`--work-fd` must be a decimal descriptor".to_string())?;
            if parsed < 3 {
                return Err("`--work-fd` must not overlap standard I/O".to_string());
            }
            work_fd = Some(parsed);
        } else if option == "--work-root" {
            if work_root.replace(value).is_some() {
                return Err("duplicate `--work-root` launcher option".to_string());
            }
        } else if option == "--staging-root" {
            if staging_root.replace(value).is_some() {
                return Err("duplicate `--staging-root` launcher option".to_string());
            }
        } else if option == "--staging-fd" {
            if staging_fd.is_some() {
                return Err("duplicate `--staging-fd` launcher option".to_string());
            }
            let raw = value
                .to_str()
                .ok_or_else(|| "`--staging-fd` is not valid UTF-8".to_string())?;
            let parsed = raw
                .parse::<i32>()
                .map_err(|_| "`--staging-fd` must be a decimal descriptor".to_string())?;
            if parsed < 3 {
                return Err("`--staging-fd` must not overlap standard I/O".to_string());
            }
            staging_fd = Some(parsed);
        } else if option == "--input-fd" {
            let raw = value
                .to_str()
                .ok_or_else(|| "`--input-fd` is not valid UTF-8".to_string())?;
            let parsed = raw
                .parse::<i32>()
                .map_err(|_| "`--input-fd` must be a decimal descriptor".to_string())?;
            if parsed < 3 {
                return Err("`--input-fd` must not overlap standard I/O".to_string());
            }
            input_fds.push(parsed);
        } else if option == "--input-name" {
            input_names.push(value);
        } else if option == "--target-dir-fd" {
            if target_dir_fd.is_some() {
                return Err("duplicate `--target-dir-fd` launcher option".to_string());
            }
            let raw = value
                .to_str()
                .ok_or_else(|| "`--target-dir-fd` is not valid UTF-8".to_string())?;
            let parsed = raw
                .parse::<i32>()
                .map_err(|_| "`--target-dir-fd` must be a decimal descriptor".to_string())?;
            if parsed < 3 {
                return Err("`--target-dir-fd` must not overlap standard I/O".to_string());
            }
            target_dir_fd = Some(parsed);
        } else if option == "--target-dir-root" {
            if target_dir_root.replace(value).is_some() {
                return Err("duplicate `--target-dir-root` launcher option".to_string());
            }
        } else if option == "--target-dir-visible-root" {
            if target_dir_visible_root.replace(value).is_some() {
                return Err("duplicate `--target-dir-visible-root` launcher option".to_string());
            }
        } else {
            return Err(format!("unknown internal launcher option {option:?}"));
        }
        option_index += 2;
    }
    if input_fds.len() != input_names.len() {
        return Err("every `--input-fd` requires one ordered `--input-name`".to_string());
    }
    let inputs: Vec<(i32, OsString)> = input_fds.into_iter().zip(input_names).collect();
    let mut internal_fds = vec![
        target_fd,
        script_fd,
        launch_status_fd,
        launch_ack_fd,
        coverage_status_fd,
        temp_home_fd,
        cwd_fd,
        work_fd,
        staging_fd,
        target_dir_fd,
    ];
    internal_fds.extend(inputs.iter().map(|(fd, _)| Some(*fd)));
    for (index, descriptor) in internal_fds.iter().enumerate() {
        if descriptor.is_some() && internal_fds[index + 1..].contains(descriptor) {
            return Err("internal launcher descriptors must be pairwise distinct".to_string());
        }
    }
    if launch_status_fd.is_some() != launch_ack_fd.is_some() {
        return Err(
            "`--launch-status-fd` and `--launch-ack-fd` must be supplied together".to_string(),
        );
    }
    if cwd_fd.is_some() != cwd_root.is_some() {
        return Err("`--cwd-fd` and `--cwd-root` must be supplied together".to_string());
    }
    if work_fd.is_some() != work_root.is_some() {
        return Err("`--work-fd` and `--work-root` must be supplied together".to_string());
    }
    // The two working-directory protocols are mutually exclusive: one binds a
    // read-only grant to the descriptor, the other a writable one, and accepting
    // both would leave the target's cwd ambiguous.
    if work_fd.is_some() && cwd_fd.is_some() {
        return Err("`--work-fd` and `--cwd-fd` are mutually exclusive".to_string());
    }
    if temp_home_fd.is_some() != temp_home.is_some() {
        return Err("`--temp-home-fd` and `--temp-home` must be supplied together".to_string());
    }
    let bound_input_mode = staging_root.is_some()
        || staging_fd.is_some()
        || !inputs.is_empty()
        || target_dir_fd.is_some()
        || target_dir_root.is_some()
        || target_dir_visible_root.is_some();
    if bound_input_mode
        && (staging_root.is_none()
            || staging_fd.is_none()
            || inputs.is_empty()
            || target_dir_fd.is_none()
            || target_dir_root.is_none()
            || target_dir_visible_root.is_none())
    {
        return Err(
            "sealed-input launch requires paired staging root/fd, inputs, target fd, logical target root, and visible target root"
                .to_string(),
        );
    }
    if bound_input_mode && cwd_fd.is_some() {
        return Err("sealed-input launch cannot also select a bound cwd".to_string());
    }
    if bound_input_mode && work_fd.is_some() {
        return Err("sealed-input launch cannot also select a bound work directory".to_string());
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
        target_argv0,
        target_fd,
        script_fd,
        launch_status_fd,
        launch_ack_fd,
        coverage_status_fd,
        temp_home,
        temp_home_fd,
        cwd_fd,
        cwd_root,
        work_fd,
        work_root,
        staging_root,
        staging_fd,
        inputs,
        target_dir_fd,
        target_dir_root,
        target_dir_visible_root,
        program_args,
    })
}

/// Handle a `__capsule-child` invocation on the main thread and never return. On
/// Linux this process remains the stable contained guard while its fork child
/// executes the target. On macOS it replaces itself with `sandbox-exec` after the
/// trusted second-launch setup. Every failure exits non-zero. Call this at the top
/// of `main()` only when [`is_invocation`] is true and the process is still
/// single-threaded.
///
/// On Windows and other non-Unix hosts this exits non-zero; those platforms use a
/// different containment backend. macOS deliberately uses this re-exec launcher
/// so descriptor closure happens after Rust has finished using its private
/// exec-status pipe, but before `sandbox-exec` and the target run.
pub fn run_on_main_thread(args: &[OsString]) -> ! {
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
    #[cfg(target_os = "macos")]
    {
        macos_launch(&parsed)
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        let _ = &parsed;
        eprintln!(
            "tirith __capsule-child: the re-exec launcher is Unix-only; this platform uses a \
             different containment backend"
        );
        std::process::exit(2);
    }
}

/// Enter a parent-held directory capability and rebase exactly one read grant to
/// the vnode's current canonical location. The descriptor itself is the identity
/// authority: pathname metadata is accepted only when it resolves back to the
/// same `(device, inode)`, and the descriptor remains in the handle policy until
/// the OS filesystem sandbox has consumed it.
#[cfg(any(target_os = "linux", target_os = "macos"))]
fn prepare_bound_working_directory(
    spec: &mut tirith_core::capsule::CapsuleSpec,
    parsed: &ParsedArgs,
) -> Result<Option<(std::path::PathBuf, i32)>, String> {
    let (fd, original_root) = match (parsed.cwd_fd, parsed.cwd_root.as_deref()) {
        (None, None) => return Ok(None),
        (Some(fd), Some(root)) => (fd, std::path::Path::new(root)),
        _ => return Err("bound cwd descriptor and root must be supplied together".to_string()),
    };
    if !original_root.is_absolute() {
        return Err("bound cwd root must be absolute".to_string());
    }
    if !spec.handles.extra_unix_fds.contains(&fd) {
        return Err(format!(
            "bound cwd descriptor {fd} is absent from the handle allow-list"
        ));
    }

    let canonical_bound = canonicalize_bound_working_policy(spec, original_root)?;

    let mut descriptor_stat = std::mem::MaybeUninit::<libc::stat>::uninit();
    if unsafe { libc::fstat(fd, descriptor_stat.as_mut_ptr()) } != 0 {
        return Err(format!(
            "inspect bound cwd descriptor {fd}: {}",
            std::io::Error::last_os_error()
        ));
    }
    let descriptor_stat = unsafe { descriptor_stat.assume_init() };
    if descriptor_stat.st_mode & libc::S_IFMT != libc::S_IFDIR {
        return Err(format!("bound cwd descriptor {fd} is not a directory"));
    }

    if unsafe { libc::fchdir(fd) } != 0 {
        return Err(format!(
            "enter bound cwd descriptor {fd}: {}",
            std::io::Error::last_os_error()
        ));
    }
    let observed = std::env::current_dir()
        .and_then(std::fs::canonicalize)
        .map_err(|error| format!("resolve bound cwd after fchdir: {error}"))?;
    let observed_stat = stat_path(&observed)
        .map_err(|error| format!("inspect resolved bound cwd {}: {error}", observed.display()))?;
    if observed_stat.st_dev != descriptor_stat.st_dev
        || observed_stat.st_ino != descriptor_stat.st_ino
    {
        return Err("resolved bound cwd no longer names the held directory identity".to_string());
    }
    rebase_bound_cwd_root(spec, &canonical_bound, &observed)?;

    let flags = unsafe { libc::fcntl(fd, libc::F_GETFD) };
    if flags < 0 || unsafe { libc::fcntl(fd, libc::F_SETFD, flags | libc::FD_CLOEXEC) } < 0 {
        return Err(format!(
            "arm close-on-exec for bound cwd descriptor {fd}: {}",
            std::io::Error::last_os_error()
        ));
    }
    Ok(Some((observed, fd)))
}

/// Resolve every filesystem root against the launcher's inherited cwd before
/// `fchdir` can change the meaning of a relative path. The bound root must be an
/// isolated read grant: a broader/narrower read or write grant would authorize
/// pathname aliases that are not tied to the retained directory descriptor.
#[cfg(any(target_os = "linux", target_os = "macos"))]
fn canonicalize_bound_working_policy(
    spec: &mut tirith_core::capsule::CapsuleSpec,
    original_root: &std::path::Path,
) -> Result<std::path::PathBuf, String> {
    let original_policy = spec.filesystem.clone();
    let exact_bound_indices: Vec<usize> = original_policy
        .read_roots
        .iter()
        .enumerate()
        .filter_map(|(index, root)| (root == original_root).then_some(index))
        .collect();
    if exact_bound_indices.len() != 1 {
        return Err(format!(
            "bound cwd root must appear exactly once in the pre-launch read policy (found {})",
            exact_bound_indices.len()
        ));
    }
    let bound_index = exact_bound_indices[0];
    let canonical_bound = canonicalize_one_read_root(original_root)?;
    for (index, root) in original_policy.read_roots.iter().enumerate() {
        if index == bound_index {
            continue;
        }
        let canonical = canonicalize_one_read_root(root)?;
        if paths_overlap(&canonical_bound, &canonical) {
            return Err(format!(
                "bound cwd root {} overlaps another read grant {}",
                canonical_bound.display(),
                canonical.display()
            ));
        }
    }
    for root in &original_policy.write_roots {
        let canonical = canonicalize_one_read_root(root)?;
        if paths_overlap(&canonical_bound, &canonical) {
            return Err(format!(
                "bound cwd root {} overlaps a writable grant {}",
                canonical_bound.display(),
                canonical.display()
            ));
        }
    }
    spec.filesystem =
        tirith_core::capsule::canonicalize_and_validate_filesystem_policy(&original_policy)
            .map_err(|error| format!("invalid pre-launch filesystem policy: {error}"))?;
    rebase_bound_cwd_root(spec, &canonical_bound, &canonical_bound)?;
    Ok(canonical_bound)
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn canonicalize_one_read_root(root: &std::path::Path) -> Result<std::path::PathBuf, String> {
    let policy = tirith_core::capsule::FilesystemPolicy {
        read_roots: vec![root.to_path_buf()],
        write_roots: Vec::new(),
        deny_roots: Vec::new(),
    };
    let canonical = tirith_core::capsule::canonicalize_and_validate_filesystem_policy(&policy)
        .map_err(|error| {
            format!(
                "cannot canonicalize filesystem root {}: {error}",
                root.display()
            )
        })?;
    canonical.read_roots.into_iter().next().ok_or_else(|| {
        format!(
            "filesystem root {} disappeared during canonicalization",
            root.display()
        )
    })
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn stat_path(path: &std::path::Path) -> std::io::Result<libc::stat> {
    use std::os::unix::ffi::OsStrExt as _;

    let path = std::ffi::CString::new(path.as_os_str().as_bytes()).map_err(|_| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "bound cwd path contains an interior NUL",
        )
    })?;
    let mut stat = std::mem::MaybeUninit::<libc::stat>::uninit();
    if unsafe { libc::stat(path.as_ptr(), stat.as_mut_ptr()) } != 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(unsafe { stat.assume_init() })
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn paths_overlap(left: &std::path::Path, right: &std::path::Path) -> bool {
    left.starts_with(right) || right.starts_with(left)
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn rebase_bound_cwd_root(
    spec: &mut tirith_core::capsule::CapsuleSpec,
    original_root: &std::path::Path,
    observed_root: &std::path::Path,
) -> Result<(), String> {
    let matching: Vec<usize> = spec
        .filesystem
        .read_roots
        .iter()
        .enumerate()
        .filter_map(|(index, root)| (root == original_root).then_some(index))
        .collect();
    if matching.len() != 1 {
        return Err(format!(
            "bound cwd root must appear exactly once in read_roots (found {})",
            matching.len()
        ));
    }
    if spec
        .filesystem
        .write_roots
        .iter()
        .any(|root| paths_overlap(original_root, root) || paths_overlap(observed_root, root))
    {
        return Err("bound cwd must not overlap a writable filesystem grant".to_string());
    }
    if spec
        .filesystem
        .read_roots
        .iter()
        .enumerate()
        .any(|(index, root)| {
            index != matching[0]
                && (paths_overlap(original_root, root) || paths_overlap(observed_root, root))
        })
    {
        return Err("bound cwd must not overlap another readable filesystem grant".to_string());
    }
    spec.filesystem.read_roots[matching[0]] = observed_root.to_path_buf();
    Ok(())
}

/// Enter a parent-held directory capability that is also the target's single
/// writable grant, and return it so the Landlock rule is built from the
/// DESCRIPTOR rather than from the pathname.
///
/// This is the shape the untrusted-project preset needs and the bound-cwd
/// protocol cannot express: there the held directory is a READ grant, and a
/// writable grant overlapping it would be a second, pathname-derived authority.
/// Here the writable grant IS the descriptor, so there is no second authority to
/// disagree with it. The pathname is still proved to identify the descriptor,
/// because a visible root that was swapped out from under the parent is a
/// refusal rather than a run.
#[cfg(target_os = "linux")]
fn prepare_bound_work_directory(
    spec: &tirith_core::capsule::CapsuleSpec,
    parsed: &ParsedArgs,
) -> Result<Option<(std::path::PathBuf, i32)>, String> {
    let (fd, raw_root) = match (parsed.work_fd, parsed.work_root.as_deref()) {
        (None, None) => return Ok(None),
        (Some(fd), Some(root)) => (fd, root),
        _ => {
            return Err("bound work descriptor and root must be supplied together".to_string());
        }
    };
    if !spec.handles.extra_unix_fds.contains(&fd) {
        return Err(format!(
            "bound work descriptor {fd} is absent from the handle allow-list"
        ));
    }
    let canonical = validate_held_ephemeral_directory(raw_root, fd, "bound work directory")?;
    if spec
        .filesystem
        .write_roots
        .iter()
        .filter(|root| root.as_path() == canonical)
        .count()
        != 1
    {
        return Err(
            "bound work directory must be one exact filesystem-policy write root".to_string(),
        );
    }
    if spec.filesystem.write_roots.iter().any(|root| {
        root.as_path() != canonical && (root.starts_with(&canonical) || canonical.starts_with(root))
    }) {
        return Err("bound work directory must not overlap another writable grant".to_string());
    }
    if spec
        .filesystem
        .read_roots
        .iter()
        .any(|root| root.starts_with(&canonical) || canonical.starts_with(root))
    {
        return Err("bound work directory must not overlap a readable grant".to_string());
    }

    // SAFETY: `fd` is an inherited directory descriptor named by the handle policy.
    if unsafe { libc::fchdir(fd) } != 0 {
        return Err(format!(
            "enter bound work descriptor {fd}: {}",
            std::io::Error::last_os_error()
        ));
    }
    let observed = std::env::current_dir()
        .and_then(std::fs::canonicalize)
        .map_err(|error| format!("resolve bound work directory after fchdir: {error}"))?;
    if observed != canonical {
        return Err(
            "the entered work directory no longer answers to the pathname the policy grants"
                .to_string(),
        );
    }
    Ok(Some((canonical, fd)))
}

#[cfg(target_os = "linux")]
struct PreparedBoundInputs {
    staging_root: std::path::PathBuf,
    staging_fd: i32,
    target_root: std::path::PathBuf,
    target_fd: i32,
    input_fds: Vec<i32>,
}

/// Construct the package launch's private input view before Landlock/seccomp.
/// Each visible filename is a read-only bind mount of a fully sealed memfd inside
/// a new user+mount namespace. The public target pathname is checked against the
/// retained descriptor, but write authority remains the descriptor itself.
#[cfg(target_os = "linux")]
fn prepare_bound_inputs(
    spec: &tirith_core::capsule::CapsuleSpec,
    parsed: &ParsedArgs,
) -> Result<Option<PreparedBoundInputs>, String> {
    use std::os::unix::fs::MetadataExt as _;

    let Some(staging_raw) = parsed.staging_root.as_deref() else {
        return Ok(None);
    };
    let staging_fd = parsed
        .staging_fd
        .ok_or_else(|| "sealed-input staging descriptor is missing".to_string())?;
    let staging = validate_held_ephemeral_directory(staging_raw, staging_fd, "staging")?;
    let target_fd = parsed
        .target_dir_fd
        .ok_or_else(|| "sealed-input target descriptor is missing".to_string())?;
    let target_raw = parsed
        .target_dir_root
        .as_deref()
        .ok_or_else(|| "sealed-input target root is missing".to_string())?;
    let target_root = std::path::PathBuf::from(target_raw);
    let target_visible_raw = parsed
        .target_dir_visible_root
        .as_deref()
        .ok_or_else(|| "sealed-input target visible root is missing".to_string())?;
    let target_visible_root = std::path::PathBuf::from(target_visible_raw);
    if !target_root.is_absolute() || !target_visible_root.is_absolute() {
        return Err("sealed-input staging and target roots must be absolute".to_string());
    }
    if !spec.handles.extra_unix_fds.contains(&staging_fd) {
        return Err("sealed-input staging descriptor is absent from HandlePolicy".to_string());
    }
    if !spec.handles.extra_unix_fds.contains(&target_fd) {
        return Err("sealed-input target descriptor is absent from HandlePolicy".to_string());
    }
    if spec
        .filesystem
        .read_roots
        .iter()
        .filter(|root| root.as_path() == staging)
        .count()
        != 1
    {
        return Err("staging root must be one exact filesystem read grant".to_string());
    }
    if spec
        .filesystem
        .write_roots
        .iter()
        .filter(|root| root.as_path() == target_root)
        .count()
        != 1
    {
        return Err("target root must be one exact filesystem write grant".to_string());
    }

    let target_visible_canonical = target_visible_root.canonicalize().map_err(|error| {
        format!(
            "canonicalize visible target root {}: {error}",
            target_visible_root.display()
        )
    })?;
    if target_visible_canonical != target_visible_root {
        return Err("sealed-input target visible root is not canonical".to_string());
    }
    let target_metadata = std::fs::metadata(&target_visible_root).map_err(|error| {
        format!(
            "inspect visible target root {}: {error}",
            target_visible_root.display()
        )
    })?;
    let mut target_stat = std::mem::MaybeUninit::<libc::stat>::uninit();
    if unsafe { libc::fstat(target_fd, target_stat.as_mut_ptr()) } != 0 {
        return Err(format!(
            "inspect target descriptor: {}",
            std::io::Error::last_os_error()
        ));
    }
    // SAFETY: fstat initialized the structure on success.
    let target_stat = unsafe { target_stat.assume_init() };
    if target_stat.st_mode & libc::S_IFMT != libc::S_IFDIR
        || target_metadata.dev() != target_stat.st_dev
        || target_metadata.ino() != target_stat.st_ino
    {
        return Err(
            "target pathname no longer identifies the retained target directory capability"
                .to_string(),
        );
    }

    let mut names = std::collections::BTreeSet::new();
    let mut approved = 0usize;
    let mut input_fds = Vec::with_capacity(parsed.inputs.len());
    for (fd, raw_name) in &parsed.inputs {
        if !spec.handles.extra_unix_fds.contains(fd) {
            return Err(format!(
                "sealed input descriptor {fd} is absent from HandlePolicy"
            ));
        }
        validate_sealed_script_fd(spec, *fd)
            .map_err(|error| format!("invalid sealed input descriptor {fd}: {error}"))?;
        let name = raw_name
            .to_str()
            .ok_or_else(|| "sealed input filename is not valid UTF-8".to_string())?;
        if !safe_bound_input_name(name) || !names.insert(name.to_string()) {
            return Err(format!(
                "invalid or duplicate sealed input filename {name:?}"
            ));
        }
        if name == "approved.txt" {
            approved += 1;
        } else if !name.ends_with(".whl") {
            return Err(format!(
                "sealed package input {name:?} must retain its .whl filename"
            ));
        }
        input_fds.push(*fd);
    }
    if approved != 1 {
        return Err(format!(
            "sealed-input launch requires exactly one approved.txt (found {approved})"
        ));
    }

    enter_private_input_namespace(staging_fd, &parsed.inputs)?;
    Ok(Some(PreparedBoundInputs {
        staging_root: staging,
        staging_fd,
        target_root,
        target_fd,
        input_fds,
    }))
}

#[cfg(target_os = "linux")]
fn safe_bound_input_name(name: &str) -> bool {
    !name.is_empty()
        && name != "."
        && name != ".."
        && !name.as_bytes().contains(&0)
        && std::path::Path::new(name)
            .components()
            .all(|component| matches!(component, std::path::Component::Normal(_)))
        && std::path::Path::new(name).components().count() == 1
}

#[cfg(target_os = "linux")]
fn enter_private_input_namespace(
    staging_fd: i32,
    inputs: &[(i32, OsString)],
) -> Result<(), String> {
    use std::os::fd::{AsRawFd as _, FromRawFd as _};

    let host_uid = unsafe { libc::geteuid() };
    let host_gid = unsafe { libc::getegid() };
    if unsafe { libc::unshare(libc::CLONE_NEWUSER) } != 0 {
        return Err(format!(
            "create private user namespace: {}",
            std::io::Error::last_os_error()
        ));
    }
    std::fs::write("/proc/self/setgroups", b"deny\n")
        .map_err(|error| format!("disable setgroups in private user namespace: {error}"))?;
    std::fs::write("/proc/self/uid_map", format!("0 {host_uid} 1\n"))
        .map_err(|error| format!("install private user namespace uid map: {error}"))?;
    std::fs::write("/proc/self/gid_map", format!("0 {host_gid} 1\n"))
        .map_err(|error| format!("install private user namespace gid map: {error}"))?;
    if unsafe { libc::unshare(libc::CLONE_NEWNS) } != 0 {
        return Err(format!(
            "create private mount namespace: {}",
            std::io::Error::last_os_error()
        ));
    }

    let slash = c_path(std::path::Path::new("/"))?;
    if unsafe {
        libc::mount(
            std::ptr::null(),
            slash.as_ptr(),
            std::ptr::null(),
            libc::MS_REC | libc::MS_PRIVATE,
            std::ptr::null(),
        )
    } != 0
    {
        return Err(format!(
            "make private mount propagation: {}",
            std::io::Error::last_os_error()
        ));
    }
    // Build a detached tmpfs mount, then attach it directly to the retained
    // staging descriptor with empty-path move_mount. No visible pathname is
    // reopened between validation, mount, population, cwd selection, or the
    // later Landlock rule. Landlock-capable kernels already postdate this mount
    // API; an unavailable syscall therefore fails the enforcing launch closed.
    const FSOPEN_CLOEXEC: libc::c_uint = 1;
    const FSCONFIG_SET_STRING: libc::c_uint = 1;
    const FSCONFIG_CMD_CREATE: libc::c_uint = 6;
    const FSMOUNT_CLOEXEC: libc::c_uint = 1;
    const MOUNT_ATTR_NOSUID: libc::c_uint = 0x0000_0002;
    const MOUNT_ATTR_NODEV: libc::c_uint = 0x0000_0004;
    const MOUNT_ATTR_NOEXEC: libc::c_uint = 0x0000_0008;
    const MOVE_MOUNT_F_EMPTY_PATH: libc::c_uint = 0x0000_0004;
    const MOVE_MOUNT_T_EMPTY_PATH: libc::c_uint = 0x0000_0040;

    let tmpfs = std::ffi::CString::new("tmpfs").expect("literal has no NUL");
    let fs_context = unsafe { libc::syscall(libc::SYS_fsopen, tmpfs.as_ptr(), FSOPEN_CLOEXEC) };
    if fs_context < 0 {
        return Err(format!(
            "create detached sealed-input tmpfs context: {}",
            std::io::Error::last_os_error()
        ));
    }
    // SAFETY: fsopen returned a fresh descriptor.
    let fs_context = unsafe { std::os::fd::OwnedFd::from_raw_fd(fs_context as i32) };
    for (key, value) in [("mode", "0700"), ("size", "64m")] {
        let key = std::ffi::CString::new(key).expect("literal has no NUL");
        let value = std::ffi::CString::new(value).expect("literal has no NUL");
        if unsafe {
            libc::syscall(
                libc::SYS_fsconfig,
                fs_context.as_raw_fd(),
                FSCONFIG_SET_STRING,
                key.as_ptr(),
                value.as_ptr(),
                0,
            )
        } != 0
        {
            return Err(format!(
                "configure detached sealed-input tmpfs: {}",
                std::io::Error::last_os_error()
            ));
        }
    }
    if unsafe {
        libc::syscall(
            libc::SYS_fsconfig,
            fs_context.as_raw_fd(),
            FSCONFIG_CMD_CREATE,
            std::ptr::null::<libc::c_char>(),
            std::ptr::null::<libc::c_void>(),
            0,
        )
    } != 0
    {
        return Err(format!(
            "instantiate detached sealed-input tmpfs: {}",
            std::io::Error::last_os_error()
        ));
    }
    let mounted = unsafe {
        libc::syscall(
            libc::SYS_fsmount,
            fs_context.as_raw_fd(),
            FSMOUNT_CLOEXEC,
            MOUNT_ATTR_NOSUID | MOUNT_ATTR_NODEV | MOUNT_ATTR_NOEXEC,
        )
    };
    if mounted < 0 {
        return Err(format!(
            "materialize detached sealed-input tmpfs: {}",
            std::io::Error::last_os_error()
        ));
    }
    // SAFETY: fsmount returned a fresh mount descriptor.
    let mounted = unsafe { std::os::fd::OwnedFd::from_raw_fd(mounted as i32) };
    let empty = std::ffi::CString::new("").expect("literal has no NUL");
    if unsafe {
        libc::syscall(
            libc::SYS_move_mount,
            mounted.as_raw_fd(),
            empty.as_ptr(),
            staging_fd,
            empty.as_ptr(),
            MOVE_MOUNT_F_EMPTY_PATH | MOVE_MOUNT_T_EMPTY_PATH,
        )
    } != 0
    {
        return Err(format!(
            "attach private sealed-input tmpfs to held staging capability: {}",
            std::io::Error::last_os_error()
        ));
    }

    for (fd, raw_name) in inputs {
        let name = c_os(raw_name)?;
        let destination_fd = unsafe {
            libc::openat(
                mounted.as_raw_fd(),
                name.as_ptr(),
                libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                0o400,
            )
        };
        if destination_fd < 0 {
            return Err(format!(
                "create private input {raw_name:?}: {}",
                std::io::Error::last_os_error()
            ));
        }
        unsafe {
            libc::close(destination_fd);
        }
        let source = std::path::PathBuf::from(format!("/proc/self/fd/{fd}"));
        let destination = std::path::PathBuf::from(format!(
            "/proc/self/fd/{}/{}",
            mounted.as_raw_fd(),
            raw_name.to_string_lossy()
        ));
        let source_c = c_path(&source)?;
        let destination_c = c_path(&destination)?;
        if unsafe {
            libc::mount(
                source_c.as_ptr(),
                destination_c.as_ptr(),
                std::ptr::null(),
                libc::MS_BIND,
                std::ptr::null(),
            )
        } != 0
        {
            return Err(format!(
                "bind sealed input {}: {}",
                destination.display(),
                std::io::Error::last_os_error()
            ));
        }
        if unsafe {
            libc::mount(
                std::ptr::null(),
                destination_c.as_ptr(),
                std::ptr::null(),
                libc::MS_BIND
                    | libc::MS_REMOUNT
                    | libc::MS_RDONLY
                    | libc::MS_NOSUID
                    | libc::MS_NODEV
                    | libc::MS_NOEXEC,
                std::ptr::null(),
            )
        } != 0
        {
            return Err(format!(
                "remount sealed input read-only {}: {}",
                destination.display(),
                std::io::Error::last_os_error()
            ));
        }
    }
    if unsafe {
        libc::mount(
            std::ptr::null(),
            c_path(&std::path::PathBuf::from(format!(
                "/proc/self/fd/{}",
                mounted.as_raw_fd()
            )))?
            .as_ptr(),
            std::ptr::null(),
            libc::MS_REMOUNT | libc::MS_RDONLY | libc::MS_NOSUID | libc::MS_NODEV | libc::MS_NOEXEC,
            std::ptr::null(),
        )
    } != 0
    {
        return Err(format!(
            "seal private input mount read-only: {}",
            std::io::Error::last_os_error()
        ));
    }
    if unsafe { libc::dup3(mounted.as_raw_fd(), staging_fd, 0) } < 0 {
        return Err(format!(
            "replace staging capability with attached tmpfs root: {}",
            std::io::Error::last_os_error()
        ));
    }
    if unsafe { libc::fchdir(staging_fd) } != 0 {
        return Err(format!(
            "enter held private sealed-input staging directory: {}",
            std::io::Error::last_os_error()
        ));
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn c_os(value: &std::ffi::OsStr) -> Result<std::ffi::CString, String> {
    use std::os::unix::ffi::OsStrExt as _;
    std::ffi::CString::new(value.as_bytes()).map_err(|_| "component contains NUL".to_string())
}

#[cfg(target_os = "linux")]
fn c_path(path: &std::path::Path) -> Result<std::ffi::CString, String> {
    use std::os::unix::ffi::OsStrExt as _;
    std::ffi::CString::new(path.as_os_str().as_bytes())
        .map_err(|_| format!("path contains NUL: {}", path.display()))
}

/// macOS launch path: construct the native `sandbox-exec` argv, close every
/// inherited descriptor outside the policy allow-list, apply the supported
/// rlimits, and replace this launcher with `sandbox-exec`.
///
/// This function runs after a successful exec of the Tirith binary. Consequently,
/// the `std::process::Command` exec-status pipe used by the original parent has
/// already observed EOF via `FD_CLOEXEC`; descriptor closure here cannot corrupt
/// Rust's spawn protocol. The process is still single-threaded because `main`
/// dispatches this hidden invocation before creating its worker thread.
#[cfg(target_os = "macos")]
fn macos_launch(parsed: &ParsedArgs) -> ! {
    use std::ffi::CString;
    use std::os::unix::ffi::OsStrExt;
    use tirith_core::capsule::CapsuleSpec;

    let mut spec: CapsuleSpec = match serde_json::from_str(&parsed.spec_json) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("tirith __capsule-child: invalid capsule spec JSON: {e}");
            std::process::exit(2);
        }
    };
    if let Err(error) = prepare_bound_working_directory(&mut spec, parsed) {
        eprintln!("tirith __capsule-child: invalid bound working directory: {error}");
        std::process::exit(2);
    }
    // Seatbelt cannot bind a filesystem grant to a held vnode, so a descriptor
    // bound working directory has no meaning here and must not be silently
    // downgraded to a pathname grant.
    if parsed.work_fd.is_some() {
        eprintln!(
            "tirith __capsule-child: a descriptor-bound work directory is unsupported on macOS"
        );
        std::process::exit(2);
    }

    // Build and validate every CString before descriptor closure so no fallible
    // string conversion or allocation is needed after the isolation boundary is
    // applied. `sandbox_exec_argv_os` also refuses unsupported egress profiles
    // while preserving non-UTF-8 Unix argument bytes exactly.
    let sandbox_argv = match tirith_core::capsule::macos::sandbox_exec_argv_os(
        &spec,
        &parsed.program,
        &parsed.program_args,
    ) {
        Ok(argv) => argv,
        Err(e) => {
            eprintln!("tirith __capsule-child: cannot build sandbox-exec invocation: {e}");
            std::process::exit(2);
        }
    };
    let argv: Vec<CString> = match sandbox_argv
        .iter()
        .map(|arg| CString::new(arg.as_os_str().as_bytes()))
        .collect()
    {
        Ok(argv) => argv,
        Err(_) => {
            eprintln!("tirith __capsule-child: sandbox-exec argument contains NUL");
            std::process::exit(2);
        }
    };

    // Order matters: close inherited fds while RLIMIT_NOFILE still reflects the
    // inherited (higher) ceiling. Lowering it first would not close an already-open
    // high fd and would shrink the scan range, allowing that fd to survive.
    crate::cli::capsule::close_extra_fds(&spec.handles);
    if let Err(e) = crate::cli::capsule::apply_macos_rlimits(&spec.resources) {
        eprintln!("tirith __capsule-child: applying macOS resource limits failed: {e}");
        std::process::exit(2);
    }

    let prog_c = argv[0].clone();
    let mut ptrs: Vec<*const libc::c_char> = argv.iter().map(|arg| arg.as_ptr()).collect();
    ptrs.push(std::ptr::null());
    // SAFETY: `prog_c` and every pointer in `ptrs` are valid, NUL-terminated C
    // strings that outlive the call, and `ptrs` has a final null pointer.
    unsafe {
        libc::execv(prog_c.as_ptr(), ptrs.as_ptr());
    }
    let err = std::io::Error::last_os_error();
    eprintln!("tirith __capsule-child: exec of sandbox-exec failed: {err}");
    std::process::exit(127);
}

/// Linux launch path: deserialize the spec, validate any parent-owned temporary
/// HOME, apply containment, verify coverage is not degraded against the spec's
/// requirement, then fork the target beneath this stable process-group leader.
/// A content-bound launch uses its held, sealed descriptor via
/// `execveat(AT_EMPTY_PATH)`; ordinary launches retain the pathname `execvp`
/// fallback. Every failure path exits non-zero.
#[cfg(target_os = "linux")]
fn linux_launch(parsed: &ParsedArgs) -> ! {
    use std::ffi::CString;
    use std::os::unix::ffi::OsStrExt as _;
    use tirith_core::capsule::linux::{apply_containment, exec_cstrings};
    use tirith_core::capsule::CapsuleSpec;

    let mut spec: CapsuleSpec = match serde_json::from_str(&parsed.spec_json) {
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
    match thread_decision(current_thread_count()) {
        ThreadDecision::Proceed => {}
        ThreadDecision::RefuseMultiThreaded(threads) => {
            eprintln!(
                "tirith __capsule-child: refusing to contain a multi-threaded process \
                 ({threads} threads); this is an internal invariant violation"
            );
            std::process::exit(2);
        }
        ThreadDecision::RefuseUnknown => {
            eprintln!(
                "tirith __capsule-child: refusing to apply containment; could not confirm the \
                 process is single-threaded (unable to read /proc/self/stat). Failing closed \
                 rather than risk an unsound multi-threaded seccomp/Landlock apply."
            );
            std::process::exit(2);
        }
    }

    let bound_cwd = match prepare_bound_working_directory(&mut spec, parsed) {
        Ok(bound) => bound,
        Err(error) => {
            eprintln!("tirith __capsule-child: invalid bound working directory: {error}");
            std::process::exit(2);
        }
    };
    let bound_work = match prepare_bound_work_directory(&spec, parsed) {
        Ok(bound) => bound,
        Err(error) => {
            eprintln!("tirith __capsule-child: invalid bound work directory: {error}");
            std::process::exit(2);
        }
    };
    let bound_inputs = match prepare_bound_inputs(&spec, parsed) {
        Ok(bound) => bound,
        Err(error) => {
            eprintln!("tirith __capsule-child: invalid sealed-input launch: {error}");
            std::process::exit(2);
        }
    };

    // Build both the executable C string and argv BEFORE we lock down, so an
    // interior NUL fails early. The executable path is intentionally independent
    // from argv[0]: a bound snapshot of bash/BusyBox must still observe the closed
    // requested name (`sh`/`ash`) to preserve alias and multicall semantics.
    let prog_c = match CString::new(parsed.program.as_os_str().as_bytes()) {
        Ok(value) => value,
        Err(_) => {
            eprintln!("tirith __capsule-child: program path contains NUL");
            std::process::exit(2);
        }
    };
    let target_argv0 = parsed.target_argv0.as_deref().unwrap_or(&parsed.program);
    let argv: Vec<CString> = match exec_cstrings(target_argv0, &parsed.program_args) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("tirith __capsule-child: {e}");
            std::process::exit(2);
        }
    };

    if let Some(fd) = parsed.target_fd {
        if let Err(error) = validate_sealed_target_fd(&spec, fd) {
            eprintln!("tirith __capsule-child: invalid sealed target descriptor: {error}");
            std::process::exit(2);
        }
    }
    if parsed.launch_status_fd.is_some() != parsed.launch_ack_fd.is_some() {
        eprintln!(
            "tirith __capsule-child: target-exec status and authorization descriptors must be supplied together"
        );
        std::process::exit(2);
    }
    if let Some(fd) = parsed.launch_status_fd {
        if let Err(error) = validate_launch_protocol_fd(&spec, fd, "status") {
            eprintln!("tirith __capsule-child: invalid target-exec status descriptor: {error}");
            std::process::exit(2);
        }
    }
    if let Some(fd) = parsed.launch_ack_fd {
        if let Err(error) = validate_launch_protocol_fd(&spec, fd, "authorization") {
            eprintln!(
                "tirith __capsule-child: invalid target-exec authorization descriptor: {error}"
            );
            std::process::exit(2);
        }
        let flags = unsafe { libc::fcntl(fd, libc::F_GETFD) };
        if flags < 0 || unsafe { libc::fcntl(fd, libc::F_SETFD, flags | libc::FD_CLOEXEC) } < 0 {
            eprintln!(
                "tirith __capsule-child: cannot arm close-on-exec for target authorization descriptor: {}",
                std::io::Error::last_os_error()
            );
            std::process::exit(2);
        }
    }
    if let Some(fd) = parsed.coverage_status_fd {
        if let Err(error) = validate_launch_protocol_fd(&spec, fd, "coverage") {
            eprintln!("tirith __capsule-child: invalid achieved-coverage descriptor: {error}");
            std::process::exit(2);
        }
        let flags = unsafe { libc::fcntl(fd, libc::F_GETFD) };
        if flags < 0 || unsafe { libc::fcntl(fd, libc::F_SETFD, flags | libc::FD_CLOEXEC) } < 0 {
            eprintln!(
                "tirith __capsule-child: cannot arm close-on-exec for achieved-coverage descriptor: {}",
                std::io::Error::last_os_error()
            );
            std::process::exit(2);
        }
    }
    if let Some(fd) = parsed.script_fd {
        if Some(fd) == parsed.target_fd
            || Some(fd) == parsed.launch_status_fd
            || Some(fd) == parsed.launch_ack_fd
        {
            eprintln!(
                "tirith __capsule-child: reviewed-script descriptor overlaps another internal descriptor"
            );
            std::process::exit(2);
        }
        if let Err(error) = validate_sealed_script_fd(&spec, fd) {
            eprintln!("tirith __capsule-child: invalid reviewed-script descriptor: {error}");
            std::process::exit(2);
        }
        let expected = OsString::from(format!("/proc/self/fd/{fd}"));
        if parsed.program_args.last() != Some(&expected) {
            eprintln!(
                "tirith __capsule-child: reviewed-script argv does not name the validated descriptor"
            );
            std::process::exit(2);
        }
    } else if parsed
        .program_args
        .last()
        .and_then(|arg| arg.to_str())
        .and_then(|arg| arg.strip_prefix("/proc/self/fd/"))
        .and_then(|fd| fd.parse::<i32>().ok())
        .is_some_and(|fd| {
            spec.handles.extra_unix_fds.contains(&fd)
                && Some(fd) != parsed.target_fd
                && Some(fd) != parsed.launch_status_fd
                && Some(fd) != parsed.launch_ack_fd
        })
    {
        eprintln!(
            "tirith __capsule-child: inherited reviewed-script operand requires --script-fd validation"
        );
        std::process::exit(2);
    }

    #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
    if let Some(fd) = parsed.launch_status_fd {
        write_target_launch_status(fd, TARGET_LAUNCH_ERROR);
        eprintln!(
            "tirith __capsule-child: kernel target-exec proof is unavailable on this Linux architecture"
        );
        std::process::exit(2);
    }

    // Every temporary-HOME launch supplies a parent-owned directory that was
    // added to the finalized Landlock read/write policy. The parent keeps its
    // TempDir guard alive through complete-tree cleanup. Creating it here would
    // be too late for the serialized policy and would leak it across target exec.
    let temp_home = match (
        spec.environment.temporary_home,
        parsed.temp_home.as_deref(),
        parsed.temp_home_fd,
    ) {
        (false, Some(_), _) | (false, _, Some(_)) => {
            eprintln!(
                "tirith __capsule-child: --temp-home supplied while temporary_home is disabled"
            );
            std::process::exit(2);
        }
        (true, Some(path), Some(fd)) => match validate_parent_temp_home(&spec, path, fd) {
            Ok(home) => Some(home),
            Err(error) => {
                eprintln!("tirith __capsule-child: invalid parent-owned temporary HOME: {error}");
                std::process::exit(2);
            }
        },
        (true, _, _) => {
            eprintln!(
                "tirith __capsule-child: temporary_home requires paired parent-owned --temp-home/--temp-home-fd"
            );
            std::process::exit(2);
        }
        (false, None, None) => None,
    };

    // Apply the full containment sequence. On ANY error we exit non-zero and never
    // exec the target (fail-closed).
    let mut bound_read_roots = Vec::new();
    let mut bound_write_roots = Vec::new();
    if let Some((root, fd)) = bound_cwd.as_ref() {
        bound_read_roots.push((root.as_path(), *fd));
    }
    if let Some((root, fd)) = bound_work.as_ref() {
        bound_write_roots.push((root.as_path(), *fd));
    }
    if let Some(bound) = bound_inputs.as_ref() {
        bound_read_roots.push((bound.staging_root.as_path(), bound.staging_fd));
        bound_write_roots.push((bound.target_root.as_path(), bound.target_fd));
    }
    if let Some(home) = temp_home.as_ref() {
        bound_write_roots.push((home.diagnostic_root.as_path(), home.fd));
    }
    let containment_result = if bound_read_roots.is_empty() && bound_write_roots.is_empty() {
        apply_containment(
            &spec,
            temp_home.as_ref().map(|home| home.runtime_root.as_path()),
        )
    } else {
        tirith_core::capsule::linux::apply_containment_with_bound_root_sets(
            &spec,
            temp_home.as_ref().map(|home| home.runtime_root.as_path()),
            &bound_read_roots,
            &bound_write_roots,
        )
    };
    let coverage = match containment_result {
        Ok(c) => c,
        Err(e) => {
            eprintln!("tirith __capsule-child: containment failed: {e}");
            std::process::exit(2);
        }
    };
    if let Some((_, fd)) = bound_cwd {
        if unsafe { libc::close(fd) } != 0 {
            eprintln!(
                "tirith __capsule-child: close bound working-directory descriptor failed: {}",
                std::io::Error::last_os_error()
            );
            std::process::exit(2);
        }
    }
    if let Some((_, fd)) = bound_work {
        // The Landlock rule has consumed the descriptor's identity; the target
        // must not inherit the capability itself.
        if unsafe { libc::close(fd) } != 0 {
            eprintln!(
                "tirith __capsule-child: close bound work-directory descriptor failed: {}",
                std::io::Error::last_os_error()
            );
            std::process::exit(2);
        }
    }
    if let Some(bound) = bound_inputs.as_ref() {
        if unsafe { libc::close(bound.staging_fd) } != 0 {
            eprintln!(
                "tirith __capsule-child: close sealed-input staging descriptor failed: {}",
                std::io::Error::last_os_error()
            );
            std::process::exit(2);
        }
        for fd in &bound.input_fds {
            if unsafe { libc::close(*fd) } != 0 {
                eprintln!(
                    "tirith __capsule-child: close sealed-input descriptor {fd} failed: {}",
                    std::io::Error::last_os_error()
                );
                std::process::exit(2);
            }
        }
    }

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

    // This is the only positive report of achieved coverage. The parent never
    // promotes a preflight probe into an execution receipt: it must observe this
    // complete record and, separately, the authenticated target-exec protocol.
    if let Some(fd) = parsed.coverage_status_fd {
        if let Err(error) = write_achieved_coverage(fd, coverage) {
            eprintln!("tirith __capsule-child: report achieved coverage: {error}");
            std::process::exit(2);
        }
        if unsafe { libc::close(fd) } != 0 {
            eprintln!(
                "tirith __capsule-child: close achieved-coverage descriptor: {}",
                std::io::Error::last_os_error()
            );
            std::process::exit(2);
        }
    }

    // Keep this contained launcher as the stable process-group leader and fork
    // the target beneath it. This parent boundary is security-critical: Linux
    // clone/clone3 permit a child-termination signal (including SIGKILL or
    // SIGSTOP), and CLONE_PARENT directs that signal at the caller's parent. If
    // the target replaced this launcher directly, a hostile descendant could
    // therefore signal Tirith itself. With the launcher retained, every such
    // signal lands on this already-contained guard instead. The outer supervisor
    // owns the complete group and will kill it before reaping this leader.
    let guard_pid = unsafe { libc::getpid() };
    let process_group = unsafe { libc::getpgrp() };
    if guard_pid <= 0 || process_group != guard_pid {
        eprintln!(
            "tirith __capsule-child: refusing target launch because the contained launcher is \
             not its process-group leader"
        );
        std::process::exit(2);
    }
    let target_pid = unsafe { libc::fork() };
    if target_pid < 0 {
        eprintln!(
            "tirith __capsule-child: fork contained target failed: {}",
            std::io::Error::last_os_error()
        );
        std::process::exit(127);
    }
    if target_pid > 0 {
        if let (Some(status_fd), Some(ack_fd)) = (parsed.launch_status_fd, parsed.launch_ack_fd) {
            if let Err(error) = confirm_target_exec_event(target_pid, status_fd, ack_fd) {
                unsafe {
                    libc::close(status_fd);
                    libc::close(ack_fd);
                }
                match &error {
                    TargetExecEventError::BeforeAck(_) => eprintln!(
                        "tirith __capsule-child: target did not cross the authorized kernel exec boundary: {error}"
                    ),
                    TargetExecEventError::AfterAck(_) => eprintln!(
                        "tirith __capsule-child: target was authorized and may have executed before terminal resume proof failed: {error}"
                    ),
                }
                // kill(2) is deliberately absent from the seccomp policy. Use
                // the narrowly-filtered PTRACE_KILL relationship to clean and
                // reap a stopped tracee, including failures before EXITKILL is
                // known armed. If it cannot be issued, never block here: exit
                // immediately so an armed EXITKILL fires and let the outer
                // uncontained supervisor finalize the anchored group.
                let _ = terminate_stopped_tracee(target_pid);
                std::process::exit(127);
            }
        }
        match wait_for_contained_target(target_pid) {
            Ok(ContainedTargetExit::Code(code)) => std::process::exit(code),
            Ok(ContainedTargetExit::Signal(signal)) => std::process::exit(128 + signal),
            Err(error) => {
                eprintln!("tirith __capsule-child: wait for contained target failed: {error}");
                std::process::exit(125);
            }
        }
    }
    // The fork child inherits the guard's group, Landlock domain, seccomp filter,
    // rlimits, scrubbed environment, and descriptor policy. Refuse if that group
    // relationship is ever changed by a future refactor before target exec.
    if unsafe { libc::getpgrp() } != guard_pid {
        eprintln!(
            "tirith __capsule-child: contained target did not inherit the launcher's process group"
        );
        std::process::exit(126);
    }

    // Only the stable guard may consume the parent's ACK_RESUME. The target
    // closes its inherited read endpoint before arming tracing, and the guard
    // endpoint itself is CLOEXEC as defense in depth against future flow edits.
    if let Some(fd) = parsed.launch_ack_fd {
        unsafe {
            libc::close(fd);
        }
    }

    // Close the pre-EXITKILL guard-death window. PR_SET_PDEATHSIG is inherited
    // across exec, and the immediate parent recheck closes the race where the
    // guard dies between fork and prctl. Thus an uncommitted target cannot
    // auto-detach and run if its trusted tracer disappears before SETOPTIONS.
    if unsafe { libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL, 0, 0, 0) } < 0
        || unsafe { libc::getppid() } != guard_pid
    {
        if let Some(fd) = parsed.launch_status_fd {
            write_target_launch_status(fd, TARGET_LAUNCH_ERROR);
        }
        eprintln!("tirith __capsule-child: cannot bind contained target lifetime to its guard");
        std::process::exit(126);
    }

    if let Some(fd) = parsed.launch_status_fd {
        let flags = unsafe { libc::fcntl(fd, libc::F_GETFD) };
        if flags < 0 || unsafe { libc::fcntl(fd, libc::F_SETFD, flags | libc::FD_CLOEXEC) } < 0 {
            write_target_launch_status(fd, TARGET_LAUNCH_ERROR);
            eprintln!(
                "tirith __capsule-child: cannot arm target-exec status descriptor: {}",
                std::io::Error::last_os_error()
            );
            std::process::exit(126);
        }
        let traced = unsafe {
            libc::ptrace(
                libc::PTRACE_TRACEME,
                0,
                std::ptr::null_mut::<libc::c_void>(),
                std::ptr::null_mut::<libc::c_void>(),
            )
        };
        if traced < 0 {
            write_target_launch_status(fd, TARGET_LAUNCH_ERROR);
            eprintln!(
                "tirith __capsule-child: cannot arm kernel target-exec tracing: {}",
                std::io::Error::last_os_error()
            );
            std::process::exit(126);
        }
        #[cfg(target_arch = "x86_64")]
        unsafe {
            // A synchronous breakpoint produces the initial ptrace stop without
            // granting kill/tgkill to code that survives the later exec.
            std::arch::asm!("int3", options(nomem, nostack));
        }
        #[cfg(target_arch = "aarch64")]
        unsafe {
            // AArch64's synchronous breakpoint is the architectural equivalent
            // of x86_64 int3 and yields the initial SIGTRAP trace stop without a
            // signal-delivery syscall grant.
            std::arch::asm!("brk #0", options(nomem, nostack));
        }
    }

    // Only the fork child reaches the execution primitives; the group-leader
    // guard above never replaces itself with attacker-controlled target code.
    let mut ptrs: Vec<*const libc::c_char> = argv.iter().map(|c| c.as_ptr()).collect();
    ptrs.push(std::ptr::null());
    if let Some(fd) = parsed.target_fd {
        let empty = b"\0";
        unsafe extern "C" {
            static mut environ: *mut *mut libc::c_char;
        }
        // SAFETY: the descriptor was validated as a fully sealed executable and
        // kept by HandlePolicy; `empty`, argv, and the current environ are all
        // live and NUL-terminated as required by execveat(AT_EMPTY_PATH).
        unsafe {
            libc::syscall(
                libc::SYS_execveat,
                fd,
                empty.as_ptr() as *const libc::c_char,
                ptrs.as_ptr(),
                environ as *const *const libc::c_char,
                libc::AT_EMPTY_PATH,
            );
        }
        let error = std::io::Error::last_os_error();
        if let Some(status_fd) = parsed.launch_status_fd {
            write_target_launch_status(status_fd, TARGET_LAUNCH_ERROR);
        }
        eprintln!(
            "tirith __capsule-child: execveat of sealed target {:?} failed: {error}",
            parsed.program
        );
        std::process::exit(127);
    }

    // Ordinary launcher calls retain pathname/PATH behavior.
    // SAFETY: `prog_c` and every pointer in `ptrs` are valid, NUL-terminated C
    // strings that outlive the call (owned by `argv`/`prog_c`), and `ptrs` is
    // NULL-terminated as execvp requires.
    unsafe {
        libc::execvp(prog_c.as_ptr(), ptrs.as_ptr());
    }
    // execvp only returns on error.
    let err = std::io::Error::last_os_error();
    if let Some(status_fd) = parsed.launch_status_fd {
        write_target_launch_status(status_fd, TARGET_LAUNCH_ERROR);
    }
    eprintln!(
        "tirith __capsule-child: exec of {:?} failed: {err}",
        parsed.program
    );
    std::process::exit(127);
}

#[cfg(target_os = "linux")]
fn write_target_launch_status(fd: i32, status: u8) -> bool {
    let mut written = 0usize;
    let bytes = [status];
    while written < bytes.len() {
        let result = unsafe {
            libc::write(
                fd,
                bytes[written..].as_ptr().cast::<libc::c_void>(),
                bytes.len() - written,
            )
        };
        if result > 0 {
            written += result as usize;
            continue;
        }
        if result < 0 && std::io::Error::last_os_error().kind() == std::io::ErrorKind::Interrupted {
            continue;
        }
        return false;
    }
    true
}

#[cfg(target_os = "linux")]
fn write_achieved_coverage(
    fd: i32,
    coverage: tirith_core::capsule::CapsuleCoverage,
) -> Result<(), String> {
    let flags = u8::from(coverage.fs_read_enforced)
        | (u8::from(coverage.fs_write_enforced) << 1)
        | (u8::from(coverage.exec_limited) << 2)
        | (u8::from(coverage.network_raw_denied) << 3)
        | (u8::from(coverage.domain_proxy_enforced) << 4)
        | (u8::from(coverage.resource_limits_enforced) << 5)
        | (u8::from(coverage.env_isolated) << 6)
        | (u8::from(coverage.handles_isolated) << 7);
    let bytes = [ACHIEVED_COVERAGE_VERSION, flags];
    let mut written = 0usize;
    while written < bytes.len() {
        let result = unsafe {
            libc::write(
                fd,
                bytes[written..].as_ptr().cast::<libc::c_void>(),
                bytes.len() - written,
            )
        };
        if result > 0 {
            written += result as usize;
        } else if result < 0
            && std::io::Error::last_os_error().kind() == std::io::ErrorKind::Interrupted
        {
            continue;
        } else {
            return Err(std::io::Error::last_os_error().to_string());
        }
    }
    Ok(())
}

#[cfg(target_os = "linux")]
#[derive(Debug, Clone, PartialEq, Eq)]
enum TargetExecEventError {
    BeforeAck(String),
    AfterAck(String),
}

#[cfg(target_os = "linux")]
impl TargetExecEventError {
    fn reason(&self) -> &str {
        match self {
            Self::BeforeAck(reason) | Self::AfterAck(reason) => reason,
        }
    }

    #[cfg(test)]
    fn contains(&self, pattern: &str) -> bool {
        self.reason().contains(pattern)
    }
}

#[cfg(target_os = "linux")]
impl std::fmt::Display for TargetExecEventError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.reason())
    }
}

#[cfg(target_os = "linux")]
fn confirm_target_exec_event(
    target_pid: libc::pid_t,
    status_fd: i32,
    ack_fd: i32,
) -> Result<(), TargetExecEventError> {
    let mut status = 0;
    loop {
        let waited = unsafe { libc::waitpid(target_pid, &mut status, libc::__WALL) };
        if waited == target_pid {
            break;
        }
        if waited < 0 {
            let error = std::io::Error::last_os_error();
            if error.kind() == std::io::ErrorKind::Interrupted {
                continue;
            }
            if error.raw_os_error() == Some(libc::ECHILD) {
                return Err(TargetExecEventError::BeforeAck(format!(
                    "wait for target trace stop: {error}"
                )));
            }
            return refuse_unarmed_stopped_tracee(
                target_pid,
                format!("wait for target trace stop: {error}"),
            )
            .map_err(TargetExecEventError::BeforeAck);
        }
    }
    if !libc::WIFSTOPPED(status) {
        return Err(TargetExecEventError::BeforeAck(
            "target exited or signalled before arming exec tracing".to_string(),
        ));
    }
    if libc::WSTOPSIG(status) != libc::SIGTRAP {
        return refuse_unarmed_stopped_tracee(
            target_pid,
            format!(
                "target stopped with signal {} before arming exec tracing",
                libc::WSTOPSIG(status)
            ),
        )
        .map_err(TargetExecEventError::BeforeAck);
    }
    let set_options = unsafe {
        libc::ptrace(
            libc::PTRACE_SETOPTIONS,
            target_pid,
            std::ptr::null_mut::<libc::c_void>(),
            ((libc::PTRACE_O_TRACEEXEC | libc::PTRACE_O_EXITKILL) as usize) as *mut libc::c_void,
        )
    };
    if set_options < 0 {
        return refuse_unarmed_stopped_tracee(
            target_pid,
            format!(
                "set PTRACE_O_TRACEEXEC|PTRACE_O_EXITKILL: {}",
                std::io::Error::last_os_error()
            ),
        )
        .map_err(TargetExecEventError::BeforeAck);
    }
    if unsafe {
        libc::ptrace(
            libc::PTRACE_CONT,
            target_pid,
            std::ptr::null_mut::<libc::c_void>(),
            std::ptr::null_mut::<libc::c_void>(),
        )
    } < 0
    {
        return Err(TargetExecEventError::BeforeAck(format!(
            "continue traced target: {}",
            std::io::Error::last_os_error()
        )));
    }

    loop {
        let waited = unsafe { libc::waitpid(target_pid, &mut status, libc::__WALL) };
        if waited < 0 {
            let error = std::io::Error::last_os_error();
            if error.kind() == std::io::ErrorKind::Interrupted {
                continue;
            }
            return Err(TargetExecEventError::BeforeAck(format!(
                "wait for target exec event: {error}"
            )));
        }
        if waited != target_pid {
            continue;
        }
        if libc::WIFSTOPPED(status)
            && libc::WSTOPSIG(status) == libc::SIGTRAP
            && ((status >> 16) as libc::c_uint) == libc::PTRACE_EVENT_EXEC as libc::c_uint
        {
            let confirmed = authorize_detach_and_report_target_exec(status_fd, ack_fd, || {
                if unsafe {
                    libc::ptrace(
                        libc::PTRACE_DETACH,
                        target_pid,
                        std::ptr::null_mut::<libc::c_void>(),
                        std::ptr::null_mut::<libc::c_void>(),
                    )
                } < 0
                {
                    return Err(format!(
                        "detach kernel-confirmed target: {}",
                        std::io::Error::last_os_error()
                    ));
                }
                Ok(())
            });
            if confirmed.is_ok() {
                // confirm_target_exec_event owns both raw protocol endpoints.
                // On error its caller closes them exactly once; on success
                // ownership ends here after terminal RESUMED was published.
                unsafe {
                    libc::close(status_fd);
                    libc::close(ack_fd);
                }
            }
            return confirmed;
        }
        if libc::WIFEXITED(status) || libc::WIFSIGNALED(status) {
            return Err(TargetExecEventError::BeforeAck(
                "target exited before the kernel reported exec".to_string(),
            ));
        }
        return Err(TargetExecEventError::BeforeAck(format!(
            "target stopped with signal {} before exec",
            libc::WSTOPSIG(status)
        )));
    }
}

/// Complete the stopped-exec authorization protocol in causal order: OBSERVED,
/// exact ACK+EOF, detach/resume, then terminal RESUMED. The caller owns and
/// closes both protocol descriptors exactly once.
#[cfg(target_os = "linux")]
fn authorize_detach_and_report_target_exec(
    status_fd: i32,
    ack_fd: i32,
    detach: impl FnOnce() -> Result<(), String>,
) -> Result<(), TargetExecEventError> {
    // The tracee is still stopped at the kernel's PTRACE_EVENT_EXEC boundary.
    // Publish only that observation, then require the outer trusted parent to
    // authorize resume with one exact byte and close its endpoint.
    if !write_target_launch_status(status_fd, TARGET_EXEC_OBSERVED) {
        return Err(TargetExecEventError::BeforeAck(
            "report stopped kernel-confirmed target exec".to_string(),
        ));
    }
    read_exact_resume_ack(ack_fd).map_err(TargetExecEventError::BeforeAck)?;
    detach().map_err(TargetExecEventError::AfterAck)?;
    if !write_target_launch_status(status_fd, TARGET_LAUNCH_RESUMED) {
        return Err(TargetExecEventError::AfterAck(
            "report detached kernel-confirmed target exec".to_string(),
        ));
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn read_exact_resume_ack(fd: i32) -> Result<(), String> {
    let mut seen = false;
    let mut bytes = [0u8; 16];
    loop {
        let count =
            unsafe { libc::read(fd, bytes.as_mut_ptr().cast::<libc::c_void>(), bytes.len()) };
        if count < 0 {
            let error = std::io::Error::last_os_error();
            if error.kind() == std::io::ErrorKind::Interrupted {
                continue;
            }
            return Err(format!("read target-resume authorization: {error}"));
        }
        if count == 0 {
            return if seen {
                Ok(())
            } else {
                Err("target-resume authorization channel closed without ACK".to_string())
            };
        }
        for byte in &bytes[..count as usize] {
            if *byte != TARGET_ACK_RESUME {
                return Err("target-resume authorization contained an invalid byte".to_string());
            }
            if seen {
                return Err("target-resume authorization was duplicated".to_string());
            }
            seen = true;
        }
    }
}

#[cfg(target_os = "linux")]
fn terminate_stopped_tracee(target_pid: libc::pid_t) -> bool {
    let killed = unsafe {
        libc::ptrace(
            libc::PTRACE_KILL,
            target_pid,
            std::ptr::null_mut::<libc::c_void>(),
            std::ptr::null_mut::<libc::c_void>(),
        )
    };
    if killed < 0 {
        // ESRCH can also mean a live tracee is not currently in ptrace-stop; it
        // is never terminal proof. Only a successful PTRACE_KILL followed by a
        // terminal wait below proves cleanup.
        return false;
    }
    let mut status = 0;
    loop {
        let waited = unsafe { libc::waitpid(target_pid, &mut status, libc::__WALL) };
        if waited == target_pid && (libc::WIFEXITED(status) || libc::WIFSIGNALED(status)) {
            return true;
        }
        if waited < 0 {
            let error = std::io::Error::last_os_error();
            if error.kind() == std::io::ErrorKind::Interrupted {
                continue;
            }
            return error.raw_os_error() == Some(libc::ECHILD);
        }
    }
}

/// Refuse before PTRACE_O_EXITKILL is known armed. A returned error guarantees
/// the target was either already terminal (handled by the caller before this
/// helper) or was PTRACE_KILLed and reaped here. If that proof cannot be made,
/// keep this tracer alive and the tracee stopped until the outer uncontained
/// supervisor kills the complete process group; exiting could auto-detach and
/// resume an unacknowledged image.
#[cfg(target_os = "linux")]
fn refuse_unarmed_stopped_tracee(target_pid: libc::pid_t, reason: String) -> Result<(), String> {
    if terminate_stopped_tracee(target_pid) {
        return Err(format!("{reason}; unarmed tracee cleanup succeeded=true"));
    }
    eprintln!(
        "tirith __capsule-child: {reason}; cannot prove unarmed tracee cleanup, waiting for outer process-group termination"
    );
    let mut status = 0;
    loop {
        let waited = unsafe { libc::waitpid(target_pid, &mut status, libc::__WALL) };
        if waited == target_pid && (libc::WIFEXITED(status) || libc::WIFSIGNALED(status)) {
            return Err(format!(
                "{reason}; outer tracee cleanup observed terminal state"
            ));
        }
        if waited < 0 {
            let error = std::io::Error::last_os_error();
            if error.kind() == std::io::ErrorKind::Interrupted {
                continue;
            }
            if error.raw_os_error() == Some(libc::ECHILD) {
                return Err(format!("{reason}; tracee is no longer a child"));
            }
            // Do not exit on an ambiguous wait failure while EXITKILL is
            // unarmed. Retry until the outer supervisor resolves the group.
        }
    }
}

/// Wait for the direct contained target while this process remains its stable
/// parent and process-group leader. The outer Tirith supervisor observes this
/// guard, not attacker-controlled code, and owns termination of the entire group.
/// A normally exited target preserves its code; a signal death is returned for
/// the caller to represent as conventional non-zero `128 + signal`. If a hostile clone directs
/// SIGKILL at this guard, the kernel terminates it directly and the outer
/// supervisor still sees a signal death and finalizes the anchored group.
#[cfg(target_os = "linux")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ContainedTargetExit {
    Code(i32),
    Signal(i32),
}

#[cfg(target_os = "linux")]
fn wait_for_contained_target(target_pid: libc::pid_t) -> std::io::Result<ContainedTargetExit> {
    let mut status = 0;
    loop {
        // __WALL is load-bearing: CLONE_PARENT makes target-created processes
        // direct children of this guard, and a clone exit_signal of 0 is not
        // waitable through ordinary SIGCHLD semantics. Reap every such child so
        // a live target cannot accumulate zombies as a process-limit DoS, but
        // return only when the primary target itself has terminated.
        let waited = unsafe { libc::waitpid(-1, &mut status, libc::__WALL) };
        if waited > 0 && waited != target_pid {
            continue;
        }
        if waited == target_pid {
            if libc::WIFEXITED(status) {
                return Ok(ContainedTargetExit::Code(libc::WEXITSTATUS(status)));
            }
            if libc::WIFSIGNALED(status) {
                return Ok(ContainedTargetExit::Signal(libc::WTERMSIG(status)));
            }
            continue;
        }
        if waited < 0 {
            let error = std::io::Error::last_os_error();
            if error.kind() == std::io::ErrorKind::Interrupted {
                continue;
            }
            return Err(error);
        }
    }
}

#[cfg(target_os = "linux")]
fn validate_sealed_target_fd(
    spec: &tirith_core::capsule::CapsuleSpec,
    fd: i32,
) -> Result<(), String> {
    use std::os::unix::fs::MetadataExt as _;

    if fd < 3 || !spec.handles.extra_unix_fds.contains(&fd) {
        return Err("descriptor is not an explicit non-stdio HandlePolicy grant".to_string());
    }
    let descriptor_flags = unsafe { libc::fcntl(fd, libc::F_GETFD) };
    if descriptor_flags < 0 {
        return Err(format!(
            "descriptor is not open: {}",
            std::io::Error::last_os_error()
        ));
    }
    let required = libc::F_SEAL_SEAL | libc::F_SEAL_SHRINK | libc::F_SEAL_GROW | libc::F_SEAL_WRITE;
    let seals = unsafe { libc::fcntl(fd, libc::F_GET_SEALS) };
    if seals < 0 || seals & required != required {
        return Err("descriptor is not sealed against every content mutation".to_string());
    }
    let proc_path = std::path::PathBuf::from(format!("/proc/self/fd/{fd}"));
    let metadata = std::fs::metadata(&proc_path)
        .map_err(|error| format!("inspect executable descriptor: {error}"))?;
    if !metadata.is_file() || metadata.mode() & 0o111 == 0 {
        return Err("descriptor is not an executable regular file".to_string());
    }
    if unsafe { libc::fcntl(fd, libc::F_SETFD, descriptor_flags | libc::FD_CLOEXEC) } < 0 {
        return Err(format!(
            "arm close-on-success for executable descriptor: {}",
            std::io::Error::last_os_error()
        ));
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn validate_launch_protocol_fd(
    spec: &tirith_core::capsule::CapsuleSpec,
    fd: i32,
    role: &str,
) -> Result<(), String> {
    if fd < 3 || !spec.handles.extra_unix_fds.contains(&fd) {
        return Err(format!(
            "{role} descriptor is not an explicit non-stdio HandlePolicy grant"
        ));
    }
    if unsafe { libc::fcntl(fd, libc::F_GETFD) } < 0 {
        return Err(format!(
            "{role} descriptor is not open: {}",
            std::io::Error::last_os_error()
        ));
    }
    let mut metadata = std::mem::MaybeUninit::<libc::stat>::zeroed();
    if unsafe { libc::fstat(fd, metadata.as_mut_ptr()) } < 0 {
        return Err(format!(
            "inspect {role} descriptor type: {}",
            std::io::Error::last_os_error()
        ));
    }
    // SAFETY: fstat initialized the structure on success.
    let metadata = unsafe { metadata.assume_init() };
    let descriptor_type = metadata.st_mode & libc::S_IFMT;
    match role {
        "status" | "coverage" => {
            let open_flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
            if descriptor_type != libc::S_IFIFO
                || open_flags < 0
                || open_flags & libc::O_ACCMODE != libc::O_WRONLY
            {
                return Err(format!(
                    "{role} descriptor is not the write-only endpoint of a pipe"
                ));
            }
        }
        "authorization" => {
            let mut socket_type = 0i32;
            let mut socket_type_len = std::mem::size_of::<i32>() as libc::socklen_t;
            let mut socket_domain = 0i32;
            let mut socket_domain_len = std::mem::size_of::<i32>() as libc::socklen_t;
            if descriptor_type != libc::S_IFSOCK
                || unsafe {
                    libc::getsockopt(
                        fd,
                        libc::SOL_SOCKET,
                        libc::SO_TYPE,
                        (&mut socket_type as *mut i32).cast::<libc::c_void>(),
                        &mut socket_type_len,
                    )
                } < 0
                || socket_type != libc::SOCK_STREAM
                || unsafe {
                    libc::getsockopt(
                        fd,
                        libc::SOL_SOCKET,
                        libc::SO_DOMAIN,
                        (&mut socket_domain as *mut i32).cast::<libc::c_void>(),
                        &mut socket_domain_len,
                    )
                } < 0
                || socket_domain != libc::AF_UNIX
            {
                return Err(
                    "authorization descriptor is not an AF_UNIX stream socket endpoint".to_string(),
                );
            }
        }
        _ => return Err("unknown target-exec protocol descriptor role".to_string()),
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn validate_sealed_script_fd(
    spec: &tirith_core::capsule::CapsuleSpec,
    fd: i32,
) -> Result<(), String> {
    use std::os::unix::fs::MetadataExt as _;

    if fd < 3 || !spec.handles.extra_unix_fds.contains(&fd) {
        return Err("descriptor is not an explicit non-stdio HandlePolicy grant".to_string());
    }
    if unsafe { libc::fcntl(fd, libc::F_GETFD) } < 0 {
        return Err(format!(
            "descriptor is not open: {}",
            std::io::Error::last_os_error()
        ));
    }
    let required = libc::F_SEAL_SEAL | libc::F_SEAL_SHRINK | libc::F_SEAL_GROW | libc::F_SEAL_WRITE;
    let seals = unsafe { libc::fcntl(fd, libc::F_GET_SEALS) };
    if seals < 0 || seals & required != required {
        return Err("descriptor is not sealed against every content mutation".to_string());
    }
    let metadata = std::fs::metadata(format!("/proc/self/fd/{fd}"))
        .map_err(|error| format!("inspect reviewed-script descriptor: {error}"))?;
    if !metadata.is_file() || metadata.mode() & 0o222 != 0 {
        return Err("descriptor is not a read-only regular file".to_string());
    }
    Ok(())
}

#[cfg(target_os = "linux")]
#[derive(Debug)]
struct PreparedTempHome {
    diagnostic_root: std::path::PathBuf,
    runtime_root: std::path::PathBuf,
    fd: i32,
}

#[cfg(target_os = "linux")]
fn validate_held_ephemeral_directory(
    raw: &std::ffi::OsStr,
    fd: i32,
    label: &str,
) -> Result<std::path::PathBuf, String> {
    use std::os::unix::fs::MetadataExt as _;

    let requested = std::path::PathBuf::from(raw);
    if !requested.is_absolute() {
        return Err(format!("{label} path is not absolute"));
    }
    let canonical = requested
        .canonicalize()
        .map_err(|error| format!("canonicalize {label} {}: {error}", requested.display()))?;
    if canonical != requested {
        return Err(format!(
            "{label} path is not canonical ({} resolves to {})",
            requested.display(),
            canonical.display()
        ));
    }
    let visible = std::fs::symlink_metadata(&canonical)
        .map_err(|error| format!("inspect visible {label} {}: {error}", canonical.display()))?;
    let mut held = std::mem::MaybeUninit::<libc::stat>::uninit();
    if unsafe { libc::fstat(fd, held.as_mut_ptr()) } != 0 {
        return Err(format!(
            "inspect held {label} descriptor: {}",
            std::io::Error::last_os_error()
        ));
    }
    // SAFETY: fstat initialized the structure on success.
    let held = unsafe { held.assume_init() };
    if !visible.is_dir()
        || visible.file_type().is_symlink()
        || visible.uid() != unsafe { libc::geteuid() }
        || visible.mode() & 0o777 != 0o700
        || held.st_mode & libc::S_IFMT != libc::S_IFDIR
        || visible.dev() != held.st_dev
        || visible.ino() != held.st_ino
    {
        return Err(format!(
            "visible {label} path does not identify the retained owner-only directory capability"
        ));
    }
    Ok(canonical)
}

#[cfg(target_os = "linux")]
fn validate_parent_temp_home(
    spec: &tirith_core::capsule::CapsuleSpec,
    raw: &std::ffi::OsStr,
    fd: i32,
) -> Result<PreparedTempHome, String> {
    if !spec.handles.extra_unix_fds.contains(&fd) {
        return Err("temporary-HOME descriptor is absent from HandlePolicy".to_string());
    }
    let canonical = validate_held_ephemeral_directory(raw, fd, "temporary HOME")?;
    if spec
        .filesystem
        .write_roots
        .iter()
        .filter(|root| root.as_path() == canonical)
        .count()
        != 1
    {
        return Err("temporary HOME must be one exact filesystem-policy write root".to_string());
    }
    let exact_read_duplicates = spec
        .filesystem
        .read_roots
        .iter()
        .filter(|root| root.as_path() == canonical)
        .count();
    if exact_read_duplicates > 1
        || spec.filesystem.read_roots.iter().any(|root| {
            root.as_path() != canonical
                && (root.starts_with(&canonical) || canonical.starts_with(root))
        })
    {
        return Err(
            "temporary-HOME read policy may contain at most one exact duplicate and no overlapping path grant"
                .to_string(),
        );
    }
    Ok(PreparedTempHome {
        diagnostic_root: canonical,
        runtime_root: std::path::PathBuf::from(format!("/proc/self/fd/{fd}")),
        fd,
    })
}

/// The number of threads in the current process, read from `/proc/self/stat`
/// (field 20). `None` if it cannot be determined; the caller treats `None` as
/// fail-closed (it cannot confirm single-threadedness, so it refuses to apply
/// containment) rather than proceeding on an unverified assumption. Linux-only.
///
/// The `/proc/self/stat` PARSE is factored into [`parse_num_threads_from_stat`] so
/// it is unit-testable without a live `/proc`.
#[cfg(target_os = "linux")]
fn current_thread_count() -> Option<usize> {
    let stat = std::fs::read_to_string("/proc/self/stat").ok()?;
    parse_num_threads_from_stat(&stat)
}

/// The fail-closed thread-count decision the launcher acts on. Kept as a pure value
/// (not cfg-gated) so the security-critical "refuse unless provably single-threaded"
/// logic is unit-testable on any platform. It is consumed by the launcher only on
/// Linux (the re-exec backend); off Linux it exists solely for those unit tests, so
/// dead-code is allowed there.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ThreadDecision {
    /// Exactly one thread was confirmed: safe to apply per-thread seccomp/Landlock.
    Proceed,
    /// More than one thread: refuse (a per-thread filter would not bind the others).
    RefuseMultiThreaded(usize),
    /// The thread count could not be read: refuse, because single-threadedness is
    /// unproven (fail closed rather than assume).
    RefuseUnknown,
}

/// Map a (possibly-unknown) thread count to the fail-closed [`ThreadDecision`].
/// **Pure**, so the refuse-by-default contract is unit-testable: `None` and any
/// count other than exactly 1 must refuse. Applying a per-thread seccomp filter or
/// Landlock `restrict_self` in a multi-threaded process is unsound (it binds only
/// the calling thread), and an unknown count cannot prove single-threadedness, so
/// both are refusals.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
pub fn thread_decision(count: Option<usize>) -> ThreadDecision {
    match count {
        Some(1) => ThreadDecision::Proceed,
        Some(threads) => ThreadDecision::RefuseMultiThreaded(threads),
        None => ThreadDecision::RefuseUnknown,
    }
}

/// Parse `num_threads` (field 20) out of the contents of `/proc/self/stat`.
/// **Pure** and platform-independent, so it can be unit-tested without `/proc`.
///
/// `/proc/<pid>/stat` is: `pid (comm) state ppid ...`. The `comm` field is wrapped
/// in parens and may itself contain spaces and `)` characters, so we split after the
/// LAST `") "` to keep the trailing fixed-position fields aligned. Counting from
/// `state` as field 1, `num_threads` is field 18 (the 20th overall field). Returns
/// `None` on any malformed input (a missing closing paren, too few fields, or a
/// non-integer), which the caller treats as fail-closed.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
pub fn parse_num_threads_from_stat(stat: &str) -> Option<usize> {
    // Split AFTER the closing paren of `comm` (use the LAST one so a `)` inside the
    // command name does not throw off the alignment).
    let after = stat.rsplit_once(") ")?.1;
    // After the ") ", fields are: state(1) ppid(2) ... num_threads is field 18
    // counting from `state` as field 1 (i.e. the 20th overall field).
    let num_threads = after.split_whitespace().nth(17)?;
    num_threads.parse::<usize>().ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn argv(parts: &[&str]) -> Vec<OsString> {
        parts.iter().map(OsString::from).collect()
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
        assert_eq!(
            p.program_args,
            vec![OsString::from("-m"), OsString::from("pip")]
        );
    }

    #[test]
    fn parse_args_program_with_no_args() {
        let a = argv(&["tirith", "__capsule-child", "{}", "--", "ls"]);
        let p = parse_args(&a).expect("parse");
        assert_eq!(p.program, "ls");
        assert!(p.program_args.is_empty());
    }

    #[test]
    fn parse_args_preserves_every_internal_launch_operand() {
        let a = argv(&[
            "tirith",
            "__capsule-child",
            "{}",
            "--target-argv0",
            "sh",
            "--target-fd",
            "63",
            "--script-fd",
            "62",
            "--launch-status-fd",
            "61",
            "--launch-ack-fd",
            "60",
            "--coverage-status-fd",
            "58",
            "--temp-home",
            "/tmp/tirith-capsule-fixed",
            "--temp-home-fd",
            "57",
            "--cwd-fd",
            "59",
            "--cwd-root",
            "/tmp/quarantine/transactions/txn-1",
            "--",
            "/tmp/bound/busybox",
            "-s",
        ]);
        let parsed = parse_args(&a).expect("parse internal launch options");
        assert_eq!(parsed.target_argv0.as_deref(), Some(OsStr::new("sh")));
        assert_eq!(parsed.target_fd, Some(63));
        assert_eq!(parsed.script_fd, Some(62));
        assert_eq!(parsed.launch_status_fd, Some(61));
        assert_eq!(parsed.launch_ack_fd, Some(60));
        assert_eq!(parsed.coverage_status_fd, Some(58));
        assert_eq!(parsed.temp_home_fd, Some(57));
        assert_eq!(
            parsed.temp_home.as_deref(),
            Some(OsStr::new("/tmp/tirith-capsule-fixed"))
        );
        assert_eq!(parsed.cwd_fd, Some(59));
        assert_eq!(
            parsed.cwd_root.as_deref(),
            Some(OsStr::new("/tmp/quarantine/transactions/txn-1"))
        );
        assert_eq!(parsed.program, "/tmp/bound/busybox");
        assert_eq!(parsed.program_args, vec![OsString::from("-s")]);
    }

    #[test]
    fn parse_args_carries_a_bound_work_directory_and_keeps_it_apart_from_a_bound_cwd() {
        let base = [
            "tirith",
            "__capsule-child",
            "{}",
            "--work-fd",
            "57",
            "--work-root",
            "/tmp/tirith-capsule-project-ab12ef",
        ];
        let parsed = parse_args(&argv(
            &[&base[..], &["--", "/bin/sh", "-c", "npm test"]].concat(),
        ))
        .expect("parse a bound work directory");
        assert_eq!(parsed.work_fd, Some(57));
        assert_eq!(
            parsed.work_root.as_deref(),
            Some(OsStr::new("/tmp/tirith-capsule-project-ab12ef"))
        );

        // Paired, exclusive with the read-only bound cwd, and never a duplicate
        // of another internal descriptor.
        assert!(parse_args(&argv(&[
            "tirith",
            "__capsule-child",
            "{}",
            "--work-fd",
            "57",
            "--",
            "/bin/sh"
        ]))
        .is_err());
        assert!(parse_args(&argv(
            &[
                &base[..],
                &[
                    "--cwd-fd",
                    "58",
                    "--cwd-root",
                    "/tmp/other",
                    "--",
                    "/bin/sh"
                ]
            ]
            .concat()
        ))
        .is_err());
        assert!(parse_args(&argv(
            &[
                &base[..],
                &[
                    "--temp-home-fd",
                    "57",
                    "--temp-home",
                    "/tmp/h",
                    "--",
                    "/bin/sh"
                ]
            ]
            .concat()
        ))
        .is_err());
    }

    #[test]
    fn parse_args_preserves_sealed_input_capabilities() {
        let a = argv(&[
            "tirith",
            "__capsule-child",
            "{}",
            "--launch-status-fd",
            "63",
            "--launch-ack-fd",
            "62",
            "--coverage-status-fd",
            "61",
            "--staging-root",
            "/tmp/tirith-bound-inputs-1",
            "--staging-fd",
            "57",
            "--input-fd",
            "60",
            "--input-name",
            "approved.txt",
            "--input-fd",
            "59",
            "--input-name",
            "dependency.whl",
            "--target-dir-fd",
            "58",
            "--target-dir-root",
            "/opt/venv",
            "--target-dir-visible-root",
            "/tmp/pending-venv",
            "--",
            "/proc/self/fd/56",
            "-m",
            "pip",
        ]);
        let parsed = parse_args(&a).expect("parse sealed-input capabilities");
        assert_eq!(parsed.coverage_status_fd, Some(61));
        assert_eq!(parsed.staging_fd, Some(57));
        assert_eq!(
            parsed.staging_root.as_deref(),
            Some(OsStr::new("/tmp/tirith-bound-inputs-1"))
        );
        assert_eq!(
            parsed.inputs,
            vec![
                (60, OsString::from("approved.txt")),
                (59, OsString::from("dependency.whl"))
            ]
        );
        assert_eq!(parsed.target_dir_fd, Some(58));
        assert_eq!(
            parsed.target_dir_root.as_deref(),
            Some(OsStr::new("/opt/venv"))
        );
        assert_eq!(
            parsed.target_dir_visible_root.as_deref(),
            Some(OsStr::new("/tmp/pending-venv"))
        );
    }

    #[test]
    fn parse_args_rejects_unknown_or_duplicate_internal_options() {
        for a in [
            argv(&[
                "tirith",
                "__capsule-child",
                "{}",
                "--unknown",
                "x",
                "--",
                "ls",
            ]),
            argv(&[
                "tirith",
                "__capsule-child",
                "{}",
                "--target-argv0",
                "sh",
                "--target-argv0",
                "bash",
                "--",
                "ls",
            ]),
            argv(&[
                "tirith",
                "__capsule-child",
                "{}",
                "--target-fd",
                "2",
                "--",
                "ls",
            ]),
            argv(&[
                "tirith",
                "__capsule-child",
                "{}",
                "--target-fd",
                "63",
                "--target-fd",
                "62",
                "--",
                "ls",
            ]),
            argv(&[
                "tirith",
                "__capsule-child",
                "{}",
                "--script-fd",
                "63",
                "--script-fd",
                "62",
                "--",
                "ls",
            ]),
            argv(&[
                "tirith",
                "__capsule-child",
                "{}",
                "--launch-status-fd",
                "63",
                "--launch-status-fd",
                "62",
                "--",
                "ls",
            ]),
            argv(&[
                "tirith",
                "__capsule-child",
                "{}",
                "--target-fd",
                "63",
                "--script-fd",
                "63",
                "--launch-status-fd",
                "62",
                "--",
                "ls",
            ]),
        ] {
            assert!(parse_args(&a).is_err());
        }
    }

    #[test]
    fn parse_args_requires_a_complete_distinct_bound_cwd_pair() {
        for args in [
            argv(&[
                "tirith",
                "__capsule-child",
                "{}",
                "--cwd-fd",
                "63",
                "--",
                "ls",
            ]),
            argv(&[
                "tirith",
                "__capsule-child",
                "{}",
                "--cwd-root",
                "/tmp/txn",
                "--",
                "ls",
            ]),
            argv(&[
                "tirith",
                "__capsule-child",
                "{}",
                "--target-fd",
                "63",
                "--cwd-fd",
                "63",
                "--cwd-root",
                "/tmp/txn",
                "--",
                "ls",
            ]),
        ] {
            assert!(parse_args(&args).is_err());
        }
    }

    #[test]
    fn parse_args_requires_paired_temp_home_path_and_capability() {
        for args in [
            argv(&[
                "tirith",
                "__capsule-child",
                "{}",
                "--temp-home",
                "/tmp/tirith-home",
                "--",
                "ls",
            ]),
            argv(&[
                "tirith",
                "__capsule-child",
                "{}",
                "--temp-home-fd",
                "57",
                "--",
                "ls",
            ]),
        ] {
            let error = parse_args(&args).expect_err("unpaired temporary HOME must fail");
            assert!(error.contains("--temp-home-fd"), "{error}");
        }
    }

    #[test]
    fn parse_args_requires_complete_distinct_sealed_input_capabilities() {
        let complete = [
            "tirith",
            "__capsule-child",
            "{}",
            "--staging-root",
            "/tmp/tirith-stage",
            "--staging-fd",
            "57",
            "--input-fd",
            "58",
            "--input-name",
            "approved.txt",
            "--target-dir-fd",
            "59",
            "--target-dir-root",
            "/opt/final-target",
            "--target-dir-visible-root",
            "/tmp/pending-target",
            "--",
            "ls",
        ];
        assert!(parse_args(&argv(&complete)).is_ok());

        for omitted_option in ["--staging-fd", "--target-dir-visible-root"] {
            let mut parts = complete.to_vec();
            let index = parts
                .iter()
                .position(|part| *part == omitted_option)
                .expect("fixture option");
            parts.drain(index..=index + 1);
            let error = parse_args(&argv(&parts))
                .expect_err("an incomplete sealed-input capability set must fail");
            assert!(error.contains("sealed-input launch"), "{error}");
        }

        let colliding = argv(&[
            "tirith",
            "__capsule-child",
            "{}",
            "--staging-root",
            "/tmp/tirith-stage",
            "--staging-fd",
            "57",
            "--input-fd",
            "58",
            "--input-name",
            "approved.txt",
            "--target-dir-fd",
            "57",
            "--target-dir-root",
            "/opt/final-target",
            "--target-dir-visible-root",
            "/tmp/pending-target",
            "--",
            "ls",
        ]);
        let error = parse_args(&colliding).expect_err("descriptor collision must fail");
        assert!(error.contains("pairwise distinct"), "{error}");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn held_ephemeral_validation_accepts_identity_and_rejects_visible_swap() {
        use std::os::fd::AsRawFd as _;
        use std::os::unix::fs::{OpenOptionsExt as _, PermissionsExt as _};

        let parent = tempfile::tempdir().expect("validation parent");
        let directory = tempfile::Builder::new()
            .prefix("tirith-child-held-")
            .tempdir_in(parent.path())
            .expect("held directory");
        std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700))
            .expect("secure held directory");
        let path = directory
            .path()
            .canonicalize()
            .expect("canonical held path");
        let handle = std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(&path)
            .expect("open held directory");
        let fd = handle.as_raw_fd();

        assert_eq!(
            validate_held_ephemeral_directory(path.as_os_str(), fd, "staging")
                .expect("unchanged visible identity"),
            path
        );
        let mut spec = tirith_core::capsule::CapsuleSpec::locked_down();
        spec.filesystem.read_roots = vec![path.clone()];
        spec.filesystem.write_roots = vec![path.clone()];
        spec.handles.extra_unix_fds = vec![fd];
        let home = validate_parent_temp_home(&spec, path.as_os_str(), fd)
            .expect("exact read/write duplicate uses unchanged temporary-HOME capability");
        assert_eq!(home.diagnostic_root, path);
        assert_eq!(
            home.runtime_root,
            std::path::PathBuf::from(format!("/proc/self/fd/{fd}"))
        );
        let mut overlapping = spec.clone();
        overlapping.filesystem.read_roots = vec![parent.path().to_path_buf()];
        let overlap_error = validate_parent_temp_home(&overlapping, path.as_os_str(), fd)
            .expect_err("non-exact HOME overlap must fail");
        assert!(overlap_error.contains("no overlapping"), "{overlap_error}");

        let displaced = parent.path().join("held-before-swap");
        std::fs::rename(&path, &displaced).expect("displace held identity");
        std::fs::create_dir(&path).expect("create replacement identity");
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700))
            .expect("secure replacement");

        let staging_error = validate_held_ephemeral_directory(path.as_os_str(), fd, "staging")
            .expect_err("visible staging swap must fail");
        assert!(
            staging_error.contains("does not identify"),
            "{staging_error}"
        );
        let home_error = validate_parent_temp_home(&spec, path.as_os_str(), fd)
            .expect_err("visible temporary-HOME swap must fail");
        assert!(home_error.contains("does not identify"), "{home_error}");
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn bound_cwd_rebase_requires_one_read_only_root() {
        let original = std::path::Path::new("/private/quarantine/txn");
        let observed = std::path::Path::new("/private/quarantine-held/txn");
        let mut spec = tirith_core::capsule::CapsuleSpec::locked_down();
        spec.filesystem.read_roots = vec![original.to_path_buf()];
        spec.filesystem.write_roots.clear();
        rebase_bound_cwd_root(&mut spec, original, observed).expect("one read-only grant");
        assert_eq!(spec.filesystem.read_roots, vec![observed.to_path_buf()]);

        let mut duplicate = tirith_core::capsule::CapsuleSpec::locked_down();
        duplicate.filesystem.read_roots = vec![original.to_path_buf(), original.to_path_buf()];
        duplicate.filesystem.write_roots.clear();
        assert!(rebase_bound_cwd_root(&mut duplicate, original, observed).is_err());

        let mut writable = tirith_core::capsule::CapsuleSpec::locked_down();
        writable.filesystem.read_roots = vec![original.to_path_buf()];
        writable.filesystem.write_roots = vec![std::path::PathBuf::from("/private/quarantine")];
        assert!(rebase_bound_cwd_root(&mut writable, original, observed).is_err());

        let mut readable_parent = tirith_core::capsule::CapsuleSpec::locked_down();
        readable_parent.filesystem.read_roots = vec![
            original.to_path_buf(),
            std::path::PathBuf::from("/private/quarantine"),
        ];
        readable_parent.filesystem.write_roots.clear();
        assert!(rebase_bound_cwd_root(&mut readable_parent, original, observed).is_err());

        let mut readable_child = tirith_core::capsule::CapsuleSpec::locked_down();
        readable_child.filesystem.read_roots =
            vec![original.to_path_buf(), original.join("nested")];
        readable_child.filesystem.write_roots.clear();
        assert!(rebase_bound_cwd_root(&mut readable_child, original, observed).is_err());
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn bound_cwd_policy_canonicalizes_relative_roots_before_fchdir() {
        let inherited_cwd = std::env::current_dir()
            .and_then(std::fs::canonicalize)
            .expect("canonical inherited cwd");
        let original = inherited_cwd.join("nonexistent-quarantine-bound-root");
        let relative_read = std::path::PathBuf::from("nonexistent-relative-read-root");
        let relative_write = std::path::PathBuf::from("nonexistent-relative-write-root");

        let mut spec = tirith_core::capsule::CapsuleSpec::locked_down();
        spec.filesystem.read_roots = vec![original.clone(), relative_read.clone()];
        spec.filesystem.write_roots = vec![relative_write.clone()];
        spec.filesystem.deny_roots.clear();

        let canonical_bound = canonicalize_bound_working_policy(&mut spec, &original)
            .expect("preflight policy canonicalization");
        assert_eq!(canonical_bound, original);
        assert!(spec
            .filesystem
            .read_roots
            .contains(&inherited_cwd.join(relative_read)));
        assert!(spec
            .filesystem
            .write_roots
            .contains(&inherited_cwd.join(relative_write)));
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn bound_cwd_policy_rejects_overlapping_read_aliases() {
        let original = std::path::PathBuf::from("/private/quarantine/txn");
        for overlapping in [
            std::path::PathBuf::from("/private/quarantine"),
            original.join("nested"),
        ] {
            let mut spec = tirith_core::capsule::CapsuleSpec::locked_down();
            spec.filesystem.read_roots = vec![original.clone(), overlapping];
            spec.filesystem.write_roots.clear();
            spec.filesystem.deny_roots.clear();
            assert!(canonicalize_bound_working_policy(&mut spec, &original).is_err());
        }
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

    // ── TG1: /proc/self/stat num_threads parse + fail-closed thread decision ──

    /// Build a `/proc/self/stat`-shaped line with the given `comm` and `num_threads`,
    /// with the surrounding fixed fields in their correct positions (state is field
    /// 3, num_threads is field 20). This mirrors the real kernel format closely
    /// enough to exercise the field-20 alignment, including the `comm`-in-parens
    /// quirk.
    fn stat_line(comm: &str, num_threads: usize) -> String {
        // Fields after comm, with `state` as the first: state ppid pgrp session
        // tty_nr tpgid flags minflt cminflt majflt cmajflt utime stime cutime cstime
        // priority nice num_threads (18 fields = field 3..20). The values are
        // arbitrary placeholders except num_threads (the 18th here).
        let tail = format!(
            "R 5678 1234 1234 34816 1234 4194304 100 0 0 0 1 2 0 0 20 0 {num_threads} \
             0 1 0 0 0 0",
        );
        format!("1234 ({comm}) {tail}")
    }

    #[test]
    fn parse_num_threads_normal_stat_is_one() {
        let stat = stat_line("cat", 1);
        assert_eq!(parse_num_threads_from_stat(&stat), Some(1));
    }

    #[test]
    fn parse_num_threads_handles_comm_with_spaces_and_parens() {
        // The comm field can contain spaces AND parens; the parser splits on the LAST
        // ") " so the trailing fixed fields stay aligned.
        let stat = stat_line("weird )( name", 1);
        assert_eq!(
            parse_num_threads_from_stat(&stat),
            Some(1),
            "comm with spaces/parens must not throw off field-20 alignment"
        );
        // And with a higher count, still aligned.
        let stat3 = stat_line("a (b) c", 3);
        assert_eq!(parse_num_threads_from_stat(&stat3), Some(3));
    }

    #[test]
    fn parse_num_threads_multi_thread_count() {
        let stat = stat_line("server", 3);
        assert_eq!(parse_num_threads_from_stat(&stat), Some(3));
    }

    #[test]
    fn parse_num_threads_garbage_is_none() {
        // No closing paren -> None.
        assert_eq!(parse_num_threads_from_stat("garbage with no parens"), None);
        // Closing paren but too few trailing fields -> None.
        assert_eq!(parse_num_threads_from_stat("1234 (x) R 5 6"), None);
        // Field 20 (num_threads) present but not an integer -> None. After the
        // ") ", `notanumber` must land at 0-indexed token 17 (the num_threads slot:
        // state at index 0 plus 17 more before it).
        let bad = "1234 (x) R 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20 notanumber 22";
        // Sanity: confirm the fixture really puts `notanumber` in the num_threads slot.
        assert_eq!(
            bad.rsplit_once(") ").unwrap().1.split_whitespace().nth(17),
            Some("notanumber")
        );
        assert_eq!(parse_num_threads_from_stat(bad), None);
        // Empty -> None.
        assert_eq!(parse_num_threads_from_stat(""), None);
    }

    #[test]
    fn thread_decision_fails_closed_unless_exactly_one() {
        // The dispositive fail-closed contract: only a confirmed single thread
        // proceeds; an unknown count or any multi-thread count refuses.
        assert_eq!(thread_decision(Some(1)), ThreadDecision::Proceed);
        assert_eq!(
            thread_decision(Some(2)),
            ThreadDecision::RefuseMultiThreaded(2)
        );
        assert_eq!(
            thread_decision(Some(64)),
            ThreadDecision::RefuseMultiThreaded(64)
        );
        assert_eq!(thread_decision(None), ThreadDecision::RefuseUnknown);
        // Zero is not "single-threaded" either (impossible, but must not proceed).
        assert_eq!(
            thread_decision(Some(0)),
            ThreadDecision::RefuseMultiThreaded(0)
        );
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

    #[cfg(all(
        target_os = "linux",
        any(target_arch = "x86_64", target_arch = "aarch64")
    ))]
    struct TraceProtocolFixture {
        target_pid: libc::pid_t,
        status_reader: i32,
        status_writer: i32,
        ack_guard: i32,
        ack_parent: i32,
    }

    #[cfg(all(
        target_os = "linux",
        any(target_arch = "x86_64", target_arch = "aarch64")
    ))]
    fn spawn_trace_protocol_fixture(
        program: &std::ffi::CString,
        arguments: &[std::ffi::CString],
        die_before_trace_stop: bool,
    ) -> TraceProtocolFixture {
        let mut status = [0i32; 2];
        assert_eq!(
            unsafe { libc::pipe2(status.as_mut_ptr(), libc::O_CLOEXEC) },
            0,
            "status pipe: {}",
            std::io::Error::last_os_error()
        );
        let mut ack = [0i32; 2];
        assert_eq!(
            unsafe {
                libc::socketpair(
                    libc::AF_UNIX,
                    libc::SOCK_STREAM | libc::SOCK_CLOEXEC,
                    0,
                    ack.as_mut_ptr(),
                )
            },
            0,
            "ACK socketpair: {}",
            std::io::Error::last_os_error()
        );
        let mut argv: Vec<*const libc::c_char> =
            arguments.iter().map(|argument| argument.as_ptr()).collect();
        argv.push(std::ptr::null());
        let target_pid = unsafe { libc::fork() };
        assert!(
            target_pid >= 0,
            "fork traced target: {}",
            std::io::Error::last_os_error()
        );
        if target_pid == 0 {
            // libtest may have other threads. Use only async-signal-safe libc,
            // inline trap instructions, and the already-built pointer vector.
            unsafe {
                libc::close(status[0]);
                libc::close(ack[0]);
                libc::close(ack[1]);
                if die_before_trace_stop {
                    libc::_exit(44);
                }
                let flags = libc::fcntl(status[1], libc::F_GETFD);
                if flags < 0 || libc::fcntl(status[1], libc::F_SETFD, flags | libc::FD_CLOEXEC) < 0
                {
                    libc::_exit(45);
                }
                if libc::ptrace(
                    libc::PTRACE_TRACEME,
                    0,
                    std::ptr::null_mut::<libc::c_void>(),
                    std::ptr::null_mut::<libc::c_void>(),
                ) < 0
                {
                    libc::_exit(46);
                }
                #[cfg(target_arch = "x86_64")]
                std::arch::asm!("int3", options(nomem, nostack));
                #[cfg(target_arch = "aarch64")]
                std::arch::asm!("brk #0", options(nomem, nostack));
                libc::execv(program.as_ptr(), argv.as_ptr());
                let error = [TARGET_LAUNCH_ERROR];
                let _ = libc::write(status[1], error.as_ptr().cast::<libc::c_void>(), 1);
                libc::_exit(127);
            }
        }
        TraceProtocolFixture {
            target_pid,
            status_reader: status[0],
            status_writer: status[1],
            ack_guard: ack[0],
            ack_parent: ack[1],
        }
    }

    #[cfg(all(
        target_os = "linux",
        any(target_arch = "x86_64", target_arch = "aarch64")
    ))]
    fn send_test_ack(fd: i32, bytes: &[u8]) {
        let sent = unsafe {
            libc::send(
                fd,
                bytes.as_ptr().cast::<libc::c_void>(),
                bytes.len(),
                libc::MSG_NOSIGNAL,
            )
        };
        assert_eq!(sent, bytes.len() as isize);
        unsafe {
            libc::close(fd);
        }
    }

    #[cfg(all(
        target_os = "linux",
        any(target_arch = "x86_64", target_arch = "aarch64")
    ))]
    fn read_status_and_close(fd: i32) -> Vec<u8> {
        use std::io::Read as _;
        use std::os::fd::FromRawFd as _;

        // SAFETY: the fixture transfers unique ownership of its reader here.
        let mut reader = unsafe { std::fs::File::from_raw_fd(fd) };
        let mut bytes = Vec::new();
        reader.read_to_end(&mut bytes).expect("read status to EOF");
        bytes
    }

    #[cfg(all(
        target_os = "linux",
        any(target_arch = "x86_64", target_arch = "aarch64")
    ))]
    #[test]
    fn real_ptrace_exec_event_requires_ack_then_detaches_and_reaps() {
        let program = std::ffi::CString::new("/bin/true").unwrap();
        let argv = [std::ffi::CString::new("true").unwrap()];
        let fixture = spawn_trace_protocol_fixture(&program, &argv, false);
        send_test_ack(fixture.ack_parent, &[TARGET_ACK_RESUME]);
        confirm_target_exec_event(fixture.target_pid, fixture.status_writer, fixture.ack_guard)
            .expect("kernel exec, ACK, detach, and terminal resume");
        assert_eq!(
            read_status_and_close(fixture.status_reader),
            [TARGET_EXEC_OBSERVED, TARGET_LAUNCH_RESUMED]
        );
        let mut status = 0;
        assert_eq!(
            unsafe { libc::waitpid(fixture.target_pid, &mut status, 0) },
            fixture.target_pid
        );
        assert!(libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 0);
        assert_ne!(unsafe { libc::kill(fixture.target_pid, 0) }, 0);
        assert_eq!(
            std::io::Error::last_os_error().raw_os_error(),
            Some(libc::ESRCH)
        );
    }

    #[cfg(all(
        target_os = "linux",
        any(target_arch = "x86_64", target_arch = "aarch64")
    ))]
    #[test]
    fn missing_invalid_or_duplicate_ack_cannot_run_execed_script_side_effects() {
        for ack in [Vec::new(), vec![b'X'], vec![TARGET_ACK_RESUME; 2]] {
            let temp = tempfile::tempdir().expect("marker directory");
            let marker = temp.path().join("must-not-exist");
            let command = format!("printf ran > '{}'", marker.display());
            let program = std::ffi::CString::new("/bin/sh").unwrap();
            let argv = [
                std::ffi::CString::new("sh").unwrap(),
                std::ffi::CString::new("-c").unwrap(),
                std::ffi::CString::new(command).unwrap(),
            ];
            let fixture = spawn_trace_protocol_fixture(&program, &argv, false);
            send_test_ack(fixture.ack_parent, &ack);
            let refusal = confirm_target_exec_event(
                fixture.target_pid,
                fixture.status_writer,
                fixture.ack_guard,
            )
            .expect_err("bad ACK must keep the execed image stopped");
            assert!(matches!(&refusal, TargetExecEventError::BeforeAck(_)));
            assert!(refusal.contains("authorization"), "{refusal}");
            assert!(terminate_stopped_tracee(fixture.target_pid));
            unsafe {
                libc::close(fixture.status_writer);
                libc::close(fixture.ack_guard);
            }
            assert_eq!(
                read_status_and_close(fixture.status_reader),
                [TARGET_EXEC_OBSERVED]
            );
            assert!(!marker.exists(), "target code ran before an exact ACK");
            assert_ne!(unsafe { libc::kill(fixture.target_pid, 0) }, 0);
            assert_eq!(
                std::io::Error::last_os_error().raw_os_error(),
                Some(libc::ESRCH)
            );
        }
    }

    #[cfg(all(
        target_os = "linux",
        any(target_arch = "x86_64", target_arch = "aarch64")
    ))]
    #[test]
    fn exec_failure_and_death_before_initial_stop_never_report_observed() {
        for (program_path, die_before_stop) in [
            ("/definitely/missing/tirith-target", false),
            ("/bin/true", true),
        ] {
            let program = std::ffi::CString::new(program_path).unwrap();
            let argv = [std::ffi::CString::new("fixture").unwrap()];
            let fixture = spawn_trace_protocol_fixture(&program, &argv, die_before_stop);
            send_test_ack(fixture.ack_parent, &[TARGET_ACK_RESUME]);
            let refusal = confirm_target_exec_event(
                fixture.target_pid,
                fixture.status_writer,
                fixture.ack_guard,
            )
            .expect_err("no successful exec event exists");
            assert!(
                refusal.contains("before") || refusal.contains("signalled"),
                "{refusal}"
            );
            unsafe {
                libc::close(fixture.status_writer);
                libc::close(fixture.ack_guard);
            }
            let statuses = read_status_and_close(fixture.status_reader);
            assert!(!statuses.contains(&TARGET_EXEC_OBSERVED), "{statuses:?}");
            assert!(!statuses.contains(&TARGET_LAUNCH_RESUMED), "{statuses:?}");
            assert_ne!(unsafe { libc::kill(fixture.target_pid, 0) }, 0);
            assert_eq!(
                std::io::Error::last_os_error().raw_os_error(),
                Some(libc::ESRCH)
            );
        }
    }

    #[cfg(all(
        target_os = "linux",
        any(target_arch = "x86_64", target_arch = "aarch64")
    ))]
    #[test]
    fn detach_failure_never_publishes_terminal_resumed() {
        let mut status = [0i32; 2];
        assert_eq!(
            unsafe { libc::pipe2(status.as_mut_ptr(), libc::O_CLOEXEC) },
            0
        );
        let mut ack = [0i32; 2];
        assert_eq!(
            unsafe {
                libc::socketpair(
                    libc::AF_UNIX,
                    libc::SOCK_STREAM | libc::SOCK_CLOEXEC,
                    0,
                    ack.as_mut_ptr(),
                )
            },
            0
        );
        send_test_ack(ack[1], &[TARGET_ACK_RESUME]);
        let refusal = authorize_detach_and_report_target_exec(status[1], ack[0], || {
            Err("injected detach failure".to_string())
        })
        .expect_err("detach failure must not become terminal success");
        assert!(matches!(&refusal, TargetExecEventError::AfterAck(_)));
        assert!(refusal.contains("injected"));
        unsafe {
            libc::close(status[1]);
            libc::close(ack[0]);
        }
        assert_eq!(read_status_and_close(status[0]), [TARGET_EXEC_OBSERVED]);
    }

    #[cfg(all(
        target_os = "linux",
        any(target_arch = "x86_64", target_arch = "aarch64")
    ))]
    #[test]
    fn unarmed_stopped_tracee_is_ptrace_killed_and_reaped_before_marker() {
        let temp = tempfile::tempdir().expect("pre-option marker directory");
        let marker = temp.path().join("must-not-exist");
        let marker_c =
            std::ffi::CString::new(marker.as_os_str().as_encoded_bytes()).expect("marker C path");
        let target_pid = unsafe { libc::fork() };
        assert!(target_pid >= 0);
        if target_pid == 0 {
            unsafe {
                if libc::ptrace(
                    libc::PTRACE_TRACEME,
                    0,
                    std::ptr::null_mut::<libc::c_void>(),
                    std::ptr::null_mut::<libc::c_void>(),
                ) < 0
                {
                    libc::_exit(50);
                }
                #[cfg(target_arch = "x86_64")]
                std::arch::asm!("int3", options(nomem, nostack));
                #[cfg(target_arch = "aarch64")]
                std::arch::asm!("brk #0", options(nomem, nostack));
                let byte = *b"x";
                let fd = libc::open(
                    marker_c.as_ptr(),
                    libc::O_WRONLY | libc::O_CREAT | libc::O_TRUNC,
                    0o600,
                );
                if fd >= 0 {
                    let _ = libc::write(fd, byte.as_ptr().cast::<libc::c_void>(), 1);
                    libc::close(fd);
                }
                libc::_exit(0);
            }
        }
        let mut status = 0;
        assert_eq!(
            unsafe { libc::waitpid(target_pid, &mut status, libc::__WALL) },
            target_pid
        );
        assert!(libc::WIFSTOPPED(status));
        assert!(terminate_stopped_tracee(target_pid));
        assert!(!marker.exists());
        assert_ne!(unsafe { libc::kill(target_pid, 0) }, 0);
    }

    #[cfg(target_os = "linux")]
    fn run_clone_parent_reap_helper() {
        use std::io::Read as _;
        use std::os::fd::FromRawFd as _;

        let guard_pid = unsafe { libc::getpid() };
        let guard_tid = unsafe { libc::syscall(libc::SYS_gettid) as libc::pid_t };
        assert_eq!(
            unsafe { libc::getpgrp() },
            guard_pid,
            "isolated guard helper must own its process group"
        );

        let mut descriptors = [0; 2];
        assert_eq!(
            unsafe { libc::pipe2(descriptors.as_mut_ptr(), libc::O_CLOEXEC) },
            0,
            "create clone-parent receipt pipe: {}",
            std::io::Error::last_os_error()
        );
        let target_pid = unsafe { libc::fork() };
        assert!(
            target_pid >= 0,
            "fork exact contained-target fixture: {}",
            std::io::Error::last_os_error()
        );
        if target_pid == 0 {
            // This child was forked from libtest, which may own runtime locks in
            // other threads. Use only async-signal-safe libc/syscall operations
            // until _exit: the parent guard remains ordinary Rust and exercises
            // the exact production wait loop below.
            unsafe {
                libc::close(descriptors[0]);
                let mut clone_pids = [0 as libc::pid_t; 32];
                for (index, pid_slot) in clone_pids.iter_mut().enumerate() {
                    let exit_signal = if index < 16 { 0 } else { libc::SIGCHLD };
                    let cloned = libc::syscall(
                        libc::SYS_clone,
                        libc::CLONE_PARENT | exit_signal,
                        0,
                        0,
                        0,
                        0,
                    ) as libc::pid_t;
                    if cloned < 0 {
                        libc::_exit(40);
                    }
                    if cloned == 0 {
                        libc::_exit(0);
                    }
                    *pid_slot = cloned;
                }
                let bytes = std::slice::from_raw_parts(
                    clone_pids.as_ptr().cast::<u8>(),
                    std::mem::size_of_val(&clone_pids),
                );
                let mut written = 0usize;
                while written < bytes.len() {
                    let count = libc::write(
                        descriptors[1],
                        bytes[written..].as_ptr().cast::<libc::c_void>(),
                        bytes.len() - written,
                    );
                    if count < 0 {
                        if *libc::__errno_location() == libc::EINTR {
                            continue;
                        }
                        libc::_exit(41);
                    }
                    written += count as usize;
                }
                libc::close(descriptors[1]);
                let requested = libc::timespec {
                    tv_sec: 4,
                    tv_nsec: 0,
                };
                let mut remaining = requested;
                while libc::nanosleep(&remaining, &mut remaining) != 0 {
                    if *libc::__errno_location() != libc::EINTR {
                        libc::_exit(42);
                    }
                }
                libc::_exit(0);
            }
        }

        unsafe {
            libc::close(descriptors[1]);
        }
        let mut pipe = unsafe { std::fs::File::from_raw_fd(descriptors[0]) };
        let watcher = std::thread::spawn(move || {
            let mut clone_pids = [0 as libc::pid_t; 32];
            let bytes = unsafe {
                std::slice::from_raw_parts_mut(
                    clone_pids.as_mut_ptr().cast::<u8>(),
                    std::mem::size_of_val(&clone_pids),
                )
            };
            pipe.read_exact(bytes)
                .expect("target publishes every CLONE_PARENT child pid");

            // libtest runs this function on a worker thread, so the forked
            // target is recorded under that thread's task entry. Production is
            // single-threaded and has guard_tid == guard_pid; selecting the
            // actual forking TID keeps this isolated receipt faithful to the
            // kernel's per-task `children` accounting.
            let children_path =
                std::path::PathBuf::from(format!("/proc/{guard_pid}/task/{guard_tid}/children"));
            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(3);
            loop {
                let children = std::fs::read_to_string(&children_path)
                    .expect("inspect exact guard direct children")
                    .split_whitespace()
                    .map(str::parse::<libc::pid_t>)
                    .collect::<Result<Vec<_>, _>>()
                    .expect("numeric exact guard child list");
                let clones_gone = clone_pids
                    .iter()
                    .all(|pid| !std::path::PathBuf::from(format!("/proc/{pid}")).exists());
                if children == [target_pid] && clones_gone {
                    return;
                }
                assert!(
                    std::time::Instant::now() < deadline,
                    "production __WALL loop retained clone children or zombies while the primary target stayed alive: children={children:?} clone_pids={clone_pids:?}"
                );
                std::thread::sleep(std::time::Duration::from_millis(10));
            }
        });

        let exit = wait_for_contained_target(target_pid)
            .expect("exact production guard wait must reap the complete direct child set");
        assert_eq!(exit, ContainedTargetExit::Code(0));
        watcher
            .join()
            .expect("clone-parent no-zombie watcher completes");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn contained_guard_reaps_clone_parent_children_with_wall() {
        const HELPER_ENV: &str = "TIRITH_TEST_CLONE_PARENT_REAP_HELPER";
        if std::env::var_os(HELPER_ENV).is_some() {
            run_clone_parent_reap_helper();
            return;
        }

        use std::os::unix::process::CommandExt as _;

        let mut command = std::process::Command::new(
            std::env::current_exe().expect("locate current unit-test executable"),
        );
        command
            .args([
                "--exact",
                "cli::capsule_child::tests::contained_guard_reaps_clone_parent_children_with_wall",
                "--test-threads=1",
                "--nocapture",
            ])
            .env(HELPER_ENV, "1")
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped());
        unsafe {
            command.pre_exec(|| {
                if libc::setpgid(0, 0) == 0 {
                    Ok(())
                } else {
                    Err(std::io::Error::last_os_error())
                }
            });
        }
        let output = command
            .output()
            .expect("spawn isolated exact guard-wait receipt");
        assert!(
            output.status.success(),
            "isolated exact guard-wait receipt failed\nstdout:\n{}\nstderr:\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }
}
