#![cfg(unix)]

use std::ffi::OsStr;
use std::os::unix::fs::symlink;
use std::os::unix::fs::PermissionsExt as _;
use std::path::Path;
use std::process::Command;
use std::sync::{Arc, Barrier};
use std::time::Duration;
use std::time::Instant;

#[cfg(not(target_os = "linux"))]
use tirith_core::trusted_child::TrustedExecutableError;
use tirith_core::trusted_child::{
    resolve_system_helper_on_path, run, sanitized_path, CaptureStream, ChildLimits, ChildOutcome,
    ChildSpec, TrustedExecutable,
};

const SIGCHLD_HELPER_MODE: &str = "TIRITH_TRUSTED_CHILD_SIGCHLD_HELPER_MODE";
const SIGCHLD_HELPER_MARKER: &str = "TIRITH_TRUSTED_CHILD_SIGCHLD_HELPER_MARKER";

fn make_executable(path: &Path, body: &str) {
    std::fs::write(path, body).unwrap();
    let mut permissions = std::fs::metadata(path).unwrap().permissions();
    permissions.set_mode(0o700);
    std::fs::set_permissions(path, permissions).unwrap();
}

fn shell() -> TrustedExecutable {
    // Prefer a non-multicall shell when available. On Alpine `/bin/sh`
    // canonicalizes to `/bin/busybox`; invoking that canonical target directly
    // with `-c` loses the `sh` argv[0] applet selection and exits 127, which is a
    // fixture artifact rather than supervisor behavior.
    ["/bin/bash", "/usr/bin/bash", "/bin/sh"]
        .into_iter()
        .find_map(|candidate| {
            let path = Path::new(candidate);
            if path.exists() {
                TrustedExecutable::from_absolute(path, &[]).ok()
            } else {
                None
            }
        })
        .expect("a system shell must be available")
}

#[test]
#[ignore = "subprocess helper for process-wide SIGCHLD contract tests"]
fn sigchld_contract_subprocess_helper() {
    let Ok(mode) = std::env::var(SIGCHLD_HELPER_MODE) else {
        return;
    };
    let marker = std::path::PathBuf::from(
        std::env::var_os(SIGCHLD_HELPER_MARKER).expect("helper marker path"),
    );

    // SAFETY: the subprocess owns its process-wide signal disposition and exits
    // immediately after this one supervision attempt.
    let mut action = unsafe { std::mem::zeroed::<libc::sigaction>() };
    action.sa_sigaction = if mode == "ignored" {
        libc::SIG_IGN
    } else {
        libc::SIG_DFL
    };
    action.sa_flags = if mode == "no-cldwait" {
        libc::SA_NOCLDWAIT
    } else {
        0
    };
    assert_eq!(unsafe { libc::sigemptyset(&mut action.sa_mask) }, 0);
    assert_eq!(
        unsafe { libc::sigaction(libc::SIGCHLD, &action, std::ptr::null_mut()) },
        0,
        "install helper SIGCHLD disposition: {}",
        std::io::Error::last_os_error()
    );

    let args = [
        OsStr::new("-c"),
        OsStr::new("printf spawned > \"$TIRITH_TRUSTED_CHILD_SIGCHLD_HELPER_MARKER\""),
    ];
    let spec = ChildSpec::new(args, ChildLimits::new(Duration::from_secs(1), 64, 64))
        .env(SIGCHLD_HELPER_MARKER, marker.as_os_str());
    let outcome = run(&shell(), &spec);
    let expected: &[&str] = if mode == "ignored" {
        // Darwin normalizes explicit SIG_IGN into an effective
        // SA_NOCLDWAIT disposition when read back through sigaction.
        &["SIGCHLD is ignored", "SA_NOCLDWAIT"]
    } else {
        &["SA_NOCLDWAIT"]
    };
    match outcome {
        ChildOutcome::SpawnError(reason) => assert!(
            expected.iter().any(|needle| reason.contains(needle)),
            "unexpected contract refusal for {mode}: {reason}"
        ),
        other => panic!("unsafe SIGCHLD embedding was not refused for {mode}: {other:?}"),
    }
    assert!(
        !marker.exists(),
        "the supervised command ran despite the invalid SIGCHLD contract"
    );
}

#[test]
fn supervisor_refuses_auto_reaping_sigchld_dispositions_before_spawn() {
    let temp = tempfile::tempdir().expect("tempdir");
    for mode in ["ignored", "no-cldwait"] {
        let marker = temp.path().join(format!("{mode}.marker"));
        let output = Command::new(std::env::current_exe().expect("current test executable"))
            .args([
                "--exact",
                "sigchld_contract_subprocess_helper",
                "--ignored",
                "--nocapture",
            ])
            .env(SIGCHLD_HELPER_MODE, mode)
            .env(SIGCHLD_HELPER_MARKER, &marker)
            .output()
            .expect("launch isolated SIGCHLD helper");
        assert!(
            output.status.success(),
            "SIGCHLD helper failed for {mode}: stdout={} stderr={}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(!marker.exists(), "helper command ran for mode {mode}");
    }
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn process_is_running(pid: libc::pid_t) -> bool {
    (unsafe { libc::kill(pid, 0) }) == 0
        || std::io::Error::last_os_error().raw_os_error() == Some(libc::EPERM)
}

#[cfg(target_os = "macos")]
fn process_is_running(pid: libc::pid_t) -> bool {
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
    read == expected as libc::c_int && unsafe { info.assume_init() }.pbi_status != libc::SZOMB
}

#[cfg(target_os = "linux")]
fn process_is_running(pid: libc::pid_t) -> bool {
    if unsafe { libc::kill(pid, 0) } != 0 {
        return false;
    }
    // kill(pid, 0) also succeeds for a dead orphaned zombie until PID 1
    // reaps it. `/proc/<pid>/stat` field 3 distinguishes that bookkeeping
    // state from a descendant that could still execute.
    let stat = match std::fs::read_to_string(format!("/proc/{pid}/stat")) {
        Ok(stat) => stat,
        Err(_) => return false,
    };
    let Some(after_name) = stat.rsplit_once(") ").map(|(_, rest)| rest) else {
        return true;
    };
    !after_name.starts_with("Z ")
}

fn assert_descendant_stopped(pid_file: &Path, context: &str) {
    let pid: libc::pid_t = std::fs::read_to_string(pid_file)
        .unwrap_or_else(|error| panic!("{context} did not publish a descendant PID: {error}"))
        .trim()
        .parse()
        .expect("descendant PID must be numeric");
    let deadline = Instant::now() + Duration::from_secs(2);
    while process_is_running(pid) && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(20));
    }
    assert!(
        !process_is_running(pid),
        "{context} descendant {pid} survived process-group cleanup"
    );
}

#[test]
fn trusted_lookup_rejects_a_denied_first_path_hit() {
    let temp = tempfile::tempdir().unwrap();
    let denied = temp.path().join("repo-bin");
    let trusted = temp.path().join("installed-bin");
    std::fs::create_dir(&denied).unwrap();
    std::fs::create_dir(&trusted).unwrap();
    make_executable(&denied.join("probe"), "#!/bin/sh\nexit 0\n");
    make_executable(&trusted.join("probe"), "#!/bin/sh\nexit 0\n");
    let path = std::env::join_paths([&denied, &trusted]).unwrap();

    let error = TrustedExecutable::resolve_on_path("probe", &path, &[denied]).unwrap_err();
    assert!(error.to_string().contains("untrusted"));
}

#[test]
fn trusted_lookup_rejects_a_denied_symlink_to_a_system_tool() {
    let temp = tempfile::tempdir().unwrap();
    let denied = temp.path().join("repo-bin");
    std::fs::create_dir(&denied).unwrap();
    symlink("/bin/sh", denied.join("probe")).unwrap();
    let path = std::env::join_paths([&denied]).unwrap();

    let error = TrustedExecutable::resolve_on_path("probe", &path, &[denied]).unwrap_err();
    assert!(error.to_string().contains("untrusted"));
}

#[test]
fn sanitized_path_rejects_a_denied_symlink_to_a_system_directory() {
    let temp = tempfile::tempdir().unwrap();
    let denied = temp.path().join("repo-bin");
    std::fs::create_dir(&denied).unwrap();
    let linked = denied.join("system-tools");
    symlink("/usr/bin", &linked).unwrap();
    let path = std::env::join_paths([&linked]).unwrap();

    assert!(sanitized_path(&path, &[denied]).is_empty());
}

#[test]
fn denied_origin_cannot_be_hidden_with_parent_components() {
    let temp = tempfile::tempdir().unwrap();
    let safe = temp.path().join("safe");
    let denied = temp.path().join("repo-bin");
    std::fs::create_dir(&safe).unwrap();
    std::fs::create_dir(&denied).unwrap();
    make_executable(&denied.join("probe"), "#!/bin/sh\nexit 0\n");
    let traversal = safe.join("..").join("repo-bin");
    let path = std::env::join_paths([&traversal]).unwrap();

    let error = TrustedExecutable::resolve_on_path("probe", &path, std::slice::from_ref(&denied))
        .unwrap_err();
    assert!(error.to_string().contains("untrusted"));
    assert!(sanitized_path(&path, &[denied]).is_empty());
}

#[test]
fn trusted_lookup_preserves_a_legitimate_absolute_tool() {
    let temp = tempfile::tempdir().unwrap();
    let installed = temp.path().join("installed-bin");
    std::fs::create_dir(&installed).unwrap();
    let probe = installed.join("probe");
    make_executable(&probe, "#!/bin/sh\nprintf legitimate\n");
    let path = std::env::join_paths([&installed]).unwrap();

    let executable = TrustedExecutable::resolve_on_path("probe", &path, &[]).unwrap();
    assert_eq!(executable.path(), probe.canonicalize().unwrap());
}

#[test]
fn trusted_lookup_rejects_symlink_entry_inside_denied_root() {
    let temp = tempfile::tempdir().unwrap();
    let denied = temp.path().join("repo-bin");
    std::fs::create_dir(&denied).unwrap();
    std::os::unix::fs::symlink("/bin/sh", denied.join("probe")).unwrap();
    let path = std::env::join_paths([&denied]).unwrap();

    let error = TrustedExecutable::resolve_on_path("probe", &path, &[denied]).unwrap_err();
    assert!(error.to_string().contains("untrusted"), "{error}");
}

#[test]
fn trusted_lookup_rejects_world_writable_directory_hierarchy() {
    let temp = tempfile::tempdir().unwrap();
    let writable = temp.path().join("group-writable-bin");
    std::fs::create_dir(&writable).unwrap();
    std::fs::set_permissions(&writable, std::fs::Permissions::from_mode(0o777)).unwrap();
    let probe = writable.join("probe");
    make_executable(&probe, "#!/bin/sh\nexit 0\n");

    let error = TrustedExecutable::from_absolute(&probe, &[]).unwrap_err();
    assert!(
        error.to_string().contains("untrusted group") || error.to_string().contains("everyone"),
        "{error}"
    );
}

#[test]
fn trusted_lookup_rejects_current_owner_group_writable_directory_hierarchy() {
    let temp = tempfile::tempdir().unwrap();
    let writable = temp.path().join("group-writable-bin");
    std::fs::create_dir(&writable).unwrap();
    std::fs::set_permissions(&writable, std::fs::Permissions::from_mode(0o770)).unwrap();
    let probe = writable.join("probe");
    make_executable(&probe, "#!/bin/sh\nexit 0\n");

    let error = TrustedExecutable::from_absolute(&probe, &[]).unwrap_err();
    assert!(error.to_string().contains("untrusted group"), "{error}");
}

#[cfg(target_vendor = "apple")]
#[test]
fn trusted_lookup_rejects_mutating_macos_acl_outside_mode_bits() {
    let temp = tempfile::tempdir().unwrap();
    let probe = temp.path().join("probe");
    make_executable(&probe, "#!/bin/sh\nexit 0\n");
    let status = std::process::Command::new("/bin/chmod")
        .args(["+a", "everyone allow write"])
        .arg(&probe)
        .status()
        .unwrap();
    assert!(status.success(), "test must install a macOS extended ACL");
    assert_eq!(
        std::fs::metadata(&probe).unwrap().permissions().mode() & 0o022,
        0,
        "the regression must exercise ACL authority invisible to mode bits"
    );

    let error = TrustedExecutable::from_absolute(&probe, &[]).unwrap_err();
    assert!(error.to_string().contains("ACL grants mutation"), "{error}");
}

#[cfg(target_vendor = "apple")]
#[test]
fn trusted_lookup_allows_deny_only_macos_acl() {
    let temp = tempfile::tempdir().unwrap();
    let probe = temp.path().join("probe");
    make_executable(&probe, "#!/bin/sh\nexit 0\n");
    let status = std::process::Command::new("/bin/chmod")
        .args(["+a", "everyone deny delete"])
        .arg(&probe)
        .status()
        .unwrap();
    assert!(status.success(), "test must install a macOS deny-only ACL");

    TrustedExecutable::from_absolute(&probe, &[])
        .expect("a deny-only ACL does not grant hidden mutation authority");
}

#[test]
fn sanitized_child_path_omits_group_writable_directory() {
    let temp = tempfile::tempdir().unwrap();
    let writable = temp.path().join("shared-bin");
    let private = temp.path().join("private-bin");
    std::fs::create_dir(&writable).unwrap();
    std::fs::create_dir(&private).unwrap();
    std::fs::set_permissions(&writable, std::fs::Permissions::from_mode(0o770)).unwrap();
    std::fs::set_permissions(&private, std::fs::Permissions::from_mode(0o700)).unwrap();
    let path = std::env::join_paths([&writable, &private]).unwrap();

    let sanitized = sanitized_path(&path, &[]);
    let entries = std::env::split_paths(&sanitized).collect::<Vec<_>>();
    assert!(!entries.contains(&writable.canonicalize().unwrap()));
    assert!(entries.contains(&private.canonicalize().unwrap()));
}

#[test]
fn supervisor_refuses_executable_identity_drift_before_spawn() {
    let temp = tempfile::tempdir().unwrap();
    let probe = temp.path().join("probe");
    let marker = temp.path().join("executed");
    make_executable(&probe, "#!/bin/sh\nexit 0\n");
    let executable = TrustedExecutable::from_absolute(&probe, &[]).unwrap();

    make_executable(
        &probe,
        &format!("#!/bin/sh\nprintf ran > '{}'\n", marker.display()),
    );
    let spec = ChildSpec::new(
        std::iter::empty::<&str>(),
        ChildLimits::new(Duration::from_secs(2), 64, 64),
    );
    let outcome = run(&executable, &spec);
    assert!(
        matches!(outcome, ChildOutcome::SpawnError(_)),
        "{outcome:?}"
    );
    assert!(!marker.exists(), "changed executable must not run");
}

#[test]
fn trusted_lookup_retains_a_multicall_symlink_separately_from_its_target() {
    let temp = tempfile::tempdir().unwrap();
    let installed = temp.path().join("installed-bin");
    std::fs::create_dir(&installed).unwrap();
    let target = installed.join("rustup");
    make_executable(&target, "#!/bin/sh\nexit 0\n");
    let proxy = installed.join("cargo");
    std::os::unix::fs::symlink(&target, &proxy).unwrap();
    let path = std::env::join_paths([&installed]).unwrap();

    let executable = TrustedExecutable::resolve_on_path("cargo", &path, &[]).unwrap();
    assert_eq!(executable.invocation_path(), proxy);
    assert_eq!(executable.path(), target.canonicalize().unwrap());
    #[cfg(target_os = "linux")]
    {
        let bound = executable.bind_content().unwrap();
        assert_eq!(bound.invocation_path(), proxy);
        assert_eq!(bound.path(), target.canonicalize().unwrap());
    }
}

#[cfg(not(target_os = "linux"))]
#[test]
fn content_binding_fails_closed_on_non_linux_unix() {
    let executable = shell();
    let error = executable.bind_content().unwrap_err();
    assert!(
        matches!(error, TrustedExecutableError::InvalidPath { .. }),
        "unsupported binding must be an InvalidPath error: {error}"
    );
    assert!(error.to_string().contains("unsupported"), "{error}");
}

#[test]
fn trusted_lookup_rejects_a_proxy_link_inside_a_denied_root() {
    let temp = tempfile::tempdir().unwrap();
    let denied = temp.path().join("repo-bin");
    let installed = temp.path().join("installed-bin");
    std::fs::create_dir(&denied).unwrap();
    std::fs::create_dir(&installed).unwrap();
    let target = installed.join("rustup");
    make_executable(&target, "#!/bin/sh\nexit 0\n");
    let proxy = denied.join("cargo");
    std::os::unix::fs::symlink(&target, &proxy).unwrap();
    let path = std::env::join_paths([&denied]).unwrap();

    let error = TrustedExecutable::resolve_on_path("cargo", &path, std::slice::from_ref(&denied))
        .unwrap_err();
    assert!(error.to_string().contains(&proxy.display().to_string()));
    assert!(error.to_string().contains(&denied.display().to_string()));
}

#[test]
fn trusted_lookup_executes_canonical_target_with_caller_spelled_argv0() {
    let temp = tempfile::tempdir().unwrap();
    let installed = temp.path().join("installed-bin");
    std::fs::create_dir(&installed).unwrap();
    let alias = installed.join("sh");
    std::os::unix::fs::symlink("/bin/sh", &alias).unwrap();
    let path = std::env::join_paths([&installed]).unwrap();
    let executable = TrustedExecutable::resolve_on_path("sh", &path, &[]).unwrap();
    let spec = ChildSpec::new(
        [OsStr::new("-c"), OsStr::new("printf '%s' \"$0\"")],
        ChildLimits::new(Duration::from_secs(2), 4096, 4096),
    );

    match run(&executable, &spec) {
        ChildOutcome::Completed {
            status,
            stdout,
            stderr,
        } => {
            assert!(status.success(), "caller-spelled shell failed: {stderr:?}");
            assert_eq!(stdout, alias.to_string_lossy().as_bytes());
        }
        other => panic!("unexpected caller-spelled launch outcome: {other:?}"),
    }
}

#[test]
fn generic_trusted_lookup_preserves_versioned_absolute_paths() {
    let temp = tempfile::tempdir().unwrap();
    let bin = temp
        .path()
        .join("Cellar")
        .join("bash")
        .join("5.3.3")
        .join("bin");
    std::fs::create_dir_all(&bin).unwrap();
    let bash = bin.join("bash");
    make_executable(&bash, "#!/bin/sh\nexit 0\n");
    let path = std::env::join_paths([&bin]).unwrap();

    let selected = TrustedExecutable::resolve_on_path("bash", &path, &[]).unwrap();
    assert_eq!(selected.path(), bash.canonicalize().unwrap());
}

#[test]
fn system_helper_rejects_an_arbitrary_same_uid_path_shadow_without_execution() {
    let home = home::home_dir().expect("test account home");
    let temporary = tempfile::Builder::new()
        .prefix("tirith-system-helper-shadow-")
        .tempdir_in(home)
        .unwrap();
    let shadow_bin = temporary.path().join("shadow-bin");
    std::fs::create_dir(&shadow_bin).unwrap();
    let marker = temporary.path().join("shadow-executed");
    let quoted_marker = marker.display().to_string().replace('\'', "'\"'\"'");
    let shadow = shadow_bin.join("sh");
    make_executable(
        &shadow,
        &format!("#!/bin/sh\nprintf executed > '{quoted_marker}'\n"),
    );
    std::fs::set_permissions(&shadow, std::fs::Permissions::from_mode(0o755)).unwrap();
    let path = std::env::join_paths([shadow_bin.as_path(), Path::new("/bin")]).unwrap();

    let error = resolve_system_helper_on_path("sh", &path).unwrap_err();
    assert!(
        error
            .to_string()
            .contains("untrusted executable provenance"),
        "same-UID 0755 helper outside cwd/temp must fail provenance: {error}"
    );
    assert!(
        !marker.exists(),
        "rejecting a PATH shadow must not execute it"
    );
}

#[test]
fn system_helper_rejects_a_user_symlink_origin_to_a_system_binary() {
    let home = home::home_dir().expect("test account home");
    let temporary = tempfile::Builder::new()
        .prefix("tirith-system-helper-link-")
        .tempdir_in(home)
        .unwrap();
    let shadow_bin = temporary.path().join("shadow-bin");
    std::fs::create_dir(&shadow_bin).unwrap();
    symlink("/bin/sh", shadow_bin.join("sh")).unwrap();
    let path = std::env::join_paths([shadow_bin.as_path(), Path::new("/bin")]).unwrap();

    let error = resolve_system_helper_on_path("sh", &path).unwrap_err();
    assert!(
        error
            .to_string()
            .contains("untrusted executable provenance"),
        "canonical system target must not launder a same-UID selection origin: {error}"
    );
}

#[test]
fn system_helper_rejects_a_same_uid_per_user_nix_profile_without_execution() {
    let home = home::home_dir().expect("test account home");
    let temporary = tempfile::Builder::new()
        .prefix("tirith-system-helper-nix-profile-")
        .tempdir_in(home)
        .unwrap();
    let profile_bin = temporary.path().join(".nix-profile").join("bin");
    std::fs::create_dir_all(&profile_bin).unwrap();
    let marker = temporary.path().join("per-user-nix-helper-executed");
    let quoted_marker = marker.display().to_string().replace('\'', "'\"'\"'");
    let shadow = profile_bin.join("sh");
    make_executable(
        &shadow,
        &format!("#!/bin/sh\nprintf executed > '{quoted_marker}'\n"),
    );
    std::fs::set_permissions(&shadow, std::fs::Permissions::from_mode(0o755)).unwrap();
    let path = std::env::join_paths([profile_bin.as_path(), Path::new("/bin")]).unwrap();

    let error = resolve_system_helper_on_path("sh", &path).unwrap_err();
    assert!(
        error
            .to_string()
            .contains("untrusted executable provenance"),
        "same-UID per-user Nix profiles must fail provenance: {error}"
    );
    assert!(
        !marker.exists(),
        "rejecting a per-user Nix helper must not execute it"
    );
}

#[test]
fn system_helper_preserves_a_root_managed_system_binary() {
    let path = std::env::join_paths([Path::new("/bin"), Path::new("/usr/bin")]).unwrap();
    let shell = resolve_system_helper_on_path("sh", &path)
        .expect("the canonical root-managed system shell must remain available");
    assert!(shell.path().is_absolute());
}

#[test]
fn forced_interpreter_rejects_a_same_uid_cellar_shaped_install() {
    let temp = tempfile::tempdir().unwrap();
    let bin = temp
        .path()
        .join("Cellar")
        .join("bash")
        .join("5.3.3")
        .join("bin");
    std::fs::create_dir_all(&bin).unwrap();
    let bash = bin.join("bash");
    make_executable(&bash, "#!/bin/sh\nexit 0\n");
    let path = std::env::join_paths([&bin]).unwrap();

    let selected = TrustedExecutable::resolve_on_path("bash", &path, &[]).unwrap();
    let error = selected
        .require_forced_interpreter_provenance()
        .unwrap_err();
    assert!(
        error.to_string().contains("root-owned")
            && error.to_string().contains("non-group/world-writable"),
        "same-UID Cellar-shaped installs must not become trusted remote interpreters: {error}"
    );
}

#[test]
fn forced_interpreter_accepts_the_canonical_system_shell() {
    let shell = TrustedExecutable::from_absolute(Path::new("/bin/sh"), &[])
        .unwrap()
        .require_forced_interpreter_provenance()
        .unwrap();
    assert!(shell.path().is_absolute());
}

#[test]
fn delayed_reinvocation_rejects_a_replaceable_user_owned_path() {
    let temp = tempfile::tempdir().unwrap();
    let candidate = temp.path().join("tirith");
    make_executable(&candidate, "#!/bin/sh\nexit 0\n");

    let error = TrustedExecutable::from_absolute(&candidate, &[])
        .unwrap()
        .require_safe_reinvocation_provenance()
        .unwrap_err();
    assert!(
        error
            .to_string()
            .contains("delayed safe-command reinvocation")
            && error.to_string().contains("root-owned"),
        "a same-UID path could be replaced after suggestion generation: {error}"
    );
}

#[test]
fn delayed_reinvocation_accepts_a_root_managed_system_path() {
    let candidate = TrustedExecutable::from_absolute(Path::new("/bin/sh"), &[])
        .unwrap()
        .require_safe_reinvocation_provenance()
        .unwrap();
    assert!(candidate.path().is_absolute());
}

#[test]
fn trusted_lookup_rejects_missing_and_world_writable_tools() {
    let temp = tempfile::tempdir().unwrap();
    let installed = temp.path().join("installed-bin");
    std::fs::create_dir(&installed).unwrap();
    let path = std::env::join_paths([&installed]).unwrap();
    assert!(TrustedExecutable::resolve_on_path("missing", &path, &[])
        .unwrap_err()
        .to_string()
        .contains("not found"));

    let executable = installed.join("world-writable");
    make_executable(&executable, "#!/bin/sh\nexit 0\n");
    std::fs::set_permissions(&executable, std::fs::Permissions::from_mode(0o707)).unwrap();
    let error = TrustedExecutable::from_absolute(&executable, &[]).unwrap_err();
    assert!(
        error.to_string().contains("writable by an untrusted group")
            || error.to_string().contains("by everyone"),
        "{error}"
    );
}

#[test]
fn resolved_path_symlink_swap_cannot_change_launched_identity() {
    use std::os::unix::fs::symlink;

    let temp = tempfile::tempdir().unwrap();
    let bin = temp.path().join("bin");
    std::fs::create_dir(&bin).unwrap();
    let original = temp.path().join("original");
    let replacement = temp.path().join("replacement");
    make_executable(&original, "#!/bin/sh\nprintf original\n");
    make_executable(&replacement, "#!/bin/sh\nprintf replacement\n");
    let selected_name = bin.join("probe");
    symlink(&original, &selected_name).unwrap();
    let path = std::env::join_paths([&bin]).unwrap();

    let selected = TrustedExecutable::resolve_on_path("probe", &path, &[]).unwrap();
    assert_eq!(selected.path(), original.canonicalize().unwrap());
    std::fs::remove_file(&selected_name).unwrap();
    symlink(&replacement, &selected_name).unwrap();

    let spec = ChildSpec::new(
        std::iter::empty::<&OsStr>(),
        ChildLimits::new(Duration::from_secs(2), 64, 64),
    );
    match run(&selected, &spec) {
        ChildOutcome::Completed { stdout, .. } => assert_eq!(stdout, b"original"),
        other => panic!("unexpected outcome: {other:?}"),
    }
}

#[test]
fn replacing_the_canonical_target_is_detected_before_spawn() {
    use std::os::unix::fs::MetadataExt as _;

    let temp = tempfile::tempdir().unwrap();
    let executable = temp.path().join("probe");
    make_executable(&executable, "#!/bin/sh\nprintf original\n");
    let selected = TrustedExecutable::from_absolute(&executable, &[]).unwrap();
    let original_inode = std::fs::metadata(&executable).unwrap().ino();

    // Allocate the replacement while the original inode is still live, then
    // atomically rename it over the canonical path. Remove-and-recreate can
    // legitimately reuse the just-freed inode and would not exercise identity
    // replacement at all.
    let replacement = temp.path().join("replacement");
    make_executable(&replacement, "#!/bin/sh\nprintf replacement\n");
    assert_ne!(
        std::fs::metadata(&replacement).unwrap().ino(),
        original_inode
    );
    std::fs::rename(&replacement, &executable).unwrap();

    let spec = ChildSpec::new(
        std::iter::empty::<&OsStr>(),
        ChildLimits::new(Duration::from_secs(2), 64, 64),
    );
    match run(&selected, &spec) {
        ChildOutcome::SpawnError(reason) => assert!(reason.contains("identity changed")),
        other => panic!("replacement must be refused before spawn: {other:?}"),
    }
}

#[cfg(target_os = "linux")]
#[test]
fn content_binding_survives_same_inode_source_mutation() {
    use std::os::unix::fs::MetadataExt as _;

    let temp = tempfile::tempdir().unwrap();
    let executable = temp.path().join("probe");
    make_executable(&executable, "#!/bin/sh\nprintf original\n");
    let selected = TrustedExecutable::from_absolute(&executable, &[])
        .unwrap()
        .bind_content()
        .unwrap();
    let inode = std::fs::metadata(&executable).unwrap().ino();

    // Truncating and rewriting preserves the source inode, defeating a pure
    // dev/inode re-stat. A content-bound launch must still execute the bytes that
    // were fixed before the mutation.
    make_executable(&executable, "#!/bin/sh\nprintf replacement\n");
    assert_eq!(std::fs::metadata(&executable).unwrap().ino(), inode);

    let spec = ChildSpec::new(
        std::iter::empty::<&OsStr>(),
        ChildLimits::new(Duration::from_secs(2), 64, 64),
    );
    match run(&selected, &spec) {
        ChildOutcome::Completed { stdout, .. } => assert_eq!(stdout, b"original"),
        other => panic!("content-bound source mutation changed the launch: {other:?}"),
    }
}

#[cfg(target_os = "linux")]
#[test]
fn content_binding_survives_canonical_path_replacement() {
    let temp = tempfile::tempdir().unwrap();
    let executable = temp.path().join("probe");
    make_executable(&executable, "#!/bin/sh\nprintf original\n");
    let selected = TrustedExecutable::from_absolute(&executable, &[])
        .unwrap()
        .bind_content()
        .unwrap();
    assert_ne!(selected.launch_path(), selected.path());

    std::fs::remove_file(&executable).unwrap();
    make_executable(&executable, "#!/bin/sh\nprintf replacement\n");

    let spec = ChildSpec::new(
        std::iter::empty::<&OsStr>(),
        ChildLimits::new(Duration::from_secs(2), 64, 64),
    );
    match run(&selected, &spec) {
        ChildOutcome::Completed { stdout, .. } => assert_eq!(stdout, b"original"),
        other => panic!("content-bound path replacement changed the launch: {other:?}"),
    }
}

#[cfg(target_os = "linux")]
#[test]
fn content_binding_detects_snapshot_tampering_before_spawn() {
    let temp = tempfile::tempdir().unwrap();
    let executable = temp.path().join("probe");
    make_executable(&executable, "#!/bin/sh\nprintf original\n");
    let selected = TrustedExecutable::from_absolute(&executable, &[])
        .unwrap()
        .bind_content()
        .unwrap();

    std::fs::set_permissions(
        selected.launch_path(),
        std::fs::Permissions::from_mode(0o700),
    )
    .unwrap();
    std::fs::write(selected.launch_path(), "#!/bin/sh\nprintf replacement\n").unwrap();

    let spec = ChildSpec::new(
        std::iter::empty::<&OsStr>(),
        ChildLimits::new(Duration::from_secs(2), 64, 64),
    );
    match run(&selected, &spec) {
        ChildOutcome::SpawnError(reason) => assert!(
            reason.contains("identity changed") || reason.contains("content changed"),
            "{reason}"
        ),
        other => panic!("tampered bound snapshot must be refused before spawn: {other:?}"),
    }
}

#[cfg(target_os = "linux")]
#[test]
fn content_binding_holds_a_fully_sealed_executable_descriptor() {
    let temp = tempfile::tempdir().unwrap();
    let executable = temp.path().join("probe");
    make_executable(&executable, "#!/bin/sh\nprintf original\n");
    let selected = TrustedExecutable::from_absolute(&executable, &[])
        .unwrap()
        .bind_content()
        .unwrap();
    let fd = selected
        .bound_launch_fd()
        .expect("Linux binding must own a sealed descriptor");
    let required = libc::F_SEAL_SEAL | libc::F_SEAL_SHRINK | libc::F_SEAL_GROW | libc::F_SEAL_WRITE;
    let seals = unsafe { libc::fcntl(fd, libc::F_GET_SEALS) };
    assert_eq!(seals & required, required);

    let hostile = b"x";
    assert_eq!(
        unsafe { libc::pwrite(fd, hostile.as_ptr().cast(), hostile.len(), 0) },
        -1,
        "same-UID writes through the held descriptor must be permanently denied"
    );
    assert_eq!(
        std::io::Error::last_os_error().raw_os_error(),
        Some(libc::EPERM)
    );
}

#[cfg(target_os = "linux")]
#[test]
fn cloned_content_binding_revalidates_and_launches_in_parallel() {
    const WORKERS: usize = 12;
    const ROUNDS: usize = 8;

    let temp = tempfile::tempdir().unwrap();
    let executable = temp.path().join("probe");
    make_executable(&executable, "#!/bin/sh\nprintf original\n");
    let selected = TrustedExecutable::from_absolute(&executable, &[])
        .unwrap()
        .bind_content()
        .unwrap();
    let barrier = Arc::new(Barrier::new(WORKERS));
    let mut workers = Vec::with_capacity(WORKERS);

    for _ in 0..WORKERS {
        let barrier = Arc::clone(&barrier);
        let selected = selected.clone();
        workers.push(std::thread::spawn(move || {
            barrier.wait();
            for _ in 0..ROUNDS {
                let spec = ChildSpec::new(
                    std::iter::empty::<&OsStr>(),
                    ChildLimits::new(Duration::from_secs(3), 64, 64),
                );
                match run(&selected, &spec) {
                    ChildOutcome::Completed { status, stdout, .. } => {
                        assert!(status.success(), "parallel bound launch failed: {status}");
                        assert_eq!(stdout, b"original");
                    }
                    other => panic!("parallel bound launch failed: {other:?}"),
                }
            }
        }));
    }

    for worker in workers {
        worker
            .join()
            .expect("parallel bound-launch worker panicked");
    }
}

#[test]
fn supervisor_preserves_short_legitimate_output_and_status() {
    let args = [OsStr::new("-c"), OsStr::new("printf legitimate")];
    let spec = ChildSpec::new(args, ChildLimits::new(Duration::from_secs(2), 64, 64));

    match run(&shell(), &spec) {
        ChildOutcome::Completed {
            status,
            stdout,
            stderr,
        } => {
            assert!(status.success());
            assert_eq!(stdout, b"legitimate");
            assert!(stderr.is_empty());
        }
        other => panic!("unexpected outcome: {other:?}"),
    }
}

#[test]
fn supervisor_enforces_the_capture_cap_before_retaining_excess() {
    let args = [OsStr::new("-c"), OsStr::new("printf 12345")];
    let spec = ChildSpec::new(args, ChildLimits::new(Duration::from_secs(2), 4, 64));

    assert!(matches!(
        run(&shell(), &spec),
        ChildOutcome::OutputLimitExceeded {
            stream: CaptureStream::Stdout,
            ..
        }
    ));
}

#[test]
fn supervisor_success_is_not_defeated_by_a_descendant_holding_output_pipes() {
    let temp = tempfile::tempdir().unwrap();
    let pid_file = temp.path().join("grandchild.pid");
    let body = format!(
        "/bin/sleep 30 & printf '%s' $! > '{}'; exit 0",
        pid_file.display()
    );
    let args = [OsStr::new("-c"), OsStr::new(&body)];
    let spec = ChildSpec::new(args, ChildLimits::new(Duration::from_secs(3), 64, 64));

    let started = Instant::now();
    let outcome = run(&shell(), &spec);
    assert!(
        started.elapsed() < Duration::from_secs(5),
        "successful direct exit waited for descendant-held pipe EOF"
    );
    match outcome {
        ChildOutcome::Completed { status, .. } => assert!(status.success()),
        other => panic!("immediate direct success was not preserved: {other:?}"),
    }
    assert_descendant_stopped(&pid_file, "successful direct exit");
}

#[test]
fn supervisor_timeout_kills_a_descendant_holding_output_pipes() {
    let temp = tempfile::tempdir().unwrap();
    let pid_file = temp.path().join("grandchild.pid");
    let body = format!(
        "/bin/sleep 30 & printf '%s' $! > '{}'; wait",
        pid_file.display()
    );
    let args = [OsStr::new("-c"), OsStr::new(&body)];
    let spec = ChildSpec::new(args, ChildLimits::new(Duration::from_secs(2), 64, 64));

    let started = Instant::now();
    let outcome = run(&shell(), &spec);
    assert!(
        started.elapsed() < Duration::from_secs(6),
        "timeout plus process-tree and reader cleanup exceeded its hard bound"
    );
    assert!(matches!(
        outcome,
        ChildOutcome::Timeout {
            cleanup_succeeded: true
        }
    ));
    assert_descendant_stopped(&pid_file, "timeout");
}

#[test]
fn supervisor_output_cap_kills_a_descendant_holding_output_pipes() {
    let temp = tempfile::tempdir().unwrap();
    let pid_file = temp.path().join("grandchild.pid");
    let body = format!(
        "/bin/sleep 30 & printf '%s' $! > '{}'; printf 12345; exit 0",
        pid_file.display()
    );
    let args = [OsStr::new("-c"), OsStr::new(&body)];
    let spec = ChildSpec::new(args, ChildLimits::new(Duration::from_secs(3), 4, 64));

    let started = Instant::now();
    let outcome = run(&shell(), &spec);
    assert!(
        started.elapsed() < Duration::from_secs(5),
        "output-cap cleanup waited for descendant-held pipe EOF"
    );
    assert!(matches!(
        outcome,
        ChildOutcome::OutputLimitExceeded {
            stream: CaptureStream::Stdout,
            cleanup_succeeded: true
        }
    ));
    assert_descendant_stopped(&pid_file, "output cap");
}

#[test]
fn supervisor_cleans_up_a_descendant_after_the_parent_completed() {
    let temp = tempfile::tempdir().unwrap();
    let pid_file = temp.path().join("detached-grandchild.pid");
    let body = format!(
        "sleep 30 </dev/null >/dev/null 2>&1 & printf '%s' $! > '{}'",
        pid_file.display()
    );
    let args = [OsStr::new("-c"), OsStr::new(&body)];
    let spec = ChildSpec::new(args, ChildLimits::new(Duration::from_secs(3), 64, 64));

    let outcome = run(&shell(), &spec);
    assert!(
        matches!(outcome, ChildOutcome::Completed { .. }),
        "{outcome:?}"
    );

    let pid: libc::pid_t = std::fs::read_to_string(pid_file)
        .unwrap()
        .trim()
        .parse()
        .unwrap();
    let mut alive = true;
    for _ in 0..100 {
        alive = process_is_running(pid);
        if !alive {
            break;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    assert!(
        !alive,
        "a descendant that closed stdio must not survive successful completion"
    );
}

#[test]
fn parallel_supervisors_do_not_signal_unrelated_process_groups() {
    exercise_parallel_supervisor_matrix(12, 8, Duration::from_millis(100));
}

#[test]
#[ignore = "manual process-group race stress; run explicitly on Unix CI hosts"]
fn stress_short_lived_parallel_supervisors() {
    exercise_parallel_supervisor_matrix(24, 200, Duration::from_millis(25));
}

fn exercise_parallel_supervisor_matrix(worker_count: usize, rounds: usize, timeout: Duration) {
    let barrier = Arc::new(Barrier::new(worker_count));
    let mut workers = Vec::with_capacity(worker_count);

    for index in 0..worker_count {
        let barrier = Arc::clone(&barrier);
        workers.push(std::thread::spawn(move || {
            barrier.wait();
            for round in 0..rounds {
                match index % 3 {
                    0 => {
                        let expected = format!("worker-{index}-round-{round}");
                        let command = format!("printf {expected}");
                        let args = [OsStr::new("-c"), OsStr::new(&command)];
                        let spec =
                            ChildSpec::new(args, ChildLimits::new(Duration::from_secs(3), 64, 64));
                        match run(&shell(), &spec) {
                            ChildOutcome::Completed {
                                status,
                                stdout,
                                stderr,
                            } => {
                                assert!(
                                    status.success(),
                                    "worker {index} round {round} was signalled: {status}"
                                );
                                assert_eq!(stdout, expected.as_bytes());
                                assert!(stderr.is_empty());
                            }
                            other => panic!(
                                "worker {index} round {round} had unexpected outcome: {other:?}"
                            ),
                        }
                    }
                    1 => {
                        let args = [OsStr::new("-c"), OsStr::new("printf 12345")];
                        let spec =
                            ChildSpec::new(args, ChildLimits::new(Duration::from_secs(3), 4, 64));
                        let outcome = run(&shell(), &spec);
                        assert!(
                            matches!(
                                &outcome,
                                ChildOutcome::OutputLimitExceeded {
                                    stream: CaptureStream::Stdout,
                                    cleanup_succeeded: true,
                                }
                            ),
                            "worker {index} round {round} output-cap outcome: {outcome:?}"
                        );
                    }
                    _ => {
                        let args = [OsStr::new("-c"), OsStr::new("sleep 5")];
                        let spec = ChildSpec::new(args, ChildLimits::new(timeout, 64, 64));
                        let outcome = run(&shell(), &spec);
                        assert!(
                            matches!(
                                &outcome,
                                ChildOutcome::Timeout {
                                    cleanup_succeeded: true,
                                }
                            ),
                            "worker {index} round {round} timeout outcome: {outcome:?}"
                        );
                    }
                }
            }
        }));
    }

    for worker in workers {
        worker.join().expect("parallel supervisor worker panicked");
    }
}
