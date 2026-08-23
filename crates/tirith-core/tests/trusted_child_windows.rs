#![cfg(windows)]

use std::time::{Duration, Instant};

use tirith_core::trusted_child::{
    run, sanitized_path, ChildLimits, ChildOutcome, ChildSpec, TrustedExecutable,
    TrustedExecutableError,
};
use windows_sys::Win32::Foundation::{CloseHandle, WAIT_OBJECT_0};
use windows_sys::Win32::System::Threading::{
    OpenProcess, WaitForSingleObject, PROCESS_SYNCHRONIZE,
};

const HELPER_MODE: &str = "TIRITH_TRUSTED_CHILD_WINDOWS_HELPER";
const HELPER_PID_FILE: &str = "TIRITH_TRUSTED_CHILD_WINDOWS_PID_FILE";

#[test]
fn windows_helper_prints_short_output() {
    if std::env::var(HELPER_MODE).ok().as_deref() != Some("short") {
        return;
    }
    print!("trusted-child-ok");
}

#[test]
fn windows_helper_floods_stdout() {
    if std::env::var(HELPER_MODE).ok().as_deref() != Some("flood") {
        return;
    }
    print!("{}", "x".repeat(8192));
}

#[test]
fn windows_helper_grandchild_holds_inherited_pipes() {
    if std::env::var(HELPER_MODE).ok().as_deref() != Some("grandchild") {
        return;
    }
    let pid_file = std::env::var_os(HELPER_PID_FILE).expect("pid file");
    std::fs::write(pid_file, std::process::id().to_string()).unwrap();
    std::thread::sleep(Duration::from_secs(30));
}

#[test]
fn windows_helper_parent_exits_with_a_live_grandchild() {
    let mode = std::env::var(HELPER_MODE).ok();
    if !matches!(mode.as_deref(), Some("parent" | "timeout-parent")) {
        return;
    }
    let executable = std::env::current_exe().unwrap();
    let mut child = std::process::Command::new(executable)
        .args([
            "--exact",
            "windows_helper_grandchild_holds_inherited_pipes",
            "--nocapture",
        ])
        .env(HELPER_MODE, "grandchild")
        .spawn()
        .unwrap();
    let pid_file = std::path::PathBuf::from(std::env::var_os(HELPER_PID_FILE).unwrap());
    for _ in 0..200 {
        if pid_file.exists() {
            break;
        }
        if child.try_wait().unwrap().is_some() {
            panic!("grandchild exited before publishing its pid");
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    assert!(pid_file.exists(), "grandchild did not publish its pid");
    if mode.as_deref() == Some("timeout-parent") {
        // Keep both the direct child and its descendant alive with inherited
        // output handles. The supervisor must hit its wall deadline, terminate
        // the complete Job, and return without waiting for either pipe holder.
        std::thread::sleep(Duration::from_secs(30));
    }
    // Dropping Child closes only this helper's process handle. The grandchild
    // deliberately remains live with inherited stdout/stderr handles.
}

/// Refusals that describe the hosted runner's own checkout, not the code under
/// test. Both have been observed on GitHub Windows runners: the build directory
/// is owned outside the trusted set, and on the `D:` work volume its ACLs also
/// grant broad write access. Either way the resolver is right to refuse, and
/// the supervisor cases below need a binding to have anything to assert.
///
/// Deliberately an exact list rather than "any InvalidPath": a refusal for any
/// other reason is a real finding and must still fail loudly.
const RUNNER_CHECKOUT_REFUSALS: &[&str] = &["untrusted owner", "grants broad write access"];

fn trusted_current_exe() -> Option<TrustedExecutable> {
    match TrustedExecutable::current() {
        Ok(executable) => Some(executable),
        Err(error @ TrustedExecutableError::InvalidPath { .. })
            if RUNNER_CHECKOUT_REFUSALS
                .iter()
                .any(|reason| error.to_string().contains(reason)) =>
        {
            eprintln!("skipping: {error}");
            None
        }
        Err(other) => panic!("unexpected trusted-executable error: {other}"),
    }
}

fn helper_spec(args: &[&str], limits: ChildLimits) -> ChildSpec {
    ChildSpec::new(args, limits).inherit_env(&[
        "SystemRoot",
        "WINDIR",
        "TEMP",
        "TMP",
        "USERPROFILE",
    ])
}

#[test]
fn windows_validation_rejects_batch_launchers_without_shell_fallback() {
    let directory = tempfile::tempdir().unwrap();
    let script = directory.path().join("shadow.cmd");
    std::fs::write(&script, "@exit /b 0\r\n").unwrap();
    let error = TrustedExecutable::from_absolute(&script, &[]).unwrap_err();
    assert!(error.to_string().contains("native .exe/.com"));
}

#[test]
fn windows_content_binding_fails_closed() {
    let Some(executable) = trusted_current_exe() else {
        return;
    };
    let error = executable.bind_content().unwrap_err();
    assert!(
        matches!(error, TrustedExecutableError::InvalidPath { .. }),
        "unsupported binding must be an InvalidPath error: {error}"
    );
    assert!(error.to_string().contains("unsupported"), "{error}");
}

#[test]
fn windows_executable_extension_check_is_case_insensitive() {
    let directory = tempfile::tempdir().unwrap();
    let executable = directory.path().join("CONTROL.EXE");
    std::fs::write(&executable, b"not executed").unwrap();
    assert!(tirith_core::path_audit::is_executable_file(&executable));
}

#[test]
fn windows_sanitized_path_keeps_protected_system_dir_and_drops_denied_temp() {
    let directory = tempfile::tempdir().unwrap();
    let system32 = std::path::PathBuf::from(std::env::var_os("SystemRoot").unwrap())
        .join("System32")
        .canonicalize()
        .unwrap();
    let source = std::env::join_paths([directory.path(), &system32]).unwrap();
    let sanitized = sanitized_path(&source, &[directory.path().to_path_buf()]);
    let entries = std::env::split_paths(&sanitized).collect::<Vec<_>>();
    assert_eq!(entries, vec![system32]);
}

#[test]
fn windows_denied_origin_check_is_case_insensitive() {
    let directory = tempfile::tempdir().unwrap();
    let denied = directory.path().join("repo-bin");
    std::fs::create_dir(&denied).unwrap();
    std::fs::write(denied.join("probe.EXE"), b"not executed").unwrap();
    let differently_cased_root = denied.with_file_name("REPO-BIN");
    let path = std::env::join_paths([&denied]).unwrap();

    let error =
        TrustedExecutable::resolve_on_path("probe", &path, &[differently_cased_root]).unwrap_err();
    assert!(error.to_string().contains("untrusted"));
}

#[test]
fn windows_supervisor_preserves_short_output_and_status() {
    let Some(executable) = trusted_current_exe() else {
        return;
    };
    let spec = helper_spec(
        &[
            "--exact",
            "windows_helper_prints_short_output",
            "--nocapture",
        ],
        ChildLimits::new(Duration::from_secs(5), 4096, 4096),
    )
    .env(HELPER_MODE, "short");
    match run(&executable, &spec) {
        ChildOutcome::Completed {
            status,
            stdout,
            stderr,
        } => {
            assert!(status.success());
            assert!(String::from_utf8_lossy(&stdout).contains("trusted-child-ok"));
            assert!(stderr.is_empty());
        }
        other => panic!("unexpected outcome: {other:?}"),
    }
}

#[test]
fn windows_supervisor_enforces_output_cap_and_cleans_up_job() {
    let Some(executable) = trusted_current_exe() else {
        return;
    };
    let spec = helper_spec(
        &["--exact", "windows_helper_floods_stdout", "--nocapture"],
        ChildLimits::new(Duration::from_secs(5), 128, 4096),
    )
    .env(HELPER_MODE, "flood");
    assert!(matches!(
        run(&executable, &spec),
        ChildOutcome::OutputLimitExceeded {
            cleanup_succeeded: true,
            ..
        }
    ));
}

#[test]
fn windows_supervisor_rejects_an_explicit_working_directory() {
    let Some(executable) = trusted_current_exe() else {
        return;
    };
    let directory = tempfile::tempdir().unwrap();
    let spec = helper_spec(
        &[
            "--exact",
            "windows_helper_prints_short_output",
            "--nocapture",
        ],
        ChildLimits::new(Duration::from_secs(5), 4096, 4096),
    )
    .env(HELPER_MODE, "short")
    .cwd(directory.path());

    match run(&executable, &spec) {
        ChildOutcome::SpawnError(reason) => {
            assert!(reason.contains("explicit Windows child cwd is disabled"));
        }
        other => panic!("unexpected outcome: {other:?}"),
    }
}

#[test]
fn windows_supervisor_preserves_success_while_killing_descendants_holding_pipes() {
    let Some(executable) = trusted_current_exe() else {
        return;
    };
    let directory = tempfile::tempdir().unwrap();
    let pid_file = directory.path().join("grandchild.pid");
    let spec = helper_spec(
        &[
            "--exact",
            "windows_helper_parent_exits_with_a_live_grandchild",
            "--nocapture",
        ],
        ChildLimits::new(Duration::from_millis(750), 4096, 4096),
    )
    .env(HELPER_MODE, "parent")
    .env(HELPER_PID_FILE, pid_file.as_os_str());

    let started = Instant::now();
    let outcome = run(&executable, &spec);
    assert!(started.elapsed() < Duration::from_secs(4));
    match outcome {
        ChildOutcome::Completed { status, .. } => assert!(status.success()),
        other => panic!("direct-child success was not preserved: {other:?}"),
    }

    let pid = std::fs::read_to_string(pid_file)
        .unwrap()
        .trim()
        .parse::<u32>()
        .unwrap();
    // SAFETY: OpenProcess only obtains a synchronization handle for the PID.
    let process = unsafe { OpenProcess(PROCESS_SYNCHRONIZE, 0, pid) };
    if !process.is_null() {
        // Job termination must make the descendant signaled within the bounded wait.
        let wait = unsafe { WaitForSingleObject(process, 2000) };
        unsafe {
            let _ = CloseHandle(process);
        }
        assert_eq!(wait, WAIT_OBJECT_0, "descendant survived Job termination");
    }
}

#[test]
fn windows_supervisor_timeout_kills_descendants_holding_pipes() {
    let Some(executable) = trusted_current_exe() else {
        return;
    };
    let directory = tempfile::tempdir().unwrap();
    let pid_file = directory.path().join("timeout-grandchild.pid");
    let spec = helper_spec(
        &[
            "--exact",
            "windows_helper_parent_exits_with_a_live_grandchild",
            "--nocapture",
        ],
        ChildLimits::new(Duration::from_millis(750), 4096, 4096),
    )
    .env(HELPER_MODE, "timeout-parent")
    .env(HELPER_PID_FILE, pid_file.as_os_str());

    let started = Instant::now();
    let outcome = run(&executable, &spec);
    assert!(
        started.elapsed() < Duration::from_secs(4),
        "timeout cleanup waited for inherited pipes"
    );
    assert!(matches!(
        outcome,
        ChildOutcome::Timeout {
            cleanup_succeeded: true
        }
    ));

    let pid = std::fs::read_to_string(pid_file)
        .unwrap()
        .trim()
        .parse::<u32>()
        .unwrap();
    // SAFETY: OpenProcess only obtains a synchronization handle for the PID.
    let process = unsafe { OpenProcess(PROCESS_SYNCHRONIZE, 0, pid) };
    if !process.is_null() {
        let wait = unsafe { WaitForSingleObject(process, 2000) };
        unsafe {
            let _ = CloseHandle(process);
        }
        assert_eq!(wait, WAIT_OBJECT_0, "descendant survived timeout cleanup");
    }
}
