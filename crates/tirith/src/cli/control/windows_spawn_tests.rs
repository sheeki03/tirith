use super::*;
use std::ffi::OsString;
use std::io::{Read, Write};
use std::os::windows::ffi::OsStringExt;
use std::path::PathBuf;
use windows::core::BOOL;
use windows::Win32::Foundation::{
    GetHandleInformation, SetHandleInformation, ERROR_BROKEN_PIPE, HANDLE_FLAGS,
    HANDLE_FLAG_INHERIT,
};
use windows::Win32::System::JobObjects::{
    IsProcessInJob, JobObjectBasicProcessIdList, QueryInformationJobObject,
};
use windows::Win32::System::Pipes::{CreatePipe, PeekNamedPipe};
use windows::Win32::System::Threading::{
    CreateEventW, GetCurrentProcess, GetProcessId, OpenEventW, SetEvent, TerminateProcess,
    EVENT_MODIFY_STATE, SYNCHRONIZATION_SYNCHRONIZE,
};

const PROBE: &str = "cli::control::lifecycle::windows_spawn::tests::native_service_spawn_probe";
const MODE: &str = "TIRITH_TEST_DASHBOARD_SPAWN_MODE";
const PREFIX: &str = "TIRITH_TEST_DASHBOARD_SPAWN_EVENT_PREFIX";
const DIRECTORY: &str = "TIRITH_TEST_DASHBOARD_SPAWN_CWD";
const SENTINEL: &str = "TIRITH_TEST_DASHBOARD_SPAWN_SENTINEL";

fn event_name(prefix: &str, suffix: &str) -> Vec<u16> {
    wide_nul(OsStr::new(&format!(
        "Local\\TirithDashboardSpawn-{prefix}-{suffix}"
    )))
    .unwrap()
}

fn event(prefix: &str, suffix: &str) -> OwnedHandle {
    let name = event_name(prefix, suffix);
    OwnedHandle(unsafe { CreateEventW(None, true, false, PCWSTR(name.as_ptr())) }.unwrap())
}

/// Own the actual returned process handle before any readiness/assertion can
/// fail. The fixture creates no descendants, has its own 15-second wait bound,
/// and never terminates a process found by PID. Drop also handles panic paths.
struct FixtureChild(ServiceChild);

impl Drop for FixtureChild {
    fn drop(&mut self) {
        if unsafe { WaitForSingleObject(self.0.process.0, 0) } != WAIT_OBJECT_0 {
            unsafe {
                let _ = TerminateProcess(self.0.process.0, 87);
                let _ = WaitForSingleObject(self.0.process.0, 5000);
            }
        }
    }
}

fn fixture_child(cwd: &Path) -> FixtureChild {
    FixtureChild(
        spawn_arguments(
            &std::env::current_exe().unwrap(),
            cwd,
            &[
                OsStr::new("--ignored"),
                OsStr::new("--exact"),
                OsStr::new(PROBE),
                OsStr::new("--test-threads=1"),
            ],
        )
        .unwrap(),
    )
}

#[test]
#[ignore = "inert child fixture; invoked only by the owned spawn tests"]
fn native_service_spawn_probe() {
    // A normal --ignored run must not consume another parallel test's context.
    let args: Vec<_> = std::env::args().collect();
    if !args
        .windows(2)
        .any(|pair| pair[0] == "--exact" && pair[1] == PROBE)
    {
        return;
    }
    let mode = std::env::var(MODE).unwrap();
    if mode == "exit259" {
        std::process::exit(259);
    }
    assert_eq!(mode, "hold");
    assert_eq!(
        std::env::current_dir().unwrap(),
        PathBuf::from(std::env::var_os(DIRECTORY).unwrap())
    );
    let mut byte = [0];
    assert_eq!(std::io::stdin().read(&mut byte).unwrap(), 0);
    std::io::stdout()
        .write_all(b"discarded fixture stdout\n")
        .unwrap();
    std::io::stdout().flush().unwrap();
    std::io::stderr()
        .write_all(b"discarded fixture stderr\n")
        .unwrap();
    std::io::stderr().flush().unwrap();

    // The value is only an inert parent's event candidate, never process
    // authority. The authoritative assertion is the parent's event state:
    // success/failure on a reused child handle value cannot manufacture a pass.
    let sentinel = std::env::var(SENTINEL).unwrap().parse::<usize>().unwrap();
    unsafe {
        let _ = SetEvent(HANDLE(sentinel as *mut std::ffi::c_void));
    }
    let prefix = std::env::var(PREFIX).unwrap();
    let ready_name = event_name(&prefix, "ready");
    let release_name = event_name(&prefix, "release");
    let ready = OwnedHandle(
        unsafe { OpenEventW(EVENT_MODIFY_STATE, false, PCWSTR(ready_name.as_ptr())) }.unwrap(),
    );
    let release = OwnedHandle(
        unsafe {
            OpenEventW(
                SYNCHRONIZATION_SYNCHRONIZE,
                false,
                PCWSTR(release_name.as_ptr()),
            )
        }
        .unwrap(),
    );
    unsafe { SetEvent(ready.0) }.unwrap();
    assert_eq!(
        unsafe { WaitForSingleObject(release.0, 15000) },
        WAIT_OBJECT_0
    );
}

#[test]
fn native_service_spawn_excludes_capture_writer_and_unrelated_event() {
    let mut state = tirith_test_support::GlobalStateGuard::new().unwrap();
    let cwd = state.roots().cwd.join("service space \u{03bb}");
    std::fs::create_dir(&cwd).unwrap();
    let prefix = uuid::Uuid::new_v4().to_string();
    let ready = event(&prefix, "ready");
    let release = event(&prefix, "release");
    let sentinel = event(&prefix, "sentinel");
    unsafe { SetHandleInformation(sentinel.0, HANDLE_FLAG_INHERIT.0, HANDLE_FLAG_INHERIT) }
        .unwrap();
    let security = SECURITY_ATTRIBUTES {
        nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
        bInheritHandle: true.into(),
        ..Default::default()
    };
    let mut read = HANDLE::default();
    let mut write = HANDLE::default();
    unsafe { CreatePipe(&mut read, &mut write, Some(&security), 0) }.unwrap();
    let read = OwnedHandle(read);
    let write = OwnedHandle(write);
    unsafe { SetHandleInformation(read.0, HANDLE_FLAG_INHERIT.0, HANDLE_FLAGS(0)) }.unwrap();
    for inherited in [write.0, sentinel.0] {
        let mut flags = 0;
        unsafe { GetHandleInformation(inherited, &mut flags) }.unwrap();
        assert_ne!(flags & HANDLE_FLAG_INHERIT.0, 0);
    }
    state.set_env(MODE, "hold");
    state.set_env(PREFIX, &prefix);
    state.set_env(DIRECTORY, &cwd);
    state.set_env(SENTINEL, (sentinel.0 .0 as usize).to_string());
    let mut child = fixture_child(&cwd);
    assert_eq!(unsafe { WaitForSingleObject(ready.0, 5000) }, WAIT_OBJECT_0);
    assert!(child.0.try_wait().unwrap().is_none());
    // Readiness is published after NUL stream, cwd and event checks in the
    // actual child. The child remains blocked on release throughout this test.
    assert_eq!(unsafe { WaitForSingleObject(sentinel.0, 0) }, WAIT_TIMEOUT);
    drop(write);
    let error = unsafe { PeekNamedPipe(read.0, None, 0, None, None, None) }.unwrap_err();
    assert_eq!(error.code(), ERROR_BROKEN_PIPE.to_hresult());

    let mut parent_in_job = BOOL::default();
    let mut child_in_job = BOOL::default();
    unsafe {
        IsProcessInJob(GetCurrentProcess(), None, &mut parent_in_job).unwrap();
        IsProcessInJob(child.0.process.0, None, &mut child_in_job).unwrap();
    }
    // The native qualification runner places this harness in a retained Job.
    // Outside a Job this is only the no-new-Job control, not positive evidence
    // of Job inheritance. This helper never creates or requests a breakaway Job.
    assert_eq!(child_in_job.as_bool(), parent_in_job.as_bool());
    if parent_in_job.as_bool() {
        // NULL selects the calling harness's Job. Verify this actual retained
        // child's membership, rather than merely accepting some unrelated Job.
        #[repr(C)]
        struct JobMembers {
            assigned: u32,
            listed: u32,
            pids: [usize; 1024],
        }
        let mut members = JobMembers {
            assigned: 0,
            listed: 0,
            pids: [0; 1024],
        };
        unsafe {
            QueryInformationJobObject(
                None,
                JobObjectBasicProcessIdList,
                (&mut members as *mut JobMembers).cast(),
                std::mem::size_of::<JobMembers>() as u32,
                None,
            )
        }
        .unwrap();
        assert!((members.listed as usize) <= members.pids.len());
        let pid = unsafe { GetProcessId(child.0.process.0) };
        assert_ne!(pid, 0);
        assert!(members.pids[..members.listed as usize].contains(&(pid as usize)));
    }
    unsafe { SetEvent(release.0) }.unwrap();
    assert_eq!(
        unsafe { WaitForSingleObject(child.0.process.0, 5000) },
        WAIT_OBJECT_0
    );
    assert!(child.0.try_wait().unwrap().unwrap().success());
    assert!(child.0.try_wait().unwrap().unwrap().success());
}

#[test]
fn native_service_spawn_wait_recognizes_completed_exit_259() {
    let mut state = tirith_test_support::GlobalStateGuard::new().unwrap();
    state.set_env(MODE, "exit259");
    let mut child = fixture_child(&state.roots().cwd);
    assert_eq!(
        unsafe { WaitForSingleObject(child.0.process.0, 5000) },
        WAIT_OBJECT_0
    );
    assert_eq!(child.0.try_wait().unwrap().unwrap().code(), Some(259));
    assert_eq!(child.0.try_wait().unwrap().unwrap().code(), Some(259));
}

#[test]
fn fixed_service_spawn_rejects_invalid_startup_before_process_creation() {
    for id in [
        "",
        "not-a-uuid",
        "00000000-0000-0000-0000-000000000000",
        "A52C29AA-E58D-4B46-94B7-5B611A179CF7",
    ] {
        assert_eq!(
            spawn(Path::new("C:\\absent.exe"), Path::new("C:\\absent"), id)
                .err()
                .unwrap()
                .kind(),
            io::ErrorKind::InvalidInput,
        );
    }
}

#[test]
fn service_spawn_rejects_relative_paths_and_nul_before_process_creation() {
    for (exe, cwd) in [
        (Path::new("relative.exe"), Path::new("C:\\absent")),
        (Path::new("C:\\absent.exe"), Path::new("relative")),
    ] {
        assert_eq!(
            spawn_arguments(exe, cwd, &[]).err().unwrap().kind(),
            io::ErrorKind::InvalidInput
        );
    }
    assert!(wide_nul(&OsString::from_wide(&[b'a' as u16, 0, b'b' as u16])).is_err());
    let long = OsString::from_wide(&vec![b'x' as u16; 32767]);
    assert_eq!(
        spawn_arguments(
            Path::new("C:\\absent.exe"),
            Path::new("C:\\absent"),
            &[&long]
        )
        .err()
        .unwrap()
        .kind(),
        io::ErrorKind::InvalidInput
    );
}

#[test]
fn service_argument_encoding_preserves_quotes_backslashes_and_native_utf16() {
    for (input, expected) in [
        ("", "\"\""),
        ("a b", "\"a b\""),
        ("a\\b", "\"a\\b\""),
        ("a\\", "\"a\\\\\""),
        ("a\"b", "\"a\\\"b\""),
        ("a\\\"b", "\"a\\\\\\\"b\""),
        ("\u{03bb}\u{1f9ea}", "\"\u{03bb}\u{1f9ea}\""),
    ] {
        assert_eq!(
            quoted(OsStr::new(input)).unwrap(),
            expected.encode_utf16().collect::<Vec<_>>()
        );
    }
    let unpaired = OsString::from_wide(&[0xd800]);
    assert_eq!(
        quoted(&unpaired).unwrap(),
        vec![b'"' as u16, 0xd800, b'"' as u16]
    );
}
