//! Fixed-program lifecycle worker transport. Private identity evidence travels
//! only through inherited pipes while both processes retain the original objects.
use serde_json::Value;

#[cfg(unix)]
mod native {
    use super::*;
    use crate::cli::selfupdate::lifecycle_operations::HandoffStage;
    use crate::cli::selfupdate::lifecycle_service;
    use std::fs::File;
    use std::io::Read;
    #[cfg(test)]
    use std::io::Write;
    use std::os::fd::{AsFd, AsRawFd, OwnedFd};
    use std::process::{Child, Command, Stdio};
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::time::{Duration, Instant};

    const FRAME_CAP: usize = 64 * 1024;
    const HANDOFF_DEADLINE: Duration = Duration::from_secs(30);
    const WORKER_DEADLINE: Duration = Duration::from_secs(600);
    static ACTIVE: AtomicBool = AtomicBool::new(false);

    struct Permit;
    impl Drop for Permit {
        fn drop(&mut self) {
            ACTIVE.store(false, Ordering::Release);
        }
    }
    struct ChildGuard(Child);
    impl Drop for ChildGuard {
        fn drop(&mut self) {
            // Only this exact child, never a PID from a browser or journal.
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }

    fn pipe(fd: i32) -> Result<(), String> {
        let mut metadata = std::mem::MaybeUninit::<libc::stat>::uninit();
        if unsafe { libc::fstat(fd, metadata.as_mut_ptr()) } != 0
            || unsafe { metadata.assume_init() }.st_mode & libc::S_IFMT != libc::S_IFIFO
        {
            return Err("lifecycle handshake requires inherited pipe handles".into());
        }
        let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
        if flags < 0 || unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) } < 0 {
            return Err("cannot configure lifecycle pipe".into());
        }
        Ok(())
    }

    fn ready(fd: i32, events: i16, deadline: Instant) -> Result<(), String> {
        loop {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return Err("lifecycle handshake timed out".into());
            }
            let mut poll = libc::pollfd {
                fd,
                events,
                revents: 0,
            };
            let result = unsafe {
                libc::poll(
                    &mut poll,
                    1,
                    remaining.as_millis().min(i32::MAX as u128) as i32,
                )
            };
            if result < 0 {
                if std::io::Error::last_os_error().kind() == std::io::ErrorKind::Interrupted {
                    continue;
                }
                return Err("lifecycle pipe readiness failed".into());
            }
            if result > 0 {
                if poll.revents & events != 0 {
                    return Ok(());
                }
                return Err("lifecycle pipe closed before handoff completed".into());
            }
        }
    }

    fn read_exact(
        reader: &mut File,
        mut bytes: &mut [u8],
        deadline: Instant,
    ) -> Result<(), String> {
        while !bytes.is_empty() {
            ready(reader.as_raw_fd(), libc::POLLIN, deadline)?;
            match reader.read(bytes) {
                Ok(0) => return Err("lifecycle parent or worker ended before handoff".into()),
                Ok(n) => bytes = &mut bytes[n..],
                Err(error)
                    if matches!(
                        error.kind(),
                        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::Interrupted
                    ) => {}
                Err(_) => return Err("cannot read lifecycle handoff".into()),
            }
        }
        Ok(())
    }

    fn read_frame(reader: &mut File, deadline: Instant) -> Result<Value, String> {
        pipe(reader.as_raw_fd())?;
        let mut prefix = [0u8; 4];
        read_exact(reader, &mut prefix, deadline)?;
        let length = u32::from_be_bytes(prefix) as usize;
        if length == 0 || length > FRAME_CAP {
            return Err("lifecycle handoff frame exceeds limit".into());
        }
        let mut bytes = vec![0u8; length];
        read_exact(reader, &mut bytes, deadline)?;
        serde_json::from_slice(&bytes).map_err(|_| "invalid lifecycle handoff frame".into())
    }

    fn write_frame(writer: &mut File, value: &Value, deadline: Instant) -> Result<(), String> {
        pipe(writer.as_raw_fd())?;
        let bytes = serde_json::to_vec(value).map_err(|_| "cannot encode lifecycle handoff")?;
        if bytes.is_empty() || bytes.len() > FRAME_CAP {
            return Err("lifecycle handoff frame exceeds limit".into());
        }
        let mut framed = Vec::with_capacity(bytes.len() + 4);
        framed.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
        framed.extend_from_slice(&bytes);
        let mut remaining = framed.as_slice();
        while !remaining.is_empty() {
            ready(writer.as_raw_fd(), libc::POLLOUT, deadline)?;
            match crate::cli::check::write_pipe_sigpipe_safe(writer, remaining) {
                Ok(0) => return Err("lifecycle handoff pipe stopped accepting data".into()),
                Ok(n) => remaining = &remaining[n..],
                Err(error)
                    if matches!(
                        error.kind(),
                        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::Interrupted
                    ) => {}
                Err(_) => return Err("cannot write lifecycle handoff".into()),
            }
        }
        Ok(())
    }

    struct HandoffFailure {
        stage: HandoffStage,
        diagnostic: String,
    }

    impl HandoffFailure {
        fn new(stage: HandoffStage, error: impl std::fmt::Display) -> Self {
            Self {
                stage,
                diagnostic: error.to_string(),
            }
        }
    }

    /// Raw-descriptor polling must use unbuffered reads and writes. Stdin may
    /// prefetch a body when reading its prefix; Stdout may retain a reply while
    /// awaiting GO. Duplicate and retain the actual pipes before any framed I/O.
    fn worker_pipes() -> Result<(File, File), String> {
        let input = std::io::stdin()
            .as_fd()
            .try_clone_to_owned()
            .map_err(|_| "cannot retain worker input pipe")?;
        let output = std::io::stdout()
            .as_fd()
            .try_clone_to_owned()
            .map_err(|_| "cannot retain worker output pipe")?;
        pipe(input.as_raw_fd())?;
        pipe(output.as_raw_fd())?;
        Ok((File::from(input), File::from(output)))
    }

    fn execute(accepted: &lifecycle_service::AcceptedOperation) -> Result<(), HandoffFailure> {
        let executable = tirith_core::trusted_child::TrustedExecutable::from_absolute(
            accepted.executable(),
            &[],
        )
        .map_err(|error| HandoffFailure::new(HandoffStage::ExecutableTrust, error))?;
        let evidence = accepted
            .handoff_identity()
            .map_err(|error| HandoffFailure::new(HandoffStage::RetainedContext, error))?;
        let mut command = Command::new(executable.launch_path());
        command
            .args([
                "dashboard",
                "lifecycle-worker",
                "--operation-id",
                accepted.operation_id(),
            ])
            .current_dir(accepted.cwd())
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null());
        use std::os::unix::process::CommandExt;
        // Detach this fixed worker so closing the service never sends it a
        // terminal hangup. No shell or dynamically supplied command is used.
        unsafe {
            command.pre_exec(|| {
                if libc::setsid() < 0 {
                    Err(std::io::Error::last_os_error())
                } else {
                    Ok(())
                }
            });
        }
        executable
            .verify_identity()
            .map_err(|error| HandoffFailure::new(HandoffStage::ExecutableIdentity, error))?;
        let mut child = ChildGuard(
            command
                .spawn()
                .map_err(|error| HandoffFailure::new(HandoffStage::Spawn, error))?,
        );
        let input = child.0.stdin.take().ok_or_else(|| {
            HandoffFailure::new(HandoffStage::InputPipe, "worker input pipe unavailable")
        })?;
        let output = child.0.stdout.take().ok_or_else(|| {
            HandoffFailure::new(HandoffStage::OutputPipe, "worker output pipe unavailable")
        })?;
        let mut input = File::from(OwnedFd::from(input));
        let mut output = File::from(OwnedFd::from(output));
        let deadline = Instant::now() + HANDOFF_DEADLINE;
        write_frame(&mut input, &evidence, deadline)
            .map_err(|error| HandoffFailure::new(HandoffStage::SendContext, error))?;
        let reply = read_frame(&mut output, deadline)
            .map_err(|error| HandoffFailure::new(HandoffStage::ReceiveContext, error))?;
        accepted
            .confirm_worker(&reply)
            .map_err(|error| HandoffFailure::new(HandoffStage::ConfirmContext, error))?;
        write_frame(&mut input, &reply, deadline)
            .map_err(|error| HandoffFailure::new(HandoffStage::SendGo, error))?;
        drop(input);
        drop(output);
        let deadline = Instant::now() + WORKER_DEADLINE;
        loop {
            match child
                .0
                .try_wait()
                .map_err(|error| HandoffFailure::new(HandoffStage::InspectWorker, error))?
            {
                Some(status) if status.success() => return Ok(()),
                Some(_) => {
                    return Err(HandoffFailure::new(
                        HandoffStage::WorkerExit,
                        "lifecycle worker stopped; inspect its saved operation",
                    ))
                }
                None if Instant::now() >= deadline => {
                    return Err(HandoffFailure::new(
                        HandoffStage::WorkerDeadline,
                        "lifecycle worker exceeded its deadline; inspect its saved operation",
                    ))
                }
                None => std::thread::sleep(Duration::from_millis(100)),
            }
        }
    }

    pub(super) fn start(
        id: &str,
    ) -> Result<crate::cli::selfupdate::lifecycle_operations::OperationView, String> {
        ACTIVE
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .map_err(|_| "another binary lifecycle worker is already active")?;
        let permit = Permit;
        let accepted = std::sync::Arc::new(lifecycle_service::begin_apply(id)?);
        let view = accepted.view()?;
        // Admission is persisted before the response. The caller already has
        // the immutable plan UUID if the response is lost.
        let worker_operation = std::sync::Arc::clone(&accepted);
        if std::thread::Builder::new()
            .name("tirith-lifecycle-handoff".into())
            .spawn(move || {
                let _permit = permit;
                if let Err(failure) = execute(&worker_operation) {
                    // execute drops/kills/reaps its own child before returning.
                    // A failed handshake must not leave a replayable Accepted job.
                    let _ = worker_operation.fail_handoff(failure.stage, &failure.diagnostic);
                }
            })
            .is_err()
        {
            let _ = accepted.fail_handoff(
                HandoffStage::ThreadSpawn,
                "cannot start lifecycle handoff thread",
            );
            return Err("cannot start lifecycle handoff thread; inspect saved operation".into());
        }
        Ok(view)
    }

    pub(super) fn worker(id: &str) -> Result<(), String> {
        if !uuid::Uuid::parse_str(id).is_ok_and(|value| value.to_string() == id) {
            return Err("invalid lifecycle worker operation identity".into());
        }
        super::super::lifecycle::require_unprivileged()?;
        let (mut input, mut output) = worker_pipes()?;
        let deadline = Instant::now() + HANDOFF_DEADLINE;
        let parent = read_frame(&mut input, deadline)?;
        let captured = lifecycle_service::capture_worker(id)?;
        let evidence = captured.handoff_identity()?;
        if parent != evidence {
            return Err("worker did not inherit the original operation context".into());
        }
        write_frame(&mut output, &evidence, deadline)?;
        let go = read_frame(&mut input, deadline)?;
        let ready = captured.confirm_handoff(&go)?;
        // The original service may exit while this worker publishes. Its
        // reaper cannot enforce a deadline after that point, so the worker
        // also owns its absolute process deadline. The durable journal retains
        // publication intent if termination interrupts an atomic transaction.
        let finished = std::sync::Arc::new(AtomicBool::new(false));
        struct Deadline(std::sync::Arc<AtomicBool>);
        impl Drop for Deadline {
            fn drop(&mut self) {
                self.0.store(true, Ordering::Release);
            }
        }
        let watchdog = std::sync::Arc::clone(&finished);
        let _deadline = Deadline(finished);
        std::thread::Builder::new()
            .name("tirith-lifecycle-deadline".into())
            .spawn(move || {
                let end = Instant::now() + WORKER_DEADLINE;
                while !watchdog.load(Ordering::Acquire) {
                    if Instant::now() >= end {
                        std::process::exit(1);
                    }
                    std::thread::sleep(Duration::from_millis(100));
                }
            })
            .map_err(|_| "cannot enforce lifecycle worker deadline")?;
        let result = ready.run()?;
        if !result.view.published {
            return Err("lifecycle result has no verified publication".into());
        }
        let binary = super::super::identity::BinaryIdentity::capture(&result.resulting_binary)?;
        if binary.sha256() != result.resulting_sha256 {
            return Err("installed binary changed before dashboard restart".into());
        }
        let executable =
            tirith_core::trusted_child::TrustedExecutable::from_absolute(binary.path(), &[])
                .map_err(|_| "installed dashboard executable is untrusted")?;
        binary.revalidate()?;
        executable
            .verify_identity()
            .map_err(|_| "installed dashboard executable changed")?;
        // New binary generates a new private URL and opens it locally. The
        // previous session token is never passed into the restarted process.
        Command::new(executable.launch_path())
            .arg("dashboard")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .map_err(|_| "binary updated; reopen the dashboard from a terminal")?;
        Ok(())
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use std::os::fd::FromRawFd;
        fn pipes() -> (File, File) {
            let mut fds = [-1; 2];
            assert_eq!(unsafe { libc::pipe(fds.as_mut_ptr()) }, 0);
            for fd in fds {
                assert_eq!(
                    unsafe { libc::fcntl(fd, libc::F_SETFD, libc::FD_CLOEXEC) },
                    0
                );
            }
            unsafe {
                (
                    std::fs::File::from_raw_fd(fds[0]),
                    std::fs::File::from_raw_fd(fds[1]),
                )
            }
        }
        const PROBE: &str = "cli::control::lifecycle_worker::native::tests::stdio_framing_child";
        const OUTPUT_FD: &str = "TIRITH_TEST_LIFECYCLE_PIPE_FD";
        const MODE: &str = "TIRITH_TEST_LIFECYCLE_PIPE_MODE";

        /// The test harness writes to /dev/null. Only this exact ignored child
        /// redirects stdout to its parent's retained pipe before using the real
        /// worker stdio adapter. No production environment-driven mode exists.
        #[test]
        #[ignore = "inert framing child; invoked only by owned stdio regression"]
        fn stdio_framing_child() {
            if !std::env::args()
                .collect::<Vec<_>>()
                .windows(2)
                .any(|pair| pair[0] == "--exact" && pair[1] == PROBE)
            {
                return;
            }
            let fd = std::env::var(OUTPUT_FD).unwrap().parse::<i32>().unwrap();
            assert!(fd >= 3);
            std::io::stdout().flush().unwrap();
            assert_eq!(
                unsafe { libc::dup2(fd, libc::STDOUT_FILENO) },
                libc::STDOUT_FILENO
            );
            assert_eq!(unsafe { libc::close(fd) }, 0);
            let (mut input, mut output) = worker_pipes().unwrap();
            let deadline = Instant::now() + Duration::from_secs(5);
            match std::env::var(MODE).unwrap().as_str() {
                "roundtrip" => {
                    for length in [16, 8192, 32 * 1024] {
                        let expected = serde_json::json!({"payload":"x".repeat(length)});
                        let incoming = read_frame(&mut input, deadline).unwrap();
                        assert_eq!(incoming, expected);
                        write_frame(&mut output, &incoming, deadline).unwrap();
                    }
                    // The parent closes its writer immediately after this GO,
                    // so POLLIN|POLLHUP must still consume the pending bytes.
                    assert_eq!(
                        read_frame(&mut input, deadline).unwrap(),
                        serde_json::json!({"go":true})
                    );
                }
                "oversized" => {
                    assert_eq!(
                        read_frame(&mut input, deadline).unwrap_err(),
                        "lifecycle handoff frame exceeds limit"
                    );
                    write_frame(
                        &mut output,
                        &serde_json::json!({"oversized_refused":true}),
                        deadline,
                    )
                    .unwrap();
                }
                "sigpipe" => {
                    // This is a separate owned process: never change the test
                    // runner's or product's global signal policy.
                    assert_ne!(
                        unsafe { libc::signal(libc::SIGPIPE, libc::SIG_DFL) },
                        libc::SIG_ERR
                    );
                    let mut before = unsafe { std::mem::zeroed::<libc::sigset_t>() };
                    assert_eq!(
                        unsafe {
                            libc::pthread_sigmask(libc::SIG_BLOCK, std::ptr::null(), &mut before)
                        },
                        0
                    );
                    assert_eq!(
                        unsafe { libc::sigismember(&before, libc::SIGPIPE) },
                        0,
                        "regression requires an initially unblocked default SIGPIPE"
                    );
                    let (reader, mut writer) = pipes();
                    pipe(writer.as_raw_fd()).unwrap();
                    #[cfg(target_os = "macos")]
                    let descriptor_policy = unsafe { libc::fcntl(writer.as_raw_fd(), 74) };
                    ready(writer.as_raw_fd(), libc::POLLOUT, deadline).unwrap();
                    // Deterministic reproduction of the readiness/write gap.
                    drop(reader);
                    let error = crate::cli::check::write_pipe_sigpipe_safe(&mut writer, b"frame")
                        .unwrap_err();
                    assert_eq!(error.kind(), std::io::ErrorKind::BrokenPipe);
                    assert!(write_frame(
                        &mut writer,
                        &serde_json::json!({"closed":true}),
                        deadline
                    )
                    .is_err());
                    let mut after = unsafe { std::mem::zeroed::<libc::sigset_t>() };
                    assert_eq!(
                        unsafe {
                            libc::pthread_sigmask(libc::SIG_BLOCK, std::ptr::null(), &mut after)
                        },
                        0
                    );
                    assert_eq!(
                        unsafe { libc::sigismember(&before, libc::SIGPIPE) },
                        unsafe { libc::sigismember(&after, libc::SIGPIPE) }
                    );
                    let mut pending = unsafe { std::mem::zeroed::<libc::sigset_t>() };
                    assert_eq!(unsafe { libc::sigpending(&mut pending) }, 0);
                    assert_eq!(unsafe { libc::sigismember(&pending, libc::SIGPIPE) }, 0);
                    let mut disposition = unsafe { std::mem::zeroed::<libc::sigaction>() };
                    assert_eq!(
                        unsafe {
                            libc::sigaction(libc::SIGPIPE, std::ptr::null(), &mut disposition)
                        },
                        0
                    );
                    assert_eq!(disposition.sa_sigaction, libc::SIG_DFL);
                    #[cfg(target_os = "macos")]
                    assert_eq!(
                        unsafe { libc::fcntl(writer.as_raw_fd(), 74) },
                        descriptor_policy
                    );
                    write_frame(
                        &mut output,
                        &serde_json::json!({"broken_pipe_refused":true}),
                        deadline,
                    )
                    .unwrap();
                }
                _ => panic!("unknown fixture mode"),
            }
            // No test-harness summary may enter the private framed stream.
            std::process::exit(0);
        }

        fn stdio_child(mode: &str) -> (ChildGuard, File, File) {
            use std::os::unix::process::CommandExt;
            let (output, writer) = pipes();
            // Keep the destination occupied in the parent so Rust's internal
            // spawn error pipe cannot receive that descriptor number.
            let destination = output.as_raw_fd();
            let passed =
                unsafe { libc::fcntl(writer.as_raw_fd(), libc::F_DUPFD_CLOEXEC, destination + 1) };
            assert!(passed >= 0);
            let passed = unsafe { File::from_raw_fd(passed) };
            let source = passed.as_raw_fd();
            let mut command = Command::new(std::env::current_exe().unwrap());
            command
                .args(["--ignored", "--exact", PROBE, "--test-threads=1"])
                .env_clear()
                .env(OUTPUT_FD, destination.to_string())
                .env(MODE, mode)
                .stdin(Stdio::piped())
                .stdout(Stdio::null())
                .stderr(Stdio::null());
            unsafe {
                command.pre_exec(move || {
                    if libc::dup2(source, destination) < 0 {
                        Err(std::io::Error::last_os_error())
                    } else {
                        Ok(())
                    }
                });
            }
            let mut child = ChildGuard(command.spawn().unwrap());
            drop(passed);
            drop(writer);
            let input = File::from(OwnedFd::from(child.0.stdin.take().unwrap()));
            (child, input, output)
        }

        fn finished(child: &mut ChildGuard, deadline: Instant) {
            loop {
                if let Some(status) = child.0.try_wait().unwrap() {
                    assert!(status.success());
                    return;
                }
                assert!(Instant::now() < deadline, "owned stdio child deadline");
                std::thread::sleep(Duration::from_millis(5));
            }
        }

        #[test]
        fn real_worker_stdio_frames_complete_without_buffering_and_accept_final_hangup() {
            let deadline = Instant::now() + Duration::from_secs(5);
            let (mut child, mut input, mut output) = stdio_child("roundtrip");
            for length in [16, 8192, 32 * 1024] {
                let expected = serde_json::json!({"payload":"x".repeat(length)});
                write_frame(&mut input, &expected, deadline).unwrap();
                assert_eq!(read_frame(&mut output, deadline).unwrap(), expected);
            }
            write_frame(&mut input, &serde_json::json!({"go":true}), deadline).unwrap();
            drop(input);
            finished(&mut child, deadline);
            let mut byte = [0];
            assert_eq!(output.read(&mut byte).unwrap(), 0);
        }

        #[test]
        fn actual_worker_stdio_fifo_rejects_oversized_frame_before_body() {
            let deadline = Instant::now() + Duration::from_secs(5);
            let (mut child, mut input, mut output) = stdio_child("oversized");
            input
                .write_all(&((FRAME_CAP + 1) as u32).to_be_bytes())
                .unwrap();
            assert_eq!(
                read_frame(&mut output, deadline).unwrap(),
                serde_json::json!({"oversized_refused":true})
            );
            drop(input);
            finished(&mut child, deadline);
        }

        #[test]
        fn reader_closing_after_ready_does_not_terminate_default_sigpipe_child() {
            let deadline = Instant::now() + Duration::from_secs(5);
            let (mut child, input, mut output) = stdio_child("sigpipe");
            assert_eq!(
                read_frame(&mut output, deadline).unwrap(),
                serde_json::json!({"broken_pipe_refused":true})
            );
            drop(input);
            finished(&mut child, deadline);
            let mut byte = [0];
            assert_eq!(output.read(&mut byte).unwrap(), 0);
        }

        #[test]
        fn pipe_frames_preserve_identity_and_refuse_unbounded_or_truncated_input() {
            let (mut read, mut write) = pipes();
            let expected = serde_json::json!({"protocol":1,"id":uuid::Uuid::new_v4().to_string()});
            write_frame(
                &mut write,
                &expected,
                Instant::now() + Duration::from_secs(1),
            )
            .unwrap();
            assert_eq!(
                read_frame(&mut read, Instant::now() + Duration::from_secs(1)).unwrap(),
                expected
            );
            write
                .write_all(&((FRAME_CAP + 1) as u32).to_be_bytes())
                .unwrap();
            assert!(read_frame(&mut read, Instant::now() + Duration::from_secs(1)).is_err());
            let (mut read, mut write) = pipes();
            write.write_all(&20u32.to_be_bytes()).unwrap();
            drop(write);
            assert!(read_frame(&mut read, Instant::now() + Duration::from_secs(1)).is_err());
        }
        #[test]
        fn stalled_pipe_obeys_the_overall_deadline_and_regular_files_are_refused() {
            let (mut read, _write) = pipes();
            let start = Instant::now();
            assert!(read_frame(&mut read, start + Duration::from_millis(30)).is_err());
            assert!(start.elapsed() < Duration::from_secs(1));
            let mut file = tempfile::tempfile().unwrap();
            assert!(read_frame(&mut file, Instant::now() + Duration::from_secs(1)).is_err());
        }
    }
}

pub(crate) fn start(
    id: &str,
) -> Result<crate::cli::selfupdate::lifecycle_operations::OperationView, String> {
    #[cfg(unix)]
    {
        native::start(id)
    }
    #[cfg(not(unix))]
    {
        let _ = id;
        Err(
            "browser binary updates are unavailable on this platform; use the owning installer"
                .into(),
        )
    }
}

pub(crate) fn run(id: &str) -> i32 {
    #[cfg(unix)]
    {
        if native::worker(id).is_ok() {
            0
        } else {
            1
        }
    }
    #[cfg(not(unix))]
    {
        let _ = id;
        1
    }
}
