//! Fixed-program lifecycle worker transport. Private identity evidence travels
//! only through inherited pipes while both processes retain the original objects.
use serde_json::Value;

#[cfg(unix)]
mod native {
    use super::*;
    use crate::cli::selfupdate::lifecycle_service;
    use std::io::{Read, Write};
    use std::os::fd::AsRawFd;
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
        reader: &mut (impl Read + AsRawFd),
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

    fn read_frame(reader: &mut (impl Read + AsRawFd), deadline: Instant) -> Result<Value, String> {
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

    fn write_frame(
        writer: &mut (impl Write + AsRawFd),
        value: &Value,
        deadline: Instant,
    ) -> Result<(), String> {
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
            match writer.write(remaining) {
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

    fn execute(accepted: &lifecycle_service::AcceptedOperation) -> Result<(), String> {
        let executable = tirith_core::trusted_child::TrustedExecutable::from_absolute(
            accepted.executable(),
            &[],
        )
        .map_err(|_| "lifecycle worker executable is untrusted")?;
        let evidence = accepted.handoff_identity()?;
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
            .map_err(|_| "lifecycle worker executable changed")?;
        let mut child = ChildGuard(
            command
                .spawn()
                .map_err(|_| "cannot start lifecycle worker")?,
        );
        let mut input = child
            .0
            .stdin
            .take()
            .ok_or("worker input pipe unavailable")?;
        let mut output = child
            .0
            .stdout
            .take()
            .ok_or("worker output pipe unavailable")?;
        let deadline = Instant::now() + HANDOFF_DEADLINE;
        write_frame(&mut input, &evidence, deadline)?;
        let reply = read_frame(&mut output, deadline)?;
        accepted.confirm_worker(&reply)?;
        write_frame(&mut input, &reply, deadline)?;
        drop(input);
        drop(output);
        let deadline = Instant::now() + WORKER_DEADLINE;
        loop {
            match child
                .0
                .try_wait()
                .map_err(|_| "cannot inspect lifecycle worker")?
            {
                Some(status) if status.success() => return Ok(()),
                Some(_) => {
                    return Err("lifecycle worker stopped; inspect its saved operation".into())
                }
                None if Instant::now() >= deadline => {
                    return Err(
                        "lifecycle worker exceeded its deadline; inspect its saved operation"
                            .into(),
                    )
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
                if execute(&worker_operation).is_err() {
                    // execute drops/kills/reaps its own child before returning.
                    // A failed handshake must not leave a replayable Accepted job.
                    let _ = worker_operation.fail_handoff();
                }
            })
            .is_err()
        {
            let _ = accepted.fail_handoff();
            return Err("cannot start lifecycle handoff thread; inspect saved operation".into());
        }
        Ok(view)
    }

    pub(super) fn worker(id: &str) -> Result<(), String> {
        if !uuid::Uuid::parse_str(id).is_ok_and(|value| value.to_string() == id) {
            return Err("invalid lifecycle worker operation identity".into());
        }
        super::super::lifecycle::require_unprivileged()?;
        let mut input = std::io::stdin();
        let mut output = std::io::stdout();
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
        fn pipes() -> (std::fs::File, std::fs::File) {
            let mut fds = [-1; 2];
            assert_eq!(unsafe { libc::pipe(fds.as_mut_ptr()) }, 0);
            unsafe {
                (
                    std::fs::File::from_raw_fd(fds[0]),
                    std::fs::File::from_raw_fd(fds[1]),
                )
            }
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
