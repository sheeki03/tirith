//! Test-only native PTY owner. Never signal a PID learned from enumeration.
use std::io;
#[cfg(target_os = "linux")]
use std::io::Read;
use std::time::{Duration, Instant};

#[derive(Default, serde::Serialize)]
pub(super) struct Cleanup {
    pub leader_reaped: bool,
    pub original_group_exited: bool,
    pub original_session_exited: bool,
    pub reaped_after_native_observation: bool,
    pub observation: Option<Observation>,
    pub group_signal_permission_denied: bool,
    pub errors: Vec<String>,
}

#[derive(serde::Serialize)]
pub(super) struct Member {
    pid: i32,
    process_group: i32,
    session: i32,
    exited: bool,
}
#[derive(serde::Serialize)]
pub(super) struct Observation {
    method: &'static str,
    original_group_exited: bool,
    original_session_exited: bool,
    members: Vec<Member>,
}

pub(super) struct Leader {
    child: Box<dyn portable_pty::Child + Send + Sync>,
    pub pid: i32,
    reaped: bool,
    lost: bool,
    group: bool,
}

pub(super) fn require_reaper() -> io::Result<()> {
    let mut action = unsafe { std::mem::zeroed::<libc::sigaction>() };
    if unsafe { libc::sigaction(libc::SIGCHLD, std::ptr::null(), &mut action) } != 0 {
        return Err(io::Error::last_os_error());
    }
    if action.sa_sigaction != libc::SIG_DFL || action.sa_flags & libc::SA_NOCLDWAIT != 0 {
        return Err(io::Error::other(
            "PTY ownership requires default waitable SIGCHLD",
        ));
    }
    Ok(())
}

impl Leader {
    pub fn new(child: Box<dyn portable_pty::Child + Send + Sync>) -> Self {
        // Unix portable-pty returns std::process::Child, whose process_id is Some.
        let pid = child.process_id().unwrap_or(0) as i32;
        let group =
            pid > 0 && unsafe { libc::getsid(pid) } == pid && unsafe { libc::getpgid(pid) } == pid;
        Self {
            child,
            pid,
            group,
            reaped: false,
            lost: false,
        }
    }

    pub fn valid_group(&self) -> bool {
        self.group
    }

    pub fn exited(&mut self) -> io::Result<bool> {
        if self.reaped || self.lost || self.pid <= 0 {
            return Err(io::Error::other("PTY leader ownership is unavailable"));
        }
        require_reaper()?;
        loop {
            let mut info = unsafe { std::mem::zeroed::<libc::siginfo_t>() };
            let result = unsafe {
                libc::waitid(
                    libc::P_PID,
                    self.pid as libc::id_t,
                    &mut info,
                    libc::WEXITED | libc::WNOHANG | libc::WNOWAIT,
                )
            };
            if result == 0 {
                return Ok(unsafe { info.si_pid() } == self.pid);
            }
            let error = io::Error::last_os_error();
            if error.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            if error.raw_os_error() == Some(libc::ECHILD) {
                self.lost = true;
            }
            return Err(error);
        }
    }

    fn signal(&mut self, group: bool) -> io::Result<()> {
        let exited = self.exited()?; // Retains the real child, even if already a zombie.
        if !group && exited {
            return Ok(());
        }
        if group && !self.group {
            return Err(io::Error::other("original PTY group not established"));
        }
        let target = if group { -self.pid } else { self.pid };
        if unsafe { libc::kill(target, libc::SIGKILL) } != 0 {
            let error = io::Error::last_os_error();
            if error.raw_os_error() != Some(libc::ESRCH) {
                return Err(error);
            }
        }
        Ok(())
    }

    /// Request termination while the real leader remains unreaped. The PTY
    /// reader must remain alive until it observes EOF or its bounded deadline.
    pub fn stop_original_group(&mut self) -> io::Result<()> {
        self.signal(true)
    }

    pub fn cleanup(&mut self) -> Cleanup {
        let mut result = Cleanup::default();
        if self.reaped {
            result.errors.push("cleanup called after reap".into());
            return result;
        }
        let until = Instant::now() + Duration::from_secs(4);
        let observation = (|| -> io::Result<()> {
            while Instant::now() < until {
                match self.signal(true) {
                    Ok(()) => {}
                    Err(error) if error.kind() == io::ErrorKind::PermissionDenied => {
                        result.group_signal_permission_denied = true;
                    }
                    Err(error) => return Err(error),
                }
                if self.exited()? {
                    let observed = members_exited(self.pid)?;
                    self.exited()?; // Ownership must still be intact after observation.
                    result.original_group_exited = observed.original_group_exited;
                    result.original_session_exited = observed.original_session_exited;
                    result.observation = Some(observed);
                    if result.original_group_exited && result.original_session_exited {
                        return Ok(());
                    }
                }
                std::thread::sleep(Duration::from_millis(20));
            }
            Err(io::Error::other(
                "original PTY group/session cleanup deadline",
            ))
        })();
        if let Err(error) = observation {
            result.errors.push(error.to_string());
        }
        // Reap last, even on a failed native observation. No subsequent signal
        // is permitted, and that failure remains explicit in the result.
        let reaping = (|| -> io::Result<()> {
            self.signal(false)?;
            let until = Instant::now() + Duration::from_secs(1);
            while !self.exited()? {
                if Instant::now() >= until {
                    return Err(io::Error::other("PTY leader exit deadline"));
                }
                std::thread::sleep(Duration::from_millis(5));
            }
            self.child.wait()?;
            self.reaped = true;
            result.leader_reaped = true;
            result.reaped_after_native_observation =
                result.original_group_exited && result.original_session_exited;
            Ok(())
        })();
        if let Err(error) = reaping {
            result.errors.push(error.to_string());
        }
        result
    }
}

#[cfg(target_os = "linux")]
fn members_exited(leader: i32) -> io::Result<Observation> {
    let (mut group, mut session) = (true, true);
    let (mut scanned, mut members) = (0, 0);
    let mut evidence = Vec::new();
    for entry in std::fs::read_dir("/proc")? {
        let entry = entry?;
        let Some(pid) = entry
            .file_name()
            .to_str()
            .and_then(|x| x.parse::<i32>().ok())
        else {
            continue;
        };
        scanned += 1;
        if scanned > 65536 {
            return Err(io::Error::other("native process table exceeds bound"));
        }
        let file = match std::fs::File::open(entry.path().join("stat")) {
            Ok(file) => file,
            Err(error) if matches!(error.raw_os_error(), Some(libc::ENOENT | libc::ESRCH)) => {
                continue
            }
            Err(error) => return Err(error),
        };
        let mut bytes = Vec::new();
        file.take(4097).read_to_end(&mut bytes)?;
        if bytes.len() > 4096 {
            return Err(io::Error::other("native process stat exceeds bound"));
        }
        let boundary = bytes
            .iter()
            .rposition(|byte| *byte == b')')
            .ok_or_else(|| io::Error::other("malformed native process stat"))?;
        let first_space = bytes
            .iter()
            .position(|byte| *byte == b' ')
            .ok_or_else(|| io::Error::other("native process identity missing"))?;
        let parsed_pid = std::str::from_utf8(&bytes[..first_space])
            .ok()
            .and_then(|v| v.parse::<i32>().ok());
        if parsed_pid != Some(pid) {
            return Err(io::Error::other("native process identity differs"));
        }
        let tail = std::str::from_utf8(&bytes[boundary + 1..]).map_err(io::Error::other)?;
        let values: Vec<_> = tail.split_whitespace().collect();
        let pgrp = values
            .get(2)
            .and_then(|v| v.parse::<i32>().ok())
            .ok_or_else(|| io::Error::other("native group missing"))?;
        let sid = values
            .get(3)
            .and_then(|v| v.parse::<i32>().ok())
            .ok_or_else(|| io::Error::other("native session missing"))?;
        if pgrp == leader || sid == leader {
            members += 1;
            if members > 4096 {
                return Err(io::Error::other("native member bound exceeded"));
            }
            let exited = matches!(values.first(), Some(&"Z" | &"X" | &"x"));
            evidence.push(Member {
                pid,
                process_group: pgrp,
                session: sid,
                exited,
            });
            if pgrp == leader {
                group &= exited;
            }
            if sid == leader {
                session &= exited;
            }
        }
    }
    Ok(Observation {
        method: "bounded_procfs_stat",
        original_group_exited: group,
        original_session_exited: session,
        members: evidence,
    })
}

#[cfg(target_os = "macos")]
fn members_exited(leader: i32) -> io::Result<Observation> {
    #[repr(C)]
    #[derive(Default)]
    struct Info {
        pid: u32,
        ppid: u32,
        pgid: u32,
        status: u32,
        comm: [u8; 16],
        flags: u32,
        uid: u32,
        gid: u32,
        ruid: u32,
        rgid: u32,
        svuid: u32,
        svgid: u32,
        reserved: u32,
    }
    #[link(name = "proc")]
    extern "C" {
        fn proc_listpids(kind: u32, value: u32, buffer: *mut libc::c_void, size: i32) -> i32;
        fn proc_pidinfo(
            pid: i32,
            flavor: i32,
            arg: u64,
            buffer: *mut libc::c_void,
            size: i32,
        ) -> i32;
    }
    let mut pids = vec![0i32; 65537];
    let capacity = (pids.len() * std::mem::size_of::<i32>()) as i32;
    unsafe {
        *libc::__error() = 0;
    }
    let used = unsafe { proc_listpids(1, 0, pids.as_mut_ptr().cast(), capacity) };
    if used <= 0 || used >= capacity || used % 4 != 0 {
        return Err(io::Error::other(
            "native process table unavailable or exceeds bound",
        ));
    }
    let (mut group, mut session, mut members) = (true, true, 0);
    let mut evidence = Vec::new();
    for pid in pids.into_iter().take(used as usize / 4).filter(|p| *p > 0) {
        let sid = unsafe { libc::getsid(pid) };
        if sid < 0 {
            let error = io::Error::last_os_error();
            if error.raw_os_error() == Some(libc::ESRCH) {
                continue;
            }
            return Err(error);
        }
        // Read only members of the pinned original session. Its original
        // process group cannot contain a member of a different session.
        if sid != leader {
            continue;
        }
        let mut info = Info::default();
        let size = std::mem::size_of::<Info>();
        if size != 64 {
            return Err(io::Error::other("unsupported native process-info ABI"));
        }
        unsafe {
            *libc::__error() = 0;
        }
        let read =
            unsafe { proc_pidinfo(pid, 13, 0, (&mut info as *mut Info).cast(), size as i32) };
        if read == 0
            && matches!(
                io::Error::last_os_error().raw_os_error(),
                Some(libc::ESRCH | libc::ENOENT)
            )
        {
            continue;
        }
        if read != size as i32 || info.pid != pid as u32 {
            return Err(io::Error::other("native member status unavailable"));
        }
        let still = unsafe { libc::getsid(pid) };
        if still < 0 && io::Error::last_os_error().raw_os_error() == Some(libc::ESRCH) {
            continue;
        }
        if still != leader {
            return Err(io::Error::other(
                "native member changed session during observation",
            ));
        }
        members += 1;
        if members > 4096 {
            return Err(io::Error::other("native member bound exceeded"));
        }
        let exited = info.status == 5; // Darwin SZOMB.
        evidence.push(Member {
            pid,
            process_group: info.pgid as i32,
            session: sid,
            exited,
        });
        session &= exited;
        if info.pgid == leader as u32 {
            group &= exited;
        }
    }
    Ok(Observation {
        method: "bounded_libproc_session",
        original_group_exited: group,
        original_session_exited: session,
        members: evidence,
    })
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn members_exited(_: i32) -> io::Result<Observation> {
    Err(io::Error::other(
        "native PTY observation unsupported on this Unix target",
    ))
}
