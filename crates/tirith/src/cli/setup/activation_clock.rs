//! Private, read-only freshness observations for an already-authorized setup.
//!
//! A deserialized stamp is data, not authorization. The caller must obtain it
//! from the immutable, validated completion evidence of an accepted activation
//! intent. Capture it only after completion, including no-op completion, and
//! never refresh it on retries. Successful ordering is not interception proof.
//! No PID supplied here is a capability to signal, wait for, or own a process.

use serde::{Deserialize, Serialize};
use tirith_core::execution_state::AuthenticatedShellContext;

const STAMP_VERSION: u32 = 1;
const NANOS_PER_SECOND: u64 = 1_000_000_000;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct CompletionStamp {
    schema_version: u32,
    clock: NativeCompletion,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
enum NativeCompletion {
    LinuxBoottimeZeroOffset {
        boot_id: [u8; 16],
        ticks_per_second: u32,
        ceiling: LinuxCompletionTickCeiling,
    },
    MacosMachAbsolute {
        boot_id: [u8; 16],
        timebase: MachTimebase,
        ticks: MachAbsoluteTicks,
    },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
struct LinuxCompletionTickCeiling(u64);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct LinuxProcessStartTick(u64);

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
struct MachAbsoluteTicks(u64);

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct MachTimebase {
    numer: u32,
    denom: u32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum NativeStart {
    #[cfg_attr(not(any(target_os = "linux", test)), allow(dead_code))]
    Linux(LinuxProcessStartTick),
    #[cfg_attr(not(any(target_os = "macos", test)), allow(dead_code))]
    Macos(MachAbsoluteTicks),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum ClockRefusal {
    Unsupported,
    NativeRead,
    Malformed,
    BootOrClockMismatch,
    ProcessChanged,
    Unauthenticated,
    NotStrictlyAfter,
}

impl std::fmt::Display for ClockRefusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Unsupported => "native activation clock is unavailable",
            Self::NativeRead => "native activation clock read failed",
            Self::Malformed => "native activation clock evidence is malformed",
            Self::BootOrClockMismatch => "activation clock or boot session changed",
            Self::ProcessChanged => "authenticated shell process changed during clock sampling",
            Self::Unauthenticated => "activation freshness requires a current authenticated shell",
            Self::NotStrictlyAfter => "shell start is not strictly after setup completion",
        })
    }
}

/// Capture only as part of immutable completion evidence. This performs no
/// setup/journal authorization and writes no files.
pub(super) fn capture_completion() -> Result<CompletionStamp, ClockRefusal> {
    Ok(CompletionStamp {
        schema_version: STAMP_VERSION,
        clock: native::capture()?,
    })
}

/// The opaque core context must already authenticate this actual shell. Its
/// revalidation must bind the direct parent, native start identity, operator,
/// session, capability anchor and executable, without parsing the opaque start
/// fingerprint. No public PID-only comparison or caller-created context exists.
pub(super) fn require_fresh_authenticated_shell(
    completion: &CompletionStamp,
    shell: &AuthenticatedShellContext,
) -> Result<(), ClockRefusal> {
    shell
        .revalidate()
        .map_err(|_| ClockRefusal::Unauthenticated)?;
    let pid = shell.shell_pid();
    if pid <= 1 || pid > i32::MAX as u32 {
        return Err(ClockRefusal::Unauthenticated);
    }
    let first = native::process_start(pid)?;
    let observed = native::capture()?;
    let second = native::process_start(pid)?;
    shell
        .revalidate()
        .map_err(|_| ClockRefusal::Unauthenticated)?;
    if first != second {
        return Err(ClockRefusal::ProcessChanged);
    }
    compare(completion, &observed, second)
}

fn compare(
    completion: &CompletionStamp,
    observed: &NativeCompletion,
    start: NativeStart,
) -> Result<(), ClockRefusal> {
    if completion.schema_version != STAMP_VERSION {
        return Err(ClockRefusal::Unsupported);
    }
    let (completed, started, now) = match (&completion.clock, observed, start) {
        (
            NativeCompletion::LinuxBoottimeZeroOffset {
                boot_id,
                ticks_per_second,
                ceiling,
            },
            NativeCompletion::LinuxBoottimeZeroOffset {
                boot_id: live_boot,
                ticks_per_second: live_hz,
                ceiling: now,
            },
            NativeStart::Linux(start),
        ) if boot_id == live_boot && ticks_per_second == live_hz => {
            tick_nanos(*ticks_per_second)?;
            (ceiling.0, start.0, now.0)
        }
        (
            NativeCompletion::MacosMachAbsolute {
                boot_id,
                timebase,
                ticks,
            },
            NativeCompletion::MacosMachAbsolute {
                boot_id: live_boot,
                timebase: live_base,
                ticks: now,
            },
            NativeStart::Macos(start),
        ) if boot_id == live_boot && timebase == live_base => {
            if timebase.numer == 0 || timebase.denom == 0 {
                return Err(ClockRefusal::Malformed);
            }
            (ticks.0, start.0, now.0)
        }
        _ => return Err(ClockRefusal::BootOrClockMismatch),
    };
    if completed == 0 || started == 0 || now == 0 || completed > now || started > now {
        return Err(ClockRefusal::Malformed);
    }
    if started <= completed {
        return Err(ClockRefusal::NotStrictlyAfter);
    }
    Ok(())
}

fn tick_nanos(hz: u32) -> Result<u64, ClockRefusal> {
    // Linux nsec_to_clock_t is exact division only for integral ns/tick.
    // Refuse unusual USER_HZ approximations rather than mixing time scales.
    if hz == 0 || NANOS_PER_SECOND % u64::from(hz) != 0 {
        return Err(ClockRefusal::Unsupported);
    }
    Ok(NANOS_PER_SECOND / u64::from(hz))
}

#[cfg(any(target_os = "linux", test))]
fn ceiling_tick(
    seconds: u64,
    nanos: u32,
    hz: u32,
) -> Result<LinuxCompletionTickCeiling, ClockRefusal> {
    if u64::from(nanos) >= NANOS_PER_SECOND {
        return Err(ClockRefusal::Malformed);
    }
    let quantum = tick_nanos(hz)?;
    let whole = seconds
        .checked_mul(u64::from(hz))
        .ok_or(ClockRefusal::Malformed)?;
    let fraction = u64::from(nanos) / quantum + u64::from(u64::from(nanos) % quantum != 0);
    Ok(LinuxCompletionTickCeiling(
        whole.checked_add(fraction).ok_or(ClockRefusal::Malformed)?,
    ))
}

fn parse_boot_id(bytes: &[u8]) -> Result<[u8; 16], ClockRefusal> {
    if bytes.len() != 36 {
        return Err(ClockRefusal::Malformed);
    }
    let text = std::str::from_utf8(bytes).map_err(|_| ClockRefusal::Malformed)?;
    let id = uuid::Uuid::parse_str(text).map_err(|_| ClockRefusal::Malformed)?;
    if id.is_nil() || !text.eq_ignore_ascii_case(&id.hyphenated().to_string()) {
        return Err(ClockRefusal::Malformed);
    }
    Ok(*id.as_bytes())
}

#[cfg(target_os = "linux")]
mod native {
    use super::*;
    use std::ffi::CString;
    use std::fs::{File, OpenOptions};
    use std::io::Read;
    use std::os::fd::{AsRawFd, FromRawFd};
    use std::os::unix::fs::OpenOptionsExt;

    fn proc_dir(parts: &[&str]) -> Result<File, ClockRefusal> {
        let mut directory = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
            .open("/proc")
            .map_err(|_| ClockRefusal::NativeRead)?;
        for part in parts {
            let name = CString::new(*part).map_err(|_| ClockRefusal::Malformed)?;
            let fd = unsafe {
                libc::openat(
                    directory.as_raw_fd(),
                    name.as_ptr(),
                    libc::O_RDONLY
                        | libc::O_DIRECTORY
                        | libc::O_NOFOLLOW
                        | libc::O_CLOEXEC
                        | libc::O_NONBLOCK,
                )
            };
            if fd < 0 {
                return Err(ClockRefusal::NativeRead);
            }
            directory = unsafe { File::from_raw_fd(fd) };
        }
        require_procfs(&directory)?;
        Ok(directory)
    }

    fn require_procfs(file: &File) -> Result<(), ClockRefusal> {
        let mut fs = std::mem::MaybeUninit::<libc::statfs>::zeroed();
        if unsafe { libc::fstatfs(file.as_raw_fd(), fs.as_mut_ptr()) } != 0 {
            return Err(ClockRefusal::NativeRead);
        }
        if unsafe { fs.assume_init() }.f_type != libc::PROC_SUPER_MAGIC {
            return Err(ClockRefusal::Unsupported);
        }
        Ok(())
    }

    fn read_file(parts: &[&str], name: &str, cap: usize) -> Result<Vec<u8>, ClockRefusal> {
        let directory = proc_dir(parts)?;
        let name = CString::new(name).map_err(|_| ClockRefusal::Malformed)?;
        let fd = unsafe {
            libc::openat(
                directory.as_raw_fd(),
                name.as_ptr(),
                libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK,
            )
        };
        if fd < 0 {
            return Err(ClockRefusal::NativeRead);
        }
        let file = unsafe { File::from_raw_fd(fd) };
        require_procfs(&file)?;
        if !file
            .metadata()
            .map_err(|_| ClockRefusal::NativeRead)?
            .is_file()
        {
            return Err(ClockRefusal::Malformed);
        }
        let mut bytes = Vec::with_capacity(cap + 1);
        file.take((cap + 1) as u64)
            .read_to_end(&mut bytes)
            .map_err(|_| ClockRefusal::NativeRead)?;
        if bytes.is_empty() || bytes.len() > cap {
            return Err(ClockRefusal::Malformed);
        }
        Ok(bytes)
    }

    fn boot_id() -> Result<[u8; 16], ClockRefusal> {
        let bytes = read_file(&["sys", "kernel", "random"], "boot_id", 37)?;
        parse_boot_id(bytes.strip_suffix(b"\n").unwrap_or(&bytes))
    }

    fn namespace_link(parts: &[&str], name: &str) -> Result<Vec<u8>, ClockRefusal> {
        let directory = proc_dir(parts)?;
        let name = CString::new(name).map_err(|_| ClockRefusal::Malformed)?;
        let mut bytes = [0u8; 128];
        let count = unsafe {
            libc::readlinkat(
                directory.as_raw_fd(),
                name.as_ptr(),
                bytes.as_mut_ptr().cast(),
                bytes.len(),
            )
        };
        if count <= 0 || count as usize >= bytes.len() {
            return Err(ClockRefusal::NativeRead);
        }
        let value = &bytes[..count as usize];
        let inode = value
            .strip_prefix(b"time:[")
            .and_then(|s| s.strip_suffix(b"]"))
            .ok_or(ClockRefusal::Malformed)?;
        if inode.is_empty() || !inode.iter().all(u8::is_ascii_digit) {
            return Err(ClockRefusal::Malformed);
        }
        Ok(value.to_vec())
    }

    fn zero_time_namespace() -> Result<Vec<u8>, ClockRefusal> {
        let pid = std::process::id().to_string();
        let tid = unsafe { libc::syscall(libc::SYS_gettid) };
        if tid <= 0 || tid > libc::c_long::from(i32::MAX) {
            return Err(ClockRefusal::NativeRead);
        }
        let tid = tid.to_string();
        let current = namespace_link(&[&pid, "task", &tid, "ns"], "time")?;
        let leader = namespace_link(&[&pid, "ns"], "time")?;
        let children = namespace_link(&[&pid, "ns"], "time_for_children")?;
        if current != leader || current != children {
            return Err(ClockRefusal::Unsupported);
        }
        // timens_offsets describes the leader's children namespace, not its
        // current namespace. Equality above is required, also for worker threads.
        parse_zero_offsets(&read_file(&[&pid], "timens_offsets", 256)?)?;
        if namespace_link(&[&pid, "task", &tid, "ns"], "time")? != current
            || namespace_link(&[&pid, "ns"], "time")? != current
            || namespace_link(&[&pid, "ns"], "time_for_children")? != current
        {
            return Err(ClockRefusal::BootOrClockMismatch);
        }
        Ok(current)
    }

    pub(super) fn capture() -> Result<NativeCompletion, ClockRefusal> {
        let namespace = zero_time_namespace()?;
        let boot = boot_id()?;
        let hz = unsafe { libc::sysconf(libc::_SC_CLK_TCK) };
        let hz = u32::try_from(hz).map_err(|_| ClockRefusal::Unsupported)?;
        tick_nanos(hz)?;
        let mut time = std::mem::MaybeUninit::<libc::timespec>::zeroed();
        if unsafe { libc::clock_gettime(libc::CLOCK_BOOTTIME, time.as_mut_ptr()) } != 0 {
            return Err(ClockRefusal::NativeRead);
        }
        let time = unsafe { time.assume_init() };
        let ceiling = ceiling_tick(
            u64::try_from(time.tv_sec).map_err(|_| ClockRefusal::Malformed)?,
            u32::try_from(time.tv_nsec).map_err(|_| ClockRefusal::Malformed)?,
            hz,
        )?;
        if boot_id()? != boot || zero_time_namespace()? != namespace {
            return Err(ClockRefusal::BootOrClockMismatch);
        }
        Ok(NativeCompletion::LinuxBoottimeZeroOffset {
            boot_id: boot,
            ticks_per_second: hz,
            ceiling,
        })
    }

    pub(super) fn process_start(pid: u32) -> Result<NativeStart, ClockRefusal> {
        let namespace = zero_time_namespace()?;
        let bytes = read_file(&[&pid.to_string()], "stat", 8192)?;
        let start = parse_linux_start(&bytes, pid)?;
        if zero_time_namespace()? != namespace {
            return Err(ClockRefusal::BootOrClockMismatch);
        }
        Ok(NativeStart::Linux(start))
    }
}

#[cfg(any(target_os = "linux", test))]
fn parse_zero_offsets(bytes: &[u8]) -> Result<(), ClockRefusal> {
    let text = std::str::from_utf8(bytes).map_err(|_| ClockRefusal::Malformed)?;
    let mut names = 0u8;
    for line in text.lines() {
        let mut fields = line.split_whitespace();
        let bit = match fields.next() {
            Some("monotonic") => 1,
            Some("boottime") => 2,
            _ => return Err(ClockRefusal::Malformed),
        };
        if names & bit != 0
            || fields.next() != Some("0")
            || fields.next() != Some("0")
            || fields.next().is_some()
        {
            return Err(ClockRefusal::Unsupported);
        }
        names |= bit;
    }
    if names != 3 {
        return Err(ClockRefusal::Malformed);
    }
    Ok(())
}

#[cfg(any(target_os = "linux", test))]
fn parse_linux_start(
    bytes: &[u8],
    expected_pid: u32,
) -> Result<LinuxProcessStartTick, ClockRefusal> {
    let text = std::str::from_utf8(bytes).map_err(|_| ClockRefusal::Malformed)?;
    let (pid, rest) = text.split_once(" (").ok_or(ClockRefusal::Malformed)?;
    if pid.parse::<u32>().ok() != Some(expected_pid) {
        return Err(ClockRefusal::ProcessChanged);
    }
    let end = rest.rfind(") ").ok_or(ClockRefusal::Malformed)?;
    let mut fields = rest[end + 2..].split_whitespace();
    match fields.next() {
        Some("R" | "S" | "D" | "T" | "t" | "P" | "I") => (),
        _ => return Err(ClockRefusal::ProcessChanged),
    }
    let tick = fields.nth(18).ok_or(ClockRefusal::Malformed)?;
    if tick.is_empty() || !tick.bytes().all(|b| b.is_ascii_digit()) {
        return Err(ClockRefusal::Malformed);
    }
    let value = tick.parse::<u64>().map_err(|_| ClockRefusal::Malformed)?;
    if value == 0 {
        return Err(ClockRefusal::Malformed);
    }
    Ok(LinuxProcessStartTick(value))
}

#[cfg(target_os = "macos")]
mod native {
    use super::*;

    // Exact system ABI from mach/mach_time.h: two uint32_t fields and
    // kern_return_t (int). Keep these small bindings local; libc's transitional
    // Mach bindings are deprecated, while the underlying system APIs remain.
    #[repr(C)]
    struct MachTimebaseInfo {
        numer: u32,
        denom: u32,
    }

    #[link(name = "System")]
    unsafe extern "C" {
        fn mach_timebase_info(info: *mut MachTimebaseInfo) -> libc::c_int;
        fn mach_absolute_time() -> u64;
    }

    fn boot_id() -> Result<[u8; 16], ClockRefusal> {
        let mut bytes = [0u8; 64];
        let mut length = bytes.len();
        let rc = unsafe {
            libc::sysctlbyname(
                c"kern.bootsessionuuid".as_ptr(),
                bytes.as_mut_ptr().cast(),
                &mut length,
                std::ptr::null_mut(),
                0,
            )
        };
        if rc != 0 {
            return Err(ClockRefusal::NativeRead);
        }
        if length != 37 || bytes[36] != 0 {
            return Err(ClockRefusal::Malformed);
        }
        parse_boot_id(&bytes[..36])
    }

    fn timebase() -> Result<MachTimebase, ClockRefusal> {
        let mut info = std::mem::MaybeUninit::<MachTimebaseInfo>::zeroed();
        if unsafe { mach_timebase_info(info.as_mut_ptr()) } != 0 {
            return Err(ClockRefusal::NativeRead);
        }
        let info = unsafe { info.assume_init() };
        if info.numer == 0 || info.denom == 0 {
            return Err(ClockRefusal::Malformed);
        }
        Ok(MachTimebase {
            numer: info.numer,
            denom: info.denom,
        })
    }

    pub(super) fn capture() -> Result<NativeCompletion, ClockRefusal> {
        let boot = boot_id()?;
        let base = timebase()?;
        let ticks = unsafe { mach_absolute_time() };
        if ticks == 0 {
            return Err(ClockRefusal::Malformed);
        }
        if boot_id()? != boot || timebase()? != base {
            return Err(ClockRefusal::BootOrClockMismatch);
        }
        Ok(NativeCompletion::MacosMachAbsolute {
            boot_id: boot,
            timebase: base,
            ticks: MachAbsoluteTicks(ticks),
        })
    }

    pub(super) fn process_start(pid: u32) -> Result<NativeStart, ClockRefusal> {
        let mut info = std::mem::MaybeUninit::<libc::rusage_info_v0>::zeroed();
        // The C API declares rusage_info_t* (void**), but writes the selected
        // fixed structure directly at buffer. V0 is 96 bytes on this ABI.
        let rc = unsafe {
            libc::proc_pid_rusage(
                pid as libc::pid_t,
                libc::RUSAGE_INFO_V0,
                info.as_mut_ptr().cast::<libc::rusage_info_t>(),
            )
        };
        if rc != 0 {
            return Err(ClockRefusal::NativeRead);
        }
        let info = unsafe { info.assume_init() };
        if info.ri_proc_start_abstime == 0 || info.ri_proc_exit_abstime != 0 {
            return Err(ClockRefusal::ProcessChanged);
        }
        Ok(NativeStart::Macos(MachAbsoluteTicks(
            info.ri_proc_start_abstime,
        )))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn linux(tick: u64) -> NativeCompletion {
        NativeCompletion::LinuxBoottimeZeroOffset {
            boot_id: [1; 16],
            ticks_per_second: 100,
            ceiling: LinuxCompletionTickCeiling(tick),
        }
    }

    fn macos(tick: u64) -> NativeCompletion {
        NativeCompletion::MacosMachAbsolute {
            boot_id: [2; 16],
            timebase: MachTimebase {
                numer: 125,
                denom: 3,
            },
            ticks: MachAbsoluteTicks(tick),
        }
    }

    fn stamp(clock: NativeCompletion) -> CompletionStamp {
        CompletionStamp {
            schema_version: STAMP_VERSION,
            clock,
        }
    }

    #[test]
    fn linux_completion_rounds_up_and_rejects_unsupported_precision_or_overflow() {
        assert_eq!(ceiling_tick(1, 0, 100), Ok(LinuxCompletionTickCeiling(100)));
        assert_eq!(ceiling_tick(1, 1, 100), Ok(LinuxCompletionTickCeiling(101)));
        assert_eq!(
            ceiling_tick(1, 10_000_000, 100),
            Ok(LinuxCompletionTickCeiling(101))
        );
        assert_eq!(
            ceiling_tick(1, 999_999_999, 100),
            Ok(LinuxCompletionTickCeiling(200))
        );
        for hz in [0, 60, 1024, u32::MAX] {
            assert_eq!(ceiling_tick(1, 0, hz), Err(ClockRefusal::Unsupported));
        }
        assert_eq!(
            ceiling_tick(1, 1_000_000_000, 100),
            Err(ClockRefusal::Malformed)
        );
        assert_eq!(ceiling_tick(u64::MAX, 0, 100), Err(ClockRefusal::Malformed));
    }

    #[test]
    fn linux_equality_and_the_conservative_ceiling_tick_cannot_claim_freshness() {
        let completion = stamp(linux(101));
        for start in [1, 100, 101] {
            assert_eq!(
                compare(
                    &completion,
                    &linux(200),
                    NativeStart::Linux(LinuxProcessStartTick(start))
                ),
                Err(ClockRefusal::NotStrictlyAfter)
            );
        }
        assert_eq!(
            compare(
                &completion,
                &linux(200),
                NativeStart::Linux(LinuxProcessStartTick(102))
            ),
            Ok(())
        );
        assert_eq!(
            compare(
                &completion,
                &linux(200),
                NativeStart::Linux(LinuxProcessStartTick(201))
            ),
            Err(ClockRefusal::Malformed)
        );
    }

    #[test]
    fn native_clock_boot_rate_and_timebase_must_match() {
        let completion = stamp(macos(100));
        assert_eq!(
            compare(
                &completion,
                &macos(200),
                NativeStart::Macos(MachAbsoluteTicks(101))
            ),
            Ok(())
        );
        assert_eq!(
            compare(
                &completion,
                &macos(200),
                NativeStart::Macos(MachAbsoluteTicks(100))
            ),
            Err(ClockRefusal::NotStrictlyAfter)
        );
        assert_eq!(
            compare(
                &completion,
                &linux(200),
                NativeStart::Linux(LinuxProcessStartTick(101))
            ),
            Err(ClockRefusal::BootOrClockMismatch)
        );
        let mut wrong_boot = macos(200);
        if let NativeCompletion::MacosMachAbsolute { boot_id, .. } = &mut wrong_boot {
            *boot_id = [3; 16];
        }
        assert_eq!(
            compare(
                &completion,
                &wrong_boot,
                NativeStart::Macos(MachAbsoluteTicks(101))
            ),
            Err(ClockRefusal::BootOrClockMismatch)
        );
        let mut wrong_base = macos(200);
        if let NativeCompletion::MacosMachAbsolute { timebase, .. } = &mut wrong_base {
            timebase.numer = 1;
        }
        assert_eq!(
            compare(
                &completion,
                &wrong_base,
                NativeStart::Macos(MachAbsoluteTicks(101))
            ),
            Err(ClockRefusal::BootOrClockMismatch)
        );
        let mut wrong_rate = linux(200);
        if let NativeCompletion::LinuxBoottimeZeroOffset {
            ticks_per_second, ..
        } = &mut wrong_rate
        {
            *ticks_per_second = 250;
        }
        assert_eq!(
            compare(
                &stamp(linux(100)),
                &wrong_rate,
                NativeStart::Linux(LinuxProcessStartTick(101))
            ),
            Err(ClockRefusal::BootOrClockMismatch)
        );
    }

    #[test]
    fn missing_zero_future_and_unknown_version_stamps_refuse() {
        assert_eq!(
            compare(
                &stamp(macos(201)),
                &macos(200),
                NativeStart::Macos(MachAbsoluteTicks(150))
            ),
            Err(ClockRefusal::Malformed)
        );
        for (completed, started) in [(0, 101), (100, 0), (100, 201)] {
            assert_eq!(
                compare(
                    &stamp(macos(completed)),
                    &macos(200),
                    NativeStart::Macos(MachAbsoluteTicks(started))
                ),
                Err(ClockRefusal::Malformed)
            );
        }
        let mut unknown = stamp(macos(100));
        unknown.schema_version = 2;
        assert_eq!(
            compare(
                &unknown,
                &macos(200),
                NativeStart::Macos(MachAbsoluteTicks(101))
            ),
            Err(ClockRefusal::Unsupported)
        );
        let mut value = serde_json::to_value(stamp(macos(100))).unwrap();
        value["authority"] = serde_json::json!(true);
        assert!(serde_json::from_value::<CompletionStamp>(value).is_err());
    }

    #[test]
    fn boot_ids_have_one_bounded_native_uuid_shape() {
        let lower = b"a1234567-1234-4234-8234-123456789abc";
        let upper = b"A1234567-1234-4234-8234-123456789ABC";
        assert_eq!(parse_boot_id(lower), parse_boot_id(upper));
        assert!(parse_boot_id(lower).is_ok());
        for malformed in [
            b"".as_slice(),
            b"00000000-0000-0000-0000-000000000000",
            b"a1234567-1234-4234-8234-123456789abc\n",
            b"a1234567123442348234123456789abc",
        ] {
            assert_eq!(parse_boot_id(malformed), Err(ClockRefusal::Malformed));
        }
    }

    #[test]
    fn namespace_offsets_are_explicit_zero_coordinates_only() {
        assert_eq!(parse_zero_offsets(b"monotonic 0 0\nboottime 0 0\n"), Ok(()));
        assert_eq!(parse_zero_offsets(b"boottime 0 0\nmonotonic 0 0\n"), Ok(()));
        for text in [
            "",
            "boottime 0 0\n",
            "boottime 0 0\nboottime 0 0\n",
            "monotonic 0 0\nboottime 1 0\n",
            "monotonic 0 0\nboottime 0 1\n",
            "monotonic 0 0\nboottime -1 0\n",
            "monotonic 0 0\nboottime 0 0 extra\n",
        ] {
            assert!(parse_zero_offsets(text.as_bytes()).is_err());
        }
    }

    fn stat_record(state: &str, start: &str) -> Vec<u8> {
        format!(
            "42 (a ) tricky\nname) {state} {} {start} 0\n",
            ["0"; 18].join(" ")
        )
        .into_bytes()
    }

    #[test]
    fn stat_start_uses_the_native_field_not_an_opaque_fingerprint() {
        assert_eq!(
            parse_linux_start(&stat_record("S", "123"), 42),
            Ok(LinuxProcessStartTick(123))
        );
        assert_eq!(
            parse_linux_start(&stat_record("S", "123"), 43),
            Err(ClockRefusal::ProcessChanged)
        );
        for state in ["Z", "X", "x", "SS", "?"] {
            assert_eq!(
                parse_linux_start(&stat_record(state, "123"), 42),
                Err(ClockRefusal::ProcessChanged)
            );
        }
        for start in ["0", "-1", "+1", "18446744073709551616", "linux:boot:1"] {
            assert!(parse_linux_start(&stat_record("S", start), 42).is_err());
        }
        assert!(parse_linux_start(b"42 (truncated) S 1 2", 42).is_err());
    }
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
mod native {
    use super::*;
    pub(super) fn capture() -> Result<NativeCompletion, ClockRefusal> {
        Err(ClockRefusal::Unsupported)
    }
    pub(super) fn process_start(_: u32) -> Result<NativeStart, ClockRefusal> {
        Err(ClockRefusal::Unsupported)
    }
}
