//! Native aarch64 deny-all-network syscall policy. Filesystem, descriptors,
//! environment and resource limits remain the shared Linux launcher's job.
//! This file is deliberately independent of the launcher for native policy tests.

use std::collections::BTreeMap;

use seccompiler::{
    BpfProgram, SeccompAction, SeccompCmpArgLen, SeccompCmpOp, SeccompCondition, SeccompFilter,
    SeccompRule, TargetArch,
};

type Rules = BTreeMap<i64, Vec<SeccompRule>>;

fn condition(index: u8, operator: SeccompCmpOp, value: u64) -> Result<SeccompCondition, String> {
    SeccompCondition::new(index, SeccompCmpArgLen::Qword, operator, value)
        .map_err(|error| error.to_string())
}

fn eq(index: u8, value: u64) -> Result<SeccompCondition, String> {
    condition(index, SeccompCmpOp::Eq, value)
}

fn rule(conditions: Vec<SeccompCondition>) -> Result<SeccompRule, String> {
    SeccompRule::new(conditions).map_err(|error| error.to_string())
}

/// Read-only native-kernel precondition. QEMU user mode does not implement these
/// seccomp queries. A successful query does not replace checking actual filter
/// installation in the fresh child; an outer policy can still deny that action.
pub(super) fn kernel_support_observed() -> bool {
    let mut action = 0x0005_0000u32; // SECCOMP_RET_ERRNO
                                     // SAFETY: PR_GET_SECCOMP is read-only; GET_ACTION_AVAIL receives one live
                                     // u32 and neither call installs a filter or changes this process's rights.
    unsafe {
        libc::prctl(libc::PR_GET_SECCOMP, 0, 0, 0, 0) >= 0
            && libc::syscall(libc::SYS_seccomp, 2, 0, &mut action as *mut u32) == 0
    }
}

fn policy_rules() -> Result<Rules, String> {
    // Runtime and file-I/O operations corresponding to the existing Linux
    // contract, using native libc syscall identities. No socket, io_uring,
    // process-group, namespace, mount, signal-injection or unbounded ptrace rule.
    let mut rules: Rules = [
        libc::SYS_brk,
        libc::SYS_mmap,
        libc::SYS_munmap,
        libc::SYS_madvise,
        libc::SYS_mprotect,
        libc::SYS_mremap,
        libc::SYS_sigaltstack,
        libc::SYS_rt_sigaction,
        libc::SYS_rt_sigprocmask,
        libc::SYS_rt_sigreturn,
        libc::SYS_futex,
        libc::SYS_set_robust_list,
        libc::SYS_set_tid_address,
        libc::SYS_rseq,
        libc::SYS_getpid,
        libc::SYS_gettid,
        libc::SYS_getppid,
        libc::SYS_getuid,
        libc::SYS_geteuid,
        libc::SYS_getgid,
        libc::SYS_getegid,
        libc::SYS_uname,
        libc::SYS_sysinfo,
        libc::SYS_getrandom,
        libc::SYS_sched_yield,
        // Native sleep and libuv probes require only local timers/readiness.
        // These create no network endpoint and cannot obtain a new peer FD.
        libc::SYS_nanosleep,
        libc::SYS_clock_nanosleep,
        libc::SYS_epoll_create1,
        libc::SYS_epoll_ctl,
        libc::SYS_epoll_pwait,
        libc::SYS_eventfd2,
        libc::SYS_ppoll,
        libc::SYS_exit,
        libc::SYS_exit_group,
        libc::SYS_read,
        libc::SYS_readv,
        libc::SYS_preadv,
        libc::SYS_preadv2,
        libc::SYS_pread64,
        libc::SYS_lseek,
        libc::SYS_write,
        libc::SYS_writev,
        libc::SYS_pwritev,
        libc::SYS_pwritev2,
        libc::SYS_pwrite64,
        libc::SYS_fsync,
        libc::SYS_fdatasync,
        libc::SYS_openat,
        libc::SYS_openat2,
        libc::SYS_fstat,
        libc::SYS_newfstatat,
        libc::SYS_statx,
        libc::SYS_getdents64,
        libc::SYS_getcwd,
        libc::SYS_readlinkat,
        libc::SYS_close,
        libc::SYS_close_range,
        libc::SYS_faccessat,
        libc::SYS_faccessat2,
        libc::SYS_getrlimit,
        libc::SYS_dup,
        libc::SYS_dup3,
        libc::SYS_pipe2,
        libc::SYS_mkdirat,
        libc::SYS_execve,
        libc::SYS_execveat,
        libc::SYS_wait4,
        libc::SYS_waitid,
        // Denied with ENOSYS by the first filter. This allow is necessary so
        // the later filter does not replace that errno with EPERM and prevent
        // libc from falling back to the argument-restricted clone operation.
        libc::SYS_clone3,
    ]
    .into_iter()
    .map(|syscall| (syscall, Vec::new()))
    .collect();

    rules.insert(libc::SYS_prlimit64, vec![rule(vec![eq(0, 0)?, eq(2, 0)?])?]);
    rules.insert(libc::SYS_getpgid, vec![rule(vec![eq(0, 0)?])?]);
    rules.insert(libc::SYS_sched_getaffinity, vec![rule(vec![eq(0, 0)?])?]);
    rules.insert(libc::SYS_get_robust_list, vec![rule(vec![eq(0, 0)?])?]);

    let mut descriptor_rules = Vec::new();
    for command in [
        libc::F_GETFD,
        libc::F_SETFD,
        libc::F_GETFL,
        libc::F_DUPFD,
        libc::F_DUPFD_CLOEXEC,
    ] {
        descriptor_rules.push(rule(vec![eq(1, command as u64)?])?);
    }
    rules.insert(libc::SYS_fcntl, descriptor_rules);
    let mut terminal_rules = Vec::new();
    for request in [
        libc::TCGETS,
        libc::TIOCGWINSZ,
        libc::TIOCGPGRP,
        libc::FIONREAD,
    ] {
        terminal_rules.push(rule(vec![
            condition(0, SeccompCmpOp::Le, libc::STDERR_FILENO as u64)?,
            eq(1, request as u64)?,
        ])?);
    }
    rules.insert(libc::SYS_ioctl, terminal_rules);

    // Only the caller's immutable group may be terminated. This is used by the
    // guard's parent-death handler; arbitrary signal injection remains denied.
    rules.insert(
        libc::SYS_kill,
        vec![rule(vec![eq(0, 0)?, eq(1, libc::SIGKILL as u64)?])?],
    );
    rules.insert(
        libc::SYS_prctl,
        vec![rule(vec![
            eq(0, libc::PR_SET_PDEATHSIG as u64)?,
            eq(1, libc::SIGKILL as u64)?,
            eq(2, 0)?,
            eq(3, 0)?,
            eq(4, 0)?,
        ])?],
    );
    let mut ptrace = vec![rule(vec![
        eq(0, libc::PTRACE_TRACEME as u64)?,
        eq(1, 0)?,
        eq(2, 0)?,
        eq(3, 0)?,
    ])?];
    let pid_conditions = || -> Result<Vec<SeccompCondition>, String> {
        Ok(vec![
            condition(1, SeccompCmpOp::Gt, 0)?,
            condition(1, SeccompCmpOp::Le, i32::MAX as u64)?,
        ])
    };
    let mut options = pid_conditions()?;
    options.extend([
        eq(0, libc::PTRACE_SETOPTIONS as u64)?,
        eq(2, 0)?,
        eq(
            3,
            (libc::PTRACE_O_TRACEEXEC | libc::PTRACE_O_EXITKILL) as u64,
        )?,
    ]);
    ptrace.push(rule(options)?);
    for request in [libc::PTRACE_CONT, libc::PTRACE_DETACH, libc::PTRACE_KILL] {
        let mut conditions = pid_conditions()?;
        conditions.extend([eq(0, request as u64)?, eq(2, 0)?, eq(3, 0)?]);
        ptrace.push(rule(conditions)?);
    }
    // ARM BRK leaves PC on the trapping instruction. The trusted launcher
    // validates its exact hidden trap before advancing four bytes. Only the
    // native general-register set is available, for an existing positive
    // tracee; kernel ptrace ownership checks still apply. No attach, memory
    // access or other register set is authorized by these rules.
    for request in [libc::PTRACE_GETREGSET, libc::PTRACE_SETREGSET] {
        let mut conditions = pid_conditions()?;
        conditions.extend([
            eq(0, request as u64)?,
            eq(2, 1)?, // NT_PRSTATUS
            condition(3, SeccompCmpOp::Gt, 0)?,
        ]);
        ptrace.push(rule(conditions)?);
    }
    rules.insert(libc::SYS_ptrace, ptrace);

    // clone3 stores flags behind a pointer and cannot be safely filtered by BPF.
    // A separate ENOSYS rule below permits libc's fallback to inspectable clone.
    // Restrict clone to reviewed fork/vfork/thread flags, without CLONE_PARENT,
    // CLONE_UNTRACED or any namespace flags; child-exit signals are 0 or SIGCHLD.
    let flags = (libc::CLONE_VM
        | libc::CLONE_FS
        | libc::CLONE_FILES
        | libc::CLONE_SIGHAND
        | libc::CLONE_VFORK
        | libc::CLONE_THREAD
        | libc::CLONE_SYSVSEM
        | libc::CLONE_SETTLS
        | libc::CLONE_PARENT_SETTID
        | libc::CLONE_CHILD_CLEARTID
        | libc::CLONE_CHILD_SETTID) as u64;
    let mut clone = Vec::new();
    for signal in [0, libc::SIGCHLD as u64] {
        clone.push(rule(vec![
            condition(0, SeccompCmpOp::MaskedEq(!(flags | 0xff)), 0)?,
            condition(0, SeccompCmpOp::MaskedEq(0xff), signal)?,
        ])?);
    }
    rules.insert(libc::SYS_clone, clone);
    Ok(rules)
}

pub(super) fn build_filters() -> Result<(BpfProgram, BpfProgram), String> {
    // Both filters validate AUDIT_ARCH_AARCH64 through the reviewed compiler.
    let clone_fallback = SeccompFilter::new(
        [(libc::SYS_clone3, Vec::new())].into_iter().collect(),
        SeccompAction::Allow,
        SeccompAction::Errno(libc::ENOSYS as u32),
        TargetArch::aarch64,
    )
    .map_err(|error| error.to_string())?
    .try_into()
    .map_err(|error: seccompiler::BackendError| error.to_string())?;
    let default_deny = SeccompFilter::new(
        policy_rules()?,
        SeccompAction::Errno(libc::EPERM as u32),
        SeccompAction::Allow,
        TargetArch::aarch64,
    )
    .map_err(|error| error.to_string())?
    .try_into()
    .map_err(|error: seccompiler::BackendError| error.to_string())?;
    Ok((clone_fallback, default_deny))
}

/// Called only in the single-threaded Linux launcher after Landlock and NNP.
pub(super) fn apply() -> Result<bool, String> {
    let (clone_fallback, default_deny) = build_filters()?;
    seccompiler::apply_filter(&clone_fallback).map_err(|error| error.to_string())?;
    seccompiler::apply_filter(&default_deny).map_err(|error| error.to_string())?;
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::process::ExitStatusExt;

    // Evaluate the compiled, architecture-checking BPF, so argument-boundary
    // assertions test actual emitted branches rather than the input rule list.
    fn evaluate(program: &BpfProgram, arch: u32, syscall: i64, args: [u64; 6]) -> u32 {
        let mut data = [0u8; 64];
        data[0..4].copy_from_slice(&(syscall as u32).to_le_bytes());
        data[4..8].copy_from_slice(&arch.to_le_bytes());
        for (index, arg) in args.into_iter().enumerate() {
            data[16 + index * 8..24 + index * 8].copy_from_slice(&arg.to_le_bytes());
        }
        let mut accumulator = 0;
        let mut pc = 0;
        for _ in 0..4096 {
            let instruction = &program[pc];
            pc += 1;
            match instruction.code {
                0x20 => {
                    let start = instruction.k as usize;
                    accumulator = u32::from_le_bytes(data[start..start + 4].try_into().unwrap());
                }
                0x54 => accumulator &= instruction.k,
                0x05 => pc += instruction.k as usize,
                0x06 => return instruction.k,
                0x15 | 0x25 | 0x35 | 0x45 => {
                    let matches = match instruction.code {
                        0x15 => accumulator == instruction.k,
                        0x25 => accumulator > instruction.k,
                        0x35 => accumulator >= instruction.k,
                        0x45 => accumulator & instruction.k != 0,
                        _ => unreachable!(),
                    };
                    pc += if matches {
                        instruction.jt
                    } else {
                        instruction.jf
                    } as usize;
                }
                code => panic!("unrecognized compiled BPF instruction {code:x}"),
            }
        }
        panic!("BPF did not terminate within its instruction bound")
    }

    #[test]
    fn compiled_filter_binds_architecture_and_sensitive_arguments() {
        const ARM: u32 = 0xc00000b7;
        const ALLOW: u32 = 0x7fff0000;
        const DENY: u32 = 0x50000 | libc::EPERM as u32;
        let (fallback, filter) = build_filters().unwrap();
        let decision = |syscall, args| evaluate(&filter, ARM, syscall, args);
        assert_eq!(
            evaluate(&filter, 0xc000003e, libc::SYS_read, [0; 6]) & 0xffff0000,
            0x80000000
        );
        assert_eq!(decision(libc::SYS_read, [0; 6]), ALLOW);
        for syscall in [libc::SYS_socket, libc::SYS_io_uring_enter, libc::SYS_kill] {
            assert_eq!(decision(syscall, [0; 6]), DENY);
        }
        assert_eq!(
            decision(libc::SYS_kill, [0, libc::SIGKILL as u64, 0, 0, 0, 0]),
            ALLOW
        );
        for args in [
            [1, libc::SIGKILL as u64, 0, 0, 0, 0],
            [u64::MAX, libc::SIGKILL as u64, 0, 0, 0, 0],
            [0, libc::SIGTERM as u64, 0, 0, 0, 0],
        ] {
            assert_eq!(decision(libc::SYS_kill, args), DENY);
        }
        assert_eq!(decision(libc::SYS_prlimit64, [0; 6]), ALLOW);
        assert_eq!(decision(libc::SYS_prlimit64, [1, 0, 0, 0, 0, 0]), DENY);
        assert_eq!(decision(libc::SYS_prlimit64, [0, 0, 1, 0, 0, 0]), DENY);
        let mut ptrace = [
            libc::PTRACE_SETOPTIONS as u64,
            1,
            0,
            (libc::PTRACE_O_TRACEEXEC | libc::PTRACE_O_EXITKILL) as u64,
            0,
            0,
        ];
        assert_eq!(decision(libc::SYS_ptrace, ptrace), ALLOW);
        for pid in [0, i32::MAX as u64 + 1, u64::MAX] {
            ptrace[1] = pid;
            assert_eq!(decision(libc::SYS_ptrace, ptrace), DENY);
        }
        ptrace[1] = 1;
        ptrace[3] = libc::PTRACE_O_TRACEEXEC as u64;
        assert_eq!(decision(libc::SYS_ptrace, ptrace), DENY);
        for request in [libc::PTRACE_GETREGSET, libc::PTRACE_SETREGSET] {
            let valid = [request as u64, 1, 1, 4096, 0, 0];
            assert_eq!(decision(libc::SYS_ptrace, valid), ALLOW);
            for (index, value) in [
                (1, 0),
                (1, i32::MAX as u64 + 1),
                (1, u64::MAX),
                (2, 0),
                (2, 2),
                (2, 0x405),
                (3, 0),
            ] {
                let mut invalid = valid;
                invalid[index] = value;
                assert_eq!(decision(libc::SYS_ptrace, invalid), DENY);
            }
        }
        for request in [
            libc::PTRACE_ATTACH,
            libc::PTRACE_PEEKDATA,
            libc::PTRACE_POKEDATA,
        ] {
            assert_eq!(
                decision(libc::SYS_ptrace, [request as u64, 1, 1, 4096, 0, 0]),
                DENY
            );
        }
        assert_eq!(
            decision(libc::SYS_ioctl, [1, libc::TCGETS as u64, 0, 0, 0, 0]),
            ALLOW
        );
        assert_eq!(
            decision(libc::SYS_ioctl, [4, libc::TCGETS as u64, 0, 0, 0, 0]),
            DENY
        );
        assert_eq!(
            decision(libc::SYS_ioctl, [0, libc::TIOCSTI as u64, 0, 0, 0, 0]),
            DENY
        );
        let parent_death = [
            libc::PR_SET_PDEATHSIG as u64,
            libc::SIGKILL as u64,
            0,
            0,
            0,
            0,
        ];
        assert_eq!(decision(libc::SYS_prctl, parent_death), ALLOW);
        let mut changed = parent_death;
        changed[1] = 0;
        assert_eq!(decision(libc::SYS_prctl, changed), DENY);
        assert_eq!(
            decision(libc::SYS_clone, [libc::SIGCHLD as u64, 0, 0, 0, 0, 0]),
            ALLOW
        );
        for flags in [
            libc::CLONE_PARENT as u64,
            libc::CLONE_UNTRACED as u64,
            libc::CLONE_NEWUSER as u64,
            1u64 << 63,
        ] {
            assert_eq!(
                decision(
                    libc::SYS_clone,
                    [flags | libc::SIGCHLD as u64, 0, 0, 0, 0, 0]
                ),
                DENY
            );
        }
        assert_eq!(
            decision(libc::SYS_clone, [libc::SIGKILL as u64, 0, 0, 0, 0, 0]),
            DENY
        );
        assert_eq!(decision(libc::SYS_clone3, [0; 6]), ALLOW);
        assert_eq!(
            evaluate(&fallback, ARM, libc::SYS_clone3, [0; 6]),
            0x50000 | libc::ENOSYS as u32
        );
    }

    #[test]
    fn rule_surface_excludes_network_and_escape_syscalls() {
        let rules = policy_rules().unwrap();
        for syscall in [
            libc::SYS_socket,
            libc::SYS_socketpair,
            libc::SYS_connect,
            libc::SYS_sendto,
            libc::SYS_recvfrom,
            libc::SYS_io_uring_setup,
            libc::SYS_io_uring_enter,
            libc::SYS_unshare,
            libc::SYS_setns,
            libc::SYS_mount,
            libc::SYS_setsid,
            libc::SYS_setpgid,
            libc::SYS_process_vm_writev,
            libc::SYS_process_vm_readv,
            libc::SYS_tgkill,
        ] {
            assert!(!rules.contains_key(&syscall));
        }
        let (fallback, deny) = build_filters().unwrap();
        assert!(!fallback.is_empty() && fallback.len() < 4096);
        assert!(!deny.is_empty() && deny.len() < 4096);
    }

    #[test]
    fn native_filter_subprocess() {
        let Ok(case) = std::env::var("TIRITH_AARCH64_FILTER_FIXTURE") else {
            return;
        };
        assert!(kernel_support_observed());
        if case == "network" {
            // Distinguish our filter from an outer container already denying
            // socket creation. This only opens unconnected local descriptors.
            for domain in [libc::AF_INET, libc::AF_INET6, libc::AF_UNIX] {
                let fd = unsafe { libc::socket(domain, libc::SOCK_STREAM, 0) };
                assert!(fd >= 0, "outer host denies baseline socket creation");
                assert_eq!(unsafe { libc::close(fd) }, 0);
            }
        }
        if case == "unavailable" {
            let blocked: BpfProgram = SeccompFilter::new(
                [(libc::SYS_seccomp, Vec::new())].into_iter().collect(),
                SeccompAction::Allow,
                SeccompAction::Errno(libc::EPERM as u32),
                TargetArch::aarch64,
            )
            .unwrap()
            .try_into()
            .unwrap();
            seccompiler::apply_filter(&blocked).unwrap();
            assert!(
                apply().is_err(),
                "denied filter setup must never claim enforcement"
            );
            return;
        }
        assert!(apply().unwrap());
        if case == "network" {
            for domain in [libc::AF_INET, libc::AF_INET6, libc::AF_UNIX] {
                assert_eq!(unsafe { libc::socket(domain, libc::SOCK_STREAM, 0) }, -1);
                assert_eq!(
                    std::io::Error::last_os_error().raw_os_error(),
                    Some(libc::EPERM)
                );
            }
            let mut sockets = [0; 2];
            assert_eq!(
                unsafe {
                    libc::socketpair(libc::AF_UNIX, libc::SOCK_STREAM, 0, sockets.as_mut_ptr())
                },
                -1
            );
            assert_eq!(
                unsafe { libc::syscall(libc::SYS_io_uring_setup, 1, std::ptr::null::<u8>()) },
                -1
            );
        } else if case == "escape" {
            for syscall in [
                libc::SYS_setsid,
                libc::SYS_setpgid,
                libc::SYS_unshare,
                libc::SYS_setns,
            ] {
                assert_eq!(unsafe { libc::syscall(syscall, 0, 0, 0, 0) }, -1);
                assert_eq!(
                    std::io::Error::last_os_error().raw_os_error(),
                    Some(libc::EPERM)
                );
            }
            assert_eq!(
                unsafe { libc::ptrace(libc::PTRACE_ATTACH, libc::getppid(), 0, 0) },
                -1
            );
            assert_eq!(
                unsafe { libc::syscall(libc::SYS_clone3, std::ptr::null::<u8>(), 0) },
                -1
            );
            assert_eq!(
                std::io::Error::last_os_error().raw_os_error(),
                Some(libc::ENOSYS)
            );
            assert_eq!(
                unsafe { libc::prctl(libc::PR_SET_DUMPABLE, 1, 0, 0, 0) },
                -1
            );
            assert_eq!(
                unsafe {
                    libc::syscall(
                        libc::SYS_clone,
                        libc::CLONE_PARENT | libc::SIGCHLD,
                        0,
                        0,
                        0,
                        0,
                    )
                },
                -1
            );
        } else if case == "exec" {
            let status = std::process::Command::new("/bin/sh")
                .args(["-c", "printf native-filter-ok; /bin/true"])
                .status()
                .unwrap();
            assert!(status.success(), "shell status {status:?}");
        } else {
            panic!("unknown fixture")
        }
    }

    #[test]
    fn native_filter_denies_network_escape_and_allows_reviewed_shell() {
        for case in ["network", "escape", "exec", "unavailable"] {
            let output = std::process::Command::new(std::env::current_exe().unwrap())
                .args([
                    "native_filter_subprocess",
                    "--nocapture",
                    "--test-threads=1",
                ])
                .env("TIRITH_AARCH64_FILTER_FIXTURE", case)
                .output()
                .unwrap();
            assert!(
                output.status.success(),
                "{case}: {:?} signal={:?}\n{}\n{}",
                output.status,
                output.status.signal(),
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
        }
    }
}
