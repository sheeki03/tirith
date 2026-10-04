//! Process and thread creation policy shared by the x86_64 and aarch64 seccomp
//! layers, so both architectures restrict `clone` the same way.
//!
//! `clone3` passes its flags behind a pointer, which BPF cannot read. A separate
//! filter installed FIRST answers `clone3` with ENOSYS, so libc falls back to
//! `clone`, whose flags are in a register and are checked against the table
//! below. The main policy must still allow `clone3`: when two filters both
//! return an errno, the later filter's errno wins, and libc only falls back on
//! ENOSYS.

use seccompiler::{BpfProgram, SeccompAction, SeccompFilter, TargetArch};

/// `clone` flags used by fork, vfork/posix_spawn and pthread_create. Excludes
/// CLONE_PARENT and CLONE_UNTRACED (which could escape the supervising guard),
/// CLONE_PTRACE, CLONE_PIDFD and every namespace flag.
pub(super) const ALLOWED_CLONE_FLAGS: u64 = (libc::CLONE_VM
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

/// The low byte of the `clone` flags is the child's exit signal.
const CLONE_EXIT_SIGNAL_MASK: u64 = 0xff;

/// Child exit signals a contained process may request: none (threads) or SIGCHLD.
const ALLOWED_CLONE_EXIT_SIGNALS: [u64; 2] = [0, libc::SIGCHLD as u64];

/// The `clone` allow rules as `(mask, value)` conditions on argument 0 (the
/// flags on both x86_64 and aarch64). A call is allowed when every condition of
/// ONE rule holds: `flags & mask == value`.
pub(super) fn clone_allow_rules() -> [[(u64, u64); 2]; 2] {
    ALLOWED_CLONE_EXIT_SIGNALS.map(|signal| {
        [
            (!(ALLOWED_CLONE_FLAGS | CLONE_EXIT_SIGNAL_MASK), 0),
            (CLONE_EXIT_SIGNAL_MASK, signal),
        ]
    })
}

/// The first filter: `clone3` fails with ENOSYS, everything else passes on to
/// the main policy.
pub(super) fn clone3_enosys_filter(arch: TargetArch, clone3: i64) -> Result<BpfProgram, String> {
    SeccompFilter::new(
        [(clone3, Vec::new())].into_iter().collect(),
        SeccompAction::Allow,
        SeccompAction::Errno(libc::ENOSYS as u32),
        arch,
    )
    .map_err(|error| error.to_string())?
    .try_into()
    .map_err(|error: seccompiler::BackendError| error.to_string())
}

/// Evaluate a compiled classic-BPF seccomp program in user space, so tests check
/// the emitted branches rather than the input rule list. Supports the
/// instructions seccompiler emits.
#[cfg(test)]
pub(super) fn evaluate_bpf(program: &BpfProgram, arch: u32, syscall: i64, args: [u64; 6]) -> u32 {
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

#[cfg(test)]
mod tests {
    use super::*;
    use seccompiler::{SeccompCmpArgLen, SeccompCmpOp, SeccompCondition, SeccompRule};

    const ALLOW: u32 = 0x7fff_0000;
    const DENY: u32 = 0x50000 | libc::EPERM as u32;
    const ENOSYS: u32 = 0x50000 | libc::ENOSYS as u32;

    /// (target, AUDIT_ARCH value, clone, clone3) with each architecture's own
    /// syscall numbers, so the x86_64 table is checked on an aarch64 host too.
    const ARCHES: [(TargetArch, u32, i64, i64); 2] = [
        (TargetArch::x86_64, 0xc000_003e, 56, 435),
        (TargetArch::aarch64, 0xc000_00b7, 220, 435),
    ];

    fn clone_only_policy(arch: TargetArch, clone: i64, clone3: i64) -> BpfProgram {
        let rules = clone_allow_rules()
            .into_iter()
            .map(|conditions| {
                SeccompRule::new(
                    conditions
                        .into_iter()
                        .map(|(mask, value)| {
                            SeccompCondition::new(
                                0,
                                SeccompCmpArgLen::Qword,
                                SeccompCmpOp::MaskedEq(mask),
                                value,
                            )
                            .unwrap()
                        })
                        .collect(),
                )
                .unwrap()
            })
            .collect();
        SeccompFilter::new(
            [(clone, rules), (clone3, Vec::new())].into_iter().collect(),
            SeccompAction::Errno(libc::EPERM as u32),
            SeccompAction::Allow,
            arch,
        )
        .unwrap()
        .try_into()
        .unwrap()
    }

    #[test]
    fn both_architectures_allow_only_reviewed_clone_flags() {
        let _shared_state = tirith_test_support::SharedStateGuard::acquire();
        let sigchld = libc::SIGCHLD as u64;
        let fork = (libc::CLONE_CHILD_SETTID | libc::CLONE_CHILD_CLEARTID) as u64 | sigchld;
        let vfork = (libc::CLONE_VM | libc::CLONE_VFORK) as u64 | sigchld;
        let thread = (libc::CLONE_VM
            | libc::CLONE_FS
            | libc::CLONE_FILES
            | libc::CLONE_SIGHAND
            | libc::CLONE_THREAD
            | libc::CLONE_SYSVSEM
            | libc::CLONE_SETTLS
            | libc::CLONE_PARENT_SETTID
            | libc::CLONE_CHILD_CLEARTID) as u64;
        for (arch, audit_arch, clone, clone3) in ARCHES {
            let policy = clone_only_policy(arch, clone, clone3);
            let decide =
                |flags: u64| evaluate_bpf(&policy, audit_arch, clone, [flags, 0, 0, 0, 0, 0]);
            for flags in [sigchld, fork, vfork, thread] {
                assert_eq!(decide(flags), ALLOW, "{arch:?} {flags:#x}");
            }
            for flags in [
                libc::CLONE_PARENT as u64 | sigchld,
                libc::CLONE_UNTRACED as u64 | sigchld,
                libc::CLONE_PTRACE as u64 | sigchld,
                libc::CLONE_PIDFD as u64 | sigchld,
                libc::CLONE_NEWUSER as u64 | sigchld,
                libc::CLONE_NEWNET as u64 | sigchld,
                libc::CLONE_NEWNS as u64 | sigchld,
                libc::CLONE_NEWPID as u64 | sigchld,
                (1u64 << 63) | sigchld,
                libc::SIGKILL as u64,
                thread | libc::SIGKILL as u64,
            ] {
                assert_eq!(decide(flags), DENY, "{arch:?} {flags:#x}");
            }
            // The main policy allows clone3 so the first filter's ENOSYS is
            // what the caller sees.
            assert_eq!(evaluate_bpf(&policy, audit_arch, clone3, [0; 6]), ALLOW);
            let fallback = clone3_enosys_filter(arch, clone3).unwrap();
            assert_eq!(evaluate_bpf(&fallback, audit_arch, clone3, [0; 6]), ENOSYS);
            assert_eq!(
                evaluate_bpf(&fallback, audit_arch, clone, [sigchld, 0, 0, 0, 0, 0]),
                ALLOW
            );
        }
    }
}
