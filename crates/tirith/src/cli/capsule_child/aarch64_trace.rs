//! The initial ARM breakpoint reports its own PC. Advance only our fixed trap,
//! never a browser address or a register set chosen by the contained program.

// A named, hidden instruction gives the parent an exact expected address in
// the same pre-exec image. `ret` runs after the validated four-byte PC advance.
std::arch::global_asm!(
    ".text",
    ".balign 4",
    ".global tirith_capsule_initial_aarch64_trap",
    ".hidden tirith_capsule_initial_aarch64_trap",
    ".type tirith_capsule_initial_aarch64_trap, %function",
    "tirith_capsule_initial_aarch64_trap:",
    "brk #0",
    "ret",
    ".size tirith_capsule_initial_aarch64_trap, .-tirith_capsule_initial_aarch64_trap",
);

unsafe extern "C" {
    fn tirith_capsule_initial_aarch64_trap();
}

/// Only the fixed, pre-exec fork child calls this after PTRACE_TRACEME.
/// It allocates nothing and invokes no signal-delivery syscall.
pub(super) unsafe fn stop() {
    // SAFETY: the symbol above is ordinary code with the C ABI and no arguments.
    unsafe { tirith_capsule_initial_aarch64_trap() };
}

/// Linux arm64 NT_PRSTATUS uses user_pt_regs: x0..x30, sp, pc, pstate.
/// Reading/writing this register set does not grant ptrace attach or memory I/O;
/// the kernel still requires an existing tracer/tracee relationship.
pub(super) fn advance_initial_stop(target_pid: libc::pid_t) -> Result<(), String> {
    const NT_PRSTATUS: usize = 1;
    const PC_INDEX: usize = 32;
    if target_pid <= 0 {
        return Err("invalid ARM tracee identity".into());
    }
    let mut registers = [0u64; 34];
    let mut vector = libc::iovec {
        iov_base: registers.as_mut_ptr().cast(),
        iov_len: std::mem::size_of_val(&registers),
    };
    // SAFETY: the live iovec points to a correctly sized Linux arm64 register
    // buffer. Ptrace validates the target relationship and register-set ID.
    if unsafe {
        libc::ptrace(
            libc::PTRACE_GETREGSET,
            target_pid,
            NT_PRSTATUS as *mut libc::c_void,
            &mut vector as *mut libc::iovec,
        )
    } < 0
    {
        return Err("cannot inspect the initial ARM trace stop".into());
    }
    let expected_pc = tirith_capsule_initial_aarch64_trap as *const () as usize as u64;
    if vector.iov_len != std::mem::size_of_val(&registers) || registers[PC_INDEX] != expected_pc {
        return Err(
            "initial ARM trace stop does not identify the fixed launcher instruction".into(),
        );
    }
    registers[PC_INDEX] = expected_pc.checked_add(4).ok_or("invalid ARM trace PC")?;
    if unsafe {
        libc::ptrace(
            libc::PTRACE_SETREGSET,
            target_pid,
            NT_PRSTATUS as *mut libc::c_void,
            &mut vector as *mut libc::iovec,
        )
    } < 0
    {
        return Err("cannot resume past the validated initial ARM breakpoint".into());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Tracee(libc::pid_t);
    impl Drop for Tracee {
        fn drop(&mut self) {
            if self.0 <= 0 {
                return;
            }
            // All test children stop before exec. Cleanup is mandatory even
            // when an assertion fails before the continuation check.
            unsafe {
                libc::ptrace(libc::PTRACE_KILL, self.0, 0, 0);
                libc::waitpid(self.0, std::ptr::null_mut(), libc::__WALL);
            }
        }
    }

    fn stopped(fixed: bool) -> Tracee {
        let pid = unsafe { libc::fork() };
        assert!(pid >= 0);
        if pid == 0 {
            // No allocator or test harness work in the post-fork child.
            unsafe {
                if libc::ptrace(libc::PTRACE_TRACEME, 0, 0, 0) < 0 {
                    libc::_exit(2);
                }
                if fixed {
                    stop();
                } else {
                    std::arch::asm!("brk #0", options(nomem, nostack));
                }
                libc::_exit(0);
            }
        }
        let tracee = Tracee(pid);
        let mut status = 0;
        assert_eq!(
            unsafe { libc::waitpid(pid, &mut status, libc::__WALL) },
            pid
        );
        assert!(libc::WIFSTOPPED(status));
        assert_eq!(libc::WSTOPSIG(status), libc::SIGTRAP);
        tracee
    }

    #[test]
    fn exact_initial_breakpoint_resumes_once() {
        let mut tracee = stopped(true);
        advance_initial_stop(tracee.0).unwrap();
        assert_eq!(
            unsafe { libc::ptrace(libc::PTRACE_CONT, tracee.0, 0, 0) },
            0
        );
        let mut status = 0;
        assert_eq!(
            unsafe { libc::waitpid(tracee.0, &mut status, libc::__WALL) },
            tracee.0
        );
        if libc::WIFEXITED(status) || libc::WIFSIGNALED(status) {
            tracee.0 = 0;
        }
        assert!(libc::WIFEXITED(status), "target must not stop at BRK again");
        assert_eq!(libc::WEXITSTATUS(status), 0);
    }

    #[test]
    fn unrelated_breakpoint_is_not_advanced() {
        let tracee = stopped(false);
        let error = advance_initial_stop(tracee.0).unwrap_err();
        assert!(error.contains("fixed launcher instruction"));
    }
}
