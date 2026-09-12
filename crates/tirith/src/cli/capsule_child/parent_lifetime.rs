//! Bind the contained process group to the thread that spawned its supervisor.
//!
//! Linux clears PDEATHSIG on fork, so protecting only the direct target leaves
//! its descendants alive when the outer supervisor disappears. The guard keeps
//! an armed parent-death handler that kills its own immutable process group.

const PARENT_DEATH_SIGNAL: libc::c_int = libc::SIGUSR1;

/// Run in the fork child, before exec, while Command::spawn keeps the creating
/// thread waiting on its private exec-status pipe. The kernel subsequently also
/// treats termination of that creating thread as cancellation, even if sibling
/// threads in the supervisor remain alive.
pub(crate) fn arm_before_exec(expected_parent: libc::pid_t) -> std::io::Result<()> {
    // SAFETY: scalar async-signal-safe Linux operations; no allocation or locks.
    if unsafe { libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL, 0, 0, 0) } != 0 {
        return Err(std::io::Error::last_os_error());
    }
    if expected_parent <= 0 || unsafe { libc::getppid() } != expected_parent {
        return Err(std::io::Error::from_raw_os_error(libc::ECHILD));
    }
    Ok(())
}

extern "C" fn terminate_own_group(_: libc::c_int) {
    // The guard is its group leader before arming, and containment forbids group
    // changes. kill(0, SIGKILL) cannot address another group or a recycled PID.
    // No Rust runtime, formatting, allocation, or mutex is used in this handler.
    unsafe {
        libc::kill(0, libc::SIGKILL);
        libc::_exit(125);
    }
}

/// Upgrade the pre-exec bootstrap before containment or any target fork.
/// A raw hidden-launcher invocation without the bootstrap fails closed.
pub(super) fn arm_group_guard() -> std::io::Result<()> {
    let parent = unsafe { libc::getppid() };
    let self_pid = unsafe { libc::getpid() };
    let mut bootstrap = 0;
    if parent <= 0
        || self_pid <= 0
        || unsafe { libc::getpgrp() } != self_pid
        || unsafe { libc::prctl(libc::PR_GET_PDEATHSIG, &mut bootstrap, 0, 0, 0) } != 0
        || bootstrap != libc::SIGKILL
    {
        return Err(std::io::Error::from_raw_os_error(libc::ECHILD));
    }
    // SIGKILL remains armed throughout handler installation and unblocking. If
    // the parent dies in this transition, no target exists yet. After switching,
    // the handler kills every process in the contained group, including forks.
    let mut action: libc::sigaction = unsafe { std::mem::zeroed() };
    action.sa_sigaction = terminate_own_group as *const () as usize;
    action.sa_flags = libc::SA_RESTART;
    let mut unblocked: libc::sigset_t = unsafe { std::mem::zeroed() };
    if unsafe { libc::sigemptyset(&mut action.sa_mask) } != 0
        || unsafe { libc::sigaction(PARENT_DEATH_SIGNAL, &action, std::ptr::null_mut()) } != 0
        || unsafe { libc::sigemptyset(&mut unblocked) } != 0
        || unsafe { libc::sigaddset(&mut unblocked, PARENT_DEATH_SIGNAL) } != 0
        || unsafe { libc::sigprocmask(libc::SIG_UNBLOCK, &unblocked, std::ptr::null_mut()) } != 0
        || unsafe { libc::prctl(libc::PR_SET_PDEATHSIG, PARENT_DEATH_SIGNAL, 0, 0, 0) } != 0
    {
        return Err(std::io::Error::last_os_error());
    }
    if unsafe { libc::getppid() } != parent {
        return Err(std::io::Error::from_raw_os_error(libc::ECHILD));
    }
    Ok(())
}

/// Verify the original lifetime binding after user/mount namespace setup and
/// before containment or target fork. A cleared binding refuses; learning a new
/// parent here could accept a child whose actual supervisor already died.
pub(super) fn revalidate_group_guard(expected_parent: libc::pid_t) -> std::io::Result<()> {
    let mut signal = 0;
    if expected_parent <= 0
        || unsafe { libc::getppid() } != expected_parent
        || unsafe { libc::getpgrp() } != unsafe { libc::getpid() }
        || unsafe { libc::prctl(libc::PR_GET_PDEATHSIG, &mut signal, 0, 0, 0) } != 0
        || signal != PARENT_DEATH_SIGNAL
    {
        return Err(std::io::Error::from_raw_os_error(libc::ECHILD));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn isolated_child(check: fn() -> bool) {
        // The post-fork branch uses only the scalar libc operations in this
        // module and _exit; it never re-enters the libtest runtime.
        let pid = unsafe { libc::fork() };
        assert!(pid >= 0, "fork lifetime fixture");
        if pid == 0 {
            unsafe { libc::_exit(if check() { 0 } else { 1 }) };
        }
        let mut status = 0;
        loop {
            let result = unsafe { libc::waitpid(pid, &mut status, 0) };
            if result == pid {
                break;
            }
            assert_eq!(
                std::io::Error::last_os_error().raw_os_error(),
                Some(libc::EINTR)
            );
        }
        assert!(libc::WIFEXITED(status));
        assert_eq!(libc::WEXITSTATUS(status), 0);
    }

    #[test]
    fn pre_exec_binding_requires_the_original_parent() {
        isolated_child(|| arm_before_exec(0).is_err());
    }

    #[test]
    fn group_guard_requires_an_armed_bootstrap() {
        isolated_child(|| (unsafe { libc::setpgid(0, 0) == 0 }) && arm_group_guard().is_err());
    }

    #[test]
    fn group_guard_upgrades_an_exact_parent_binding() {
        isolated_child(|| {
            let parent = unsafe { libc::getppid() };
            if unsafe { libc::setpgid(0, 0) } != 0
                || arm_before_exec(parent).is_err()
                || arm_group_guard().is_err()
            {
                return false;
            }
            let mut signal = 0;
            (unsafe { libc::prctl(libc::PR_GET_PDEATHSIG, &mut signal, 0, 0, 0) == 0 })
                && signal == PARENT_DEATH_SIGNAL
        });
    }
    #[test]
    fn namespace_revalidation_requires_original_parent_and_armed_signal() {
        isolated_child(|| {
            let parent = unsafe { libc::getppid() };
            if unsafe { libc::setpgid(0, 0) } != 0
                || arm_before_exec(parent).is_err()
                || arm_group_guard().is_err()
                || revalidate_group_guard(parent).is_err()
                || revalidate_group_guard(0).is_ok()
            {
                return false;
            }
            if unsafe { libc::prctl(libc::PR_SET_PDEATHSIG, 0, 0, 0, 0) } != 0 {
                return false;
            }
            revalidate_group_guard(parent).is_err()
        });
    }
}
