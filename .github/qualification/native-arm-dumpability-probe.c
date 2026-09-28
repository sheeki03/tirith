#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/ptrace.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#ifndef MFD_EXEC
#define MFD_EXEC 0x0010U
#endif
#ifndef F_SEAL_EXEC
#define F_SEAL_EXEC 0x0020
#endif

#define ELF_CAP (2 * 1024 * 1024)
#define MAGIC UINT64_C(0x5449524954484432)
#define SEALS (F_SEAL_WRITE | F_SEAL_GROW | F_SEAL_SHRINK | F_SEAL_SEAL | F_SEAL_EXEC)
static const char canary[] = "tirith-dumpability-canary-v1";
static int active_pid = -1;
static int active_reaped = 0;

struct frame {
    uint64_t magic;
    uint64_t address;
    int phase, pid, uid, gid, dumpable, executable_fd, canary_fd;
    int executable_closed, executable_mode, executable_seals;
};

static _Noreturn void child_fail(const char *stage) {
    dprintf(STDERR_FILENO, "probe child refused: %s errno=%d\n", stage, errno);
    _exit(71);
}

static int write_exact(int fd, const void *data, size_t size) {
    const char *p = data;
    while (size) {
        ssize_t n = write(fd, p, size);
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) return -1;
        p += n;
        size -= (size_t)n;
    }
    return 0;
}

static int receive_frame(int fd, struct frame *value) {
    memset(value, 0, sizeof(*value));
    size_t used = 0;
    // At most 5000 one-millisecond readiness waits for this fixed-size frame.
    for (int turn = 0; turn < 5000 && used < sizeof(*value); ++turn) {
        struct pollfd p = {.fd = fd, .events = POLLIN};
        int ready = poll(&p, 1, 1);
        if (ready < 0 && errno == EINTR) continue;
        if (ready < 0) return -1;
        if (!ready) continue;
        ssize_t n = read(fd, (char *)value + used, sizeof(*value) - used);
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) return -1;
        used += (size_t)n;
    }
    return used == sizeof(*value) && value->magic == MAGIC ? 0 : -1;
}

static int clean_child(void) {
    if (active_pid < 0 || active_reaped) return 0;
    // This PID is our unreaped fork child. No PID enumeration or reused-PID signal.
    siginfo_t info = {0};
    if (waitid(P_PID, (id_t)active_pid, &info, WEXITED | WNOHANG | WNOWAIT) != 0) return -1;
    if (!info.si_pid && kill(active_pid, SIGKILL) != 0) return -1;
    int status = 0;
    pid_t result;
    do { result = waitpid(active_pid, &status, 0); } while (result < 0 && errno == EINTR);
    if (result != active_pid) return -1;
    active_reaped = 1;
    printf("{\"owned_child_cleanup\":true,\"pid\":%d,\"raw_status\":%d}\n", active_pid, status);
    return 0;
}

static int fail(const char *stage) {
    fprintf(stderr, "probe refused: %s errno=%d\n", stage, errno);
    (void)clean_child();
    return 1;
}

static int fd_arg(const char *s) {
    if (!*s) return -1;
    unsigned value = 0;
    for (; *s; ++s) {
        if (*s < '0' || *s > '9' || value > 1024) return -1;
        value = value * 10 + (unsigned)(*s - '0');
    }
    return value >= 3 && value < 256 ? (int)value : -1;
}

static int post_exec(int argc, char **argv) {
    if (argc != 6) child_fail("post-exec argv");
    int output = fd_arg(argv[2]), input = fd_arg(argv[3]);
    int canary_fd = fd_arg(argv[4]), executable = fd_arg(argv[5]);
    if (output < 0 || input < 0 || canary_fd < 0 || executable < 0) child_fail("post-exec descriptors");
    // This is checked before opening anything after exec, so descriptor reuse cannot mask closure.
    errno = 0;
    int closed = fcntl(executable, F_GETFD) == -1 && errno == EBADF;
    struct stat info;
    if (fstat(canary_fd, &info) || !S_ISREG(info.st_mode) || (info.st_mode & 07777) != 0400 || info.st_uid != getuid()) child_fail("retained canary");
    struct frame value = {0};
    value.magic = MAGIC; value.address = (uint64_t)(uintptr_t)canary; value.phase = 2;
    value.pid = getpid(); value.uid = getuid(); value.gid = getgid();
    value.dumpable = prctl(PR_GET_DUMPABLE, 0, 0, 0, 0);
    value.executable_fd = executable; value.canary_fd = canary_fd; value.executable_closed = closed;
    if (write_exact(output, &value, sizeof(value))) child_fail("post-exec report");
    char command = 0;
    if (read(input, &command, 1) != 1 || command != 'X') child_fail("post-exec completion");
    _exit(0);
}

static _Noreturn void child_case(int output, int input, int mode, pid_t parent) {
    alarm(8); // SIGALRM terminates without generating a core if the parent protocol stalls.
    if (prctl(PR_SET_PDEATHSIG, SIGKILL, 0, 0, 0) || getppid() != parent) child_fail("parent lifetime");
    if (prctl(PR_SET_DUMPABLE, 0, 0, 0, 0) || prctl(PR_GET_DUMPABLE, 0, 0, 0, 0) != 0) child_fail("initial nondumpability");
    int source = open("/proc/self/exe", O_RDONLY | O_CLOEXEC);
    struct stat source_stat;
    if (source < 0 || fstat(source, &source_stat) || !S_ISREG(source_stat.st_mode) || source_stat.st_size <= 0 || source_stat.st_size > ELF_CAP) child_fail("held ELF source");
    int executable = (int)syscall(SYS_memfd_create, "tirith-owned-exec-probe", MFD_CLOEXEC | MFD_ALLOW_SEALING | MFD_EXEC);
    if (executable < 0) child_fail("private executable memfd");
    char buffer[16384];
    off_t copied = 0;
    while (copied < source_stat.st_size) {
        size_t wanted = (size_t)(source_stat.st_size - copied);
        if (wanted > sizeof(buffer)) wanted = sizeof(buffer);
        ssize_t count = pread(source, buffer, wanted, copied);
        if (count <= 0 || write_exact(executable, buffer, (size_t)count)) child_fail("bounded ELF copy");
        copied += count;
    }
    close(source);
    if (fchmod(executable, (mode_t)mode) || fcntl(executable, F_ADD_SEALS, SEALS) < 0) child_fail("execute inode seals");
    struct stat info;
    int seals = fcntl(executable, F_GET_SEALS);
    if (fstat(executable, &info) || info.st_uid != getuid() || (info.st_mode & 07777) != (mode_t)mode || info.st_size != copied || seals < 0 || (seals & SEALS) != SEALS || !(fcntl(executable, F_GETFD) & FD_CLOEXEC)) child_fail("execute inode validation");
    int canary_fd = (int)syscall(SYS_memfd_create, "tirith-owned-canary", MFD_CLOEXEC | MFD_ALLOW_SEALING);
    if (canary_fd < 0 || write_exact(canary_fd, canary, sizeof(canary)) || fchmod(canary_fd, 0400) || fcntl(canary_fd, F_ADD_SEALS, F_SEAL_WRITE | F_SEAL_GROW | F_SEAL_SHRINK | F_SEAL_SEAL) < 0) child_fail("canary input");
    if (fcntl(output, F_SETFD, 0) || fcntl(input, F_SETFD, 0) || fcntl(canary_fd, F_SETFD, 0)) child_fail("protocol inheritance");
    struct frame value = {0};
    value.magic = MAGIC; value.phase = 1; value.pid = getpid(); value.uid = getuid(); value.gid = getgid();
    value.dumpable = prctl(PR_GET_DUMPABLE, 0, 0, 0, 0); value.executable_fd = executable; value.canary_fd = canary_fd;
    value.executable_mode = mode; value.executable_seals = seals;
    if (write_exact(output, &value, sizeof(value))) child_fail("pre-exec report");
    char command = 0;
    if (read(input, &command, 1) != 1 || command != 'G') child_fail("pre-exec authorization");
    char out_arg[16], in_arg[16], canary_arg[16], exec_arg[16];
    snprintf(out_arg, sizeof(out_arg), "%d", output); snprintf(in_arg, sizeof(in_arg), "%d", input);
    snprintf(canary_arg, sizeof(canary_arg), "%d", canary_fd); snprintf(exec_arg, sizeof(exec_arg), "%d", executable);
    char *args[] = {"tirith-owned-exec-probe", "child", out_arg, in_arg, canary_arg, exec_arg, NULL};
    char *env[] = {"LANG=C", "PATH=/usr/bin:/bin", NULL};
    syscall(SYS_execveat, executable, "", args, env, AT_EMPTY_PATH);
    child_fail("execute-only execveat");
}

static int proc_open(pid_t pid, int fd, const char *suffix, int flags, int permit, int read_canary) {
    char path[96];
    if (fd >= 0) snprintf(path, sizeof(path), "/proc/%d/fd/%d", pid, fd);
    else snprintf(path, sizeof(path), "/proc/%d/%s", pid, suffix);
    errno = 0;
    int opened = open(path, flags | O_CLOEXEC);
    int error = errno;
    printf("{\"access\":\"%s\",\"fd\":%d,\"permit_expected\":%s,\"opened\":%s,\"errno\":%d}\n", suffix, fd, permit ? "true" : "false", opened >= 0 ? "true" : "false", error);
    if (opened < 0) return !permit && (error == EACCES || error == EPERM) ? 0 : -1;
    int okay = permit;
    if (permit && read_canary) {
        char got[sizeof(canary)];
        okay = pread(opened, got, sizeof(got), 0) == (ssize_t)sizeof(got) && !memcmp(got, canary, sizeof(got));
    }
    close(opened);
    return okay ? 0 : -1;
}

static int exe_readlink(pid_t pid, int permit) {
    char path[64], destination[128];
    snprintf(path, sizeof(path), "/proc/%d/exe", pid);
    errno = 0;
    ssize_t count = readlink(path, destination, sizeof(destination));
    int error = errno;
    printf("{\"exe_readlink\":%zd,\"errno\":%d,\"permit_expected\":%s}\n", count, error, permit ? "true" : "false");
    if (!permit) return count == -1 && (error == EACCES || error == EPERM) ? 0 : -1;
    return count > 0 && count < (ssize_t)sizeof(destination) ? 0 : -1;
}

static int ptrace_control(pid_t pid, int permit) {
    errno = 0;
    long result = ptrace(PTRACE_SEIZE, pid, NULL, NULL);
    int error = errno;
    printf("{\"ptrace_seize\":%ld,\"errno\":%d,\"permit_expected\":%s}\n", result, error, permit ? "true" : "false");
    if (result < 0) return !permit && error == EPERM ? 0 : -1;
    if (!permit) return -1;
    if (ptrace(PTRACE_INTERRUPT, pid, NULL, NULL)) return -1;
    for (int turn = 0; turn < 2000; ++turn) {
        siginfo_t info = {0};
        if (waitid(P_PID, (id_t)pid, &info, WSTOPPED | WEXITED | WNOHANG | WNOWAIT)) return -1;
        if (info.si_pid) {
            if (info.si_pid != pid || (info.si_code != CLD_TRAPPED && info.si_code != CLD_STOPPED)) return -1;
            return ptrace(PTRACE_DETACH, pid, NULL, NULL) ? -1 : 0;
        }
        struct timespec pause = {.tv_nsec = 1000000}; nanosleep(&pause, NULL);
    }
    return -1;
}

static int one_case(int mode) {
    int report_pipe[2], control_pipe[2];
    if (pipe2(report_pipe, O_CLOEXEC) || pipe2(control_pipe, O_CLOEXEC)) return fail("pipes");
    pid_t parent = getpid(), child = fork();
    if (child < 0) return fail("fork");
    if (child == 0) {
        close(report_pipe[0]); close(control_pipe[1]);
        child_case(report_pipe[1], control_pipe[0], mode, parent);
    }
    active_pid = child; active_reaped = 0;
    close(report_pipe[1]); close(control_pipe[0]);
    struct frame before, after;
    if (receive_frame(report_pipe[0], &before) || before.phase != 1 || before.pid != child || before.dumpable != 0 || before.uid != 65534 || before.gid != 65534 || before.executable_mode != mode || (before.executable_seals & SEALS) != SEALS) return fail("pre-exec frame");
    printf("{\"case_mode\":%d,\"phase\":\"preexec\",\"pid\":%d,\"dumpable\":%d,\"private_fd\":%d,\"canary_fd\":%d,\"seals\":%d}\n", mode, child, before.dumpable, before.executable_fd, before.canary_fd, before.executable_seals);
    if (proc_open(child, before.executable_fd, "private_preexec", O_PATH, 0, 0) || proc_open(child, before.canary_fd, "canary_preexec", O_RDONLY, 0, 0)) return fail("pre-exec private descriptor acquisition");
    if (write_exact(control_pipe[1], "G", 1) || receive_frame(report_pipe[0], &after)) return fail("exec acknowledgement");
    int permit = mode == 0500;
    if (after.phase != 2 || after.pid != child || after.uid != 65534 || after.gid != 65534 || after.dumpable != (permit ? 1 : 2) || !after.executable_closed || after.executable_fd != before.executable_fd || after.canary_fd != before.canary_fd || !after.address) return fail("post-exec dumpability or CLOEXEC");
    printf("{\"case_mode\":%d,\"phase\":\"postexec\",\"pid\":%d,\"dumpable\":%d,\"executable_cloexec_confirmed\":true}\n", mode, child, after.dumpable);
    if (exe_readlink(child, permit) || proc_open(child, after.canary_fd, "canary_postexec", O_RDONLY, permit, 1) || proc_open(child, -1, "exe", O_PATH, permit, 0) || proc_open(child, -1, "mem", O_RDONLY, permit, 0)) return fail("post-exec proc acquisition");
    char got[sizeof(canary)] = {0};
    struct iovec local = {.iov_base = got, .iov_len = sizeof(got)};
    struct iovec remote = {.iov_base = (void *)(uintptr_t)after.address, .iov_len = sizeof(got)};
    errno = 0;
    ssize_t read_count = process_vm_readv(child, &local, 1, &remote, 1, 0);
    int error = errno;
    printf("{\"process_vm_readv\":%zd,\"errno\":%d,\"permit_expected\":%s}\n", read_count, error, permit ? "true" : "false");
    if (permit ? (read_count != (ssize_t)sizeof(got) || memcmp(got, canary, sizeof(got))) : (read_count != -1 || error != EPERM)) return fail("same-UID memory acquisition");
    if (ptrace_control(child, permit)) return fail("same-UID ptrace control or external LSM mask");
    if (write_exact(control_pipe[1], "X", 1)) return fail("completion request");
    siginfo_t info = {0};
    for (int turn = 0; turn < 2000; ++turn) {
        if (waitid(P_PID, (id_t)child, &info, WEXITED | WNOHANG | WNOWAIT)) return fail("normal exit observation");
        if (info.si_pid) break;
        struct timespec pause = {.tv_nsec = 1000000}; nanosleep(&pause, NULL);
    }
    if (info.si_pid != child || info.si_code != CLD_EXITED || info.si_status != 0) return fail("normal exit status");
    char trailing = 0;
    struct pollfd p = {.fd = report_pipe[0], .events = POLLIN};
    if (poll(&p, 1, 100) <= 0 || read(report_pipe[0], &trailing, 1) != 0) return fail("report EOF");
    if (clean_child()) return fail("owned child reap");
    close(report_pipe[0]); close(control_pipe[1]);
    printf("{\"case_mode\":%d,\"passed\":true,\"normal_exit\":true,\"report_eof\":true}\n", mode);
    return 0;
}

int main(int argc, char **argv) {
    if (getuid() != 65534 || geteuid() != 65534 || getgid() != 65534 || getegid() != 65534 || prctl(PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0) != 1) return fail("unprivileged runtime identity");
    if (argc > 1 && !strcmp(argv[1], "child")) return post_exec(argc, argv);
    if (argc != 1) return fail("fixed invocation only");
    signal(SIGPIPE, SIG_IGN);
    char policy[4] = {0};
    int fd = open("/proc/sys/fs/suid_dumpable", O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0 || read(fd, policy, sizeof(policy)) != 2 || memcmp(policy, "2\n", 2)) return fail("this control requires observed unmodified mode 2");
    close(fd);
    printf("{\"host_suid_dumpable\":2,\"uid\":65534,\"no_new_privs\":true,\"intentional_core_generation\":false}\n");
    if (one_case(0500) || one_case(0100)) return 1;
    puts("{\"passed\":true,\"case_count\":2,\"same_uid_controls\":true,\"product_qualification\":false}");
    return 0;
}
