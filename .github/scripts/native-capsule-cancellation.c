#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <ftw.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

static pid_t target_pid, descendant_pid, group_pid;
static char marker[128];

static int find_marker(const char *path, const struct stat *st, int type, struct FTW *walk) {
    (void)walk;
    const char *leaf = strrchr(path, '/');
    if (type != FTW_F || !S_ISREG(st->st_mode) || !leaf || strcmp(leaf + 1, marker)) return 0;
    FILE *input = fopen(path, "r");
    int fields = input ? fscanf(input, "%d %d %d", &target_pid, &descendant_pid, &group_pid) : 0;
    if (input) fclose(input);
    return fields == 3 ? 1 : 0;
}

static int not_running(pid_t pid) {
    char path[64], line[4096];
    snprintf(path, sizeof(path), "/proc/%d/stat", pid);
    FILE *input = fopen(path, "r");
    if (!input) return errno == ENOENT;
    char *got = fgets(line, sizeof(line), input);
    fclose(input);
    char *end = got ? strrchr(line, ')') : NULL;
    return end && (end[2] == 'Z' || end[2] == 'X');
}

static void tick(void) {
    struct timespec interval = {0, 10000000};
    while (nanosleep(&interval, &interval) && errno == EINTR) {}
}

int main(int argc, char **argv) {
    if (argc == 3 && !strcmp(argv[1], "live")) {
        if (strlen(argv[2]) >= sizeof(marker) || strchr(argv[2], '/')) return 69;
        snprintf(marker, sizeof(marker), "%s", argv[2]);
        pid_t descendant = fork();
        if (descendant < 0) return 70;
        if (descendant == 0) { for (;;) { __asm__ __volatile__("" ::: "memory"); } }
        int fd = open(marker, O_WRONLY | O_CREAT | O_EXCL, 0600);
        if (fd < 0 || dprintf(fd, "%d %d %d\n", getpid(), descendant, getpgrp()) < 0) return 71;
        close(fd);
        for (;;) { __asm__ __volatile__("" ::: "memory"); }
    }
    if (argc != 4) return 72;
    snprintf(marker, sizeof(marker), "tirith-qualification-running-%ld.pid", (long)getpid());
    int guard = !strcmp(argv[1], "guard_kill");
    int early = !strcmp(argv[1], "before_exec");
    int signal = !strcmp(argv[1], "parent_term") ? SIGTERM : SIGKILL;
    if (!guard && !early && strcmp(argv[1], "parent_term") && strcmp(argv[1], "parent_kill")) return 73;
    pid_t supervisor = fork();
    if (supervisor < 0) return 74;
    if (supervisor == 0) {
        int output = open("/dev/null", O_WRONLY);
        if (output < 0 || dup2(output, STDOUT_FILENO) < 0) _exit(75);
        close(output);
        execl(argv[2], argv[2], "capsule", "run", "--format", "json", "--project", argv[3], "--", "./cancel-probe", "live", marker, (char *)NULL);
        _exit(76);
    }
    if (!early) {
        for (unsigned n = 0; n < 12000; ++n) {
            if (nftw("/tmp", find_marker, 16, FTW_PHYS) == 1) break;
            if (not_running(supervisor)) break;
            tick();
        }
        if (target_pid <= 1 || descendant_pid <= 1 || group_pid <= 1 || group_pid == getpgrp()) {
            kill(supervisor, SIGKILL);
            waitpid(supervisor, NULL, 0);
            fprintf(stderr, "contained target tree did not become ready\n");
            return 77;
        }
    }
    pid_t interrupted = guard ? group_pid : supervisor;
    if (kill(interrupted, signal)) return 78;
    int stopped = 0;
    for (unsigned n = 0; n < 1000; ++n) {
        stopped = not_running(supervisor) && (early || (not_running(target_pid) && not_running(descendant_pid) && not_running(group_pid)));
        if (stopped) break;
        tick();
    }
    if (early) {
        int found = nftw("/tmp", find_marker, 16, FTW_PHYS) == 1;
        stopped = stopped && !found;
    }
    // Own fixture cleanup remains mandatory even when the production assertion
    // fails. These PIDs are from this isolated child and its still-held group.
    if (!stopped && group_pid > 1 && group_pid != getpgrp()) kill(-group_pid, SIGKILL);
    if (!not_running(supervisor)) kill(supervisor, SIGKILL);
    int status = 0;
    while (waitpid(supervisor, &status, 0) < 0 && errno == EINTR) {}
    printf("{\"case\":\"%s\",\"passed\":%s,\"process_tree_stopped\":%s,\"supervisor_status\":%d,\"target_pid\":%d,\"descendant_pid\":%d,\"guard_pid\":%d}\n", argv[1], stopped ? "true" : "false", stopped ? "true" : "false", status, target_pid, descendant_pid, group_pid);
    return stopped ? 0 : 1;
}
