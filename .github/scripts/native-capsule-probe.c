#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <poll.h>
#include <time.h>
#include <sys/epoll.h>
#include <sys/eventfd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/ptrace.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>
static int denied(long rc) { return rc < 0 && (errno == EPERM || errno == EACCES); }
int main(int argc, char **argv) {
    if (argc < 2) return 90;
    if (!strcmp(argv[1], "driver-inherit")) {
        if(argc < 5)return 80;
        int file=open(argv[2],O_RDONLY); if(file<0)return 81;
        int socket_fd=socket(AF_INET,SOCK_DGRAM,0); if(socket_fd<0)return 82;
        if(dup2(file,198)!=198 || dup2(socket_fd,197)!=197)return 83;
        close(file); close(socket_fd);
        execv(argv[3],argv+3); return 84;
    }
    if (!strcmp(argv[1], "inherited")) {
        for(int fd=197;fd<=198;++fd) {
            errno=0; if(fcntl(fd,F_GETFD)!=-1 || errno!=EBADF)return 85;
        }
        return 0;
    }
    if (!strcmp(argv[1], "network")) {
        int families[] = {AF_INET, AF_INET6, AF_UNIX};
        for (unsigned i=0; i<3; ++i) { errno=0; long fd=syscall(SYS_socket,families[i],SOCK_STREAM,0); if (!denied(fd)) return 10+i; }
        int pair[2]; errno=0; if (!denied(socketpair(AF_UNIX,SOCK_STREAM,0,pair))) return 14;
        errno=0; if (!denied(syscall(SYS_io_uring_setup,1,NULL))) return 15;
        return 0;
    }
    if (!strcmp(argv[1], "escape")) {
        errno=0; if (!denied(setsid())) return 20;
        errno=0; if (!denied(setpgid(0,0))) return 21;
        errno=0; if (!denied(syscall(SYS_unshare,0x10000000))) return 22;
        errno=0; if (!denied(ptrace(PTRACE_ATTACH,getpid(),0,0))) return 23;
        return 0;
    }
    if (!strcmp(argv[1], "filesystem")) {
        if(argc!=4) return 30;
        errno=0; if (!denied(open(argv[2],O_RDONLY))) return 31;
        errno=0; if (!denied(open(argv[3],O_WRONLY|O_TRUNC))) return 32;
        if(getenv("GITHUB_TOKEN")) return 33;
        int fd=open("written.txt",O_WRONLY|O_CREAT|O_EXCL,0600); if(fd<0)return 34;
        if(write(fd,"contained\n",10)!=10) return 35;
        close(fd);
        return 0;
    }
    if (!strcmp(argv[1], "resources")) {
        struct rlimit memory, files; if(getrlimit(RLIMIT_AS,&memory)||getrlimit(RLIMIT_NOFILE,&files))return 40;
        if(memory.rlim_cur>2UL*1024*1024*1024 || files.rlim_cur>256)return 41;
        errno=0; void* p=mmap(NULL,4UL*1024*1024*1024,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANONYMOUS,-1,0);
        if(p!=MAP_FAILED || errno!=ENOMEM)return 42;
        int opened[300], count=0; while(count<300) { int fd=open("README.md",O_RDONLY); if(fd<0)break; opened[count++]=fd; }
        int exhausted=(count>0 && count<300 && errno==EMFILE); while(count)close(opened[--count]); return exhausted?0:43;
    }
    if (!strcmp(argv[1], "readiness")) {
        struct timespec duration = {0, 1000000};
        if (nanosleep(&duration, NULL) || clock_nanosleep(CLOCK_MONOTONIC, 0, &duration, NULL)) return 47;
        int ep = epoll_create1(EPOLL_CLOEXEC), event = eventfd(0, EFD_CLOEXEC | EFD_NONBLOCK);
        if (ep < 0 || event < 0) return 48;
        struct epoll_event interest = {.events = EPOLLIN, .data.u64 = 7}, observed = {0};
        unsigned long long ready = 1;
        if (epoll_ctl(ep, EPOLL_CTL_ADD, event, &interest) || write(event, &ready, 8) != 8) return 49;
        if (epoll_pwait(ep, &observed, 1, 100, NULL) != 1 || observed.data.u64 != 7) return 51;
        struct pollfd poll = {.fd = event, .events = POLLIN};
        if (ppoll(&poll, 1, &duration, NULL) != 1 || !(poll.revents & POLLIN)) return 52;
        close(event); close(ep); return 0;
    }
    if (!strcmp(argv[1], "process_limit")) {
        struct rlimit processes;
        if (getrlimit(RLIMIT_NPROC, &processes) || processes.rlim_cur > 256) return 44;
        int gate[2]; if (pipe(gate)) return 45;
        pid_t children[512]; unsigned count = 0;
        while (count < 512) {
            pid_t child = fork();
            if (child < 0) break;
            if (child == 0) { char byte; close(gate[1]); while (read(gate[0], &byte, 1) < 0 && errno == EINTR) {} _exit(0); }
            children[count++] = child;
        }
        int exhausted = count > 0 && count < 512 && errno == EAGAIN;
        close(gate[1]); close(gate[0]);
        for (unsigned n = 0; n < count; ++n) { int status = 0; while (waitpid(children[n], &status, 0) < 0 && errno == EINTR) {} if (status) exhausted = 0; }
        return exhausted ? 0 : 46;
    }
    if (!strcmp(argv[1], "output")) { char buffer[4096]; memset(buffer,'x',sizeof(buffer)); for(unsigned i=0;i<8192;++i) { if(write(1,buffer,sizeof(buffer))<0)return 0; } return 50; }
    if (!strcmp(argv[1], "fork")) { pid_t child=fork(); if(child<0)return 60; if(child==0)_exit(0); int status=0; if(waitpid(child,&status,0)!=child)return 61; return status?62:0; }
    return 99;
}
