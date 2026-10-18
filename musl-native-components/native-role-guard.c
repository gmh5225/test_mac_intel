/* Authored additive seccomp boundary and exact argv[0] transport. */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <linux/audit.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#if defined(__aarch64__)
#define OWN_ARCH AUDIT_ARCH_AARCH64
#elif defined(__x86_64__)
#define OWN_ARCH AUDIT_ARCH_X86_64
#else
#error Unsupported native control architecture
#endif
#define REFUSE(nr) BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, (nr), 0, 1), BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | EPERM)
static int install(void) {
    struct sock_filter rules[] = {
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, arch)),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, OWN_ARCH, 1, 0),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS),
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, nr)),
        REFUSE(__NR_socket), REFUSE(__NR_socketpair), REFUSE(__NR_connect),
        REFUSE(__NR_bind), REFUSE(__NR_listen), REFUSE(__NR_accept),
        REFUSE(__NR_accept4), REFUSE(__NR_sendto), REFUSE(__NR_sendmsg),
#ifdef __NR_io_uring_setup
        REFUSE(__NR_io_uring_setup), REFUSE(__NR_io_uring_register), REFUSE(__NR_io_uring_enter),
#endif
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW)
    };
    struct sock_fprog program = { (unsigned short)(sizeof(rules)/sizeof(rules[0])), rules };
    return prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) || syscall(__NR_seccomp, SECCOMP_SET_MODE_FILTER, 0, &program);
}
int main(int argc, char **argv) {
    if (install()) { perror("owned additive filter"); return 70; }
    if (argc == 3 && strcmp(argv[1], "--probe") == 0) {
        int fd = open("/input/owned.txt", O_RDONLY); if (fd < 0) return 71;
        char byte; int readable = read(fd, &byte, 1) == 1; close(fd);
        fd = open(argv[2], O_RDONLY); int outside = errno;
        if (fd >= 0) return 72;
        fd = open("/etc/neverd-owned-forbidden", O_WRONLY | O_CREAT, 0600); int write = errno;
        if (fd >= 0) return 73;
        int net[4];
        for (int i = 0; i < 4; ++i) {
            fd = socket(i < 2 ? AF_INET : AF_INET6, i % 2 ? SOCK_DGRAM : SOCK_STREAM, 0); net[i] = errno;
            if (fd >= 0) return 74;
        }
        fd = socket(AF_UNIX, SOCK_STREAM, 0); int local = errno; if (fd >= 0) return 75;
        pid_t child = fork(); if (child < 0) return 80;
        if (child == 0) { execl("/bin/sh", "sh", "-c", "exit 99", (char *)NULL); _exit(errno == ENOENT ? 0 : 81); }
        int status; if (waitpid(child, &status, 0) != child || !WIFEXITED(status) || WEXITSTATUS(status) != 0) return 82;
        printf("{\"readable\":%d,\"outside_errno\":%d,\"write_errno\":%d,\"network_errno\":[%d,%d,%d,%d],\"unix_errno\":%d,\"shell_exec_refused\":true}\n",
            readable,outside,write,net[0],net[1],net[2],net[3],local);
        return readable && outside == ENOENT && write == EROFS && local == EPERM && net[0] == EPERM && net[1] == EPERM && net[2] == EPERM && net[3] == EPERM ? 0 : 76;
    }
    if (argc == 4 && strcmp(argv[1], "--receiver-probe") == 0) {
        char cwd[4096]; if (!getcwd(cwd, sizeof(cwd))) return 83;
        printf("owned receiver cwd=%s\nmarker=%s\npath=%s\n", cwd, argv[2], argv[3]);
        return 0;
    }
    if (argc >= 2 && strcmp(argv[1], "--argv-probe") == 0) {
        for (int i = 0; i < argc; ++i) {
            const unsigned char *p = (const unsigned char *)argv[i];
            while (*p) printf("%02x", (unsigned)*p++);
            putchar('\n');
        }
        return 0;
    }
    if (argc == 2 && strcmp(argv[1], "--flood-probe") == 0) {
        char buffer[4096]; memset(buffer, 'x', sizeof(buffer));
        for (;;) if (write(STDOUT_FILENO, buffer, sizeof(buffer)) <= 0) return 78;
    }
    if (argc == 2 && strcmp(argv[1], "--descendant-probe") == 0) {
        pid_t child = fork(); if (child < 0) return 79;
        if (child > 0) { printf("owned child %ld\n", (long)child); fflush(stdout); }
        for (;;) pause();
    }
    if (argc < 3) return 64;
    execv(argv[1], argv + 2); perror("owned exact role exec"); return 77;
}
