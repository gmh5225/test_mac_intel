/* Authored controls: create/close sockets only; no connections or host writes. */
#define _GNU_SOURCE
#include <errno.h>
#include <dirent.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <stdint.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <unistd.h>
#include "unix-block-bpf.h"

static void fail(const char *what) {
    perror(what);
    exit(70);
}

static void install_filter(void) {
    /* Copy into aligned sock_filter storage; the generated header is bytes. */
    struct sock_filter code[sizeof(unix_block_bpf) / sizeof(struct sock_filter)];
    _Static_assert(sizeof(unix_block_bpf) % sizeof(struct sock_filter) == 0,
                   "partial BPF instruction");
    memcpy(code, unix_block_bpf, sizeof(code));
    struct sock_fprog prog = {.len = sizeof(code) / sizeof(code[0]), .filter = code};
    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0) fail("no_new_privs");
    if (prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog) != 0) fail("seccomp");
}

static void socket_case(const char *name, uint64_t domain) {
    errno = 0;
    long result = syscall(SYS_socket, domain, SOCK_STREAM | SOCK_CLOEXEC, 0);
    int saved = errno;
    if (result >= 0 && close((int)result) != 0) fail("close");
    printf("{\"case\":\"%s\",\"result\":%d,\"errno\":%d},",
           name, result >= 0 ? 0 : -1, saved);
}

static void report(const char *mode) {
    printf("{\"mode\":\"%s\",\"no_new_privs\":%d,\"seccomp\":%d,\"cases\":[",
           mode, prctl(PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0), prctl(PR_GET_SECCOMP));
    socket_case("unix", AF_UNIX);
    socket_case("unix-high-bits", UINT64_C(0x100000000) | AF_UNIX);
    socket_case("inet", AF_INET);
    socket_case("inet6", AF_INET6);
    int pair[2];
    errno = 0;
    int result = socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, pair);
    int saved = errno;
    if (result == 0) {
        if (close(pair[0]) != 0 || close(pair[1]) != 0) fail("close pair");
    }
    printf("{\"case\":\"unix-pair\",\"result\":%d,\"errno\":%d},", result, saved);
    /* Invalid/empty requests cannot create a ring or operate on a valid fd. */
    const long calls[] = {SYS_io_uring_setup, SYS_io_uring_enter, SYS_io_uring_register};
    const char *names[] = {"uring-setup", "uring-enter", "uring-register"};
    for (size_t i = 0; i < sizeof(calls) / sizeof(calls[0]); ++i) {
        errno = 0;
        long value = i == 0 ? syscall(calls[i], 0, NULL) :
            syscall(calls[i], -1, 0, 0, 0, NULL, 0);
        saved = errno;
        if (value >= 0) {
            if (i == 0) (void)close((int)value);
            fputs("invalid io_uring request unexpectedly succeeded\n", stderr);
            exit(71);
        }
        printf("{\"case\":\"%s\",\"result\":-1,\"errno\":%d}%s",
               names[i], saved, i == 2 ? "" : ",");
    }
    puts("]}");
}

static void process_state(void) {
    unsigned long long effective = 0, ambient = 0;
    int fields = 0;
    char line[512];
    FILE *status = fopen("/proc/self/status", "r");
    if (!status) fail("status");
    while (fgets(line, sizeof(line), status)) {
        if (sscanf(line, "CapEff: %llx", &effective) == 1) fields |= 1;
        if (sscanf(line, "CapAmb: %llx", &ambient) == 1) fields |= 2;
    }
    fclose(status);
    if (fields != 3) exit(73);
    char pid_ns[80], user_ns[80], mount_ns[80];
    char *values[] = {pid_ns, user_ns, mount_ns};
    const char *paths[] = {"/proc/self/ns/pid", "/proc/self/ns/user", "/proc/self/ns/mnt"};
    for (size_t i = 0; i < 3; ++i) {
        ssize_t n = readlink(paths[i], values[i], 79);
        if (n < 1 || n >= 79) fail("namespace link");
        values[i][n] = '\0';
    }
    DIR *proc = opendir("/proc");
    if (!proc) fail("proc directory");
    struct dirent *entry;
    int visible = 0;
    while ((entry = readdir(proc))) {
        if (entry->d_name[0] >= '1' && entry->d_name[0] <= '9' &&
            strspn(entry->d_name, "0123456789") == strlen(entry->d_name)) ++visible;
    }
    closedir(proc);
    printf("{\"pid\":%d,\"ppid\":%d,\"uid\":%d,\"gid\":%d,\"cap_effective\":%llu,"
           "\"cap_ambient\":%llu,\"no_new_privs\":%d,\"seccomp\":%d,\"visible_pids\":%d,"
           "\"pid_ns\":\"%s\",\"user_ns\":\"%s\",\"mount_ns\":\"%s\"}\n",
           (int)getpid(), (int)getppid(), (int)getuid(), (int)getgid(), effective, ambient,
           prctl(PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0), prctl(PR_GET_SECCOMP), visible,
           pid_ns, user_ns, mount_ns);
}

int main(int argc, char **argv) {
    if (argc != 2) return 64;
    if (strcmp(argv[1], "exit-37") == 0) return 37;
    if (strcmp(argv[1], "process-state") == 0) { process_state(); return 0; }
    if (strcmp(argv[1], "raise-term") == 0) { raise(SIGTERM); return 74; }
    if (strcmp(argv[1], "raise-kill") == 0) { raise(SIGKILL); return 74; }
    if (strcmp(argv[1], "malformed-filter") == 0) {
        struct sock_filter code = {.code = 0xffff};
        struct sock_fprog prog = {.len = 1, .filter = &code};
        if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0) fail("no_new_privs");
        errno = 0;
        int result = prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog);
        int saved = errno;
        printf("{\"case\":\"malformed-filter\",\"result\":%d,\"errno\":%d}\n",
               result, saved);
        return result == -1 && saved == EINVAL ? 0 : 72;
    }
    if (strcmp(argv[1], "filter") == 0 || strcmp(argv[1], "filter-exec") == 0) {
        install_filter();
        if (strcmp(argv[1], "filter-exec") == 0) {
            execl("/proc/self/exe", "seccomp-control", "inherited", (char *)NULL);
            fail("exec control");
        }
    } else if (strcmp(argv[1], "baseline") != 0 && strcmp(argv[1], "inherited") != 0) {
        return 64;
    }
    report(argv[1]);
    return 0;
}
