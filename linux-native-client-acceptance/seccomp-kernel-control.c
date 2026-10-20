/* Owned syscall control. Creates an unconnected socket; never opens a device. */
#define _GNU_SOURCE
#include <errno.h>
#include <linux/audit.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/utsname.h>
#include <unistd.h>

#if defined(__x86_64__)
#define EXPECTED_ARCH AUDIT_ARCH_X86_64
#define CPU "x86_64"
#elif defined(__aarch64__)
#define EXPECTED_ARCH AUDIT_ARCH_AARCH64
#define CPU "aarch64"
#else
#error Unsupported control architecture
#endif

int main(int argc, char **argv) {
    if (argc != 2) return 64;
    struct utsname system;
    if (uname(&system) != 0) return 65;
    const char *mode = argv[1];
    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0) return 66;
    struct sock_filter code[] = {
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, arch)),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, EXPECTED_ARCH, 1, 0),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS),
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, nr)),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_getpid, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | 123),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
    };
    struct sock_fprog program = {.len = sizeof(code) / sizeof(code[0]), .filter = code};
    int result = 0, saved = 0;
    if (strcmp(mode, "malformed") == 0) {
        struct sock_filter invalid = {.code = 0xffff};
        struct sock_fprog bad = {.len = 1, .filter = &invalid};
        errno = 0;
        result = prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &bad);
        saved = errno;
        printf("{\"mode\":\"malformed\",\"result\":%d,\"errno\":%d}\n", result, saved);
        return result == -1 && saved == EINVAL ? 0 : 67;
    }
    if (strcmp(mode, "prctl") == 0 || strcmp(mode, "exec") == 0 || strcmp(mode, "syscall") == 0) {
        errno = 0;
        result = strcmp(mode, "syscall") == 0 ?
            (int)syscall(SYS_seccomp, SECCOMP_SET_MODE_FILTER, 0, &program) :
            prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &program);
        saved = errno;
        if (result != 0) {
            printf("{\"mode\":\"%s\",\"install_result\":%d,\"install_errno\":%d}\n", mode, result, saved);
            return 68;
        }
        if (strcmp(mode, "exec") == 0) {
            execl("/proc/self/exe", "owned-seccomp-control", "inherited", (char *)NULL);
            return 69;
        }
    } else if (strcmp(mode, "baseline") != 0 && strcmp(mode, "inherited") != 0) return 64;
    errno = 0;
    long pid = syscall(SYS_getpid);
    int pid_errno = errno;
    errno = 0;
    int socket_fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    int socket_errno = errno;
    if (socket_fd >= 0 && close(socket_fd) != 0) return 70;
    int active = prctl(PR_GET_SECCOMP, 0, 0, 0, 0);
    printf("{\"mode\":\"%s\",\"compiled_cpu\":\"%s\",\"kernel_cpu\":\"%s\","
           "\"pid_result\":%d,\"pid_errno\":%d,\"socket_result\":%d,\"socket_errno\":%d,"
           "\"no_new_privs\":%d,\"seccomp_mode\":%d}\n", mode, CPU, system.machine,
           pid >= 0 ? 0 : -1, pid_errno, socket_fd >= 0 ? 0 : -1, socket_errno,
           prctl(PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0), active);
    int filtered = strcmp(mode, "baseline") != 0;
    return pid_errno == (filtered ? 123 : 0) && (pid < 0) == filtered &&
           socket_fd >= 0 && socket_errno == 0 && (!filtered || active == 2) ? 0 : 71;
}
