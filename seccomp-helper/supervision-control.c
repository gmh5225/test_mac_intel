/* Authored native controls. Signals target only a forked child of this driver;
 * all sockets and filesystem operations stay in the disposable test boundary. */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

static void fail(const char *label) { perror(label); exit(70); }
static void need(int ok, const char *label) { if (!ok) fail(label); }
static int ready_fd(void) {
    const char *value = getenv("NEVERD_READY_FD");
    need(value && strspn(value, "0123456789") == strlen(value), "ready descriptor");
    int fd = atoi(value); need(fd >= 3 && fd < 256, "ready range"); return fd;
}
static void ready(void) {
    int fd = ready_fd();
    need(write(fd, "R", 1) == 1, "ready write");
    need(close(fd) == 0, "ready close");
}
static int wait_code(pid_t child) {
    int status;
    while (waitpid(child, &status, 0) < 0) if (errno != EINTR) fail("waitpid");
    return WIFEXITED(status) ? WEXITSTATUS(status) : WIFSIGNALED(status) ? 128 + WTERMSIG(status) : 255;
}
static unsigned long long caught(pid_t pid) {
    char path[96], line[512]; unsigned long long mask = 0;
    snprintf(path, sizeof(path), "/proc/%d/status", (int)pid);
    FILE *file = fopen(path, "r"); if (!file) return 0;
    while (fgets(line, sizeof(line), file)) if (sscanf(line, "SigCgt: %llx", &mask) == 1) break;
    fclose(file); return mask;
}
static pid_t only_child(pid_t pid) {
    char path[128]; int first = 0, second = 0;
    snprintf(path, sizeof(path), "/proc/%d/task/%d/children", (int)pid, (int)pid);
    FILE *file = fopen(path, "r"); if (!file) return -1;
    int fields = fscanf(file, "%d %d", &first, &second); fclose(file);
    return fields == 1 && first > 0 ? first : -1;
}
static void child_exec(const char *helper, const char *mode, const char *option, int ready_pipe[2], const char *observe) {
    close(ready_pipe[0]);
    char fd[16]; snprintf(fd, sizeof(fd), "%d", ready_pipe[1]);
    need(setenv("NEVERD_READY_FD", fd, 1) == 0, "ready environment");
    need(setenv("ARGV0", "apply-seccomp", 1) == 0, "role environment");
    if (observe) {
        need(setenv("SRT_OBSERVE_SOCK", observe, 1) == 0, "observe environment");
        if (strcmp(option, "no-encoded") != 0)
            need(setenv("SRT_ENCODED_CMD", "fixture%20command", 1) == 0, "encoded environment");
    }
    execl(helper, helper, "/runtime/supervision-control", mode, option, (char *)NULL);
    fail("helper exec");
}
static void await_ready(int ready_pipe[2]) {
    close(ready_pipe[1]); struct pollfd p = {.fd = ready_pipe[0], .events = POLLIN};
    need(poll(&p, 1, 10000) == 1 && (p.revents & POLLIN), "worker ready timeout");
    char c; need(read(p.fd, &c, 1) == 1 && c == 'R', "worker ready marker"); close(p.fd);
}
static void signal_received(int sig) {
    /* async-signal-safe output with the number encoded in one byte. */
    char message[] = "received signal 00\n";
    message[16] = (char)('0' + sig / 10); message[17] = (char)('0' + sig % 10);
    (void)!write(STDOUT_FILENO, message, sizeof(message) - 1);
    _exit(37);
}
static int signal_payload(const char *option) {
    if (strcmp(option, "caught") == 0) {
        const int signals[] = {SIGTERM, SIGINT, SIGHUP, SIGQUIT, SIGUSR1, SIGUSR2};
        for (size_t i = 0; i < sizeof(signals) / sizeof(signals[0]); ++i) {
            struct sigaction action = {.sa_handler = signal_received}; sigemptyset(&action.sa_mask);
            need(sigaction(signals[i], &action, NULL) == 0, "payload handler");
        }
    } else need(strcmp(option, "default") == 0, "signal option");
    ready(); for (;;) pause();
    return 74;
}
static int signal_driver(const char *helper, const char *number, const char *option) {
    int sig = atoi(number); const int signals[] = {SIGTERM, SIGINT, SIGHUP, SIGQUIT, SIGUSR1, SIGUSR2};
    unsigned long long mask = 0; int valid = 0;
    for (size_t i = 0; i < sizeof(signals) / sizeof(signals[0]); ++i) {
        mask |= 1ULL << (signals[i] - 1); valid |= sig == signals[i];
    }
    need(valid, "signal number");
    int pipefd[2]; need(pipe(pipefd) == 0, "ready pipe");
    pid_t helper_pid = fork(); need(helper_pid >= 0, "fork helper");
    if (helper_pid == 0) child_exec(helper, "signal-payload", option, pipefd, NULL);
    await_ready(pipefd);
    /* Readiness proves exec reached the workload; independently wait until
     * both supervisors installed every forwarder, avoiding a scheduling race. */
    struct timespec tick = {.tv_sec = 0, .tv_nsec = 1000000}; pid_t init = -1, worker = -1;
    for (int i = 0; i < 5000; ++i) {
        init = only_child(helper_pid); worker = init > 0 ? only_child(init) : -1;
        if (worker > 0 && (caught(helper_pid) & mask) == mask && (caught(init) & mask) == mask) break;
        nanosleep(&tick, NULL);
    }
    need(worker > 0 && (caught(helper_pid) & mask) == mask && (caught(init) & mask) == mask, "forwarders ready");
    need(kill(helper_pid, sig) == 0, "external signal to owned helper");
    int code = wait_code(helper_pid);
    need(kill(worker, 0) == -1 && errno == ESRCH, "worker disappeared");
    printf("{\"external_signal\":%d,\"delivery\":\"%s\",\"helper_exit\":%d,\"worker_gone\":true,\"both_forwarders_ready\":true}\n", sig, option, code);
    return code == (strcmp(option, "caught") == 0 ? 37 : 128 + sig) ? 0 : 71;
}
static void close_checked(long fd) { need(fd >= 0 && close((int)fd) == 0, "close syscall result"); }
static int observer_payload(const char *option) {
    need(!getenv("SRT_OBSERVE_SOCK") && !getenv("SRT_ENCODED_CMD"), "observer variables removed");
    ready();
    const char *gate_value = getenv("NEVERD_GATE_FD"); need(gate_value != NULL, "observer gate descriptor");
    int gate = atoi(gate_value); char marker;
    need(gate >= 3 && gate < 256 && read(gate, &marker, 1) == 1 && marker == 'G', "observer gate");
    close(gate);
    long fd = syscall(SYS_openat, AT_FDCWD, "/work/read-only", O_RDONLY, 0); close_checked(fd);
    fd = syscall(SYS_openat, AT_FDCWD, "/work/absolute\"line\n", O_WRONLY | O_CREAT | O_TRUNC, 0600);
    need(fd >= 0 && write((int)fd, "one\n", 4) == 4, "write fixture"); close_checked(fd);
    fd = syscall(SYS_openat, AT_FDCWD, "relative", O_WRONLY | O_CREAT | O_TRUNC, 0600); close_checked(fd);
    need(syscall(SYS_mkdirat, AT_FDCWD, "directory", 0700) == 0, "mkdirat fixture");
    long dir = syscall(SYS_openat, AT_FDCWD, "directory", O_RDONLY | O_DIRECTORY, 0); need(dir >= 0, "directory descriptor");
    fd = syscall(SYS_openat, dir, "by-fd", O_WRONLY | O_CREAT | O_TRUNC, 0600); close_checked(fd);
    need(syscall(SYS_symlinkat, "relative", AT_FDCWD, "symlink") == 0, "symlinkat fixture");
    need(syscall(SYS_linkat, AT_FDCWD, "relative", dir, "hardlink", 0) == 0, "linkat fixture");
    need(syscall(SYS_renameat2, dir, "by-fd", dir, "renamed", 0) == 0, "renameat2 fixture");
    need(syscall(SYS_fchmodat, dir, "renamed", 0640) == 0, "fchmodat fixture");
    need(syscall(SYS_unlinkat, AT_FDCWD, "symlink", 0) == 0, "unlinkat fixture");
    need(syscall(SYS_unlinkat, dir, "hardlink", 0) == 0, "unlinkat hardlink");
    close_checked(dir);
    errno = 0; fd = syscall(SYS_openat, AT_FDCWD, "/runtime/forbidden", O_WRONLY | O_CREAT, 0600);
    need(fd == -1 && errno == EROFS, "read-only enforcement remains active");
    if (strcmp(option, "backpressure") == 0) for (int i = 0; i < 8192; ++i) {
        fd = syscall(SYS_openat, AT_FDCWD, "/work/relative", O_WRONLY, 0); close_checked(fd);
    }
    puts("{\"payload_complete\":true,\"observer_environment_removed\":true,\"readonly_errno\":30}");
    return 37;
}
static int observer_driver(const char *helper, const char *option) {
    const char *socket_path = strcmp(option, "missing") == 0 ? "/work/missing.sock" : "/work/observe.sock";
    int listener = -1;
    if (strcmp(option, "missing") != 0) {
        listener = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0); need(listener >= 0, "observer socket");
        int size = 1024; need(setsockopt(listener, SOL_SOCKET, SO_RCVBUF, &size, sizeof(size)) == 0, "observer buffer");
        struct sockaddr_un address = {.sun_family = AF_UNIX}; strcpy(address.sun_path, socket_path);
        need(bind(listener, (struct sockaddr *)&address, sizeof(address)) == 0 && listen(listener, 1) == 0, "observer listen");
    }
    int pipefd[2], gatefd[2]; need(pipe(pipefd) == 0 && pipe(gatefd) == 0, "observer pipes");
    pid_t child = fork(); need(child >= 0, "fork observed helper");
    if (child == 0) {
        if (listener >= 0) close(listener);
        close(gatefd[1]); char fd[16]; snprintf(fd, sizeof(fd), "%d", gatefd[0]);
        need(setenv("NEVERD_GATE_FD", fd, 1) == 0, "observer gate environment");
        child_exec(helper, "observer-payload", option, pipefd, socket_path);
    }
    close(gatefd[0]);
    int stream = -1;
    if (listener >= 0) {
        struct pollfd p = {.fd = listener, .events = POLLIN};
        need(poll(&p, 1, 10000) == 1 && (p.revents & POLLIN), "observe accept timeout");
        stream = accept4(listener, NULL, NULL, SOCK_CLOEXEC); need(stream >= 0, "observer accept"); close(listener);
    }
    await_ready(pipefd);
    pid_t init = only_child(child), worker = init > 0 ? only_child(init) : -1;
    need(worker > 0, "observed owned descendant");
    FILE *identity = fopen("/work/observer-worker.json", "wx"); need(identity != NULL, "observer identity");
    need(fprintf(identity, "{\"worker_pid\":%d,\"owned_descendant\":true}\n", (int)worker) > 0 && fclose(identity) == 0, "observer identity retention");
    int output = open("/work/events.jsonl", O_WRONLY | O_CREAT | O_EXCL, 0600); need(output >= 0, "event file");
    if (strcmp(option, "drop") == 0) { need(shutdown(stream, SHUT_RDWR) == 0, "drop observer"); close(stream); stream = -1; }
    need(write(gatefd[1], "G", 1) == 1 && close(gatefd[1]) == 0, "observer release");
    int code;
    if (strcmp(option, "backpressure") == 0) {
        /* Reap before reading: an implementation that blocks on telemetry
         * cannot complete. The outer harness bounds this driver as well. */
        code = wait_code(child);
    } else code = -1;
    if (stream >= 0) {
        char data[4096]; size_t total = 0;
        for (;;) {
            struct pollfd p = {.fd = stream, .events = POLLIN};
            need(poll(&p, 1, 10000) == 1, "event drain timeout");
            ssize_t count = read(stream, data, sizeof(data));
            if (count == 0) break;
            need(count > 0 && (total += (size_t)count) <= 2 * 1024 * 1024, "event budget");
            need(write(output, data, (size_t)count) == count, "event retention");
        }
        close(stream);
    }
    need(close(output) == 0, "event file close");
    if (code < 0) code = wait_code(child);
    printf("{\"observer_mode\":\"%s\",\"helper_exit\":%d}\n", option, code);
    return code == 37 ? 0 : 72;
}
int main(int argc, char **argv) {
    alarm(25);
    if (argc == 3 && strcmp(argv[1], "signal-payload") == 0) return signal_payload(argv[2]);
    if (argc == 5 && strcmp(argv[1], "signal-driver") == 0) return signal_driver(argv[2], argv[3], argv[4]);
    if (argc == 3 && strcmp(argv[1], "observer-payload") == 0) return observer_payload(argv[2]);
    if (argc == 4 && strcmp(argv[1], "observer-driver") == 0) return observer_driver(argv[2], argv[3]);
    return 64;
}
