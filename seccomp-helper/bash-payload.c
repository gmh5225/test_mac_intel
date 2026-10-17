/* Authored workload: prove the Bash tool reached its enforced inner boundary. */
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <unistd.h>

static int different(const char *path, const char *environment) {
    char value[96]; ssize_t n = readlink(path, value, sizeof(value) - 1);
    const char *outer = getenv(environment);
    if (n <= 0 || n >= (ssize_t)sizeof(value) - 1 || !outer) return -1;
    value[n] = 0; return strcmp(value, outer) != 0;
}
int main(int argc, char **argv) {
    if (argc != 2 || (strcmp(argv[1], "policy") && strcmp(argv[1], "baseline"))) return 64;
    int sandboxed = strcmp(argv[1], "policy") == 0;
    errno = 0; int descriptor = fcntl(3, F_GETFD); int descriptor_errno = errno;
    errno = 0; int sock = socket(AF_UNIX, SOCK_STREAM, 0); int socket_errno = errno;
    if (sock >= 0) close(sock);
    int fd = open("/work/allowed", O_WRONLY | O_CREAT | O_EXCL, 0600);
    if (fd < 0 || write(fd, "sandbox write\n", 14) != 14 || close(fd)) return 70;
    errno = 0; fd = open("/protected/forbidden", O_WRONLY | O_CREAT | O_TRUNC, 0600); int denied_errno = errno;
    if (fd >= 0) close(fd);
    errno = 0; fd = open("/secret/input", O_RDONLY); int read_errno = errno;
    char value[64] = {0}; int count = fd >= 0 ? (int)read(fd, value, sizeof(value)) : -1;
    if (fd >= 0) close(fd);
    unsigned long long caps = 0; char line[512]; FILE *status = fopen("/proc/self/status", "r"); if (!status) return 71;
    while (fgets(line, sizeof(line), status)) if (sscanf(line, "CapEff: %llx", &caps) == 1) break;
    fclose(status);
    int pid = different("/proc/self/ns/pid", "NEVERD_OUTER_PID_NS"), user = different("/proc/self/ns/user", "NEVERD_OUTER_USER_NS");
    int mount = different("/proc/self/ns/mnt", "NEVERD_OUTER_MOUNT_NS");
    int network = different("/proc/self/ns/net", "NEVERD_OUTER_NET_NS");
    const char *port = getenv("NEVERD_FIXTURE_PORT"); if (!port || atoi(port) < 1024 || atoi(port) > 65535) return 74;
    int inet = socket(AF_INET, SOCK_STREAM, 0); if (inet < 0) return 75;
    struct sockaddr_in address = {.sin_family = AF_INET, .sin_port = htons((unsigned short)atoi(port)), .sin_addr.s_addr = htonl(INADDR_LOOPBACK)};
    errno = 0; int connect_result = connect(inet, (struct sockaddr *)&address, sizeof(address)); int connect_errno = errno;
    if (connect_result == 0) {
        static const char request[] = "GET /probe HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n";
        char reply[512];
        if (write(inet, request, sizeof(request) - 1) != sizeof(request) - 1 || read(inet, reply, sizeof(reply)) < 12 || memcmp(reply, "HTTP/1.1 200", 12)) return 76;
    }
    close(inet);
    printf("{\"sandboxed\":%s,\"fd3_absent\":%s,\"unix_errno\":%d,\"write_denied_errno\":%d,\"read_denied_errno\":%d,\"read_bytes\":%d,\"cap_effective\":%llu,\"no_new_privs\":%d,\"seccomp\":%d,\"nested_pid\":%d,\"nested_user\":%d,\"nested_mount\":%d,\"nested_network\":%d,\"direct_fixture_connect\":%d,\"direct_fixture_errno\":%d}\n",
           sandboxed ? "true" : "false", descriptor == -1 && descriptor_errno == EBADF ? "true" : "false", socket_errno,
           denied_errno, read_errno, count, caps, prctl(PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0), prctl(PR_GET_SECCOMP), pid, user, mount, network, connect_result, connect_errno);
    if (sandboxed) return descriptor == -1 && descriptor_errno == EBADF && socket_errno == EPERM && denied_errno == EROFS && read_errno == ENOENT &&
                          caps == 0 && prctl(PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0) == 1 && prctl(PR_GET_SECCOMP) == 2 && pid == 1 && user == 1 && mount == 1 &&
                          network == 1 && connect_result == -1 && connect_errno == ECONNREFUSED ? 0 : 72;
    return sock >= 0 && denied_errno == 0 && count == 21 && memcmp(value, "owned secret fixture\n", 21) == 0 && caps == 0 && pid == 0 && user == 0 && mount == 0 &&
           network == 0 && connect_result == 0 && connect_errno == 0 ? 0 : 73;
}
