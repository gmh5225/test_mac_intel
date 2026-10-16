/* Record this invocation's outer namespaces immediately before exec. */
#define _GNU_SOURCE
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

int main(int argc, char **argv) {
    if (argc < 2) return 64;
    const char *paths[] = {"/proc/self/ns/pid", "/proc/self/ns/user", "/proc/self/ns/mnt"};
    char values[3][80];
    for (int i = 0; i < 3; ++i) {
        ssize_t n = readlink(paths[i], values[i], sizeof(values[i]) - 1);
        if (n < 1 || n >= (ssize_t)sizeof(values[i]) - 1) return 65;
        values[i][n] = '\0';
    }
    printf("NEVERD_OUTER_NAMESPACE {\"pid_ns\":\"%s\",\"user_ns\":\"%s\",\"mount_ns\":\"%s\"}\n",
           values[0], values[1], values[2]);
    if (fflush(stdout) != 0) return 66;
    const char *route = getenv("NEVERD_ROUTE_FD3");
    if (route && strcmp(route, "1") == 0) {
        int fd = open(argv[1], O_PATH);
        if (fd < 0 || (fd != 3 && dup2(fd, 3) != 3)) return 67;
        if (fd != 3 && close(fd) != 0) return 68;
        argv[1] = "/proc/self/fd/3";
        execv(argv[1], &argv[1]);
        perror("descriptor driver exec");
        return 126;
    }
    execv(argv[1], &argv[1]);
    perror("namespace driver exec");
    return 126;
}
