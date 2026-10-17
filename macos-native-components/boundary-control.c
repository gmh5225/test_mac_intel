/* Own-file, process and network probes before any captured client executes. */
#include <errno.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/wait.h>
int main(int argc, char **argv) {
    if (argc != 4) return 64;
    int fd = open(argv[1], O_RDONLY); int outside = errno;
    if (fd >= 0) { close(fd); return 65; }
    fd = open(argv[2], O_WRONLY | O_CREAT | O_TRUNC, 0600); int write = errno;
    if (fd >= 0) { close(fd); return 66; }
    fd = open(argv[3], O_RDONLY); if (fd < 0) return 67;
    char byte; int readable = read(fd, &byte, 1) == 1; close(fd);
    int network[4];
    for (int i = 0; i < 4; ++i) {
        int family = i < 2 ? AF_INET : AF_INET6;
        int type = i % 2 ? SOCK_DGRAM : SOCK_STREAM;
        fd = socket(family, type, 0); network[i] = errno;
        if (fd >= 0) {
            struct sockaddr_storage storage; memset(&storage, 0, sizeof(storage));
            socklen_t size;
            if (family == AF_INET) {
                struct sockaddr_in *address = (struct sockaddr_in *)&storage;
                address->sin_family = AF_INET; address->sin_port = htons(9);
                inet_pton(AF_INET, "127.0.0.1", &address->sin_addr); size = sizeof(*address);
            } else {
                struct sockaddr_in6 *address = (struct sockaddr_in6 *)&storage;
                address->sin6_family = AF_INET6; address->sin6_port = htons(9);
                inet_pton(AF_INET6, "::1", &address->sin6_addr); size = sizeof(*address);
            }
            int result = type == SOCK_STREAM ? connect(fd, (struct sockaddr *)&storage, size)
                : (int)sendto(fd, "x", 1, 0, (struct sockaddr *)&storage, size);
            network[i] = errno; close(fd); if (result >= 0) return 68;
        }
    }
    pid_t child = fork(); if (child < 0) return 69;
    if (!child) {
        execl("/bin/sh", "sh", "-c", "exit 99", (char *)NULL);
        _exit(errno == EPERM || errno == EACCES ? 0 : 70);
    }
    int status; if (waitpid(child, &status, 0) != child) return 71;
    int exec_denied = WIFEXITED(status) && WEXITSTATUS(status) == 0;
    printf("{\"outside_errno\":%d,\"write_errno\":%d,\"readable\":%d,\"network_errno\":[%d,%d,%d,%d],\"shell_exec_denied\":%d}\n",
           outside, write, readable, network[0], network[1], network[2], network[3], exec_denied);
    return readable && exec_denied ? 0 : 72;
}
