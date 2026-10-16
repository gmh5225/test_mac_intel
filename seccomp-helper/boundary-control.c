/* Authored qualification of the separate, empty-root namespace boundary. */
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

int main(void) {
    const char *outside = getenv("BOUNDARY_OUTSIDE");
    if (!outside || outside[0] != '/') return 64;
    errno = 0;
    int fd = open(outside, O_RDONLY | O_CLOEXEC);
    int outside_errno = errno;
    if (fd >= 0) { close(fd); return 65; }
    errno = 0;
    fd = open("/runtime/write-denied", O_WRONLY | O_CREAT | O_EXCL, 0600);
    int readonly_errno = errno;
    if (fd >= 0) { close(fd); return 66; }
    errno = 0;
    int shell = access("/bin/sh", X_OK);
    int shell_errno = errno;
    fd = open("/work/allowed", O_WRONLY | O_CREAT | O_EXCL, 0600);
    if (fd < 0 || write(fd, "owned fixture\n", 14) != 14 || close(fd) != 0) return 67;
    fd = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
    if (fd < 0) return 68;
    struct sockaddr_in target = {.sin_family = AF_INET, .sin_port = htons(9)};
    if (inet_pton(AF_INET, "192.0.2.1", &target.sin_addr) != 1) return 69;
    errno = 0;
    int network = connect(fd, (struct sockaddr *)&target, sizeof(target));
    int network_errno = errno;
    close(fd);
    printf("{\"outside_errno\":%d,\"readonly_errno\":%d,\"shell_result\":%d,"
           "\"shell_errno\":%d,\"network_result\":%d,\"network_errno\":%d,\"uid\":%d}\n",
           outside_errno, readonly_errno, shell, shell_errno, network, network_errno, (int)getuid());
    return outside_errno == ENOENT && readonly_errno == EROFS && shell == -1 &&
           shell_errno == ENOENT && network == -1 && network_errno == ENETUNREACH && getuid() != 0 ? 0 : 70;
}
