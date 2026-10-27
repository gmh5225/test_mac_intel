/* Owned checks of the outer tool-fixture root, before any captured entry. */
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <unistd.h>

int main(void) {
    const char *outside = getenv("BOUNDARY_OUTSIDE");
    if (!outside || outside[0] != '/') return 64;
    errno = 0;
    int fd = open(outside, O_RDONLY | O_CLOEXEC), outside_errno = errno;
    if (fd >= 0) { close(fd); return 65; }
    errno = 0;
    fd = open("/runtime/write-denied", O_WRONLY | O_CREAT | O_EXCL, 0600);
    int readonly_errno = errno;
    if (fd >= 0) { close(fd); return 66; }
    fd = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
    if (fd < 0) return 67;
    struct sockaddr_in target = {.sin_family = AF_INET, .sin_port = htons(9)};
    if (inet_pton(AF_INET, "192.0.2.1", &target.sin_addr) != 1) return 68;
    errno = 0;
    int network = connect(fd, (struct sockaddr *)&target, sizeof(target)), network_errno = errno;
    close(fd);
    int nnp = prctl(PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0);
    printf("{\"outside_errno\":%d,\"readonly_errno\":%d,\"network_result\":%d,\"network_errno\":%d,\"uid\":%d,\"no_new_privs\":%d}\n",
        outside_errno, readonly_errno, network, network_errno, (int)getuid(), nnp);
    return outside_errno == ENOENT && readonly_errno == EROFS && network == -1 &&
        network_errno == ENETUNREACH && getuid() != 0 && nnp == 1 ? 0 : 69;
}
