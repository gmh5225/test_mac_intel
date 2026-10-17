/* Match the caller's close-before-payload requirement using an owned fd. */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

int main(int argc, char **argv) {
    if (argc != 2 || strcmp(argv[1], "close-and-report") != 0) return 64;
    if (fcntl(3, F_GETFD) < 0) return 65;
    if (close(3) != 0) return 66;
    errno = 0;
    int result = fcntl(3, F_GETFD);
    int saved = errno;
    printf("{\"fd3_valid_before_close\":true,\"fd3_result_after_close\":%d,\"errno\":%d}\n", result, saved);
    return result == -1 && saved == EBADF ? 0 : 67;
}
