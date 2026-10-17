/* Authored public compatibility controls; no captured client executes. */
#define _GNU_SOURCE 1
#include <assert.h>
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

void *__real_dlsym(void *, const char *);
void *__wrap_dlsym(void *handle, const char *name) {
#ifdef RECOVERY_FORCE_OLD_FCNTL
    if (strcmp(name, "fcntl64") == 0) return NULL;
#endif
    return __real_dlsym(handle, name);
}

int main(void) {
    char path[] = "/tmp/bfs-compat-XXXXXX";
    int fd = mkstemp(path);
    assert(fd >= 0);
    assert(fcntl64(fd, F_GETFD) == 0);
    assert(fcntl64(fd, F_SETFD, FD_CLOEXEC) == 0);
    assert(fcntl64(fd, F_GETFD) == FD_CLOEXEC);
    struct flock lock = {.l_type = F_WRLCK, .l_whence = SEEK_SET};
    assert(fcntl64(fd, F_GETLK, &lock) == 0 && lock.l_type == F_UNLCK);
    errno = 0;
    assert(fcntl64(-1, F_GETFD) == -1 && errno == EBADF);
    struct statx st;
    assert(statx(AT_FDCWD, path, 0, STATX_BASIC_STATS, &st) == 0);
    assert(S_ISREG(st.stx_mode) && st.stx_size == 0);
    assert(unlink(path) == 0);
    errno = 0;
    assert(statx(AT_FDCWD, path, 0, STATX_BASIC_STATS, &st) == -1 && errno == ENOENT);
    assert(close(fd) == 0);
#ifdef RECOVERY_FORCE_OLD_FCNTL
    puts("fcntl no-argument/integer/pointer and statx controls passed with old-symbol fallback");
#else
    puts("fcntl no-argument/integer/pointer and statx controls passed with native-symbol forwarding");
#endif
    return 0;
}
