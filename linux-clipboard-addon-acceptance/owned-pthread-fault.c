/* Controlled error return only for calls originating in the mounted addon. */
#define _GNU_SOURCE
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

int pthread_create(pthread_t *thread, const pthread_attr_t *attributes,
                   void *(*entry)(void *), void *data) {
    Dl_info caller = {0};
    const char *path = NULL;
    if (dladdr(__builtin_return_address(0), &caller)) path = caller.dli_fname;
    if (path && strncmp(path, "/modules/", 9) == 0 &&
        access("/tmp/private-clipboard/owned-fail-reader-spawn", F_OK) == 0) {
        size_t stack = 0;
        if (attributes) (void)pthread_attr_getstacksize(attributes, &stack);
        int fd = open("/evidence/owned-pthread-failures.jsonl", O_WRONLY | O_APPEND | O_CREAT | O_CLOEXEC, 0600);
        if (fd < 0) _exit(86);
        char line[512];
        int length = snprintf(line, sizeof(line), "{\"caller\":\"%s\",\"pthread_create_return\":%d,\"stack_bytes\":%zu}\n", path, EAGAIN, stack);
        if (length <= 0 || (size_t)length >= sizeof(line) || write(fd, line, (size_t)length) != length) _exit(87);
        close(fd);
        return EAGAIN;
    }
    int (*real_create)(pthread_t *, const pthread_attr_t *, void *(*)(void *), void *) = dlsym(RTLD_NEXT, "pthread_create");
    if (!real_create) _exit(88);
    return real_create(thread, attributes, entry, data);
}
