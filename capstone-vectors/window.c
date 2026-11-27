/* Start and stop perf stat at the two existing std::clock calls in the driver. */
#define _GNU_SOURCE
#include <dlfcn.h>
#include <errno.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

static unsigned calls;
static clock_t (*libc_clock)(void);

static void control(const char *command, size_t length)
{
    int request = atoi(getenv("ND_COUNTER_REQUEST"));
    int acknowledge = atoi(getenv("ND_COUNTER_ACK"));
    char reply[16];
    struct pollfd ready = { acknowledge, POLLIN, 0 };
    if (write(request, command, length) != (ssize_t)length ||
        poll(&ready, 1, 6000) <= 0 || read(acknowledge, reply, sizeof reply) < 3 ||
        memcmp(reply, "ack", 3) != 0) {
        fprintf(stderr, "perf control did not acknowledge %s", command);
        _exit(81);
    }
}

clock_t clock(void)
{
    if (!libc_clock) {
        libc_clock = (clock_t (*)(void))dlsym(RTLD_NEXT, "clock");
        if (!libc_clock) _exit(82);
    }
    if (++calls == 1) control("enable\n", 7);
    else if (calls == 2) control("disable\n", 8);
    else _exit(83);
    return libc_clock();
}

__attribute__((destructor)) static void checked(void)
{
    if (calls != 2) _exit(84);
    fputs("nd-perf-window=2\n", stderr);
}
