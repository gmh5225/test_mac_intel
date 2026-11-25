#define _GNU_SOURCE
#include <dlfcn.h>
#include <inttypes.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/time.h>
#include <time.h>
#include <ucontext.h>
#include <unistd.h>

static volatile sig_atomic_t samples;
static volatile uintptr_t points[65536];
static unsigned calls;
static void capture(int sig, siginfo_t *info, void *context)
{
    (void)sig; (void)info;
    if (samples == 65536) _exit(81);
    ucontext_t *uc = context;
#if defined(__x86_64__)
    points[samples++] = (uintptr_t)uc->uc_mcontext.gregs[REG_RIP];
#elif defined(__aarch64__)
    points[samples++] = (uintptr_t)uc->uc_mcontext.pc;
#else
#error unsupported sampler host
#endif
}

clock_t clock(void)
{
    static clock_t (*real_clock)(void);
    if (!real_clock) {
        real_clock = (clock_t (*)(void))dlsym(RTLD_NEXT, "clock");
        if (!real_clock) _exit(82);
    }
    struct itimerval timer = {0};
    if (++calls == 1) {
        struct sigaction action = {0};
        action.sa_sigaction = capture;
        action.sa_flags = SA_SIGINFO | SA_RESTART;
        sigemptyset(&action.sa_mask);
        if (sigaction(SIGPROF, &action, NULL)) _exit(83);
        timer.it_value.tv_usec = atoi(getenv("SAMPLE_INITIAL_US"));
        timer.it_interval.tv_usec = atoi(getenv("SAMPLE_PERIOD_US"));
    } else if (calls != 2) {
        _exit(84);
    }
    if (setitimer(ITIMER_PROF, &timer, NULL)) _exit(85);
    return real_clock();
}

__attribute__((destructor)) static void finish(void)
{
    if (calls != 2 || samples == 0) _exit(86);
    FILE *out = fopen(getenv("SAMPLE_OUTPUT"), "w");
    if (!out) _exit(87);
    for (sig_atomic_t i = 0; i < samples; ++i) {
        Dl_info loc = {0};
        int found = dladdr((const void *)points[i], &loc);
        fprintf(out, "%" PRIxPTR "\t%s\t%s\n", points[i],
                found && loc.dli_fname ? loc.dli_fname : "?",
                found && loc.dli_sname ? loc.dli_sname : "?");
    }
    if (fclose(out)) _exit(88);
}
