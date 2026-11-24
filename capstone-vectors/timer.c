#define _GNU_SOURCE
#include <dlfcn.h>
#include <ucontext.h>
#include <stdint.h>
#include <string.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/time.h>

volatile sig_atomic_t family_current = -1;
int family_base;
static volatile sig_atomic_t samples[32768], written;
_Static_assert(sizeof(sig_atomic_t) == 4, "offset representation");

static volatile sig_atomic_t low[32768], high[32768];
static void capture(int signal, siginfo_t *info, void *state)
{
	(void)signal;
	(void)info;
	sig_atomic_t n = written;
	if (n < (sig_atomic_t)(sizeof(samples) / sizeof(samples[0])))
	{
		#if defined(__aarch64__)
        uint64_t pc=((ucontext_t *)state)->uc_mcontext.pc;
#elif defined(__x86_64__)
        uint64_t pc=((ucontext_t *)state)->uc_mcontext.gregs[REG_RIP];
#else
#error Unsupported profiling architecture
#endif
		low[n] = (sig_atomic_t)(uint32_t)pc;
		high[n] = (sig_atomic_t)(pc >> 32);
		samples[n] = family_current;
	}
	written = n + 1;
}
void start_family_profile(void)
{
	struct sigaction action = { 0 };
	action.sa_sigaction = capture;
	action.sa_flags = SA_RESTART | SA_SIGINFO;
	sigemptyset(&action.sa_mask);
	if (sigaction(SIGPROF, &action, NULL))
		abort();
	unsigned usec = (unsigned)strtoul(getenv("FAMILY_TIMER_US"), NULL, 10);
	struct itimerval timer = { { 0, usec }, { 0, usec } };
	if (setitimer(ITIMER_PROF, &timer, NULL))
		abort();
}
void end_family_profile(void)
{
	const struct itimerval off = { 0 };
	if (setitimer(ITIMER_PROF, &off, NULL))
		abort();
	sig_atomic_t n = written;
	if (n <= 0 || (size_t)n >= sizeof(samples) / sizeof(samples[0]))
		abort();
	FILE *f = fopen(getenv("FAMILY_SAMPLES"), "wb");
	if (!f) abort();
	for (sig_atomic_t i = 0; i != n; ++i) {
		int v = samples[i];
		if (fwrite(&v, sizeof(v), 1, f) != 1) abort();
	}
	if (fclose(f)) abort();
	const char *path = getenv("FAMILY_PC_PATH");
	FILE *map = fopen(path, "w");
	if (!map) abort();
	Dl_info own;
	if (!dladdr((const void *)&start_family_profile,&own)) abort();
	const void *main_image=own.dli_fbase;
	for (sig_atomic_t i = 0; i != n; ++i) {
		uintptr_t pc = (uint32_t)low[i] | ((uintptr_t)(uint32_t)high[i] << 32);
		Dl_info info;
		if (!dladdr((const void *)pc, &info)) {
			fputs("?\t?\n", map);
		} else if (info.dli_fbase == main_image) {
			fprintf(map, "main\t%llx\n", (unsigned long long)pc);
		} else {
			const char *slash = strrchr(info.dli_fname,'/');
			fprintf(map, "%s\t%s\n",slash ? slash+1 : info.dli_fname,info.dli_sname ? info.dli_sname : "?");
		}
	}
	if (fclose(map)) abort();
}
