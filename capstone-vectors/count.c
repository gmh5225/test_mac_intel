#include <inttypes.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
static uint64_t counters[5];
extern int __real_vsnprintf(char *, size_t, const char *, va_list);
int __wrap_vsnprintf(char *dst, size_t size, const char *fmt, va_list args)
{
	static const char *const hex[] = { "%" PRIx64 "h", "0%" PRIx64 "h",
					  "-%" PRIx64 "h", "-0%" PRIx64 "h" };
	unsigned i = 0;
	while(i < 4 && strcmp(fmt, hex[i]) != 0)
		++i;
	++counters[i];
	return __real_vsnprintf(dst, size, fmt, args);
}
static void __attribute__((destructor)) show_counts(void)
{
	for(unsigned i = 0; i < 5; ++i)
		fprintf(stderr, "%" PRIu64 " ", counters[i]);
	fputc('\n', stderr);
}
