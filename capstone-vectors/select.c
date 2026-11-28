#include <stdio.h>
#include <stdlib.h>
static unsigned split_choice;
#ifdef COUNT_SPLITS
static unsigned long long split_hits;
__attribute__((destructor)) static void report_splits(void)
{
	fprintf(stderr, "split calls %llu\n", split_hits);
}
#endif
__attribute__((constructor)) static void select_split(void)
{
	const char *s = getenv("BENCH_SPLIT");
	if (!s || (s[0] != '0' && s[0] != '1') || s[1])
		abort();
	split_choice = (unsigned)(s[0] == '1');
}
