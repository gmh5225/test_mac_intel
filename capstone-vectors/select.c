#include "arch/X86/X86ScanAdapter.h"
#include <stdio.h>
#include <stdlib.h>

extern __typeof__(X86_scanNativeBatch) __real_X86_scanNativeBatch;
extern __typeof__(X86_scanNativeBatch) X86_scanAlternateBatch;
static __typeof__(&X86_scanNativeBatch) scan;
#ifdef COUNT_BATCH_CALLS
static size_t calls;
__attribute__((destructor)) static void report_calls(void)
{
	fprintf(stderr, "batch calls %zu\n", calls);
}
#endif

__attribute__((constructor)) static void select_scan(void)
{
	const char *choice = getenv("BENCH_SCAN");
	if (!choice || (choice[0] != '0' && choice[0] != '1') || choice[1])
		abort();
	scan = choice[0] == '1' ? X86_scanAlternateBatch : __real_X86_scanNativeBatch;
}

X86ScanBatchResult __wrap_X86_scanNativeBatch(csh handle, const uint8_t *code,
					      size_t size, uint64_t address,
					      uint32_t *output, size_t capacity)
{
#ifdef COUNT_BATCH_CALLS
	++calls;
#endif
	return scan(handle, code, size, address, output, capacity);
}
