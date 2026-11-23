#include "cs_priv.h"
#include "arch/X86/X86SimpleOutput.h"
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>

static unsigned admission;
#if COUNT_HITS
static uint64_t calls, hits;
#endif

__attribute__((constructor)) static void select_mode(void)
{
	const char *v = getenv("CS_COMPARE_VEX");
	if (!v || v[0] < '0' || v[0] > '2' || v[1])
		abort();
	admission = (unsigned)(v[0] - '0');
}

extern bool __real_X86_writeVexBaseMemory(const uint8_t *, size_t, unsigned, cs_insn *, uint16_t *, const struct X86SimpleRegister *);
bool __wrap_X86_writeVexBaseMemory(const uint8_t *p, size_t n, unsigned prefix,
			   cs_insn *out, uint16_t *len, const struct X86SimpleRegister *regs)
{
	if (!admission || (admission == 1 && (p[prefix + 1] & 0xc7) != 5))
		return false;
	bool ok = __real_X86_writeVexBaseMemory(p, n, prefix, out, len, regs);
#if COUNT_HITS
	++calls;
	hits += ok;
#endif
	return ok;
}

#if COUNT_HITS
__attribute__((destructor)) static void report(void)
{
	fprintf(stderr, "admitted %" PRIu64 " %" PRIu64 "\n", calls, hits);
}
#endif
