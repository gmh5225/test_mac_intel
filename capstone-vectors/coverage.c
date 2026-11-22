#include "cs_priv.h"
#include <inttypes.h>
#include <stdio.h>

static uint64_t attempts, accepted;

extern bool __real_X86_writeEvexRipMemory(cs_struct *, const uint8_t *, cs_insn *, uint16_t *);

bool __wrap_X86_writeEvexRipMemory(cs_struct *handle, const uint8_t *code, cs_insn *insn, uint16_t *size)
{
	++attempts;
	bool hit = __real_X86_writeEvexRipMemory(handle, code, insn, size);
	accepted += hit;
	return hit;
}

__attribute__((destructor)) static void report(void)
{
	fprintf(stderr, "evex %" PRIu64 " %" PRIu64 "\n", attempts, accepted);
}
