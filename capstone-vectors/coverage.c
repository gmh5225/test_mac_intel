#include "cs_priv.h"
#include "arch/X86/X86SimpleOutput.h"
#include <inttypes.h>
#include <stdio.h>

static uint64_t attempts, accepted;

extern bool __real_X86_writeVexBaseMemory(const uint8_t *, size_t, unsigned, cs_insn *, uint16_t *, const struct X86SimpleRegister *);

bool __wrap_X86_writeVexBaseMemory(const uint8_t *code, size_t n, unsigned prefix, cs_insn *insn, uint16_t *size, const struct X86SimpleRegister *regs)
{
	++attempts;
	bool hit = __real_X86_writeVexBaseMemory(code, n, prefix, insn, size, regs);
	accepted += hit;
	return hit;
}

__attribute__((destructor)) static void report(void)
{
	fprintf(stderr, "vexrip %" PRIu64 " %" PRIu64 "\n", attempts, accepted);
}
