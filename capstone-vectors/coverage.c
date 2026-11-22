#include "cs_priv.h"
#include "arch/X86/X86SimpleOutput.h"
#include <inttypes.h>
#include <stdio.h>

static uint64_t accepted;
extern bool __real_X86_writeVectorRipMemory(const uint8_t *, cs_insn *, uint16_t *, const struct VectorOutputRow *, unsigned, unsigned, unsigned, unsigned, unsigned);

bool __wrap_X86_writeVectorRipMemory(const uint8_t *p, cs_insn *insn, uint16_t *length,
                                     const struct VectorOutputRow *row, unsigned prefix,
                                     unsigned ll, unsigned rex, unsigned dst, unsigned src)
{
	const bool success = __real_X86_writeVectorRipMemory(p, insn, length, row, prefix, ll, rex, dst, src);
	accepted += success && prefix < 4;
	return success;
}

__attribute__((destructor)) static void report(void)
{
	fprintf(stderr, "vexrip %" PRIu64 " %" PRIu64 "\n", accepted, accepted);
}
