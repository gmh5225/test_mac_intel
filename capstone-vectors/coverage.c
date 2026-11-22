#include "cs_priv.h"
#include <inttypes.h>
#include <stdio.h>

static uint64_t attempts, accepted;

extern bool __real_X86_writePlainEvexRegisters(cs_struct *, const uint8_t *, size_t, cs_insn *, uint16_t *);

bool __wrap_X86_writePlainEvexRegisters(cs_struct *handle, const uint8_t *code, size_t available, cs_insn *insn, uint16_t *size)
{
	const bool control = (code[1] & 15) == 3 && available >= 7;
	attempts += control;
	bool hit = __real_X86_writePlainEvexRegisters(handle, code, available, insn, size);
	accepted += control && hit && *size == 7;
	return hit;
}

__attribute__((destructor)) static void report(void)
{
	fprintf(stderr, "imm8 %" PRIu64 " %" PRIu64 "\n", attempts, accepted);
}
