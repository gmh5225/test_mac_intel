#include "arch/X86/X86SimpleOutput.h"
#include <inttypes.h>
#include <stdio.h>

static uint64_t attempts, accepted;
bool __real_X86_writeVectorOutput(const uint8_t *, size_t, cs_insn *, uint16_t *, const struct X86SimpleRegister *, bool);

bool __wrap_X86_writeVectorOutput(const uint8_t *p, size_t size, cs_insn *insn, uint16_t *length, const struct X86SimpleRegister *regs, bool wide)
{
	bool eligible = size >= 10 && p[0] == 0x66 && (p[1] == 0x2e || p[1] == 0x66);
	bool ok = __real_X86_writeVectorOutput(p, size, insn, length, regs, wide);
	attempts += eligible;
	accepted += eligible && ok && insn->id == X86_INS_NOP && *length >= 10;
	return ok;
}
__attribute__((destructor)) static void report(void)
{
	fprintf(stderr, "padding %" PRIu64 " %" PRIu64 "\n", attempts, accepted);
}
