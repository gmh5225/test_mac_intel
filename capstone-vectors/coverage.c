#include "arch/X86/X86SimpleOutput.h"
#include <inttypes.h>
#include <stdio.h>

static uint64_t attempts, accepted;
extern bool __real_X86_writeIntegerBlockBroadcast(const uint8_t *, size_t, cs_insn *, uint16_t *, const struct X86SimpleRegister *);

bool __wrap_X86_writeIntegerBlockBroadcast(const uint8_t *bytes, size_t available, cs_insn *insn, uint16_t *length, const struct X86SimpleRegister *regs)
{
	const bool integer = available >= 6 && bytes[4] == 0x5a;
	attempts += integer;
	bool ok = __real_X86_writeIntegerBlockBroadcast(bytes, available, insn, length, regs);
	accepted += integer && ok;
	return ok;
}

__attribute__((destructor)) static void report(void)
{
	fprintf(stderr, "broadcast %" PRIu64 " %" PRIu64 "\n", attempts, accepted);
}
