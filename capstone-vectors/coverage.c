#include "cs_disasm_internal.h"
#include <inttypes.h>
#include <stdio.h>

static uint64_t attempts, accepted;
static bool probing;

CS_PRESERVE_MOST bool __real_X86_decodeOutputMiss32(cs_struct *, const uint8_t *, size_t, cs_insn *, uint16_t *, bool);
CS_PRESERVE_MOST bool __real_X86_decodeRegisterFallback32(cs_struct *, const uint8_t *, size_t, cs_insn *, uint16_t *, bool);

CS_PRESERVE_MOST bool __wrap_X86_decodeRegisterFallback32(cs_struct *h, const uint8_t *p, size_t n, cs_insn *i, uint16_t *z, bool bulk)
{
	probing = false;
	return __real_X86_decodeRegisterFallback32(h, p, n, i, z, bulk);
}

CS_PRESERVE_MOST bool __wrap_X86_decodeOutputMiss32(cs_struct *h, const uint8_t *p, size_t n, cs_insn *i, uint16_t *z, bool bulk)
{
	const bool seg = p[0] == 0x26 || p[0] == 0x2e || p[0] == 0x36 || p[0] == 0x3e || p[0] == 0x64 || p[0] == 0x65;
	probing = n >= 7 && seg && (p[1] == 0x2b || p[1] == 0x89 || p[1] == 0x8b) && (p[2] & 0xc7) == 5;
	attempts += probing;
	bool ok = __real_X86_decodeOutputMiss32(h, p, n, i, z, bulk);
	accepted += probing && ok;
	probing = false;
	return ok;
}

__attribute__((destructor)) static void report(void)
{
	fprintf(stderr, "segment %" PRIu64 " %" PRIu64 "\n", attempts, accepted);
}
