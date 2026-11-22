#include "cs_priv.h"
#include "arch/X86/X86OutputOptions.h"
#include "cs_disasm_internal.h"

#define X86_decodeOutputMiss32 observed_miss32
#define X86_decodeRegisterFallback32(...) false
#include "arch/X86/X86MemoryFallback32.c"

bool observed_test(csh handle, bool wide, const uint8_t *p, size_t n,
		   cs_insn *insn, uint16_t *length)
{
	return !wide && n && p[0] == 0xf6 &&
	       observed_miss32((cs_struct *)(uintptr_t)handle, p, n, insn, length, false);
}
