#include "arch/X86/X86OutputOptions.h"
#include "arch/X86/X86SimpleOutput.h"

bool observed_plain(csh h, bool wide, const uint8_t *p, size_t n, cs_insn *out, uint16_t *length)
{
	cs_struct *handle = (cs_struct *)(uintptr_t)h;
	return n >= 2 && p[0] == 0x66 && (p[1] == 0x2e || p[1] == 0x66) &&
		!X86_OUTPUT_UNSUPPORTED(handle, false) && X86_writeVectorOutput(p, n, out, length, NULL, wide);
}
