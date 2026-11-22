#include "arch/X86/X86OutputOptions.h"
#include "arch/X86/X86SimpleOutput.h"

bool observed_plain(csh h, bool wide, const uint8_t *p, size_t n, cs_insn *out, uint16_t *len)
{
	cs_struct *handle = (cs_struct *)(uintptr_t)h;
	if (!wide || !n || (p[0] & 0xfe) != 0xc4 || X86_OUTPUT_UNSUPPORTED(handle, false))
		return false;
	const unsigned prefix = p[0] == 0xc5 ? 2 : 3;
	if (n < prefix + 6 || (p[prefix + 1] & 0xc7) != 5)
		return false;
	/* Standalone two-operand VEX loads use an older writer. */
	if (prefix == 2 && (p[1] & 0x78) == 0x78 &&
	    (p[2] == 0x10 || p[2] == 0x28 || p[2] == 0x6f))
		return false;
	return X86_writeVectorOutput(p, n, out, len, NULL, true);
}
