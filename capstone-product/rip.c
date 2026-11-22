#include "cs_priv.h"
#include "arch/X86/X86SimpleOutput.h"

bool observed_plain(csh h, bool wide, const uint8_t *p, size_t n, cs_insn *out, uint16_t *length)
{
#if __has_include("arch/X86/X86GenEvexRipMemory.inc")
	return wide && n >= 10 && p[0] == 0x62 && (p[5] & 0xc7) == 5 &&
		X86_writeEvexRipMemory((cs_struct *)(uintptr_t)h,p,out,length);
#else
	return false;
#endif
}
