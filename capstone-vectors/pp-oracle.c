#ifdef CHECK_BASE_MEMORY
#define CAPSTONE_X86_ONLY
#endif
#include "cs_priv.h"
#include "arch/X86/X86SimpleOutput.h"
#include "arch/X86/X86GenSimpleOutput.inc"

bool observed_plain(csh h, bool wide, const uint8_t *p, size_t n, cs_insn *out, uint16_t *length)
{
#ifdef CHECK_BASE_MEMORY
    return wide && n >= 6 && p[0] == 0x62 && p[5] < 0xc0 && (p[5] & 7) != 4 &&
           X86_writeEvexVectorMemory((cs_struct *)(uintptr_t)h, p, n, out, length, x86_simple_registers[3]);
#elif __has_include("arch/X86/X86GenEvexRipMemory.inc")
	return wide && n >= 10 && p[0] == 0x62 && (p[5] & 0xc7) == 5 &&
		X86_writeEvexRipMemory((cs_struct *)(uintptr_t)h,p,out,length);
#else
	return false;
#endif
}
