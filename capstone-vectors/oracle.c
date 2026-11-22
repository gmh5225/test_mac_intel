#include "cs_priv.h"
#include "arch/X86/X86SimpleOutput.h"

bool observed_plain(csh h, bool wide, const uint8_t *p, size_t n, cs_insn *out, uint16_t *length)
{
#if __has_include("arch/X86/X86GenPlainEvexRegisterOutput.inc")
	return wide && n >= 6 && p[0] == 0x62 && p[5] >= 0xc0 &&
		X86_writePlainEvexRegisters((cs_struct *)(uintptr_t)h,p,out,length);
#else
	return false;
#endif
}
