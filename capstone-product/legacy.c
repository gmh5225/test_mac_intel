#include "cs_priv.h"
#if __has_include("arch/X86/X86GenLegacyRegisterImmediates.inc")
#define X86_decodeOutputMiss64 observed_output_miss
#include "arch/X86/X86VectorFallback64.c"
#endif
bool observed_legacy(csh h, bool wide, const uint8_t *p, size_t size, cs_insn *out, uint16_t *length)
{
#if __has_include("arch/X86/X86GenLegacyRegisterImmediates.inc")
	if (!wide || size < 4 || p[0] != 0x66)
		return false;
	const uint8_t rex = (p[1] & 0xf0) == 0x40 ? p[1] : 0;
	const unsigned offset = 4 + (rex != 0);
	if (size <= offset || p[offset-3] != 0x0f || p[offset-1] < 0xc0 ||
	    p[offset-2] < 0x70 || p[offset-2] > 0x73 || X86_OUTPUT_UNSUPPORTED((cs_struct *)(uintptr_t)h,false))
		return false;
	return writeLegacyRegisterImmediate(p,out,length,offset,rex);
#else
	return false;
#endif
}
