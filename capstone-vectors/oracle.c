#include "arch/X86/X86OutputOptions.h"
#include "arch/X86/X86SimpleOutput.h"
#include "arch/X86/X86GenSimpleOutput.inc"

bool observed_broadcast(csh h, bool wide, const uint8_t *bytes, size_t size, cs_insn *out, uint16_t *length)
{
	cs_struct *s = (cs_struct *)(uintptr_t)h;
	if (size < 6 || bytes[0] != 0x62 || !wide || X86_OUTPUT_UNSUPPORTED(s, false))
		return false;
	return X86_writeEvexBroadcastPrechecked(bytes, size, out, length, x86_simple_registers[3]);
}
