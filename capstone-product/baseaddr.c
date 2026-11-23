#include "arch/X86/X86OutputOptions.h"
#include "arch/X86/X86SimpleOutput.h"
#include "arch/X86/X86GenSimpleOutput.inc"

bool observed_plain(csh h, bool wide, const uint8_t *p, size_t n, cs_insn *out, uint16_t *len)
{
#if __has_include("arch/X86/X86GenVexBaseMemory.inc")
    cs_struct *handle = (cs_struct *)(uintptr_t)h;
    if (!wide || n == 0 || (p[0] & 0xfe) != 0xc4)
        return false;
    const unsigned prefix = p[0] == 0xc5 ? 2 : 3;
    return n >= prefix + 2 && p[prefix + 1] < 0xc0 &&
           !X86_OUTPUT_UNSUPPORTED(handle, false) && X86_writeVexBaseMemory(p, n, prefix, out, len, x86_simple_registers[3]);
#else
    return false;
#endif
}
