#define X86_disasmIterText observed_amd64_text
#include "arch/X86/X86Sse64Output.c"

bool observed_plain(csh handle, bool wide, const uint8_t *p, size_t size,
                    cs_insn *out, uint16_t *length)
{
    if (!wide || !size)
        return false;
    const unsigned lead = (p[0] & 0xf0) == 0x40;
    if (size < lead + 2)
        return false;
    const uint8_t op = p[lead], mr = p[lead+1];
    if ((op != 0x80 && op != 0x81 && op != 0x83) || mr >= 0xc0 ||
        (mr & 0x38) != 0x38)
        return false;
    return tryOutput64((cs_struct *)(uintptr_t)handle, p, size, out, length);
}
