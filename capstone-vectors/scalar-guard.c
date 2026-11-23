#define X86_disasmIterText observed_text
#include "arch/X86/X86Sse64Output.c"
bool observed_plain(csh handle, bool wide, const uint8_t *code, size_t size,
                    cs_insn *insn, uint16_t *length)
{
    if (!wide || size < 2 || code[0] != 0x66 ||
        (code[1] != 0x66 && code[1] != 0x2e))
        return false;
    return tryOutput64((cs_struct *)(uintptr_t)handle, code, size, insn, length);
}
