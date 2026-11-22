#include "cs_priv.h"
#include "arch/X86/X86SimpleOutput.h"
#include "arch/X86/X86GenSimpleOutput.inc"

bool observed_mixed(csh handle, bool wide, const uint8_t *bytes, size_t size,
                    cs_insn *out, uint16_t *length)
{
#if __has_include("arch/X86/X86GenVexRegisterImmediates.inc")
    return size && bytes[0] == 0xc4 &&
           X86_writeVexRegisterImmediate((cs_struct *)(uintptr_t)handle,
                                         bytes, size, out, length,
                                         x86_simple_registers, wide);
#else
    return false;
#endif
}
