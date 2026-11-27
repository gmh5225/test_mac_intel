#include "arch/X86/X86SimpleOutput.h"
#include "arch/X86/X86GenSimpleOutput.inc"

bool measure_vex2(const uint8_t *code, size_t size, cs_insn *out, uint16_t *length)
{
#ifdef KNOWN_PREFIX
    return X86_writeVex2Output(code, size, out, length, x86_simple_registers[3]);
#else
    return X86_writeVectorOutput(code, size, out, length, x86_simple_registers[3], true);
#endif
}
