#include "cs_priv.h"
#include "arch/X86/X86SimpleOutput.h"
#include "arch/X86/X86GenSimpleOutput.inc"
bool observed_move(const uint8_t *p, size_t n, cs_insn *i, uint16_t *length)
{
    return X86_writeEvexMemoryOutput(p,n,i,length,x86_simple_registers[3]);
}
