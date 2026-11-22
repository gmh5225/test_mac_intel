#include "cs_priv.h"
#include "arch/X86/X86SimpleOutput.h"
#include "arch/X86/X86GenSimpleOutput.inc"
#if __has_include("arch/X86/X86EvexMemoryRecord.h")
#define X86_EVEX_INDEXED_SIB
#define X86_EVEX_MEMORY_DATA
#include "arch/X86/X86EvexMemoryRecord.h"
#endif
bool observed_move(const uint8_t *p, size_t n, cs_insn *i, uint16_t *length)
{
    if (X86_writeEvexMemoryOutput(p,n,i,length,x86_simple_registers[3])) return true;
#ifdef CS_X86_EVEX_MEMORY_RECORD_H
    if (n>=7 && p[0]==0x62 && p[5]<0xc0 && (p[5]&7)==4)
        return writeIndexedEvexMemory(p,n,i,length,x86_simple_registers[3]);
#endif
    return false;
}
