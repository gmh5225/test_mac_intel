#define X86_decodeOutputMiss32 observed_output_miss
#include "arch/X86/X86MemoryFallback32.c"

bool observed_plain(csh handle, bool wide, const uint8_t *code, size_t size,
                    cs_insn *insn, uint16_t *length)
{
#ifdef OBSERVED_OPCODE
    return !wide && size && writeOpcodeImmediate32((cs_struct *)(uintptr_t)handle, code, size, insn, length);
#else
    return false;
#endif
}
