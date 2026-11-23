#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#if __has_include("arch/X86/X86GenBareVexRegisters64.inc")
#define X86_decodeOutputMiss64 observed_vector_miss
#include "arch/X86/X86VectorFallback64.c"
#undef X86_decodeOutputMiss64
bool observed_bare(const uint8_t *bytes, size_t length, bool wide)
{
    if (!wide || !length || (bytes[0] & 0xfe) != 0xc4)
        return false;
    cs_insn out = { 0 };
    uint16_t size;
    return writeBareVexRegisters64(bytes, length, &out, &size,
                                   bytes[0] == 0xc5 ? 2 : 3);
}
#else
bool observed_bare(const uint8_t *bytes, size_t length, bool wide)
{
    return false;
}
#endif
