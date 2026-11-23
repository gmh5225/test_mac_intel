#define X86_decodeOutputMiss64 observed_miss64
#include "arch/X86/X86VectorFallback64.c"

bool observed_plain(csh h, bool wide, const uint8_t *p, size_t n,
                    cs_insn *out, uint16_t *len)
{
#ifdef OBSERVED_CMP64
    return wide && n && tryCompareMemory64((cs_struct *)(uintptr_t)h,p,n,out,len);
#else
    return false;
#endif
}
