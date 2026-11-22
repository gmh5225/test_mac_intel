#include "cs_priv.h"
#include "arch/X86/X86OutputOptions.h"
#include "cs_disasm_internal.h"
/* Stop at the actual production miss boundary. Guards exercise the original
 * admission and the original writer, including rejected partial encodings. */
#define X86_decodeOutputMiss64 observed_map38_miss
#define cs_decode_full_insn(...) false
#define cs_decode_full_insn_body(...) false
#include "arch/X86/X86VectorFallback64.c"

bool observed_plain(csh h, bool wide, const uint8_t *p, size_t n, cs_insn *insn, uint16_t *length)
{
    return wide && n && observed_map38_miss((cs_struct *)(uintptr_t)h, p, n, insn, length, false);
}
