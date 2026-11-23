#include "cs_disasm_internal.h"
#include <inttypes.h>
#include <stdio.h>

static bool probing;
static uint64_t attempts, accepted;

CS_PRESERVE_MOST bool __real_X86_decodeOutputMiss64(cs_struct *, const uint8_t *, size_t, cs_insn *, uint16_t *, bool);
CS_PRESERVE_MOST bool __real_cs_decode_full_insn(cs_struct *, const uint8_t *, size_t, cs_insn *, uint16_t *, bool);

CS_PRESERVE_MOST bool __wrap_cs_decode_full_insn(cs_struct *handle, const uint8_t *p, size_t size, cs_insn *insn, uint16_t *len, bool batch)
{
    probing = false;
    return __real_cs_decode_full_insn(handle, p, size, insn, len, batch);
}

CS_PRESERVE_MOST bool __wrap_X86_decodeOutputMiss64(cs_struct *handle, const uint8_t *p, size_t size, cs_insn *insn, uint16_t *len, bool batch)
{
    probing = size >= 6 && p[0] == 0x62 && (p[1] & 15) == 1 &&
              p[2] == 0x7f && (p[3] & 7) && (p[4] | 0x10) == 0x7f;
    attempts += probing;
    bool ok = __real_X86_decodeOutputMiss64(handle, p, size, insn, len, batch);
    accepted += probing && ok;
    probing = false;
    return ok;
}

__attribute__((destructor)) static void report(void)
{
    fprintf(stderr, "masked %" PRIu64 " %" PRIu64 "\n", attempts, accepted);
}
