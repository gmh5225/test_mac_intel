#include "arch/X86/X86OutputOptions.h"
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>

static uint64_t attempts, accepted;
bool observed_plain(csh, bool, const uint8_t *, size_t, cs_insn *, uint16_t *);
CS_PRESERVE_MOST bool __real_X86_decodeOutputMiss64(cs_struct *, const uint8_t *, size_t, cs_insn *, uint16_t *, bool);
CS_PRESERVE_MOST bool __wrap_X86_decodeOutputMiss64(cs_struct *h, const uint8_t *p, size_t n, cs_insn *out, uint16_t *length, bool batch)
{
    bool real = __real_X86_decodeOutputMiss64(h, p, n, out, length, batch);
    if (n >= 5 && p[0] == 0x66) {
        unsigned lead = (p[1] & 0xf0) == 0x40;
        if (n >= 5 + lead && p[1+lead] == 0x0f && p[2+lead] == 0x38 && p[4+lead] >= 0xc0) {
            cs_insn observed = { 0 };
            uint16_t size = 0;
            attempts++;
            if (observed_plain((csh)(uintptr_t)h, true, p, n, &observed, &size)) {
                if (!real || observed.id != out->id || size != *length) abort();
                accepted++;
            }
        }
    }
    return real;
}
__attribute__((destructor)) static void report(void)
{
    fprintf(stderr, "map38 %" PRIu64 " %" PRIu64 "\n", attempts, accepted);
}
