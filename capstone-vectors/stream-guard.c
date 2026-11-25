#include "cs_priv.h"
#include "SStream.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "alias-writer.inc"

static unsigned behavior, calls, hash;
static int observe(char *out, size_t size, const char *fmt, va_list args)
{
    if (strcmp(fmt, "%s%s") != 0) abort();
    va_list values; va_copy(values, args);
    for (int i = 0; i < 2; ++i) {
        const char *s = va_arg(values, const char *);
        if (i == 0 && strcmp(s, "\t") != 0) abort();
        while (*s) hash = hash * 33 + (unsigned char)*s++;
        hash = hash * 33 + 1;
    }
    va_end(values); ++calls;
    if (behavior == 2) return -1;
    if (behavior == 3) { if (size) { memset(out, 'c', size - 1); out[size - 1] = 0; } return (int)size + 3; }
    return vsnprintf(out, size, fmt, args);
}
static void reference(SStream *ss, const char *name)
{
    SStream_concat(ss, "%s%s", "\t", name);
    SStream_concat0(ss, "\t");
}
int main(void)
{
    const char *names[] = { "b", "bal", "beqz", "bnez", "bc1t", "bc1f", "jalr", "jr", "not", "move", "li", "addiu", "andi", "" };
    unsigned count = 0;
    cs_vsnprintf_t standard = cs_vsnprintf;
    for (behavior = 0; behavior < 4; ++behavior) {
        cs_vsnprintf = behavior ? observe : standard;
        for (unsigned state = 0; state < 16; ++state) {
            for (unsigned i = 0; i < sizeof(names)/sizeof(names[0]); ++i) {
                for (size_t idx = 0; idx < SSTREAM_BUF_LEN; ++idx) {
                    SStream a, b; memset(&a, 0xa5, sizeof(a));
                    a.index = idx; a.is_closed = (state & 1) != 0; a.markup_stream = (state & 2) != 0;
                    a.prefixed_by_markup = (state & 4) != 0; a.unsigned_num = 0;
                    if (state & 8) a.buffer[idx] = 0;
                    memcpy(&b, &a, sizeof(b));
                    calls = hash = 0;
                    reference(&a, names[i]);
                    unsigned n = calls, h = hash;
                    calls = hash = 0;
                    MEASURE_WRITE(&b, names[i]);
                    if (memcmp(&a, &b, sizeof(a)) || n != calls || hash != h) {
                        fprintf(stderr, "formatter %u state %u index %zu name %s\n", behavior, state, idx, names[i]);
                        return 1;
                    }
                    ++count;
                }
            }
        }
    }
    cs_vsnprintf = standard;
    printf("%u\n", count);
    return 0;
}
