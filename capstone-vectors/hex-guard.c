#include "arch/X86/X86InstPrinter.h"
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static uint64_t records;

static void check(uint64_t value, unsigned sign)
{
    char digits[22];
    int len = snprintf(digits, sizeof(digits), sign ? "-0x%" PRIx64 : "0x%" PRIx64, value);
    if (len <= 0 || (size_t)len >= sizeof(digits))
        abort();
    const size_t available = SSTREAM_BUF_LEN - (size_t)len - 1;
    const size_t offsets[] = { 0, 1, 7, 16, available / 2, available - 1, available };
    for (unsigned i = 0; i < sizeof(offsets)/sizeof(*offsets); ++i) {
        SStream expected, actual;
        memset(&actual, 0x5a, sizeof(actual));
        actual.is_closed = actual.markup_stream = actual.prefixed_by_markup = false;
        actual.unsigned_num = sign != 0;
        actual.index = offsets[i];
        actual.buffer[actual.index] = 0;
        memcpy(&expected, &actual, sizeof(actual));
        memcpy(expected.buffer + expected.index, digits, (size_t)len + 1);
        expected.index += (size_t)len;
        X86_Intel_printHexPrechecked(&actual, value, sign != 0);
        if (memcmp(&actual, &expected, sizeof(actual))) {
            fprintf(stderr, "hex mismatch at %zu value=%" PRIx64 "\n", offsets[i], value);
            exit(3);
        }
        ++records;
    }
}
int main(void)
{
    for (uint64_t i=0; i<65536; ++i)
        for (unsigned s=0; s<2; ++s)
            check(i,s);
    for (unsigned i=0; i<64; ++i)
        for (int delta=-1; delta<=1; ++delta)
            for (unsigned s=0; s<2; ++s)
                check((UINT64_C(1)<<i)+delta,s);
    uint64_t value=UINT64_C(0x3165090062);
    for (unsigned i=0; i<30000; ++i) {
        value ^= value<<13; value ^= value>>7; value ^= value<<17;
        check(value,0); check(value,1);
    }
    printf("%" PRIu64 " complete bounded hexadecimal records\n",records);
    return 0;
}
