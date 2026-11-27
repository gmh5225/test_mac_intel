#include <stdint.h>
#include <stdio.h>
#include <string.h>
#define CAPSTONE_SSTREAM_PRECHECKED
#include "SStream.h"
#include "arch/X86/X86GenRegisterName1.inc"
#if defined(PACKED_NAMES) || defined(EXPLICIT_NAMES)
#include "arch/X86/X86GenPrinterRegisterNames.inc"
#endif

int main(void)
{
    unsigned long count = 0;
    const unsigned total = sizeof(RegAsmOffset) / sizeof(RegAsmOffset[0]);
    for (unsigned i = 0; i < total; ++i) {
        const char *old = getRegisterName(i + 1);
        const unsigned length = getRegisterNameLength(i + 1);
        const char *text = old;
        unsigned width = length;
#ifdef PACKED_NAMES
        text = X86PrinterRegisterNames[i];
        width = 7 - text[7];
#elif defined(EXPLICIT_NAMES)
        text = X86PrinterRegisterNames[i].name;
        width = X86PrinterRegisterNames[i].length;
#endif
        if (!width || width != length || width != strlen(old) ||
            memcmp(text, old, width + 1))
            return 1;
        for (size_t offset = 0; offset < SSTREAM_BUF_LEN - width; ++offset) {
            for (unsigned fill = 0; fill < 2; ++fill) {
                SStream actual = { 0 }, expected;
                memset(actual.buffer, fill ? 0xa5 : 0x35, sizeof(actual.buffer));
                actual.index = offset;
                actual.unsigned_num = fill != 0;
                actual.buffer[offset] = 0;
                memcpy(&expected, &actual, sizeof(expected));
                memcpy(expected.buffer + offset, old, length + 1);
                expected.index += length;
                SStream_concat0_small(&actual, text, width);
                if (memcmp(&actual, &expected, sizeof(expected)))
                    return 2;
                ++count;
            }
        }
    }
    printf("%u %lu\n", total, count);
    return 0;
}
