/* Compare the compiled bounded printer with the canonical generated spellings. */
#define X86_Intel_printInstructionPrechecked test_print_instruction
#include "arch/X86/X86IntelInstPrinterPrechecked.c"
#include <stdio.h>

int main(void)
{
    size_t cases = 0;
    for (unsigned reg = 1; reg < X86_NUM_TARGET_REGS; ++reg) {
        const char *name = getRegisterName(reg);
        size_t len = strlen(name);
        if (getRegisterNameLength(reg) != len) return 1;
        for (unsigned pattern = 0; pattern != 2; ++pattern) {
            for (size_t start = 0; start + len < SSTREAM_BUF_LEN; ++start) {
                SStream actual, expected;
                memset(&actual, pattern ? 0x5a : 0xa5, sizeof(actual));
                actual.index = start;
                actual.is_closed = actual.markup_stream = actual.prefixed_by_markup = false;
                actual.unsigned_num = (pattern != 0);
                actual.buffer[start] = 0;
                memcpy(&expected, &actual, sizeof(actual));
                memcpy(expected.buffer + start, name, len + 1);
                expected.index += len;
                printRegName(&actual, reg);
                if (memcmp(&actual, &expected, sizeof(actual))) {
                    fprintf(stderr, "register %u offset %zu size %zu\n", reg, start, len);
                    return 2;
                }
                ++cases;
            }
        }
    }
    printf("%u %zu\n", X86_NUM_TARGET_REGS - 1, cases);
    return 0;
}
