#include <inttypes.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>
#include "cs_priv.h"
#include "arch/X86/X86SimpleOutput.h"

static unsigned tests;
static unsigned char *page;
static size_t page_size;
static void check(int32_t value)
{
    char expected[20];
    const uint32_t mag = value < 0 ? 0U - (uint32_t)value : (uint32_t)value;
    const char *sign = value < 0 ? " - " : " + ";
    int len = 0;
    if (mag)
        len = (mag > HEX_THRESHOLD)
            ? snprintf(expected, sizeof(expected), "%s0x%" PRIx32, sign, mag)
            : snprintf(expected, sizeof(expected), "%s%" PRIu32, sign, mag);
    if (len < 0 || (size_t)len >= sizeof(expected)) exit(2);
    /* The right-hand guard enforces exact writes and permits zero output. */
    for (unsigned room = 0; room < 2; ++room) {
        size_t extra = room ? 1 + (mag & 15) : 0;
        char *out = (char *)page + page_size - len - extra;
        memset(out - 1, 0xa5, 1 + len + extra);
        char *end = X86_writeDisplacement(out, value);
        if (end != out + len || (unsigned char)out[-1] != 0xa5 ||
            (len && memcmp(out, expected, len))) exit(3);
        for (size_t i = 0; i < extra; ++i)
            if ((unsigned char)end[i] != 0xa5) exit(4);
        ++tests;
    }
}
int main(void)
{
    page_size = sysconf(_SC_PAGESIZE);
    page = mmap(NULL, 2 * page_size, PROT_READ | PROT_WRITE,
                MAP_ANON | MAP_PRIVATE, -1, 0);
    if (page == MAP_FAILED || mprotect(page + page_size, page_size, PROT_NONE)) return 1;
    for (int value = INT16_MIN; value <= INT16_MAX; ++value) check(value);
    for (unsigned bit = 0; bit < 31; ++bit)
        for (int delta = -2; delta <= 2; ++delta) {
            int32_t v = (int32_t)((UINT32_C(1) << bit) + (uint32_t)delta);
            check(v);
            check(-v);
        }
    check(INT32_MIN);
    check(INT32_MAX);
    uint32_t state = UINT32_C(0x49434544);
    for (unsigned i = 0; i < 262144; ++i) {
        state = state * 1664525U + 1013904223U;
        check((int32_t)state);
    }
    printf("%u\n", tests);
    return munmap(page, 2 * page_size) != 0;
}
