#include <stdint.h>
#include <stdio.h>
#include "MCInst.h"

extern void *__real_memset(void *, int, size_t);
struct site { uintptr_t pc; uint64_t offsets[64]; };
static struct site sites[16];

void *__wrap_memset(void *dst, int value, size_t n)
{
    if (value == 0 && n == sizeof(MCInst)) {
        uintptr_t pc = (uintptr_t)__builtin_return_address(0);
        for (unsigned i = 0; i != 16; ++i) {
            if (!sites[i].pc || sites[i].pc == pc) {
                sites[i].pc = pc;
                sites[i].offsets[(uintptr_t)dst & 63]++;
                break;
            }
        }
    }
    return __real_memset(dst, value, n);
}

__attribute__((destructor)) static void dump_offsets(void)
{
    for (unsigned i = 0; i != 16 && sites[i].pc; ++i)
        for (unsigned offset = 0; offset != 64; ++offset)
            if (sites[i].offsets[offset])
                fprintf(stderr, "mcinst %zx %zu %u %llu\n", (size_t)sites[i].pc,
                        sizeof(MCInst), offset, (unsigned long long)sites[i].offsets[offset]);
}
