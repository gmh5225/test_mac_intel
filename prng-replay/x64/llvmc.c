#include <stdbool.h>
#include <stdint.h>

/* Scalars are read and written through plain pointer casts at any address:
   build for a target with unaligned access, with -fno-strict-aliasing. */


extern int32_t ProcessPrng(uint8_t *pbData, __typeof__(__builtin_choose_expr(sizeof(unsigned long long) == 8, (unsigned long long)0, (uint64_t)0)) cbData);
uint64_t InspectProcessPrng(uint8_t* arg0, uint64_t arg1) {
    uint64_t call0;

    call0 = ((uint64_t)(uint32_t)(ProcessPrng((uint8_t *)(uintptr_t)((uint64_t)arg0), (__typeof__(__builtin_choose_expr(sizeof(unsigned long long) == 8, (unsigned long long)0, (uint64_t)0)))(uintptr_t)(arg1))));
    return call0;
}

