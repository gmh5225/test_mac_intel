#include <stdbool.h>
#include <stdint.h>

#if !defined(__SIZEOF_INT128__) && defined(__BITINT_MAXWIDTH__) && __BITINT_MAXWIDTH__ >= 128
typedef unsigned _BitInt(128) __uint128_t;
typedef _BitInt(128) __int128_t;
#endif

/* Scalars are read and written through plain pointer casts at any address:
   build for a target with unaligned access, with -fno-strict-aliasing. */


extern __attribute__((stdcall)) int32_t ProcessPrng(uint8_t *pbData, __typeof__(__builtin_choose_expr(sizeof(unsigned long) == 4, (unsigned long)0, (uint32_t)0)) cbData);
uint32_t InspectProcessPrng(uint32_t arg0, uint32_t arg1) {
    return ((uint32_t)(uint32_t)(ProcessPrng((uint8_t *)(uintptr_t)(arg0), (__typeof__(__builtin_choose_expr(sizeof(unsigned long) == 4, (unsigned long)0, (uint32_t)0)))(uintptr_t)(arg1))));
}

