#include <immintrin.h>
#include <intrin.h>
#include <stdint.h>
#include <string.h>

/* Scalars are read and written through plain pointer casts at any address:
   build for a target with unaligned access, with -fno-strict-aliasing. */

/* neverd.entry: 0x180001120 */
int64_t neg_2_flags_narrow(int64_t arg0) {
    int64_t var_m8;
    int64_t t4_2;
    int32_t t4_3;
    uint64_t v0;
    int64_t v1;

    v0 = (uint32_t)((int32_t)(0 - (uint64_t)arg0));
    v1 = __builtin_bit_cast(int64_t, 0 - v0);
    t4_2 = __readeflags();
    var_m8 = ((((((t4_2 & -2262) | (int64_t)(v0 != 0)) | (uint64_t)((int64_t)((uint8_t)(__builtin_popcount((uint8_t)v1) & 1) == 0)) << 2) | (uint64_t)((int64_t)(((v0 ^ v1) & 0x10) != 0)) << 4) | (uint64_t)((int64_t)(v1 == 0)) << 6) | (uint64_t)((int64_t)(v1 < 0)) << 7) | (uint64_t)((int64_t)__builtin_sub_overflow(__builtin_bit_cast(int64_t, (uint64_t)0), __builtin_bit_cast(int64_t, v0), &(int64_t){0})) << 0xB;
    t4_3 = var_m8;
    return v1 ^ (int64_t)(uint32_t)(t4_3 & 0x801);
}
