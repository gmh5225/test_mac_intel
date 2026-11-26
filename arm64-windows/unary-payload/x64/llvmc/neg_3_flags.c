#include <immintrin.h>
#include <intrin.h>
#include <stdint.h>


uint64_t neg_3_flags(uint64_t arg0) {
    uint64_t eflags0;

    eflags0 = __readeflags();
    return ((((arg0 == (uint64_t)(-9223372036854775807LL - 1)) ? 0x800 : 0) | (uint64_t)(((uint8_t)((arg0 != 0)) & (((uint8_t)1 << 1) - 1)))) ^ (0 - arg0));
}
