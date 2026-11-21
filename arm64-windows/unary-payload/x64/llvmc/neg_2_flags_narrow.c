#include <immintrin.h>
#include <intrin.h>
#include <stdint.h>


uint64_t neg_2_flags_narrow(uint64_t arg0) {
    uint64_t eflags0;

    eflags0 = __readeflags();
    return ((uint64_t)(((uint8_t)(((uint64_t)(((uint64_t)((uint32_t)((0 - arg0))))) != 0)) & (((uint8_t)1 << 1) - 1))) ^ (0 - (uint64_t)((uint32_t)((0 - arg0)))));
}
