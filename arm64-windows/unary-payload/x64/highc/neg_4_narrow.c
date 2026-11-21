#include <stdint.h>

/* neverd.entry: 0x1800010C0 */
int64_t neg_4_narrow(int64_t arg0) {
    return __builtin_bit_cast(int64_t, 0 - (uint64_t)(uint32_t)((int32_t)(0 - (uint64_t)arg0)));
}
