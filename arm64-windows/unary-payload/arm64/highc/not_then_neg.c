#include <stdint.h>

/* neverd.entry: 0x180001120 */
int64_t not_then_neg(int64_t arg0) {
    return __builtin_bit_cast(int64_t, 0 - (uint64_t)(~arg0));
}
