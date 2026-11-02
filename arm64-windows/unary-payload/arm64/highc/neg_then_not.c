#include <stdint.h>

/* neverd.entry: 0x180001130 */
int64_t neg_then_not(int64_t arg0) {
    return ~__builtin_bit_cast(int64_t, 0 - (uint64_t)arg0);
}
