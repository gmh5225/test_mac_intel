#include <stdint.h>

/* neverd.entry: 0x180001070 */
int64_t not_4_narrow(int64_t arg0) {
    return ~(int64_t)(uint32_t)((int32_t)(~arg0));
}
