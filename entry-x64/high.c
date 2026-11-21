#include <stdint.h>

extern uint64_t consume_four(uint64_t x, uint64_t y, uint64_t z, uint64_t fourth);
extern int64_t read_cpu_leaf();

/* neverd.entry: 0x140001000 */
/* neverd.exception: encoding=x64-unwind-v1, status=complete, personality=none
 * code=[0x140001000, 0x14000101A), unwind=0x1400020F8
 * highir.structured_regions=0, fallback_regions=0
 */
int64_t forward_4(int64_t arg0, int64_t arg1, int64_t arg2, int64_t arg3) {
    read_cpu_leaf();
    return consume_four(0, 0, 0, arg3);
}
