#include <stdint.h>


uint64_t read_cpu_leaf(uint32_t);
uint64_t consume_four(uint64_t, uint64_t, uint64_t, uint64_t);
/* neverd.exception: encoding=x64-unwind-v1, status=complete, personality=
 * code=[0x140001000, 0x14000101A), unwind=0x1400020F8 */
uint64_t forward_4(uint32_t arg0, uint64_t arg1, uint64_t arg2, uint64_t arg3) {
    uint64_t call0;

    call0 = read_cpu_leaf(arg0);
    return consume_four(0, 0, 0, arg3);
}

