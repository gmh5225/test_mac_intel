#include <stdint.h>


__typeof__(__builtin_choose_expr(sizeof(long) == 4, (long)0, (int32_t)0)) RxInitializeRxTimer(void);
/* neverd.exception: encoding=x64-unwind-v1, status=complete, personality=
 * code=[0x180001080, 0x18000108F), unwind=0x180002284 */
uint64_t UseRdbssInitializeTimer() {
    return ((uint64_t)(uint32_t)(RxInitializeRxTimer()));
}

__typeof__(&RxInitializeRxTimer) neverd_ucrt_abi_0 = &RxInitializeRxTimer;
