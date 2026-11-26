#include <stdint.h>

extern __typeof__(__builtin_choose_expr(sizeof(long) == 4, (long)0, (int32_t)0)) RxInitializeRxTimer(void);

/* neverd.entry: 0x180001080 */
/* neverd.exception: encoding=x64-unwind-v1, status=complete, personality=none
 * code=[0x180001080, 0x18000108F), unwind=0x180002284
 * highir.structured_regions=0, fallback_regions=0
 */
int64_t UseRdbssInitializeTimer(void) {
    return (uint64_t)((uint32_t)RxInitializeRxTimer());
}
__typeof__(&RxInitializeRxTimer) neverd_ucrt_abi_0 = &RxInitializeRxTimer;
