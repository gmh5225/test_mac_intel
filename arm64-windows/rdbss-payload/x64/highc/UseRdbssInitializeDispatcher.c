#include <stdint.h>

extern __typeof__(__builtin_choose_expr(sizeof(long) == 4, (long)0, (int32_t)0)) RxInitializeDispatcher(void);

/* neverd.entry: 0x180001070 */
/* neverd.exception: encoding=x64-unwind-v1, status=complete, personality=none
 * code=[0x180001070, 0x18000107F), unwind=0x18000227C
 * highir.structured_regions=0, fallback_regions=0
 */
int64_t UseRdbssInitializeDispatcher(void) {
    return (uint64_t)((uint32_t)RxInitializeDispatcher());
}
__typeof__(&RxInitializeDispatcher) neverd_ucrt_abi_0 = &RxInitializeDispatcher;
