#include <stdint.h>

extern __typeof__(__builtin_choose_expr(sizeof(long) == 4, (long)0, (int32_t)0)) RxTearDownDispatcher(void);

/* neverd.entry: 0x180001060 */
/* neverd.exception: encoding=arm64-packed, status=complete, personality=none
 * code=[0x180001060, 0x180001070)
 * highir.structured_regions=0, fallback_regions=0
 */
int64_t UseRdbssTearDownDispatcher(void) {
    return (uint64_t)((uint32_t)RxTearDownDispatcher());
}
__typeof__(&RxTearDownDispatcher) neverd_ucrt_abi_0 = &RxTearDownDispatcher;
