#include <stdint.h>


__typeof__(__builtin_choose_expr(sizeof(long) == 4, (long)0, (int32_t)0)) RxTearDownDispatcher(void);
/* neverd.exception: encoding=x64-unwind-v1, status=complete, personality=
 * code=[0x180001090, 0x18000109F), unwind=0x18000228C */
uint64_t UseRdbssTearDownDispatcher() {
    return ((uint64_t)(uint32_t)(RxTearDownDispatcher()));
}

__typeof__(&RxTearDownDispatcher) neverd_ucrt_abi_0 = &RxTearDownDispatcher;
