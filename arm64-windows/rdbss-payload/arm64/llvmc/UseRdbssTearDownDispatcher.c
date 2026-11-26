#include <stdint.h>


__typeof__(__builtin_choose_expr(sizeof(long) == 4, (long)0, (int32_t)0)) RxTearDownDispatcher(void);
/* neverd.exception: encoding=arm64-packed, status=complete, personality=
 * code=[0x180001060, 0x180001070) */
uint64_t UseRdbssTearDownDispatcher() {
    return ((uint64_t)(uint32_t)(RxTearDownDispatcher()));
}

__typeof__(&RxTearDownDispatcher) neverd_ucrt_abi_0 = &RxTearDownDispatcher;
