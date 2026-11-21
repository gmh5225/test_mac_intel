#include <stdint.h>


__typeof__(__builtin_choose_expr(sizeof(long) == 4, (long)0, (int32_t)0)) RxInitializeDispatcher(void);
/* neverd.exception: encoding=x64-unwind-v1, status=complete, personality=
 * code=[0x180001070, 0x18000107F), unwind=0x18000227C */
uint64_t UseRdbssInitializeDispatcher() {
    return ((uint64_t)(uint32_t)(RxInitializeDispatcher()));
}

__typeof__(&RxInitializeDispatcher) neverd_ucrt_abi_0 = &RxInitializeDispatcher;
