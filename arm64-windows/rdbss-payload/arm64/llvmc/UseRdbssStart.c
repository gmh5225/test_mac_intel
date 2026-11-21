#include <stdint.h>


typedef struct _RX_CONTEXT _RX_CONTEXT;
__typeof__(__builtin_choose_expr(sizeof(long) == 4, (long)0, (int32_t)0)) RxStartMinirdr(struct _RX_CONTEXT *RxContext, uint8_t *PostToFsp);
/* neverd.exception: encoding=arm64-packed, status=complete, personality=
 * code=[0x180001010, 0x180001020) */
uint64_t UseRdbssStart(_RX_CONTEXT* arg0, uint8_t* arg1) {
    uint64_t call0;

    call0 = ((uint64_t)(uint32_t)(RxStartMinirdr((struct _RX_CONTEXT *)(uintptr_t)((uint64_t)arg0), (uint8_t *)(uintptr_t)((uint64_t)arg1))));
    return call0;
}

__typeof__(&RxStartMinirdr) neverd_ucrt_abi_0 = &RxStartMinirdr;
