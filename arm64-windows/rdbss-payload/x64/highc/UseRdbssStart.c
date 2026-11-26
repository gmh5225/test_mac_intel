typedef struct _RX_CONTEXT _RX_CONTEXT;

#include <stdint.h>

extern __typeof__(__builtin_choose_expr(sizeof(long) == 4, (long)0, (int32_t)0)) RxStartMinirdr(struct _RX_CONTEXT *RxContext, uint8_t *PostToFsp);

/* neverd.entry: 0x180001040 */
/* neverd.exception: encoding=x64-unwind-v1, status=complete, personality=none
 * code=[0x180001040, 0x18000104F), unwind=0x180002264
 * highir.structured_regions=0, fallback_regions=0
 */
int64_t UseRdbssStart(_RX_CONTEXT* arg0, uint8_t* arg1) {
    return (uint64_t)((uint32_t)RxStartMinirdr(arg0, arg1));
}
__typeof__(&RxStartMinirdr) neverd_ucrt_abi_0 = &RxStartMinirdr;
