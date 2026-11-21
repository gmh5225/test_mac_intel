typedef struct RDBSS__IRP RDBSS__IRP;
typedef struct _RDBSS_DEVICE_OBJECT _RDBSS_DEVICE_OBJECT;
typedef struct _RX_CONTEXT _RX_CONTEXT;

#include <stdint.h>

extern struct _RX_CONTEXT *RxCreateRxContext(struct RDBSS__IRP *Irp, struct _RDBSS_DEVICE_OBJECT *RxDeviceObject, __typeof__(__builtin_choose_expr(sizeof(unsigned long) == 4, (unsigned long)0, (uint32_t)0)) InitialContextFlags);

/* neverd.entry: 0x180001030 */
/* neverd.exception: encoding=arm64-packed, status=complete, personality=none
 * code=[0x180001030, 0x180001040)
 * highir.structured_regions=0, fallback_regions=0
 */
int64_t UseRdbssCreateContext(RDBSS__IRP* arg0, _RDBSS_DEVICE_OBJECT* arg1, int32_t arg2) {
    return (int64_t)(uintptr_t)RxCreateRxContext(arg0, arg1, arg2);
}
__typeof__(&RxCreateRxContext) neverd_ucrt_abi_0 = &RxCreateRxContext;
