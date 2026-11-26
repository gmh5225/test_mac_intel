#include <stdint.h>


typedef struct RDBSS__IRP RDBSS__IRP;
typedef struct _RDBSS_DEVICE_OBJECT _RDBSS_DEVICE_OBJECT;
typedef struct _RX_CONTEXT _RX_CONTEXT;
struct _RX_CONTEXT *RxCreateRxContext(struct RDBSS__IRP *Irp, struct _RDBSS_DEVICE_OBJECT *RxDeviceObject, __typeof__(__builtin_choose_expr(sizeof(unsigned long) == 4, (unsigned long)0, (uint32_t)0)) InitialContextFlags);
/* neverd.exception: encoding=x64-unwind-v1, status=complete, personality=
 * code=[0x180001060, 0x18000106F), unwind=0x180002274 */
uint64_t UseRdbssCreateContext(RDBSS__IRP* arg0, _RDBSS_DEVICE_OBJECT* arg1, uint32_t arg2) {
    uint64_t call0;

    call0 = ((uint64_t)(uintptr_t)(RxCreateRxContext((struct RDBSS__IRP *)(uintptr_t)((uint64_t)arg0), (struct _RDBSS_DEVICE_OBJECT *)(uintptr_t)((uint64_t)arg1), (__typeof__(__builtin_choose_expr(sizeof(unsigned long) == 4, (unsigned long)0, (uint32_t)0)))(uintptr_t)(arg2))));
    return call0;
}

__typeof__(&RxCreateRxContext) neverd_ucrt_abi_0 = &RxCreateRxContext;
