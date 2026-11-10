#include <stdint.h>


typedef struct _RDBSS_DEVICE_OBJECT _RDBSS_DEVICE_OBJECT;
void RxpUnregisterMinirdr(struct _RDBSS_DEVICE_OBJECT *RxDeviceObject);
/* neverd.exception: encoding=arm64-packed, status=complete, personality=
 * code=[0x180001020, 0x180001030) */
void UseRdbssUnregister(_RDBSS_DEVICE_OBJECT* arg0) {
    RxpUnregisterMinirdr((struct _RDBSS_DEVICE_OBJECT *)(uintptr_t)((uint64_t)arg0));
    return;
}

__typeof__(&RxpUnregisterMinirdr) neverd_ucrt_abi_0 = &RxpUnregisterMinirdr;
