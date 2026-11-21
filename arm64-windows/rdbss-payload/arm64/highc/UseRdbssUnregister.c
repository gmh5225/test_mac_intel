typedef struct _RDBSS_DEVICE_OBJECT _RDBSS_DEVICE_OBJECT;

#include <stdint.h>

extern void RxpUnregisterMinirdr(struct _RDBSS_DEVICE_OBJECT *RxDeviceObject);

/* neverd.entry: 0x180001020 */
/* neverd.exception: encoding=arm64-packed, status=complete, personality=none
 * code=[0x180001020, 0x180001030)
 * highir.structured_regions=0, fallback_regions=0
 */
void UseRdbssUnregister(_RDBSS_DEVICE_OBJECT* arg0) {
    RxpUnregisterMinirdr(arg0);
    return;
}
__typeof__(&RxpUnregisterMinirdr) neverd_ucrt_abi_0 = &RxpUnregisterMinirdr;
