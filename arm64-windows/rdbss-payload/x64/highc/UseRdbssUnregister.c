typedef struct _RDBSS_DEVICE_OBJECT _RDBSS_DEVICE_OBJECT;

#include <stdint.h>

extern void RxpUnregisterMinirdr(struct _RDBSS_DEVICE_OBJECT *RxDeviceObject);

/* neverd.entry: 0x180001050 */
/* neverd.exception: encoding=x64-unwind-v1, status=complete, personality=none
 * code=[0x180001050, 0x18000105F), unwind=0x18000226C
 * highir.structured_regions=0, fallback_regions=0
 */
void UseRdbssUnregister(_RDBSS_DEVICE_OBJECT* arg0) {
    RxpUnregisterMinirdr(arg0);
    return;
}
__typeof__(&RxpUnregisterMinirdr) neverd_ucrt_abi_0 = &RxpUnregisterMinirdr;
