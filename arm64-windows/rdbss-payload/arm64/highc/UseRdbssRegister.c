typedef struct _RDBSS_DEVICE_OBJECT _RDBSS_DEVICE_OBJECT;
typedef struct RDBSS__DRIVER_OBJECT RDBSS__DRIVER_OBJECT;
typedef struct _MINIRDR_DISPATCH _MINIRDR_DISPATCH;
typedef struct _UNICODE_STRING _UNICODE_STRING;

#include <stdint.h>

extern __typeof__(__builtin_choose_expr(sizeof(long) == 4, (long)0, (int32_t)0)) RxRegisterMinirdr(struct _RDBSS_DEVICE_OBJECT **DeviceObject, struct RDBSS__DRIVER_OBJECT *DriverObject, struct _MINIRDR_DISPATCH *MrdrDispatch, __typeof__(__builtin_choose_expr(sizeof(unsigned long) == 4, (unsigned long)0, (uint32_t)0)) Controls, struct _UNICODE_STRING *DeviceName, __typeof__(__builtin_choose_expr(sizeof(unsigned long) == 4, (unsigned long)0, (uint32_t)0)) DeviceExtensionSize, __typeof__(__builtin_choose_expr(sizeof(unsigned long) == 4, (unsigned long)0, (uint32_t)0)) DeviceType, __typeof__(__builtin_choose_expr(sizeof(unsigned long) == 4, (unsigned long)0, (uint32_t)0)) DeviceCharacteristics);

/* neverd.entry: 0x180001000 */
/* neverd.exception: encoding=arm64-packed, status=complete, personality=none
 * code=[0x180001000, 0x180001010)
 * highir.structured_regions=0, fallback_regions=0
 */
int64_t UseRdbssRegister(_RDBSS_DEVICE_OBJECT** arg0, RDBSS__DRIVER_OBJECT* arg1, _MINIRDR_DISPATCH* arg2, int32_t arg3, _UNICODE_STRING* arg4, int32_t arg5, int32_t arg6, int32_t arg7) {
    return (uint64_t)((uint32_t)RxRegisterMinirdr(arg0, arg1, arg2, arg3, arg4, arg5, arg6, arg7));
}
__typeof__(&RxRegisterMinirdr) neverd_ucrt_abi_0 = &RxRegisterMinirdr;
