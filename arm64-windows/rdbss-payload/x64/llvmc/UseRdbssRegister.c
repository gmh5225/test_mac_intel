#include <stdint.h>


typedef struct RDBSS__DRIVER_OBJECT RDBSS__DRIVER_OBJECT;
typedef struct _MINIRDR_DISPATCH _MINIRDR_DISPATCH;
typedef struct _RDBSS_DEVICE_OBJECT _RDBSS_DEVICE_OBJECT;
typedef struct _UNICODE_STRING _UNICODE_STRING;
__typeof__(__builtin_choose_expr(sizeof(long) == 4, (long)0, (int32_t)0)) RxRegisterMinirdr(struct _RDBSS_DEVICE_OBJECT **DeviceObject, struct RDBSS__DRIVER_OBJECT *DriverObject, struct _MINIRDR_DISPATCH *MrdrDispatch, __typeof__(__builtin_choose_expr(sizeof(unsigned long) == 4, (unsigned long)0, (uint32_t)0)) Controls, struct _UNICODE_STRING *DeviceName, __typeof__(__builtin_choose_expr(sizeof(unsigned long) == 4, (unsigned long)0, (uint32_t)0)) DeviceExtensionSize, __typeof__(__builtin_choose_expr(sizeof(unsigned long) == 4, (unsigned long)0, (uint32_t)0)) DeviceType, __typeof__(__builtin_choose_expr(sizeof(unsigned long) == 4, (unsigned long)0, (uint32_t)0)) DeviceCharacteristics);
/* neverd.exception: encoding=x64-unwind-v1, status=complete, personality=
 * code=[0x180001000, 0x18000103D), unwind=0x18000225C */
uint64_t UseRdbssRegister(_RDBSS_DEVICE_OBJECT** arg0, RDBSS__DRIVER_OBJECT* arg1, _MINIRDR_DISPATCH* arg2, uint32_t arg3, uint64_t arg4, uint64_t arg5, uint64_t arg6, uint64_t arg7) {
    uint64_t call0;

    call0 = ((uint64_t)(uint32_t)(RxRegisterMinirdr((struct _RDBSS_DEVICE_OBJECT **)(uintptr_t)((uint64_t)arg0), (struct RDBSS__DRIVER_OBJECT *)(uintptr_t)((uint64_t)arg1), (struct _MINIRDR_DISPATCH *)(uintptr_t)((uint64_t)arg2), (__typeof__(__builtin_choose_expr(sizeof(unsigned long) == 4, (unsigned long)0, (uint32_t)0)))(uintptr_t)(arg3), (struct _UNICODE_STRING *)(uintptr_t)(arg4), (__typeof__(__builtin_choose_expr(sizeof(unsigned long) == 4, (unsigned long)0, (uint32_t)0)))(uintptr_t)((uint32_t)(arg5)), (__typeof__(__builtin_choose_expr(sizeof(unsigned long) == 4, (unsigned long)0, (uint32_t)0)))(uintptr_t)((uint32_t)(arg6)), (__typeof__(__builtin_choose_expr(sizeof(unsigned long) == 4, (unsigned long)0, (uint32_t)0)))(uintptr_t)((uint32_t)(arg7)))));
    return call0;
}

__typeof__(&RxRegisterMinirdr) neverd_ucrt_abi_0 = &RxRegisterMinirdr;
