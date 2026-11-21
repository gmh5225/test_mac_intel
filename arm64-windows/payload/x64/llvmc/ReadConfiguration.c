#include <stdint.h>

/* Scalars are read and written through plain pointer casts at any address:
   build for a target with unaligned access, with -fno-strict-aliasing. */


typedef struct _NDIS_CONFIGURATION_OBJECT _NDIS_CONFIGURATION_OBJECT;
typedef struct _NDIS_CONFIGURATION_PARAMETER _NDIS_CONFIGURATION_PARAMETER;
typedef struct _UNICODE_STRING _UNICODE_STRING;

// 1 types, from the program's local types.
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#if !defined(__cplusplus) && !defined(static_assert)
#define static_assert _Static_assert
#endif

#ifndef NEVERD_TYPE__NDIS_PARAMETER_TYPE
#define NEVERD_TYPE__NDIS_PARAMETER_TYPE
// _NDIS_PARAMETER_TYPE: 4 bytes
enum _NDIS_PARAMETER_TYPE
{
    NdisParameterInteger = 0,
    NdisParameterHexInteger = 1,
    NdisParameterString = 2,
    NdisParameterMultiString = 3,
    NdisParameterBinary = 4,
};
static_assert(sizeof(enum _NDIS_PARAMETER_TYPE) == 4, "_NDIS_PARAMETER_TYPE");
#endif


typedef enum _NDIS_PARAMETER_TYPE _NDIS_PARAMETER_TYPE;

/* neverd.image: 0x180000000 (original loaded image storage) */
extern uint8_t unk_180000000[8469];
extern void NdisCloseConfiguration(void *ConfigurationHandle);
extern int32_t NdisOpenConfigurationEx(struct _NDIS_CONFIGURATION_OBJECT *ConfigObject, void **ConfigurationHandle);
extern void NdisReadConfiguration(int32_t *Status, struct _NDIS_CONFIGURATION_PARAMETER **ParameterValue, void *ConfigurationHandle, struct _UNICODE_STRING *Keyword, enum _NDIS_PARAMETER_TYPE ParameterType);
uint64_t ReadConfiguration(_NDIS_CONFIGURATION_OBJECT* arg0, _UNICODE_STRING* arg1) {
    uint64_t icall_image_target5;
    uint64_t icall_image_target646;
    uint64_t icall_image_target897;
    uint64_t call1;
    uint32_t v2;
    uint64_t ld0;
    _Alignas(16) struct {
        uint8_t gap0[48];
        uint32_t var_m28;
        uint8_t gap34[8];
        uint32_t var_m1C;
        uint64_t var_m18;
        uint64_t var_m10;
        uint8_t gap50[88];
    } frame0;

    frame0.var_m18 = 0;
    icall_image_target5 = 0;
    __builtin_memcpy(&icall_image_target5, (unk_180000000 + 8360), 8);
    call1 = ((uint64_t)(uint32_t)(NdisOpenConfigurationEx((struct _NDIS_CONFIGURATION_OBJECT *)(uintptr_t)((uint64_t)arg0), (void **)(uintptr_t)(&frame0.var_m18))));
    v2 = (uint32_t)(call1);
    frame0.var_m1C = v2;
    if (!(v2)) {
        frame0.var_m10 = 0;
        ld0 = frame0.var_m18;
        frame0.var_m28 = 2;
        icall_image_target646 = 0;
        __builtin_memcpy(&icall_image_target646, (unk_180000000 + 8368), 8);
        NdisReadConfiguration((int32_t *)(uintptr_t)(&frame0.var_m1C), (struct _NDIS_CONFIGURATION_PARAMETER **)(uintptr_t)(&frame0.var_m10), (void *)(uintptr_t)(ld0), (struct _UNICODE_STRING *)(uintptr_t)((uint64_t)arg1), (enum _NDIS_PARAMETER_TYPE)(uintptr_t)(2));
        icall_image_target897 = 0;
        __builtin_memcpy(&icall_image_target897, (unk_180000000 + 8352), 8);
        NdisCloseConfiguration((void *)(uintptr_t)(frame0.var_m18));
        return (uint64_t)((uint32_t)(frame0.var_m1C));
    }
    return call1;
}
