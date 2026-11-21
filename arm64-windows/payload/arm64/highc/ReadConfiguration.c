typedef struct _NDIS_CONFIGURATION_OBJECT _NDIS_CONFIGURATION_OBJECT;
typedef struct _UNICODE_STRING _UNICODE_STRING;
typedef struct _NDIS_CONFIGURATION_PARAMETER _NDIS_CONFIGURATION_PARAMETER;

#include <stdint.h>
#include <string.h>

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

/* Scalars are read and written through plain pointer casts at any address:
   build for a target with unaligned access, with -fno-strict-aliasing. */

extern void NdisCloseConfiguration(void *ConfigurationHandle);
extern int32_t NdisOpenConfigurationEx(struct _NDIS_CONFIGURATION_OBJECT *ConfigObject, void **ConfigurationHandle);
extern void NdisReadConfiguration(int32_t *Status, struct _NDIS_CONFIGURATION_PARAMETER **ParameterValue, void *ConfigurationHandle, struct _UNICODE_STRING *Keyword, enum _NDIS_PARAMETER_TYPE ParameterType);

/* neverd.entry: 0x180001000 */
int64_t ReadConfiguration(_NDIS_CONFIGURATION_OBJECT* arg0, _UNICODE_STRING* arg1) {
    _Alignas(16) struct frame_180001000 {
        uint8_t gap0[8];
        uint64_t var_m28;
        uint8_t gap10[4];
        uint32_t var_m1C;
        int64_t var_m18;
        uint8_t gap20[32];
    } stack_storage;
    uint64_t v2;

    stack_storage.var_m18 = 0;
    v2 = (uint64_t)((uint32_t)NdisOpenConfigurationEx(arg0, (void **)&stack_storage.var_m18));
    stack_storage.var_m1C = v2;
    if ((int32_t)v2 == 0) {
        stack_storage.var_m28 = 0;
        NdisReadConfiguration((int32_t *)&stack_storage.var_m1C, (struct _NDIS_CONFIGURATION_PARAMETER **)&stack_storage.var_m28, (void *)(uintptr_t)stack_storage.var_m18, arg1, NdisParameterString);
        NdisCloseConfiguration((void *)(uintptr_t)stack_storage.var_m18);
        v2 = stack_storage.var_m1C;
    }
    return v2;
}
