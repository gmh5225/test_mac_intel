#include <stdint.h>

#ifndef __neverd_aarch64_raw_call
#if defined(__clang__)
#if __has_feature(ptrauth_calls)
#define __neverd_aarch64_raw_call(fn) __builtin_ptrauth_sign_unauthenticated((fn), 0, 0)
#endif
#endif
#ifndef __neverd_aarch64_raw_call
#define __neverd_aarch64_raw_call(fn) (fn)
#endif
#endif

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
    uint64_t ld0;
    uint64_t ld631;
    uint64_t ld912;
    void* v5;
    uint64_t call6;
    uint32_t v7;
    uint64_t ld623;
    uint64_t ld904;
    _Alignas(16) struct {
        uint8_t gap0[8];
        uint64_t var_m28;
        uint8_t gap10[4];
        uint32_t var_m1C;
        uint64_t var_m18;
        uint8_t gap20[96];
    } frame0;

    v5 = __builtin_return_address(0);
    *(uint64_t *)((char*)&frame0 + 40) = (uint64_t)v5;
    frame0.var_m18 = 0;
    ld0 = 0;
    for (unsigned image_byte10 = 0; image_byte10 < 8; ++image_byte10)
        ((uint8_t*)&ld0)[image_byte10] = ((volatile uint8_t*)(unk_180000000 + 8360))[image_byte10];
    call6 = ((uint64_t)(uint32_t)(NdisOpenConfigurationEx((struct _NDIS_CONFIGURATION_OBJECT *)(uintptr_t)((uint64_t)arg0), (void **)(uintptr_t)(&frame0.var_m18))));
    v7 = (uint32_t)(call6);
    frame0.var_m1C = v7;
    if (!(v7)) {
        frame0.var_m28 = 0;
        ld623 = frame0.var_m18;
        ld631 = 0;
        for (unsigned image_byte11 = 0; image_byte11 < 8; ++image_byte11)
            ((uint8_t*)&ld631)[image_byte11] = ((volatile uint8_t*)(unk_180000000 + 8368))[image_byte11];
        NdisReadConfiguration((int32_t *)(uintptr_t)(&frame0.var_m1C), (struct _NDIS_CONFIGURATION_PARAMETER **)(uintptr_t)(&frame0.var_m28), (void *)(uintptr_t)(ld623), (struct _UNICODE_STRING *)(uintptr_t)((uint64_t)arg1), (enum _NDIS_PARAMETER_TYPE)(uintptr_t)(2));
        ld904 = frame0.var_m18;
        ld912 = 0;
        for (unsigned image_byte12 = 0; image_byte12 < 8; ++image_byte12)
            ((uint8_t*)&ld912)[image_byte12] = ((volatile uint8_t*)(unk_180000000 + 8352))[image_byte12];
        NdisCloseConfiguration((void *)(uintptr_t)(ld904));
        return (uint64_t)((uint32_t)(frame0.var_m1C));
    }
    return call6;
}
