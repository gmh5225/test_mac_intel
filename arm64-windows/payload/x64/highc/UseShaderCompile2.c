typedef struct _D3D_SHADER_MACRO _D3D_SHADER_MACRO;
typedef struct ID3DInclude ID3DInclude;
typedef struct ID3D10Blob ID3D10Blob;

#include <immintrin.h>
#include <stdint.h>
#include <string.h>

/* Scalars are read and written through plain pointer casts at any address:
   build for a target with unaligned access, with -fno-strict-aliasing. */

extern int32_t D3DCompile2(const void *pSrcData, __typeof__(__builtin_choose_expr(sizeof(unsigned long long) == 8, (unsigned long long)0, (uint64_t)0)) SrcDataSize, const char *pSourceName, const struct _D3D_SHADER_MACRO *pDefines, struct ID3DInclude *pInclude, const char *pEntrypoint, const char *pTarget, uint32_t Flags1, uint32_t Flags2, uint32_t SecondaryDataFlags, const void *pSecondaryData, __typeof__(__builtin_choose_expr(sizeof(unsigned long long) == 8, (unsigned long long)0, (uint64_t)0)) SecondaryDataSize, struct ID3D10Blob **ppCode, struct ID3D10Blob **ppErrorMsgs);

/* neverd.entry: 0x1800011D0 */
int64_t UseShaderCompile2(void* arg0, int64_t arg1, char* arg2, _D3D_SHADER_MACRO* arg3, int64_t arg4, int64_t arg5, int64_t arg6, int64_t arg7, int64_t arg8, int64_t arg9, int64_t arg10, int64_t arg11, int64_t arg12, int64_t arg13) {
    _Alignas(16) struct frame_1800011D0 {
        uint8_t gap0[48];
        __int128 var_m58;
        int64_t var_m48;
        int32_t var_m40;
        uint8_t gap4C[4];
        int32_t var_m38;
        uint8_t gap54[4];
        int32_t var_m30;
        uint8_t gap5C[4];
        __int128 var_m28;
        __int128 var_m18;
        uint8_t gap80[48];
        __int128 var_28;
        uint8_t gapC0[32];
        __int128 var_58;
        __int128 var_68;
        uint8_t gap100[8];
    } stack_storage;
    __int128 t45;
    __int128 t45_1;

    *(int64_t *)&stack_storage.var_28 = arg4;
    *(int64_t *)((uint8_t *)&stack_storage.var_28 + 8) = arg5;
    *(int64_t *)&stack_storage.var_58 = arg10;
    *(int64_t *)((uint8_t *)&stack_storage.var_58 + 8) = arg11;
    *(int64_t *)&stack_storage.var_68 = arg12;
    *(int64_t *)((uint8_t *)&stack_storage.var_68 + 8) = arg13;
    t45 = stack_storage.var_28;
    t45_1 = stack_storage.var_58;
    stack_storage.var_m18 = stack_storage.var_68;
    stack_storage.var_m28 = t45_1;
    stack_storage.var_m30 = arg9;
    stack_storage.var_m38 = arg8;
    stack_storage.var_m40 = arg7;
    stack_storage.var_m48 = arg6;
    stack_storage.var_m58 = t45;
    return (uint64_t)((uint32_t)D3DCompile2(arg0, arg1, arg2, arg3, (struct ID3DInclude *)(uintptr_t)*(int64_t *)&stack_storage.var_m58, (const char *)(uintptr_t)*(int64_t *)((uint8_t *)&stack_storage.var_m58 + 8), (const char *)(uintptr_t)arg6, arg7, arg8, arg9, (const void *)(uintptr_t)*(int64_t *)&stack_storage.var_m28, *(int64_t *)((uint8_t *)&stack_storage.var_m28 + 8), (struct ID3D10Blob **)(uintptr_t)*(int64_t *)&stack_storage.var_m18, (struct ID3D10Blob **)(uintptr_t)*(int64_t *)((uint8_t *)&stack_storage.var_m18 + 8)));
}
