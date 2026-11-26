typedef struct _D3D_SHADER_MACRO _D3D_SHADER_MACRO;
typedef struct ID3DInclude ID3DInclude;
typedef struct ID3D10Blob ID3D10Blob;

#include <stdint.h>
#include <string.h>

/* Scalars are read and written through plain pointer casts at any address:
   build for a target with unaligned access, with -fno-strict-aliasing. */

extern int32_t D3DCompile2(const void *pSrcData, __typeof__(__builtin_choose_expr(sizeof(unsigned long long) == 8, (unsigned long long)0, (uint64_t)0)) SrcDataSize, const char *pSourceName, const struct _D3D_SHADER_MACRO *pDefines, struct ID3DInclude *pInclude, const char *pEntrypoint, const char *pTarget, uint32_t Flags1, uint32_t Flags2, uint32_t SecondaryDataFlags, const void *pSecondaryData, __typeof__(__builtin_choose_expr(sizeof(unsigned long long) == 8, (unsigned long long)0, (uint64_t)0)) SecondaryDataSize, struct ID3D10Blob **ppCode, struct ID3D10Blob **ppErrorMsgs);

/* neverd.entry: 0x180001118 */
int64_t UseShaderCompile2(void* arg0, int64_t arg1, char* arg2, _D3D_SHADER_MACRO* arg3, ID3DInclude* arg4, char* arg5, char* arg6, int32_t arg7, int64_t arg8, int64_t arg9, int64_t arg10, int64_t arg11, int64_t arg12, int64_t arg13) {
    _Alignas(16) struct frame_180001118 {
        int32_t var_m40;
        uint8_t gap4[4];
        int32_t var_m38;
        uint8_t gapC[4];
        unsigned __int128 var_m30;
        int64_t var_m20;
        int64_t var_m18;
        uint8_t gap30[64];
    } stack_storage;
    stack_storage.var_m40 = arg8;
    stack_storage.var_m18 = arg13;
    stack_storage.var_m20 = arg12;
    stack_storage.var_m30 = ((unsigned __int128)((uint64_t)(arg11)) << 64 | (unsigned __int128)((uint64_t)(arg10)));
    stack_storage.var_m38 = arg9;
    return (uint64_t)((uint32_t)D3DCompile2(arg0, arg1, arg2, arg3, arg4, arg5, arg6, arg7, arg8, arg9, (const void *)(uintptr_t)*(int64_t *)&stack_storage.var_m30, *(int64_t *)((uint8_t *)&stack_storage.var_m30 + 8), (struct ID3D10Blob **)(uintptr_t)arg12, (struct ID3D10Blob **)(uintptr_t)arg13));
}
