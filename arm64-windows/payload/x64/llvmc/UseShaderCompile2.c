#include <stdint.h>


typedef struct ID3D10Blob ID3D10Blob;
typedef struct ID3DInclude ID3DInclude;
typedef struct _D3D_SHADER_MACRO _D3D_SHADER_MACRO;
int32_t D3DCompile2(const void *pSrcData, __typeof__(__builtin_choose_expr(sizeof(unsigned long long) == 8, (unsigned long long)0, (uint64_t)0)) SrcDataSize, const char *pSourceName, const struct _D3D_SHADER_MACRO *pDefines, struct ID3DInclude *pInclude, const char *pEntrypoint, const char *pTarget, uint32_t Flags1, uint32_t Flags2, uint32_t SecondaryDataFlags, const void *pSecondaryData, __typeof__(__builtin_choose_expr(sizeof(unsigned long long) == 8, (unsigned long long)0, (uint64_t)0)) SecondaryDataSize, struct ID3D10Blob **ppCode, struct ID3D10Blob **ppErrorMsgs);
uint64_t UseShaderCompile2(void* arg0, uint64_t arg1, char* arg2, _D3D_SHADER_MACRO* arg3, uint64_t arg4, uint64_t arg5, uint64_t arg6, uint64_t arg7, uint64_t arg8, uint64_t arg9, uint64_t arg10, uint64_t arg11, uint64_t arg12, uint64_t arg13) {
    uint64_t call0;

    call0 = ((uint64_t)(uint32_t)(D3DCompile2((const void *)(uintptr_t)((uint64_t)arg0), (__typeof__(__builtin_choose_expr(sizeof(unsigned long long) == 8, (unsigned long long)0, (uint64_t)0)))(uintptr_t)(arg1), (const char *)(uintptr_t)((uint64_t)arg2), (const struct _D3D_SHADER_MACRO *)(uintptr_t)((uint64_t)arg3), (struct ID3DInclude *)(uintptr_t)(arg4), (const char *)(uintptr_t)(arg5), (const char *)(uintptr_t)(arg6), (uint32_t)(uintptr_t)((uint32_t)(arg7)), (uint32_t)(uintptr_t)((uint32_t)(arg8)), (uint32_t)(uintptr_t)((uint32_t)(arg9)), (const void *)(uintptr_t)(arg10), (__typeof__(__builtin_choose_expr(sizeof(unsigned long long) == 8, (unsigned long long)0, (uint64_t)0)))(uintptr_t)(arg11), (struct ID3D10Blob **)(uintptr_t)(arg12), (struct ID3D10Blob **)(uintptr_t)(arg13))));
    return call0;
}
