#include <stdbool.h>
#include <stdint.h>

#ifndef __neverd_aarch64_code_address
#if defined(__clang__)
#if __has_feature(ptrauth_calls)
#define __neverd_aarch64_code_address(fn) __builtin_ptrauth_strip((void *)(fn), 0)
#endif
#endif
#ifndef __neverd_aarch64_code_address
#define __neverd_aarch64_code_address(fn) (fn)
#endif
#endif
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


extern int32_t ProcessPrng(uint8_t *pbData, __typeof__(__builtin_choose_expr(sizeof(unsigned long long) == 8, (unsigned long long)0, (uint64_t)0)) cbData);
uint64_t InspectProcessPrng(uint8_t* arg0, uint64_t arg1) {
    uint64_t call1;

    call1 = ((uint64_t)(uint32_t)(ProcessPrng((uint8_t *)(uintptr_t)((uint64_t)arg0), (__typeof__(__builtin_choose_expr(sizeof(unsigned long long) == 8, (unsigned long long)0, (uint64_t)0)))(uintptr_t)(arg1))));
    return call1;
}

