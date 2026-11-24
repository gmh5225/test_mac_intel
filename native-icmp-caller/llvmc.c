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


extern int32_t IcmpCloseHandle(void *IcmpHandle);
uint64_t UseIcmpHandle(void* arg0) {
    uint64_t call1;

    call1 = ((uint64_t)(uint32_t)(IcmpCloseHandle((void *)(uintptr_t)((uint64_t)arg0))));
    return call1;
}

__typeof__(&IcmpCloseHandle) neverd_ucrt_abi_0 = &IcmpCloseHandle;
