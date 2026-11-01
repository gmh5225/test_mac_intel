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


/* neverd.image: 0x180000000 (original loaded image storage) */
extern uint8_t unk_180000000[9739];
extern int32_t PathCchCombineEx(uint16_t *pszPathOut, __typeof__(__builtin_choose_expr(sizeof(unsigned long long) == 8, (unsigned long long)0, (uint64_t)0)) cchPathOut, const uint16_t *pszPathIn, const uint16_t *pszMore, __typeof__(__builtin_choose_expr(sizeof(unsigned long) == 4, (unsigned long)0, (uint32_t)0)) dwFlags);
uint64_t UsePath(uint16_t* arg0, uint64_t arg1, uint16_t* arg2, uint16_t* arg3, uint32_t arg4) {
    uint64_t ld0;
    uint64_t call1;

    ld0 = 0;
    for (unsigned image_byte2 = 0; image_byte2 < 8; ++image_byte2)
        ((uint8_t*)&ld0)[image_byte2] = ((volatile uint8_t*)(unk_180000000 + 9080))[image_byte2];
    call1 = ((uint64_t)(uint32_t)(PathCchCombineEx((uint16_t *)(uintptr_t)((uint64_t)arg0), (__typeof__(__builtin_choose_expr(sizeof(unsigned long long) == 8, (unsigned long long)0, (uint64_t)0)))(uintptr_t)(arg1), (const uint16_t *)(uintptr_t)((uint64_t)arg2), (const uint16_t *)(uintptr_t)((uint64_t)arg3), (__typeof__(__builtin_choose_expr(sizeof(unsigned long) == 4, (unsigned long)0, (uint32_t)0)))(uintptr_t)(arg4))));
    return call1;
}
