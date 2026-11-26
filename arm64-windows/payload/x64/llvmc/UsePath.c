#include <stdint.h>

/* Scalars are read and written through plain pointer casts at any address:
   build for a target with unaligned access, with -fno-strict-aliasing. */


/* neverd.image: 0x180000000 (original loaded image storage) */
extern uint8_t unk_180000000[9739];
extern int32_t PathCchCombineEx(uint16_t *pszPathOut, __typeof__(__builtin_choose_expr(sizeof(unsigned long long) == 8, (unsigned long long)0, (uint64_t)0)) cchPathOut, const uint16_t *pszPathIn, const uint16_t *pszMore, __typeof__(__builtin_choose_expr(sizeof(unsigned long) == 4, (unsigned long)0, (uint32_t)0)) dwFlags);
uint64_t UsePath(uint16_t* arg0, uint64_t arg1, uint16_t* arg2, uint16_t* arg3, uint64_t arg4) {
    uint64_t icall_image_target1;
    uint64_t call0;

    icall_image_target1 = 0;
    __builtin_memcpy(&icall_image_target1, (unk_180000000 + 9080), 8);
    call0 = ((uint64_t)(uint32_t)(PathCchCombineEx((uint16_t *)(uintptr_t)((uint64_t)arg0), (__typeof__(__builtin_choose_expr(sizeof(unsigned long long) == 8, (unsigned long long)0, (uint64_t)0)))(uintptr_t)(arg1), (const uint16_t *)(uintptr_t)((uint64_t)arg2), (const uint16_t *)(uintptr_t)((uint64_t)arg3), (__typeof__(__builtin_choose_expr(sizeof(unsigned long) == 4, (unsigned long)0, (uint32_t)0)))(uintptr_t)((uint32_t)(arg4)))));
    return call0;
}
