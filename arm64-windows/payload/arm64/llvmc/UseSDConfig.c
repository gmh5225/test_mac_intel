#include <stdint.h>


typedef struct _SD_MINIPORT _SD_MINIPORT;
__typeof__(__builtin_choose_expr(sizeof(long) == 4, (long)0, (int32_t)0)) SdPortGetPciConfigSpace(struct _SD_MINIPORT *Miniport, uint8_t Offset, uint8_t *Buffer, __typeof__(__builtin_choose_expr(sizeof(unsigned long) == 4, (unsigned long)0, (uint32_t)0)) Length);
uint64_t UseSDConfig(_SD_MINIPORT* arg0, uint32_t arg1, uint8_t* arg2, uint32_t arg3) {
    uint64_t call0;

    call0 = ((uint64_t)(uint32_t)(SdPortGetPciConfigSpace((struct _SD_MINIPORT *)(uintptr_t)((uint64_t)arg0), (uint8_t)(uintptr_t)(arg1), (uint8_t *)(uintptr_t)((uint64_t)arg2), (__typeof__(__builtin_choose_expr(sizeof(unsigned long) == 4, (unsigned long)0, (uint32_t)0)))(uintptr_t)(arg3))));
    return call0;
}
