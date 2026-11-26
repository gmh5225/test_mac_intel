typedef struct _SD_MINIPORT _SD_MINIPORT;

#include <stdint.h>

extern __typeof__(__builtin_choose_expr(sizeof(long) == 4, (long)0, (int32_t)0)) SdPortGetPciConfigSpace(struct _SD_MINIPORT *Miniport, uint8_t Offset, uint8_t *Buffer, __typeof__(__builtin_choose_expr(sizeof(unsigned long) == 4, (unsigned long)0, (uint32_t)0)) Length);

/* neverd.entry: 0x180001000 */
int64_t UseSDConfig(_SD_MINIPORT* arg0, int32_t arg1, uint8_t* arg2, int32_t arg3) {
    return (uint64_t)((uint32_t)SdPortGetPciConfigSpace(arg0, arg1, arg2, arg3));
}
