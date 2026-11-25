#include <stdint.h>

extern int32_t ProcessPrng(uint8_t *pbData, __typeof__(__builtin_choose_expr(sizeof(unsigned long long) == 8, (unsigned long long)0, (uint64_t)0)) cbData);

/* neverd.entry: 0x180001000 */
int64_t InspectProcessPrng(uint8_t* arg0, int64_t arg1) {
    return (uint64_t)((uint32_t)ProcessPrng(arg0, arg1));
}
