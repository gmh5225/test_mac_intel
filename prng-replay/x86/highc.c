#include <stdint.h>

/* Scalars are read and written through plain pointer casts at any address:
   build for a target with unaligned access, with -fno-strict-aliasing. */

extern __attribute__((stdcall)) int32_t ProcessPrng(uint8_t *pbData, __typeof__(__builtin_choose_expr(sizeof(unsigned long) == 4, (unsigned long)0, (uint32_t)0)) cbData);

/* neverd.entry: 0x10001000 */
int32_t InspectProcessPrng(int32_t arg0, int32_t arg1) {
    return ProcessPrng((uint8_t *)(uintptr_t)arg0, arg1);
}
