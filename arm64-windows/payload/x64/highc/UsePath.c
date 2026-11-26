#include <stdint.h>
#include <string.h>

/* Scalars are read and written through plain pointer casts at any address:
   build for a target with unaligned access, with -fno-strict-aliasing. */

extern int32_t PathCchCombineEx(uint16_t *pszPathOut, __typeof__(__builtin_choose_expr(sizeof(unsigned long long) == 8, (unsigned long long)0, (uint64_t)0)) cchPathOut, const uint16_t *pszPathIn, const uint16_t *pszMore, __typeof__(__builtin_choose_expr(sizeof(unsigned long) == 4, (unsigned long)0, (uint32_t)0)) dwFlags);

/* neverd.entry: 0x180001010 */
int64_t UsePath(uint16_t* arg0, int64_t arg1, uint16_t* arg2, uint16_t* arg3, int64_t arg4) {
    return (uint64_t)((uint32_t)PathCchCombineEx(arg0, arg1, arg2, arg3, arg4));
}
