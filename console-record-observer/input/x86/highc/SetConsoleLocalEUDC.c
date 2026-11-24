#include <stdint.h>

// 1 types, from the program's local types.
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#if !defined(__cplusplus) && !defined(static_assert)
#define static_assert _Static_assert
#endif

#ifndef NEVERD_TYPE__COORD
#define NEVERD_TYPE__COORD
// _COORD: 0x4 (4) bytes
struct _COORD
{
    int16_t X;                                                  // 0x0
    int16_t Y;                                                  // 0x2
};
static_assert(sizeof(struct _COORD) == 0x4, "_COORD");
static_assert(offsetof(struct _COORD, X) == 0x0, "_COORD.X");
static_assert(offsetof(struct _COORD, Y) == 0x2, "_COORD.Y");
#endif


typedef struct _COORD _COORD;

/* Scalars are read and written through plain pointer casts at any address:
   build for a target with unaligned access, with -fno-strict-aliasing. */

extern __attribute__((stdcall)) int32_t SetConsoleLocalEUDC(void* hConsoleHandle, uint16_t wCodePoint, struct _COORD cFontSize, char* lpSB);

/* neverd.entry: 0x10001000 */
int32_t InspectSetConsoleLocalEUDC(int32_t arg0, int32_t arg1, int32_t arg2, int32_t arg3) {
    return SetConsoleLocalEUDC((void*)(uintptr_t)arg0, arg1, ({ struct _COORD __neverd_record; uint32_t __neverd_piece0 = (uint32_t)(uintptr_t)(arg2); __builtin_memcpy((unsigned char *)&__neverd_record + 0, &__neverd_piece0, 4); __neverd_record; }), (char*)(uintptr_t)arg3);
}
