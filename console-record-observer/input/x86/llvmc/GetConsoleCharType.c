#include <stdbool.h>
#include <stdint.h>

#if !defined(__SIZEOF_INT128__) && defined(__BITINT_MAXWIDTH__) && __BITINT_MAXWIDTH__ >= 128
typedef unsigned _BitInt(128) __uint128_t;
typedef _BitInt(128) __int128_t;
#endif


typedef struct _COORD _COORD;

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


__attribute__((stdcall)) int32_t GetConsoleCharType(void* hConsole, struct _COORD coordCheck, __typeof__(__builtin_choose_expr(sizeof(unsigned long) == 4, (unsigned long)0, (uint32_t)0))* pdwType);
uint32_t InspectGetConsoleCharType(uint32_t arg0, uint32_t arg1, uint32_t arg2) {
    return ((uint32_t)(uint32_t)(GetConsoleCharType((void*)(uintptr_t)(arg0), ({ struct _COORD __neverd_record; uint32_t __neverd_piece0 = (uint32_t)(uintptr_t)(arg1); __builtin_memcpy((unsigned char *)&__neverd_record + 0, &__neverd_piece0, 4); __neverd_record; }), (__typeof__(__builtin_choose_expr(sizeof(unsigned long) == 4, (unsigned long)0, (uint32_t)0))*)(uintptr_t)(arg2))));
}

