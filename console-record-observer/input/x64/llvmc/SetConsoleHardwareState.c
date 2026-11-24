#include <stdbool.h>
#include <stdint.h>


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


int32_t SetConsoleHardwareState(void* hConsoleOutput, struct _COORD dwResolution, struct _COORD dwFontSize);
uint64_t InspectSetConsoleHardwareState(uint64_t arg0, uint64_t arg1, uint64_t arg2) {
    uint64_t call0;

    call0 = ((uint64_t)(uint32_t)(SetConsoleHardwareState((void*)(uintptr_t)(arg0), ({ struct _COORD __neverd_record; uint32_t __neverd_piece0 = (uint32_t)(uintptr_t)(arg1); __builtin_memcpy((unsigned char *)&__neverd_record + 0, &__neverd_piece0, 4); __neverd_record; }), ({ struct _COORD __neverd_record; uint32_t __neverd_piece0 = (uint32_t)(uintptr_t)(arg2); __builtin_memcpy((unsigned char *)&__neverd_record + 0, &__neverd_piece0, 4); __neverd_record; }))));
    return call0;
}

