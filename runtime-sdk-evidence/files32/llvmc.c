#include <stdbool.h>
#include <stdint.h>

#if !defined(__SIZEOF_INT128__) && defined(__BITINT_MAXWIDTH__) && __BITINT_MAXWIDTH__ >= 128
typedef unsigned _BitInt(128) __uint128_t;
typedef _BitInt(128) __int128_t;
#endif

/* Scalars are read and written through plain pointer casts at any address:
   build for a target with unaligned access, with -fno-strict-aliasing. */


typedef union _LARGE_INTEGER _LARGE_INTEGER;

// 2 types, from the program's local types.
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifndef NEVERD_ALIGN8
#if !defined(_MSC_VER) && defined(__i386__)
#define NEVERD_ALIGN8 __attribute__((aligned(8)))
#else
#define NEVERD_ALIGN8
#endif
#endif

#if !defined(__cplusplus) && !defined(static_assert)
#define static_assert _Static_assert
#endif

#ifndef NEVERD_TYPE_DWORD
#define NEVERD_TYPE_DWORD
typedef uint32_t DWORD;
#endif

#ifndef NEVERD_TYPE__LARGE_INTEGER
#define NEVERD_TYPE__LARGE_INTEGER
// _LARGE_INTEGER: 0x8 (8) bytes
union _LARGE_INTEGER
{
    struct                                                      // 0x0
    {
        DWORD LowPart;                                          // 0x0
        int32_t HighPart;                                       // 0x4
    };
    struct
    {
        DWORD LowPart;                                          // 0x0
        int32_t HighPart;                                       // 0x4
    } u;                                                        // 0x0
    NEVERD_ALIGN8 int64_t QuadPart;                             // 0x0
};
static_assert(sizeof(union _LARGE_INTEGER) == 0x8, "_LARGE_INTEGER");
static_assert(offsetof(union _LARGE_INTEGER, LowPart) == 0x0, "_LARGE_INTEGER.LowPart");
static_assert(offsetof(union _LARGE_INTEGER, HighPart) == 0x4, "_LARGE_INTEGER.HighPart");
static_assert(offsetof(union _LARGE_INTEGER, u) == 0x0, "_LARGE_INTEGER.u");
static_assert(offsetof(union _LARGE_INTEGER, QuadPart) == 0x0, "_LARGE_INTEGER.QuadPart");
#endif


extern __attribute__((stdcall)) int32_t SetFilePointerEx(void* hFile, union _LARGE_INTEGER liDistanceToMove, _LARGE_INTEGER* lpNewFilePointer, __typeof__(__builtin_choose_expr(sizeof(unsigned long) == 4, (unsigned long)0, (uint32_t)0)) dwMoveMethod);
uint32_t Seek(uint32_t arg0, uint32_t arg1, uint32_t arg2) {
    uint32_t call0;
    _Alignas(16) struct {
        uint8_t gap0[4];
        uint32_t var_m2C;
        uint32_t var_m28;
        uint32_t var_m24;
        uint32_t var_m20;
        uint32_t var_m1C;
        uint64_t var_m18;
        uint8_t gap20[96];
    } frame0;

    *(uint32_t *)((char*)&frame0 + 28) = 0;
    *(uint32_t *)&frame0.var_m18 = 0;
    frame0.var_m1C = 0;
    frame0.var_m20 = (uint32_t)(uintptr_t)(&frame0.var_m18);
    frame0.var_m24 = arg2;
    frame0.var_m28 = arg1;
    frame0.var_m2C = arg0;
    call0 = ((uint32_t)(uint32_t)(SetFilePointerEx((void*)(uintptr_t)(arg0), ({ union _LARGE_INTEGER __neverd_record; uint32_t __neverd_piece0 = (uint32_t)(uintptr_t)(arg1); __builtin_memcpy((unsigned char *)&__neverd_record + 0, &__neverd_piece0, 4); uint32_t __neverd_piece1 = (uint32_t)(uintptr_t)(arg2); __builtin_memcpy((unsigned char *)&__neverd_record + 4, &__neverd_piece1, 4); __neverd_record; }), (_LARGE_INTEGER*)(uintptr_t)(&frame0.var_m18), (__typeof__(__builtin_choose_expr(sizeof(unsigned long) == 4, (unsigned long)0, (uint32_t)0)))(uintptr_t)(0))));
    return (((unsigned)call0 == 0) ? -1 : *(uint32_t *)&frame0.var_m18);
}

