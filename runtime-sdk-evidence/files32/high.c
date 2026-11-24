#if defined(__GNUC__) && !defined(__clang__) && !__has_builtin(__builtin_rotateleft32)
#define __builtin_rotateleft32(V, A) __extension__ ({ \
    __auto_type __neverd_rotate_value = (__UINT32_TYPE__)(V); \
    unsigned int __neverd_rotate_amount = (A) & 31u; \
    (__UINT32_TYPE__)(__neverd_rotate_amount ? ((__neverd_rotate_value << __neverd_rotate_amount) | (__neverd_rotate_value >> (32 - __neverd_rotate_amount))) : __neverd_rotate_value); })
#endif

typedef union _LARGE_INTEGER _LARGE_INTEGER;

#include <stdint.h>

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


/* Scalars are read and written through plain pointer casts at any address:
   build for a target with unaligned access, with -fno-strict-aliasing. */

extern __attribute__((stdcall)) int32_t SetFilePointerEx(void* hFile, union _LARGE_INTEGER liDistanceToMove, _LARGE_INTEGER* lpNewFilePointer, __typeof__(__builtin_choose_expr(sizeof(unsigned long) == 4, (unsigned long)0, (uint32_t)0)) dwMoveMethod);

/* neverd.entry: 0x401056 */
int32_t Seek(int32_t arg0, int32_t arg1, int32_t arg2) {
    _Alignas(16) struct frame_401056 {
        uint8_t gap0[4];
        int32_t var_m2C;
        int32_t var_m28;
        int32_t var_m24;
        uint32_t var_m20;
        uint32_t var_m1C;
        int32_t var_m18;
        uint32_t var_m14;
        uint8_t gap20[32];
    } stack_storage;
    int32_t v4;

    stack_storage.var_m14 = 0;
    stack_storage.var_m18 = 0;
    stack_storage.var_m1C = 0;
    stack_storage.var_m20 = (uintptr_t)&stack_storage.var_m18;
    stack_storage.var_m24 = arg2;
    stack_storage.var_m28 = arg1;
    stack_storage.var_m2C = arg0;
    v4 = SetFilePointerEx((void*)(uintptr_t)arg0, ({ union _LARGE_INTEGER __neverd_record; uint32_t __neverd_piece0 = (uint32_t)(uintptr_t)(arg1); __builtin_memcpy((unsigned char *)&__neverd_record + 0, &__neverd_piece0, 4); uint32_t __neverd_piece1 = (uint32_t)(uintptr_t)(arg2); __builtin_memcpy((unsigned char *)&__neverd_record + 4, &__neverd_piece1, 4); __neverd_record; }), (_LARGE_INTEGER*)&stack_storage.var_m18, 0);
    return 0 - (uint32_t)((uint32_t)v4 < 1) | stack_storage.var_m18;
}
