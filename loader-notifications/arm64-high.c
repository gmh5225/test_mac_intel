typedef struct HINSTANCE__ HINSTANCE__;

#include <stdint.h>

// 5 types, from the program's local types.
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#if !defined(__cplusplus) && !defined(static_assert)
#define static_assert _Static_assert
#endif

#ifndef NEVERD_TYPE_HINSTANCE__
#define NEVERD_TYPE_HINSTANCE__
// HINSTANCE__: 0x4 (4) bytes
struct HINSTANCE__
{
    int32_t unused;                                             // 0x0
};
static_assert(sizeof(struct HINSTANCE__) == 0x4, "HINSTANCE__");
static_assert(offsetof(struct HINSTANCE__, unused) == 0x0, "HINSTANCE__.unused");
#endif

#ifndef NEVERD_TYPE_DWORD
#define NEVERD_TYPE_DWORD
typedef uint32_t DWORD;
#endif

#ifndef NEVERD_TYPE_LPVOID
#define NEVERD_TYPE_LPVOID
typedef void *LPVOID;
#endif

#ifndef NEVERD_TYPE_BOOL
#define NEVERD_TYPE_BOOL
typedef int32_t BOOL;
#endif

#ifndef NEVERD_TYPE_HINSTANCE
#define NEVERD_TYPE_HINSTANCE
typedef struct HINSTANCE__ *HINSTANCE;
#endif


/* Scalars are read and written through plain pointer casts at any address:
   build for a target with unaligned access, with -fno-strict-aliasing. */

/* neverd.image: 0x180003000 */
uint64_t unk_180003000;

/* neverd.entry: 0x180001000 */
/* neverd.prototype: windows-user-arm64: BOOL DllEntryPoint(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpReserved) */
BOOL DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpReserved) {
    uint64_t t7;

    if (fdwReason == 0) {
        t7 = unk_180003000;
        if (t7) {
            *(int64_t *)(t7 + 8) = (uintptr_t)hinstDLL;
            *(uint64_t *)(t7 + 0x10) = 0;
            *(int64_t *)(t7 + 0x18) = (uintptr_t)lpReserved;
            *(uint64_t *)(t7 + 0x20) = 1;
            return 1;
        }
    }
    return 1;
}
