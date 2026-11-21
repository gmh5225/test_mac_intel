#include <stdint.h>

/* Scalars are read and written through plain pointer casts at any address:
   build for a target with unaligned access, with -fno-strict-aliasing. */


typedef struct HINSTANCE__ HINSTANCE__;


// 3 types, from the program's local types.
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

struct HINSTANCE__;

#ifndef NEVERD_TYPE_DWORD
#define NEVERD_TYPE_DWORD
typedef uint32_t DWORD;
#endif

#ifndef NEVERD_TYPE_LPVOID
#define NEVERD_TYPE_LPVOID
typedef void *LPVOID;
#endif

#ifndef NEVERD_TYPE_HINSTANCE
#define NEVERD_TYPE_HINSTANCE
typedef struct HINSTANCE__ *HINSTANCE;
#endif


/* neverd.image: 0x180000000 (original loaded image storage) */
extern uint8_t unk_180000000[12296];
int32_t DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpReserved) {
    uint64_t ld0;

    if (!(fdwReason)) {
        goto L_bb_2;
    }
    return 1;
L_common_ret:
    return 1;
L_bb_2:
    ld0 = 0;
    for (unsigned image_byte1 = 0; image_byte1 < 8; ++image_byte1)
        ((uint8_t*)&ld0)[image_byte1] = ((volatile uint8_t*)(unk_180000000 + 12288))[image_byte1];
    if (!(ld0)) {
        return 1;
    }
    *(uint64_t *)((void*)(ld0 + 8)) = ((uint64_t)(uintptr_t)hinstDLL);
    *(uint64_t *)((void*)(ld0 + 0x10)) = 0;
    *(uint64_t *)((void*)(ld0 + 0x18)) = ((uint64_t)(uintptr_t)lpReserved);
    *(uint64_t *)((void*)(ld0 + 0x20)) = 1;
    return 1;
}

