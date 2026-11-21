#include <stdint.h>

/* Scalars are read and written through plain pointer casts at any address:
   build for a target with unaligned access, with -fno-strict-aliasing. */

/* neverd.entry: 0x140001000 */
/* neverd.debug: return=uint64_t params=2 */
__attribute__((cdecl)) uint64_t observe_entry(uint64_t* state, uint64_t argument) {
    uint64_t t2;
    int64_t t5;

    t2 = *(uint64_t *)state;
    t5 = *(int64_t *)((uintptr_t)state + 8);
    *(int64_t *)state = __builtin_bit_cast(int64_t, t2 + argument) ^ t5;
    *(int64_t *)((uintptr_t)state + 8) = argument;
    return __builtin_bit_cast(int64_t, t2 + argument) ^ t5;
}
