#include <stdint.h>

/* Scalars are read and written through plain pointer casts at any address:
   build for a target with unaligned access, with -fno-strict-aliasing. */


uint64_t observe_entry(uint64_t* state, uint64_t argument) {
    uint64_t ld0;
    void* memptr101;
    uint64_t ld112;
    uint64_t xor3;

    ld0 = *(uint64_t *)state;
    memptr101 = (void*)((uint64_t)state + 8);
    ld112 = *(uint64_t *)memptr101;
    xor3 = (ld0 + argument) ^ ld112;
    *(uint64_t *)state = xor3;
    *(uint64_t *)memptr101 = argument;
    return xor3;
}

