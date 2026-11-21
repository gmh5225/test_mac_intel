#include <stdint.h>

/* A freestanding, two-register Windows function with caller-owned state. */
__declspec(dllexport) uint64_t observe_entry(uint64_t *state, uint64_t argument) {
    uint64_t result = (state[0] + argument) ^ state[1];
    state[0] = result;
    state[1] = argument;
    return result;
}
