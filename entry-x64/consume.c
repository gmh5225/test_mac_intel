#include <stdint.h>
__declspec(noinline) uint64_t consume_four(uint64_t x, uint64_t y, uint64_t z, uint64_t fourth) {
    return fourth ^ (x + y + z);
}
