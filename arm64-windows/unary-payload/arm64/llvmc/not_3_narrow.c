#include <stdint.h>


uint64_t not_3_narrow(uint64_t arg0) {
    return ((uint64_t)((uint32_t)(arg0)) ^ 4294967295);
}
