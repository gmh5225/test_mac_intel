#include <stdint.h>


uint64_t neg_4_narrow(uint64_t arg0) {
    return (0 - (uint64_t)((uint32_t)((0 - arg0))));
}
