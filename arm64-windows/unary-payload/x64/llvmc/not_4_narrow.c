#include <stdint.h>


uint64_t not_4_narrow(uint64_t arg0) {
    return (arg0 | -4294967296);
}
