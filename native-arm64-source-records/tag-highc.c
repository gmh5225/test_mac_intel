#include <stdbool.h>
#include <stdint.h>

extern bool IsWellFormedTag(uint16_t* pszTag);

/* neverd.entry: 0x180001000 */
int32_t InspectIsWellFormedTag(uint16_t* arg0) {
    int32_t v0;

    v0 = (uint32_t)((uint64_t)((uint8_t)IsWellFormedTag(arg0)));
    return v0 & 1;
}
