#include <stdbool.h>
#include <stdint.h>


bool IsWellFormedTag(uint16_t* pszTag);
uint64_t InspectIsWellFormedTag(uint16_t* arg0) {
    return (((uint64_t)(uint8_t)(IsWellFormedTag((uint16_t*)(uintptr_t)((uint64_t)arg0)))) & 1);
}

