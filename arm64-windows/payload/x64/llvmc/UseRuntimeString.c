#include <stdint.h>


typedef struct HSTRING__ HSTRING__;
int32_t WindowsCreateString(const uint16_t *sourceString, uint32_t length, struct HSTRING__ **string);
uint64_t UseRuntimeString(uint16_t* arg0, uint32_t arg1, HSTRING__** arg2) {
    uint64_t call0;

    call0 = ((uint64_t)(uint32_t)(WindowsCreateString((const uint16_t *)(uintptr_t)((uint64_t)arg0), (uint32_t)(uintptr_t)(arg1), (struct HSTRING__ **)(uintptr_t)((uint64_t)arg2))));
    return call0;
}
