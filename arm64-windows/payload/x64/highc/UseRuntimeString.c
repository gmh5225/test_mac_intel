typedef struct HSTRING__ HSTRING__;

#include <stdint.h>

extern int32_t WindowsCreateString(const uint16_t *sourceString, uint32_t length, struct HSTRING__ **string);

/* neverd.entry: 0x180001030 */
int64_t UseRuntimeString(uint16_t* arg0, int32_t arg1, HSTRING__** arg2) {
    return (uint64_t)((uint32_t)WindowsCreateString(arg0, arg1, arg2));
}
