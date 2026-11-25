// Microsoft documents ProcessPrng as a named export of BCryptPrimitives.dll.
// The function pointer uses the Windows calling convention on 32-bit callers.
#include <windows.h>
#include <stdio.h>
#include <string.h>

typedef BOOL (WINAPI *ProcessPrngRoutine)(PBYTE, SIZE_T);

int main(void) {
    HMODULE module = LoadLibraryExW(L"bcryptprimitives.dll", NULL, LOAD_LIBRARY_SEARCH_SYSTEM32);
    if (!module)
        return 1;
    FARPROC address = GetProcAddress(module, "ProcessPrng");
    if (!address)
        return 2;
    ProcessPrngRoutine random_bytes;
    _Static_assert(sizeof(random_bytes) == sizeof(address), "function-pointer ABI");
    memcpy(&random_bytes, &address, sizeof(random_bytes));

    const SIZE_T lengths[] = {0, 1, 7, 32, 63};
    unsigned changed = 0;
    for (size_t test = 0; test < ARRAYSIZE(lengths); ++test) {
        BYTE region[80];
        memset(region, 0xA5, sizeof(region));
        SIZE_T bytes = lengths[test];
        if (random_bytes(region + 8, bytes) != TRUE)
            return 3;
        for (size_t i = 0; i < sizeof(region); ++i) {
            if (i >= 8 && i < 8 + bytes) {
                changed += region[i] != 0xA5;
            } else if (region[i] != 0xA5) {
                return 4;
            }
        }
    }
    // The count of changed bytes is an observation. Random bytes can match the fill.
    printf("{\"pointer_bits\":%u,\"result_bits\":%u,\"calls\":%u,\"changed_bytes\":%u}\n",
           (unsigned)(8 * sizeof(void *)), (unsigned)(8 * sizeof(BOOL)),
           (unsigned)ARRAYSIZE(lengths), changed);
    FreeLibrary(module);
    return 0;
}
