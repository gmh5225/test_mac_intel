#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <windows.h>
#include <iphlpapi.h>
#include <icmpapi.h>
#include <stdint.h>
#include <stdio.h>

BOOL UseIcmpHandle(HANDLE handle);
int64_t highc_UseIcmpHandle(void *handle);
uint64_t llvmc_UseIcmpHandle(void *handle);

int main(void) {
    USHORT process = 0;
    USHORT native = 0;
    if (!IsWow64Process2(GetCurrentProcess(), &process, &native) ||
        process != IMAGE_FILE_MACHINE_UNKNOWN || native != IMAGE_FILE_MACHINE_ARM64)
        return 1;

    BOOL result[3];
    for (unsigned i = 0; i < 3; ++i) {
        HANDLE handle = IcmpCreateFile();
        if (handle == INVALID_HANDLE_VALUE)
            return 2;
        if (i == 0)
            result[i] = UseIcmpHandle(handle);
        else if (i == 1)
            result[i] = (BOOL)highc_UseIcmpHandle(handle);
        else
            result[i] = (BOOL)llvmc_UseIcmpHandle(handle);
        if (!result[i])
            return 3;
    }
    if (result[0] != result[1] || result[0] != result[2])
        return 4;
    printf("{\"process_machine\":%u,\"native_machine\":%u,"
           "\"original\":%ld,\"highc\":%ld,\"llvmc\":%ld}\n",
           (unsigned)process, (unsigned)native, (long)result[0],
           (long)result[1], (long)result[2]);
    return 0;
}
