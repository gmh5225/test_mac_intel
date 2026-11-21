#define _WIN32_WINNT 0x0A00
#include <windows.h>
#include <stdio.h>

/* Exercise the installed driver's normal Win32 device interface. */
int main(void) {
    USHORT process = 0, native = 0;
    WCHAR target[256];
    if (!IsWow64Process2(GetCurrentProcess(), &process, &native) ||
        process != IMAGE_FILE_MACHINE_UNKNOWN || native != IMAGE_FILE_MACHINE_ARM64)
        return 1;
    if (!QueryDosDeviceW(L"NUL", target, ARRAYSIZE(target)) ||
        lstrcmpiW(target, L"\\Device\\Null") != 0)
        return 2;
    HANDLE device = CreateFileW(L"\\\\.\\NUL", GENERIC_READ | GENERIC_WRITE,
                                FILE_SHARE_READ | FILE_SHARE_WRITE, NULL,
                                OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (device == INVALID_HANDLE_VALUE)
        return 3;
    const DWORD sizes[] = {1, 16, 257, 4096};
    BYTE bytes[4096] = {0};
    printf("{\"process_machine\":%u,\"native_machine\":%u,"
           "\"device\":\"\\\\Device\\\\Null\",\"io\":[", process, native);
    int passed = 1;
    for (unsigned i = 0; i < ARRAYSIZE(sizes); ++i) {
        DWORD written = 0, read = 0;
        BOOL write_ok = WriteFile(device, bytes, sizes[i], &written, NULL);
        DWORD write_error = write_ok ? 0 : GetLastError();
        BOOL read_ok = ReadFile(device, bytes, sizes[i], &read, NULL);
        DWORD read_error = read_ok ? 0 : GetLastError();
        printf("%s{\"size\":%lu,\"written\":%lu,\"write_error\":%lu,"
               "\"read\":%lu,\"read_error\":%lu}", i ? "," : "", sizes[i],
               written, write_error, read, read_error);
        passed &= write_ok && written == sizes[i] && read == 0 &&
                  (read_ok || read_error == ERROR_HANDLE_EOF);
    }
    puts("]}");
    CloseHandle(device);
    return passed ? 0 : 4;
}
