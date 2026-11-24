#include <windows.h>
#include <ncrypt.h>
#include <stdio.h>
#include <stdint.h>

typedef SECURITY_STATUS (__cdecl *Open)(NCRYPT_PROV_HANDLE *, LPCWSTR, DWORD);
typedef SECURITY_STATUS (__cdecl *Close)(NCRYPT_HANDLE, DWORD);

int wmain(int argc, wchar_t **argv) {
    if (argc != 3)
        return 2;
    HMODULE first = LoadLibraryW(argv[1]);
    HMODULE second = LoadLibraryW(argv[2]);
    if (!first || !second)
        return 3;
    Open open = (Open)GetProcAddress(first, "InspectSslOpenProvider");
    Close close = (Close)GetProcAddress(second, "InspectSslFreeObject");
    if (!open || !close)
        return 4;
    USHORT process = 0, native = 0;
    if (!IsWow64Process2(GetCurrentProcess(), &process, &native))
        return 5;
    struct { uintptr_t before; NCRYPT_PROV_HANDLE handle; uintptr_t after; } record = {
        0x71431UL, 0, 0x21651UL
    };
    SECURITY_STATUS opened = open(&record.handle, L"Microsoft SSL Protocol Provider", 0);
    int has_handle = record.handle != 0;
    SECURITY_STATUS closed = opened == 0 && has_handle ? close(record.handle, 0) : -1;
    if (record.before != 0x71431UL || record.after != 0x21651UL)
        return 6;
    printf("{\"native_machine\":%u,\"process_machine\":%u,\"open_status\":%ld,"
           "\"returned_handle\":%s,\"close_status\":%ld}\n",
           native, process, (long)opened, has_handle ? "true" : "false", (long)closed);
    return opened || closed || !has_handle ? 7 : 0;
}
