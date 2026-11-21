#include <stdint.h>
#include <windows.h>

#ifdef LINK_AT_STARTUP
__declspec(dllimport) extern uint64_t * volatile DetachSink;
#endif

int wmain(int argc, wchar_t **argv) {
    USHORT process, native;
#if defined(_M_ARM64)
    const USHORT expected = IMAGE_FILE_MACHINE_ARM64;
#elif defined(_M_X64)
    const USHORT expected = IMAGE_FILE_MACHINE_AMD64;
#else
#error Unsupported test architecture
#endif
    if (argc != 2 || !IsWow64Process2(GetCurrentProcess(), &process, &native) ||
        process != IMAGE_FILE_MACHINE_UNKNOWN || native != expected)
        return 10;
#ifdef LINK_AT_STARTUP
    if (DetachSink != NULL)
        return 11;
    HMODULE module = GetModuleHandleW(L"subject.dll");
#else
    HMODULE module = LoadLibraryW(L"subject.dll");
#endif
    if (!module)
        return 12;
    uint64_t * volatile *sink = (uint64_t * volatile *)GetProcAddress(module, "DetachSink");
    if (!sink || *sink != NULL)
        return 13;
    HANDLE file = CreateFileW(argv[1], GENERIC_READ | GENERIC_WRITE,
                              FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
    if (file == INVALID_HANDLE_VALUE)
        return 14;
    HANDLE section = CreateFileMappingW(file, NULL, PAGE_READWRITE, 0, 0, NULL);
    if (!section)
        return 15;
    uint64_t *state = MapViewOfFile(section, FILE_MAP_WRITE, 0, 0, 0);
    if (!state)
        return 16;
    state[0] = (uintptr_t)module;
    *sink = state;
    if (state[4] != 0)
        return 17;
#ifndef LINK_AT_STARTUP
    if (!FreeLibrary(module) || state[4] != 1)
        return 18;
#endif
    // Windows retains the mapped view through its process-detach callbacks.
    return 0;
}
