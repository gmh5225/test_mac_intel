#include <windows.h>
#include <stdint.h>

uint64_t * volatile DetachSink;

BOOL WINAPI DllMain(HINSTANCE module, DWORD reason, LPVOID reserved) {
    if (reason == DLL_PROCESS_DETACH) {
        uint64_t *sink = DetachSink;
        if (sink) {
            sink[1] = (uintptr_t)module;
            sink[2] = reason;
            sink[3] = (uintptr_t)reserved;
            sink[4] = 1;
        }
    }
    return TRUE;
}
