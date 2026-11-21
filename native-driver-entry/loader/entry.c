#include <windows.h>

HINSTANCE volatile ObservedModule;
DWORD volatile ObservedReason;
LPVOID volatile ObservedReserved;

BOOL WINAPI DllMain(HINSTANCE module, DWORD reason, LPVOID reserved) {
    ObservedModule = module;
    ObservedReason = reason;
    ObservedReserved = reserved;
    return TRUE;
}
