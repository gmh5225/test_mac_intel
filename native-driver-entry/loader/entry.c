#include "detach_record.h"

HINSTANCE volatile ObservedModule;
DWORD volatile ObservedReason;
LPVOID volatile ObservedReserved;
struct detach_record *volatile ObservedDetachRecord;

BOOL WINAPI DllMain(HINSTANCE module, DWORD reason, LPVOID reserved) {
    ObservedModule = module;
    ObservedReason = reason;
    ObservedReserved = reserved;
    if (reason == DLL_PROCESS_DETACH) {
        struct detach_record *record = ObservedDetachRecord;
        if (record) {
            record->module = (UINT_PTR)module;
            record->reason = reason;
            record->reserved = (UINT_PTR)reserved;
        }
    }
    return TRUE;
}
