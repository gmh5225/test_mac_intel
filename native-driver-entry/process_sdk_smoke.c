#define PSAPI_VERSION 1
#include <windows.h>
#include <psapi.h>
#include <processsnapshot.h>
#include <stdio.h>

int main(void) {
    HANDLE process = GetCurrentProcess();
    HMODULE modules[256];
    DWORD needed = 0;
    BOOL enumerated = EnumProcessModulesEx(process, modules, sizeof(modules),
                                            &needed, LIST_MODULES_ALL);
    if (!enumerated || needed == 0 || needed > sizeof(modules)) return 1;
    HMODULE executable = GetModuleHandleW(NULL);
    BOOL matched = FALSE;
    for (DWORD i = 0; i < needed / sizeof(modules[0]); ++i) {
        if (modules[i] == executable) matched = TRUE;
    }
    if (!matched) return 2;
    HPSS snapshot = NULL;
    DWORD captured = PssCaptureSnapshot(process, PSS_CAPTURE_NONE, 0, &snapshot);
    if (captured != ERROR_SUCCESS || snapshot == NULL) return 3;
    DWORD released = PssFreeSnapshot(process, snapshot);
    if (released != ERROR_SUCCESS) return 4;
    printf("{\"module_found\":true,\"capture_status\":%lu,\"release_status\":%lu}\n",
           (unsigned long)captured, (unsigned long)released);
    return 0;
}
