#include <windows.h>
#include <stdio.h>
#include <string.h>

#ifdef LINK_AT_STARTUP
__declspec(dllimport) extern DWORD ObservedReason;
#endif

struct observations {
    HMODULE image;
    HINSTANCE volatile *module;
    DWORD volatile *reason;
    LPVOID volatile *reserved;
    int thread_reserved_nonnull;
};

static int matches(struct observations *state, DWORD reason) {
    return *state->module == state->image && *state->reason == reason;
}

static DWORD WINAPI observe_thread(void *context) {
    struct observations *state = context;
    state->thread_reserved_nonnull = *state->reserved != NULL;
    return matches(state, DLL_THREAD_ATTACH) ? 0 : 1;
}

int main(void) {
    struct observations state = {0};
    int startup;
#ifdef LINK_AT_STARTUP
    startup = 1;
    state.image = GetModuleHandleW(L"subject.dll");
    if (ObservedReason != DLL_PROCESS_ATTACH)
        return 10;
#else
    startup = 0;
    state.image = LoadLibraryW(L"subject.dll");
#endif
    if (!state.image)
        return 11;
    state.module = (HINSTANCE volatile *)GetProcAddress(state.image, "ObservedModule");
    state.reason = (DWORD volatile *)GetProcAddress(state.image, "ObservedReason");
    state.reserved = (LPVOID volatile *)GetProcAddress(state.image, "ObservedReserved");
    if (!state.module || !state.reason || !state.reserved)
        return 12;
    int initial_reserved_nonnull = *state.reserved != NULL;
    if (!matches(&state, DLL_PROCESS_ATTACH) || initial_reserved_nonnull != startup)
        return 13;
    HANDLE thread = CreateThread(NULL, 0, observe_thread, &state, 0, NULL);
    if (!thread)
        return 14;
    DWORD result = 1;
    if (WaitForSingleObject(thread, 30000) != WAIT_OBJECT_0 ||
        !GetExitCodeThread(thread, &result) || result || !CloseHandle(thread))
        return 15;
    if (!matches(&state, DLL_THREAD_DETACH))
        return 16;
    printf("{\"mode\":\"%s\",\"module_handles_match\":true,\"reasons\":[1,2,3],"
           "\"reserved_nonnull\":[%s,%s,%s]}\n",
           startup ? "process-start" : "dynamic",
           initial_reserved_nonnull ? "true" : "false",
           state.thread_reserved_nonnull ? "true" : "false",
           *state.reserved ? "true" : "false");
    if (!startup && !FreeLibrary(state.image))
        return 17;
    return 0;
}
