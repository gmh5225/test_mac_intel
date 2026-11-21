#include "detach_record.h"
#include <stdio.h>


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

static struct detach_record *open_record(const char *path) {
    HANDLE file = CreateFileA(path, GENERIC_READ | GENERIC_WRITE,
                              FILE_SHARE_READ | FILE_SHARE_WRITE, NULL,
                              OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (file == INVALID_HANDLE_VALUE)
        return NULL;
    HANDLE mapping = CreateFileMappingW(file, NULL, PAGE_READWRITE, 0, 0, NULL);
    CloseHandle(file);
    if (!mapping)
        return NULL;
    struct detach_record *view = MapViewOfFile(mapping, FILE_MAP_WRITE, 0, 0,
                                              sizeof(struct detach_record));
    CloseHandle(mapping);
    return view;
}

int main(int argc, char **argv) {
    if (argc != 2)
        return 9;
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
    struct detach_record *volatile *slot = (struct detach_record *volatile *)
        GetProcAddress(state.image, "ObservedDetachRecord");
    struct detach_record *view = open_record(argv[1]);
    if (!slot || !view)
        return 17;
    *slot = view;
    printf("{\"mode\":\"%s\",\"image_handle\":\"%p\",\"module_handles_match\":true,\"reasons\":[1,2,3],"
           "\"reserved_nonnull\":[%s,%s,%s]}\n",
           startup ? "process-start" : "dynamic", (void *)state.image,
           initial_reserved_nonnull ? "true" : "false",
           state.thread_reserved_nonnull ? "true" : "false",
           *state.reserved ? "true" : "false");
    if (!startup) {
        if (!FreeLibrary(state.image))
            return 18;
        if (!UnmapViewOfFile(view))
            return 19;
    }
    // On process exit Windows keeps the mapped view until DLL detach has run.
    return 0;
}
