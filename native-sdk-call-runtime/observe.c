#define COBJMACROS
#include <windows.h>
#include <mfapi.h>
#include <mfidl.h>
#include <mfreadwrite.h>
#include <stdio.h>

typedef DWORD (__cdecl *Startup)(DWORD *);
typedef void (__cdecl *Cleanup)(void);
typedef HRESULT (__cdecl *OpenReader)(LPCWSTR, IMFAttributes *, IMFSourceReader **);

static FARPROC load_wrapper(const wchar_t *path, const char *name) {
    HMODULE library = LoadLibraryW(path);
    return library ? GetProcAddress(library, name) : NULL;
}

int wmain(int argc, wchar_t **argv) {
    if (argc != 5)
        return 2;
    Startup startup = (Startup)load_wrapper(argv[1], "InspectMcastApiStartup");
    Cleanup cleanup = (Cleanup)load_wrapper(argv[2], "InspectMcastApiCleanup");
    OpenReader open_reader = (OpenReader)load_wrapper(argv[3], "InspectMFCreateSourceReaderFromURL");
    if (!startup || !cleanup || !open_reader) {
        fprintf(stderr, "LoadLibrary or GetProcAddress failed (%lu)\n", GetLastError());
        return 3;
    }
    USHORT process = 0, native = 0;
    if (!IsWow64Process2(GetCurrentProcess(), &process, &native))
        return 4;
    DWORD inputs[] = {0, 1, 0xffffffffUL};
    printf("{\"native_machine\":%u,\"process_machine\":%u,\"versions\":[", native, process);
    for (unsigned i = 0; i < sizeof(inputs) / sizeof(inputs[0]); ++i) {
        struct { DWORD before, version, after; } version = {0xa1b2c3d4UL, inputs[i], 0x55667788UL};
        DWORD status = startup(&version.version);
        if (status == ERROR_SUCCESS)
            cleanup();
        if (version.before != 0xa1b2c3d4UL || version.after != 0x55667788UL)
            return 5;
        printf("%s{\"requested\":%lu,\"status\":%lu,\"returned\":%lu,\"cleanup\":%s}",
               i ? "," : "", inputs[i], status, version.version, status == ERROR_SUCCESS ? "true" : "false");
    }
    HRESULT com = CoInitializeEx(NULL, COINIT_MULTITHREADED);
    if (FAILED(com))
        return 6;
    HRESULT mf = MFStartup(MF_VERSION, MFSTARTUP_FULL);
    if (FAILED(mf)) {
        fprintf(stderr, "MFStartup failed (0x%08lx)\n", (unsigned long)mf);
        CoUninitialize();
        return 7;
    }
    IMFSourceReader *reader = NULL;
    IMFMediaType *type = NULL;
    HRESULT status = open_reader(argv[4], NULL, &reader);
    HRESULT media = E_UNEXPECTED;
    UINT32 rate = 0;
    if (SUCCEEDED(status) && reader) {
        media = IMFSourceReader_GetNativeMediaType(reader, MF_SOURCE_READER_FIRST_AUDIO_STREAM, 0, &type);
        if (SUCCEEDED(media) && type) {
            media = IMFMediaType_GetUINT32(type, &MF_MT_AUDIO_SAMPLES_PER_SECOND, &rate);
            IMFMediaType_Release(type);
        }
        IMFSourceReader_Release(reader);
    }
    MFShutdown();
    CoUninitialize();
    printf("],\"reader\":{\"status\":%ld,\"media_status\":%ld,\"rate_hz\":%u}}\n",
           (long)status, (long)media, rate);
    return 0;
}
