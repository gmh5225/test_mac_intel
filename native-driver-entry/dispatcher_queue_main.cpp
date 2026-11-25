#include <windows.h>
#include <dispatcherqueue.h>
#include <roapi.h>
#include <windows.foundation.h>
#include <windows.system.h>

#ifdef NEVERD_CHECK_SDK_DISPATCHER
static HRESULT InspectDispatcher(DispatcherQueueOptions options,
                                 PDISPATCHERQUEUECONTROLLER *result) {
    return CreateDispatcherQueueController(options, result);
}
#else
extern "C" HRESULT InspectDispatcher(DispatcherQueueOptions,
                                    PDISPATCHERQUEUECONTROLLER *);
#endif

template <size_t N>
static void record(const char (&stage)[N], HRESULT result) {
    const char digits[] = "0123456789abcdef";
    char value[10];
    value[0] = '=';
    for (unsigned i = 0; i < 8; ++i)
        value[i + 1] = digits[(static_cast<unsigned>(result) >> ((7 - i) * 4)) & 15];
    value[9] = '\n';
    DWORD count;
    HANDLE output = GetStdHandle(STD_OUTPUT_HANDLE);
    WriteFile(output, stage, N - 1, &count, nullptr);
    WriteFile(output, value, sizeof(value), &count, nullptr);
}

static HRESULT shutdownQueue(PDISPATCHERQUEUECONTROLLER controller) {
    ABI::Windows::Foundation::IAsyncAction *action = nullptr;
    HRESULT hr = controller->ShutdownQueueAsync(&action);
    if (FAILED(hr) || !action)
        return FAILED(hr) ? hr : E_UNEXPECTED;
    IAsyncInfo *info = nullptr;
    hr = action->QueryInterface(IID_PPV_ARGS(&info));
    if (SUCCEEDED(hr)) {
        AsyncStatus status = AsyncStatus::Started;
        const ULONGLONG start = GetTickCount64();
        while (SUCCEEDED(hr = info->get_Status(&status)) && status == AsyncStatus::Started) {
            if (GetTickCount64() - start >= 10000) {
                hr = HRESULT_FROM_WIN32(ERROR_TIMEOUT);
                break;
            }
            if (MsgWaitForMultipleObjectsEx(0, nullptr, 50, QS_ALLINPUT, MWMO_INPUTAVAILABLE) == WAIT_FAILED) {
                hr = HRESULT_FROM_WIN32(GetLastError());
                break;
            }
            MSG message;
            while (PeekMessageW(&message, nullptr, 0, 0, PM_REMOVE)) {
                TranslateMessage(&message);
                DispatchMessageW(&message);
            }
        }
        if (SUCCEEDED(hr))
            hr = action->GetResults();
        info->Release();
    }
    action->Release();
    return hr;
}

extern "C" void RunDispatcherTest() {
    const HRESULT apartment = RoInitialize(RO_INIT_SINGLETHREADED);
    record("apartment", apartment);
    if (FAILED(apartment))
        ExitProcess(1);
    DispatcherQueueOptions options{sizeof(DispatcherQueueOptions), DQTYPE_THREAD_CURRENT, DQTAT_COM_NONE};
    PDISPATCHERQUEUECONTROLLER first = nullptr, duplicate = nullptr;
    const HRESULT created = InspectDispatcher(options, &first);
    record("create", created);
    bool passed = SUCCEEDED(created) && first;
    if (first) {
        const HRESULT again = InspectDispatcher(options, &duplicate);
        record("duplicate", again);
        passed = passed && FAILED(again) && !duplicate;
        if (duplicate)
            duplicate->Release();
        const HRESULT stopped = shutdownQueue(first);
        record("shutdown", stopped);
        passed = passed && SUCCEEDED(stopped);
        first->Release();
    }
    RoUninitialize();
    record("uninitialized", S_OK);
    // This PE has no CRT startup to terminate the process on return from main.
    ExitProcess(passed ? 0 : 2);
}
