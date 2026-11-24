#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdint.h>
#include <stdio.h>

extern int OriginalSeek(void *, long long);
extern int32_t HighSeek(int32_t, int32_t, int32_t);
extern uint32_t LLVMSeek(uint32_t, uint32_t, uint32_t);

int main(void) {
    HANDLE file = CreateFileW(L"neverd-seek-runtime.tmp", GENERIC_READ | GENERIC_WRITE,
        0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_TEMPORARY | FILE_FLAG_DELETE_ON_CLOSE, NULL);
    if (file == INVALID_HANDLE_VALUE) return 20;
    const int64_t offsets[] = { 0, 1, 41, 0x80000001LL, 0xffffffffLL, 0x100000000LL,
        0x149abcdefLL, 0xfedc1234567LL, 0x12340001ffffffffLL, -1, -0x100000001LL };
    LARGE_INTEGER zero, start, distance, expected, observed;
    zero.QuadPart = 0;
    start.QuadPart = 37;
    unsigned calls = 0;
    for (unsigned repeat = 0; repeat < 8; ++repeat) {
        for (unsigned i = 0; i < sizeof(offsets) / sizeof(offsets[0]); ++i) {
            distance.QuadPart = offsets[i];
            if (!SetFilePointerEx(file, start, NULL, FILE_BEGIN)) return 21;
            BOOL ok = SetFilePointerEx(file, distance, &expected, FILE_BEGIN);
            uint32_t result = ok ? expected.LowPart : UINT32_MAX;
            int64_t expected_pos = ok ? expected.QuadPart : start.QuadPart;
            for (unsigned route = 0; route < 3; ++route) {
                if (!SetFilePointerEx(file, start, NULL, FILE_BEGIN)) return 22;
                uint32_t handle = (uint32_t)(uintptr_t)file;
                uint32_t actual = route == 0 ? (uint32_t)OriginalSeek(file, distance.QuadPart) :
                    route == 1 ? (uint32_t)HighSeek((int32_t)handle, (int32_t)distance.LowPart, distance.HighPart) :
                        LLVMSeek(handle, distance.LowPart, (uint32_t)distance.HighPart);
                if (actual != result || !SetFilePointerEx(file, zero, &observed, FILE_CURRENT) ||
                    observed.QuadPart != expected_pos) return 30 + route;
                ++calls;
            }
        }
    }
    if (OriginalSeek(INVALID_HANDLE_VALUE, 5) != -1 || HighSeek(-1, 5, 0) != -1 ||
        LLVMSeek(UINT32_MAX, 5, 0) != UINT32_MAX) return 34;
    if (!CloseHandle(file)) return 35;
    printf("PASS %u original/HighC/LLVMC calls and 3 invalid-handle calls\n", calls);
    return 0;
}
