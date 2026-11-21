#define _WIN32_WINNT 0x0A00
#include <windows.h>
#include <stdint.h>
#include <inttypes.h>
#include <stdio.h>

typedef uint64_t (*forward_fn)(uint32_t, uint64_t, uint64_t, uint64_t);
extern uint64_t forward_4(uint32_t, uint64_t, uint64_t, uint64_t);
extern uint64_t forward_high(uint32_t, uint64_t, uint64_t, uint64_t);
extern uint64_t forward_llvm(uint32_t, uint64_t, uint64_t, uint64_t);
struct entry_state { uint64_t rcx, rdx, r8, r9, rsp, rip; };
extern uint64_t capture_and_forward(uint32_t, uint64_t, uint64_t, uint64_t,
                                    forward_fn, struct entry_state *);
int main(void) {
    USHORT process, native;
    if (!IsWow64Process2(GetCurrentProcess(), &process, &native) ||
        process != IMAGE_FILE_MACHINE_UNKNOWN || native != IMAGE_FILE_MACHINE_AMD64)
        return 1;
    const uint64_t values[] = {0, 1, 0x8000000000000000ull, UINT64_MAX, 0x7766554433221100ull};
    const forward_fn funcs[] = {forward_4, forward_high, forward_llvm};
    const char *names[] = {"original", "HighC", "LLVMC"};
    printf("{\"native_machine\":%u,\"process_machine\":%u,\"observations\":[", native, process);
    for (unsigned i = 0; i < sizeof values / sizeof *values; ++i) {
        for (unsigned j = 0; j < sizeof funcs / sizeof *funcs; ++j) {
            struct entry_state entry = {0};
            const uint64_t value = capture_and_forward(5, 0x73, 0x88, values[i], funcs[j], &entry);
            if ((uint32_t)entry.rcx != 5 || entry.rdx != 0x73 || entry.r8 != 0x88 ||
                entry.r9 != values[i] || (entry.rsp & 15) != 8 || !entry.rip || value != values[i])
                return 2;
            printf("%s{\"route\":\"%s\",\"rcx\":\"0x%" PRIx64 "\",\"rdx\":\"0x%" PRIx64
                   "\",\"r8\":\"0x%" PRIx64 "\",\"r9\":\"0x%" PRIx64 "\",\"rsp\":\"0x%" PRIx64
                   "\",\"rip\":\"0x%" PRIx64 "\",\"value\":\"0x%" PRIx64 "\"}",
                   (i || j) ? "," : "", names[j], entry.rcx, entry.rdx, entry.r8, entry.r9,
                   entry.rsp, entry.rip, value);
        }
    }
    puts("]}");
    return 0;
}
