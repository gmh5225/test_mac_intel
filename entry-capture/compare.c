#define _WIN32_WINNT 0x0A00
#include <windows.h>
#include <stdint.h>
#include <inttypes.h>
#include <stdio.h>

typedef uint64_t (*entry_fn)(uint64_t *, uint64_t);
extern uint64_t observe_entry(uint64_t *, uint64_t);
extern uint64_t observe_high(uint64_t *, uint64_t);
extern uint64_t observe_llvm(uint64_t *, uint64_t);
struct incoming { uintptr_t x0; uint64_t x1; uintptr_t sp, lr; };
extern uint64_t capture_and_call(entry_fn, uint64_t *, uint64_t, struct incoming *);

int main(void) {
    USHORT process, native;
    if (!IsWow64Process2(GetCurrentProcess(), &process, &native) ||
        process != IMAGE_FILE_MACHINE_UNKNOWN || native != IMAGE_FILE_MACHINE_ARM64)
        return 1;
    const uint64_t inputs[] = {0, 1, 0x8000000000000000ull, UINT64_MAX, 0x7766554433221100ull};
    const entry_fn funcs[] = {observe_entry, observe_high, observe_llvm};
    const char *names[] = {"original", "HighC", "LLVMC"};
    uint64_t state[2], original[3];
    printf("{\"native_machine\":%u,\"process_machine\":%u,\"observations\":[",native,process);
    for (unsigned i=0; i<sizeof inputs/sizeof *inputs; ++i) {
        for (unsigned j=0; j<sizeof funcs/sizeof *funcs; ++j) {
            state[0] = UINT64_MAX - i;
            state[1] = 0x800000001234abcdull + i;
            struct incoming captured = {0};
            uint64_t value = capture_and_call(funcs[j],state,inputs[i],&captured);
            if (captured.x0 != (uintptr_t)state || captured.x1 != inputs[i] ||
                !captured.lr || !captured.sp || (captured.sp & 15))
                return 2;
            if (j == 0) {
                original[0]=value; original[1]=state[0]; original[2]=state[1];
            } else if (value!=original[0] || state[0]!=original[1] || state[1]!=original[2])
                return 3;
            printf("%s{\"route\":\"%s\",\"x0\":\"0x%" PRIxPTR "\",\"x1\":\"0x%" PRIx64
                   "\",\"sp\":\"0x%" PRIxPTR "\",\"lr\":\"0x%" PRIxPTR "\",\"value\":\"0x%" PRIx64
                   "\",\"stored\":[\"0x%" PRIx64 "\",\"0x%" PRIx64 "\"]}",
                   (i || j) ? "," : "",names[j],captured.x0,captured.x1,captured.sp,captured.lr,value,state[0],state[1]);
        }
    }
    puts("]}");
    return 0;
}
