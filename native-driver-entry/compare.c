#include <stdint.h>
#include <stdio.h>
#include <windows.h>

uintptr_t observed[2];
uint32_t desired_status;
typedef int32_t (*entry_fn)(void *, void *);
extern int32_t original_shim(void *, void *);
extern int32_t high_shim(void *, void *);
extern int32_t llvm_shim(void *, void *);

int main(void) {
    USHORT process, native;
    if (!IsWow64Process2(GetCurrentProcess(), &process, &native) ||
        process != IMAGE_FILE_MACHINE_UNKNOWN || native != IMAGE_FILE_MACHINE_ARM64)
        return 1;
    const uint32_t statuses[] = {0, 1, 0x80000001u, 0xc0000001u, 0xffffffffu};
    const entry_fn entries[] = {original_shim, high_shim, llvm_shim};
    const char *names[] = {"original", "HighC", "LLVMC"};
    uint8_t objects[40] = {0};
    printf("{\"native_machine\":%u,\"process_machine\":%u,\"observations\":[", native, process);
    for (unsigned i = 0; i < sizeof statuses / sizeof statuses[0]; ++i) {
        void *object = objects + i;
        void *path = objects + 32 - i;
        for (unsigned j = 0; j < sizeof entries / sizeof entries[0]; ++j) {
            observed[0] = observed[1] = 0;
            desired_status = statuses[i];
            uint32_t got = (uint32_t)entries[j](object, path);
            if (got != statuses[i] || observed[0] != (uintptr_t)object ||
                observed[1] != (uintptr_t)path)
                return 2;
            printf("%s{\"route\":\"%s\",\"input\":%u,\"status\":%u,"
                   "\"driver_object_matches\":true,\"registry_path_matches\":true}",
                   i || j ? "," : "", names[j], i, got);
        }
    }
    puts("]}");
    return 0;
}
