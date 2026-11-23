#include <capstone/capstone.h>
#include <stdio.h>
int main(void)
{
    const uint8_t bytes[] = {0x90, 0x89, 0xd8, 0xc3};
    const uint8_t *cursor = bytes;
    size_t remaining = sizeof(bytes);
    uint64_t address = 0x400000;
    csh handle;
    if (cs_open(CS_ARCH_X86, CS_MODE_32, &handle))
        return 1;
    cs_insn *out = cs_malloc(handle);
    if (!out)
        return 2;
    unsigned count = 0;
    while (remaining && cs_disasm_iter(handle, &cursor, &remaining, &address, out))
        ++count;
    cs_free(out, 1);
    cs_close(&handle);
    if (count != 3 || remaining || address != 0x400004)
        return 3;
    puts("verified");
    return 0;
}
