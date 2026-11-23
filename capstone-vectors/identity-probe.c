#include <capstone/capstone.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
static uint64_t digest = 14695981039346656037ull;
static void mix(const void *data, size_t size)
{
    const unsigned char *p = data;
    for (size_t i = 0; i < size; ++i)
        digest = (digest ^ p[i]) * 1099511628211ull;
}
static int check(cs_arch arch, cs_mode mode, const uint8_t *code, size_t size,
                 size_t expected, int details)
{
    csh h;
    if (cs_open(arch, mode, &h) != CS_ERR_OK) return 1;
    if (cs_option(h, CS_OPT_DETAIL, details ? CS_OPT_ON : CS_OPT_OFF) != CS_ERR_OK) return 2;
    cs_insn *out = cs_malloc(h);
    if (!out) return 3;
    uint64_t ip = 0x10000;
    size_t count = 0;
    cs_detail *detail = out->detail;
    while (size) {
        memset(out, 0, sizeof(*out));
        if (detail) memset(detail, 0, sizeof(*detail));
        out->detail = detail;
        if (!cs_disasm_iter(h, &code, &size, &ip, out)) return 4;
        if (!out->size || !out->id || out->address != ip - out->size) return 5;
        out->detail = NULL;
        mix(out, sizeof(*out));
        if (detail) mix(detail, sizeof(*detail));
        ++count;
    }
    out->detail = detail;
    cs_free(out, 1);
    cs_close(&h);
    return count == expected ? 0 : 6;
}
int main(void)
{
    static const uint8_t x86[] = {0x90, 0x89, 0xd8, 0x83, 0xf8, 0xff, 0xc3};
    static const uint8_t arm[] = {0x1f, 0x20, 0x03, 0xd5, 0xc0, 0x03, 0x5f, 0xd6};
    const cs_opt_mem mem = {malloc, calloc, realloc, free, vsnprintf};
    if (cs_option(0, CS_OPT_MEM, (uintptr_t)&mem) != CS_ERR_OK) return 10;
    for (int details = 0; details != 2; ++details) {
        if (check(CS_ARCH_X86, CS_MODE_32, x86, sizeof(x86), 4, details) ||
            check(CS_ARCH_X86, CS_MODE_64, x86, sizeof(x86), 4, details) ||
            check(CS_ARCH_AARCH64, CS_MODE_LITTLE_ENDIAN, arm, sizeof(arm), 2, details)) return 11;
    }
    printf("%016llx\n", (unsigned long long)digest);
    return 0;
}
