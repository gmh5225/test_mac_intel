#include <capstone/capstone.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
int main(void) {
    const cs_arch arches[] = {CS_ARCH_ARM, CS_ARCH_AARCH64, CS_ARCH_M68K, CS_ARCH_MIPS, CS_ARCH_PPC, CS_ARCH_SPARC, CS_ARCH_SYSTEMZ, CS_ARCH_X86, CS_ARCH_XCORE};
    for (size_t i = 0; i < sizeof(arches)/sizeof(*arches); ++i)
        if (!cs_support(arches[i])) { fprintf(stderr, "missing architecture %d\n", (int)arches[i]); return 2; }
    const uint8_t bytes[] = {0xc5,0xfc,0x28,0x44,0x8b,0x10};
    csh h;
    if (cs_open(CS_ARCH_X86, CS_MODE_64, &h) || cs_option(h, CS_OPT_DETAIL, CS_OPT_ON)) return 3;
    cs_insn *i = NULL;
    if (cs_disasm(h, bytes, sizeof(bytes), 0x1000, 1, &i) != 1) return 4;
    int ok = i->id == X86_INS_VMOVAPS && i->size == sizeof(bytes) && i->detail->x86.op_count == 2 &&
        i->detail->x86.operands[1].type == X86_OP_MEM && i->detail->x86.operands[1].mem.scale == 4 && i->detail->x86.operands[1].mem.disp == 16;
    printf("%s %s\n", i->mnemonic, i->op_str);cs_free(i,1);cs_close(&h);
    return ok ? 0 : 5;
}
