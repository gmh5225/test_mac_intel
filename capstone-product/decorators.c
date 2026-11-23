#include "cs_priv.h"
#include "arch/X86/X86Mapping.h"
#include "MCInst.h"
#include "SStream.h"
#include <inttypes.h>
#include <stdio.h>

int main(void)
{
    static const uint8_t cases[][4] = {
        {0x8b,0x40,0x04}, {0x8b,0xc1}, {0x89,0x00}, {0x8d,0x40,0xff},
        {0x83,0x38,0xfe}, {0xa5}, {0xf8}, {0xd1,0xd0},
        {0xd9,0x20}, {0xdd,0x20}, {0x0f,0x44,0x00},
    };
    static const char *texts[] = {"", "mov eax, [rax]", "{}", "{1to2}", "{1to4}x",
        "{1to8}", "xxx{1to16}", "{unrelated} {1to4}", "{1to2}{1to16}",
        " \t{1to16", "vadd{k1}{z}"};
    static const cs_mode modes[] = {CS_MODE_16,CS_MODE_32,CS_MODE_64};
    uint64_t hash=UINT64_C(1469598103934665603);
    size_t checked=0, decorated=0;
    for (size_t m=0; m<sizeof(modes)/sizeof(modes[0]); ++m) {
        csh h=0;
        if (cs_open(CS_ARCH_X86,modes[m],&h) || cs_option(h,CS_OPT_DETAIL,CS_OPT_ON)) return 1;
        for (size_t k=0;k<sizeof(cases)/sizeof(cases[0]);++k) {
            cs_insn *decoded=NULL;
            if (cs_disasm(h,cases[k],sizeof(cases[k]),0x410000,1,&decoded)!=1) return 2;
            for (size_t t=0;t<sizeof(texts)/sizeof(texts[0]);++t) {
                cs_insn insn=*decoded;
                cs_detail detail=*decoded->detail;
                MCInst mi;
                MCInst_Init(&mi,CS_ARCH_X86);
                insn.detail=&detail;
                mi.csh=(cs_struct *)(uintptr_t)h;
                mi.flat_insn=&insn;
                SStream ss;
                SStream_Init(&ss);
                SStream_concat0(&ss,texts[t]);
                X86_postprinter(h,&insn,&ss,&mi);
                const uint8_t *raw=(const uint8_t *)&detail;
                for (size_t b=0;b<offsetof(cs_detail,x86)+sizeof(cs_x86);++b)
                    hash=(hash^raw[b])*UINT64_C(1099511628211);
                for (unsigned j=0;j<detail.x86.op_count;++j)
                    decorated+=detail.x86.operands[j].avx_bcast!=X86_AVX_BCAST_INVALID;
                ++checked;
            }
            cs_free(decoded,1);
        }
        cs_close(&h);
    }
    printf("%zu %zu %" PRIx64 "\n",checked,decorated,hash);
    return checked==363 && decorated>0 ? 0 : 3;
}
