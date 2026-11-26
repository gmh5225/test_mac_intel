#include <capstone/capstone.h>
#include "arch/X86/X86ScanAdapter.h"
#include <cstdio>
#include <cstring>

int main()
{
    csh h;
    if (cs_open(CS_ARCH_X86, CS_MODE_64, &h) || cs_option(h, CS_OPT_DETAIL, CS_OPT_ON)) return 1;
    cs_insn *record=cs_malloc(h);
    if (!record) return 2;
    const unsigned roots[]={X86_REG_XMM0,X86_REG_YMM0,X86_REG_ZMM0};
    unsigned checks=0;
    for (unsigned width=0;width<3;++width) for (unsigned dst=0;dst<32;++dst)
    for (unsigned src=0;src<32;++src) for (unsigned rm=0;rm<32;++rm) {
        const uint8_t code[]={0x62,uint8_t(0xf1^((dst&8)<<4)^(dst&16)^((rm&8)<<2)^((rm&16)<<2)),
                              uint8_t(0x7d^((src&15)<<3)),uint8_t((width<<5)|(8^((src&16)>>1))),
                              0xfe,uint8_t(0xc0|((dst&7)<<3)|(rm&7))};
        const uint8_t *p=code;
        size_t left=sizeof(code);
        uint64_t ip=0x140001000;
        std::memset(record->op_str,0xa5,sizeof(record->op_str));
        if (!X86_disasmIterText(h,&p,&left,&ip,record) || left || p!=code+6 ||
            record->id!=X86_INS_VPADDD || record->detail->x86.op_count!=3) return 3;
        const unsigned regs[]={roots[width]+dst,roots[width]+src,roots[width]+rm};
        char expected[sizeof(record->op_str)]={};
        std::snprintf(expected,sizeof(expected),"%s, %s, %s",cs_reg_name(h,regs[0]),cs_reg_name(h,regs[1]),cs_reg_name(h,regs[2]));
        if (std::memcmp(expected,record->op_str,sizeof(expected))) return 4;
        for (unsigned i=0;i<3;++i) {
            auto &op=record->detail->x86.operands[i];
            if (op.type!=X86_OP_REG || unsigned(op.reg)!=regs[i] || op.size!=(16u<<width)) return 5;
        }
        ++checks;
    }
    std::printf("%u\n",checks);
    cs_free(record,1);
    cs_close(&h);
}
