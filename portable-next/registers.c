#include <capstone/capstone.h>
#include <stdio.h>
int main(void)
{
    const cs_mode modes[] = {CS_MODE_16, CS_MODE_32, CS_MODE_64};
    const uint8_t enc[][4] = {{0xc5,0xf8,0x77}, {0xc5,0xfc,0x77}, {0xc4,0xe1,0x78,0x77}, {0xc4,0xe1,0x7c,0x77}};
    for (unsigned m=0; m<3; ++m) {
        csh h=0;
        if (cs_open(CS_ARCH_X86,modes[m],&h)||cs_option(h,CS_OPT_DETAIL,CS_OPT_ON)) return 1;
        for (unsigned op=0; op<4; ++op) {
            cs_insn *i=NULL;
            if (cs_disasm(h,enc[op],op<2?3:4,0x2000,1,&i)!=1) return 2;
            cs_regs reads,writes;
            uint8_t nr=0,nw=0;
            if (cs_regs_access(h,i,reads,&nr,writes,&nw)) return 3;
            printf("%u %s vex%u %u %u %s %s\n",16u<<m,i->mnemonic, op<2?2:3,i->detail->regs_write_count,nw,cs_reg_name(h,writes[0]),cs_reg_name(h,writes[nw-1]));
            cs_free(i,1);
        }
        cs_close(&h);
    }
    return 0;
}
