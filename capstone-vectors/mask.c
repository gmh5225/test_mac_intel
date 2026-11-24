#include "cs_priv.h"
#include "arch/X86/X86BaseInfo.h"
#include "arch/X86/X86Disassembler.h"
#include <stdio.h>
#include <string.h>
static unsigned checked, masked, accepted;
static void check(csh handle, const uint8_t *bytes, size_t available)
{
    MCInst decoded;
    cs_insn pub = {0};
    cs_detail detail;
    cs_struct *h = (cs_struct *)(uintptr_t)handle;
    MCInst_InitX86(&decoded);
    decoded.flat_insn = &pub;
    pub.detail = h->detail_opt ? &detail : NULL;
    pub.address = decoded.address = UINT64_C(0xffffffff80000000);
    decoded.csh = h;
    uint16_t length = 0;
    bool ok = X86_getInstruction(handle, bytes, available, &decoded, &length,
                                 pub.address, h->getinsn_info);
    uint32_t record[3] = {ok ? decoded.flags : 0, ok ? decoded.Opcode : 0,
                          ok ? (uint32_t)length | (uint32_t)decoded.size << 8 : 0};
    ++checked;
    accepted+=ok;
    masked+=ok && (decoded.flags & X86_IP_HAS_EVEX_OPMASK);
    fwrite(record,sizeof(record),1,stdout);
    if (ok)
        for (unsigned i=0;i<decoded.size;++i) {
            MCOperand *op=MCInst_getOperand(&decoded,i);
            uint64_t kind=op->Kind, value=0;
            if (MCOperand_isReg(op)) value=MCOperand_getReg(op);
            else if (MCOperand_isImm(op)) value=(uint64_t)MCOperand_getImm(op);
            fwrite(&kind,sizeof(kind),1,stdout);
            fwrite(&value,sizeof(value),1,stdout);
        }
}
int main(void)
{
    for (int bit=0;bit<3;++bit) {
        csh h=0;
        if(cs_open(CS_ARCH_X86,bit==0 ? CS_MODE_16 : bit==1 ? CS_MODE_32:CS_MODE_64,&h))return 2;
        for(int det=0;det<2;++det) {
            cs_option(h,CS_OPT_DETAIL,det ? CS_OPT_ON : CS_OPT_OFF);
            for(unsigned op=0;op<256;++op)
                for(unsigned mr=0;mr<256;mr+=13) {
                    uint8_t legacy[]={0x66,0x0f,(uint8_t)op,(uint8_t)mr,0x33,0x55,0x77,0x12};
                    uint8_t vex[]={0xc4,0xe2,0x79,(uint8_t)op,(uint8_t)mr,0xff,0,0};
                    for(size_t n=1;n<=sizeof(legacy);++n) {
                        check(h,legacy,n);check(h,vex,n);
                    }
                }
            for(unsigned op=0;op<256;++op)
                for(unsigned map=1;map<=3;++map)
                    for(unsigned p=0;p<4;++p)
                        for(unsigned width=0;width<2;++width)
                            for(unsigned aaa=0;aaa<8;++aaa)
                                for(unsigned form=0;form<8;++form) {
                                    uint8_t b[15]={0x62,(uint8_t)(0xf0|map),(uint8_t)(0x7c|p|(width<<7)),
                                        (uint8_t)(8|aaa|((form&3)<<5)|((form&4)?0x80:0)),(uint8_t)op,
                                        (uint8_t)((form&1)?0xc2:0x42),0x2a,0x56};
                                    check(h,b,sizeof(b));
                                }
        }
        cs_close(&h);
    }
    fprintf(stderr,"%u cases %u masks %u decoded\n",checked,masked,accepted);
    return ferror(stdout) ? 3 : 0;
}

