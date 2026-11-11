#include "cs_priv.h"
#include "arch/X86/X86BaseInfo.h"
#include "arch/X86/X86Disassembler.h"
#include <stdio.h>
#include <io.h>
#include <fcntl.h>
#include <string.h>
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
    fwrite(record, sizeof(record), 1, stdout);
}
int main(void)
{
    if (_setmode(_fileno(stdout), _O_BINARY) < 0) return 4;
    for (int bit=0;bit<2;++bit) {
        csh h=0;
        if(cs_open(CS_ARCH_X86,bit ? CS_MODE_64:CS_MODE_32,&h))return 2;
        for(int det=0;det<2;++det) {
            cs_option(h,CS_OPT_DETAIL,det ? CS_OPT_ON : CS_OPT_OFF);
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
    return ferror(stdout) ? 3 : 0;
}
