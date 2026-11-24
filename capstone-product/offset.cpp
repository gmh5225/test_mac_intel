#include <capstone/capstone.h>
#include <initializer_list>
#include <cinttypes>
#include <cstdio>
struct Sample { cs_mode mode; uint8_t bytes[8]; size_t size; };
int main() {
    const Sample samples[]={
        {CS_MODE_16,{0x67,0x8b,0x05,0x34,0x12,0x00,0x80},7},
        {CS_MODE_32,{0x67,0x8b,0x06,0x34,0x82},5},
        {CS_MODE_64,{0x67,0x8b,0x04,0x25,0x34,0x12,0x00,0x80},8},
        {CS_MODE_64,{0x8b,0x04,0x25,0x34,0x12,0x00,0x80},7},
        {CS_MODE_16,{0x67,0x8b,0x80,0x34,0x12,0x00,0x80},7},
        {CS_MODE_64,{0x67,0x8b,0x05,0x34,0x12,0x00,0x80},7},
        {CS_MODE_16,{0x8b,0x06,0x34,0x82},4},
        {CS_MODE_32,{0x8b,0x05,0x34,0x12,0x00,0x80},6},
    };
    for(unsigned i=0;i<sizeof(samples)/sizeof(samples[0]);++i) {
        const auto &row=samples[i]; csh h;
        if(cs_open(CS_ARCH_X86,row.mode,&h))return 1;
        for(unsigned syntax:{CS_OPT_SYNTAX_INTEL,CS_OPT_SYNTAX_ATT,CS_OPT_SYNTAX_MASM}) {
            if(cs_option(h,CS_OPT_SYNTAX,syntax))return 2;
            for(unsigned details:{0u,1u}) {
                if(cs_option(h,CS_OPT_DETAIL,details?CS_OPT_ON:CS_OPT_OFF))return 3;
                auto rec=cs_malloc(h); const uint8_t *p=row.bytes; size_t length=row.size; uint64_t ip=0x1000;
                if(!cs_disasm_iter(h,&p,&length,&ip,rec)||length||p!=row.bytes+row.size||ip!=0x1000+row.size)return 4;
                std::printf("%u\t%u\t%u\t%s\t%s",i,syntax,details,rec->mnemonic,rec->op_str);
                if(details) {
                    const auto &x=rec->detail->x86; unsigned n=0;
                    for(unsigned j=0;j<x.op_count;++j)if(x.operands[j].type==X86_OP_MEM) {
                        const auto &mem=x.operands[j].mem;
                        std::printf("\t%u/%u/%u/%u/%" PRId64,x.addr_size,mem.base,mem.index,x.encoding.disp_size,mem.disp);
                        ++n;
                    }
                    if(n!=1)return 5;
                }
                std::puts("");cs_free(rec,1);
            }
        }
        cs_close(&h);
    }
}
