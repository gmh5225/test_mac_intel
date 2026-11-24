#include <capstone/capstone.h>
#include <cstdio>
#include <cstring>
#include <cctype>
int main(int argc,char**) {
    csh h[3]; cs_insn *p[3];
    for(unsigned i=0;i<3;++i) {
        if(cs_open(CS_ARCH_X86,(cs_mode)(CS_MODE_16<<i),h+i) || cs_option(h[i],CS_OPT_DETAIL,CS_OPT_ON))return 1;
        p[i]=cs_malloc(h[i]); if(!p[i])return 1;
    }
    unsigned bits; char input[128];
    while(std::scanf("%u %127s",&bits,input)==2) {
        unsigned i=bits==16?0:bits==32?1:2;
        size_t n=std::strlen(input)/2; uint8_t data[64]; if(n>sizeof data)return 2;
        auto digit=[](char c){return std::isdigit((unsigned char)c)?c-'0':std::tolower((unsigned char)c)-'a'+10;};
        for(size_t j=0;j<n;++j)data[j]=digit(input[2*j])*16+digit(input[2*j+1]);
        uint64_t ip=0x1000; const uint8_t *at=data;
        cs_insn *item = p[i], *allocated = nullptr;
        if(argc==2) {
            if(!cs_disasm(h[i],data,n,ip,1,&allocated)){std::puts("-");continue;}
            item=allocated;
        } else if(!cs_disasm_iter(h[i],&at,&n,&ip,item)){std::puts("-");continue;}
        auto &inst=*item;auto &x=inst.detail->x86;
        std::printf("%u %s",inst.size,cs_insn_name(h[i],inst.id));
        for(unsigned j=0;j<x.op_count;++j){auto &o=x.operands[j];
            if(o.type==X86_OP_REG)std::printf(" r%s",cs_reg_name(h[i],o.reg));
            else if(o.type==X86_OP_MEM)std::printf(" m%u",o.size);
            else if(o.type==X86_OP_IMM)std::printf(" i");
            else std::printf(" ?");
        }
        std::printf(" |%s|%s|%d|%d|%u\n",inst.mnemonic,inst.op_str,(int)x.avx_cc,(int)x.sse_cc,inst.id);
        if(allocated)cs_free(allocated,1);
    }
    for(unsigned i=0;i<3;++i){cs_free(p[i],1);cs_close(h+i);}
}
