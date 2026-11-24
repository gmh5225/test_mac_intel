#include <capstone/capstone.h>
#include "arch/X86/X86ScanAdapter.h"
#include <array>
#include <cstdio>
#include <cstring>

int main() {
    csh text[3]{}, scan[3]{};
    cs_insn *full[3]{}, *minimal[3]{};
    for (unsigned i=0;i<3;++i) {
        auto mode=cs_mode(CS_MODE_16<<i);
        if (cs_open(CS_ARCH_X86,mode,text+i)||cs_open(CS_ARCH_X86,mode,scan+i)||
            cs_option(text[i],CS_OPT_DETAIL,CS_OPT_ON)||cs_option(scan[i],CS_OPT_TEXT,CS_OPT_OFF))
            return 1;
        full[i]=cs_malloc(text[i]); minimal[i]=cs_malloc(scan[i]);
        if (!full[i]||!minimal[i])return 2;
    }
    unsigned bits; char hex[128];
    while(std::scanf("%u %127s",&bits,hex)==2) {
        const unsigned i=bits==16?0:bits==32?1:2;
        const size_t count=std::strlen(hex)/2;
        if(count>63)return 3;
        std::array<uint8_t,64> bytes{};
        for(size_t j=0;j<count;++j){unsigned x;if(std::sscanf(hex+2*j,"%2x",&x)!=1)return 4;bytes[j]=uint8_t(x);}
        uint64_t address=0x1000;size_t left=count;const uint8_t *cursor=bytes.data();
        const bool ok=cs_disasm_iter(text[i],&cursor,&left,&address,full[i]);
        const uint32_t id=ok?(full[i]->id<<8)|full[i]->size:0;
        const size_t consumed=ok?full[i]->size:0;
        unsigned wrong=0;
        if (address!=0x1000+consumed||left!=count-consumed||cursor!=bytes.data()+consumed)wrong|=8;
        cursor=bytes.data();left=count;address=0x1000;
        const bool valid=cs_disasm_iter(scan[i],&cursor,&left,&address,minimal[i]);
        if(valid!=ok||(valid&&((minimal[i]->id<<8)|minimal[i]->size)!=id)||address!=0x1000+consumed||
           left!=count-consumed||cursor!=bytes.data()+consumed)wrong|=1;
        unsigned bit=2;
        for(auto step:{X86_scanBatch,X86_scanNativeBatch}){
            std::array<uint32_t,2> result{0xacefacef,0x45673210};
            auto row=step(scan[i],bytes.data(),count,0x1000,result.data(),1);
            if(row.count!=size_t(ok)||row.bytes!=consumed||result[0]!=(ok?id:0xacefacef)||result[1]!=0x45673210)wrong|=bit;
            bit*=2;
        }
        std::printf("%u %u %u\n",id,wrong,valid?minimal[i]->id:0);
    }
    for(unsigned i=0;i<3;++i){cs_free(full[i],1);cs_free(minimal[i],1);cs_close(&text[i]);cs_close(&scan[i]);}
}
