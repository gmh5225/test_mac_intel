#include <capstone/capstone.h>
#include "arch/X86/X86ScanAdapter.h"
#include <array>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <vector>

int main() {
    const std::vector<std::vector<uint8_t>> legacy={{},{0x66},{0x66,0x66},{0x67,0x66},{0x66,0x67},{0x64,0x66},{0x66,0x64},{0x66,0xf2},{0xf2,0x66},{0x66,0xf3},{0xf3,0x66},{0xf2},{0xf3}};
    for(auto mode:{CS_MODE_16,CS_MODE_32,CS_MODE_64}){
        auto prefixes=legacy;
        if(mode==CS_MODE_64){
            for (auto p:std::vector<std::vector<uint8_t>>{{0x48},{0x49},{0x4c},{0x4d},{0x66,0x48},{0x48,0x66}})
                prefixes.push_back(p);
        }
        csh text{},scan{};
        if(cs_open(CS_ARCH_X86,mode,&text)||cs_open(CS_ARCH_X86,mode,&scan)||
            cs_option(text,CS_OPT_DETAIL,CS_OPT_ON)||cs_option(scan,CS_OPT_TEXT,CS_OPT_OFF))return 1;
        cs_insn *full=cs_malloc(text),*short_insn=cs_malloc(scan);
        if(!full||!short_insn)return 2;
        for (auto op:{0x6e,0x6f,0x7e,0x7f,0xd6}) {
            std::array<unsigned,3> mismatches{};unsigned checked=0,accepted=0;
            for(const auto &prefix:prefixes)for(int modrm=0;modrm<256;++modrm){
                auto buffer=prefix;
                buffer.insert(buffer.end(),{0x0f,uint8_t(op),uint8_t(modrm),0xa5,0x39,0x39,0x39,0x39,0x39,0x39});
                for(size_t n=prefix.size()+2;n<=buffer.size();++n){
                    const uint8_t *data=buffer.data();size_t size=n;uint64_t address=0x1000;
                    const bool valid=cs_disasm_iter(text,&data,&size,&address,full);
                    const uint32_t expected=valid?(full->id<<8)|full->size:0;
                    accepted+=valid;++checked;
                    data=buffer.data();size=n;address=0x1000;
                    const bool ok=cs_disasm_iter(scan,&data,&size,&address,short_insn);
                    const auto compact=ok?(short_insn->id<<8)|short_insn->size:0;
                    if((ok!=valid ||compact!=expected)&&!mismatches[0]++)
                        std::fprintf(stderr,"mode=%d op=%02x modrm=%02x prefix=%zu length=%zu full=%u compact=%u\n",int(mode),op,modrm,prefix.size(),n,expected,compact);
                    unsigned j=0;
                    for(auto step:{X86_scanBatch,X86_scanNativeBatch}){
                        std::array<uint32_t,2> result{0xacefacef,0x45673210};const auto b=step(scan,buffer.data(),n,0x1000,result.data(),1);
                        if(b.count!=size_t(valid)||b.bytes!=(valid?full->size:0)||result[0]!=(valid?expected:0xacefacef)||result[1]!=0x45673210)
                            ++mismatches[j+1];
                        ++j;
                    }
                }
            }
            std::printf("%d %02x %u %u %u %u %u\n",int(mode),op,checked,accepted,mismatches[0],mismatches[1],mismatches[2]);std::fflush(stdout);
        }
        cs_free(short_insn,1);cs_free(full,1);cs_close(&scan);cs_close(&text);
    }
}
