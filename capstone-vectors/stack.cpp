#define main old_compare
#include "compare.cpp"
#undef main

int main(int argc,char **argv) {
    if(argc!=3)return 2;
    Api ref(argv[1]),trial(argv[2]);
    const size_t page=sysconf(_SC_PAGESIZE);
    auto *buf=static_cast<uint8_t *>(mmap(nullptr,2*page,PROT_READ|PROT_WRITE,MAP_ANON|MAP_PRIVATE,-1,0));
    check(buf!=MAP_FAILED && !mprotect(buf+page,page,PROT_NONE),"protect");
    uint64_t cases=0,valid=0;
    for(auto bits:{CS_MODE_16,CS_MODE_32,CS_MODE_64})for(unsigned custom=0;custom<2;++custom) {
        Session a(ref,CS_ARCH_X86,bits),b(trial,CS_ARCH_X86,bits);
        cs_opt_mnem m{X86_INS_CMP,"comparison.override"};
        if(custom){a.set(CS_OPT_MNEMONIC,reinterpret_cast<uintptr_t>(&m));b.set(CS_OPT_MNEMONIC,reinterpret_cast<uintptr_t>(&m));}
        for(unsigned cfg=0;cfg<16;++cfg){
            for(auto h:{&a,&b}){
                h->set(CS_OPT_DETAIL,(cfg&1)?CS_OPT_ON:CS_OPT_OFF);h->set(CS_OPT_UNSIGNED,(cfg&2)?CS_OPT_ON:CS_OPT_OFF);
                h->set(CS_OPT_TEXT,(cfg&4)?CS_OPT_OFF:CS_OPT_ON);h->set(CS_OPT_SYNTAX,(cfg&8)?CS_OPT_SYNTAX_ATT:CS_OPT_SYNTAX_INTEL);
            }
            for(unsigned pub=1;pub<2;++pub){
                auto left=pub?ref.sym<decltype(ref.next)>("cs_disasm_iter"):ref.next;
                auto right=pub?trial.sym<decltype(trial.next)>("cs_disasm_iter"):trial.next;
                std::vector<unsigned> opcodes;
                for(unsigned k=0x4f;k<=0x60;k++)opcodes.push_back(k);
                for(unsigned k=0xb7;k<=0xc0;k++)opcodes.push_back(k);
                for(unsigned op:opcodes)
                for(unsigned prefix:{0,0x66,0x67,0x2e,0x40,0x48,0xf0,0xf2,0xf3,0x6666,0x6766,0x66f0,0xf266,0x66f3})
                for(uint32_t value:{0u,1u,9u,10u,0x7fu,0x80u,0xffu,0x7fffu,0x8000u,0x7fffffffu,0x80000000u,0xffffffffu,0xc0u,0xf8u}){
                    uint8_t raw[8]={uint8_t(prefix>>8),uint8_t(prefix),uint8_t(op),uint8_t(value),uint8_t(value>>8),uint8_t(value>>16),uint8_t(value>>24),0x90};
                    unsigned first=prefix>255?0:prefix?1:2;
                    for(unsigned len=0;len<=sizeof(raw)-first;++len){
                        uint8_t *start=buf+page-len;std::memcpy(start,raw+first,len);
                        const uint8_t *p[2]={start,start};size_t rem[2]={len,len};uint64_t ip[2]={UINT64_MAX-2,UINT64_MAX-2};
                        cs_insn insn[2];cs_detail detail[2];bool result[2];
                        for(unsigned i=0;i<2;++i){
                            std::memset(insn+i,0x5a,sizeof(cs_insn));std::memset(detail+i,0x5a,sizeof(cs_detail));
                            insn[i].illegal=insn[i].usesAliasDetails=insn[i].is_alias=false;insn[i].detail=detail+i;
                            result[i]=(i?right:left)(i?b.h:a.h,p+i,rem+i,ip+i,insn+i);
                            check(insn[i].detail==detail+i,"caller detail pointer");insn[i].detail=nullptr;
                        }
                        if(result[0]!=result[1] || p[0]!=p[1] || rem[0]!=rem[1] || ip[0]!=ip[1] || ref.error(a.h)!=trial.error(b.h) ||
                           std::memcmp(insn,insn+1,sizeof(cs_insn)) || std::memcmp(detail,detail+1,sizeof(cs_detail))){
                            std::fprintf(stderr,"delta bits=%d custom=%u config=%u public=%u op=%x prefix=%x value=%x length=%u\n",bits,custom,cfg,pub,op,prefix,value,len);
                            return 1;
                        }
                        ++cases;valid+=result[0];
                    }
                }
            }
        }
    }
    std::printf("%llu %llu\n",(unsigned long long)cases,(unsigned long long)valid);
    return munmap(buf,2*page)!=0;
}
