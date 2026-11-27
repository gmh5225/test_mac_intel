#define main old_compare
#include "index-compare.cpp"
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
            for(unsigned pub=0;pub<2;++pub){
                auto left=pub?ref.sym<decltype(ref.next)>("cs_disasm_iter"):ref.next;
                auto right=pub?trial.sym<decltype(trial.next)>("cs_disasm_iter"):trial.next;
                for(unsigned op:{0x8b,0x8d,0x58}) for(unsigned prefix:{0,0x66,0x67,0x64,0x4a,0xc5})
                for(unsigned mod:{0u,1u,2u}) for(unsigned value=0;value<256;++value){
                    const bool dense=bits!=CS_MODE_16 && !custom && cfg<2 && op==0x8b && !prefix;
                    if(!dense && value%37 && value!=0x25 && value!=0xfd && value!=255)continue;
                    if(prefix==0xc5 && op!=0x58)continue;
                    uint8_t raw[12]={};unsigned n=0;
                    if(prefix){raw[n++]=uint8_t(prefix);if(prefix==0xc5)raw[n++]=0xfc;}
                    if(op==0x58 && prefix!=0xc5)raw[n++]=0x0f;
                    raw[n++]=uint8_t(op);raw[n++]=uint8_t((mod<<6)|0x1c);raw[n++]=uint8_t(value);
                    if(mod==2 || (!mod && (value&7)==5)){
                        const uint32_t disp=(value&1)?0x80000000U:0x7f123409U;
                        for(unsigned j=0;j<4;++j)raw[n++]=uint8_t(disp>>(j*8));
                    }else if(mod==1)raw[n++]=uint8_t((value&3)?0xf6:9);
                    for(unsigned len=0;len<=n;++len){
                        uint8_t *start=buf+page-len;std::memcpy(start,raw,len);
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
