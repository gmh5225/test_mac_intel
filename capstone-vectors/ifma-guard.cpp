#define main original_compare_main
#include "trial-compare.cpp"
#undef main

int main(int argc,char **argv) {
    if(argc!=3)return 2;
    Api ref(argv[1]),next(argv[2]);
    size_t page=sysconf(_SC_PAGESIZE);
    auto *p=static_cast<uint8_t *>(mmap(nullptr,2*page,PROT_READ|PROT_WRITE,MAP_ANON|MAP_PRIVATE,-1,0));
    check(p!=MAP_FAILED&&!mprotect(p+page,page,PROT_NONE),"guard");
    uint64_t trials=0,accepted=0,vex3_memory=0;
    for(auto bits:{CS_MODE_32,CS_MODE_64,CS_MODE_16}) {
        Session a(ref,CS_ARCH_X86,bits),b(next,CS_ARCH_X86,bits);
        cs_opt_mnem neutral{X86_INS_UD2,"ud2"};a.set(CS_OPT_MNEMONIC,reinterpret_cast<uintptr_t>(&neutral));
        for(unsigned cfg=0;cfg<8;++cfg) {
            for(auto *s:{&a,&b}) {
                s->set(CS_OPT_DETAIL,cfg&1?CS_OPT_ON:CS_OPT_OFF);
                s->set(CS_OPT_UNSIGNED,cfg&2?CS_OPT_ON:CS_OPT_OFF);
                s->set(CS_OPT_TEXT,cfg&4?CS_OPT_OFF:CS_OPT_ON);
            }
            for(unsigned op:{0xb4,0xb5})for(unsigned mr=0;mr<256;++mr)
            for(unsigned key=0;key<16;++key) {
                const unsigned m=2,ext=((mr>>3)+key)&7,src=(mr+key)&15;
                const unsigned disp_values[]={0u,0xffffff80u,127u,0x80000000u,0x7fffffffu,0x80000064u};
                const unsigned disp=disp_values[(mr+key)%6];
                const unsigned flags=0x81|(src<<3)|((key&1)<<2);
                uint8_t bytes[12]={0xc4,static_cast<uint8_t>((ext<<5)|m),static_cast<uint8_t>(flags),
                    static_cast<uint8_t>(op),static_cast<uint8_t>(mr),static_cast<uint8_t>(disp),static_cast<uint8_t>(disp>>8),
                    static_cast<uint8_t>(disp>>16),static_cast<uint8_t>(disp>>24),0xfe,0x46,0x81};
                const unsigned first=0;
                for(unsigned n=first;n<=11;++n) {
                    const uint8_t *pos=p+page-n;
                    std::memcpy(p+page-n,bytes,n);const uint8_t *in[2]={pos,pos};
                    size_t left[2]={n,n};uint64_t pc[2]={UINT64_MAX-3,UINT64_MAX-3};
                    cs_insn out[2];cs_detail detail[2];bool ok[2];
                    for(unsigned k=0;k<2;++k){
                        auto &s=k?b:a;std::memset(out+k,0x5a,sizeof(cs_insn));std::memset(detail+k,0x5a,sizeof(cs_detail));
                        out[k].illegal=out[k].is_alias=out[k].usesAliasDetails=false;
                        out[k].detail=(cfg&1)?detail+k:nullptr;ok[k]=s.api.next(s.h,in+k,left+k,pc+k,out+k);
                        check(out[k].detail==((cfg&1)?detail+k:nullptr),"owner");out[k].detail=nullptr;
                    }
                    if(ok[0]!=ok[1]||left[0]!=left[1]||in[0]!=in[1]||pc[0]!=pc[1]||ref.error(a.h)!=next.error(b.h)||
                        std::memcmp(out,out+1,sizeof(cs_insn))||std::memcmp(detail,detail+1,sizeof(cs_detail))) {
                        std::fprintf(stderr,"difference mode=%d cfg=%u opcode=%x map=%u mr=%02x n=%u\n",bits,cfg,op,m,mr,n);return 1;
                    }
                    ++trials;accepted+=ok[0];vex3_memory+=ok[0]&&bits==CS_MODE_64&&mr<0xc0&&left[0]+5<=n;
                }
            }
        }
    }
    std::printf("%llu %llu %llu\n",(unsigned long long)trials,(unsigned long long)accepted,(unsigned long long)vex3_memory);
    return munmap(p,2*page)!=0;
}
