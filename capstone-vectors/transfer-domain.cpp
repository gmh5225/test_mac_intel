#define main original_compare_main
#include "trial-compare.cpp"
#undef main

int main(int argc,char **argv) {
    if(argc!=3)return 2;
    Api ref(argv[1]),next(argv[2]);
    size_t page=sysconf(_SC_PAGESIZE);
    auto *p=static_cast<uint8_t *>(mmap(nullptr,2*page,PROT_READ|PROT_WRITE,MAP_ANON|MAP_PRIVATE,-1,0));
    check(p!=MAP_FAILED&&!mprotect(p+page,page,PROT_NONE),"guard");
    uint64_t trials=0,accepted=0,ordinary=0;
    for(auto bits:{CS_MODE_64}) {
        Session a(ref,CS_ARCH_X86,bits),b(next,CS_ARCH_X86,bits);

        for(unsigned cfg=0;cfg<8;++cfg) {
            for(auto *s:{&a,&b}) {
                s->set(CS_OPT_DETAIL,cfg&1?CS_OPT_ON:CS_OPT_OFF);
                s->set(CS_OPT_UNSIGNED,cfg&2?CS_OPT_ON:CS_OPT_OFF);
                s->set(CS_OPT_TEXT,cfg&4?CS_OPT_OFF:CS_OPT_ON);
            }
            for(unsigned op:{0x28,0x29,0x50})for(unsigned prefix:{2,3})
            for(unsigned mr=0xc0;mr<=0xff;++mr)for(unsigned k=0;k<(prefix==2?8u:16u);++k)
            for(unsigned ext=0;ext<(prefix==2?2u:8u);++ext)for(unsigned alternate=0;alternate<2;++alternate) {
                const unsigned src=alternate?(mr+ext+k)%15:15;
                uint8_t bytes[12]={};
                bytes[0]=prefix==2?0xc5:0xc4;
                if(prefix==3) bytes[1]=uint8_t((ext<<5)|1);
                bytes[prefix-1]=uint8_t((prefix==2?ext<<7:(k&8)<<4)|(src<<3)|(k&7));
                bytes[prefix]=uint8_t(op);bytes[prefix+1]=uint8_t(mr);
                for(unsigned n=0;n<=prefix+3;++n) {
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
                        std::fprintf(stderr,"difference mode=%d cfg=%u opcode=%x map=%u mr=%02x n=%u\n",bits,cfg,op,prefix,mr,n);return 1;
                    }
                    ++trials;accepted+=ok[0];ordinary+=ok[0] && !alternate && left[0]+prefix+2==n;
                }
            }
        }
    }
    std::printf("%llu %llu %llu\n",(unsigned long long)trials,(unsigned long long)accepted,(unsigned long long)ordinary);
    return munmap(p,2*page)!=0;
}
