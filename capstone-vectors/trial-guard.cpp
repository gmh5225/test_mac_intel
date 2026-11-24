#define main old_compare_main
#include "trial-compare.cpp"
#undef main

struct Probe {
    Session session;
    decltype(&cs_disasm_iter) iter;
    Probe(Api &api, cs_mode mode):session(api,CS_ARCH_X86,mode),
        iter(api.sym<decltype(iter)>("cs_disasm_iter")) {
        session.set(CS_OPT_TEXT,CS_OPT_OFF);
    }
};

int main(int argc,char **argv) {
    if(argc!=3)return 2;
    Api base(argv[1]),candidate(argv[2]);
    size_t pagesize=sysconf(_SC_PAGESIZE);
    auto *page=static_cast<uint8_t *>(mmap(nullptr,2*pagesize,PROT_READ|PROT_WRITE,
        MAP_ANON|MAP_PRIVATE,-1,0));
    check(page!=MAP_FAILED&&!mprotect(page+pagesize,pagesize,PROT_NONE),"guard");
    const std::vector<std::vector<uint8_t>> prefixes={
        {},{0x66},{0x67},{0xf2},{0xf3},{0xf0},{0x48},{0x4f},{0x66,0x48},
        {0x0f},{0x0f,0x38},{0x0f,0x3a},{0x66,0x0f},{0xf2,0x0f},{0xf3,0x0f},
        {0xc5,0xf9},{0xc5,0xfe},{0xc4,0xe2,0x7d},{0xc4,0xe3,0x79},
        {0x62,0xf1,0x7d,0x48},{0x62,0xf2,0xfd,0x09},{0xd5,0x80}};
    uint64_t cases=0,accepted=0;
    for(auto mode:{CS_MODE_16,CS_MODE_32,CS_MODE_64}) {
        Probe left(base,mode),right(candidate,mode);
        for(const auto &prefix:prefixes)for(unsigned op=0;op<256;++op) {
            for(unsigned mr:{0u,4u,5u,0x38u,0x45u,0x84u,0xc0u,0xfbu}) {
                uint8_t code[16]={};
                const size_t lead=prefix.size();
                std::copy(prefix.begin(),prefix.end(),code);
                code[lead]=uint8_t(op);code[lead+1]=uint8_t(mr);
                for(size_t i=lead+2;i<sizeof(code);++i)code[i]=uint8_t(i*19+op*13+mr);
                for(size_t n=0;n<=15;++n) {
                    uint8_t *origin=page+pagesize-n;
                    std::memcpy(origin,code,n);
                    cs_insn records[2];cs_detail details[2];
                    const uint8_t *ptr[2]={origin,origin};size_t sizes[2]={n,n};
                    uint64_t pcs[2]={UINT64_MAX-3,UINT64_MAX-3};bool result[2];
                    for(unsigned k=0;k<2;++k) {
                        auto &view=k?right:left;
                        std::memset(&records[k],cases&1?0x5a:0xd5,sizeof(cs_insn));
                        records[k].illegal=(cases>>1)&1;
                        records[k].is_alias=(cases>>2)&1;
                        records[k].usesAliasDetails=(cases>>3)&1;
                        std::memset(&details[k],0x5a,sizeof(cs_detail));
                        auto *detail=cases&1?&details[k]:nullptr;
                        records[k].detail=detail;
                        result[k]=view.iter(view.session.h,ptr+k,sizes+k,pcs+k,records+k);
                        check(records[k].detail==detail,"retained detail");
                        records[k].detail=nullptr;
                    }
                    if(result[0]!=result[1]||ptr[0]!=ptr[1]||sizes[0]!=sizes[1]||
                       pcs[0]!=pcs[1]||base.error(left.session.h)!=candidate.error(right.session.h)||
                       std::memcmp(records,records+1,sizeof(cs_insn))||
                       std::memcmp(details,details+1,sizeof(cs_detail))) {
                        std::fprintf(stderr,"diff mode %u length %zu prefix",unsigned(mode),n);
                        for(auto b:prefix)std::fprintf(stderr," %02x",b);
                        std::fprintf(stderr," opcode %02x modrm %02x id %u/%u result %d/%d\n",
                            op,mr,records[0].id,records[1].id,result[0],result[1]);return 1;
                    }
                    ++cases;accepted+=result[0];
                }
            }
        }
    }
    std::printf("%llu %llu\n",(unsigned long long)cases,(unsigned long long)accepted);
    return munmap(page,2*pagesize)!=0;
}
