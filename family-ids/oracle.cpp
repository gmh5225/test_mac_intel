#define main existing_compare_main
#include "compare.cpp"
#undef main

struct Outcome {
    bool accepted;
    unsigned id;
    size_t consumed;
    uint64_t ip;
    cs_err error;
    bool operator==(const Outcome &v) const {
        return accepted==v.accepted && id==v.id && consumed==v.consumed && ip==v.ip && error==v.error;
    }
};

int main(int argc,char **argv) {
    if(argc!=3) return 2;
    Api baseline(argv[1]),candidate(argv[2]);
    const auto pg=size_t(sysconf(_SC_PAGESIZE));
    auto *area=static_cast<uint8_t *>(mmap(nullptr,2*pg,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANON,-1,0));
    check(area!=MAP_FAILED&&!mprotect(area+pg,pg,PROT_NONE),"mmap guard");
    uint64_t cases=0,valid=0,before_mismatch=0,after_mismatch=0,introduced=0,resolved=0;
    for (auto mode : {CS_MODE_64, CS_MODE_32, CS_MODE_16, static_cast<cs_mode>(CS_MODE_64|CS_MODE_X86_AMD)}) {
        Session full(baseline,CS_ARCH_X86,mode),old_scan(baseline,CS_ARCH_X86,mode),scan(candidate,CS_ARCH_X86,mode);
        cs_opt_mnem name={X86_INS_UD2,"ud2"};full.set(CS_OPT_MNEMONIC,reinterpret_cast<size_t>(&name));
        full.set(CS_OPT_DETAIL,CS_OPT_ON);old_scan.set(CS_OPT_TEXT,CS_OPT_OFF);scan.set(CS_OPT_TEXT,CS_OPT_OFF);
        Session *sessions[]={&full,&old_scan,&scan};cs_insn *records[3];
        for (unsigned i=0;i<3;++i){records[i]=sessions[i]->api.alloc(sessions[i]->h);check(records[i],"CS record");}
        uint8_t b[16]={0x62,0xf1,0x7c,0x48,0x10,0xc2,0x25,0xff,0xb4,0x16,0x93,0,0,0,0,0};
        auto compare=[&](unsigned n){
            auto *start=area+pg-n;std::memcpy(start,b,n);Outcome output[3];
            for(unsigned i=0;i<3;++i){
                const uint8_t *cur=start;size_t left=n;uint64_t ip=UINT64_MAX-3;
                auto &s=*sessions[i];bool ok=s.api.next(s.h,&cur,&left,&ip,records[i]);
                output[i]={ok,ok?records[i]->id:0u,size_t(cur-start),ip,s.api.error(s.h)};
                check(left+output[i].consumed==n&&(!ok||records[i]->size==output[i].consumed),"consumed bytes");
            }
            bool before=output[0]==output[1],after=output[0]==output[2];
            if((!after||!before) && before_mismatch+after_mismatch<12)
                std::fprintf(stderr,"mode=%u p=%02x%02x%02x op=%02x mr=%02x sib=%02x n=%u full=%u/%zu base=%u/%zu candidate=%u/%zu\n",
                    unsigned(mode),b[1],b[2],b[3],b[4],b[5],b[6],n,output[0].id,output[0].consumed,
                    output[1].id,output[1].consumed,output[2].id,output[2].consumed);
            ++cases;valid+=output[0].accepted;before_mismatch+=!before;after_mismatch+=!after;introduced+=before&&!after;resolved+=!before&&after;
        };
        for (unsigned op:{0x10,0x11,0x28,0x29}) {
            b[4]=uint8_t(op);
            for(unsigned p0:{0xf1,0x01,0xf2,0xf8}) {
                b[1]=uint8_t(p0);
                for(unsigned p1=0;p1<256;++p1)for(unsigned p2=0;p2<256;++p2){
                    b[2]=uint8_t(p1);b[3]=uint8_t(p2);b[5]=uint8_t((p1^p2)&1?0xc2:0x54);b[6]=0x25;compare(15);
                }
            }
            b[2]=uint8_t(op&1?0xfd:0x7c);b[3]=0x48;
            for(unsigned p0=0;p0<256;++p0) {
                b[1]=uint8_t(p0);
                for(unsigned mr=0;mr<256;++mr){b[5]=uint8_t(mr);b[6]=uint8_t((p0*11+mr*7)&255);compare(15);}
            }
            b[1]=0xf1;
            for(unsigned mr:{0x04,0x44,0x84,0x05,0x45,0x85,0xc4})
                for(unsigned sib=0;sib<256;++sib){
                    b[5]=uint8_t(mr);b[6]=uint8_t(sib);
                    for(unsigned n=0;n<=15;++n)compare(n);
                }
        }
        for(unsigned i=0;i<3;++i)sessions[i]->api.free(records[i],1);
    }
    std::printf("%llu %llu %llu %llu %llu %llu\n",(unsigned long long)cases,(unsigned long long)valid,
        (unsigned long long)before_mismatch,(unsigned long long)after_mismatch,(unsigned long long)introduced,(unsigned long long)resolved);
    return munmap(area,pg*2)!=0;
}
