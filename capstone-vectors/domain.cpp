#define main comparison_for_other_targets
#include "public-compare.cpp"
#undef main
#include <sstream>

static bool equal_step(Session &a, Session &b, const uint8_t *code, size_t size,
                       uint64_t addr, bool detail, unsigned &consumed) {
    const auto *pa=code,*pb=code; size_t na=size,nb=size; uint64_t ia=addr,ib=addr;
    cs_insn left{},right{}; cs_detail dl{},dr{};
    std::memset(left.mnemonic,0x5a,sizeof(left.mnemonic));
    std::memset(left.op_str,0xa5,sizeof(left.op_str));
    std::memset(left.bytes,0x55,sizeof(left.bytes));
    right=left;
    if(detail) {left.detail=&dl;right.detail=&dr;}
    const bool ok=a.api.next(a.h,&pa,&na,&ia,&left), same=b.api.next(b.h,&pb,&nb,&ib,&right);
    check(ok==same && na==nb && ia==ib && pa==pb && a.api.error(a.h)==b.api.error(b.h),"cursor or error");
    check(left.detail==(detail?&dl:nullptr) && right.detail==(detail?&dr:nullptr),"detail pointer");
    left.detail=right.detail=nullptr;
    if(std::memcmp(&left,&right,sizeof left) || std::memcmp(&dl,&dr,sizeof dl)) {
        std::fprintf(stderr,"ARM word %02x %02x at %" PRIx64 ": %u %s %s / %u %s %s\n",code[0],size>1?code[1]:0,addr,left.id,left.mnemonic,left.op_str,right.id,right.mnemonic,right.op_str);
        std::exit(8);
    }
    if (ok) {
        check(left.size && na+left.size==size && ia==addr+left.size && pa==code+left.size,"progress");
        if (detail) {
            cs_regs ar{},aw{},br{},bw{};uint8_t nr=0,nw=0,tr=0,tw=0;left.detail=&dl;right.detail=&dr;
            const auto ae=a.api.regs(a.h,&left,ar,&nr,aw,&nw),be=b.api.regs(b.h,&right,br,&tr,bw,&tw);
            check(ae==be && nr==tr && nw==tw && !std::memcmp(ar,br,nr*sizeof ar[0]) && !std::memcmp(aw,bw,nw*sizeof aw[0]),"regs_access");
        }
    }
    consumed=ok?left.size:0;
    return ok;
}
int main(int argc,char **argv) {
    if(argc!=4)return 2;
    Api old(argv[1]),trial(argv[2]);
    uint64_t cases=0,accepted=0,real=0,bytes=0,rejected=0;
    for (unsigned thumb : {0u,unsigned(CS_MODE_THUMB)})
     for (unsigned be : {0u,unsigned(CS_MODE_BIG_ENDIAN)})
      for (unsigned opt=0;opt<4;++opt) {
        cs_mode mode=cs_mode(thumb|be);Session a(old,CS_ARCH_ARM,mode),b(trial,CS_ARCH_ARM,mode);
        for(auto *h:{&a,&b}) {
            h->set(CS_OPT_TEXT,opt?CS_OPT_ON:CS_OPT_OFF);
            h->set(CS_OPT_DETAIL,opt<2?CS_OPT_OFF:(opt==2?unsigned(CS_OPT_ON):unsigned(CS_OPT_ON)|unsigned(CS_OPT_DETAIL_REAL)));
        }
        for(uint32_t imm=0;imm<4096;++imm)
         for(uint32_t base : {0xe5901000u,0xe500f000u,0x14900000u,0xe4d02000u,0xe3a01000u,0xe3510000u,0xe3810000u,0xf8d01000u,0xf8c20000u}) {
            uint32_t word=base|imm;uint8_t buf[4];
            for(unsigned j=0;j<4;++j) {
                unsigned idx=be ? 3-j : (thumb ? (j^2) : j);
                buf[idx]=uint8_t(word>>(8*j));
            }
            unsigned used;accepted+=equal_step(a,b,buf,4,0x1000,opt>=2,used);++cases;
            if(!(imm&255)) for(unsigned len=0;len<4;++len) {accepted+=equal_step(a,b,buf,len,0x1000,opt>=2,used);++cases;}
        }
        if(thumb||be)continue;
        for(const char *name:{"cat","ls","cp","sort"}) {
            const std::string stem=std::string(argv[3])+"/arm-"+name;
            std::ifstream input(stem+".text",std::ios::binary),ranges(stem+".ranges");
            check(input.good()&&ranges.good(),"missing ELF corpus");
            std::vector<uint8_t> memory(std::istreambuf_iterator<char>(input),{});size_t off,len;uint64_t addr;
            while(ranges>>off>>len>>addr) {
                check(len&&off+len<=memory.size()&&!(len%4),"extent bounds");
                while(len) {
                    unsigned used=0;
                    bool ok=equal_step(a,b,memory.data()+off,len,addr,opt>=2,used);
                    if(!ok){++rejected;used=4;}check(used==4,"A32 instruction length");
                    ++real;bytes+=used;addr+=used;off+=used;len-=used;
                }
            }
            check(ranges.eof(),"extent parse");
        }
      }
    std::printf("{\"cases\":%" PRIu64 ",\"accepted\":%" PRIu64 ",\"real\":%" PRIu64 ",\"bytes\":%" PRIu64 ",\"real_rejected\":%" PRIu64 "}\n",cases,accepted,real,bytes,rejected);
}
