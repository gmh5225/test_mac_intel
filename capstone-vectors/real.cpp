#define main unused_comparison_main
#include "public-compare.cpp"
#undef main

int main(int argc, char **argv) {
    if (argc!=4) return 2;
    Api before(argv[1]), after(argv[2]);
    std::ifstream file(argv[3],std::ios::binary);
    std::vector<uint8_t> bytes(std::istreambuf_iterator<char>(file),{});
    if (bytes.empty()) return 3;
    uint64_t accepted=0, rejected=0;
    for (unsigned spelling=0;spelling<4;++spelling) for (unsigned mode=0;mode<4;++mode) {
        Session a(before,CS_ARCH_MIPS,CS_MODE_MIPS64R2),b(after,CS_ARCH_MIPS,CS_MODE_MIPS64R2);
        for (auto *s : {&a,&b}) {
            s->set(CS_OPT_SYNTAX,(spelling&1?CS_OPT_SYNTAX_NOREGNAME:0)|(spelling&2?CS_OPT_SYNTAX_NO_DOLLAR:0));
            s->set(CS_OPT_TEXT,mode?CS_OPT_ON:CS_OPT_OFF);
            s->set(CS_OPT_DETAIL,mode<2?0:mode==2?CS_OPT_ON:CS_OPT_ON|CS_OPT_DETAIL_REAL);
        }
        size_t off=0;
        while (off<bytes.size()) {
            const auto *p=bytes.data()+off,*q=p;size_t n=bytes.size()-off,m=n;
            uint64_t ip=0x100000+off,jp=ip;
            cs_insn x{},y{};cs_detail dx,dy;
            memset(x.bytes,0xa5,sizeof x.bytes);memset(x.mnemonic,0xa5,sizeof x.mnemonic);memset(x.op_str,0x5a,sizeof x.op_str);y=x;
            memset(&dx,0xa5,sizeof dx);dy=dx;
            if(mode>=2){x.detail=&dx;y.detail=&dy;}
            bool ok=a.api.next(a.h,&p,&n,&ip,&x),other=b.api.next(b.h,&q,&m,&jp,&y);
            check(ok==other&&p==q&&n==m&&ip==jp&&a.api.error(a.h)==b.api.error(b.h),"cursor");
            check(x.detail==(mode>=2?&dx:nullptr)&&y.detail==(mode>=2?&dy:nullptr)&&!memcmp(&dx,&dy,sizeof dx),"detail");
            if (ok&&mode>=2) {
                cs_regs ar{},aw{},br{},bw{};uint8_t nr=0,nw=0,mr=0,mw=0;
                check(a.api.regs(a.h,&x,ar,&nr,aw,&nw)==b.api.regs(b.h,&y,br,&mr,bw,&mw)&&nr==mr&&nw==mw&&!memcmp(ar,br,sizeof ar)&&!memcmp(aw,bw,sizeof aw),"register accesses");
            }
            x.detail=y.detail=nullptr;check(!memcmp(&x,&y,sizeof x),"instruction");
            if (!ok) { ++rejected;off+=std::min(size_t(4),bytes.size()-off); }
            else {check(x.size>0,"size");++accepted;off+=x.size;}
        }
    }
    printf("%" PRIu64 " %" PRIu64 "\n",accepted,rejected);
}
