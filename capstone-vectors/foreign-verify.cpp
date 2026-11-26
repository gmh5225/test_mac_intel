#define main prior_main
#include "trial-compare.cpp"
#undef main

int main(int argc,char **argv) {
    if(argc!=6) return 2;
    Api base(argv[1]),candidate(argv[2]);
    check(base.next!=candidate.next,"independent shared libraries");
    const std::string arch_name=argv[3];
    cs_arch arch;
    cs_mode mode;
    if(arch_name=="arm64") { arch=CS_ARCH_AARCH64; mode=CS_MODE_LITTLE_ENDIAN; }
    else if(arch_name=="arm") { arch=CS_ARCH_ARM; mode=CS_MODE_ARM; }
    else if(arch_name=="mips64el") { arch=CS_ARCH_MIPS; mode=CS_MODE_MIPS64R2; }
    else if(arch_name=="riscv64") { arch=CS_ARCH_RISCV; mode=cs_mode(CS_MODE_RISCV64|CS_MODE_RISCV_C|CS_MODE_RISCV_A); }
    else if(arch_name=="ppc64el") { arch=CS_ARCH_PPC; mode=CS_MODE_64; }
    else return 2;
    Session a(base,arch,mode),b(candidate,arch,mode);
    const unsigned output=std::stoul(argv[5]);
    for(auto *s:{&a,&b}) {
        s->set(CS_OPT_DETAIL,output==2?CS_OPT_ON:CS_OPT_OFF);
        s->set(CS_OPT_TEXT,output?CS_OPT_ON:CS_OPT_OFF);
    }
    std::ifstream file(argv[4],std::ios::binary);
    std::vector<uint8_t> bytes{std::istreambuf_iterator<char>(file),{}};
    check(!bytes.empty(),"ELF text");
    const uint8_t *cursor=bytes.data();
    size_t remaining=bytes.size();
    uint64_t ip=0x100000,valid=0,invalid=0;
    while(remaining) {
        const uint8_t *other=cursor;size_t left=remaining;uint64_t address=ip;
        cs_insn left_insn{},right_insn{};cs_detail x,y;
        std::memset(&x,0x5a,sizeof(x));std::memcpy(&y,&x,sizeof(y));
        std::memset(&left_insn,0x5a,sizeof(left_insn));
        left_insn.illegal=left_insn.usesAliasDetails=left_insn.is_alias=false;
        std::memcpy(&right_insn,&left_insn,sizeof(right_insn));left_insn.detail=&x;right_insn.detail=&y;
        const bool ok=a.api.next(a.h,&cursor,&remaining,&ip,&left_insn);
        const bool matched=b.api.next(b.h,&other,&left,&address,&right_insn);
        check(ok==matched&&cursor==other&&left==remaining&&address==ip&&a.api.error(a.h)==b.api.error(b.h),"foreign cursor and error");
        check(left_insn.detail==&x&&right_insn.detail==&y,"foreign detail ownership");
        left_insn.detail=right_insn.detail=nullptr;
        check(!std::memcmp(&left_insn,&right_insn,sizeof(left_insn))&&!std::memcmp(&x,&y,sizeof(x)),"foreign public records");
        if(!ok) {
            const size_t step=std::min(remaining,size_t(arch==CS_ARCH_RISCV?2:4));
            cursor+=step;remaining-=step;ip+=step;++invalid;continue;
        }
        if(output==2) {
            left_insn.detail=&x;right_insn.detail=&y;
            cs_regs ar{},aw{},br{},bw{};uint8_t an=0,am=0,bn=0,bm=0;
            const auto ae=a.api.regs(a.h,&left_insn,ar,&an,aw,&am);
            const auto be=b.api.regs(b.h,&right_insn,br,&bn,bw,&bm);
            check(ae==be&&an==bn&&am==bm&&!std::memcmp(ar,br,sizeof(ar))&&!std::memcmp(aw,bw,sizeof(aw)),"foreign register accesses");
        }
        ++valid;
    }
    std::printf("%" PRIu64 " %" PRIu64 "\n",valid,invalid);
}
