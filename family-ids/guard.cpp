#include <capstone/capstone.h>
#include <array>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <dlfcn.h>
#include <sys/mman.h>
#include <unistd.h>

struct API {
    void *lib;
    decltype(&cs_open) open;
    decltype(&cs_close) close;
    decltype(&cs_option) option;
    decltype(&cs_disasm_iter) next;
    explicit API(const char *p) : lib(dlopen(p,RTLD_NOW|RTLD_LOCAL)),
       open((decltype(open))dlsym(lib,"cs_open")),close((decltype(close))dlsym(lib,"cs_close")),
       option((decltype(option))dlsym(lib,"cs_option")),next((decltype(next))dlsym(lib,"cs_disasm_iter")) {}
};
int main(int argc,char **argv) {
    if (argc!=3) return 1;
    API original(argv[1]),candidate(argv[2]);
    const size_t page=sysconf(_SC_PAGESIZE);
    auto area=(uint8_t*)mmap(nullptr,page*2,PROT_READ|PROT_WRITE,MAP_ANON|MAP_PRIVATE,-1,0);
    if (!original.lib||!candidate.lib||area==MAP_FAILED||mprotect(area+page,page,PROT_NONE)) return 2;
    uint64_t checks=0,valid16=0,valid32=0;
    for (auto base:{CS_MODE_RISCV32,CS_MODE_RISCV64})
    for (unsigned extensions:{0u,unsigned(CS_MODE_RISCV_C | CS_MODE_RISCV_FD | CS_MODE_RISCV_V | CS_MODE_RISCV_ZCMP_ZCMT_ZCE | CS_MODE_RISCV_ZICFISS)})
    for (auto syntax:{CS_OPT_SYNTAX_DEFAULT,CS_OPT_SYNTAX_REAL,CS_OPT_SYNTAX_UNCOMPRESSED_REAL,CS_OPT_SYNTAX_ALIAS})
    for (unsigned detail:{0u,unsigned(CS_OPT_ON),unsigned(CS_OPT_ON|CS_OPT_DETAIL_REAL),unsigned(CS_OPT_ON|CS_OPT_DETAIL_UNCOMPRESSED_REAL),unsigned(CS_OPT_ON|CS_OPT_DETAIL_ALIAS)}) {
        unsigned mode=unsigned(base)|extensions;csh a=0,b=0;
        if (original.open(CS_ARCH_RISCV,cs_mode(mode),&a) || candidate.open(CS_ARCH_RISCV,cs_mode(mode),&b)) return 3;
        if (original.option(a,CS_OPT_SYNTAX,syntax)||candidate.option(b,CS_OPT_SYNTAX,syntax)||
            original.option(a,CS_OPT_DETAIL,detail)||candidate.option(b,CS_OPT_DETAIL,detail)) return 4;
        for (unsigned word=0;word<65536;++word) {
            auto compare=[&](size_t n) {
                uint8_t *p=area+page-n;
                uint32_t raw=(uint32_t(word*0x9e37u+0x7141u)<<16)|word;
                for (size_t i=0;i<n;++i) p[i]=i<4?uint8_t(raw>>(i*8)):uint8_t(word>>(i&7));
                cs_insn x,y;cs_detail dx,dy;
                memset(&x,0xa5,sizeof(x));x.is_alias=false;x.illegal=false;x.usesAliasDetails=false;
                memset(&dx,0x5a,sizeof(dx));memcpy(&y,&x,sizeof(x));memcpy(&dy,&dx,sizeof(dx));
                x.detail=detail?&dx:nullptr;y.detail=detail?&dy:nullptr;
                const uint8_t *pa=p,*pb=p;size_t na=n,nb=n;uint64_t ia=0x100000+word,ib=ia;
                bool va=original.next(a,&pa,&na,&ia,&x),vb=candidate.next(b,&pb,&nb,&ib,&y);
                x.detail=y.detail=nullptr;++checks;
                if (va && x.size==2) ++valid16;
                if (va && x.size==4) ++valid32;
                if (va==vb && pa==pb && na==nb && ia==ib && !memcmp(&x,&y,sizeof(x)) && !memcmp(&dx,&dy,sizeof(dx))) return true;
                fprintf(stderr,"word=%04x length=%zu mode=%x syntax=%u detail=%u\n",word,n,mode,unsigned(syntax),detail);return false;
            };
            if (!compare(2)||!compare(4))return 5;
            if (word%97==0)for (auto n:{0u,1u,3u,5u,6u})if(!compare(n))return 6;
        }
        original.close(&a);candidate.close(&b);
    }
    munmap(area,page*2);
    printf("%llu %llu %llu\n",(unsigned long long)checks,(unsigned long long)valid16,(unsigned long long)valid32);
    return checks>10000000 && valid16 && valid32?0:7;
}
