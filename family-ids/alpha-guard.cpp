#include <capstone/capstone.h>
#include <sys/mman.h>
#include <unistd.h>
#include <dlfcn.h>
#include <array>
#include <utility>
#include <cstdint>
#include <cstdio>
#include <cstring>
struct Reader {
    void *library;
    decltype(&cs_open) open;
    decltype(&cs_close) close;
    decltype(&cs_option) option;
    decltype(&cs_disasm_iter) next;
    Reader(const char *path) : library(dlopen(path, RTLD_LOCAL | RTLD_NOW)),
        open((decltype(open))dlsym(library,"cs_open")),close((decltype(close))dlsym(library,"cs_close")),
        option((decltype(option))dlsym(library,"cs_option")),next((decltype(next))dlsym(library,"cs_disasm_iter")) {}
};
int main(int argc,char **argv) {
    if(argc!=3)return 1;
    Reader old(argv[1]),updated(argv[2]);if(!old.library || !updated.library)return 2;
    size_t page=(size_t)sysconf(_SC_PAGESIZE);
    uint8_t *memory=(uint8_t*)mmap(nullptr,page*2,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANON,-1,0);
    if(memory==MAP_FAILED || mprotect(memory+page,page,PROT_NONE))return 3;
    unsigned checks=0,okays=0,open_modes=0;
    for(cs_mode mode:{CS_MODE_LITTLE_ENDIAN,CS_MODE_BIG_ENDIAN}) {
        csh a=0,b=0;auto err=old.open(CS_ARCH_ALPHA,mode,&a);
        if(err!=updated.open(CS_ARCH_ALPHA,mode,&b))return 4;
        if(err!=CS_ERR_OK)return 5;
        ++open_modes;
        for(bool detail:{false,true})for(bool text:{false,true}) {
            for (auto [opt,value]:{std::pair{CS_OPT_DETAIL,detail},std::pair{CS_OPT_TEXT,text}}) {
                if(old.option(a,opt,value?CS_OPT_ON:CS_OPT_OFF)||updated.option(b,opt,value?CS_OPT_ON:CS_OPT_OFF))return 6;
            }
            for(unsigned first=0;first!=256;++first) for(unsigned sample=0;sample!=8;++sample) for(unsigned n=0;n<=6;++n) {
                uint8_t *p=memory+page-n;
                for(unsigned i=0;i<n;++i)p[i]=i==((mode&CS_MODE_BIG_ENDIAN)?0u:3u)?first:(sample*61+first*7+i*29)&255;
                const uint8_t *aa=p,*bb=p;size_t na=n,nb=n;uint64_t ia=UINT64_MAX-3,ib=ia;
                cs_insn x,y;cs_detail dx,dy;memset(&x,0xa5,sizeof(x));memset(&dx,0x5a,sizeof(dx));
                x.illegal=x.is_alias=x.usesAliasDetails=false;memcpy(&y,&x,sizeof(x));memcpy(&dy,&dx,sizeof(dx));
                x.detail=detail?&dx:nullptr;y.detail=detail?&dy:nullptr;
                const bool yes=old.next(a,&aa,&na,&ia,&x),other=updated.next(b,&bb,&nb,&ib,&y);
                x.detail=y.detail=nullptr;
                if(other!=yes||aa!=bb||na!=nb||ia!=ib||memcmp(&x,&y,sizeof(x))||memcmp(&dx,&dy,sizeof(dx))){
                    std::fprintf(stderr,"mode %u detail %u text %u opcode %02x sample %u len %u\n",(unsigned)mode,detail,text,first,sample,n);return 7;
                }
                checks++;okays+=yes;
            }
        }
        old.close(&a);updated.close(&b);
    }
    munmap(memory,page*2);printf("%u %u %u\n",open_modes,checks,okays);
    return checks==open_modes*256u*8*7*4 && okays>0 ? 0:8;
}
