#include <capstone/capstone.h>
#include <algorithm>
#include <cstdarg>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <dlfcn.h>
#include <fstream>
#include <iterator>
#include <vector>
static uint64_t calls, pairs;
static int observed(char *out,size_t n,const char *fmt,va_list args) {
    ++calls;if(std::strcmp(fmt,"%s%s")==0)++pairs;
    return std::vsnprintf(out,n,fmt,args);
}
struct Api {
    void *lib;
    decltype(&cs_open) open;decltype(&cs_close) close;
    decltype(&cs_option) option;decltype(&cs_disasm_iter) iter;
    explicit Api(const char *p):lib(dlopen(p,RTLD_LOCAL|RTLD_NOW)) {
        if(!lib)std::abort();
        open=(decltype(open))dlsym(lib,"cs_open");close=(decltype(close))dlsym(lib,"cs_close");
        option=(decltype(option))dlsym(lib,"cs_option");iter=(decltype(iter))dlsym(lib,"cs_disasm_iter");
    }
};
int main(int argc,char **argv) {
    if(argc!=5)return 1;const bool custom=std::atoi(argv[4]);
    Api api[]{Api(argv[1]),Api(argv[2])};
    std::ifstream f(argv[3],std::ios::binary);if(!f)return 2;
    std::vector<uint8_t> bytes((std::istreambuf_iterator<char>(f)),{});
    csh h[2]{};cs_opt_mem hooks{std::malloc,std::calloc,std::realloc,std::free,observed};
    for(int i=0;i<2;++i) {
        if(custom && api[i].option(0,CS_OPT_MEM,size_t(&hooks)))return 3;
        if(api[i].open(CS_ARCH_MIPS,CS_MODE_MIPS64,&h[i])||api[i].option(h[i],CS_OPT_DETAIL,CS_OPT_ON))return 4;
    }
    uint64_t total[2]{},all[2]{},valid=0,reject=0,ip=0x100000;size_t at=0;
    while(at<bytes.size()) {
        cs_insn a[2];cs_detail d[2];const uint8_t *ptr[2];size_t left[2];uint64_t addr[2];bool ok[2];
        std::memset(a,int(at&255),sizeof a);std::memset(d,int(at&255),sizeof d);
        for(int i=0;i<2;++i) {
            auto &v=a[i];v.illegal=v.is_alias=v.usesAliasDetails=false;v.detail=&d[i];
            ptr[i]=bytes.data()+at;left[i]=bytes.size()-at;addr[i]=ip;calls=pairs=0;
            ok[i]=api[i].iter(h[i],&ptr[i],&left[i],&addr[i],&v);
            total[i]+=pairs;all[i]+=calls;if(v.detail!=&d[i])return 5;v.detail=nullptr;
        }
        if(ok[0]!=ok[1]||ptr[0]!=ptr[1]||left[0]!=left[1]||addr[0]!=addr[1]||
           std::memcmp(&a[0],&a[1],sizeof a[0])||std::memcmp(&d[0],&d[1],sizeof d[0]))return 6;
        auto step=ok[0]?a[0].size:std::min<size_t>(4,bytes.size()-at);
        if(!step)return 7;
        if(ok[0])++valid;else ++reject;at+=step;ip+=step;
    }
    if(total[0]!=total[1]||all[0]!=all[1]||(custom && !total[0]))return 8;
    std::printf("%llu %llu %llu %llu\n",(unsigned long long)valid,(unsigned long long)reject,(unsigned long long)total[0],(unsigned long long)all[0]);
    return api[0].close(&h[0])||api[1].close(&h[1]);
}
