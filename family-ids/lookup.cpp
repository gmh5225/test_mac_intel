#include <capstone/capstone.h>
#include <array>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <dlfcn.h>
#include <limits>

template<class F> F symbol(void *handle,const char *name) {
    auto result=dlsym(handle,name);
    if(!result){std::fprintf(stderr,"%s\n",dlerror());std::exit(2);}
    return reinterpret_cast<F>(result);
}
struct Library {
    void *lib; decltype(&cs_open) open; decltype(&cs_close) close;
    unsigned (*count)();
    int (*access)(csh,unsigned,uint64_t *,uint8_t *);
    explicit Library(const char *path):lib(dlopen(path,RTLD_NOW|RTLD_LOCAL)),
      open(symbol<decltype(open)>(lib,"cs_open")),close(symbol<decltype(close)>(lib,"cs_close")),
      count(symbol<decltype(count)>(lib,"capstone_bench_access_count")),
      access(symbol<decltype(access)>(lib,"capstone_bench_access")) {}
};
int main(int argc,char **argv) {
    if(argc!=3)return 2;
    Library a(argv[1]),b(argv[2]);
    unsigned end=a.count(),checked=0,active=0,missing=0;
    if(!end||end!=b.count())return 3;
    csh lhs{},rhs{};
    for(cs_mode mode:{CS_MODE_16,CS_MODE_32,CS_MODE_64}){
        if(a.open(CS_ARCH_X86,mode,&lhs)||b.open(CS_ARCH_X86,mode,&rhs))return 4;
        for(bool cached:{false,true}){
            for(unsigned n=0;n<=end+2;++n){
                unsigned id=n==end+2?std::numeric_limits<unsigned>::max():n;
                std::array<uint8_t,15> x,y;x.fill(0xa5);y=x;
                uint64_t fx=0x853249170001abcdULL,fy=fx;
                int ok=a.access(cached?lhs:0,id,&fx,x.data()),ok2=b.access(cached?rhs:0,id,&fy,y.data());
                if(ok!=ok2 || x!=y || fx!=fy){std::fprintf(stderr,"mode %u cached %d id %u\n",unsigned(mode),int(cached),id);return 5;}
                ++checked;if(ok)++active;else ++missing;
            }
        }
        a.close(&lhs);b.close(&rhs);
    }
    std::printf("{\"ids\":%u,\"checked\":%u,\"present\":%u,\"absent\":%u}\n",end,checked,active,missing);
}
