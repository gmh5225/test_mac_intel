#include <capstone/capstone.h>
#include <algorithm>
#include <cinttypes>
#include <cstdarg>
#include <cstdio>
#include <cstdlib>
#include <cstring>

#include <fstream>
#include <iterator>
#include <random>
#include <vector>

static uint64_t callbacks, callback_hash, record_hash, accepted, rejected;
static csh current;
static FILE *case_trace;
static unsigned suffixes;
static bool toggle, changed;
static void mix(uint64_t &hash,const void *p,size_t n) {
    const auto *v=static_cast<const unsigned char *>(p);
    for(size_t i=0;i<n;++i)hash=(hash^v[i])*UINT64_C(1099511628211);
}
static int CAPSTONE_API format(char *out,size_t size,const char *fmt,va_list args) {
    if(!std::strcmp(fmt,".%u%c") || !std::strcmp(fmt,".%c"))++suffixes;
    ++callbacks;mix(callback_hash,fmt,std::strlen(fmt)+1);
    int written=std::vsnprintf(out,size,fmt,args);
    if (written>=0 && size)mix(callback_hash,out,std::min(size-1,static_cast<size_t>(written)));
    if(toggle && !changed && current) {
        changed=true;
        if(cs_option(current,CS_OPT_DETAIL,CS_OPT_ON)!=CS_ERR_OK)std::abort();
    }
    return written;
}
static void set(cs_opt_type o,size_t v) {
    if(cs_option(current,o,v)!=CS_ERR_OK)std::abort();
}
static void next(const uint8_t **p,size_t *left,uint64_t *ip,bool storage) {
    cs_insn out{};
    cs_detail detail{};
    std::memset(&out,0xa5,sizeof out);out.detail=storage?&detail:nullptr;
    if(storage)std::memset(&detail,0x5a,sizeof detail);
    const bool ok=cs_disasm_iter(current,p,left,ip,&out);
    auto error=cs_errno(current);mix(record_hash,&error,sizeof error);
    mix(record_hash,&ok,sizeof ok);mix(record_hash,ip,sizeof(*ip));mix(record_hash,left,sizeof(*left));
    out.detail=nullptr;mix(record_hash,&out,sizeof out);
    if(storage)mix(record_hash,&detail,sizeof detail);
    if(ok)++accepted;else ++rejected;
}

int main(int argc,char **argv) {
    if(argc!=3 && argc!=6)return 3;
    if(const char *file=std::getenv("CS_CASE_TRACE"))case_trace=std::fopen(file,"w");
    const bool hooks=std::atoi(argv[2])!=0;
    if(hooks) {
        cs_opt_mem mem{std::malloc,std::calloc,std::realloc,std::free,format};
        if(cs_option(0,CS_OPT_MEM,reinterpret_cast<size_t>(&mem))!=CS_ERR_OK)return 4;
    }
    if(argc==6) {
        std::ifstream f(argv[3],std::ios::binary);
        const std::vector<uint8_t> bytes{std::istreambuf_iterator<char>(f),{}};
        if(bytes.empty()||cs_open(CS_ARCH_AARCH64,CS_MODE_LITTLE_ENDIAN,&current))return 5;
        const unsigned config=std::atoi(argv[5]);
        if(config)set(CS_OPT_DETAIL,config==1?CS_OPT_ON:config==2?CS_OPT_DETAIL_REAL:CS_OPT_ON|CS_OPT_DETAIL_REAL);
        uint64_t ip=std::strtoull(argv[4],nullptr,0);
        const uint8_t *p=bytes.data();size_t left=bytes.size();
        while(left){const size_t old=left;next(&p,&left,&ip,config!=0);if(left==old){++p;--left;++ip;}}
        cs_close(&current);
    } else {
        const cs_mode modes[]={CS_MODE_LITTLE_ENDIAN,CS_MODE_APPLE_PROPRIETARY};
        for(cs_mode mode:modes)for(unsigned big=0;big<2;++big) {
            if(cs_open(CS_ARCH_AARCH64,static_cast<cs_mode>(mode|(big?CS_MODE_BIG_ENDIAN:0)),&current))return 6;
            for(unsigned i=0;i<80;++i) {
                set(CS_OPT_SYNTAX,(i&1?CS_OPT_SYNTAX_NOREGNAME:0)|(i&2?CS_OPT_SYNTAX_NO_DOLLAR:0));
                set(CS_OPT_UNSIGNED,i&4?CS_OPT_ON:CS_OPT_OFF);
                set(CS_OPT_TEXT,(i&8)?CS_OPT_OFF:CS_OPT_ON);
                std::mt19937 rng(2026+i);
                for(unsigned n=0;n<160;++n) {
                    const unsigned config=i>>4;
                    set(CS_OPT_DETAIL,CS_OPT_OFF);
                    if(config>=1 && config<=3)set(CS_OPT_DETAIL,config==1?CS_OPT_ON:config==2?CS_OPT_DETAIL_REAL:CS_OPT_ON|CS_OPT_DETAIL_REAL);
                    toggle=hooks&&config==4;changed=false;
                    uint64_t raw=(uint64_t(rng())<<32)|rng();
                    uint8_t code[8];std::memcpy(code,&raw,sizeof code);
                    const uint32_t aliases[]={0xaa0103e0U,0xeb02003fU,0xd503201fU,0xd10003ffU,0xb24003e0U,0xd3407c20U};
                    if(n%4==0){ uint32_t word=aliases[(n/4)%6]; std::memcpy(code,&word,4); if(big)std::reverse(code,code+4); }
                    const uint8_t *ptr=code;size_t len=n%8+1;uint64_t ip=UINT64_C(0xfffffff8);
                    const unsigned before=suffixes;const uint64_t calls=callbacks;
                    next(&ptr,&len,&ip,config!=0);
                    if(case_trace && callbacks!=calls)std::fprintf(case_trace,"%u %u %u %u %016" PRIx64 " %u %u\n",unsigned(mode),big,i,n,raw,unsigned(callbacks-calls),suffixes-before);
                }
            }
            cs_close(&current);
        }
    }
    if(case_trace)std::fclose(case_trace);
    FILE *log=std::fopen(argv[1],"w");
    if(!log)return 7;
    std::fprintf(log,"{\"accepted\":%" PRIu64 ",\"rejected\":%" PRIu64 ",\"record_hash\":%" PRIu64
        ",\"callbacks\":%" PRIu64 ",\"callback_hash\":%" PRIu64 "}\n",
        accepted,rejected,record_hash,callbacks,callback_hash);
    return std::fclose(log)!=0;
}
