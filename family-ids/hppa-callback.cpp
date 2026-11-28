#include <capstone/capstone.h>
#include <array>
#include <cstdarg>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <dlfcn.h>

struct Api {
    void *lib;
    decltype(&cs_open) open;
    decltype(&cs_close) close;
    decltype(&cs_option) option;
    decltype(&cs_disasm_iter) iter;
    explicit Api(const char *path) : lib(dlopen(path,RTLD_NOW|RTLD_LOCAL)),
        open((decltype(open))dlsym(lib,"cs_open")),close((decltype(close))dlsym(lib,"cs_close")),
        option((decltype(option))dlsym(lib,"cs_option")),iter((decltype(iter))dlsym(lib,"cs_disasm_iter")) {}
};
static Api *active;
static cs_opt_mem memory{malloc,calloc,realloc,free,vsnprintf};
static int behavior;
static unsigned calls;
static int custom(char *out,size_t n,const char *fmt,va_list args) {
    ++calls;
    int result=vsnprintf(out,n,fmt,args);
    if (behavior==2 && result>1 && n>1) out[1]='\0';
    if (behavior==3 && result>1) return 1;
    if (behavior==4) return -1;
    if (behavior==5) {
        memory.vsnprintf=vsnprintf;
        if (active->option(0,CS_OPT_MEM,(size_t)&memory)!=CS_ERR_OK) std::abort();
    }
    return result;
}
struct Observation {
    cs_insn insn;
    cs_detail detail;
    bool ok;
    size_t consumed,left;
    uint64_t ip;
    unsigned callbacks;
};
int main(int argc,char **argv) {
    if(argc!=3) return 1;
    Api a(argv[1]),b(argv[2]);
    if(!a.lib||!b.lib) return 2;
    const std::array<std::array<uint8_t,4>,4> inputs{{
        {0x34,0x22,0x3f,0xf1}, {0x23,0x98,0xc5,0x4f},
        {0x2b,0x98,0xc5,0x4f}, {0x18,0x84,0x29,0x06}}};
    unsigned total=0,seen[6]={};
    for(int kind=0;kind<6;++kind)for(bool detail:{false,true})for(bool un:{false,true})for(bool skip:{false,true})for(auto &bytes:inputs) {
        auto observe=[&](Api &api,Observation &v) {
            active=&api;behavior=kind;calls=0;memory.vsnprintf=kind?custom:vsnprintf;
            if(api.option(0,CS_OPT_MEM,(size_t)&memory))std::abort();
            csh h=0;if(api.open(CS_ARCH_HPPA,cs_mode(CS_MODE_HPPA_20|CS_MODE_BIG_ENDIAN),&h)||
               api.option(h,CS_OPT_DETAIL,detail?CS_OPT_ON:CS_OPT_OFF)||
               api.option(h,CS_OPT_UNSIGNED,un?CS_OPT_ON:CS_OPT_OFF)||
               api.option(h,CS_OPT_SKIPDATA,skip?CS_OPT_ON:CS_OPT_OFF))std::abort();
            std::memset(&v.insn,0x5a,sizeof(v.insn));std::memset(&v.detail,0xa5,sizeof(v.detail));
            v.insn.is_alias=v.insn.usesAliasDetails=v.insn.illegal=false;v.insn.alias_id=0;
            v.insn.detail=detail?&v.detail:nullptr;
            const uint8_t *ptr=bytes.data();v.left=bytes.size();v.ip=0x100080;
            v.ok=api.iter(h,&ptr,&v.left,&v.ip,&v.insn);v.callbacks=calls;
            if(v.insn.detail!=(detail?&v.detail:nullptr))std::abort();v.insn.detail=nullptr;
            v.consumed=size_t(ptr-bytes.data());
            if(api.close(&h))std::abort();memory.vsnprintf=vsnprintf;
            if(api.option(0,CS_OPT_MEM,(size_t)&memory))std::abort();
        };
        Observation x,y;observe(a,x);observe(b,y);
        if(!x.ok||!y.ok||x.callbacks!=y.callbacks||x.consumed!=y.consumed||
           x.left!=y.left||x.ip!=y.ip||std::memcmp(&x.insn,&y.insn,sizeof(x.insn))||
           std::memcmp(&x.detail,&y.detail,sizeof(x.detail))) return 3;
        seen[kind]+=x.callbacks;++total;
    }
    for(int i=1;i<6;++i) if(!seen[i])return 4;
    std::printf("%u complete formatter and option records\n",total);
    return 0;
}
