#include <capstone/capstone.h>
#include <algorithm>
#include <array>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <dlfcn.h>
#include <fstream>
#include <iterator>
#include <vector>

struct Library {
    void *lib;
    decltype(&cs_disasm_iter) decode;
    decltype(&cs_free) release;
    decltype(&cs_close) close;
    csh handle = 0;
    cs_insn *insn;
    template <class T> T symbol(const char *name) {
        auto p = reinterpret_cast<T>(dlsym(lib, name)); if (!p) std::abort(); return p;
    }
    Library(const char *path, cs_mode mode) : lib(dlopen(path, RTLD_LOCAL | RTLD_NOW)) {
        if (!lib) std::abort();
        decode = symbol<decltype(decode)>("cs_disasm_iter");
        release = symbol<decltype(release)>("cs_free");
        close = symbol<decltype(close)>("cs_close");
        if (symbol<decltype(&cs_open)>("cs_open")(CS_ARCH_X86,mode,&handle) ||
            symbol<decltype(&cs_option)>("cs_option")(handle,CS_OPT_DETAIL,CS_OPT_ON|CS_OPT_DETAIL_REAL))
            std::abort();
        insn = symbol<decltype(&cs_malloc)>("cs_malloc")(handle);
        if (!insn || !insn->detail) std::abort();
    }
    ~Library() { release(insn,1); close(&handle); dlclose(lib); }
    bool run(const uint8_t *code, size_t size, uint64_t ip) {
        auto *saved = insn->detail;
        std::memset(insn,0,sizeof(*insn));std::memset(saved,0,sizeof(*saved));insn->detail=saved;
        return decode(handle,&code,&size,&ip,insn);
    }
};
struct Audit {
    Library full,before,after;
    uint64_t calls=0,ok=0,bc=0,sz=0,ids=0;
    Audit(char **lib, cs_mode mode):full(lib[0],mode),before(lib[1],mode),after(lib[2],mode) {}
    size_t check(const uint8_t *code,size_t len,uint64_t ip) {
        ++calls;bool x=before.run(code,len,ip),y=after.run(code,len,ip);
        auto a=before.insn,b=after.insn;
        auto fail=[&](const char *where,int operand=-1){
            std::fprintf(stderr,"%s operand=%d id=%u bytes=",where,operand,a->id);
            for(size_t j=0;j<std::min(len,size_t(15));++j)std::fprintf(stderr,"%02x",code[j]);
            if(operand>=0){auto &o=a->detail->x86.operands[operand],&n=b->detail->x86.operands[operand],&f=full.insn->detail->x86.operands[operand];std::fprintf(stderr," old/new/ref b=%u/%u/%u size=%u/%u/%u type=%u/%u/%u",o.avx_bcast,n.avx_bcast,f.avx_bcast,o.size,n.size,f.size,o.type,n.type,f.type);}
            std::fputc('\n',stderr);std::exit(4);
        };
        if(x!=y)fail("acceptance");
        if(!x)return 0;
        ++ok;
        if(a->id!=b->id){
            if(!full.run(code,len,ip)||full.insn->size!=b->size||full.insn->id!=b->id)fail("reference public ID");
            switch(b->id){
            case X86_INS_VPCMPB:case X86_INS_VPCMPD:case X86_INS_VPCMPQ:case X86_INS_VPCMPW:
            case X86_INS_VPCMPUB:case X86_INS_VPCMPUD:case X86_INS_VPCMPUQ:case X86_INS_VPCMPUW:break;
            default:fail("unrelated public ID");
            }
            a->id=b->id;++ids;
        }
        if(std::memcmp(a,b,offsetof(cs_insn,detail))||a->id!=b->id||a->size!=b->size)fail("instruction");
        if(!std::memcmp(a->detail,b->detail,sizeof(cs_detail)))return a->size;
        if(!full.run(code,len,ip)||full.insn->size!=a->size||full.insn->id!=a->id)fail("reference");
        auto &newx=b->detail->x86;auto &fx=full.insn->detail->x86;
        if(fx.op_count!=newx.op_count||a->detail->x86.op_count!=newx.op_count)fail("count");
        for(unsigned i=0;i<newx.op_count;++i){
            auto &o=a->detail->x86.operands[i];const auto &n=newx.operands[i], &f=fx.operands[i];
            if(o.avx_bcast!=n.avx_bcast){
                if(n.type!=X86_OP_MEM||f.type!=n.type||f.avx_bcast!=n.avx_bcast)fail("broadcast",i);
                o.avx_bcast=n.avx_bcast;++bc;
            }
            if(o.size!=n.size){
                if(n.type!=X86_OP_REG||n.reg<X86_REG_K0||n.reg>X86_REG_K7||f.type!=n.type||f.reg!=n.reg||f.size!=n.size)fail("mask",i);
                o.size=n.size;++sz;
            }
        }
        if(std::memcmp(a->detail,b->detail,sizeof(cs_detail)))fail("unrelated detail");
        return a->size;
    }
};
int main(int argc,char **argv) {
    if(argc<5)return 2;
    Audit s(argv+1,std::atoi(argv[4])==32?CS_MODE_32:CS_MODE_64);
    if(argc>5) {
        for(int i=5;i<argc;++i){
            std::ifstream f(argv[i],std::ios::binary);std::vector<uint8_t>b((std::istreambuf_iterator<char>(f)),{});
            if(b.empty())return 2;
            for(size_t off=0;off<b.size();){auto n=s.check(b.data()+off,b.size()-off,0x401000+off);off+=std::max(n,size_t(1));}
        }
    } else {
        uint8_t b[15]={0x62,0,0,0,0,0,0x24,0x80,0,0,0,0x11,0xc0,0,0};
        for(unsigned map:{1u,2u,3u,5u,6u})for(unsigned pp=0;pp<4;++pp)
        for(unsigned w=0;w<2;++w)for(unsigned ll=0;ll<4;++ll)for(unsigned bc=0;bc<2;++bc)
        for(unsigned aaa:{0u,1u,3u})for(unsigned z=0;z<2;++z)for(unsigned op=0;op<256;++op)
        for(unsigned mod:{0x00u,0x48u,0x84u,0xc1u,0xffu}){
            b[1]=0xf0|map;b[2]=(w<<7)|0x7c|pp;b[3]=(z<<7)|(ll<<5)|(bc<<4)|8|aaa;b[4]=op;b[5]=mod;
            s.check(b,sizeof(b),UINT64_MAX-4);
        }
        // RIP-relative broadcast with an encoded NLE predicate in glibc libmvec.
        const uint8_t libc_compare[]={0x62,0xf3,0x75,0x58,0x1f,0x0d,0x80,0x74,0x0c,0x00,0x06};
        s.check(libc_compare,sizeof(libc_compare),0x401000);
        // Signed/unsigned byte, word, dword and qword compare forms. The
        // predicate is always in the final byte for these register/base forms.
        for(unsigned op:{0x1eu,0x1fu,0x3eu,0x3fu})for(unsigned w=0;w<=1;++w)
        for(unsigned ll=0;ll<=3;++ll)for(unsigned k:{0u,2u})for(unsigned bc=0;bc<2;++bc)
        for(unsigned mod:{0xcbu,0x08u})for(unsigned pred=0;pred<256;++pred){
            uint8_t c[]={0x62,0xf3,uint8_t((w<<7)|0x6d),uint8_t((ll<<5)|(bc<<4)|8|k),uint8_t(op),uint8_t(mod),uint8_t(pred)};
            s.check(c,sizeof(c),0x401000);
        }

    }
    std::printf("%llu %llu %llu %llu %llu\n",(unsigned long long)s.calls,(unsigned long long)s.ok,(unsigned long long)s.bc,(unsigned long long)s.sz,(unsigned long long)s.ids);
}
