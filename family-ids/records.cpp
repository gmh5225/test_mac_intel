#include <capstone/capstone.h>
#include <dlfcn.h>
#include <algorithm>
#include <array>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <iterator>
#include <vector>

template<typename T> T sym(void *lib, const char *name) {
    auto fn=reinterpret_cast<T>(dlsym(lib,name));
    if(!fn) { std::fprintf(stderr,"missing %s\n", name); std::exit(2); }
    return fn;
}
struct Api {
    void *lib;
    decltype(&cs_open) open; decltype(&cs_option) option; decltype(&cs_disasm_iter) iter;
    decltype(&cs_errno) error; decltype(&cs_close) close;
    explicit Api(const char *path):lib(dlopen(path, RTLD_NOW|RTLD_LOCAL)),
      open(sym<decltype(open)>(lib,"cs_open")),option(sym<decltype(option)>(lib,"cs_option")),
      iter(sym<decltype(iter)>(lib,"cs_disasm_iter")),error(sym<decltype(error)>(lib,"cs_errno")),
      close(sym<decltype(close)>(lib,"cs_close")) {}
};
unsigned family(const uint8_t *data, size_t size) {
    while(size && (*data==0x26 || *data==0x2e || *data==0x36 || *data==0x3e ||
                  *data==0x64 || *data==0x65 || *data==0x67)) {++data; --size;}
    if(size<7 || data[0]!=0x62 || (data[1]&0xf)!=3 || (data[2]&7)!=5) return 0;
    bool wide=data[2]&128;
    switch(data[4]) {
      case 0x1e:return wide?X86_INS_VPCMPUQ:X86_INS_VPCMPUD;
      case 0x1f:return wide?X86_INS_VPCMPQ:X86_INS_VPCMPD;
      case 0x3e:return wide?X86_INS_VPCMPUW:X86_INS_VPCMPUB;
      case 0x3f:return wide?X86_INS_VPCMPW:X86_INS_VPCMPB;
    }
    return 0;
}
unsigned floating(const uint8_t *data,size_t size) {
    while(size && (*data==0x26 || *data==0x2e || *data==0x36 || *data==0x3e ||
                   *data==0x64 || *data==0x65 || *data==0x67)) {++data; --size;}
    unsigned pp;
    if(size>=5 && data[0]==0xc5 && data[2]==0xc2) pp=data[1]&3;
    else if(size>=6 && data[0]==0xc4 && (data[1]&31)==1 && data[3]==0xc2) pp=data[2]&3;
    else if(size>=7 && data[0]==0x62 && (data[1]&15)==1 && data[4]==0xc2) pp=data[2]&3;
    else return 0;
    static constexpr unsigned ids[]={X86_INS_VCMPPS,X86_INS_VCMPPD,X86_INS_VCMPSS,X86_INS_VCMPSD};
    return ids[pp];
}
struct Count { uint64_t calls=0, valid=0, corrected=0; };
struct Pair {
    const Api &a,&b;
    csh ah=0,bh=0;
    bool detail,diet;
    unsigned flags,bits;
    Count c;
    Pair(const Api &a,const Api &b,unsigned bits,unsigned flags,bool att,bool diet):a(a),b(b),detail(flags&2),diet(diet),flags(flags),bits(bits) {
        for(auto pair : {std::make_pair(&a,&ah),std::make_pair(&b,&bh)}) {
            auto [d,h]=pair;
            if(d->open(CS_ARCH_X86,bits==64?CS_MODE_64:CS_MODE_32,h)||
               d->option(*h,CS_OPT_TEXT,(flags&1)?CS_OPT_ON:CS_OPT_OFF)||
               d->option(*h,CS_OPT_DETAIL,detail?(CS_OPT_ON|CS_OPT_DETAIL_REAL):CS_OPT_OFF)||
               d->option(*h,CS_OPT_SYNTAX,att?CS_OPT_SYNTAX_ATT:CS_OPT_SYNTAX_INTEL)) std::exit(3);
        }
    }
    ~Pair(){a.close(&ah);b.close(&bh);}
    size_t decode(const uint8_t *start,size_t n,uint64_t ip,unsigned required=0) {
        ++c.calls;
        const uint8_t *l=start,*r=start;size_t ls=n,rs=n;uint64_t li=ip,ri=ip;
        cs_insn x,y;cs_detail xd,yd;
        std::memset(&x,0x5a,sizeof x); std::memset(&y,0x5a,sizeof y);
        std::memset(&xd,0x5a,sizeof xd);std::memset(&yd,0x5a,sizeof yd);
        x.is_alias=x.usesAliasDetails=x.illegal=y.is_alias=y.usesAliasDetails=y.illegal=false;
        x.detail=detail?&xd:nullptr;y.detail=detail?&yd:nullptr;
        bool ok=a.iter(ah,&l,&ls,&li,&x),ok2=b.iter(bh,&r,&rs,&ri,&y);
        bool same=ok==ok2 && l==r && ls==rs && li==ri && a.error(ah)==b.error(bh);
        if(ok) ++c.valid;
        (void)required;
        same &= x.detail==(detail?&xd:nullptr) && y.detail==(detail?&yd:nullptr);
        unsigned before=x.id;
        x.detail=nullptr;y.detail=nullptr;
        if(!same||std::memcmp(&x,&y,sizeof x)||std::memcmp(&xd,&yd,sizeof xd)){
            std::fprintf(stderr,"record mismatch ip=%llx len=%zu bits=%u flags=%u old/new=%u/%u valid=%u/%u required=%u:",(unsigned long long)ip,n,bits,flags,before,y.id,ok,ok2,required);
            for(size_t i=0;i<std::min<size_t>(n,15);++i) std::fprintf(stderr," %02x",start[i]);
            auto dump=[](const char *name,const void *one,const void *two,size_t n) {
              auto l=(const uint8_t*)one,r=(const uint8_t*)two;unsigned k=0;
              for(size_t i=0;i<n && k<12;++i) if(l[i]!=r[i]){std::fprintf(stderr," %s[%zu]=%02x/%02x",name,i,l[i],r[i]);++k;}
            };
            dump("insn",&x,&y,sizeof x);dump("detail",&xd,&yd,sizeof xd);
            std::fprintf(stderr,"\n");std::exit(1);
        }
        return ok?n-ls:0;
    }
};
void matrix(Pair &p) {
    for(uint8_t op:{0x1e,0x1f,0x3e,0x3f})for(int w:{0,128})for(int ll:{8,40,72})for(int mask:{0,3})
      for(auto m:std::array<std::vector<uint8_t>,4>{{{0xcb},{0xb},{0x4c,0x54,0x7f},{0xd,0x72,0xaf,0x34,0}}})
        for(int bc:{0,16}){
          if(bc && (op>=0x30 || m[0]>=0xc0))continue;
          std::vector<uint8_t> s={0x62,0xf3,uint8_t(0x6d|w),uint8_t(ll|mask|bc),op};
          s.insert(s.end(),m.begin(),m.end());s.push_back(0);
          for(unsigned imm=0;imm<256;++imm) {
              s.back()=imm;p.decode(s.data(),s.size(),0x1000,family(s.data(),s.size()));
          }
          for(size_t n=0;n<s.size();++n)p.decode(s.data(),n,0x1000);
        }
}
void float_matrix(Pair &p) {
    for(unsigned prefix: {2,3,4}) for(unsigned pp=0;pp<4;++pp)
      for(unsigned l=0;l<(pp>=2 ? 1u : (prefix==4 ? 3u:2u));++l)
       for(unsigned mask=0;mask<(prefix==4?2u:1u);++mask)
        for(auto m:std::array<std::vector<uint8_t>,4>{{{0xcb},{0xb},{0x4c,0x54,0x7f},{0xd,0x72,0xaf,0x34,0}}}){
          std::vector<uint8_t> s;
          if(prefix==2)s={0xc5,uint8_t(0xe8 | (l<<2) | pp)};
          if(prefix==3)s={0xc4,0xe1,uint8_t(0x68 | (l<<2) | pp)};
          if(prefix==4)s={0x62,0xf1,uint8_t(0x6c | ((pp&1)<<7) | pp),uint8_t(8 | (l<<5) | (mask?3:0))};
          s.push_back(0xc2);s.insert(s.end(),m.begin(),m.end());s.push_back(0);
          for(unsigned i=0;i<256;++i){s.back()=i;p.decode(s.data(),s.size(),0x1000,floating(s.data(),s.size()));}
          for(size_t n=0;n<s.size();++n)p.decode(s.data(),n,0x1000);
        }
}
int main(int argc,char **argv) {
    if(argc!=8)return 2;
    Api a(argv[1]),b(argv[2]);unsigned bits=std::stoul(argv[3]);
    bool generated=std::strcmp(argv[4],"matrix")==0;uint64_t ip=std::stoull(argv[5],nullptr,0);
    bool att=std::atoi(argv[6]);bool diet=std::atoi(argv[7]);std::vector<uint8_t> bytes;
    if(!generated){std::ifstream f(argv[4],std::ios::binary);if(!f)return 2;bytes.assign(std::istreambuf_iterator<char>(f),{});}
    for(unsigned flags=0;flags<(diet?2:4);++flags){
        Pair p(a,b,bits,flags,att,diet);
        if(generated){matrix(p);float_matrix(p);}else for(size_t k=0;k<bytes.size();){
            auto n=p.decode(bytes.data()+k,bytes.size()-k,ip+k);k+=n?n:1;
        }
        std::printf("%u %u %u %llu %llu %llu\n",bits,flags,att,(unsigned long long)p.c.calls,(unsigned long long)p.c.valid,(unsigned long long)p.c.corrected);
    }
}
