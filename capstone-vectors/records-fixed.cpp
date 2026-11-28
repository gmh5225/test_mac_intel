#include <capstone/capstone.h>
#include <dlfcn.h>
#include <fstream>
#include <iterator>
#include <vector>
#include <cstdio>
#include <cstring>
#include <cinttypes>

struct API {
  void *lib;
  decltype(&cs_open) open;
  decltype(&cs_close) close;
  decltype(&cs_malloc) alloc;
  decltype(&cs_free) release;
  decltype(&cs_option) option;
  decltype(&cs_disasm_iter) next;
  decltype(&cs_regs_access) regs;
  explicit API(const char *path) : lib(dlopen(path,RTLD_LOCAL|RTLD_NOW)) {
    if(!lib) {std::fprintf(stderr,"%s\n",dlerror());std::exit(20);}
#define CS_FN(dst, name) if(!(dst = reinterpret_cast<decltype(dst)>(dlsym(lib, std::strcmp(#name,"cs_disasm_iter")==0?"measure_fixed_iterator":#name)))) std::exit(21)
    CS_FN(open,cs_open); CS_FN(close,cs_close); CS_FN(alloc,cs_malloc);
    CS_FN(release,cs_free); CS_FN(option,cs_option); CS_FN(next,cs_disasm_iter); CS_FN(regs,cs_regs_access);
#undef CS_FN
  }
};
int main(int argc,char **argv) {
  if(argc!=6)return 2;
  API a(argv[1]),b(argv[2]); if(a.next==b.next)return 3;
  std::ifstream input(argv[3],std::ios::binary);
  std::vector<unsigned char> data((std::istreambuf_iterator<char>(input)),{});
  int bits=std::atoi(argv[5]);cs_mode mode=bits==32?CS_MODE_32:CS_MODE_64;
  uint64_t stats[4][2]={}, changes[4][3]={};
  for(unsigned config=0;config<4;++config){
    std::ifstream ranges(argv[4]);
    csh l{},r{};bool detail=config&1;int syntax=config&2?CS_OPT_SYNTAX_ATT:CS_OPT_SYNTAX_INTEL;
    if(a.open(CS_ARCH_X86,mode,&l)||b.open(CS_ARCH_X86,mode,&r))return 4;
    for(auto pair:{std::make_pair(&a,l),std::make_pair(&b,r)})if(pair.first->option(pair.second,CS_OPT_DETAIL,detail?CS_OPT_ON:CS_OPT_OFF)||pair.first->option(pair.second,CS_OPT_SYNTAX,syntax))return 5;
    cs_insn *x=a.alloc(l),*y=b.alloc(r);if(!x||!y)return 6;
    size_t start,n;uint64_t ip;
    while(ranges>>start>>n>>ip){
      if(start>data.size()||n>data.size()-start)return 7;
      const uint8_t *p=data.data()+start,*q=p;size_t remain=n;uint64_t pc=ip;
      while(n){
        auto *dx=x->detail,*dy=y->detail;
        std::memset(x,0xa5,sizeof(*x));x->usesAliasDetails=x->is_alias=x->illegal=false;
        std::memcpy(y,x,sizeof(*x));x->detail=dx;y->detail=dy;
        if(detail){std::memset(dx,0xa5,sizeof(*dx));std::memcpy(dy,dx,sizeof(*dx));}
        auto old=p;bool ok=a.next(l,&p,&n,&ip,x);
        if(b.next(r,&q,&remain,&pc,y)!=ok || p!=q || n!=remain || ip!=pc)return 8;
        x->detail=y->detail=nullptr;
        if(std::memcmp(x,y,sizeof(*x)) || (detail && std::memcmp(dx,dy,sizeof(*dx)))){
          std::fprintf(stderr,"record mismatch at offset %zu config %u\n",size_t(old-data.data()),config);return 9;}
        x->detail=dx;y->detail=dy;
        if(ok && detail){
          cs_regs ar{},aw{},br{},bw{}; uint8_t nr=0,nw=0,mr=0,mw=0;
          if(a.regs(l,x,ar,&nr,aw,&nw)!=b.regs(r,y,br,&mr,bw,&mw) || nw!=mw || std::memcmp(aw,bw,sizeof(aw)))return 10;
          cs_regs expected{};
          unsigned kept=0;
          const auto &detail=*dx;
          for(unsigned i=0;i<nr;++i){
            bool memory_segment=false,seen=false;
            for(unsigned j=0;j<detail.x86.op_count;++j){
              const auto &op=detail.x86.operands[j];
              memory_segment|=op.type==X86_OP_MEM && op.mem.segment!=X86_REG_INVALID && op.mem.segment==ar[i];
            }
            for(unsigned j=0;j<kept;++j)seen|=expected[j]==ar[i];
            if(i>=detail.regs_read_count && memory_segment && seen)continue;
            expected[kept++]=ar[i];
          }
          if(kept!=mr || std::memcmp(expected,br,sizeof(br)))return 11;
          changes[config][0]+=kept!=nr;changes[config][1]+=nr-kept;changes[config][2]+=detail.x86.op_count;

        }
        ++stats[config][ok];
        if(!ok){if(p!=old || !n)return 11;++p;++q;--n;--remain;++ip;++pc;}
        else if(p<=old)return 12;
      }
    }
    if(!ranges.eof()||!stats[config][1])return 13;
    a.release(x,1); b.release(y,1); a.close(&l); b.close(&r);
  }
  for(const auto &s:changes)std::printf("%" PRIu64 " %" PRIu64 " %" PRIu64 "\n",s[0],s[1],s[2]);
  for(const auto &s:stats)std::printf("%" PRIu64 " %" PRIu64 "\n",s[0],s[1]);
}
