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
#define CS_FN(dst, name) if(!(dst = reinterpret_cast<decltype(dst)>(dlsym(lib,#name)))) std::exit(21)
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
  uint64_t changes[4][3]={},stats[4][2]={};
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
        if(std::memcmp(x,y,sizeof(*x)))return 9;
        x->detail=dx;y->detail=dy;
        if(detail) {
          unsigned op=dy->x86.opcode[0];
          bool src=op==0x6e||op==0x6f||(op>=0xa4&&op<=0xa7)||op==0xac||op==0xad;
          bool dest=op==0x6c||op==0x6d||(op>=0xa4&&op<=0xa7)||op==0xaa||op==0xab||op==0xae||op==0xaf;
          bool string=ok&&(src||dest);
          auto segment=[](uint16_t v){return v==X86_REG_ES||v==X86_REG_CS||v==X86_REG_SS||v==X86_REG_DS||v==X86_REG_FS||v==X86_REG_GS;};
          auto tracked=[&](uint16_t v){return segment(v)||v==X86_REG_SI||v==X86_REG_ESI||v==X86_REG_RSI||v==X86_REG_DI||v==X86_REG_EDI||v==X86_REG_RDI||v==X86_REG_CX||v==X86_REG_ECX||v==X86_REG_RCX;};
          auto rest=[&](const uint16_t *z,unsigned n){std::vector<uint16_t> v;for(unsigned i=0;i<n;i++)if(!tracked(z[i]))v.push_back(z[i]);return v;};
          if(std::memcmp(dx,dy,sizeof(*dx))) {
            if(!string)return 17;
            if(rest(dx->regs_read,dx->regs_read_count)!=rest(dy->regs_read,dy->regs_read_count)||rest(dx->regs_write,dx->regs_write_count)!=rest(dy->regs_write,dy->regs_write_count))return 18;
            cs_detail temp=*dx;
            std::memcpy(temp.regs_read,dy->regs_read,sizeof(temp.regs_read));temp.regs_read_count=dy->regs_read_count;
            std::memcpy(temp.regs_write,dy->regs_write,sizeof(temp.regs_write));temp.regs_write_count=dy->regs_write_count;
            if(std::memcmp(&temp,dy,sizeof(temp)))return 19;
            ++changes[config][0];
          }
          if(ok){
            cs_regs ar{},aw{},br{},bw{};uint8_t nr=0,nw=0,mr=0,mw=0;
            if(a.regs(l,x,ar,&nr,aw,&nw)||b.regs(r,y,br,&mr,bw,&mw))return 20;
            if(string) {
              ++changes[config][2];unsigned width=dy->x86.addr_size;
              x86_reg si=width==2?X86_REG_SI:width==4?X86_REG_ESI:X86_REG_RSI,di=width==2?X86_REG_DI:width==4?X86_REG_EDI:X86_REG_RDI,cx=width==2?X86_REG_CX:width==4?X86_REG_ECX:X86_REG_RCX;
              unsigned seg=dy->x86.prefix[1];x86_reg selection=seg==0x64?X86_REG_FS:seg==0x65?X86_REG_GS:bits==64?X86_REG_INVALID:seg==0x26?X86_REG_ES:seg==0x2e?X86_REG_CS:seg==0x36?X86_REG_SS:X86_REG_DS;
              for(unsigned v=1;v<X86_REG_ENDING;v++){
                if(!tracked(v))continue;
                bool idx=(src&&v==si)||(dest&&v==di)||((dy->x86.prefix[0]==0xf2||dy->x86.prefix[0]==0xf3)&&v==cx);
                bool sreg=(src&&v==selection)||(bits!=64&&dest&&v==X86_REG_ES);
                unsigned rd=0,wr=0;for(unsigned j=0;j<mr;j++)rd+=br[j]==v;for(unsigned j=0;j<mw;j++)wr+=bw[j]==v;
                if(rd!=unsigned(idx||sreg)||wr!=unsigned(idx)){std::fprintf(stderr,"access mismatch offset=%zu bits=%d reg=%u %s %s\n",size_t(old-data.data()),bits,v,y->mnemonic,y->op_str);return 21;}
              }
              if(rest(ar,nr)!=rest(br,mr)||rest(aw,nw)!=rest(bw,mw))return 22;
            }else{
              std::vector<uint16_t> expected;
              for(unsigned i=0;i<nr;i++){bool seen=false;for(auto n:expected)seen|=n==ar[i];if(!segment(ar[i])||!seen)expected.push_back(ar[i]);}
              if(expected!=std::vector<uint16_t>(br,br+mr)||nw!=mw||std::memcmp(aw,bw,sizeof(aw)))return 23;
            }
            if(nr!=mr||nw!=mw||std::memcmp(ar,br,sizeof(ar))||std::memcmp(aw,bw,sizeof(aw)))++changes[config][1];
          }
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
