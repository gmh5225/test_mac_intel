#include <capstone/capstone.h>
#include <dlfcn.h>
#include <sys/mman.h>
#include <unistd.h>
#include <algorithm>
#include <array>
#include <cinttypes>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <fstream>
#include <iterator>
#include <random>
#include <string>
#include <vector>

[[noreturn]] static void fail(const char *why) {
  std::fprintf(stderr, "%s\n", why);
  std::exit(1);
}
static void check(bool condition, const char *why) { if (!condition) fail(why); }
struct Api {
  void *so;
  template<class T> T sym(const char *n) { void *fp = dlsym(so, n); check(fp, n); return reinterpret_cast<T>(fp); }
  decltype(&cs_open) open;
  decltype(&cs_close) close;
  decltype(&cs_option) option;
  decltype(&cs_disasm) disasm;
  decltype(&cs_disasm_iter) next;
  decltype(&cs_malloc) alloc;
  decltype(&cs_free) free;
  decltype(&cs_errno) error;
  decltype(&cs_regs_access) regs;
  explicit Api(const char *file) : so(dlopen(file, RTLD_NOW | RTLD_LOCAL)),
      open(sym<decltype(open)>("cs_open")), close(sym<decltype(close)>("cs_close")),
      option(sym<decltype(option)>("cs_option")),disasm(sym<decltype(disasm)>("cs_disasm")),
      next(sym<decltype(next)>("cs_disasm_iter")),alloc(sym<decltype(alloc)>("cs_malloc")),
      free(sym<decltype(free)>("cs_free")),error(sym<decltype(error)>("cs_errno")),
      regs(sym<decltype(regs)>("cs_regs_access")) { check(so, file); }
};
struct Session {
  Api &api;
  csh h{};
  Session(Api &a, cs_arch arch, cs_mode mode) : api(a) { check(!api.open(arch,mode,&h),"open"); }
  void set(cs_opt_type opt, size_t v) { check(!api.option(h,opt,v),"option"); }
  ~Session() { if (h) api.close(&h); }
};
struct Result {
  Session &s;
  cs_insn *a{};
  size_t n;
  Result(Session &session,const uint8_t *p,size_t l,uint64_t ip,size_t count) : s(session),n(s.api.disasm(s.h,p,l,ip,count,&a)) {}
  ~Result() { if(a) s.api.free(a,n); }
  Result(const Result &) = delete;
};
static uint64_t total_records=0, total_batches=0;
static size_t compare(Session &l,Session &r,const uint8_t *p,size_t n,uint64_t ip,size_t count) {
  Result a(l,p,n,ip,count), b(r,p,n,ip,count);
  check(a.n==b.n&&l.api.error(l.h)==r.api.error(r.h)&&(!a.a==!b.a),"batch count/error");
  ++total_batches;
  size_t used=0;
  for(size_t i=0;i<a.n;++i) {
    const cs_insn &ai=a.a[i], &bi=b.a[i];
    cs_insn flat;std::memcpy(&flat,&ai,sizeof flat);flat.detail=bi.detail;
    if(std::memcmp(&flat,&bi,sizeof flat)||(!ai.detail!=!bi.detail)||
       (ai.detail&&std::memcmp(ai.detail,bi.detail,sizeof(cs_detail)))) {
      std::fprintf(stderr,"record differs at %" PRIx64 " batch=%zu index=%zu ID=%u/%u %s/%s %s/%s\n",ai.address,count,i,ai.id,bi.id,ai.mnemonic,bi.mnemonic,ai.op_str,bi.op_str);
      std::exit(1);
    }
    if(ai.detail&&ai.id) {
      cs_regs lr{},lw{},rr{},rw{};uint8_t nr=0,nw=0,br=0,bw=0;
      const auto le=l.api.regs(l.h,&ai,lr,&nr,lw,&nw),re=r.api.regs(r.h,&bi,rr,&br,rw,&bw);
      check(le==re&&nr==br&&nw==bw&&!std::memcmp(lr,rr,nr*sizeof(lr[0]))&&!std::memcmp(lw,rw,nw*sizeof(lw[0])),"registers");
    }
    check(ai.size,"zero length");used+=ai.size;++total_records;
  }
  return used;
}
static uint64_t clk(clockid_t type) { timespec t{};check(!clock_gettime(type,&t),"clock");return uint64_t(t.tv_sec)*1000000000+t.tv_nsec; }
static uint64_t visit(Session &s,const std::vector<uint8_t> &bytes,uint64_t ip,int mode,size_t stride,size_t &accepted) {
  uint64_t res=0;accepted=0;
  for(size_t off=0;off<bytes.size();) {
    Result a(s,bytes.data()+off,bytes.size()-off,ip+off,64);
    if(!a.n){off+=std::min(stride,bytes.size()-off);continue;}
    accepted+=a.n;
    for(size_t i=0;i<a.n;++i) {
      auto &x=a.a[i];off+=x.size;res+=x.id+x.size;
      if(mode) res+=std::strlen(x.mnemonic)+std::strlen(x.op_str);
      if(mode==2) {res+=x.detail->ppc.op_count+x.detail->regs_read_count+x.detail->regs_write_count;}
    }
  }
  return res;
}
static uint64_t iter_work(Session &s,const std::vector<uint8_t> &bytes,uint64_t ip,int mode,size_t stride,size_t &seen) {
  cs_insn *record=s.api.alloc(s.h);check(record,"alloc");const uint8_t *p=bytes.data();size_t n=bytes.size();seen=0;uint64_t sum=0;
  while(n) {
    if(!s.api.next(s.h,&p,&n,&ip,record)){size_t skip=std::min(stride,n);p+=skip;ip+=skip;n-=skip;continue;}
    ++seen;sum+=record->id+record->size;
    if(mode)sum+=std::strlen(record->mnemonic)+std::strlen(record->op_str);
    if(mode==2){sum+=record->detail->ppc.op_count+record->detail->regs_read_count+record->detail->regs_write_count;}
  }
  s.api.free(record,1);return sum;
}
static void verify_iter(Session &a,Session &b,const std::vector<uint8_t> &bytes,uint64_t ip,int mode,size_t stride) {
  const uint8_t *left=bytes.data(),*right=left;size_t n=bytes.size(),m=n;uint64_t pc=ip,other=ip;
  cs_detail dx,dy;cs_insn x{},y{};
  bool equal=true;
  std::memset(&dx,0x5a,sizeof dx);std::memcpy(&dy,&dx,sizeof dy);
  std::memset(x.bytes,0xa4,sizeof x.bytes);std::memset(x.mnemonic,0xa4,sizeof x.mnemonic);std::memset(x.op_str,0xa4,sizeof x.op_str);
  std::memcpy(&y,&x,sizeof y);
  x.detail=mode==2?&dx:nullptr;y.detail=mode==2?&dy:nullptr;
  while(n){
    const size_t offset=size_t(left-bytes.data());
    const bool ok=a.api.next(a.h,&left,&n,&pc,&x), got=b.api.next(b.h,&right,&m,&other,&y);
    cs_insn flat;std::memcpy(&flat,&x,sizeof flat);flat.detail=y.detail;
    equal=ok==got&&left==right&&n==m&&pc==other&&a.api.error(a.h)==b.api.error(b.h)&&!std::memcmp(&flat,&y,sizeof flat)&&!std::memcmp(&dx,&dy,sizeof dx);
    if(!equal){std::fprintf(stderr,"iterator differs at %zu mode %d ids %u/%u names %s/%s\n",offset,mode,x.id,y.id,x.mnemonic,y.mnemonic);std::exit(11);}
    if(!ok){size_t skip=std::min(stride,n);left+=skip;right+=skip;pc+=skip;other+=skip;n-=skip;m-=skip;}
  }
}

static void configure(Session &s,int m) {s.set(CS_OPT_TEXT,m?CS_OPT_ON:CS_OPT_OFF);s.set(CS_OPT_DETAIL,m==2?CS_OPT_ON:CS_OPT_OFF);}
static int paired_images(char **argv) {
  unsigned seed = static_cast<unsigned>(std::strtoul(argv[7], nullptr, 10));
  unsigned order[] = {0,1,2};
  for (unsigned n=0; n<seed%6; ++n) std::next_permutation(order,order+3);
  Api first(argv[1+order[0]]), second(argv[1+order[1]]), third(argv[1+order[2]]);
  Api *images[3]; images[order[0]]=&first; images[order[1]]=&second; images[order[2]]=&third;
  check(first.next!=second.next && first.next!=third.next && second.next!=third.next, "separate images");
  std::ifstream f(argv[5],std::ios::binary);
  std::vector<uint8_t> bytes{std::istreambuf_iterator<char>(f),{}};
  check(!bytes.empty(),"input");
  uint64_t ip=std::strtoull(argv[6],nullptr,10);
  std::mt19937 rng(seed);
  for (int mode=0;mode<3;++mode) for (int iter=0;iter<2;++iter) {
    std::shuffle(order,order+3,rng);
    unsigned reps=0;
    uint64_t expected=0;
    size_t seen=0;
    auto work = iter ? iter_work : visit;
    for(unsigned which:order) {
      Session s(*images[which],CS_ARCH_PPC,CS_MODE_64);configure(s,mode);
      size_t records=0;uint64_t start=clk(CLOCK_PROCESS_CPUTIME_ID);
      auto value=work(s,bytes,ip,mode,4,records);
      auto ns=clk(CLOCK_PROCESS_CPUTIME_ID)-start;
      check(records && ns,"warm");
      if(!reps){seen=records;expected=value;reps=static_cast<unsigned>((25000000+ns-1)/ns);}
      check(seen==records && expected==value,"warm digest");
      uint64_t w=clk(CLOCK_MONOTONIC),c=clk(CLOCK_PROCESS_CPUTIME_ID),sum=0;
      for(unsigned j=0;j<reps;++j)sum+=work(s,bytes,ip,mode,4,records);
      c=clk(CLOCK_PROCESS_CPUTIME_ID)-c;w=clk(CLOCK_MONOTONIC)-w;
      check(records==seen && sum==expected*reps,"measured digest");
      std::printf("%d %d %u %" PRIu64 " %" PRIu64 " %u %zu %" PRIu64 "\n",
                  mode,iter,which,c,w,reps,records,value);
    }
  }
  return 0;
}

int main(int argc,char **argv) {
  if(argc==8 && std::string(argv[4])=="paired")return paired_images(argv);
  if(argc<4)return 2;
  Api a(argv[1]),b(argv[2]);check(a.disasm!=b.disasm,"distinct decoders");
  std::string op=argv[3];
  if(argc<7)return 2;
  std::ifstream f(argv[4],std::ios::binary);std::vector<uint8_t> bytes{std::istreambuf_iterator<char>(f),{}};check(!bytes.empty(),"input");
  std::string target=argv[5];uint64_t ip=std::strtoull(argv[6],nullptr,10);
  check(target=="ppc","architecture");
  Session left(a,CS_ARCH_PPC,CS_MODE_64),right(b,CS_ARCH_PPC,CS_MODE_64);
  const size_t stride=4;
  if(op=="verify"){
    for(int m=0;m<3;++m) {
      configure(left,m);configure(right,m);
      verify_iter(left,right,bytes,ip,m,stride);
      for(size_t off=0;off<bytes.size();){
        size_t consumed=compare(left,right,bytes.data()+off,bytes.size()-off,ip+off,64);
        off+=consumed?consumed:std::min(stride,bytes.size()-off);
      }
    }
    std::printf("{\"batches\":%" PRIu64 ",\"records\":%" PRIu64 "}\n",total_batches,total_records);return 0;
  }
  return 2;
}
