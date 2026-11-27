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
struct Trace {
  const uint8_t *origin{};
  size_t length{},skip{};
  std::vector<size_t> offsets;
};
static size_t skip(const uint8_t *code,size_t size,size_t offset,void *ctx) {
  auto &s=*static_cast<Trace *>(ctx);
  check(s.origin==code&&s.length==size&&offset<size,"batch callback buffer");
  s.offsets.push_back(offset);return s.skip;
}
static Api *alloc_owner;
static csh allocate_handle;
static bool arm_alloc;
static void *changing_calloc(size_t n,size_t z) {
  if(arm_alloc&&n==1&&z==sizeof(cs_detail)) {
    arm_alloc=false;check(!alloc_owner->option(allocate_handle,CS_OPT_DETAIL,CS_OPT_OFF),"allocator switches detail");
  }
  return std::calloc(n,z);
}
static void options(Api &a,Api &b) {
  long ps=sysconf(_SC_PAGESIZE);check(ps>256,"page");
  auto *page=static_cast<uint8_t *>(mmap(nullptr,size_t(ps)*2,PROT_READ|PROT_WRITE,MAP_ANON|MAP_PRIVATE,-1,0));
  check(page!=MAP_FAILED&&!mprotect(page+ps,ps,PROT_NONE),"guard");
  std::vector<std::vector<uint8_t>> forms={{0xc5,0xf8,0xc2,0xc1,2},{0xc5,0xf8,0x77},{0xc4,0xe1,0x78,0x77},{0x66,0x48,0xd9,0x30},{0x9b,0xd9,0x30},{0x48,0x8b,0x84,0x24,4,0,0,0},{0x0f,0x84,1,0,0,0},{0xe8,0xff,0xff,0xff,0xff},{0x0f,0x0b},{0x90},{0x62,0xf1,0x7d,0x48,0xfe,0xd9},std::vector<uint8_t>(17,0x66)};
  for(auto mode:{CS_MODE_16,CS_MODE_32,CS_MODE_64})for(int opt=0;opt<9;++opt) {
    Session left(a,CS_ARCH_X86,mode),right(b,CS_ARCH_X86,mode);
    cs_opt_mnem custom{X86_INS_MOV,"move"};
    for(auto *s:{&left,&right}) {
      if(opt) s->set(CS_OPT_DETAIL,opt==2?(CS_OPT_ON|CS_OPT_DETAIL_REAL):CS_OPT_ON);
      if(opt==3)s->set(CS_OPT_SYNTAX,CS_OPT_SYNTAX_ATT);
      if(opt==4)s->set(CS_OPT_UNSIGNED,CS_OPT_ON);
      if(opt==5)s->set(CS_OPT_MNEMONIC,reinterpret_cast<size_t>(&custom));
      if(opt==6)s->set(CS_OPT_TEXT,CS_OPT_OFF);
      if(opt==7)s->set(CS_OPT_SKIPDATA,CS_OPT_ON);
      if(opt==8)s->set(CS_OPT_ONLY_OFFSET_BRANCH,CS_OPT_ON);
    }
    for(const auto &f: forms)for(size_t n=0;n<=f.size();++n) {
      const auto *start=page+ps-n;
      std::memcpy(page+ps-n,f.data(),n);
      for(size_t count:{0u,1u,4u})compare(left,right,start,n,UINT64_MAX-3,count);
    }
    std::vector<uint8_t> many(260,0x50);many[56]=0x58;
    for(size_t count:{0u,1u,31u,32u,33u,63u,64u,65u,128u,260u})compare(left,right,many.data(),many.size(),0x401000,count);
  }
  munmap(page,ps*2);
  size_t callbacks=0;
  for(size_t step:{0u,1u,70000u,80000u}) {
    std::vector<uint8_t> bytes(70002,0x90);std::fill_n(bytes.data()+1,17,0x66);
    Trace traces[2]={{bytes.data(),bytes.size(),step,{}},{bytes.data(),bytes.size(),step,{}}};
    Session l(a,CS_ARCH_X86,CS_MODE_32),r(b,CS_ARCH_X86,CS_MODE_32);
    cs_opt_skipdata cbs[2]{};unsigned idx=0;
    for(Session *s:{&l,&r}) {
      cbs[idx]={"skip_data",skip,&traces[idx]};s->set(CS_OPT_SKIPDATA_SETUP,reinterpret_cast<size_t>(&cbs[idx]));
      s->set(CS_OPT_SKIPDATA,CS_OPT_ON);s->set(CS_OPT_DETAIL,CS_OPT_ON);++idx;
    }
    size_t used=compare(l,r,bytes.data(),bytes.size(),UINT64_MAX-5,4);
    check(traces[0].offsets==traces[1].offsets&&!traces[0].offsets.empty()&&traces[0].offsets[0]==1,"callback offset");
    if(step==70000)check(used==2+sizeof(cs_insn::bytes)&&traces[0].offsets.size()==1,"long skip");
    callbacks+=traces[0].offsets.size();
  }
  const uint8_t code[]={0x50,0x8b,0xc2};cs_insn flat[2];cs_detail details[2];unsigned idx=0;
  cs_opt_mem memory{std::malloc,changing_calloc,std::realloc,std::free,std::vsnprintf};
  for(Api *api:{&a,&b}) {
    check(!api->option(0,CS_OPT_MEM,reinterpret_cast<size_t>(&memory)),"allocator");
    Session s(*api,CS_ARCH_X86,CS_MODE_32);s.set(CS_OPT_DETAIL,CS_OPT_ON);
    alloc_owner=api;allocate_handle=s.h;arm_alloc=true;
    Result one(s,code,sizeof code,0x401000,1);check(one.n==1&&!arm_alloc&&one.a->detail,"reentrant allocation");
    std::memcpy(&flat[idx],one.a,sizeof(cs_insn));flat[idx].detail=nullptr;std::memcpy(&details[idx],one.a->detail,sizeof(cs_detail));++idx;
  }
  check(!std::memcmp(flat,flat+1,sizeof(cs_insn))&&!std::memcmp(details,details+1,sizeof(cs_detail)),"reentrant result");
  std::printf("{\"batches\":%" PRIu64 ",\"records\":%" PRIu64 ",\"callback_events\":%zu,\"reentrant_details\":true}\n",total_batches,total_records,callbacks);
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
      if(mode==2) {cs_regs rr,rw;uint8_t nr=0,nw=0;check(!s.api.regs(s.h,&x,rr,&nr,rw,&nw),"regs");res+=nr+nw;}
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
    if(mode==2){cs_regs rr,rw;uint8_t nr=0,nw=0;check(!s.api.regs(s.h,record,rr,&nr,rw,&nw),"iter regs");sum+=nr+nw;}
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
static uint64_t exact_extents(Session &session, const std::vector<uint8_t> &bytes,
                              uint64_t start, int mode, const std::vector<uint8_t> &extents,
                              size_t &seen) {
  cs_insn *insn=session.api.alloc(session.h);
  check(insn,"record");
  size_t offset=0; uint64_t sum=0; seen=0;
  for(uint8_t extent:extents) {
    if (!extent) {++offset; continue;}
    const uint8_t *pc=bytes.data()+offset;
    uint64_t ip=start+offset; size_t left=extent;
    check(session.api.next(session.h,&pc,&left,&ip,insn)&&left==0&&insn->size==extent,
          "complete isolated instruction");
    ++seen; offset+=extent;
    sum+=insn->id+extent;
    if(mode) sum+=std::strlen(insn->mnemonic)+std::strlen(insn->op_str);
    if(mode==2) {cs_regs rr,rw;uint8_t nr=0,nw=0;
      check(!session.api.regs(session.h,insn,rr,&nr,rw,&nw),"registers");sum+=nr+nw;}
  }
  check(offset==bytes.size(),"extents");
  session.api.free(insn,1);
  return sum;
}

static int single(char **argv) {
  Api api(argv[1]);
  std::ifstream stream(argv[3],std::ios::binary);
  std::vector<uint8_t> bytes{std::istreambuf_iterator<char>(stream),{}};
  check(!bytes.empty(),"input");
  std::string target=argv[4],op=argv[6];
  uint64_t ip=std::strtoull(argv[5],nullptr,10);
  cs_arch arch=target=="arm64"?CS_ARCH_AARCH64:target=="mips64el"?CS_ARCH_MIPS:CS_ARCH_X86;
  cs_mode width=arch==CS_ARCH_AARCH64?CS_MODE_LITTLE_ENDIAN:arch==CS_ARCH_MIPS?CS_MODE_MIPS64:target=="64"?CS_MODE_64:CS_MODE_32;
  Session session(api,arch,width);int mode=std::atoi(argv[7]);configure(session,mode);
  unsigned reps=unsigned(std::strtoul(argv[8],nullptr,10));check(reps,"reps");
  size_t stride=arch==CS_ARCH_X86?1:4,records=0,seen=0;
  std::vector<uint8_t> extents;
  if(op=="short") {
    cs_insn *insn=api.alloc(session.h);check(insn,"extent record");
    size_t remaining=bytes.size();const uint8_t *p=bytes.data();auto pc=ip;
    while(remaining) {
      auto pos=p;size_t available=remaining;
      bool valid=api.next(session.h,&p,&remaining,&pc,insn);
      if(!valid){++p;--remaining;++pc;}
      check(valid?(p-pos==insn->size && insn->size<=15):(p-pos==1),"extent length");
      extents.push_back(valid?insn->size:0);
      check(remaining+size_t(p-pos)==available,"remaining");
    }
    api.free(insn,1);
  }
  auto work=[&](Session &s,const std::vector<uint8_t> &bytes,uint64_t ip,int mode,size_t stride,size_t &seen){
    return op=="short"?exact_extents(s,bytes,ip,mode,extents,seen):iter_work(s,bytes,ip,mode,stride,seen);
  };
  auto want=work(session,bytes,ip,mode,stride,records);
  uint64_t sum=0,wall=clk(CLOCK_MONOTONIC),cpu=clk(CLOCK_PROCESS_CPUTIME_ID);
  for(unsigned i=0;i<reps;++i) sum+=work(session,bytes,ip,mode,stride,seen);
  auto took=clk(CLOCK_PROCESS_CPUTIME_ID)-cpu, elapsed=clk(CLOCK_MONOTONIC)-wall;
  check(seen==records&&sum==want*reps,"result");Dl_info loc{};
  check(dladdr(reinterpret_cast<const void *>(api.next),&loc)&&loc.dli_fbase,"mapping");
  std::printf("%" PRIu64 " %" PRIu64 " %zu %" PRIu64 " %" PRIuPTR " %" PRIuPTR "\n",took,elapsed,seen,want,reinterpret_cast<uintptr_t>(loc.dli_fbase),reinterpret_cast<uintptr_t>(api.next)-reinterpret_cast<uintptr_t>(loc.dli_fbase));
  return 0;
}

int main(int argc,char **argv) {
  if(argc==9 && std::string(argv[2])=="single")return single(argv);
  if(argc<4)return 2;
  Api a(argv[1]),b(argv[2]);check(a.disasm!=b.disasm,"distinct array decoders");
  std::string op=argv[3];if(op=="options"){options(a,b);return 0;}
  if(argc<7)return 2;
  std::ifstream f(argv[4],std::ios::binary);std::vector<uint8_t> bytes{std::istreambuf_iterator<char>(f),{}};check(!bytes.empty(),"input");
  std::string target=argv[5];uint64_t ip=std::strtoull(argv[6],nullptr,10);
  cs_arch arch=target=="arm64"?CS_ARCH_AARCH64:target=="mips64el"?CS_ARCH_MIPS:CS_ARCH_X86;
  cs_mode width=arch==CS_ARCH_AARCH64?CS_MODE_LITTLE_ENDIAN:arch==CS_ARCH_MIPS?CS_MODE_MIPS64:target=="64"?CS_MODE_64:CS_MODE_32;
  Session left(a,arch,width),right(b,arch,width);const size_t stride=(arch==CS_ARCH_X86)?1:4;
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
  check((op=="time"||op=="iter")&&argc==8,"args");
  auto measure=op=="iter"?iter_work:visit;int mode=std::atoi(argv[7]);configure(left,mode);configure(right,mode);
  size_t records=0,seen;auto t=clk(CLOCK_PROCESS_CPUTIME_ID);auto want=measure(left,bytes,ip,mode,stride,records);
  uint64_t reps=std::clamp<uint64_t>(20000000/std::max<uint64_t>(1,clk(CLOCK_PROCESS_CPUTIME_ID)-t),1,128);
  check(measure(right,bytes,ip,mode,stride,seen)==want&&seen==records,"timing records");
  std::array<Session *,3> sessions{&left,&right,&left};std::array<unsigned,3> order{0,1,2};std::mt19937 rng(2315);
  std::printf("{\"records\":%zu,\"value\":%" PRIu64 ",\"reps\":%" PRIu64 ",\"cycles\":[",records,want,reps);
  for(int i=0;i<21;++i){
    std::shuffle(order.begin(),order.end(),rng);uint64_t cp[3]{},wall[3]{};
    for(unsigned j=0;j<6;++j){unsigned k=order[j<3?j:5-j];auto w=clk(CLOCK_MONOTONIC),c=clk(CLOCK_PROCESS_CPUTIME_ID);
      uint64_t value=0;for(unsigned rep=0;rep<reps;++rep)value+=measure(*sessions[k],bytes,ip,mode,stride,seen);
      cp[k]+=clk(CLOCK_PROCESS_CPUTIME_ID)-c;wall[k]+=clk(CLOCK_MONOTONIC)-w;
      check(value==want*reps&&seen==records,"changed timing result");}
    std::printf("%s[[%" PRIu64 ",%" PRIu64 "],[%" PRIu64 ",%" PRIu64 "],[%" PRIu64 ",%" PRIu64 "]]",i?",":"",cp[0],wall[0],cp[1],wall[1],cp[2],wall[2]);
  }
  std::puts("]}");
}
