#include <capstone/capstone.h>
#ifdef _WIN32
#define NOMINMAX
#include <windows.h>
#else
#include <dlfcn.h>
#include <sys/mman.h>
#include <unistd.h>
#endif
#include <algorithm>
#include <array>
#include <cinttypes>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <chrono>
#include <utility>
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
#ifdef _WIN32
static void *load_library(const char *f) { return reinterpret_cast<void *>(LoadLibraryA(f)); }
static void *symbol(void *h,const char *n) { return reinterpret_cast<void *>(GetProcAddress(static_cast<HMODULE>(h),n)); }
#else
static void *load_library(const char *f) { return dlopen(f, RTLD_NOW | RTLD_LOCAL); }
static void *symbol(void *h,const char *n) { return dlsym(h,n); }
#endif
struct Api {
  void *so;
  template<class T> T sym(const char *n) { void *fp = symbol(so, n); check(fp, n); return reinterpret_cast<T>(fp); }
  decltype(&cs_open) open;
  decltype(&cs_close) close;
  decltype(&cs_option) option;
  decltype(&cs_disasm) disasm;
  decltype(&cs_disasm_iter) next;
  decltype(&cs_malloc) alloc;
  decltype(&cs_free) free;
  decltype(&cs_errno) error;
  decltype(&cs_regs_access) regs;
  explicit Api(const char *file) : so(load_library(file)),
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
#ifdef _WIN32
  SYSTEM_INFO si;GetSystemInfo(&si);size_t ps=si.dwPageSize;DWORD old_prot;
  auto *page=static_cast<uint8_t *>(VirtualAlloc(nullptr,2*ps,MEM_COMMIT|MEM_RESERVE,PAGE_READWRITE));
  check(page&&VirtualProtect(page+ps,ps,PAGE_NOACCESS,&old_prot),"guard");
#else
  long ps=sysconf(_SC_PAGESIZE);check(ps>256,"page");
  auto *page=static_cast<uint8_t *>(mmap(nullptr,size_t(ps)*2,PROT_READ|PROT_WRITE,MAP_ANON|MAP_PRIVATE,-1,0));
  check(page!=MAP_FAILED&&!mprotect(page+ps,ps,PROT_NONE),"guard");
#endif
  std::vector<std::vector<uint8_t>> forms={{0xc5,0xf8,0xc2,0xc1,2},{0xc5,0xf8,0x77},{0xc4,0xe1,0x78,0x77},{0x66,0x48,0xd9,0x30},{0x9b,0xd9,0x30},{0x48,0x8b,0x84,0x24,4,0,0,0},{0x0f,0x84,1,0,0,0},{0xe8,0xff,0xff,0xff,0xff},{0x0f,0x0b},{0x90},{0x62,0xf1,0x7d,0x48,0xfe,0xd9},std::vector<uint8_t>(17,0x66)};
  for(auto mode:{CS_MODE_16,CS_MODE_32,CS_MODE_64})for(int opt=0;opt<9;++opt) {
    Session left(a,CS_ARCH_X86,mode),right(b,CS_ARCH_X86,mode);
    cs_opt_mnem custom{X86_INS_MOV,"move"};
    for(auto *s:{&left,&right}) {
      if(opt) s->set(CS_OPT_DETAIL,opt==2?(CS_OPT_ON|CS_OPT_DETAIL_REAL):CS_OPT_ON);
      if(opt==3){
        auto rc=s->api.option(s->h,CS_OPT_SYNTAX,CS_OPT_SYNTAX_ATT);
#ifdef VERIFY_NO_ATT
        check(rc==CS_ERR_X86_ATT,"no AT&T");
#else
        check(rc==CS_ERR_OK||rc==CS_ERR_DIET,"AT&T");
#endif
      }
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
#ifdef _WIN32
  VirtualFree(page,0,MEM_RELEASE);
#else
  munmap(page,ps*2);
#endif
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
static uint64_t cpu_ticks() {
#ifdef _WIN32
  ULONG64 ticks;
  check(QueryThreadCycleTime(GetCurrentThread(), &ticks), "thread cycles");
  return ticks;
#else
  struct timespec ts{};
  check(clock_gettime(CLOCK_THREAD_CPUTIME_ID, &ts)==0,"thread CPU");
  return uint64_t(ts.tv_sec)*1000000000+ts.tv_nsec;
#endif
}
static uint64_t visit_record(Session &s, const cs_insn &i, unsigned m) {
  uint64_t sum=i.id+i.size+i.address+i.bytes[0];
  if(m) sum+=std::strlen(i.mnemonic)+std::strlen(i.op_str);
  if(m==2 && i.detail) {
    cs_regs rr,ww;uint8_t nr=0,nw=0;
    if(s.api.regs(s.h,&i,rr,&nr,ww,&nw)==CS_ERR_OK) {
      for(unsigned j=0;j<nr;++j)sum+=rr[j];
      for(unsigned j=0;j<nw;++j)sum+=ww[j];
    }
    auto &x=i.detail->x86;
    sum+=x.eflags+x.op_count;
    for(unsigned j=0;j<x.op_count;++j)sum+=x.operands[j].type+x.operands[j].size+x.operands[j].access;
  }
  return sum;
}
static std::pair<size_t,uint64_t> sweep(Session &s,const std::vector<uint8_t>& bytes,
                                        uint64_t ip,unsigned mode,bool iter) {
  uint64_t sum=0;size_t records=0;
  if(iter) {
    cs_insn *record=s.api.alloc(s.h);check(record!=nullptr,"record");
    const uint8_t *p=bytes.data();size_t remaining=bytes.size();
    while(remaining) {
      if(s.api.next(s.h,&p,&remaining,&ip,record)) {
        sum+=visit_record(s,*record,mode);++records;
      } else {
        ++p;--remaining;++ip;
      }
    }
    s.api.free(record,1);
  } else {
    for(size_t off=0;off<bytes.size();) {
      Result batch(s,bytes.data()+off,bytes.size()-off,ip+off,64);
      if(!batch.n) { ++off; continue; }
      for(size_t i=0;i<batch.n;++i) {
        sum+=visit_record(s,batch.a[i],mode);
        off+=batch.a[i].size;
      }
      records+=batch.n;
    }
  }
  return {records,sum};
}
static int timing(int argc,char**argv) {
  check(argc==7,"timing arguments");
#ifdef _WIN32
  DWORD_PTR available,system;
  check(GetProcessAffinityMask(GetCurrentProcess(),&available,&system)&&available&&
        SetThreadAffinityMask(GetCurrentThread(),available&(~available+1)),"affinity");
#endif
  const unsigned seed=static_cast<unsigned>(std::strtoul(argv[6],nullptr,10));
  int slot=seed%2;
  Api first(argv[1+slot]), second(argv[2-slot]);
  Api *base=slot?&second:&first, *candidate=slot?&first:&second;
  check(base->disasm!=candidate->disasm,"loaded images");
  std::ifstream input(argv[3],std::ios::binary);std::vector<uint8_t> bytes{std::istreambuf_iterator<char>(input),{}};
  const int bits=std::atoi(argv[4]);const uint64_t ip=std::strtoull(argv[5],nullptr,10);
  const auto width=bits==32?CS_MODE_32:CS_MODE_64;std::mt19937 rng(seed);
  for(unsigned mode=0;mode<3;++mode) for(bool iter:{false,true}) {
    std::pair<size_t,uint64_t> want{};
    std::array<unsigned,3> order{0,1,2};std::shuffle(order.begin(),order.end(),rng);
    for(unsigned which:order) {
      Session session(which==2?*candidate:*base,CS_ARCH_X86,width);
      configure(session,mode);
      const auto warm=sweep(session,bytes,ip,mode,iter);
      if(!want.first)want=warm;check(want==warm,"native digest");
      auto start=std::chrono::steady_clock::now();uint64_t cpu=cpu_ticks();
      auto result=sweep(session,bytes,ip,mode,iter);
      uint64_t ticks=cpu_ticks()-cpu;
      auto elapsed=std::chrono::duration_cast<std::chrono::nanoseconds>(std::chrono::steady_clock::now()-start).count();
      check(result==want && ticks>0 && elapsed>0,"timed digest");
      std::printf("%u %u %u %" PRIu64 " %" PRIu64 " %zu %" PRIu64 "\n",mode,iter?1:0,which,ticks,static_cast<uint64_t>(elapsed),result.first,result.second);
    }
  }
  return 0;
}

int main(int argc,char **argv) {
  if (argc==7) return timing(argc,argv);
  if(argc!=6)return 2;
  Api a(argv[1]),b(argv[2]);check(a.disasm!=b.disasm,"distinct libraries");
  std::ifstream f(argv[3],std::ios::binary);std::vector<uint8_t> bytes{std::istreambuf_iterator<char>(f),{}};check(!bytes.empty(),"input");
  int bits=std::atoi(argv[4]);cs_mode width=bits==16?CS_MODE_16:bits==32?CS_MODE_32:CS_MODE_64;
  uint64_t ip=std::strtoull(argv[5],nullptr,10);
  Session left(a,CS_ARCH_X86,width),right(b,CS_ARCH_X86,width);
  for(int m=0;m<3;++m){
    configure(left,m);configure(right,m);verify_iter(left,right,bytes,ip,m,1);
    for(size_t off=0;off<bytes.size();){
      size_t used=compare(left,right,bytes.data()+off,bytes.size()-off,ip+off,64);
      off+=used?used:1;
    }
  }
  std::printf("{\"batches\":%" PRIu64 ",\"records\":%" PRIu64 ",\"width\":%d}",total_batches,total_records,bits); std::putchar(10);
  options(a,b);
}
