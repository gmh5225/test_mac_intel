#include "arch/X86/X86ScanAdapter.h"
#include <algorithm>
#include <cstdint>
#include <cstdlib>
#include <fstream>
#include <iostream>
#include <iterator>
#include <vector>
#ifdef _WIN32
#include <windows.h>
static uint64_t ticks() { ULONG64 n; if (!QueryThreadCycleTime(GetCurrentThread(), &n)) std::abort(); return n; }
#else
#include <time.h>
static uint64_t ticks() { timespec t; if (clock_gettime(CLOCK_THREAD_CPUTIME_ID, &t)) std::abort(); return uint64_t(t.tv_sec) * 1000000000 + t.tv_nsec; }
#endif
struct Event { size_t offset; uint16_t length; uint64_t target; };
struct Result { uint64_t targets=0, calls=0, valid=0, instructions=0, rejected=0, boundaries=0; };
static void option(csh handle, cs_opt_type type, size_t value) {
  if (cs_option(handle,type,value) != CS_ERR_OK) std::abort();
}
static uint64_t detailed(csh handle, cs_insn *insn, const uint8_t *ptr, size_t size, uint64_t ip) {
  option(handle,CS_OPT_TEXT,CS_OPT_ON);option(handle,CS_OPT_DETAIL,CS_OPT_ON);
  const size_t exact=size; uint64_t target=UINT64_MAX;
  if (cs_disasm_iter(handle,&ptr,&size,&ip,insn) && insn->size==exact && insn->id==X86_INS_CALL && insn->detail->x86.op_count && insn->detail->x86.operands[0].type==X86_OP_IMM)
    target=(uint64_t)insn->detail->x86.operands[0].imm;
  option(handle,CS_OPT_DETAIL,CS_OPT_OFF);option(handle,CS_OPT_TEXT,CS_OPT_OFF);
  return target;
}
static uint64_t compact(csh handle,const uint8_t *ptr,size_t size,uint64_t ip) {
  uint64_t target=UINT64_MAX;const uint16_t len=X86_scanCallTarget(handle,ptr,size,ip,&target);
  return len && len==size ? target : UINT64_MAX;
}
static void record(Result &r,uint64_t target,size_t off) {
  ++r.calls;if (target!=UINT64_MAX) ++r.valid;
  r.targets=(r.targets^target^off)*UINT64_C(0x100000001b3);
}
static void walk(csh h,cs_insn *i,const std::vector<uint8_t>& b,uint64_t base,bool query,Result &r,std::vector<Event>* events) {
  const uint8_t *c=b.data();size_t left=b.size();uint64_t ip=base;
  while(left){
    const uint8_t *at=c;const uint64_t addr=ip;
    if(!cs_disasm_iter(h,&c,&left,&ip,i)){++c;++ip;--left;++r.rejected;continue;}
    const uint16_t size=i->size;const size_t off=at-b.data();
    ++r.instructions;r.boundaries=(r.boundaries^i->id^size^off)*UINT64_C(0x100000001b3);
    if(i->id!=X86_INS_CALL)continue;
    const uint64_t target=query?compact(h,at,size,addr):detailed(h,i,at,size,addr);
    record(r,target,off);
    if(events){if(compact(h,at,size,addr)!=target)std::abort();events->push_back({off,size,target});}
  }
}
int main(int argc,char **argv){
  if(argc!=6)return 2;
#ifdef _WIN32
  SetThreadAffinityMask(GetCurrentThread(),1);
#endif
  std::ifstream f(argv[1],std::ios::binary);if(!f)return 3;
  const std::vector<uint8_t>b((std::istreambuf_iterator<char>(f)),{});
  const bool x64=std::atoi(argv[2])==64, linear=std::atoi(argv[3])!=0, query=std::atoi(argv[4])!=0;
  const int repeats=std::atoi(argv[5]);const uint64_t base=x64?UINT64_C(0x140001000):UINT64_C(0x401000);
  csh h=0;if(cs_open(CS_ARCH_X86,x64?CS_MODE_64:CS_MODE_32,&h)!=CS_ERR_OK)return 4;
  option(h,CS_OPT_DETAIL,CS_OPT_ON);cs_insn *i=cs_malloc(h);if(!i)return 5;option(h,CS_OPT_TEXT,CS_OPT_OFF);option(h,CS_OPT_DETAIL,CS_OPT_OFF);
  std::vector<Event> events;Result oracle;walk(h,i,b,base,false,oracle,&events);
  if(events.empty())return 6;
  auto run=[&](){Result r;if(linear)walk(h,i,b,base,query,r,nullptr);else{
    for(const Event& e:events){const uint8_t *at=b.data()+e.offset;const uint64_t ip=base+e.offset;
      const uint64_t target=query?compact(h,at,e.length,ip):detailed(h,i,at,e.length,ip);
      record(r,target,e.offset);
    }}
    if(r.calls!=oracle.calls||r.valid!=oracle.valid||r.targets!=oracle.targets||
       (linear&&(r.instructions!=oracle.instructions||r.rejected!=oracle.rejected||r.boundaries!=oracle.boundaries))) std::abort();};
  run();const uint64_t start=ticks();for(int n=0;n<repeats;++n)run();const uint64_t elapsed=ticks()-start;
  std::cout<<elapsed<<" "<<oracle.instructions<<" "<<oracle.rejected<<" "<<oracle.calls<<" "<<oracle.valid<<" "<<oracle.targets<<" "<<oracle.boundaries<<" "<<repeats<<"\n";
  cs_free(i,1);cs_close(&h);
}
