#include "arch/X86/X86ScanAdapter.h"
#include <capstone/capstone.h>
#include <algorithm>
#include <cstdlib>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <ctime>
#include <fstream>
#include <iterator>
#include <string>
#include <vector>
struct Counts {uint64_t valid=0,bad=0,bytes=0,ids=0;};
uint64_t now(clockid_t clock){timespec t;clock_gettime(clock,&t);return uint64_t(t.tv_sec)*1000000000+t.tv_nsec;}
int main(int argc,char **argv){
 if(argc!=7)return 2;
 unsigned bits=std::stoul(argv[1]), cap=std::stoul(argv[2]),reps=std::stoul(argv[6]);if(cap>128 || reps==0)return 2;
 uint64_t addr=std::stoull(argv[4],nullptr,0);std::ifstream f(argv[3],std::ios::binary);if(!f)return 2;
 std::vector<uint8_t> data((std::istreambuf_iterator<char>(f)),{});if(data.empty())return 2;
 std::vector<std::pair<size_t,size_t>> spans;
 if(std::string(argv[5])=="-")spans.emplace_back(0,data.size());
 else{std::ifstream s(argv[5]);size_t off,len;while(s>>off>>len){if(off>data.size()||len>data.size()-off||!len)return 3;spans.emplace_back(off,len);}if(!s.eof()||spans.empty())return 3;}
 csh h{};if(cs_open(CS_ARCH_X86,bits==64?CS_MODE_64:CS_MODE_32,&h)||cs_option(h,CS_OPT_TEXT,CS_OPT_OFF))return 3;
 cs_insn *insn=cs_malloc(h);if(!insn)return 4;
 FILE *dump=std::getenv("RECORD_FILE")?std::fopen(std::getenv("RECORD_FILE"),"wb"):nullptr;
 auto record=[&](uint32_t v){if(dump && std::fwrite(&v,4,1,dump)!=1)std::abort();};
 auto scan=[&]{
   Counts o;
   for(auto [off,len]:spans){
     size_t left=len;const uint8_t *cursor=data.data()+off;uint64_t ip=addr+off;
     while(left){
       if(cap){
         uint32_t items[128];auto b=X86_scanBatch(h,cursor,left,ip,items,cap);
         if(b.count){size_t used=0;
           for(size_t i=0;i<b.count;++i){auto n=items[i]&255,id=items[i]>>8;if(!n||!id||n>left-used)std::abort();used+=n;o.ids+=id;record(items[i]);}
           if(used!=b.bytes||b.count>cap)std::abort();
           o.valid+=b.count;o.bytes+=used;cursor+=used;left-=used;ip+=used;continue;
         }
       }
       if(cs_disasm_iter(h,&cursor,&left,&ip,insn)){++o.valid;record((insn->id<<8)|insn->size);o.ids+=insn->id;o.bytes+=insn->size;}
       else{record(0);++o.bad;++cursor;++ip;--left;}
     }
   }
   return o;
 };
 Counts warm=scan();if(dump){std::fclose(dump);dump=nullptr;}uint64_t c=now(CLOCK_PROCESS_CPUTIME_ID),t=now(CLOCK_MONOTONIC);
 for(unsigned k=0;k<reps;++k){auto v=scan();if(v.valid!=warm.valid||v.bad!=warm.bad||v.ids!=warm.ids||v.bytes!=warm.bytes)return 5;}
 t=now(CLOCK_MONOTONIC)-t;c=now(CLOCK_PROCESS_CPUTIME_ID)-c;
 std::printf("%llu %llu %llu %llu %llu %llu\n",(unsigned long long)c,(unsigned long long)t,(unsigned long long)warm.valid,(unsigned long long)warm.bad,(unsigned long long)warm.bytes,(unsigned long long)warm.ids);
 cs_free(insn,1);cs_close(&h);
}
