#include <capstone/capstone.h>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <fstream>
#include <iterator>
#include <ctime>
#include <vector>
uint64_t ns(clockid_t id){timespec t{};clock_gettime(id,&t);return uint64_t(t.tv_sec)*1000000000+t.tv_nsec;}
int main(int argc,char **argv){
 if(argc!=6)return 2;
 auto bits=std::atoi(argv[1]),mode=std::atoi(argv[2]),reps=std::atoi(argv[5]);
 auto ip=std::strtoull(argv[4],nullptr,0);
 std::ifstream in(argv[3],std::ios::binary); if(!in)return 2;
 std::vector<uint8_t> bytes((std::istreambuf_iterator<char>(in)),{});
 csh handle{};if(cs_open(CS_ARCH_X86,bits==64?CS_MODE_64:CS_MODE_32,&handle) ||
 cs_option(handle,CS_OPT_TEXT,mode==0?CS_OPT_OFF:CS_OPT_ON)||
 cs_option(handle,CS_OPT_DETAIL,mode==2?CS_OPT_ON:CS_OPT_OFF))return 3;
 cs_insn *i=cs_malloc(handle);if(!i)return 4;
 auto go=[&]{
   uint64_t count=0,values=0;
   const uint8_t *ptr=bytes.data();size_t left=bytes.size();uint64_t va=ip;
   while(left){
     if(cs_disasm_iter(handle,&ptr,&left,&va,i)){
       ++count;values+=i->size;
       if(mode)values+=uint8_t(i->mnemonic[0])+uint8_t(i->op_str[0]);
       if(mode==2)values+=i->detail->x86.op_count;
     }else{++ptr;--left;++va;}
   }
   return count*0x10001+values;
 };
 uint64_t warm=go(), total=0, c=ns(CLOCK_PROCESS_CPUTIME_ID),t=ns(CLOCK_MONOTONIC);
 for(int n=0;n<reps;++n)total+=go();
 t=ns(CLOCK_MONOTONIC)-t;c=ns(CLOCK_PROCESS_CPUTIME_ID)-c;
 if(total!=warm*reps)return 5;
 std::printf("%llu %llu %llu\n",(unsigned long long)c,(unsigned long long)t,(unsigned long long)warm);
 cs_free(i,1);cs_close(&handle);
}
