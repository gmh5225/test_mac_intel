#include <cstdlib>
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
 if(argc!=7)return 2;
 auto bits=std::atoi(argv[1]),mode=std::atoi(argv[2]),reps=std::atoi(argv[5]);
 auto ip=std::strtoull(argv[4],nullptr,0);
 std::ifstream in(argv[3],std::ios::binary); if(!in)return 2;
 std::vector<uint8_t> bytes((std::istreambuf_iterator<char>(in)),{});
 cs_arch arch=CS_ARCH_X86;cs_mode cm=bits==64?CS_MODE_64:CS_MODE_32;unsigned align=1;
 switch(bits){
 case 101:arch=CS_ARCH_ARM;cm=CS_MODE_ARM;align=4;break;
 case 102:arch=CS_ARCH_AARCH64;cm=CS_MODE_LITTLE_ENDIAN;align=4;break;
 case 103:arch=CS_ARCH_MIPS;cm=CS_MODE_MIPS64;align=4;break;
 case 104:arch=CS_ARCH_PPC;cm=CS_MODE_64;align=4;break;
 case 105:arch=CS_ARCH_RISCV;cm=cs_mode(CS_MODE_RISCV64|CS_MODE_RISCV_C|CS_MODE_RISCV_FD|CS_MODE_RISCV_A);align=2;break;
 case 106:arch=CS_ARCH_SPARC;cm=cs_mode(CS_MODE_BIG_ENDIAN|CS_MODE_V9);align=4;break;
 case 107:arch=CS_ARCH_SYSTEMZ;cm=cs_mode(CS_MODE_BIG_ENDIAN|CS_MODE_SYSTEMZ_Z16);align=2;break;
 case 108:arch=CS_ARCH_LOONGARCH;cm=CS_MODE_LOONGARCH64;align=4;break;
 case 109:arch=CS_ARCH_XTENSA;cm=CS_MODE_XTENSA_ESP8266;align=1;break;
 }
 csh handle{};if(cs_open(arch,cm,&handle) ||
 cs_option(handle,CS_OPT_TEXT,mode==0?CS_OPT_OFF:CS_OPT_ON)||
 cs_option(handle,CS_OPT_DETAIL,mode>=2?CS_OPT_ON:CS_OPT_OFF))return 3;
 cs_insn *i=cs_malloc(handle);if(!i)return 4;
 struct Extent { size_t offset, length; uint64_t address; };
 std::ifstream ranges(argv[6]);std::vector<Extent> spans;Extent extent;
 while (ranges >> extent.offset >> extent.length >> extent.address) {
  if(!extent.length || extent.offset>bytes.size() || extent.length>bytes.size()-extent.offset)return 4;
  spans.push_back(extent);
 }
 if(!ranges.eof() || spans.empty())return 4;
 auto go=[&]{
   uint64_t count=0,values=0;
   for(const auto &span:spans){const uint8_t *ptr=bytes.data()+span.offset;size_t left=span.length;uint64_t va=span.address;
   while(left){
     if(cs_disasm_iter(handle,&ptr,&left,&va,i)){
       ++count;values+=i->size;
       if(mode==3){
           cs_regs rr,ww;uint8_t nr=0,nw=0;
           if(cs_regs_access(handle,i,rr,&nr,ww,&nw)!=CS_ERR_OK)std::abort();
           values+=nr+nw;
           for(unsigned n=0;n<nr;++n)values+=rr[n];
           for(unsigned n=0;n<nw;++n)values+=ww[n];
       }
       if(mode)values+=uint8_t(i->mnemonic[0])+uint8_t(i->op_str[0]);
       if(mode>=2){
         switch(arch){
           case CS_ARCH_ARM:values+=i->detail->arm.op_count;break;
           case CS_ARCH_AARCH64:values+=i->detail->aarch64.op_count;break;
           case CS_ARCH_PPC:values+=i->detail->ppc.op_count;break;
           case CS_ARCH_MIPS:values+=i->detail->mips.op_count;break;
           case CS_ARCH_SPARC:values+=i->detail->sparc.op_count;break;
           case CS_ARCH_SYSTEMZ:values+=i->detail->systemz.op_count;break;
           case CS_ARCH_LOONGARCH:values+=i->detail->loongarch.op_count;break;
           case CS_ARCH_XTENSA:values+=i->detail->xtensa.op_count;break;
           case CS_ARCH_RISCV:values+=i->detail->riscv.op_count;break;
           default:values+=i->detail->x86.op_count;
         }
       }
     }else{size_t step=left<align?left:align;ptr+=step;left-=step;va+=step;}
   }
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
