#include <capstone/capstone.h>
#include <algorithm>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cstddef>
#include <fstream>
#include <iterator>
#include <vector>
static void mix(uint64_t &value,const void *data,size_t size){
 auto *p=static_cast<const uint8_t *>(data);
 while(size>=8){uint64_t word;std::memcpy(&word,p,8);value=(value^word)*1099511628211ull;p+=8;size-=8;}
 while(size--){value=(value^*p++)*1099511628211ull;}
}
int main(int argc,char **argv){
 if(argc!=5)return 1;const unsigned selector=std::atoi(argv[1]);const unsigned opt=std::atoi(argv[3]);
 std::ifstream in(argv[2],std::ios::binary);if(!in)return 2;std::vector<uint8_t> bytes{std::istreambuf_iterator<char>(in),{}};
 cs_arch arch;cs_mode mode;size_t record_size,alignment;
 switch (selector) {
 case 101: arch=CS_ARCH_ARM;mode=CS_MODE_ARM;record_size=sizeof(cs_arm);alignment=4;break;
 case 102: arch=CS_ARCH_AARCH64;mode=CS_MODE_LITTLE_ENDIAN;record_size=sizeof(cs_aarch64);alignment=4;break;
 case 103: arch=CS_ARCH_MIPS;mode=CS_MODE_MIPS64;record_size=sizeof(cs_mips);alignment=4;break;
 case 104: arch=CS_ARCH_PPC;mode=CS_MODE_64;record_size=sizeof(cs_ppc);alignment=4;break;
 case 105: arch=CS_ARCH_RISCV;mode=cs_mode(CS_MODE_RISCV64|CS_MODE_RISCV_C|CS_MODE_RISCV_FD|CS_MODE_RISCV_A);record_size=sizeof(cs_riscv);alignment=2;break;
 case 106: arch=CS_ARCH_SPARC;mode=cs_mode(CS_MODE_BIG_ENDIAN|CS_MODE_V9);record_size=sizeof(cs_sparc);alignment=4;break;
 case 107: arch=CS_ARCH_SYSTEMZ;mode=cs_mode(CS_MODE_BIG_ENDIAN|CS_MODE_SYSTEMZ_Z16);record_size=sizeof(cs_systemz);alignment=2;break;
 case 108: arch=CS_ARCH_LOONGARCH;mode=CS_MODE_LOONGARCH64;record_size=sizeof(cs_loongarch);alignment=4;break;
 case 109: arch=CS_ARCH_XTENSA;mode=CS_MODE_XTENSA_ESP8266;record_size=sizeof(cs_xtensa);alignment=1;break;
 case 110: arch=CS_ARCH_ALPHA;mode=CS_MODE_LITTLE_ENDIAN;record_size=sizeof(cs_alpha);alignment=4;break;
 default:return 3;
 }
 csh h=0;if(cs_open(arch,mode,&h))return 3;
 const bool with_detail=opt!=0;
 const size_t det=opt==2?CS_OPT_ON|CS_OPT_DETAIL_REAL:opt==3?CS_OPT_ON|CS_OPT_DETAIL_ALIAS:opt?CS_OPT_ON:CS_OPT_OFF;
 if(cs_option(h,CS_OPT_DETAIL,det)!=CS_ERR_OK)return 4;
 if(opt==4&&cs_option(h,CS_OPT_TEXT,CS_OPT_OFF)!=CS_ERR_OK)return 5;
 cs_insn i;cs_detail detail;std::memset(&i,0xa5,sizeof(i));std::memset(&detail,0xa5,sizeof(detail));i.detail=with_detail?&detail:nullptr;
 struct Extent { size_t offset, length; uint64_t address; };
 std::ifstream ranges(argv[4]);std::vector<Extent> spans;Extent extent;
 while (ranges >> extent.offset >> extent.length >> extent.address) {
  if(!extent.length || extent.offset>bytes.size() || extent.length>bytes.size()-extent.offset)return 4;
  spans.push_back(extent);
 }
 if(!ranges.eof() || spans.empty())return 4;
 uint64_t ok=0,bad=0,v=14695981039346656037ull,alias=0;
 for(const auto &span:spans){const uint8_t *p=bytes.data()+span.offset;size_t left=span.length;uint64_t ip=span.address;
 while(left){
  if(cs_disasm_iter(h,&p,&left,&ip,&i)){
   ++ok;alias+=i.is_alias;mix(v,&i,offsetof(cs_insn,detail));if(with_detail)mix(v,&detail,offsetof(cs_detail,aarch64)+record_size);
  }else{auto n=std::min(alignment,left);left-=n;p+=n;ip+=n;++bad;}
  mix(v,&ip,sizeof(ip));
 }
 }
 cs_close(&h);std::printf("%llu %llu %llu %llu\n",(unsigned long long)ok,(unsigned long long)bad,(unsigned long long)alias,(unsigned long long)v);
}
