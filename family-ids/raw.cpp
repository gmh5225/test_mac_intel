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
 if(argc!=4)return 1;const bool arm=std::strcmp(argv[1],"arm")==0;const unsigned opt=std::atoi(argv[3]);
 std::ifstream in(argv[2],std::ios::binary);if(!in)return 2;std::vector<uint8_t> bytes{std::istreambuf_iterator<char>(in),{}};
 csh h=0;if(cs_open(arm?CS_ARCH_AARCH64:CS_ARCH_MIPS,arm?CS_MODE_LITTLE_ENDIAN:CS_MODE_MIPS64,&h))return 3;
 const bool with_detail=opt!=0;
 const size_t det=opt==2?CS_OPT_ON|CS_OPT_DETAIL_REAL:opt==3?CS_OPT_ON|CS_OPT_DETAIL_ALIAS:opt?CS_OPT_ON:CS_OPT_OFF;
 if(cs_option(h,CS_OPT_DETAIL,det)!=CS_ERR_OK)return 4;
 if(opt==4&&cs_option(h,CS_OPT_TEXT,CS_OPT_OFF)!=CS_ERR_OK)return 5;
 cs_insn i;cs_detail detail;std::memset(&i,0xa5,sizeof(i));std::memset(&detail,0xa5,sizeof(detail));i.detail=with_detail?&detail:nullptr;
 const uint8_t *p=bytes.data();size_t left=bytes.size();uint64_t ip=0x10000000,ok=0,bad=0,v=14695981039346656037ull,alias=0;
 while(left){
  if(cs_disasm_iter(h,&p,&left,&ip,&i)){
   ++ok;alias+=i.is_alias;mix(v,&i,offsetof(cs_insn,detail));if(with_detail)mix(v,&detail,offsetof(cs_detail,aarch64)+(arm?sizeof(detail.aarch64):sizeof(detail.mips)));
  }else{auto n=std::min(size_t(4),left);left-=n;p+=n;ip+=n;++bad;}
  mix(v,&ip,sizeof(ip));
 }
 cs_close(&h);std::printf("%llu %llu %llu %llu\n",(unsigned long long)ok,(unsigned long long)bad,(unsigned long long)alias,(unsigned long long)v);
}
