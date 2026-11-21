#include <sys/mman.h>
#include <unistd.h>
#include <capstone/capstone.h>
#include <dlfcn.h>
#include <array>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <stdexcept>

#include "arch/X86/X86ScanAdapter.h"
struct API {
 decltype(&cs_open) open=cs_open;
 decltype(&cs_close) close=cs_close;
 decltype(&cs_option) option=cs_option;
 decltype(&cs_errno) error=cs_errno;
 decltype(&cs_disasm_iter) iter;
};
struct Machine {
 API &api;csh handle=0;
 Machine(API&a,cs_mode mode,bool text,bool detail,bool skip):api(a){
  if(a.open(CS_ARCH_X86,mode,&handle)||a.option(handle,CS_OPT_TEXT,text?CS_OPT_ON:CS_OPT_OFF)||a.option(handle,CS_OPT_DETAIL,detail?CS_OPT_ON:CS_OPT_OFF)||a.option(handle,CS_OPT_SKIPDATA,skip?CS_OPT_ON:CS_OPT_OFF))throw std::runtime_error("open or option");
 }
 ~Machine(){api.close(&handle);}
};
static uint32_t word=0x87544a39;
static uint32_t random_word(){word^=word<<13;word^=word>>17;word^=word<<5;return word;}
static uint64_t verified=0;
static void compare(Machine&a, Machine&b,const uint8_t*code,unsigned n,bool detail) {
 Machine* sides[]={&a,&b};cs_insn insns[2];cs_detail extra[2];bool result[2];cs_err error[2];uint64_t pc0=(uint64_t(word)<<32)|~word,ip[2]={pc0,pc0};size_t left[2]={n,n};const uint8_t*cursor[2]={code,code};
 for(unsigned i=0;i<2;++i) {
  auto &d=*sides[i];auto &insn=insns[i];std::memset(&insn,word,sizeof(insn));std::memset(&extra[i],word,sizeof(extra[i]));insn.illegal=insn.is_alias=insn.usesAliasDetails=false;insn.detail=detail ? &extra[i] : nullptr;
  result[i]=d.api.iter(d.handle,&cursor[i],&left[i],&ip[i],&insn);error[i]=d.api.error(d.handle);if(insn.detail!=(detail?&extra[i]:nullptr))throw std::runtime_error("detail pointer");insn.detail=nullptr;
 }
 if(result[0]!=result[1]||error[0]!=error[1]||ip[0]!=ip[1]||left[0]!=left[1]||cursor[0]!=cursor[1]||std::memcmp(insns,insns+1,sizeof(cs_insn))||(detail&&std::memcmp(extra,extra+1,sizeof(cs_detail)))){
  std::fprintf(stderr,"mismatch after %llu at ",(unsigned long long)verified);for(unsigned i=0;i<n;++i)std::fprintf(stderr,"%02x",code[i]);std::fprintf(stderr," sizes %zu,%zu ids %u,%u\n",left[0],left[1],insns[0].id,insns[1].id);std::exit(3);
 }
 ++verified;
}
int main() {
 API a{},b{};a.iter=cs_disasm_iter;b.iter=X86_disasmIterText;
 const size_t page=(size_t)sysconf(_SC_PAGESIZE);
 auto memory=(uint8_t*)mmap(nullptr,page*2,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANON,-1,0);
 if(memory==MAP_FAILED||mprotect(memory+page,page,PROT_NONE))return 5;
 for(cs_mode mode:{CS_MODE_16,CS_MODE_32,CS_MODE_64})for(unsigned flags=0;flags<8;++flags){
  bool text=flags&1,detail=flags&2,skip=flags&4;Machine x(a,mode,text,detail,skip),y(b,mode,text,detail,skip);
  cs_opt_mnem canonical{X86_INS_UD2,"ud2"};if(cs_option(x.handle,CS_OPT_MNEMONIC,(size_t)&canonical)!=CS_ERR_OK)return 7;
  for(unsigned n=0;n<8192;++n){
   uint8_t bytes[15];for(auto &v:bytes)v=(uint8_t)random_word();unsigned k=0;
   const unsigned op[]={0xef,0xfe,0xd4,0x44,0x25,0x00,0x19,0x1b,0x39,0x3b,0x71,0x72,0x73};
   if(n%8==7){unsigned pos=0;if(mode==CS_MODE_64 && (n&8))bytes[pos++]=(uint8_t)(0x40|((n>>4)&15));bytes[pos++]=0xff;bytes[pos++]=(uint8_t)((n>>3)&0xff);}
   else if(n%4==3){const uint8_t lead[]={0xc6,0xc7,0x0f,0xff,0x66,0x48,0x83,0x8d};bytes[0]=lead[(n>>2)&7];}else if(n%4==0){bytes[0]=0x62;bytes[1]=(n&0xf0)|(1+(n/3)%3);bytes[2]=((n>>4)&0xf8)|5;
    bytes[3]=((n>>2)&0x60)|8;bytes[4]=op[(n>>8)%13];bytes[5]=(uint8_t)(n>>1);
   }else if(n%4==1){bytes[0]=0xc5;bytes[1]=(uint8_t)(n>>4);bytes[2]=op[(n>>8)%13];bytes[3]=(uint8_t)(n>>1);}
   else{bytes[0]=0xc4;bytes[1]=(n&0xe0)|(1+(n/3)%3);bytes[2]=(uint8_t)(n>>4);bytes[3]=op[(n>>8)%13];bytes[4]=(uint8_t)(n>>1);}
   for(unsigned length=0;length<=15;++length){auto input=memory+page-length;std::memcpy(input,bytes,length);compare(x,y,input,length,detail);}
  }
 }

 munmap(memory,page*2);
 std::printf("equal private-entry records for %llu protected-page extents\n",(unsigned long long)verified);
}
