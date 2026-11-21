#include <capstone/capstone.h>
#include <dlfcn.h>
#include <array>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <stdexcept>

struct API {
 void *library;
 decltype(&cs_open) open;
 decltype(&cs_close) close;
 decltype(&cs_option) option;
 decltype(&cs_disasm_iter) iter;
 decltype(&cs_errno) error;
 explicit API(const char *file) {
  library=dlopen(file,RTLD_NOW|RTLD_LOCAL);if(!library)throw std::runtime_error(dlerror());
  open=(decltype(open))dlsym(library,"cs_open");close=(decltype(close))dlsym(library,"cs_close");option=(decltype(option))dlsym(library,"cs_option");iter=(decltype(iter))dlsym(library,"cs_disasm_iter");error=(decltype(error))dlsym(library,"cs_errno");
  if(!open||!close||!option||!iter||!error)throw std::runtime_error("missing API");
 }
};
struct Machine {
 API &api;csh handle=0;
 Machine(API&a,cs_mode mode,bool text,bool detail,bool skip):api(a){
  if(a.open(CS_ARCH_MIPS,mode,&handle)||a.option(handle,CS_OPT_TEXT,text?CS_OPT_ON:CS_OPT_OFF)||a.option(handle,CS_OPT_DETAIL,detail?CS_OPT_ON:CS_OPT_OFF)||a.option(handle,CS_OPT_SKIPDATA,skip?CS_OPT_ON:CS_OPT_OFF))throw std::runtime_error("open or option");
 }
 ~Machine(){api.close(&handle);}
};
static uint32_t word=0x87544a39;
static uint32_t random_word(){word^=word<<13;word^=word>>17;word^=word<<5;return word;}
static uint64_t verified=0;
static void compare(Machine&a, Machine&b,const uint8_t*code,unsigned n,unsigned flags,cs_mode mode) {
 bool detail=flags&2;
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
int main(int argc,char **argv) {
 API a(argv[1]),b(argv[2]);
 for(unsigned mode:{unsigned(CS_MODE_MIPS32),unsigned(CS_MODE_MIPS64),unsigned(CS_MODE_MIPS32R6),unsigned(CS_MODE_MIPS2),unsigned(CS_MODE_MIPS32R2),unsigned(CS_MODE_MIPS64R2),unsigned(CS_MODE_MIPS32|CS_MODE_MIPS32R2),unsigned(CS_MODE_MIPS64|CS_MODE_MIPS64R2),unsigned(CS_MODE_MIPS32|CS_MODE_MIPS64R2),unsigned(CS_MODE_MIPS32R2|CS_MODE_MIPS64R2),unsigned(CS_MODE_MIPS64R2|CS_MODE_MIPS_PTR64),unsigned(CS_MODE_MIPS64R5),unsigned(CS_MODE_MICRO|CS_MODE_MIPS32R2),unsigned(CS_MODE_MIPS32R2|CS_MODE_MIPS16),unsigned(CS_MODE_MIPS32R2|CS_MODE_MIPS64),unsigned(CS_MODE_MIPS32|CS_MODE_MIPS64|CS_MODE_MIPS32R2|CS_MODE_MIPS64R2),unsigned(CS_MODE_MIPS32|CS_MODE_MIPS64),unsigned(CS_MODE_MIPS32R6|CS_MODE_MIPS_NOFLOAT),unsigned(CS_MODE_NANOMIPS),unsigned(CS_MODE_NANOMIPS|CS_MODE_I7200),unsigned(CS_MODE_NANOMIPS|CS_MODE_NMS1),unsigned(CS_MODE_OCTEON),unsigned(CS_MODE_OCTEONP),0u})
 for(unsigned endian:{0u,unsigned(CS_MODE_BIG_ENDIAN)}) {
  cs_mode m=cs_mode(mode|endian);
  for(unsigned flags=0;flags<8;++flags) {
   bool detail=flags&2;Machine x(a,m,flags&1,detail,flags&4),y(b,m,flags&1,detail,flags&4);
   for(unsigned i=0;i<65536;++i) {
    unsigned word=i*2654435761u;uint8_t bytes[8]={};
    for(unsigned j=0;j<4;++j)bytes[endian?3-j:j]=uint8_t(word>>(8*j));
    compare(x,y,bytes,(i&31)<5?(i&31):8,flags,m);
   }
  }
 }
 for (cs_mode profile : {CS_MODE_NANOMIPS, CS_MODE_NMS1, CS_MODE_I7200}) {
  for (unsigned endian : {0u,unsigned(CS_MODE_BIG_ENDIAN)}) for(unsigned flags=0;flags<8;++flags) {
   const auto mode=cs_mode(unsigned(profile)|endian);
   Machine x(a,mode,flags&1,flags&2,flags&4), y(b,mode,flags&1,flags&2,flags&4);
   for(unsigned value=0;value<=0xffff;++value) {
    uint8_t bytes[2];bytes[endian?1:0]=uint8_t(value);bytes[endian?0:1]=uint8_t(value>>8);
    compare(x,y,bytes,2,flags,mode);
    uint8_t wide[6]={bytes[0],bytes[1],uint8_t(value>>3),uint8_t(value>>7),uint8_t(~value),uint8_t(value>>5)};
    for(unsigned extent=3;extent<=6;++extent) compare(x,y,wide,extent,flags,mode);
   }
  }
 }
 std::printf("verified %llu raw records\n",(unsigned long long)verified);
}
