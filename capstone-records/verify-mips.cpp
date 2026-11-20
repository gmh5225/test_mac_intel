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
static uint64_t verified=0, corrected=0;
static void compare(Machine&a, Machine&b,const uint8_t*code,unsigned n,unsigned flags,cs_mode mode) {
 bool detail=flags&2;
 Machine* sides[]={&a,&b};cs_insn insns[2];cs_detail extra[2];bool result[2];cs_err error[2];uint64_t pc0=(uint64_t(word)<<32)|~word,ip[2]={pc0,pc0};size_t left[2]={n,n};const uint8_t*cursor[2]={code,code};
 for(unsigned i=0;i<2;++i) {
  auto &d=*sides[i];auto &insn=insns[i];std::memset(&insn,word,sizeof(insn));std::memset(&extra[i],word,sizeof(extra[i]));insn.illegal=insn.is_alias=insn.usesAliasDetails=false;insn.detail=detail ? &extra[i] : nullptr;
  result[i]=d.api.iter(d.handle,&cursor[i],&left[i],&ip[i],&insn);error[i]=d.api.error(d.handle);if(insn.detail!=(detail?&extra[i]:nullptr))throw std::runtime_error("detail pointer");insn.detail=nullptr;
 }
 const unsigned first=n>=2 ? ((mode & CS_MODE_BIG_ENDIAN) ? (unsigned(code[0])<<8)|code[1] : (unsigned(code[1])<<8)|code[0]) : 0;
 if ((mode & CS_MODE_NMS1)==CS_MODE_NMS1 && (first & 0xfc00)==0xd800 && (first & 15)) {
  const bool skip=(flags & 4) && n>=4;
  const unsigned id=((first>>4)&7) < ((first>>7)&7) ? MIPS_INS_BEQC : MIPS_INS_BNEC;
  const unsigned amount=skip?4:0;
  if(!result[0] || insns[0].id!=id || insns[0].size!=2 || left[0]!=n-2 || cursor[0]!=code+2 || ip[0]!=pc0+2 ||
     result[1]!=skip || left[1]!=n-amount || cursor[1]!=code+amount || ip[1]!=pc0+amount ||
     (skip && (insns[1].id!=0 || insns[1].size!=4 || std::memcmp(insns[1].bytes,code,4)))) {
   std::fprintf(stderr,"unexpected NMS1 branch result at %04x, %u available, flags %u\\n",first,n,flags);
   std::exit(4);
  }
  ++corrected;
  return;
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
 if(!corrected)return 5;
 std::printf("verified %llu expected NMS1 corrections\\n",(unsigned long long)corrected);
 std::printf("verified %llu raw records\n",(unsigned long long)verified);
}
