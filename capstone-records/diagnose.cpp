#include <capstone/capstone.h>
#include <dlfcn.h>
#include <array>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <stdexcept>
#include <utility>
#include <cstddef>

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
static void compare(Machine&a, Machine&b,const uint8_t*code,unsigned n,bool detail) {
 Machine* sides[]={&a,&b};cs_insn insns[2];cs_detail extra[2];bool result[2];cs_err error[2];uint64_t pc0=(uint64_t(word)<<32)|~word,ip[2]={pc0,pc0};size_t left[2]={n,n};const uint8_t*cursor[2]={code,code};
 for(unsigned i=0;i<2;++i) {
  auto &d=*sides[i];auto &insn=insns[i];std::memset(&insn,word,sizeof(insn));std::memset(&extra[i],word,sizeof(extra[i]));insn.illegal=insn.is_alias=insn.usesAliasDetails=false;insn.detail=detail ? &extra[i] : nullptr;
  result[i]=d.api.iter(d.handle,&cursor[i],&left[i],&ip[i],&insn);error[i]=d.api.error(d.handle);if(insn.detail!=(detail?&extra[i]:nullptr))throw std::runtime_error("detail pointer");insn.detail=nullptr;
 }
 if(result[0]!=result[1]||error[0]!=error[1]||ip[0]!=ip[1]||left[0]!=left[1]||cursor[0]!=cursor[1]||std::memcmp(insns,insns+1,sizeof(cs_insn))||(detail&&std::memcmp(extra,extra+1,sizeof(cs_detail)))){
  std::fprintf(stderr,"difference at %llu length %u for ",(unsigned long long)verified,n);
  for(unsigned j=0;j<n;++j)std::fprintf(stderr,"%02x",code[j]);std::fprintf(stderr,"\n");
  for(unsigned h=0;h<2;++h)std::fprintf(stderr,"side %u result %d err %d size %zu id %u addr %llx alias %d %s %s\n",h,result[h],error[h],left[h],insns[h].id,(unsigned long long)ip[h],insns[h].is_alias,insns[h].mnemonic,insns[h].op_str);
  for(auto part:{std::pair<const unsigned char*,size_t>((const unsigned char*)insns,sizeof(cs_insn)), std::pair<const unsigned char*,size_t>((const unsigned char*)extra,detail?sizeof(cs_detail):0)}) {
    unsigned count=0;for(size_t j=0;j<part.second;++j)if(part.first[j]!=part.first[j+part.second] && count++<16)std::fprintf(stderr,"%s offset %zu: %02x/%02x\n",part.first==(const unsigned char*)insns?"insn":"detail",j,part.first[j],part.first[j+part.second]);
  }
  if(verified>128)std::exit(3);

 }
 ++verified;
}
int main(int argc,char **argv) {
 API a(argv[1]),b(argv[2]);
 std::fprintf(stderr,"offsets id=%zu mnemonic=%zu op_str=%zu detail=%zu bytes=%zu\n",offsetof(cs_insn,id),offsetof(cs_insn,mnemonic),offsetof(cs_insn,op_str),offsetof(cs_insn,detail),offsetof(cs_insn,bytes));
  for(auto mode:{cs_mode(CS_MODE_MIPS64R2|CS_MODE_MIPS_PTR64),CS_MODE_MIPS64R2,CS_MODE_MIPS64})for(unsigned flags=0;flags<8;++flags) {
    bool detail=flags&2;Machine x(a,mode,flags&1,detail,flags&4),y(b,mode,flags&1,detail,flags&4);
    uint8_t bytes[]={0x10,0x9b,0x77,0xe3,0,0,0,0};
    std::fprintf(stderr,"case: mode %u flags %u\n",unsigned(mode),flags);
    compare(x,y,bytes,8,detail);
  }
}
