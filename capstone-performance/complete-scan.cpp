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
int main(int argc,char**argv) {
 if (argc!=3) return 1; API a(argv[1]), b(argv[2]);
 for (cs_mode mode : {CS_MODE_16,CS_MODE_32,CS_MODE_64}) {
  Machine x(a,mode,false,false,false),y(b,mode,false,false,false);
  for (unsigned prefix=0; prefix<10; ++prefix) {
   const unsigned prefixes[][4]={{0},{0x66},{0x67},{0x48},{0x41},{0x66,0x67},{0x67,0x66},{0x2e,0x48},{0x48,0x66},{0x66,0x48}};
   unsigned n=prefix==0?0:prefix<5?1:2;
   for(unsigned esc=0;esc<2;++esc) for(unsigned op=0;op<256;++op) for(unsigned mr=0;mr<256;++mr){
    uint8_t code[20];for(auto &v:code)v=(uint8_t)random_word();for(unsigned i=0;i<n;++i)code[i]=prefixes[prefix][i];unsigned start=n;if(esc)code[start++]=0x0f;code[start++]=op;code[start++]=mr;
    for(unsigned sib:{0u,5u,0x25u,0xffu}) { code[start]=(uint8_t)sib;compare(x,y,code,15,false);compare(x,y,code,(mr+op+sib+prefix)%16,false); }
   }
  }
  for(unsigned i=0;i<180000;++i){uint8_t code[24];for(auto &v:code)v=(uint8_t)random_word();unsigned n=i%18;for(unsigned j=0;j<n;++j)code[j]=j&1?0x66:0x67;compare(x,y,code,i%24,false);}
 }
 std::printf("equal public records, boundaries and errors for %llu inputs\n",(unsigned long long)verified);
}
