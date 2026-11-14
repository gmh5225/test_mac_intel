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
  open=(decltype(open))dlsym(library,"cs_open");close=(decltype(close))dlsym(library,"cs_close");option=(decltype(option))dlsym(library,"cs_option");iter=(decltype(iter))dlsym(library,"cs_test_owned_iter");error=(decltype(error))dlsym(library,"cs_errno");
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
 if(argc!=3)return 1;API a(argv[1]),b(argv[2]);if(a.iter==b.iter)return 4;

 using Hit=bool(*)(csh,const uint8_t*,size_t,cs_insn*);
 auto hit=(Hit)dlsym(b.library,"cs_test_owned_hit");
 if(!hit)throw std::runtime_error("missing owned hit export");
 {
  Machine m(b,CS_MODE_64,true,true,false);
  cs_insn insn{};cs_detail detail{};insn.detail=&detail;
  const uint8_t bytes[]={0xf3,0x0f,0x6f,0x58,0x10};
  if(!hit(m.handle,bytes,sizeof(bytes),&insn))
   throw std::runtime_error("candidate fast path was not exercised");
 }
 for(cs_mode mode:{CS_MODE_64,CS_MODE_32,CS_MODE_16})for(unsigned flags=0;flags<8;++flags) {
  bool text=flags&1,detail=flags&2,skip=flags&4;Machine x(a,mode,text,detail,skip),y(b,mode,text,detail,skip);uint8_t bytes[15];
  for(unsigned mandatory:{0u,0x66u,0xf3u,0xf2u})for(unsigned prefix=0;prefix<=(mode==CS_MODE_64?16u:0u);++prefix)
   for(unsigned op:{0x10u,0x11u,0x28u,0x29u,0x6fu,0x7fu})
    for(unsigned mr=0;mr<256;++mr)for(unsigned sb=0;sb<((mr&7)==4?256u:1u);++sb) {
     for(auto &v:bytes)v=(uint8_t)random_word();unsigned k=0;
     if(mandatory)bytes[k++]=mandatory;
     if(prefix)bytes[k++]=0x3f+prefix;
     bytes[k++]=0x0f;bytes[k++]=op;bytes[k++]=mr;
     if((mr&7)==4)bytes[k++]=sb;
     compare(x,y,bytes,15,detail);compare(x,y,bytes,random_word()%11,detail);
    }
  for(unsigned n=0;n<65536;++n) {
   for(auto &v:bytes)v=(uint8_t)random_word();
   unsigned off=n%8==0?1:n%8==1?2:0;
   unsigned k=off;
   if(n&1)bytes[k++]=(n&2)?0xf3:0x66;
   if(n&4)bytes[k++]=0x40|((n>>8)&15);
   bytes[k++]=0x0f;bytes[k++]=(n&16)?0x10+(n%4):0x6f+(n%17);
   if(off)bytes[0]=n&32?0xf0:0x64;
   if(off==2)bytes[1]=n&64?0xf2:0x67;
   compare(x,y,bytes,n%16,detail);
  }
 }
 std::printf("equal private-entry records, cursor and errors for %llu inputs\n",(unsigned long long)verified);
}
