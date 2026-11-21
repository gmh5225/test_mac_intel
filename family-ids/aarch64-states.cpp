#include <capstone/capstone.h>
#include <dlfcn.h>
#include <array>
#include <fstream>
#include <iterator>
#include <vector>
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
 Machine(API&a,cs_mode mode,bool text,bool detail,bool skip,unsigned syntax,bool unsigned_imm):api(a){
  if(a.open(CS_ARCH_AARCH64,mode,&handle)||a.option(handle,CS_OPT_TEXT,text?CS_OPT_ON:CS_OPT_OFF)||a.option(handle,CS_OPT_DETAIL,detail?CS_OPT_ON:CS_OPT_OFF)||a.option(handle,CS_OPT_SKIPDATA,skip?CS_OPT_ON:CS_OPT_OFF))throw std::runtime_error("open or option");
  if(a.option(handle,CS_OPT_SYNTAX,syntax)||a.option(handle,CS_OPT_UNSIGNED,unsigned_imm?CS_OPT_ON:CS_OPT_OFF))throw std::runtime_error("format option");
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
 if(argc<4)return 1;API a(argv[1]),b(argv[2]);
 for (unsigned bits : {0u,(unsigned)CS_MODE_BIG_ENDIAN}) for(unsigned flags=0; flags<8; ++flags) {
  cs_mode mode=(cs_mode)bits;
  bool text=flags&1,detail=flags&2,skip=flags&4;
  Machine x(a,mode,text,detail,skip,CS_OPT_SYNTAX_DEFAULT,false),y(b,mode,text,detail,skip,CS_OPT_SYNTAX_DEFAULT,false);
  for(unsigned i=0;i<1048576;++i){
    uint32_t value=random_word();
    if((i&7)==0)value=0xd503201f;
    if((i&7)==1)value=0x91000000|(value&0x003fffff);
    uint8_t bytes[8]={};for(unsigned q=0;q<4;++q)bytes[bits&CS_MODE_BIG_ENDIAN?3-q:q]=uint8_t(value>>(8*q));
    compare(x,y,bytes,(i&31)<5?(i&31):8,detail);
  }
 }
 std::printf("equal AArch64 public records, cursor and errors for %llu inputs\n",(unsigned long long)verified);
 for (int i=3;i<argc;i++) {
   std::ifstream input(argv[i],std::ios::binary);if(!input)return 4;
   std::vector<uint8_t> bytes((std::istreambuf_iterator<char>(input)),{});
   if(bytes.empty()||bytes.size()%4)return 5;
   uint64_t start=verified;
   for(unsigned flags=0;flags<8;++flags) {
     bool text=flags&1,detail=flags&2,skip=flags&4;
     Machine left(a,CS_MODE_LITTLE_ENDIAN,text,detail,skip,CS_OPT_SYNTAX_DEFAULT,false);
     Machine right(b,CS_MODE_LITTLE_ENDIAN,text,detail,skip,CS_OPT_SYNTAX_DEFAULT,false);
     for(size_t pc=0;pc<bytes.size();pc+=4) {
       random_word();
       compare(left,right,bytes.data()+pc,4,detail);
     }
   }
   std::printf("equal real AArch64 records for %llu inputs from %s\n",(unsigned long long)(verified-start),argv[i]);
 }
}
