#include <capstone/capstone.h>
#include <sys/mman.h>
#include <unistd.h>
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

int main(int argc,char **argv) {
 if(argc!=3)return 1;API a(argv[1]),b(argv[2]);if(a.iter==b.iter)return 4;
 using Hit=bool(*)(csh,const uint8_t*,size_t,cs_insn*);
 auto hit=(Hit)dlsym(b.library,"cs_test_owned_hit");
 if(!hit)throw std::runtime_error("missing owned hit export");
 for(cs_mode mode:{CS_MODE_32,CS_MODE_64}) {
  Machine m(b,mode,true,true,false);cs_insn insn{};cs_detail detail{};insn.detail=&detail;
  for(const auto &bytes:std::array<std::array<uint8_t,7>,4>{{
   {0xa8,0x80,0,0,0,0,0},{0xa9,0xff,0xff,0xff,0xff,0,0},
   {0xf6,0xc4,0x80,0,0,0,0},{0xf7,0xc3,0xff,0xff,0xff,0xff,0}}}) {
   if(!hit(m.handle,bytes.data(),bytes.size(),&insn)||detail.x86.operands[0].access!=CS_AC_READ)
    throw std::runtime_error("read-only TEST fast path was not exercised");
  }
 }
 const size_t page=(size_t)sysconf(_SC_PAGESIZE);
 auto memory=(uint8_t*)mmap(nullptr,page*2,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANON,-1,0);
 if(memory==MAP_FAILED||mprotect(memory+page,page,PROT_NONE))return 5;
 for(cs_mode mode:{CS_MODE_16,CS_MODE_32,CS_MODE_64})for(unsigned flags=0;flags<8;++flags) {
  const bool text=flags&1,detail=flags&2,skip=flags&4;
  Machine x(a,mode,text,detail,skip),y(b,mode,text,detail,skip);
  for(unsigned prefix=0;prefix<32;++prefix)for(uint8_t opcode:{0xa8,0xa9,0xf6,0xf7})
   for(unsigned mr=0;mr<256;++mr)for(uint32_t value:{0u,9u,10u,0x80u,0xffu,0x80000000u,0xffffffffu}) {
    uint8_t bytes[15];for(auto &v:bytes)v=(uint8_t)random_word();
    unsigned length=0;
    if(prefix>0 && prefix<17)bytes[length++]=(uint8_t)(0x3f+prefix);
    else if(prefix>=17) {
     const uint8_t prefixes[]={0x66,0x67,0xf0,0xf2,0xf3,0x64,0x65,0x66,0x67,0xf0,0xf2,0xf3,0x64,0x65,0x48};
     bytes[length++]=prefixes[prefix-17];
     if(prefix>=24)bytes[length++]=0x48;
    }
    bytes[length++]=opcode;
    if(opcode>=0xf6)bytes[length++]=(uint8_t)mr;
    for(unsigned j=0;j<4;++j)bytes[length++]=(uint8_t)(value>>(8*j));
    compare(x,y,bytes,length,detail);
    unsigned cut=random_word()%(length+1);
    auto input=memory+page-cut;std::memcpy(input,bytes,cut);
    compare(x,y,input,cut,detail);
   }
 }
 munmap(memory,page*2);
 std::printf("equal TEST private-entry records, cursor and errors for %llu inputs including guarded truncations\n",(unsigned long long)verified);
}
