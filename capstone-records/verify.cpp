#include <capstone/capstone.h>
#include <dlfcn.h>
#include <array>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <stdexcept>
#include <vector>

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
 Machine(API&a,cs_arch arch,cs_mode mode,bool text,bool detail,bool skip):api(a){
  if(a.open(arch,mode,&handle)||a.option(handle,CS_OPT_TEXT,text?CS_OPT_ON:CS_OPT_OFF)||a.option(handle,CS_OPT_DETAIL,detail?CS_OPT_ON:CS_OPT_OFF)||a.option(handle,CS_OPT_SKIPDATA,skip?CS_OPT_ON:CS_OPT_OFF))throw std::runtime_error("open or option");
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
 if(argc!=3 && argc!=4)return 1; const unsigned iterations=argc==4?std::stoul(argv[3]):65536;API a(argv[1]),b(argv[2]);
 struct Target {cs_arch arch; unsigned mode;};
 std::vector<Target> targets={{CS_ARCH_AARCH64,0},{CS_ARCH_AARCH64,CS_MODE_BIG_ENDIAN}};
 const unsigned mips_modes[]={
 CS_MODE_MIPS1,CS_MODE_MIPS2,CS_MODE_MIPS3,CS_MODE_MIPS4,CS_MODE_MIPS5,
 CS_MODE_MIPS32,CS_MODE_MIPS32R2,CS_MODE_MIPS32R3,CS_MODE_MIPS32R5,CS_MODE_MIPS32R6,
 CS_MODE_MIPS64,CS_MODE_MIPS64R2,CS_MODE_MIPS64R3,CS_MODE_MIPS64R5,CS_MODE_MIPS64R6,
 CS_MODE_MIPS16,CS_MODE_MICRO|CS_MODE_MIPS32,CS_MODE_MICRO32R3,CS_MODE_MICRO32R6,
 CS_MODE_NANOMIPS,CS_MODE_NMS1,CS_MODE_I7200,CS_MODE_OCTEON,CS_MODE_OCTEONP,
 CS_MODE_MIPS64|CS_MODE_MIPS_PTR64,CS_MODE_MIPS32R6|CS_MODE_MIPS_PTR64|CS_MODE_MIPS_NOFLOAT
 };
 for(unsigned mode:mips_modes)for(unsigned big:{0u,static_cast<unsigned>(CS_MODE_BIG_ENDIAN)})targets.push_back({CS_ARCH_MIPS,mode|big});
 for (Target target : targets) for(unsigned flags=0; flags<16; ++flags) {
  unsigned bits=target.mode;
  cs_mode mode=(cs_mode)bits;
  bool text=flags&1,detail=flags&2,skip=flags&4;
  Machine x(a,target.arch,mode,text,detail,skip),y(b,target.arch,mode,text,detail,skip);
  if(flags&8){a.option(x.handle,CS_OPT_DETAIL,detail?(CS_OPT_ON|CS_OPT_DETAIL_REAL):CS_OPT_OFF);b.option(y.handle,CS_OPT_DETAIL,detail?(CS_OPT_ON|CS_OPT_DETAIL_REAL):CS_OPT_OFF);}
  for(unsigned i=0;i<iterations;++i){
    uint32_t value=random_word();
    if(i&1) {
      if(target.arch==CS_ARCH_AARCH64) {const uint32_t forms[]={0xaa0003e0,0x2a0003e0,0xd3400000,0x93400000,0x53000000,0x52800000,0x4e001c00,0x6e001c00};value=forms[(i>>1)&7]|(value&0x001f03ff);}
      else {const uint32_t forms[]={0x00000025,0x00000021,0x10000000,0x14000000,0x24000000,0x34000000,0x00000000,0x00000027};value=forms[(i>>1)&7]|(value&0x03ffffc0);}
    }
    uint8_t bytes[8]={};for(unsigned q=0;q<4;++q)bytes[bits&CS_MODE_BIG_ENDIAN?3-q:q]=uint8_t(value>>(8*q));
    compare(x,y,bytes,(i&31)<5?(i&31):8,detail);
  }
 }
 std::printf("equal AArch64/MIPS public records, cursor and errors for %llu inputs\n",(unsigned long long)verified);
}
