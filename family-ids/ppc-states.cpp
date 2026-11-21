#include <capstone/capstone.h>
#include <dlfcn.h>
#include <array>
#include <cstddef>
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
  if(a.open(arch,mode,&handle)||a.option(handle,CS_OPT_TEXT,text?CS_OPT_ON:CS_OPT_OFF)||a.option(handle,CS_OPT_DETAIL,detail?CS_OPT_ON:CS_OPT_OFF)||a.option(handle,CS_OPT_SKIPDATA,skip?CS_OPT_ON:CS_OPT_OFF)){std::fprintf(stderr,"open/option arch %u mode %#x\n",unsigned(arch),unsigned(mode));throw std::runtime_error("open or option");}
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
  std::fprintf(stderr,"mismatch after %llu at ",(unsigned long long)verified);for(unsigned i=0;i<n;++i)std::fprintf(stderr,"%02x",code[i]);std::fprintf(stderr," sizes %zu,%zu ids %u,%u\n",left[0],left[1],insns[0].id,insns[1].id);std::fprintf(stderr,"insn text: [%s] [%s] vs [%s] [%s]\n",insns[0].mnemonic,insns[0].op_str,insns[1].mnemonic,insns[1].op_str);
  for(size_t k=0;k<sizeof(cs_insn);++k)if(((uint8_t*)&insns[0])[k]!=((uint8_t*)&insns[1])[k])std::fprintf(stderr,"insn[%zu] %02x %02x\n",k,((uint8_t*)&insns[0])[k],((uint8_t*)&insns[1])[k]);
  if(detail)for(size_t k=0;k<sizeof(cs_detail);++k)if(((uint8_t*)&extra[0])[k]!=((uint8_t*)&extra[1])[k])std::fprintf(stderr,"detail[%zu] %02x %02x\n",k,((uint8_t*)&extra[0])[k],((uint8_t*)&extra[1])[k]);
  std::fprintf(stderr,"tricore offset=%zu op_count=%zu operands=%zu operand_size=%zu\n",offsetof(cs_detail,tricore),offsetof(cs_tricore,op_count),offsetof(cs_tricore,operands),sizeof(cs_tricore_op));
  std::exit(3);
 }
 ++verified;
}
int main(int argc,char**argv) {
 if(argc!=3 && argc!=4)return 1; const unsigned iterations=argc==4?std::stoul(argv[3]):32768;API a(argv[1]),b(argv[2]);
 struct Target {cs_arch arch; unsigned mode;};
 std::vector<Target> targets;
 auto add=[&](cs_arch arch,std::initializer_list<unsigned> modes) {for(unsigned mode:modes)targets.push_back({arch,mode});};
 add(CS_ARCH_PPC,{CS_MODE_32,CS_MODE_32|CS_MODE_BIG_ENDIAN,CS_MODE_64,CS_MODE_64|CS_MODE_BIG_ENDIAN,CS_MODE_64|CS_MODE_QPX|CS_MODE_BIG_ENDIAN,CS_MODE_32|CS_MODE_SPE|CS_MODE_BIG_ENDIAN,CS_MODE_32|CS_MODE_BOOKE|CS_MODE_BIG_ENDIAN,CS_MODE_32|CS_MODE_PS|CS_MODE_BIG_ENDIAN});
 for (Target target : targets) for(unsigned flags=0; flags<16; ++flags) {
  unsigned bits=target.mode;
  cs_mode mode=(cs_mode)bits;
  std::fprintf(stderr,"case arch=%u mode=%#x flags=%u\n",unsigned(target.arch),bits,flags);
  bool text=flags&1,detail=flags&2,skip=flags&4;
  Machine x(a,target.arch,mode,text,detail,skip),y(b,target.arch,mode,text,detail,skip);
  if(flags&8){a.option(x.handle,CS_OPT_DETAIL,detail?(CS_OPT_ON|CS_OPT_DETAIL_REAL):CS_OPT_OFF);b.option(y.handle,CS_OPT_DETAIL,detail?(CS_OPT_ON|CS_OPT_DETAIL_REAL):CS_OPT_OFF);}
  for(unsigned i=0;i<iterations;++i){
    uint8_t bytes[16];for(unsigned q=0;q<16;++q)bytes[q]=uint8_t(random_word());
    compare(x,y,bytes,(i&31)<16?(i&31):16,detail);
  }
 }
 std::printf("equal nine additional ISA public records, cursor and errors for %llu inputs\n",(unsigned long long)verified);
}
