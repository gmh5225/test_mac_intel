#include <capstone/capstone.h>
#include <dlfcn.h>
#include <sys/mman.h>
#include <unistd.h>
#include <array>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <stdexcept>

struct API {
 void *library;
 decltype(&cs_open) open; decltype(&cs_close) close; decltype(&cs_option) option;
 decltype(&cs_disasm_iter) iter; decltype(&cs_errno) error;
 using Hit=bool(*)(csh,const uint8_t*,size_t,cs_insn*); Hit hit;
 explicit API(const char *file) {
  library=dlopen(file,RTLD_NOW|RTLD_LOCAL);if(!library)throw std::runtime_error(dlerror());
  open=(decltype(open))dlsym(library,"cs_open");close=(decltype(close))dlsym(library,"cs_close");
  option=(decltype(option))dlsym(library,"cs_option");iter=(decltype(iter))dlsym(library,"cs_test_owned_iter");
  error=(decltype(error))dlsym(library,"cs_errno");hit=(Hit)dlsym(library,"cs_test_owned_hit");
  if(!open||!close||!option||!iter||!error||!hit)throw std::runtime_error("missing API");
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
static uint64_t verified=0,hits=0,guarded=0;
static void compare(Machine&a,Machine&b,const uint8_t*code,unsigned n,bool allocated=true) {
 Machine*sides[]={&a,&b};cs_insn insns[2];cs_detail extra[2];bool result[2];cs_err error[2];
 uint64_t pc=(uint64_t(word)<<32)|~word,ip[2]={pc,pc};size_t left[2]={n,n};const uint8_t*cursor[2]={code,code};
 for(unsigned i=0;i<2;++i){
  auto&d=*sides[i];auto&insn=insns[i];std::memset(&insn,word,sizeof(insn));std::memset(&extra[i],word,sizeof(extra[i]));
  insn.illegal=insn.is_alias=insn.usesAliasDetails=false;insn.detail=allocated?&extra[i]:nullptr;
  result[i]=d.api.iter(d.handle,&cursor[i],&left[i],&ip[i],&insn);error[i]=d.api.error(d.handle);
  if(insn.detail!=(allocated?&extra[i]:nullptr))throw std::runtime_error("detail pointer");insn.detail=nullptr;
 }
 if(result[0]!=result[1]||error[0]!=error[1]||ip[0]!=ip[1]||left[0]!=left[1]||cursor[0]!=cursor[1]||
    std::memcmp(insns,insns+1,sizeof(cs_insn))||(allocated&&std::memcmp(extra,extra+1,sizeof(cs_detail)))){
  std::fprintf(stderr,"mismatch after %llu at ",(unsigned long long)verified);for(unsigned i=0;i<n;++i)std::fprintf(stderr,"%02x",code[i]);
  std::fprintf(stderr," ids %u,%u text [%s] [%s]\n",insns[0].id,insns[1].id,insns[0].op_str,insns[1].op_str);
  if(allocated)for(unsigned i=0;i<sizeof(cs_detail);++i)if(((uint8_t*)extra)[i]!=((uint8_t*)(extra+1))[i])std::fprintf(stderr,"detail byte %u: %02x %02x\n",i,((uint8_t*)extra)[i],((uint8_t*)(extra+1))[i]);
  std::exit(3);
 }
 ++verified;
}
int main(int argc,char**argv){
 if(argc!=3)return 1;API a(argv[1]),b(argv[2]);if(a.iter==b.iter)return 4;
 const size_t page=(size_t)sysconf(_SC_PAGESIZE);
 auto memory=(uint8_t*)mmap(nullptr,page*2,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANON,-1,0);
 if(memory==MAP_FAILED||mprotect(memory+page,page,PROT_NONE))return 5;
 for(bool detail:{false,true}){
  Machine x(a,CS_MODE_64,true,detail,false),y(b,CS_MODE_64,true,detail,false);
  for(unsigned pp:{1u,2u})for(unsigned store=0;store<2;++store)for(unsigned ll=0;ll<3;++ll)
   for(unsigned ext=0;ext<16;++ext)for(unsigned mr=0;mr<192;++mr) {
    bool sib=(mr&7)==4;unsigned mod=mr>>6,ds=mod==2||(!mod&&(mr&7)==5)?4:mod,len=6+sib+ds;
    uint8_t bytes[15]={0x62,uint8_t(ext<<4|1),uint8_t(0xfc|pp),uint8_t(ll<<5|8),uint8_t(0x6f|store<<4),uint8_t(mr),0x24};
    cs_insn out{};cs_detail data{};out.detail=detail?&data:nullptr;
    bool candidate=b.hit(y.handle,bytes,len,&out),base=a.hit(x.handle,bytes,len,&out);
    if(base)throw std::runtime_error("unexpected baseline packed move hit");
    bool admitted=!sib || !(~ext & 4);
    if(candidate!=admitted)throw std::runtime_error("admission projection mismatch");
    hits+=candidate;
    for(unsigned n=0;n<(ds==1?256u:ds==4?32u:1u);++n){
     static const uint32_t edges[]={0,1,9,10,0x7f,0x80,0xff,0x80000000,0x7fffffff,0xffffffff};
     uint32_t v=ds==1?n:n<10?edges[n]:random_word();
     for(unsigned j=0;j<4;++j)bytes[6+sib+j]=uint8_t(v>>(8*j));
     compare(x,y,bytes,len);compare(x,y,bytes,15,!detail?false:true);
    }
    for(unsigned n=0;n<=len;++n){auto input=memory+page-n;std::memcpy(input,bytes,n);compare(x,y,input,n);++guarded;}
   }
 }
 for(unsigned mode:{unsigned(CS_MODE_64),unsigned(CS_MODE_32),unsigned(CS_MODE_16),unsigned(CS_MODE_32|CS_MODE_64),unsigned(CS_MODE_16|CS_MODE_64)})
  for(unsigned flags=0;flags<8;++flags){
   Machine x(a,cs_mode(mode),flags&1,flags&2,flags&4),y(b,cs_mode(mode),flags&1,flags&2,flags&4);
   for(unsigned n=0;n<65536;++n){
    uint8_t bytes[15];for(auto &v:bytes)v=(uint8_t)random_word();
    bytes[0]=0x62;bytes[1]=uint8_t(1|((n>>4)&0xf0));bytes[2]=uint8_t(0xfd+(n&1));bytes[3]=uint8_t(8|((n>>1)&0x60));bytes[4]=uint8_t(0x6f|((n>>2)&0x10));bytes[5]=uint8_t(n);
    if(n&0x1000)bytes[1+(n%4)]=uint8_t(n>>8);
    if(n&0x2000){std::memmove(bytes+1,bytes,14);static const uint8_t prefixes[]={0x66,0x67,0x64,0x48};bytes[0]=prefixes[n%4];}
    unsigned len=n%16;auto input=memory+page-len;std::memcpy(input,bytes,len);compare(x,y,input,len);++guarded;
   }
  }
 // Every SIB encoding and effective index extension, including fallback forms.
 {Machine x(a,CS_MODE_64,true,true,false),y(b,CS_MODE_64,true,true,false);
  for(unsigned ext=0;ext<16;++ext)for(unsigned sib=0;sib<256;++sib)for(unsigned mod=0;mod<3;++mod)
   for(unsigned ll=0;ll<3;++ll)for(unsigned pp:{1u,2u})for(unsigned store=0;store<2;++store){
    uint8_t bytes[]={0x62,uint8_t(ext<<4|1),uint8_t(0xfc|pp),uint8_t(ll<<5|8),uint8_t(0x6f|store<<4),uint8_t(mod<<6|0x1c),uint8_t(sib),0x80,0,0,0x80};
    compare(x,y,bytes,sizeof(bytes));
   }
  // Option changes must select the established slow path without stale detail.
  for(unsigned option=0;option<4;++option){
   if(option==0){a.option(x.handle,CS_OPT_SYNTAX,CS_OPT_SYNTAX_ATT);b.option(y.handle,CS_OPT_SYNTAX,CS_OPT_SYNTAX_ATT);}
   if(option==1){a.option(x.handle,CS_OPT_SYNTAX,CS_OPT_SYNTAX_INTEL);b.option(y.handle,CS_OPT_SYNTAX,CS_OPT_SYNTAX_INTEL);a.option(x.handle,CS_OPT_UNSIGNED,CS_OPT_ON);b.option(y.handle,CS_OPT_UNSIGNED,CS_OPT_ON);}
   if(option==2){cs_opt_mnem m={X86_INS_VMOVDQU64,"custom_move"};a.option(x.handle,CS_OPT_MNEMONIC,(size_t)&m);b.option(y.handle,CS_OPT_MNEMONIC,(size_t)&m);}
   if(option==3){a.option(x.handle,CS_OPT_TEXT,CS_OPT_OFF);b.option(y.handle,CS_OPT_TEXT,CS_OPT_OFF);}
   for(unsigned n=0;n<256;++n){uint8_t bytes[]={0x62,0xf1,0xfe,0x48,0x6f,0x58,uint8_t(n)};compare(x,y,bytes,sizeof(bytes));}
  }
 }
 munmap(memory,page*2);
 std::printf("equal private-entry full records, cursor and errors for %llu inputs; %llu new admitted forms; %llu protected-page extents\n",(unsigned long long)verified,(unsigned long long)hits,(unsigned long long)guarded);
}
