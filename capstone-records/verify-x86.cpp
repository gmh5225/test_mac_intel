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
 if(argc!=3)return 1;API a(argv[1]),b(argv[2]);if(a.iter==b.iter)return 4;
 for (cs_mode mode:{CS_MODE_64,CS_MODE_32,CS_MODE_16})for(unsigned flags=0;flags<8;++flags){
  bool text=flags&1,detail=flags&2,skip=flags&4;Machine x(a,mode,text,detail,skip), y(b,mode,text,detail,skip);uint8_t bytes[15];
  // Sweep conventional and reserved map, W, pp, vector length and ModR/M values.
  if(mode==CS_MODE_64 && !text && !detail && !skip)
   for(unsigned map=0;map<8;++map)for(unsigned p1:{0x04,0x05,0x06,0x07,0x84,0x85,0x86,0x87})for(unsigned ll=0;ll<4;++ll)for(unsigned op=0;op<256;++op)for(unsigned mr:{0,5,0x44,0x85,0xc0,0xc1,0xff}){
    for(auto &v:bytes)v=(uint8_t)random_word();bytes[0]=0x62;bytes[1]=(bytes[1]&0xf8)|map;bytes[2]=(bytes[2]&0x78)|p1;bytes[3]=(bytes[3]&0x9f)|(ll<<5);bytes[4]=op;bytes[5]=mr;compare(x,y,bytes,15,false);
   }
  if(mode==CS_MODE_32 && !text && !detail && !skip) {
    for(unsigned payload=0;payload<256;++payload) for(unsigned opcode=0;opcode<256;++opcode) for(unsigned mr=0;mr<256;mr+=3) {
     uint8_t b[15]={0xc5,uint8_t(payload),uint8_t(opcode),uint8_t(mr),uint8_t(random_word()),0x80,0x7f,0xff,0x7f,0,2,3,0,4,0};
     compare(x,y,b,15,false);compare(x,y,b,random_word()%12,false);
    }
   }
  for(unsigned i=0;i<65536;++i) {
   for(auto &v:bytes)v=(uint8_t)random_word();unsigned offset=i%8==0 ? 1 : i%8==1 ? 2 : 0;bytes[offset]=0x62;if(i%3)bytes[offset+2]|=4;
   if(offset)bytes[0]=(i&16) ? 0x67 : 0x64;if(offset==2)bytes[1]=(i&32) ? 0x48 : 0x66;
   compare(x,y,bytes,i%16,detail);
  }
 }
 std::printf("equal public records, cursor and errors for %llu inputs\n",(unsigned long long)verified);
}
