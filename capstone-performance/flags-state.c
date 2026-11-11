#include <capstone/capstone.h>
#include "cs_priv.h"
#include "MCInst.h"
#include <dlfcn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct {
 void *lib; csh handle;
 cs_err (*open)(cs_arch, cs_mode, csh *);
 cs_err (*option)(csh, cs_opt_type, size_t);
 cs_err (*close)(csh *);
 bool (*decode)(csh, const uint8_t *, size_t, MCInst *, uint16_t *, uint64_t, void *);
} Api;
static uint64_t compared, rng=0x5a37f8021bc9d4e6ULL;
static unsigned random32(void) { rng^=rng<<13; rng^=rng>>7; rng^=rng<<17; return (unsigned)rng; }
static void load(Api *a, const char *path) {
 a->lib=dlopen(path,RTLD_NOW|RTLD_LOCAL); if(!a->lib){fprintf(stderr,"%s\n",dlerror());exit(2);}
 #define SYM(field,name) *(void **)(&a->field)=dlsym(a->lib,name); if(!a->field)exit(2)
 SYM(open,"cs_open");SYM(option,"cs_option");SYM(close,"cs_close");SYM(decode,"X86_getInstruction");
 #undef SYM
}
static void check(Api *a, Api *b, const uint8_t *code, size_t length) {
 MCInst mi[2];cs_insn pub[2];cs_detail detail[2];uint16_t size[2]={0x9a5b,0x9a5b};bool ok[2];Api *api[2]={a,b};
 for(unsigned n=0;n<2;n++) {
  memset(&mi[n],0xa5,sizeof(mi[n]));MCInst_InitX86(&mi[n]);
  memset(&pub[n],0xa5,sizeof(pub[n]));memset(&detail[n],0xa5,sizeof(detail[n]));
  pub[n].detail=&detail[n];pub[n].address=0x140001000ULL;pub[n].size=0;
  mi[n].flat_insn=&pub[n];mi[n].csh=(cs_struct *)(uintptr_t)api[n]->handle;mi[n].address=pub[n].address;
  ok[n]=api[n]->decode(api[n]->handle,code,length,&mi[n],&size[n],pub[n].address,mi[n].csh->getinsn_info);
 }
 bool pointers=(mi[0].MRI!=NULL)==(mi[1].MRI!=NULL);
 mi[0].flat_insn=mi[1].flat_insn=NULL;mi[0].csh=mi[1].csh=NULL;mi[0].MRI=mi[1].MRI=NULL;
 pub[0].detail=pub[1].detail=NULL;
 if(!pointers||ok[0]!=ok[1]||size[0]!=size[1]||memcmp(mi,mi+1,sizeof(mi[0]))||memcmp(pub,pub+1,sizeof(pub[0]))||memcmp(detail,detail+1,sizeof(detail[0]))) {
  fprintf(stderr,"state mismatch at %llu length %zu flags %u/%u success %u/%u bytes",(unsigned long long)compared,length,mi[0].flags,mi[1].flags,ok[0],ok[1]);
  for(size_t i=0;i<length;i++)fprintf(stderr," %02x",code[i]);fprintf(stderr,"\n");exit(1);
 }
 ++compared;
}
int main(int argc,char **argv) {
 if(argc!=3)return 2;Api a={0},b={0};load(&a,argv[1]);load(&b,argv[2]);
 const cs_mode modes[]={CS_MODE_16,CS_MODE_32,CS_MODE_64};
 const uint8_t p0[]={0xf1,0xf2,0xf3,0x01,0x02,0x03,0x91,0xd1,0x61};
 const uint8_t p1[]={0x7c,0x7d,0x7e,0x7f,0xfd,0x6d,0xed,0x75};
 const uint8_t opcodes[]={0x58,0xfe,0x6f,0x10,0x2a,0x90,0x62,0x00,0xff};
 for(unsigned m=0;m<3;m++) {
  if(a.open(CS_ARCH_X86,modes[m],&a.handle)||b.open(CS_ARCH_X86,modes[m],&b.handle))return 2;
  for(unsigned d=0;d<2;d++) {
   if(a.option(a.handle,CS_OPT_DETAIL,d?CS_OPT_ON:CS_OPT_OFF)||b.option(b.handle,CS_OPT_DETAIL,d?CS_OPT_ON:CS_OPT_OFF))return 2;
   uint8_t code[16];
   for(unsigned value=0;value<65536;value++) {
    memset(code,0,sizeof(code));code[0]=value;code[1]=value>>8;code[2]=0xc0;check(&a,&b,code,16);
    code[0]=0xc5;code[1]=value;code[2]=value>>8;code[3]=0xc0;check(&a,&b,code,16);
   }
   for(unsigned i=0;i<sizeof(p0);i++)for(unsigned j=0;j<sizeof(p1);j++)for(unsigned bits=0;bits<256;bits++)for(unsigned k=0;k<sizeof(opcodes);k++) {
    memset(code,0,sizeof(code));code[0]=0x62;code[1]=p0[i];code[2]=p1[j];code[3]=bits;code[4]=opcodes[k];code[5]=(bits&1)?0xc0:0x44;code[6]=0x24;code[7]=0x7f;check(&a,&b,code,16);
   }
   for(unsigned n=0;n<100000;n++) {
    for(unsigned i=0;i<16;i++)code[i]=(uint8_t)random32();
    if(n%4==0){code[0]=0x62;code[1]=0xf1;code[2]=0x7c;}
    check(&a,&b,code,n%17);
   }
  }
  if(a.close(&a.handle)||b.close(&b.handle))return 2;
 }
 printf("%llu complete private decoder states matched, including flags, failed decodes, poison tails and EVEX aaa=0..7\n",(unsigned long long)compared);
 dlclose(a.lib);dlclose(b.lib);return 0;
}
