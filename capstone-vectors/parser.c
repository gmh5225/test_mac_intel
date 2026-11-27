#include "MappingAlias.h"
#include <inttypes.h>
#include <stdio.h>
static const name_map names[] = {
#include "arch/PowerPC/PPCGenCSAliasMnemMap.inc"
 {PPC_INS_ALIAS_SLWI,"slwi"},{PPC_INS_ALIAS_SRWI,"srwi"},{PPC_INS_ALIAS_SLDI,"sldi"},{PPC_INS_ALIAS_END,NULL}
};
#include "arch/PowerPC/PPCMapping.h"
static const ppc_alias_name indexed[] = {
#include "arch/PowerPC/PPCGenAliasNameIndex.inc"
};
_Static_assert(sizeof(name_map)==sizeof(ppc_alias_name), "64-bit table changed size");
_Static_assert(offsetof(name_map,name)==offsetof(ppc_alias_name,name), "name relocation moved");
static uint64_t checked;
static int compare(MCInst *mi,SStream *ss) {
 for(unsigned flag=0;flag<=1;++flag){
  MCInst_setIsAlias(mi,flag);
  mi->flat_insn->alias_id=UINT64_MAX;
  map_set_alias_id(mi,ss,names,ARR_SIZE(names));
  uint64_t old=mi->flat_insn->alias_id;
  mi->flat_insn->alias_id=UINT64_MAX;
  PPC_setAliasId(mi,ss,indexed,PPC_ALIAS_BUCKET_MASK);
  if(mi->flat_insn->alias_id!=old) {fprintf(stderr,"alias mismatch [%.30s]\n",ss->buffer);return 1;}
  ++checked;
 }
 return 0;
}
int main(void) {
 if(ARR_SIZE(names)!=ARR_SIZE(indexed))return 6;
 for(unsigned i=0;names[i].name;++i){
  if(names[i].id!=indexed[i].id||strcmp(names[i].name,indexed[i].name))return 7;
 }
 cs_struct handle={0};handle.arch=CS_ARCH_PPC;
 cs_insn insn={0};MCInst mi={0};mi.csh=&handle;mi.flat_insn=&insn;SStream ss={0};
 const char *suffixes[]={""," ","\t0"," r3, r4",".",".\t","x123456789abcdef",",x","+","-","\xff"};
 for(unsigned i=0;names[i].name;++i) for(unsigned k=0;k<ARR_SIZE(suffixes);++k){
  for(unsigned blanks=0;blanks<3;++blanks){
   const char *leading=blanks==0?"":blanks==1?"  ":"\t ";
   snprintf(ss.buffer,sizeof ss.buffer,"%s%s%s",leading,names[i].name,suffixes[k]);
   if(compare(&mi,&ss))return 2;
  }
  const size_t len=strlen(names[i].name);
  for(size_t n=0;n<=len;++n){
   snprintf(ss.buffer,sizeof ss.buffer,"%.*s%s",(int)n,names[i].name,suffixes[k]);
   if(compare(&mi,&ss))return 3;
  }
 }
 for(unsigned v=1;v<256;++v){
  memset(ss.buffer,(int)v,20);ss.buffer[20]='\0';if(compare(&mi,&ss))return 4;
 }
 for(unsigned a=0;a<256;++a)for(unsigned b=0;b<256;++b){
  ss.buffer[0]=(char)a;ss.buffer[1]=(char)b;ss.buffer[2]='\0';if(compare(&mi,&ss))return 8;
 }
 memset(ss.buffer,' ',sizeof(ss.buffer));ss.buffer[sizeof(ss.buffer)-1]='\0';
 if(compare(&mi,&ss))return 9;
 for(unsigned len=1;len<=2;++len){
  memcpy(ss.buffer+sizeof(ss.buffer)-1-len,"mr",len);if(compare(&mi,&ss))return 10;
 }
 printf("%" PRIu64 "\n",checked);
}
