#include <capstone/capstone.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
static const char *name(csh h,x86_reg r){return r==X86_REG_INVALID?"-":cs_reg_name(h,r);}
int main(int argc,char **argv){
 csh hs[3];cs_insn *ins[3];const unsigned modes[]={CS_MODE_16,CS_MODE_32,CS_MODE_64};
 bool all=argc>1&&!strcmp(argv[1],"all"), att=argc>2&&!strcmp(argv[2],"att"), scan=argc>2&&!strcmp(argv[2],"scan");
 for(unsigned n=0;n<3;n++){if(cs_open(CS_ARCH_X86,modes[n],&hs[n])||cs_option(hs[n],CS_OPT_DETAIL,scan?CS_OPT_OFF:CS_OPT_ON)||cs_option(hs[n],CS_OPT_TEXT,scan?CS_OPT_OFF:CS_OPT_ON)||cs_option(hs[n],CS_OPT_SYNTAX,att?CS_OPT_SYNTAX_ATT:CS_OPT_SYNTAX_INTEL))return 2;ins[n]=cs_malloc(hs[n]);if(!ins[n])return 3;}
 char line[32768];uint8_t data[16000];
 while(fgets(line,sizeof line,stdin)){
  char *pos=line;unsigned bits=strtoul(pos,&pos,10);uint64_t ip=strtoull(pos,&pos,10);while(*pos==' ')pos++;
  size_t n=strcspn(pos,"\r\n")/2; if(n>sizeof data||!n)return 4;
  for(size_t k=0;k<n;k++){unsigned a=0;if(sscanf(pos+2*k,"%2x",&a)!=1)return 5;data[k]=(uint8_t)a;}
  unsigned k=bits==16?0:bits==32?1:2;csh h=hs[k];cs_insn *i=ins[k];const uint8_t *curr=data;size_t left=n;bool first=true;
  while(left){
   if(!first)putchar(';');first=false;
   if(!cs_disasm_iter(h,&curr,&left,&ip,i)){putchar('0');break;}
   printf("%u",i->size);
   if(!scan && (i->id==X86_INS_VPMADD52LUQ||i->id==X86_INS_VPMADD52HUQ)){
    cs_x86*x=&i->detail->x86;
    if(x->opcode[0]==0xc4){
     const cs_x86_op *dst=&x->operands[att?2:0],*src=&x->operands[1],*rm=&x->operands[att?0:2];
     if(x->op_count!=3||dst->access!=CS_AC_READ_WRITE||src->access!=CS_AC_READ||rm->access!=CS_AC_READ||dst->type!=X86_OP_REG||src->type!=X86_OP_REG||rm->size!=dst->size||src->size!=dst->size||x->eflags||rm->avx_bcast||dst->avx_zero_opmask){fprintf(stderr,"IFMA metadata at %"PRIx64"\n",i->address);return 6;}
     printf(",%s,%u,%s,%s,",i->id==X86_INS_VPMADD52LUQ?"Vpmadd52luq":"Vpmadd52huq",dst->size,name(h,dst->reg),name(h,src->reg));
     if(rm->type==X86_OP_REG)printf("%s",name(h,rm->reg));else if(rm->type==X86_OP_MEM){
      uint64_t mask=x->addr_size==2?UINT16_MAX:x->addr_size==4?UINT32_MAX:UINT64_MAX;
      x86_reg index=rm->mem.index;
      if(index==X86_REG_EIZ||index==X86_REG_RIZ){
       if(((x->sib>>3)&7)!=4||(x->rex&2))return 8;
       index=X86_REG_INVALID;
      }
      printf("@%s,%s,%d,%"PRIx64",%u,%u",name(h,rm->mem.base),name(h,index),index?rm->mem.scale:1,(uint64_t)rm->mem.disp&mask,x->encoding.disp_offset,x->encoding.disp_size);
     }else return 7;
    }
   }
   if(!all)break;
  }putchar('\n');
 }
 for(unsigned n=0;n<3;n++){cs_free(ins[n],1);cs_close(&hs[n]);}return 0;
}
