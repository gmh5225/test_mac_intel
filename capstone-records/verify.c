#include <capstone/capstone.h>
#include <dlfcn.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#ifndef RTLD_FIRST
#define RTLD_FIRST 0
#endif
#define COUNT(a) (sizeof(a)/sizeof(*(a)))
struct api { void *library; __typeof__(&cs_regs_access) access; __typeof__(&cs_close) close; csh handle; };
static int load(struct api *a,const char *file,cs_arch arch,cs_mode mode) {
 a->library=dlopen(file,RTLD_NOW|RTLD_LOCAL|RTLD_FIRST); if(!a->library) return 1;
 __typeof__(&cs_open) openfn=dlsym(a->library,"cs_open");
 __typeof__(&cs_option) optfn=dlsym(a->library,"cs_option");
 a->access=dlsym(a->library,"cs_regs_access");a->close=dlsym(a->library,"cs_close");
 return !openfn||!optfn||!a->access||!a->close||openfn(arch,mode,&a->handle)!=CS_ERR_OK||optfn(a->handle,CS_OPT_DETAIL,CS_OPT_ON)!=CS_ERR_OK;
}
static uint32_t state=0xb754d139;
static uint32_t pick(void) {state^=state<<13;state^=state>>17;state^=state<<5;return state;}
static unsigned reg(void) {const unsigned v[]={0,1,2,3,4,8,9,17,64,65,512,65535,65536,65537,UINT32_MAX};return v[pick()%COUNT(v)];}
static void fill(cs_detail *d,unsigned arch,unsigned n) {
 d->writeback=pick()%2;
 d->regs_read_count=pick()%(1+COUNT(d->regs_read)); d->regs_write_count=pick()%(1+COUNT(d->regs_write));
 for(unsigned i=0;i<d->regs_read_count;++i)d->regs_read[i]=(uint16_t)reg();
 for(unsigned i=0;i<d->regs_write_count;++i)d->regs_write[i]=(uint16_t)reg();
 unsigned maximum=!(n%32);
 /* Bound constructed states to the public 64-register output capacity. */
 if(maximum)d->regs_write_count%=41;
 if(arch==0) {
  cs_arm *a=&d->arm;a->op_count=maximum?COUNT(a->operands):pick()%9;
  for(unsigned i=0;i<a->op_count;++i) {
   cs_arm_op *op=&a->operands[i];unsigned type=maximum?0:pick()%4;op->access=pick()%4;
   if(type<2){op->type=ARM_OP_REG;op->reg=maximum?(int)(i%24):(int)reg();}
   else if(type==2){op->type=ARM_OP_MEM;op->mem.base=(arm_reg)reg();op->mem.index=(arm_reg)reg();}
   else op->type=ARM_OP_IMM;
  }
 } else if(arch==1) {
  cs_aarch64 *a=&d->aarch64;a->op_count=maximum?COUNT(a->operands):pick()%9;
  for(unsigned i=0;i<a->op_count;++i) {
   cs_aarch64_op *op=&a->operands[i];unsigned type=maximum?0:pick()%6;op->access=pick()%4;
   switch(type) {
    case 0:case 1:op->type=AARCH64_OP_REG;op->reg=maximum?(aarch64_reg)(i%24):(aarch64_reg)reg();break;
    case 2:op->type=AARCH64_OP_MEM;op->mem.base=(aarch64_reg)reg();op->mem.index=(aarch64_reg)reg();break;
    case 3:op->type=AARCH64_OP_SME;op->sme.tile=(aarch64_reg)reg();op->sme.slice_reg=(aarch64_reg)reg();break;
    case 4:op->type=AARCH64_OP_PRED;op->pred.reg=(aarch64_reg)reg();op->pred.vec_select=(aarch64_reg)reg();break;
    default:op->type=AARCH64_OP_IMM;break;
   }
   if(!maximum && pick()%3==0){op->shift.type=AARCH64_SFT_LSL_REG;op->shift.value=reg();}
  }
 } else {
  cs_mips *a=&d->mips;a->op_count=maximum?COUNT(a->operands):pick()%9;
  for(unsigned i=0;i<a->op_count;++i) {
   cs_mips_op *op=&a->operands[i];unsigned type=maximum?0:pick()%4;op->access=pick()%4;
   if(type<2){op->type=MIPS_OP_REG;op->reg=maximum?(mips_reg)(i%24):(mips_reg)reg();}
   else if(type==2){op->type=MIPS_OP_MEM;op->mem.base=(mips_reg)reg();}
   else op->type=MIPS_OP_IMM;
  }
 }
}
int main(int argc,char **argv) {
 if(argc!=3)return 1;
 const cs_arch archs[]={CS_ARCH_ARM,CS_ARCH_AARCH64,CS_ARCH_MIPS};
 const cs_mode modes[]={CS_MODE_ARM,CS_MODE_LITTLE_ENDIAN,CS_MODE_MIPS64|CS_MODE_LITTLE_ENDIAN};
 for(unsigned arch=0;arch<COUNT(archs);++arch) {
  struct api apis[2];if(load(apis,argv[1],archs[arch],modes[arch])||load(apis+1,argv[2],archs[arch],modes[arch])||apis[0].access==apis[1].access)return 2;
  for(unsigned n=0;n<750000;++n) {
   cs_detail d={0};cs_insn in={0};in.id=1;in.detail=&d;fill(&d,arch,n);cs_detail before=d;
   uint16_t outputs[2][128];uint8_t counts[2][2];const unsigned offsets[]={0,1,2,7,32,64};unsigned wo=offsets[n%COUNT(offsets)];
   memset(outputs,0xa5,sizeof(outputs));memset(counts,0x6b,sizeof(counts));
   for(unsigned i=0;i<2;++i) {
    if(apis[i].access(apis[i].handle,&in,outputs[i],counts[i],outputs[i]+wo,counts[i]+1))return 3;
    if(memcmp(&d,&before,sizeof(d)))return 4;
   }
   if(memcmp(outputs[0],outputs[1],sizeof(outputs[0]))||memcmp(counts[0],counts[1],sizeof(counts[0]))) {fprintf(stderr,"arch %u case %u offset %u\n",arch,n,wo);return 5;}
  }
  for(unsigned i=0;i<2;++i){apis[i].close(&apis[i].handle);dlclose(apis[i].library);}
 }
 puts("2250000 ARM/AArch64/MIPS register-list states matched: counts, overlapping outputs, full-width IDs, output tails, and source preservation");return 0;
}
