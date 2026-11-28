#include <capstone/capstone.h>
#include <inttypes.h>
#include <stdio.h>
#include <string.h>
static const x86_reg tracked[] = {X86_REG_SI,X86_REG_ESI,X86_REG_RSI,X86_REG_DI,X86_REG_EDI,X86_REG_RDI,X86_REG_CX,X86_REG_ECX,X86_REG_RCX,X86_REG_ES,X86_REG_CS,X86_REG_SS,X86_REG_DS,X86_REG_FS,X86_REG_GS};
static unsigned mask(const uint16_t *r,unsigned count,unsigned *dups){
 unsigned seen=0;for(unsigned j=0;j<count;j++)for(unsigned i=0;i<15;i++)if(r[j]==tracked[i]){if(seen&(1u<<i))++*dups;seen|=1u<<i;}return seen;
}
int main(void){
 csh handles[3][2][2];cs_insn *out[3][2][2];
 for(unsigned b=0;b<3;b++)for(unsigned a=0;a<2;a++)for(unsigned t=0;t<2;t++){
  csh *h=&handles[b][a][t];if(cs_open(CS_ARCH_X86,(cs_mode)(CS_MODE_16<<b),h)||cs_option(*h,CS_OPT_DETAIL,CS_OPT_ON)||cs_option(*h,CS_OPT_SYNTAX,a?CS_OPT_SYNTAX_ATT:CS_OPT_SYNTAX_INTEL)||cs_option(*h,CS_OPT_TEXT,t?CS_OPT_ON:CS_OPT_OFF))return 2;out[b][a][t]=cs_malloc(*h);
 }
 char hex[31];unsigned id,bits;
 while(scanf("%u %u %30s",&id,&bits,hex)==3){
  unsigned b=bits==16?0:bits==32?1:2;uint8_t bytes[15];size_t n=strlen(hex)/2;
  for(unsigned i=0;i<n;i++){unsigned z;if(sscanf(hex+2*i,"%2x",&z)!=1)return 3;bytes[i]=(uint8_t)z;}
  for(unsigned a=0;a<2;a++)for(unsigned t=0;t<2;t++){
   csh h=handles[b][a][t];cs_insn *x=out[b][a][t];const uint8_t *p=bytes;size_t sz=n;uint64_t ip=0x1000;
   if(!cs_disasm_iter(h,&p,&sz,&ip,x)||sz||ip!=0x1000+n)return 4;
   cs_regs read,written;uint8_t nr,nw;unsigned dup=0;
   if(cs_regs_access(h,x,read,&nr,written,&nw))return 5;
   unsigned rr=mask(read,nr,&dup),ww=mask(written,nw,&dup);
   uint64_t hash=0;const char *parts[]={x->mnemonic,x->op_str};
   for(unsigned i=0;i<2;i++){for(const unsigned char *c=(const unsigned char *)parts[i];*c;c++)hash=(hash^*c)*1099511628211ULL;hash=(hash^255)*1099511628211ULL;}
   printf("%u %u %u %u %u %u %" PRIu64 " %u %u %u\n",id,a,t,x->size,x->id,x->detail->x86.op_count,hash,rr,ww,dup);
  }
 }
 for(unsigned b=0;b<3;b++)for(unsigned a=0;a<2;a++)for(unsigned t=0;t<2;t++){cs_free(out[b][a][t],1);cs_close(&handles[b][a][t]);}
 return 0;
}

