#include <capstone/capstone.h>
#include <stdio.h>
#include <string.h>
int main(void){
 csh hs[3];cs_insn *ins[3];for(unsigned b=0;b<3;b++){if(cs_open(CS_ARCH_X86,(cs_mode)(CS_MODE_16<<b),hs+b)||cs_option(hs[b],CS_OPT_DETAIL,CS_OPT_ON))return 1;ins[b]=cs_malloc(hs[b]);if(!ins[b])return 2;}
 char hex[31];unsigned id,bits;while(scanf("%u %u %30s",&id,&bits,hex)==3){unsigned b=bits==16?0:bits==32?1:2;unsigned char bytes[15];size_t n=strlen(hex)/2;
 for(unsigned i=0;i<n;i++){unsigned v;if(sscanf(hex+i*2,"%2x",&v)!=1)return 3;bytes[i]=(unsigned char)v;}uint64_t pc=0x1000;const uint8_t*p=bytes;
 if(!cs_disasm_iter(hs[b],&p,&n,&pc,ins[b])||n||p!=bytes+strlen(hex)/2)return 4;
 cs_regs x,y;uint8_t nx=0,ny=0;printf("%u %u %u %d\n",id,ins[b]->size,ins[b]->id,cs_regs_access(hs[b],ins[b],x,&nx,y,&ny)==CS_ERR_DIET);}
 for(unsigned b=0;b<3;b++){cs_free(ins[b],1);cs_close(hs+b);}return 0;
}

