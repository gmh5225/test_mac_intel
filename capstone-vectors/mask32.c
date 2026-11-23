#define X86_disasmIter32 observed_mask_iter32
#include "arch/X86/X86Vex32Output.c"
bool observed_test32(csh h,const uint8_t *p,size_t n,cs_insn *out,uint16_t *len)
{
 const unsigned lead=0;
 if(n<lead+2 || (p[lead]&0xfe)!=0xf6 || (p[lead+1]&0x38) || p[lead+1]>=0xc0)return false;
 return tryOutput32((cs_struct *)(uintptr_t)h,p,n,out,len);
}
