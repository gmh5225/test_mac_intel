#define X86_disasmIterText observed_mask_iter64
#include "arch/X86/X86Sse64Output.c"
extern bool observed_test32(csh,const uint8_t*,size_t,cs_insn*,uint16_t*);
bool observed_plain(csh h, bool wide, const uint8_t *p, size_t n,cs_insn *out,uint16_t *len)
{
 if(!wide)return observed_test32(h,p,n,out,len);
 const unsigned lead=n && (p[0]&0xf0)==0x40;
 if(n<lead+2 || (p[lead]&0xfe)!=0xf6 || (p[lead+1]&0x38) || p[lead+1]>=0xc0)return false;
 return tryOutput64((cs_struct *)(uintptr_t)h,p,n,out,len);
}
