#include "arch/X86/X86OutputOptions.h"
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
static uint64_t attempts,accepted;
bool observed_test(csh,bool,const uint8_t *,size_t,cs_insn *,uint16_t *);
CS_PRESERVE_MOST bool __real_X86_decodeOutputMiss32(cs_struct *,const uint8_t *,size_t,cs_insn *,uint16_t *,bool);
CS_PRESERVE_MOST bool __wrap_X86_decodeOutputMiss32(cs_struct *h,const uint8_t *p,size_t n,cs_insn *out,uint16_t *len,bool batch)
{
	bool real=__real_X86_decodeOutputMiss32(h,p,n,out,len,batch);
	if (n>=2 && p[0]==0xf6 && p[1]<0xc0 && !(p[1]&0x38)) {
		cs_insn record={0};uint16_t length=0;
		++attempts;
		if (observed_test((csh)(uintptr_t)h,false,p,n,&record,&length)) {
			if (!real || length!=*len || record.id!=out->id) abort();
			++accepted;
		}
	}
	return real;
}
__attribute__((destructor)) static void report(void)
{
	fprintf(stderr,"testmem32 %" PRIu64 " %" PRIu64 "\n",attempts,accepted);
}
