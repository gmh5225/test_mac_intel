#include "arch/X86/X86Mapping.h"
#include <dlfcn.h>
#include <stdio.h>
#ifndef RTLD_FIRST
#define RTLD_FIRST 0
#endif
typedef const uint8_t *(*query)(cs_struct *, unsigned, uint64_t *);
int main(int argc,char **argv)
{
	if(argc!=2)return 2;
	void *dll=dlopen(argv[1],RTLD_NOW|RTLD_LOCAL|RTLD_FIRST);
	if(!dll)return 3;
	query old=(query)dlsym(dll,"X86_get_op_access");
	csh handle;
	if(!old || cs_open(CS_ARCH_X86,CS_MODE_64,&handle)!=CS_ERR_OK)return 4;
	cs_struct *h=(cs_struct *)handle;
	uint32_t *cache=h->x86_insn_lut;
	unsigned observations=0;
	for(unsigned state=0;state<3;++state){
		h->x86_insn_lut=state==1?NULL:cache;
		for(unsigned n=0;n<=65538;++n){
			unsigned id=n==65537?UINT32_MAX:n==65538?0x80000000u:n;
			uint64_t flags1=UINT64_C(0x1212343456567878),flags2=flags1;
			const uint8_t *a=old(state==2?NULL:h,id,&flags1);
			const uint8_t *b=X86_get_op_access(state==2?NULL:h,id,&flags2);
			if(!!a!=!!b || flags1!=flags2)return 5;
			if(a)for(unsigned i=0;i<6;++i){
				if(a[i]!=b[i]){
					fprintf(stderr,"opcode %u access %u differs\n",id,i);
					return 6;
				}
				if(!a[i])break;
			}
			++observations;
		}
	}
	h->x86_insn_lut=cache;
	if(cs_close(&handle)!=CS_ERR_OK)return 7;
	printf("Verified %u complete flags and operand access lists across cached, missing-cache and NULL handles\n",observations);
	return 0;
}
