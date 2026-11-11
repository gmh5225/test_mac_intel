#include "arch/X86/X86Mapping.h"
#include "cs_priv.h"
#include <dlfcn.h>
#include <stdio.h>
#include <string.h>
#ifndef RTLD_FIRST
#define RTLD_FIRST 0
#endif
int main(int argc, char **argv)
{
	if (argc!=2) return 2;
	void *base=dlopen(argv[1], RTLD_NOW|RTLD_LOCAL|RTLD_FIRST);
	if (!base) return 3;
	cs_err (*open_base)(cs_arch,cs_mode,csh *)=(cs_err (*)(cs_arch,cs_mode,csh *))dlsym(base,"cs_open");
	cs_err (*close_base)(csh *)=(cs_err (*)(csh *))dlsym(base,"cs_close");
	const cs_mode modes[]={CS_MODE_16,CS_MODE_32,CS_MODE_64};
	csh active[3],reference[3];
	if (!open_base || !close_base) return 4;
	for(unsigned i=0;i<3;++i) {
		if(cs_open(CS_ARCH_X86,modes[i],&active[i])!=CS_ERR_OK ||
		   open_base(CS_ARCH_X86,modes[i],&reference[i])!=CS_ERR_OK) return 5;
		cs_struct *n=(cs_struct *)active[i],*old=(cs_struct *)reference[i];
		if(!n->x86_uses_shared_luts || n->x86_insn_lut_max!=old->x86_insn_lut_max) return 6;
		size_t bytes=(n->x86_insn_lut_max+1)*sizeof(uint32_t);
		if(memcmp(n->x86_insn_lut,old->x86_insn_lut,bytes) ||
		   memcmp(n->x86_insn_reg_lut,old->x86_insn_reg_lut,bytes)) return 7;
		if(i && (n->x86_insn_lut!=((cs_struct *)active[0])->x86_insn_lut ||
			 n->x86_insn_reg_lut!=((cs_struct *)active[0])->x86_insn_reg_lut)) return 8;
	}
	for(unsigned i=0;i<3;++i){
		cs_struct *n=(cs_struct *)active[i],*old=(cs_struct *)reference[i];
		size_t bytes=(n->x86_insn_lut_max+1)*sizeof(uint32_t);
		if(memcmp(n->x86_insn_lut,old->x86_insn_lut,bytes) ||
		   memcmp(n->x86_insn_reg_lut,old->x86_insn_reg_lut,bytes)) return 9;
		if(cs_close(&active[i])!=CS_ERR_OK || close_base(&reference[i])!=CS_ERR_OK) return 10;
	}
	puts("All packed opcodes and implicit registers match in three simultaneously open modes and after sibling closes");
	return 0;
}
