#include "cs_priv.h"
#include <dlfcn.h>
#include <stdio.h>
#include <string.h>

typedef void (*map_fn)(MCInst *);
extern void ARC_set_instr_map_data(MCInst *);
extern void LoongArch_set_instr_map_data(MCInst *);

int main(int argc, char **argv)
{
	if (argc != 2) return 2;
	void *base = dlopen(argv[1], RTLD_NOW | RTLD_LOCAL);
	if (!base) return 2;
	struct { const char *name; map_fn current; cs_arch arch; unsigned end; } cases[] = {
		{ "ARC_set_instr_map_data", ARC_set_instr_map_data, CS_ARCH_ARC, 719 },
		{ "LoongArch_set_instr_map_data", LoongArch_set_instr_map_data, CS_ARCH_LOONGARCH, 2397 },
	};
	unsigned n = 0;
	for (unsigned a = 0; a < sizeof(cases)/sizeof(cases[0]); ++a) {
		map_fn old = (map_fn)dlsym(base, cases[a].name);
		if (!old) return 2;
		cs_struct handle = { 0 };
		handle.arch = cases[a].arch;
		for (unsigned op = 0; op < cases[a].end; ++op)
			for (unsigned seed = 0; seed < 12; ++seed)
				for (unsigned opt = 0; opt < 4; ++opt) {
					cs_detail d[2]; cs_insn ins[2]; MCInst mi = { 0 };
					mi.csh=&handle; mi.Opcode=op;
					handle.detail_opt = (opt & 1) ? CS_OPT_ON : CS_OPT_OFF;
					memset(d,0x5a+seed,sizeof(d));
					memset(ins,0xa5-seed,sizeof(ins));
					for (unsigned k=0;k<2;++k) {
						d[k].groups_count=seed%6;
						d[k].regs_read_count=seed%9;
						d[k].regs_write_count=seed%11;
						ins[k].detail=(opt&2)?&d[k]:NULL;
						mi.flat_insn=&ins[k];
						(k?cases[a].current:old)(&mi);
						ins[k].detail=NULL;
					}
					if (memcmp(ins,ins+1,sizeof(ins[0])) || memcmp(d,d+1,sizeof(d[0]))) {
						fprintf(stderr,"mismatch %s %u %u %u\n",cases[a].name,op,seed,opt);
						return 1;
					}
					++n;
				}
	}
	printf("%u complete seeded ARC and LoongArch map comparisons matched\n",n);
	return 0;
}
