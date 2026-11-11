#include "Mapping.h"
#include <dlfcn.h>
#include <stdio.h>
#include <string.h>

#ifndef RTLD_FIRST
#define RTLD_FIRST 0
#endif

void ARC_init_cs_detail(MCInst *);
void LoongArch_init_cs_detail(MCInst *);
void ARC_setup_op(cs_arc_op *);
void LoongArch_setup_op(cs_loongarch_op *);

typedef void (*detail_init)(MCInst *);

int main(int argc, char **argv)
{
	if (argc != 2)
		return 2;
	void *base = dlopen(argv[1], RTLD_LOCAL | RTLD_NOW | RTLD_FIRST);
	if (!base)
		return 3;
	detail_init current[] = { ARC_init_cs_detail, LoongArch_init_cs_detail };
	detail_init reference[] = {
		(detail_init)dlsym(base, "ARC_init_cs_detail"),
		(detail_init)dlsym(base, "LoongArch_init_cs_detail"),
	};
	void (*arc_op)(cs_arc_op *) = (void (*)(cs_arc_op *))dlsym(base, "ARC_setup_op");
	void (*loong_op)(cs_loongarch_op *) = (void (*)(cs_loongarch_op *))dlsym(base, "LoongArch_setup_op");
	if (!reference[0] || !reference[1] || !arc_op || !loong_op)
		return 4;
	unsigned checked = 0;
	for (unsigned byte = 0; byte < 256; ++byte) {
		cs_arc_op a[2];
		cs_loongarch_op b[2];
		memset(a, byte, sizeof(a));
		memset(b, byte, sizeof(b));
		arc_op(&a[0]);
		ARC_setup_op(&a[1]);
		loong_op(&b[0]);
		LoongArch_setup_op(&b[1]);
		if (memcmp(&a[0], &a[1], sizeof(a[0])) || memcmp(&b[0], &b[1], sizeof(b[0])))
			return 5;
		checked += 2;
		for (unsigned arch = 0; arch < 2; ++arch) {
			cs_struct h = { 0 };
			h.arch = arch ? CS_ARCH_LOONGARCH : CS_ARCH_ARC;
			for (unsigned flags = 0; flags < 16; ++flags) {
				h.detail_opt = flags;
				for (unsigned present = 0; present < 2; ++present) {
					cs_insn insn = { 0 };
					MCInst mi = { 0 };
					cs_detail detail[2];
					memset(detail, byte, sizeof(detail));
					mi.csh = &h;
					mi.flat_insn = &insn;
					insn.detail = present ? &detail[0] : NULL;
					reference[arch](&mi);
					insn.detail = present ? &detail[1] : NULL;
					current[arch](&mi);
					if (memcmp(&detail[0], &detail[1], sizeof(cs_detail))) {
						fprintf(stderr, "mismatch arch %u flags %u byte %u present %u\n",arch,flags,byte,present);
						return 6;
					}
					++checked;
				}
			}
		}
	}
	printf("Verified %u complete storage comparisons\n",checked);
	dlclose(base);
	return 0;
}
