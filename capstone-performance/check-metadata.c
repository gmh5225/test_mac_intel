#include "Mapping.h"
#include <dlfcn.h>
#include <stdio.h>

#ifndef RTLD_FIRST
#define RTLD_FIRST 0
#endif

typedef void (*map_id_fn)(MCInst *, const insn_map *, unsigned);
typedef void (*append_fn)(MCInst *, const insn_map *);

int main(int argc, char **argv)
{
	if (argc != 2)
		return 2;
	void *library = dlopen(argv[1], RTLD_NOW | RTLD_LOCAL | RTLD_FIRST);
	if (!library)
		return 3;
	map_id_fn map_id = (map_id_fn)dlsym(library, "map_cs_id");
	append_fn reads = (append_fn)dlsym(library, "map_implicit_reads");
	append_fn writes = (append_fn)dlsym(library, "map_implicit_writes");
	append_fn groups = (append_fn)dlsym(library, "map_groups");
	if (!map_id || !reads || !writes || !groups)
		return 4;
	insn_map table[32] = { 0 };
	unsigned checked = 0;
	for (unsigned sparse = 0; sparse < 2; ++sparse) {
		for (unsigned i = 0; i < 32; ++i) {
			table[i].id = sparse ? i & ~1u : i;
			table[i].mapid = 100 + i;
			for (unsigned j = 0; j < i % 4; ++j) {
				table[i].regs_use[j] = 33 + i + j;
				table[i].regs_mod[j] = 77 + i + j;
				table[i].groups[j] = 1 + j;
			}
		}
		for (unsigned opcode = 0; opcode < 32; opcode += 1 + sparse) {
			for (unsigned seed = 0; seed < 256; ++seed) {
				for (unsigned options = 0; options < 4; ++options) {
					cs_struct handle = { 0 };
					handle.detail_opt = options & 1 ? CS_OPT_ON : CS_OPT_OFF;
					MCInst mi = { 0 };
					cs_insn insn, expected;
					cs_detail detail, expected_detail;
					memset(&insn, seed, sizeof(insn));
					memset(&detail, seed, sizeof(detail));
					detail.regs_read_count = seed % (MAX_IMPL_R_REGS - 2);
					detail.regs_write_count = seed % (MAX_IMPL_W_REGS - 2);
					detail.groups_count = seed % (MAX_NUM_GROUPS - 2);
					mi.csh = &handle;
					mi.Opcode = opcode;
					mi.flat_insn = &insn;
					insn.detail = options & 2 ? &detail : NULL;
					memcpy(&expected, &insn, sizeof(insn));
					memcpy(&expected_detail, &detail, sizeof(detail));
					expected.detail = options & 2 ? &expected_detail : NULL;
					mi.flat_insn = &expected;
					map_id(&mi, table, 32);
					reads(&mi, table);
					writes(&mi, table);
					groups(&mi, table);
					mi.flat_insn = &insn;
					map_insn_metadata(&mi, table, 32);
					expected.detail = insn.detail;
					if (memcmp(&expected, &insn, sizeof(insn)) ||
					    memcmp(&expected_detail, &detail, sizeof(detail))) {
						fprintf(stderr, "metadata mismatch at %u/%u/%u/%u\n",
							sparse, opcode, seed, options);
						return 5;
					}
					++checked;
				}
			}
		}
	}
	printf("%u complete instruction and detail states match\n", checked);
	dlclose(library);
	return 0;
}
