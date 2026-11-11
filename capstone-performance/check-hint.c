#include <dlfcn.h>
#include <limits.h>
#include <stdio.h>
#include "arch/X86/X86Mapping.c"

#ifndef RTLD_FIRST
#define RTLD_FIRST 0
#endif

typedef unsigned (*reference_find)(unsigned);

static int check_id(cs_struct *h, reference_find find, unsigned id)
{
	unsigned expected = find(id);
	if (find_insn_h(h, id) != expected || find_insn_h(NULL, id) != expected) {
		fprintf(stderr, "row mismatch for %u, expected %u\n", id, expected);
		return 1;
	}
	return 0;
}

int main(int argc, char **argv)
{
	if (argc != 2)
		return 2;
	void *base = dlopen(argv[1], RTLD_NOW | RTLD_LOCAL | RTLD_FIRST);
	if (!base)
		return 3;
	reference_find find = (reference_find)dlsym(base, "find_insn");
	if (!find)
		return 4;
	csh handle = 0;
	if (cs_open(CS_ARCH_X86, CS_MODE_32, &handle) != CS_ERR_OK)
		return 5;
	cs_struct *h = (cs_struct *)(uintptr_t)handle;
	uint32_t *cache = h->x86_insn_lut;
	if (!cache)
		return 6;
	for (unsigned cached = 0; cached < 2; ++cached) {
		h->x86_insn_lut = cached ? cache : NULL;
		for (unsigned id = 0; id <= UINT16_MAX; ++id)
			if (check_id(h, find, id))
				return 7;
		if (check_id(h, find, UINT_MAX) || check_id(h, find, UINT_MAX - 1))
			return 8;
	}
	h->x86_insn_lut = cache;
	cs_close(&handle);
	dlclose(base);
	printf("Compared 262152 cached, uncached and NULL-handle row selections\n");
	return 0;
}
