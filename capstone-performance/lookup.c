#include "cs_priv.h"
#include <stdlib.h>
#include <string.h>

/* The benchmark runs one handle at a time. Restore the original ownership
 * before cs_close. Both arms allocate, copy and free identical buffers. */
static uint32_t *old_id, *old_reg, *copy_id, *copy_reg;

void trial_begin(csh h)
{
	cs_struct *cs = (cs_struct *)(uintptr_t)h;
	size_t bytes = (cs->x86_insn_lut_max + 1) * sizeof(uint32_t);
	old_id = (uint32_t *)cs->x86_insn_lut;
	old_reg = (uint32_t *)cs->x86_insn_reg_lut;
	copy_id = malloc(bytes);
	copy_reg = calloc(1, bytes);
	if (!old_id || !old_reg || !copy_id || !copy_reg)
		abort();
	memcpy(copy_id, old_id, bytes);
	memcpy(copy_reg, old_reg, bytes);
	if (!strcmp(getenv("LOOKUP_STORAGE"),"copy")) {
		cs->x86_insn_lut = copy_id;
		cs->x86_insn_reg_lut = copy_reg;
	}
}
void trial_end(csh h)
{
	cs_struct *cs = (cs_struct *)(uintptr_t)h;
	cs->x86_insn_lut = old_id;
	cs->x86_insn_reg_lut = old_reg;
	free(copy_id);
	free(copy_reg);
}
