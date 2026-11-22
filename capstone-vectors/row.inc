/* The counter is appended only to the untimed observation build. */
#include "census-vex-rows.inc"
unsigned census_vector_memory(const uint8_t *p, size_t len, const cs_insn *ref)
{
	if (len < 4 || (p[0] & 0xfe) != 0xc4)
		return 0;
	unsigned prefix = p[0] == 0xc5 ? 2 : 3;
	if (len < prefix + 2 || (p[prefix - 1] & 3) != 1)
		return 0;
	unsigned map = prefix == 2 ? 1 : p[1] & 31;
	if (map < 1 || map > 3 || p[prefix + 1] >= 0xc0)
		return 0;
	unsigned flags = p[prefix - 1], ll = (flags >> 2) & 1;
	unsigned wl = ll | (prefix == 2 ? 0 : (flags >> 6) & 2);
	unsigned slot = vex_register_plans[map - 1][p[prefix]];
	unsigned row = vex_register_widths[slot][wl];
	if (!(vex_rip_register_rows[row >> 3] & (1u << (row & 7))))
		return 0;
	const cs_detail *d = ref->detail;
	const cs_x86 *x86 = &d->x86;
	const struct VectorOutputRow *record = &vex_register_rows[row];
	unsigned rxb = (~(unsigned)p[1] >> 5) & (prefix == 2 ? 4 : 7);
	unsigned vector_base = ll ? X86_REG_YMM0 : X86_REG_XMM0;
	unsigned dst = ((p[prefix + 1] >> 3) & 7) | ((rxb & 4) << 1);
	unsigned src = (~flags >> 3) & 15;
	if (ref->id != record->id || strcmp(ref->mnemonic, record->mnemonic) ||
	    d->regs_read_count || d->regs_write_count || d->groups_count != record->group_count ||
	    memcmp(d->groups, record->groups, sizeof(record->groups)) || x86->op_count != 3 ||
	    x86->operands[0].type != X86_OP_REG || x86->operands[1].type != X86_OP_REG ||
	    x86->operands[2].type != X86_OP_MEM || x86->operands[0].reg != vector_base + dst ||
	    x86->operands[1].reg != vector_base + src)
		return 2;
	for (unsigned i = 0; i != 3; ++i)
		if (x86->operands[i].access != record->access[i] || x86->operands[i].size != (16u << ll))
			return 2;
	return 1;
}
