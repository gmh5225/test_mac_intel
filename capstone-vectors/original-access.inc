// convert Intel access info to AT&T access info
static void legacy_get_op_access(cs_struct *h, unsigned int id, uint8_t *access,
			  uint64_t *eflags)
{
	uint8_t count, i;
	const uint8_t *arr = X86_get_op_access(h, id, eflags);

	// initialize access
	memset(access, 0, CS_X86_MAXIMUM_OPERAND_SIZE * sizeof(access[0]));
	if (!arr) {
		return;
	}

	// find the non-zero last entry
	for (count = 0; arr[count]; count++)
		;

	if (count == 0)
		return;

	// copy in reverse order this access array from Intel syntax -> AT&T syntax
	count--;
	for (i = 0; i <= count && ((count - i) < CS_X86_MAXIMUM_OPERAND_SIZE) &&
		    i < CS_X86_MAXIMUM_OPERAND_SIZE;
	     i++) {
		if (arr[count - i] != CS_AC_IGNORE)
			access[i] = arr[count - i];
		else
			access[i] = 0;
	}
}

static void legacy_fixup_evex_opmask_access(MCInst *MI)
{
	cs_x86 *x86 = &MI->flat_insn->detail->x86;
	const uint8_t *arr;
	uint8_t count, i, access_index = 0;
	if (!(MI->flags & X86_IP_HAS_EVEX_OPMASK))
		return;

	arr = X86_get_op_access(MI->csh, MCInst_getOpcode(MI), &x86->eflags);
	if (!arr)
		return;
	for (count = 0; count < CS_X86_MAXIMUM_OPERAND_SIZE; ++count) {
		if (!arr[count])
			break;
	}
	if (count < 2 || count != x86->op_count)
		return;

	for (i = count; i > 2; --i) {
		x86->operands[access_index].access = arr[i - 1];
		if (x86->operands[access_index].access == CS_AC_IGNORE)
			x86->operands[access_index].access = 0;
		access_index++;
	}
	x86->operands[access_index++].access = arr[0];
	x86->operands[access_index].access = arr[1];
}

