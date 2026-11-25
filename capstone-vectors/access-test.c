#include "arch/X86/X86ATTInstPrinter.c"
#include "original-access.inc"

int main(void)
{
	csh handle;
	if (cs_open(CS_ARCH_X86, CS_MODE_64, &handle)) return 2;
	cs_struct *state = (cs_struct *)(uintptr_t)handle;
	uint64_t checks = 0, early_checks = 0, missing = 0, masked = 0;
	for (unsigned id = 0; id <= X86_INSTRUCTION_LIST_END; ++id) {
		uint64_t flags = UINT64_MAX;
		const uint8_t *row = X86_get_op_access(state, id, &flags);
		unsigned length = 0;
		while (row && row[length]) ++length;
		if (length >= CS_X86_MAXIMUM_OPERAND_SIZE) return 3;
		missing += row == NULL;
		for (unsigned use_mask = 0; use_mask < 2; ++use_mask) {
			for (unsigned n = 0; n <= CS_X86_MAXIMUM_OPERAND_SIZE; ++n) {
				cs_detail expected, actual;
				memset(&expected, 0xa5, sizeof(expected));
				expected.x86.op_count = (uint8_t)n;
				actual = expected;
				cs_insn before = {0}, after = {0};
				before.detail = &expected; after.detail = &actual;
				MCInst mi = {0}, trial = {0};
				mi.csh = state; mi.flat_insn = &before;
				MCInst_setOpcode(&mi, id);
				mi.flags = use_mask ? X86_IP_HAS_EVEX_OPMASK : 0;
				trial = mi; trial.flat_insn = &after;
				uint8_t rights[CS_X86_MAXIMUM_OPERAND_SIZE];
				legacy_get_op_access(state, id, rights, &expected.x86.eflags);
#ifdef TEST_CURRENT_ACCESS
				if (n < CS_X86_MAXIMUM_OPERAND_SIZE) {
					cs_detail saved = expected;
					expected.x86.operands[n].access = rights[n];
					setCurrentOperandAccess(&trial);
					if (memcmp(&expected, &actual, sizeof(expected))) return 4;
					expected = saved;
					memset(&actual, 0xa5, sizeof(actual)); actual.x86.op_count = n;
					++early_checks;
				}
#endif
				for (unsigned i = 0; i < n; ++i) expected.x86.operands[i].access = rights[i];
				legacy_fixup_evex_opmask_access(&mi);
				setFinalOperandAccess(&trial);
				if (memcmp(&expected, &actual, sizeof(expected))) {
					fprintf(stderr, "id=%u mask=%u operands=%u row=%u\n", id, use_mask, n, length);
					return 5;
				}
				masked += use_mask && n == length && length >= 2;
				++checks;
			}
		}
	}
	cs_close(&handle);
	printf("{\"checked\":%llu,\"early\":%llu,\"masked\":%llu,\"missing\":%llu}\n",
	       (unsigned long long)checks, (unsigned long long)early_checks,
	       (unsigned long long)masked, (unsigned long long)missing);
	return !missing || !masked;
}
