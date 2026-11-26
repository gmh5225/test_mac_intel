#include "arch/X86/X86IntelInstPrinter.c"
#include <stdio.h>

int main(void)
{
	unsigned long long checked = 0, missing = 0, ignored = 0, over = 0;
	csh h;
	if (cs_open(CS_ARCH_X86, CS_MODE_64, &h) != CS_ERR_OK) return 1;
	cs_struct *handle = (cs_struct *)(uintptr_t)h;
	for (unsigned id = 0; id <= X86_INSTRUCTION_LIST_END; ++id) {
		uint64_t flags = 0x87654321;
		const uint8_t *row = X86_get_op_access(handle, id, &flags);
		if (!row) ++missing;
		for (unsigned j = 0; row && row[j]; ++j)
			ignored += row[j] == CS_AC_IGNORE;
		for (unsigned n = 0; n <= ARR_SIZE(((cs_x86 *)0)->operands); ++n) {
			for (unsigned fill = 0; fill <= 1; ++fill) {
				cs_detail ref, got;
				memset(&ref, fill ? 0xa5 : 0x00, sizeof(ref));
				ref.x86.op_count = n; memcpy(&got,&ref,sizeof(got));
				MCInst mi = {0}; cs_insn insn = {0};
				insn.detail = &got; mi.csh = handle; mi.flat_insn = &insn;
				MCInst_setOpcode(&mi, id);
				uint8_t rights[CS_X86_MAXIMUM_OPERAND_SIZE];
				get_op_access(handle,id,rights,&ref.x86.eflags);
				for (unsigned i = 0; i < n && i < sizeof(rights); ++i)
					ref.x86.operands[i].access = rights[i];
				set_final_operand_access(&mi);
				if (memcmp(&ref, &got, sizeof(ref))) {
					fprintf(stderr,"id %u op_count %u fill %u\n",id,n,fill);
					return 2;
				}
				++checked; over+=n>sizeof(rights);
			}
		}
	}
	cs_close(&h);
	printf("%llu %llu %llu %llu\n",checked,missing,ignored,over);
	return !(missing && ignored && over);
}
