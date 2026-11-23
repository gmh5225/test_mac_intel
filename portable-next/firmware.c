#include <capstone/capstone.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>

int main(int argc,char **argv)
{
	if (argc != 4) return 2;
	FILE *file = fopen(argv[1], "rb");
	if (!file || fseek(file, 0, SEEK_END)) return 3;
	long bytes = ftell(file);
	if (bytes < 0 || fseek(file, 0, SEEK_SET)) return 3;
	uint8_t *image = malloc((size_t)bytes);
	if (!image || fread(image, 1, (size_t)bytes, file) != (size_t)bytes) return 3;
	fclose(file);
	csh handle;
	if (cs_open(CS_ARCH_XCORE, CS_MODE_LITTLE_ENDIAN, &handle) ||
	    cs_option(handle, CS_OPT_DETAIL, strtoul(argv[3], NULL, 0))) return 4;
	cs_insn *insn = cs_malloc(handle);
	if (!insn || !insn->detail) return 4;
	const uint8_t *cursor = image;
	size_t left = (size_t)bytes;
	uint64_t ip = strtoull(argv[2], NULL, 0);
	while (left) {
		const uint8_t *old = cursor;
		uint64_t address = ip;
		size_t available = left;
		if (!cs_disasm_iter(handle, &cursor, &left, &ip, insn)) {
			if (ip != address || old != cursor || left != available) return 5;
			printf("%" PRIu64 "\t0\t0\t\t\t\n", address);
			size_t step = left >= 2 ? 2 : 1;
			cursor += step; ip += step; left -= step;
			continue;
		}
		if (insn->size != (size_t)(cursor-old) || ip != address+insn->size ||
		    insn->address != address || left != available-insn->size) return 6;
		printf("%" PRIu64 "\t%u\t%u\t%s\t%s\t", address,(unsigned)insn->size,insn->id,insn->mnemonic,insn->op_str);
		const cs_xcore *x = &insn->detail->xcore;
		if (x->op_count > sizeof(x->operands)/sizeof(x->operands[0])) return 6;
		for (unsigned n=0;n<x->op_count;++n) {
			const cs_xcore_op *op=x->operands+n;
			if(op->type==XCORE_OP_REG) printf("R,%s;",cs_reg_name(handle,op->reg));
			else if(op->type==XCORE_OP_IMM) printf("I,%d;",op->imm);
			else if(op->type==XCORE_OP_MEM)
				printf("M,%s,%s,%d,%d;",op->mem.base?cs_reg_name(handle,op->mem.base):"",
				       op->mem.index?cs_reg_name(handle,op->mem.index):"",op->mem.disp,op->mem.direct);
			else return 7;
		}
		putchar('\n');
	}
	cs_free(insn,1);cs_close(&handle);free(image);
	return 0;
}
