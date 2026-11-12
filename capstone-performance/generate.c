/* Native experiment. Build output for fixed single-byte legacy opcodes using
 * the corresponding release library as the reference on this ABI. */
#include <capstone/capstone.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

enum { used_detail = offsetof(cs_detail, x86) + sizeof(cs_x86) };
struct record {
	unsigned id;
	char mnemonic[CS_MNEMONIC_SIZE];
	char operands[sizeof(((cs_insn *)0)->op_str)];
	unsigned char detail[used_detail];
};

static bool fixed_opcode(unsigned op, bool wide)
{
	if ((!wide && op >= 0x40 && op <= 0x4f) ||
	    (op >= 0x50 && op <= 0x5f) || (op >= 0x90 && op <= 0x99) ||
	    (op >= 0x9c && op <= 0x9f) || (op >= 0xf8 && op <= 0xfd))
		return true;
	switch (op) {
	case 0xc3: case 0xc9: case 0xcb: case 0xcc: case 0xcf:
	case 0xd7: case 0xec: case 0xed: case 0xee: case 0xef:
	case 0xf4: case 0xf5:
		return true;
	default:
		return false;
	}
}

static void bytes(const unsigned char *values, size_t size)
{
	while (size > 1 && !values[size-1]) --size;
	putchar('{');
	for (size_t i = 0; i < size; ++i)
		printf("%s%u", i ? "," : "", values[i]);
	putchar('}');
}

int main(void)
{
	struct record records[256] = {0};
	unsigned char index[2][256] = {{0}};
	unsigned count = 1;
	for (unsigned mode = 0; mode < 2; ++mode) {
		csh handle;
		if (cs_open(CS_ARCH_X86, mode ? CS_MODE_64 : CS_MODE_32, &handle) != CS_ERR_OK ||
		    cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON) != CS_ERR_OK)
			return 2;
		cs_insn *insn = cs_malloc(handle);
		if (!insn) return 2;
		for (unsigned op = 0; op < 256; ++op) {
			if (!fixed_opcode(op, mode)) continue;
			struct record value = {0};
			for (unsigned suffix = 0; suffix <= 256; ++suffix) {
				uint8_t input[15]; memset(input, suffix, sizeof(input)); input[0] = op;
				const uint8_t *cursor = input;
				size_t left = suffix == 0 ? 1 : sizeof(input);
				uint64_t address = suffix == 0 ? 0 : UINT64_MAX - suffix;
				if (!cs_disasm_iter(handle, &cursor, &left, &address, insn) ||
				    insn->size != 1 || cursor != input + 1) return 3;
				struct record actual = {0};
				actual.id = insn->id;
				memcpy(actual.mnemonic, insn->mnemonic, sizeof(actual.mnemonic));
				memcpy(actual.operands, insn->op_str, sizeof(actual.operands));
				memcpy(actual.detail, insn->detail, sizeof(actual.detail));
				if (suffix && memcmp(&actual, &value, sizeof(value))) return 4;
				value = actual;
			}
			unsigned slot = 1;
			while (slot < count && memcmp(&records[slot], &value, sizeof(value))) ++slot;
			if (slot == count) records[count++] = value;
			index[mode][op] = (unsigned char)slot;
		}
		cs_free(insn, 1); cs_close(&handle);
	}
	puts("static const unsigned char fixed_index[2][256] = {");
	for (unsigned i=0;i<2;++i) { bytes(index[i],256); puts(","); } puts("};");
	printf("static const struct { unsigned id; char mnemonic[CS_MNEMONIC_SIZE]; char operands[sizeof(((cs_insn *)0)->op_str)]; unsigned char detail[%u]; } fixed_records[] = {\n", (unsigned)used_detail);
	for (unsigned i=0;i<count;++i) {
		printf("{%u,",records[i].id);bytes((unsigned char*)records[i].mnemonic,sizeof(records[i].mnemonic));putchar(',');
		bytes((unsigned char*)records[i].operands,sizeof(records[i].operands));putchar(',');
		bytes(records[i].detail,sizeof(records[i].detail));puts("},");
	}
	puts("};");return 0;
}
