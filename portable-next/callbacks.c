#include "cs_priv.h"
#include "MCInst.h"
#include <stdio.h>
#include <string.h>

static Printer_t original_printer;
static Disasm_t original_decoder;
static unsigned seen, errors;

static void inspect(const MCInst *instruction)
{
	const unsigned char zero[sizeof(MCOperand)] = { 0 };
	++seen;
	if (memcmp(&instruction->Operands[MAX_MC_OPS - 1], zero, sizeof(zero)))
		++errors;
}

static bool decode(csh handle, const uint8_t *bytes, size_t length, MCInst *instruction,
		   uint16_t *size, uint64_t address, void *info)
{
	inspect(instruction);
	return original_decoder(handle, bytes, length, instruction, size, address, info);
}

static void print(MCInst *instruction, SStream *stream, void *info)
{
	inspect(instruction);
	original_printer(instruction, stream, info);
}

static void post(csh handle, cs_insn *record, SStream *stream, MCInst *instruction)
{
	(void)handle; (void)record; (void)stream;
	inspect(instruction);
}

int main(void)
{
	for (unsigned hook = 0; hook < 3; ++hook) {
		csh handle;
		if (cs_open(CS_ARCH_XCORE, CS_MODE_LITTLE_ENDIAN, &handle) != CS_ERR_OK)
			return 1;
		cs_struct *state = (cs_struct *)(uintptr_t)handle;
		original_decoder = state->disasm;
		original_printer = state->printer;
		if (hook == 0) state->disasm = decode;
		if (hook == 1) state->printer = print;
		if (hook == 2) state->post_printer = post;
		const uint8_t bytes[] = { 0, 0, 0, 0, 0xf0, 0x49, 0x7f };
		cs_insn *result = NULL;
		unsigned before = seen;
		size_t n = cs_disasm(handle, bytes, sizeof(bytes), 0x1000, 2, &result);
		if (n != 2 || seen != before + 2) return 2;
		cs_free(result, n);
		cs_close(&handle);
	}
	printf("%u %u\n", seen, errors);
	return errors != 0;
}
