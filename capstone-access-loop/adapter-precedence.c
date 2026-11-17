/* Check adapter priority on register, ordinary memory and SIB transfer plans. */
#include <stdio.h>
#include "X86ScanAdapter.h"

typedef struct { unsigned calls; uint32_t result; } State;
static uint32_t scan(void *opaque, const uint8_t *code, size_t size)
{
	(void)code;
	(void)size;
	State *state = opaque;
	++state->calls;
	return state->result;
}
#define CHECK(x) do { if (!(x)) { fprintf(stderr, "line %u: %s\n", __LINE__, #x); return 1; } } while (0)

int main(void)
{
	static const struct {
		uint8_t code[11];
		unsigned size, id;
	} cases[] = {
		{ { 0x62, 0xf1, 0x7d, 0x48, 0xef, 0xc1 }, 6, X86_INS_VPXORD },
		{ { 0x62, 0xf1, 0x7d, 0x48, 0x6f, 0xc1 }, 6, X86_INS_VMOVDQA32 },
		{ { 0x62, 0xf1, 0x7f, 0x48, 0x6f, 0x04, 0x25, 1, 2, 3, 4 }, 11, X86_INS_VMOVDQU8 },
		{ { 0x62, 0xf1, 0xfe, 0x48, 0x7f, 0x40, 0x80 }, 7, X86_INS_VMOVDQU64 },
		{ { 0x62, 0xf1, 0xfd, 0x48, 0x6f, 0x80, 1, 2, 3, 4 }, 10, X86_INS_VMOVDQA64 },
		{ { 0x62, 0xf2, 0x7d, 0x48, 0x1a, 0x00 }, 6, X86_INS_VBROADCASTF32X4 },
		{ { 0x62, 0xf2, 0xfd, 0x48, 0x1a, 0x04, 0x08 }, 7, X86_INS_VBROADCASTF64X2 },
	};
	unsigned checks = 0;
	for (unsigned sample = 0; sample != sizeof(cases) / sizeof(cases[0]); ++sample) {
		const uint8_t *code = cases[sample].code;
		const unsigned size = cases[sample].size;
		const uint32_t answers[] = { 0, (X86_INS_NOP << 8) | 1, (X86_INS_NOP << 8) | (size + 1) };
		for (unsigned private_entry = 0; private_entry != 2; ++private_entry)
			for (unsigned options = 0; options != 4; ++options)
				for (unsigned answer = 0; answer != 3; ++answer) {
					csh handle = 0;
					CHECK(cs_open(CS_ARCH_X86, CS_MODE_64, &handle) == CS_ERR_OK);
					CHECK(cs_option(handle, CS_OPT_TEXT, (options & 1) ? CS_OPT_ON : CS_OPT_OFF) == CS_ERR_OK);
					CHECK(cs_option(handle, CS_OPT_DETAIL, (options & 2) ? CS_OPT_ON : CS_OPT_OFF) == CS_ERR_OK);
					State state = { 0, answers[answer] };
					CHECK(X86_setScanAdapter(handle, CS_MODE_64, scan, &state));
					cs_insn *insn = cs_malloc(handle);
					CHECK(insn);
					const uint8_t *cursor = code;
					size_t remaining = size;
					uint64_t address = 0x1000;
					CHECK((private_entry ? X86_disasmIter : cs_disasm_iter)(handle, &cursor, &remaining, &address, insn));
					const unsigned length = !options && answer == 1 ? 1 : size;
					CHECK(state.calls == !options);
					CHECK(insn->id == (length == 1 ? X86_INS_NOP : cases[sample].id));
					CHECK(insn->size == length && cursor == code + length && remaining == size - length && address == 0x1000 + length);
					cs_free(insn, 1);
					CHECK(cs_close(&handle) == CS_ERR_OK);
					++checks;
				}
	}
	printf("adapter priority, misses and text/detail gates: %u cases passed\n", checks);
	return 0;
}
