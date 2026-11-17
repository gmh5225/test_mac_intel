/* Verify that canonical raw plans retain a registered adapter's priority. */
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
	const uint8_t code[] = { 0x62, 0xf1, 0x7d, 0x48, 0xef, 0xc1 };
	const uint32_t answers[] = { 0, (X86_INS_NOP << 8) | 1, (X86_INS_NOP << 8) | 7 };
	unsigned checks = 0;
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
				size_t remaining = sizeof(code);
				uint64_t address = 0x1000;
				CHECK((private_entry ? X86_disasmIter : cs_disasm_iter)(handle, &cursor, &remaining, &address, insn));
				const unsigned length = !options && answer == 1 ? 1 : sizeof(code);
				CHECK(state.calls == !options);
				CHECK(insn->id == (length == 1 ? X86_INS_NOP : X86_INS_VPXORD));
				CHECK(insn->size == length && cursor == code + length && remaining == sizeof(code) - length && address == 0x1000 + length);
				cs_free(insn, 1);
				CHECK(cs_close(&handle) == CS_ERR_OK);
				++checks;
			}
	printf("adapter priority, misses and text/detail gates: %u cases passed\n", checks);
	return 0;
}
