#include "cs_disasm_internal.h"

static int calls;
void census_reset(void) { calls = 0; }
int census_calls(void) { return calls; }
extern CS_PRESERVE_MOST bool __real_cs_decode_full_insn(cs_struct *, const uint8_t *, size_t, cs_insn *, uint16_t *, bool);
CS_PRESERVE_MOST bool __wrap_cs_decode_full_insn(cs_struct *h, const uint8_t *p, size_t n, cs_insn *record, uint16_t *len, bool batch)
{
	++calls;
	return __real_cs_decode_full_insn(h, p, n, record, len, batch);
}
