#include <capstone/capstone.h>
extern bool X86_disasmIterText(csh, const uint8_t **, size_t *, uint64_t *, cs_insn *);
bool measure_fixed_iterator(csh handle, const uint8_t **p, size_t *size, uint64_t *address, cs_insn *insn)
{
	return X86_disasmIterText(handle, p, size, address, insn);
}
