size_t X86_disasmOneText32(csh, const uint8_t *, size_t, uint64_t, cs_insn *);
CAPSTONE_INTERNAL size_t X86_disasmOneText(csh ud, const uint8_t *code,
				    size_t size, uint64_t address, cs_insn *insn)
{
#ifdef CS_DECODE_TRY_OUTPUT
	if (X86_matchesTextMode(ud, CS_MODE_64))
		{
			size_t remaining = size;
			return cs_disasm_iter_core(ud, &code, &remaining, &address, insn) ? size - remaining : 0;
		}
#endif
	return X86_disasmOneText32(ud, code, size, address, insn);
}