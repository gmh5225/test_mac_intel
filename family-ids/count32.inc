CAPSTONE_INTERNAL size_t X86_disasmOneText32(csh ud, const uint8_t *code,
				    size_t size, uint64_t address, cs_insn *insn)
{
#ifdef CS_DECODE_TRY_OUTPUT
	if (X86_matchesTextMode(ud, CS_MODE_32))
		{
			size_t remaining = size;
			return cs_disasm_iter_core(ud, &code, &remaining, &address, insn) ? size - remaining : 0;
		}
#endif
	size_t remaining = size;
	return X86_disasmIter(ud, &code, &remaining, &address, insn) ?
		       size - remaining :
		       0;
}