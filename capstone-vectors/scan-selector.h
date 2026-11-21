static inline bool X86_disasmIterScan32(csh handle, const uint8_t **code,
					size_t *size, uint64_t *address,
					cs_insn *insn)
{
	if (handle && *size && (*code)[0] == 0xc5)
		return X86_disasmIter32(handle, code, size, address, insn);
	return cs_disasm_iter(handle, code, size, address, insn);
}
