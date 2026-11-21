#ifndef CAPSTONE_DIET
CAPSTONE_EXPORT unsigned int capstone_bench_access_count(void)
{
	return X86_INSTRUCTION_LIST_END;
}

CAPSTONE_EXPORT int capstone_bench_access(csh handle, unsigned int id,
					 uint64_t *flags, uint8_t out[15])
{
#ifdef CAPSTONE_TEST_ORDERED_ACCESS
	const X86OperandAccess *entry = X86_get_operand_access(id, flags);
	memcpy(out, entry->intel, 6);
	memcpy(out + 6, entry->att, 6);
	out[12] = entry->count;
	out[13] = entry->destination_access;
	out[14] = entry->opmask_access;
	return entry != &x86_access_descriptors[0];
#else
	const uint8_t *raw = X86_get_op_access((cs_struct *)(uintptr_t)handle, id, flags);
	unsigned count = 0;
	memset(out, 0, 15);
	if (!raw)
		return 0;
	while (count < 6 && raw[count])
		++count;
	for (unsigned i = 0; i < count; ++i) {
		uint8_t value = raw[i] == CS_AC_IGNORE ? 0 : raw[i];
		out[i] = out[6 + count - 1 - i] = value;
	}
	out[12] = (uint8_t)count;
	if (count)
		out[13] = raw[0];
	if (count > 1)
		out[14] = raw[1];
	return 1;
#endif
}
#endif
