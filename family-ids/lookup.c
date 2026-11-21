#ifndef CAPSTONE_DIET
CAPSTONE_EXPORT unsigned int capstone_bench_access_count(void)
{
    return X86_INSTRUCTION_LIST_END;
}

CAPSTONE_EXPORT int capstone_bench_access(csh handle, unsigned int id,
                                         uint64_t *flags, uint8_t out[6])
{
    const uint8_t *arr = X86_get_op_access((cs_struct *)(uintptr_t)handle, id, flags);
    if (!arr)
        return 0;
    for (unsigned int i = 0; i < sizeof(((insn_op *)0)->access); ++i) {
        out[i] = arr[i];
        if (!arr[i])
            break;
    }
    return 1;
}
#endif
