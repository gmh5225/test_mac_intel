def compose(current, original, counts):
    declaration = 'void X86_get_insn_id(cs_struct *h, cs_insn *insn, unsigned int id)'
    end = '// map special instructions with accumulate registers.'
    def split(source):
        start = source.index(declaration)
        stop = source.index(end, start)
        return source[:start], source[start:stop], source[stop:]
    before, fixed, after = split(current)
    _, base, _ = split(original)
    old_table = counts.replace('x86_mapping_counts', 'bench_original_counts')
    original_include = '#include "X86GenMappingCounts.inc"'
    before = before.replace(original_include, original_include + '\n' + old_table)
    def definition(body, name):
        return body.replace('void X86_get_insn_id(', 'static __attribute__((noinline)) void ' + name + '(')
    hook = '''
static void (*selected_mapper)(cs_struct *, cs_insn *, unsigned int) = bench_base_mapper;
static unsigned long long mapping_calls;

CAPSTONE_EXPORT void cs_bench_select_mapping(unsigned fixed)
{
    selected_mapper = fixed ? bench_fixed_mapper : bench_base_mapper;
    mapping_calls = 0;
}

CAPSTONE_EXPORT unsigned long long cs_bench_mapping_calls(void)
{
    return mapping_calls;
}

void X86_get_insn_id(cs_struct *h, cs_insn *insn, unsigned int id)
{
    selected_mapper(h, insn, id);
}
'''
    return (before + definition(base.replace('x86_mapping_counts','bench_original_counts'), 'bench_base_mapper')
            + definition(fixed, 'bench_fixed_mapper') + hook + after)
