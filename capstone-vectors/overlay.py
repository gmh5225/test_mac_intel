"""Build untimed counters separately. Both timed settings execute the same image."""
from pathlib import Path
import subprocess

def write_control(src, profile):
    header = src / 'arch/X86/X86VexBaseMemory.h'
    sib = src / 'arch/X86/X86VexSibTransfer.h'
    base = subprocess.check_output(['git','-C',src,'show','HEAD:arch/X86/X86VexBaseMemory.h'], text=True)
    candidate = subprocess.check_output(['git','-C',src,'show',':arch/X86/X86VexBaseMemory.h'], text=True)
    transfer = subprocess.check_output(['git','-C',src,'show',':arch/X86/X86VexSibTransfer.h'], text=True)
    start = 'static bool writeVexBaseMemory('
    def last_body(s):
        body = s[s.index(start):].strip()
        assert body.endswith('\n#endif')
        return body.removesuffix('\n#endif')
    signature = last_body(base).split('\n{',1)[0]
    params = '(code, size, prefix, insn, insn_size, regs)'
    baseline = last_body(base).replace(start, 'static bool readBaselineVexMemory(',1)
    treated = last_body(candidate).replace(start, 'static bool readCandidateVexMemory(',1)
    state = '''
#include <stdlib.h>
static unsigned select_candidate;
__attribute__((constructor))
static void chooseVexReader(void)
{
    const char *value = getenv("BENCH_VEX_READER");
    select_candidate = value && value[0] == '1';
}
'''
    counter = '''#include <stdio.h>
static unsigned long long observed_entries, observed_records, observed_transfers;
__attribute__((destructor))
static void reportVexReader(void)
{
    fprintf(stderr, "reader %u %llu %llu %llu\\n", select_candidate,
            observed_entries, observed_records, observed_transfers);
}
'''
    before = candidate[:candidate.index(start)]
    marker = '#include "X86VexSibTransfer.h"'
    assert before.count(marker)==1 and 'return true;\n}\n#endif' in transfer
    before = before.replace(marker, state + (counter if profile else '') + marker)
    if profile:
        transfer = transfer.replace('return true;\n}\n#endif', '++observed_transfers;\n\treturn true;\n}\n#endif')
    body = 'bool used = select_candidate ? readCandidateVexMemory'+params+' : readBaselineVexMemory'+params+';'
    if profile:
        body += '\n    ++observed_entries;\n    observed_records += used;'
    header.write_text(before + baseline + '\n' + treated + '\n' + signature + '\n{\n    ' + body + '\n    return used;\n}\n#endif\n')
    sib.write_text(transfer)
