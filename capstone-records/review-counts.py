from collections import defaultdict
from pathlib import Path
import gzip
import json
import re

r = Path(__file__).resolve().parent
read = lambda p: json.loads(p.read_text())


def self_cost(path):
    names = {}
    rows = defaultdict(lambda: [0, 0, 0])
    function = None
    call = False
    positions = 0
    for line in gzip.open(path, 'rt'):
        line = line.strip()
        if line.startswith('positions: '):
            positions = len(line.split()) - 1
        if line.startswith(('fn=', 'cfn=')):
            m = re.fullmatch(r'c?fn=\((\d+)\)(?: (.*))?', line)
            assert m, line
            if m[2] is not None:
                names[m[1]] = m[2]
            if line.startswith('fn='):
                function = names[m[1]]
        elif line.startswith('calls='):
            call = True
        elif line and line[0] in '+-*0123456789':
            fields = line.split()
            if not call and len(fields) > positions:
                events = list(map(int, fields[positions:]))
                events += [0] * (3 - len(events))
                assert function is not None
                for i in range(3):
                    rows[function][i] += events[i]
            call = False
    return dict(rows)


run = read(r / 'profile-run.json')
assert run['conclusion'] == 'success'
rows, receipts = [], []
for e in sorted((r / 'profile').iterdir()):
    assert read(e / 'complete.json')['rows'] == 12
    assert read(e / 'cleanup.json')['removed']
    assert read(e / 'reader-section-identity.json')['old_runtime_objects_identical'] == 37
    costs = read(e / 'instruction-costs.json')
    receipts.append(dict(host=e.name, cleanup=read(e / 'cleanup.json')))
    for case, mode in [('arm64-ls', 0), ('arm64-ls', 2), ('mips64el-ls', 2), ('jpeg-avx2-i386', 0)]:
        variants = {x['variant']: x for x in costs if (x['case'], x['mode']) == (case, mode)}
        assert set(variants) == {'base', 'packed', 'scan'}
        assert all(x['result'] == variants['base']['result'] for x in variants.values())
        n = sum(variants['base']['result'][k] for k in ('instructions', 'rejected'))
        funcs = {key: self_cost(e / f'{case}-{mode}-{key}.callgrind.gz') for key in variants}
        for key in variants:
            raw=gzip.open(e / f'{case}-{mode}-{key}.callgrind.gz','rt').read()
            totals=list(map(int,next(line[8:].split() for line in raw.splitlines() if line.startswith('totals: '))))
            assert [sum(v[i] for v in funcs[key].values()) for i in range(3)] == totals[:3]
            assert [variants[key]['events'][event]-totals[i] for i,event in enumerate(('Ir','Dr','Dw'))] == [9,0,6]
        differences = {}
        for old, new in [('base', 'packed'), ('packed', 'scan')]:
            changed = []
            for name in funcs[old].keys() | funcs[new].keys():
                delta = [funcs[new].get(name, [0, 0, 0])[i] - funcs[old].get(name, [0, 0, 0])[i] for i in range(3)]
                if any(delta):
                    changed.append(dict(function=name, delta=delta, per_attempt=[x / n for x in delta]))
            differences[old + '-' + new] = sorted(changed, key=lambda x: -sum(map(abs, x['delta'])))
        row = dict(host=e.name, case=case, mode=mode, attempts=n,
                   iterator_self={key: funcs[key]['cs_disasm_iter'] for key in variants},
                   events={key: val['events'] for key, val in variants.items()}, functions=differences)
        rows.append(row)
        delta = [(funcs['packed']['cs_disasm_iter'][i] - funcs['base']['cs_disasm_iter'][i]) / n for i in range(3)]
        print(e.name, case, mode, 'iterator delta Ir/Dr/Dw per attempt', delta)
        if case != 'jpeg-avx2-i386':
            print('remaining', differences)
assert len(rows) == 16
result = dict(complete=True, run=run, source=read(r/'semantic-review.json'), rows=rows, receipts=receipts,
              findings=[
                  'GCC 11 and 13 have identical non-x86 traversal Ir/Dr/Dw before and after the C5 reader; extra instruction count cannot explain their native regressions.',
                  'Clang 18 public iterator adds one memory read and one memory write per non-x86 call, with unchanged self instruction count.',
                  'Clang 14 iterator removes about two instructions and one read per call despite increasing its stack allocation. AArch64 memset executes seven extra instructions and four writes per call in this trace.',
                  'Instruction-identical packed/private-section binaries can select different libc memset paths; trace totals are not solely determined by Capstone instruction bytes.',
                  'Native regression causality is incomplete: counts establish changed work but do not apportion wall time or identify hardware cache/branch mechanisms.'
              ], native_qualified=False)
(r/'review.json').write_text(json.dumps(result, indent=2)+'\n')
