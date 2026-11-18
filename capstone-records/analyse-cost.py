"""Attribute executed-work changes separately from native timing and layout."""
from pathlib import Path
import hashlib
import json
import re

r = Path(__file__).resolve().parent
parser = r.parent / 'round1362-evex-extension-isolated-entry/review-cost.py'
code = parser.read_text()
scope = {'__file__': str(parser)}
exec(code[:code.index('rows=[]')], scope)
read = lambda path: json.loads(path.read_text())

def symbols(path):
    result = {}
    for line in path.read_text().splitlines():
        match = re.fullmatch(r'([0-9a-f]+) ([0-9a-f]+) (\S) (.+)', line)
        if match:
            result.setdefault(match[4], []).append(dict(address=int(match[1], 16),
                size=int(match[2], 16), kind=match[3]))
    return result

rows = []
for directory in sorted((r / 'native').iterdir()):
    assert read(directory / 'complete.json')['cases'] == 18
    costs = read(directory / 'instruction-costs.json')
    variants = ('base', 'iterator', 'leaf', 'candidate')
    tables = {v: symbols(directory / (v + '-symbols.txt')) for v in variants}
    for case, mode in [('arm-ls', 2), ('arm64-ls', 0), ('mips64el-ls', 2)]:
        counts = {v: scope['trace'](directory / ('cost-' + case + '-' + v + '.callgrind.gz'), v)[0]
                  for v in variants}
        raw = {x['variant']: x for x in costs if x['case'] == case and x['mode'] == mode}
        for v in variants:
            assert [sum(x[i] for x in counts[v].values()) for i in range(3)] == [raw[v]['events'][k] for k in ('Ir', 'Dr', 'Dw')]
        hot = sorted(counts['base'], key=lambda name: -counts['base'][name][0])[:25]
        for variant in variants[1:]:
            names = counts['base'].keys() | counts[variant].keys()
            differences = {name: [counts[variant].get(name, [0]*3)[i] - counts['base'].get(name, [0]*3)[i]
                                  for i in range(3)] for name in names}
            differences = {name: value for name, value in differences.items() if any(value)}
            rows.append(dict(host=directory.name, cpu=read(directory / 'cpu.json'), case=case, mode=mode,
                variant=variant, delta_ir=sum(x[0] for x in differences.values()), changed_functions=differences,
                x86_work={name: value for name, value in counts[variant].items() if name.startswith('X86_')},
                original_hot_functions={name: dict(baseline_ir=counts['base'][name][0],
                    before=tables['base'].get(name), after=tables[variant].get(name)) for name in hot}))
assert len(rows) == 18
report = dict(complete=True, rows=rows, parser_sha256=hashlib.sha256(code.encode()).hexdigest(),
    scope='Exclusive simulated Ir/Dr/Dw, verified against trace totals. Native timing, runtime PC placement and hardware PMU results remain separate evidence. No hardware cause is inferred from simulated cache events.',
    publication_qualified=False)
(r / 'cost-attribution.json').write_text(json.dumps(report, indent=2) + '\n')
for row in rows:
    ranked = sorted(row['changed_functions'], key=lambda k: -abs(row['changed_functions'][k][0]))[:4]
    print(row['host'], row['case'], row['variant'], 'Ir delta', row['delta_ir'],
          [(name, row['changed_functions'][name]) for name in ranked])
