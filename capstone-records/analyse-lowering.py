from collections import defaultdict
from pathlib import Path
import gzip
import hashlib
import json
import re

r = Path(__file__).resolve().parent
parser = r.parent / 'round1362-evex-extension-isolated-entry/review-cost.py'
code = parser.read_text().split('rows=[]')[0]
code = code.replace("owner.endswith('/run-' + variant)", "owner.endswith('/same-image')")
scope = {'__file__': str(parser)}
exec(code, scope)
rows = []
for d in sorted((r / 'native').iterdir()):
    if '-arm-' in d.name:
        continue
    assembly = {v: scope['instructions'](d / (v + '-linked-assembly.gz')) for v in ('base', 'scan')}
    for case, mode in [('scalar32', 1), ('putty-32-0.85', 1), ('putty-32-0.85', 2)]:
        variants = {}
        for v in ('base', 'scan'):
            named, pcs = scope['trace'](d / f'cost-{case}-{mode}-{v}.callgrind.gz', v)
            missing = pcs.keys() - assembly[v].keys()
            assert not missing, (d.name, v, [hex(x) for x in list(missing)[:10]])
            histogram = defaultdict(int)
            instructions = []
            for pc, count in pcs.items():
                _, asm, owner, start = assembly[v][pc]
                if owner != 'cs_decode_full_insn':
                    continue
                histogram[asm.split()[0]] += count
                instructions.append(dict(offset=hex(pc-start), asm=asm, executions=count))
            assert sum(histogram.values()) == named['cs_decode_full_insn'][0]
            variants[v] = dict(histogram=dict(histogram), instructions=instructions)
        changes = {k: variants['scan']['histogram'].get(k, 0) - variants['base']['histogram'].get(k, 0)
                   for k in variants['base']['histogram'].keys() | variants['scan']['histogram'].keys()}
        changes = {k: v for k, v in changes.items() if v}
        rows.append(dict(host=d.name, case=case, mode=mode, changes=changes,
                         ir_delta=sum(changes.values()), variants=variants))

report = dict(complete=len(rows)==9, source=json.loads((r / 'tree.json').read_text()), rows=rows,
              parser_sha256=hashlib.sha256(code.encode()).hexdigest(),
              scope='Physical cs_decode_full_insn instruction addresses in three x86-host Callgrind panels per compiler. Counts are simulated, not timings; complete assembly and executed-PC lists are retained. ARM context ownership is deliberately outside this focused join.')
(r / 'lowering-review.json').write_text(json.dumps(report, indent=2) + '\n')
for row in rows:
    print(row['host'], row['case'], row['mode'], row['ir_delta'], row['changes'])
