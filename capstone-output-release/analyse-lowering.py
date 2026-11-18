from pathlib import Path
import hashlib
import json
import re

r = Path(__file__).resolve().parent
parser = r.parent/'round1362-evex-extension-isolated-entry/review-cost.py'
code = parser.read_text().replace("owner.endswith('/run-' + variant)", "owner.endswith('/same-image')")
scope = {'__file__': str(parser)}
exec(code[:code.index('rows=[]')],scope)
rows = []
for d in sorted((r/'native').glob('*clang*')):
    if not (d/'instruction-costs.json').exists():
        continue
    variants = {}
    for label in ('base','scan'):
        assembly = scope['instructions'](d/(label+'-linked-assembly.gz'))
        instructions = [(a,v) for a,v in assembly.items() if v[2]=='X86_trySimpleOutput']
        branches = []
        for i,(address,record) in enumerate(instructions):
            if not re.match(r'jmp\s+\*%',record[1]):
                continue
            dynamic = {}
            for case,mode in (('scalar32',1),('scalar64',1),('simd64',2)):
                counts = scope['trace'](d/f'cost-{case}-{mode}-{label}.callgrind.gz',label)[1]
                dynamic[case] = counts.get(address,0)
            branches.append(dict(offset=hex(address-record[3]),executions=dynamic,
                sequence=[dict(offset=hex(a-v[3]),instruction=v[1]) for a,v in instructions[max(0,i-6):i+1]]))
        variants[label] = dict(indirect_jumps=branches)
    assert len(variants['base']['indirect_jumps']) == 0
    assert len(variants['scan']['indirect_jumps']) == 0
    rows.append(dict(host=d.name,variants=variants))
assert len(rows) == 2
report = dict(complete=True,source=json.loads((r/'tree.json').read_text()),rows=rows,
              parser_sha256=hashlib.sha256(code.encode()).hexdigest(),
              finding='The tagged special-plan domain retains no indirect jump in the ordinary Clang iterator. The extra R1481 reserved-case jump table is absent with only new C6/C7 admission moved to its specialized reader.',
              limits='This confirms the compiler-lowering hypothesis only. Dynamic instruction counts, memory-writer costs and native timings are judged independently; no other-ISA performance inference follows from x86 object identity.')
(r/'lowering-review.json').write_text(json.dumps(report,indent=2)+'\n')
print('Confirmed no ordinary iterator jump table on either Clang version')
