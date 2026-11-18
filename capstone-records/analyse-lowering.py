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
    assert len(variants['scan']['indirect_jumps']) == 1
    assert all(v>0 for v in variants['scan']['indirect_jumps'][0]['executions'].values())
    rows.append(dict(host=d.name,variants=variants))
assert len(rows) == 2
report = dict(complete=True,source=json.loads((r/'tree.json').read_text()),rows=rows,
              parser_sha256=hashlib.sha256(code.encode()).hexdigest(),
              finding='Adding the memory-immediate reserved case makes both Clang builds lower the existing special-case branch chain to a range check plus indexed jump table. The table load, address formation and indirect jump execute on the original scalar/SIMD samples, which contain no admitted C6/C7 memory-immediate instructions.',
              limits='Clang 14 additionally changes stack instruction traffic, documented in iterator-attribution.json; those groups include normal local storage and are not all proven allocator spills. GCC inlines the iterator and lowers differently, with lower aggregate iterator counts. Unchanged other-ISA objects and their relocated native addresses are separate evidence, not explained by this x86 jump table.')
(r/'lowering-review.json').write_text(json.dumps(report,indent=2)+'\n')
print('Confirmed new hot jump table on both Clang versions')
