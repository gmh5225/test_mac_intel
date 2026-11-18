from pathlib import Path
import hashlib
import json
import re

r = Path(__file__).resolve().parent
parser = r.parent / 'round1362-evex-extension-isolated-entry/review-cost.py'
code = parser.read_text().replace("owner.endswith('/run-' + variant)", "owner.endswith('/same-image')")
scope = {'__file__': str(parser)}
exec(code[:code.index('rows=[]')], scope)
rows = []
for d in sorted((r / 'native').iterdir()):
    if not (d / 'instruction-costs.json').exists():
        continue
    images = {v: scope['instructions'](d / (v + '-linked-assembly.gz')) for v in ('base', 'scan')}
    costs = json.loads((d / 'instruction-costs.json').read_text())
    for case, mode in sorted({(x['case'], x['mode']) for x in costs}):
        variants = {}
        for v, assembly in images.items():
            counts = scope['trace'](d / f'cost-{case}-{mode}-{v}.callgrind.gz', v)[1]
            sites = []
            for address, (_, instruction, owner, start) in assembly.items():
                if re.match(r'(?:call|jmp)\s+.*<MCOperand_init(?:Reg|Imm)>', instruction):
                    sites.append(dict(address=hex(address), caller=owner, offset=hex(address-start),
                                      instruction=instruction, executions=counts.get(address, 0)))
            helpers = {name: dict(static_instructions=0, executed_instructions=0)
                       for name in ('MCOperand_initReg', 'MCOperand_initImm')}
            for address, (_, instruction, owner, _) in assembly.items():
                name = owner.split('#')[0] if owner else None
                if name in helpers:
                    helpers[name]['static_instructions'] += 1
                    helpers[name]['executed_instructions'] += counts.get(address, 0)
            variants[v] = dict(static_transfer_sites=len(sites),
                               executed_transfers=sum(x['executions'] for x in sites),
                               executed_sites=[x for x in sites if x['executions']], helpers=helpers)
        rows.append(dict(host=d.name, case=case, mode=mode, variants=variants))
assert len(rows) == 33
assert all(x['variants']['scan']['static_transfer_sites'] == 0 for x in rows)
assert all(x['variants']['scan']['executed_transfers'] == 0 for x in rows)
report = dict(complete=True, source_tree=json.loads((r / 'tree.json').read_text())['tree'], rows=rows,
              parser_sha256=hashlib.sha256(code.encode()).hexdigest(),
              finding='The forced-inline helpers have no physical call/jump sites in any measured x86-host image. The prior GCC prototype had 1299 sites and 34287 executed transfers in the PE32 formatting workload; that specific added call/return work is eliminated.',
              limits='Simulated exclusive events from the fixed guest image. Duplicate static symbols are distinguished by physical address. This does not attribute all native timing changes or all changed reader inlining to these calls.')
(r / 'helper-calls.json').write_text(json.dumps(report, indent=2) + '\n')
for row in rows:
    if row['case'] in ('putty-32-0.85', 'arm-ls') and row['mode'] in (0, 1):
        print(row['host'], row['case'], row['mode'],
              {v: (x['static_transfer_sites'], x['executed_transfers']) for v,x in row['variants'].items()})
