from collections import defaultdict
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
    measured = json.loads((d / 'instruction-costs.json').read_text())
    for case, mode in sorted({(x['case'], x['mode']) for x in measured}):
        variants = {}
        for variant, assembly in images.items():
            costs, executions = scope['trace'](d / f'cost-{case}-{mode}-{variant}.callgrind.gz', variant)
            expected, = [x for x in measured if (x['case'], x['mode'], x['variant']) == (case, mode, variant)]
            assert [sum(v[i] for v in costs.values()) for i in range(3)] == [expected['events'][k] for k in ('Ir', 'Dr', 'Dw')]
            unresolved = set(executions) - set(assembly)
            assert not unresolved, [hex(x) for x in sorted(unresolved)[:10]]
            owners = defaultdict(int)
            predicate_instructions = []
            descriptor_calls = []
            for address, count in executions.items():
                data, instruction, owner, start = assembly[address]
                owners[(owner, start)] += count
                if owner.split('#')[0] == 'DecodePredicateOperand':
                    predicate_instructions.append(dict(address=hex(address), offset=address-start,
                        instruction=instruction, executions=count))
                if re.match(r'(?:call|jmp)\s+.*<MCInstrDesc_get>', instruction):
                    descriptor_calls.append(dict(address=hex(address), caller=owner, start=hex(start),
                        offset=address-start, executions=count, instruction=instruction))
            variants[variant] = dict(total_ir=expected['events']['Ir'],
                physical_predicate_ir=sum(x['executions'] for x in predicate_instructions),
                predicate_instructions=sorted(predicate_instructions, key=lambda x: int(x['address'], 16)),
                descriptor_transfers=sum(x['executions'] for x in descriptor_calls),
                descriptor_call_sites=descriptor_calls,
                relevant_owners=[dict(name=name, address=hex(start), instructions=count)
                    for (name, start), count in owners.items()
                    if name.split('#')[0] in ('DecodePredicateOperand', 'MCInstrDesc_get', 'MCOperand_CreateImmReg0')])
        rows.append(dict(host=d.name, case=case, mode=mode, variants=variants,
            ir_delta=variants['scan']['total_ir']-variants['base']['total_ir'],
            predicate_ir_delta=variants['scan']['physical_predicate_ir']-variants['base']['physical_predicate_ir'],
            descriptor_transfer_delta=variants['scan']['descriptor_transfers']-variants['base']['descriptor_transfers']))
assert len(rows) == 33
report = dict(complete=True, source=json.loads((r / 'tree.json').read_text()), rows=rows,
    parser_sha256=hashlib.sha256(code.encode()).hexdigest(),
    scope='Exclusive simulated instruction counts attributed by physical linked PCs, not caller-return contexts. Duplicate symbols use their separate start addresses. Call sites count executed transfers; they do not alone attribute all native timing differences.')
(r / 'predicate-costs.json').write_text(json.dumps(report, indent=2) + '\n')
for row in rows:
    if row['case'] == 'arm-ls':
        print(row['host'], row['mode'], row['ir_delta'], row['predicate_ir_delta'], row['descriptor_transfer_delta'])
