from pathlib import Path
import hashlib
import json

r = Path(__file__).resolve().parent
parser = r.parent / 'round1362-evex-extension-isolated-entry/review-cost.py'
source = parser.read_text().split('rows=[]')[0]
source = source.replace('executed = defaultdict(int)', 'executed = defaultdict(int)\n    per_pc = defaultdict(lambda: [0, 0, 0])')
source = source.replace('    return costs, executed', '    return costs, executed, dict(per_pc)')
anchor = '            call = False'
assert source.count(anchor) == 1
source = source.replace(anchor, '''                if not call and owner and owner.endswith('/run-' + variant):
                    for i in range(3):
                        per_pc[(function, positions[0])][i] += counts[i]
''' + anchor)
scope = {'__file__': str(parser)}
exec(source, scope)
rows = []
for d in sorted((r / 'profile').iterdir()):
    function = 'X86_disasmIter' if '-gcc-' in d.name else 'X86_trySimpleOutput'
    variants = {}
    for label in ('integer', 'plan32'):
        costs, _, pcs = scope['trace'](d / ('libssl3t64-i386-1-' + label + '.callgrind.gz'), label)
        selected = {pc: values for (fn, pc), values in pcs.items() if fn == function}
        instructions = scope['instructions'](d / (label + '-linked-disassembly.gz'))
        machine = {pc: values for pc, values in instructions.items() if values[2] == function}
        assert selected and machine
        load_base = min(selected) - min(machine)
        assert all(pc - load_base in machine for pc in selected)
        totals = [sum(v[i] for v in selected.values()) for i in range(3)]
        assert totals == costs[function]
        stack, transfers = [], []
        for pc, values in selected.items():
            asm = machine[pc - load_base][1]
            item = dict(offset=pc - min(selected), assembly=asm, events=values)
            if '%rsp' in asm and (values[1] or values[2]):
                stack.append(item)
            if asm.startswith(('push', 'pop', 'call', 'ret')):
                transfers.append(item)
        variants[label] = dict(function=function, load_base=load_base, total=totals,
            explicit_rsp_events=[sum(x['events'][i] for x in stack) for i in range(3)],
            transfer_events=[sum(x['events'][i] for x in transfers) for i in range(3)],
            rsp_instructions=sorted(stack, key=lambda x: -x['events'][2]), transfers=transfers)
    rows.append(dict(profile=d.name, variants=variants,
        delta={key:[variants['plan32'][key][i]-variants['integer'][key][i] for i in range(3)]
               for key in ('total','explicit_rsp_events','transfer_events')}))
report = dict(complete=True, source=json.loads((r / 'tree.json').read_text()), rows=rows,
    parser_sha256=hashlib.sha256(source.encode()).hexdigest(),
    scope='Exact executed PCs in the unchanged SSL32 format consumer, matched to linked disassembly. Explicit RSP operands and call/push/pop/return are reported separately; RBP is not assumed to be a frame pointer. These are simulated accesses, not hardware stalls.')
(r / 'dispatch-lowering.json').write_text(json.dumps(report, indent=2) + '\n')
for row in rows:
    print(row['profile'], row['delta'])
    for label, values in row['variants'].items():
        print(label, [(x['assembly'],x['events']) for x in values['rsp_instructions'][:3]])
