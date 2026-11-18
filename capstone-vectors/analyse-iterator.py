from collections import Counter
from pathlib import Path
import hashlib
import json

r = Path(__file__).resolve().parent
parser = r.parent / 'round1362-evex-extension-isolated-entry/review-cost.py'
scope = {'__file__': str(parser)}
code = parser.read_text()
exec(code[:code.index('rows=[]')], scope)


def group(assembly):
    parts = assembly.split(None, 1)
    opcode = parts[0]
    if len(parts) == 1 or '%rsp' not in parts[1]:
        return opcode
    depth = 0
    for i, char in enumerate(parts[1]):
        depth += (char == '(') - (char == ')')
        if char == ',' and depth == 0:
            source, dest = parts[1][:i], parts[1][i+1:]
            if opcode.startswith('mov'):
                return opcode + (' stack-read' if '%rsp' in source else ' stack-write')
            break
    return opcode + ' stack-operand'


rows = []
for directory in sorted((r / 'profile').glob('*clang*')):
    if not (directory / 'complete.json').exists():
        continue
    assembly = {v: scope['instructions'](directory / (v + '-linked-disassembly.gz'))
                for v in ('integer', 'plan32')}
    values = json.loads((directory / 'instruction-costs.json').read_text())
    for case, mode in sorted({(x['case'], x['mode']) for x in values if x['mode']}):
        parsed = {v: scope['trace'](directory / f'{case}-{mode}-{v}.callgrind.gz', v)
                  for v in assembly}
        functions = parsed['integer'][0].keys() | parsed['plan32'][0].keys()
        changes = {f: [parsed['plan32'][0].get(f, [0]*3)[i] -
                       parsed['integer'][0].get(f, [0]*3)[i] for i in range(3)]
                   for f in functions}
        changes = {f: counts for f, counts in changes.items() if any(counts)}
        groups, tails = {}, {}
        for label in parsed:
            counts = Counter()
            tails[label] = []
            for address, (_, instruction, owner, start) in assembly[label].items():
                if owner != 'X86_trySimpleOutput':
                    continue
                executed = parsed[label][1].get(address, 0)
                counts[group(instruction)] += executed
                if 'X86_writeVex32Output>' in instruction or 'X86_writeVectorOutput>' in instruction:
                    tails[label].append(dict(offset=hex(address-start), instruction=instruction, executed=executed))
            assert sum(counts.values()) == parsed[label][0]['X86_trySimpleOutput'][0]
            groups[label] = dict(counts)
        rows.append(dict(profile=directory.name, case=case, mode=mode,
                         changed_function_events=changes, iterator_groups=groups, tail_calls=tails,
                         total_ir_delta=sum(x[0] for x in changes.values())))

assert len(rows) == 16, len(rows)
report = dict(complete=True, source_tree=json.loads((r / 'tree.json').read_text())['tree'], rows=rows,
              parser_sha256=hashlib.sha256(code.encode()).hexdigest(),
              scope='Exclusive simulated Ir/Dr/Dw on unchanged real-input consumers. Stack instruction groups include legitimate local storage, not only allocator spills. Native timing and the published-baseline comparison are separate.')
(r / 'iterator-attribution.json').write_text(json.dumps(report, indent=2) + '\n')
for row in rows:
    if row['case'] == 'libssl3t64-i386' and row['mode'] == 1:
        print(row['profile'], row['case'], row['total_ir_delta'],
              row['changed_function_events'].get('X86_trySimpleOutput'))
