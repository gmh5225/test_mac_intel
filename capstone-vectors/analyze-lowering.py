from pathlib import Path
import gzip
import hashlib
import json
import re

r = Path(__file__).resolve().parent
parser = r.parent / 'round1362-evex-extension-isolated-entry/review-cost.py'
text = parser.read_text().split('rows=[]')[0]
text = text.replace('executed = defaultdict(int)', 'executed = defaultdict(int)\n    edges = defaultdict(int)\n    callee = None')
text = text.replace("            if line.startswith('fn='):\n                function = names[m[1]]", "            if line.startswith('fn='):\n                function = names[m[1]]\n            else:\n                callee = names[m[1]]")
text = text.replace("        elif line.startswith('calls='):\n            call = True", "        elif line.startswith('calls='):\n            edges[(function, callee)] += int(line.split()[0][6:])\n            call = True")
text = text.replace('return costs, executed', 'return costs, executed, edges')
scope = {'__file__': str(parser)}
exec(text, scope)

def body(assembly, function):
    match = re.search(r'^([0-9a-f]+) <' + function + r'>:\n(.*?)(?=^\s*$|^[0-9a-f]+ <|\Z)', assembly, re.M | re.S)
    return match[2].splitlines() if match else []

rows = []
for experiment in [r, r.parent / 'round1404-output-mode-leaves']:
    report = json.loads((experiment / 'profile-review.json').read_text())
    assert report['complete']
    for d in sorted((experiment / 'profile').iterdir()):
        asm = gzip.decompress((d / 'modes-dispatch-object.asm.gz').read_bytes()).decode()
        selected = next(x for x in report['rows'] if x['host'] == d.name and x['case'] == 'libssl3t64-i386' and x['mode'] == 1)
        edges = {}
        for label in ('integer', 'modes'):
            costs, _, calls = scope['trace'](d / ('libssl3t64-i386-1-' + label + '.callgrind.gz'), label)
            assert [sum(v[i] for v in costs.values()) for i in range(3)] == [selected['totals'][label][k] for k in ('Ir', 'Dr', 'Dw')]
            edges[label] = [dict(caller=a, callee=b, calls=n) for (a, b), n in calls.items()
                            if 'SimpleOutput' in (a or '') or 'SimpleOutput' in (b or '')]
        entry = body(asm, 'X86_trySimpleOutput')
        if '-clang-' in d.name:
            assert entry
            before_mode_test = entry[:next(i for i, x in enumerate(entry) if 'cmp' in x)]
            saves = sum('push' in x for x in before_mode_test)
            assert saves == (6 if experiment == r else 0)
        else:
            assert not entry
            assert not any('SimpleOutput' in x['callee'] for x in edges['integer'])
            assert any(x['callee'] == 'X86_writeSimpleOutput32' and x['calls'] > 0 for x in edges['modes'])
            saves = None
        rows.append(dict(experiment=experiment.name, host=d.name, source=report['source'],
                         case=selected['case'], mode=1, totals=selected['totals'],
                         instruction_reduction=selected['instruction_reduction'],
                         changed_functions=selected['changed_function_costs'], calls=edges,
                         selector_pushes_before_mode_test=saves,
                         selector_assembly=entry[:32],
                         mode32_prologue=body(asm, 'X86_writeSimpleOutput32')[:22],
                         object_disassembly_sha256=hashlib.sha256(asm.encode()).hexdigest()))
result = dict(complete=True, rows=rows,
    conclusion='Clang previously saved and restored six registers before jumping into a second 32-bit frame. Separate leaves remove that frame. GCC previously inlined output into the iterator; both leaf experiments introduce an additional per-instruction call, callee prologue and stack-protector work. The next experiment keeps GCC inlining while retaining constant bitness.',
    scope='Actual recorded call edges and exclusive instruction/read/write counts, matched to the frozen disassembly; no native cycle or cache-stall inference.',
    followup='../round1407-output-mode-inline', original_negative_evidence_preserved=True)
(r / 'lowering-review.json').write_text(json.dumps(result, indent=2) + '\n')
for x in rows:
    print(x['experiment'], x['host'], 'Ir reduction', round(x['instruction_reduction'] * 100, 4), 'selector saves', x['selector_pushes_before_mode_test'], 'new call edges', x['calls']['modes'][:2])
