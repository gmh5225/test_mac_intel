from collections import defaultdict
from pathlib import Path
import gzip
import hashlib
import json
import re

r = Path(__file__).resolve().parent
d, = (r / 'native').iterdir()
parser = r.parent / 'round1362-evex-extension-isolated-entry/review-cost.py'
code = parser.read_text()
code = code[:code.index('rows=[]')]
code = code.replace("owner.endswith('/run-' + variant)", "owner.endswith('/same-image')")
code = code.replace('executed[positions[0]] += counts[0]', '''executed[positions[0]] += counts[0]
                    for i in range(3):
                        address_events[positions[0]][i] += counts[i]''')
scope = {'__file__': str(parser)}
exec(code, scope)

assembly = {}
for variant in ('base', 'dispatch', 'scan'):
    instructions = {}
    owner = None
    for line in gzip.open(d / (variant + '-linked-assembly.gz'), 'rt'):
        header = re.match(r'^([0-9a-f]+) <(.+)>:', line)
        if header:
            owner = header[2]
        match = re.match(r'^\s*([0-9a-f]+):\s*[0-9a-f]{8}\s+(.*)$', line)
        if match:
            instructions[int(match[1], 16)] = (owner, match[2])
    assembly[variant] = instructions

rows = []
values = json.loads((d / 'instruction-costs.json').read_text())
for case, mode in sorted({(x['case'], x['mode']) for x in values
                          if x['case'] in ('scalar32', 'scalar64', 'simd64')}):
    owners = {}
    for variant in assembly:
        scope['address_events'] = defaultdict(lambda: [0, 0, 0])
        scope['trace'](d / f'cost-{case}-{mode}-{variant}.callgrind.gz', variant)
        addresses = scope['address_events']
        missing = addresses.keys() - assembly[variant].keys()
        assert not missing, (variant, case, [hex(x) for x in sorted(missing)[:10]])
        counts = defaultdict(lambda: [0, 0, 0])
        for address, events in addresses.items():
            owner, _ = assembly[variant][address]
            for i in range(3):
                counts[owner][i] += events[i]
        assert [sum(x[i] for x in counts.values()) for i in range(3)] == [
            sum(x[i] for x in addresses.values()) for i in range(3)]
        owners[variant] = dict(counts)
    changes = {}
    for variant in ('dispatch', 'scan'):
        delta = {name: [owners[variant].get(name, [0]*3)[i] -
                        owners['base'].get(name, [0]*3)[i] for i in range(3)]
                 for name in owners[variant].keys() | owners['base'].keys()}
        changes[variant] = {name: events for name, events in delta.items() if any(events)}
    rows.append(dict(case=case, mode=mode, changes=changes, owners=owners))

report = dict(complete=True, source=json.loads((r / 'candidates.json').read_text()),
              rows=rows, parser_sha256=hashlib.sha256(code.encode()).hexdigest(),
              finding='ARM Callgrind attributes some instructions after a return to the callee. '
                      'For example, the extra MOV after X86_writeImmediateOutput returns belongs '
                      'to X86_trySimpleOutput in the linked assembly. Actual instruction addresses '
                      'locate this cost in the iterator; the immediate writer itself is unchanged.',
              scope='The four old scalar/SIMD panels only: exclusive simulated instruction and memory references mapped by actual linked '
                    'instruction address for the fixed guest executable. Shared-library events and '
                    'native timing are outside this attribution. Original named-function reports '
                    'remain preserved, and total counts are not changed.',
              excluded='The initial broader address join found four MIPS printer-context addresses '
                       'absent from the saved executable disassembly. This focused x86 analysis makes '
                       'no claim about physical MIPS/libc ownership; native-review.json retains those '
                       'original context counts.',
              format_reference='https://valgrind.org/docs/manual/cl-format.html')
(r / 'address-attribution.json').write_text(json.dumps(report, indent=2) + '\n')
for row in rows:
    if row['case'] in ('scalar32', 'scalar64', 'simd64'):
        print(row['case'], row['mode'], row['changes'], flush=True)
