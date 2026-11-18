from pathlib import Path
import difflib
import gzip
import hashlib
import json
import re

r = Path(__file__).resolve().parent


def canonical(path):
    source = gzip.decompress(path.read_bytes()).decode().splitlines()
    start = next(i for i, line in enumerate(source)
                 if line.startswith('define ') and '@X86_trySimpleOutput(' in line)
    end = next(i for i in range(start, len(source)) if source[i] == '}')
    lines = source[start:end+1]
    names = {'%' + name: '%arg' + str(i) for i, name in
             enumerate(('handle', 'code', 'size', 'insn', 'insn_size'))}
    labels = {}
    index = 0
    for line in lines:
        label = re.match(r'^([-\w.]+):', line)
        if label:
            labels[label[1]] = 'block' + str(len(labels))
            names['%' + label[1]] = '%' + labels[label[1]]
        value = re.match(r'^\s*(%[-\w.]+)\s*=', line)
        if value:
            names[value[1]] = '%value' + str(index)
            index += 1
    result = []
    for line in lines:
        line = line.split(';', 1)[0].strip()
        if not line:
            continue
        if line.endswith(':'):
            line = labels[line[:-1]] + ':'
        line = re.sub(r'%[-\w.]+', lambda m: names.get(m[0], m[0]), line)
        result.append(line)
    return result


profiles = []
for directory in sorted((r / 'profile').glob('*clang*')):
    if not (directory / 'plan32-iterator.ll.gz').exists():
        continue
    original = canonical(directory / 'integer-iterator.ll.gz')
    candidate = canonical(directory / 'plan32-iterator.ll.gz')
    calls = [[line for line in text if '@X86_writeVex32Output(' in line]
             for text in (original, candidate)]
    assert all(len(x) == 1 for x in calls)
    remainder = [[line for line in text if '@X86_writeVex32Output(' not in line]
                 for text in (original, candidate)]
    diff = list(difflib.unified_diff(original, candidate, fromfile='four-argument', tofile='six-argument'))
    file = directory.name + '-canonical-iterator-ir.patch'
    (r / file).write_text('\n'.join(diff) + '\n')
    profiles.append(dict(profile=directory.name, original_call=calls[0][0], candidate_call=calls[1][0],
                         remainder_identical=remainder[0] == remainder[1], diff=file,
                         canonical_ir_sha256=[hashlib.sha256('\n'.join(v).encode()).hexdigest()
                                              for v in (original, candidate)]))
report = dict(complete=len(profiles) == 2, profiles=profiles,
              method='Rename SSA definitions and block labels in their original order; retain all operations, operands, metadata, types and branch destinations. Compare the remainder after removing the one VEX32 call.',
              scope='A matching remainder isolates this compiler experiment to call arguments at optimized LLVM IR, before machine register allocation. It does not assert identical machine code or native throughput.')
(r / 'ir-signature-review.json').write_text(json.dumps(report, indent=2) + '\n')
for profile in profiles:
    print(profile['profile'], 'IR outside the leaf call identical:', profile['remainder_identical'])
