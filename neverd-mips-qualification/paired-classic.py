"""Compare both NeverD revisions and their public iterators on one runner."""
import hashlib
import json
import os
from pathlib import Path
import random
import statistics
import subprocess
import sys
import tempfile

from classic_corpora import varied_words

directory, output = map(Path, sys.argv[1:])
suffix = '.exe' if os.name == 'nt' else ''
binary = {v: directory.resolve() / (f'neverd-mips-bench-{v}' + suffix) for v in ('base', 'candidate')}
corpora = {
    'MIPS III interrupt': ('mips3', [0x8c820000, 0xac820000, 0x20820001,
                                   0x00850034, 0x0000000c, 0x10000001, 0x24020001]),
    'MIPS III ALU': ('mips3', [0x00851021, 0x00851025, 0x00851026,
                              0x0085102b, 0x0085102d, 0x00850034]),
    'MIPS64r2': ('mips64', [0x8c820000, 0xac820000, 0x10000001, 0x24020001]),
}
corpora.update(varied_words())
rng = random.Random(249035)
cases = {}
rows = []
results = {'binaries': {k: hashlib.sha256(v.read_bytes()).hexdigest() for k, v in binary.items()},
           'inputs': {}, 'blocks': 8, 'measurements': rows}
with tempfile.TemporaryDirectory() as temp:
    for name, (isa, words) in corpora.items():
        for byteorder, suffix in [('big', ''), ('little', 'el')]:
            label = name + '/' + byteorder
            blob = b''.join(w.to_bytes(4, byteorder) for w in words) * (1 if len(words) > 32 else 32)
            f = Path(temp) / str(len(cases))
            f.write_bytes(blob)
            cases[label] = (isa + suffix, f)
            results['inputs'][label] = hashlib.sha256(blob).hexdigest()

    def measure(key, stage, version, repeats):
        profile, path = cases[key]
        run = subprocess.check_output([binary[version], profile, stage, path, str(repeats)])
        return json.loads(run)

    jobs = [(key, stage) for key in cases for stage in ('capstone', 'decode', 'lift')
            if stage != 'lift' or not ('varied' in key or 'memory and exceptions' in key)]
    counts = {}
    for key, stage in jobs:
        probe = measure(key, stage, 'base', 1000)
        counts[key,stage] = min(80000, max(3000, int(1000 * 0.2 / max(0.001, probe['wall_seconds']))))
    for block in range(results['blocks']):
        rng.shuffle(jobs)
        for key, stage in jobs:
            steps = ['base','candidate'] if block % 2 else ['candidate','base']
            for version in steps + steps[::-1]:
                m = measure(key, stage, version, counts[key,stage])
                rows.append(dict(case=key, stage=stage, version=version, block=block, **m))
        print('completed block', block + 1, flush=True)
for key in cases:
    sample = [v for v in rows if v['case'] == key]
    assert len({(v['instructions_per_repeat'], v['digest']) for v in sample if v['stage'] != 'lift'}) == 1
    if any(v['stage'] == 'lift' for v in sample):
        assert len({(v['instructions_per_repeat'], v['operations_per_repeat'], v['digest']) for v in sample if v['stage'] == 'lift'}) == 1
    assert all(v['wall_seconds'] > 0 for v in sample)
output.write_text(json.dumps(results, indent=2) + '\n')
