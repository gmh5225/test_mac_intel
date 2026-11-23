"""Time direct Capstone, physical NeverD decode and lifting with identical code bytes."""
import hashlib
import json
import os
from pathlib import Path
import random
import subprocess
import sys
import tempfile

binary = Path(sys.argv[1]).resolve()
if os.name == 'nt':
    binary = binary.with_suffix('.exe')
results = {}
corpora = {
    'classic': (4, [0x24820001, 0x00851021, 0x00021040, 0x00451026]),
    'micro': (2, [0x0c44, 0x0558, 0x0559, 0x2540, 0x2543, 0xed7f, 0xed40,
                  0x00a4, 0x1150, 0x00a4, 0x11d0]),
    'mips16': (2, [0x6a81, 0xf010, 0x6a00, 0xf7ff, 0x6a1f, 0x4aff, 0xf7ff,
                   0x4a1f, 0x63ff, 0xf7ff, 0x631f]),
}
historical = json.loads(Path(__file__).with_name('source.json').read_text()).get('historical_profiles', False)
if historical:
    corpora.update({
        'mips1': (4, [0x24630002, 0x1000fffe, 0x24420001]),
        'mips2': (4, [0x24630002, 0x50850001, 0x24420001, 0x00621826]),
        'mips3': (4, [0x10000001, 0x24420100, 0x24420200]),
    })
randomizer = random.Random(419)
with tempfile.TemporaryDirectory() as temporary:
    fixture = Path(temporary) / 'input.bin'
    for isa in ['mips', 'mips64', 'micromips', 'micromips64', 'mips16'] + (['mips1', 'mips2', 'mips3'] if historical else []):
        family = 'micro' if isa.startswith('micro') else 'mips16' if isa == 'mips16' else 'classic'
        width, words = corpora[isa if isa in corpora else family]
        for endian, suffix in [('big', ''), ('little', 'el')]:
            profile = isa + suffix
            data = b''.join(w.to_bytes(width, endian) for w in words) * 32
            fixture.write_bytes(data)
            rows = {'capstone': [], 'decode': [], 'lift': []}
            for trial in range(5):
                order = list(rows)
                randomizer.shuffle(order)
                for stage in order:
                    invocation = [binary, profile, stage, fixture, '1300']
                    rows[stage].append(json.loads(subprocess.check_output(invocation)))
            digest = {row['digest'] for mode in ('decode', 'capstone') for row in rows[mode]}
            counts = {row['instructions_per_repeat'] for runs in rows.values() for row in runs}
            assert len(digest) == len(counts) == 1 and next(iter(counts)) > 0
            assert all(row['operations_per_repeat'] > 0 for row in rows['lift'])
            results[profile] = dict(sha256=hashlib.sha256(data).hexdigest(), measurements=rows)
    if historical:
        for order, suffix in [('big', ''), ('little', 'el')]:
            for words, minimum_level in [([0x50850001, 0], 2), ([0x0085102d], 3)]:
                fixture.write_bytes(b''.join(w.to_bytes(4, order) for w in words))
                for level in [1, 2, 3]:
                    profile = f'mips{level}{suffix}'
                    run = subprocess.run([binary, profile, 'decode', fixture, '1'], capture_output=True)
                    assert (run.returncode == 0) == (level >= minimum_level), (profile, words, run.stderr)
                    if run.returncode:
                        assert b'invalid/truncated' in run.stderr, run.stderr
Path(sys.argv[2]).write_text(json.dumps(results, indent=2) + '\n')
