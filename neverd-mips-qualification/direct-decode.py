"""Compare the public iterator and native decoder in adjacent measurements."""
import hashlib
import json
from pathlib import Path
import platform
import statistics
import subprocess
import sys
import tempfile

from classic_corpora import varied_words

binary, output = (Path(arg).resolve() for arg in sys.argv[1:])
case = 'MIPS III mixed memory and exceptions'
isa, words = dict(varied_words())[case]
expected_sha = {
    'big': 'dc8592caa7c3d869a2f441ecd92ebf9baac6078d6e999006328bedd8abee61dc',
    'little': '19ec52ebbdc95c127d8bbfc3e1c8281d99ee84034e1dcf885a2ad6ff463bb669',
}
blocks = 24
samples = []
with tempfile.TemporaryDirectory() as temp:
    cases = {}
    for order, digest in expected_sha.items():
        code = b''.join(word.to_bytes(4, order) for word in words)
        assert hashlib.sha256(code).hexdigest() == digest
        path = Path(temp) / order
        path.write_bytes(code)
        cases[order] = (isa if order == 'big' else isa + 'el', path)

    def run(order, stage, repeats):
        profile, path = cases[order]
        return json.loads(subprocess.check_output([binary, profile, stage, path, str(repeats)]))

    repeats = {}
    for order in cases:
        pilot = run(order, 'decode', 2000)
        repeats[order] = max(1500, min(60000, round(2000 * 0.2 / pilot['wall_seconds'])))
        run(order, 'capstone', repeats[order])
    for block in range(blocks):
        orders = ('big', 'little') if block % 4 < 2 else ('little', 'big')
        stages = ('capstone', 'decode') if block % 2 == 0 else ('decode', 'capstone')
        for order in orders:
            for stage in stages + stages[::-1]:
                samples.append({'block': block, 'byte_order': order, 'stage': stage,
                                **run(order, stage, repeats[order])})

summary = {}
for order in cases:
    selected = [row for row in samples if row['byte_order'] == order]
    assert len({(r['instructions_per_repeat'], r['digest']) for r in selected}) == 1
    assert all(r['instructions_per_repeat'] == len(words) for r in selected)
    summary[order] = {}
    for field in ('wall_seconds', 'cpu_seconds'):
        medians = {}
        for stage in ('capstone', 'decode'):
            by_block = []
            for block in range(blocks):
                pair = [r[field] * 1e9 / (r['instructions_per_repeat'] * r['repeats'])
                        for r in selected if r['stage'] == stage and r['block'] == block]
                assert len(pair) == 2 and min(pair) > 0
                by_block.append(statistics.median(pair))
            medians[stage] = by_block
        delta = [100 * (nd / cs - 1) for nd, cs in zip(medians['decode'], medians['capstone'])]
        summary[order][field] = {
            'decode_ns': statistics.median(medians['decode']),
            'capstone_ns': statistics.median(medians['capstone']),
            'paired_elapsed_percent': statistics.median(delta),
            'faster_blocks': sum(d < 0 for d in delta),
            'block_percents': delta,
        }
receipt = {
    'source': subprocess.check_output(['git', 'rev-parse', 'HEAD'], text=True).strip(),
    'capstone': subprocess.check_output(['git', '-C', 'third_party/capstone', 'rev-parse', 'HEAD'], text=True).strip(),
    'hardware': subprocess.check_output(['sysctl', '-n', 'machdep.cpu.brand_string'], text=True).strip(),
    'system': platform.platform(), 'binary_sha256': hashlib.sha256(binary.read_bytes()).hexdigest(),
    'case': case, 'inputs': expected_sha, 'blocks': blocks, 'summary': summary, 'samples': samples,
}
output.write_text(json.dumps(receipt, indent=2) + '\n')
for order, metrics in summary.items():
    print(order, metrics['wall_seconds']['paired_elapsed_percent'], metrics['wall_seconds']['faster_blocks'])
