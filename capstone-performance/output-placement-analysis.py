"""Preserve per-output-offset effects and the same-path timing controls."""
from pathlib import Path
import json
import math
import statistics

ROOT = Path(__file__).resolve().parent


def geomean(values):
    return math.exp(statistics.mean(map(math.log, values)))


analyses = []
for artifact in sorted((ROOT / 'windows').glob('*')):
    if not (artifact / 'download.json').exists():
        continue
    if not (artifact / 'complete.json').exists():
        print(artifact.name, 'incomplete')
        continue
    measured = json.loads((artifact / 'measurements.json').read_text())
    snapshots = json.loads((artifact / 'snapshots.json').read_text())
    for row in snapshots:
        assert all(value == row['outputs'][0] for value in row['outputs'])
    cells = []
    for item in measured:
        rows = item['rows']
        for consumer in sorted({row['consumer'] for row in rows}):
            selected = [row for row in rows if row['consumer'] == consumer]
            offsets = []
            for padding in sorted({row['base'] for row in selected}):
                group = [row for row in selected if row['base'] == padding]
                addresses = {key: set() for key in ('image_base', 'output', 'detail_storage',
                                                    'input_storage', 'handle', 'stack', 'run_stack')}
                times = {'base': [], 'new': []}
                wall = []
                for row in group:
                    assert all(value['result'] == row['raw'][0][1]['result'] for _, value in row['raw'])
                    per_wall = {'base': [], 'new': []}
                    for label, value in row['raw']:
                        for key in addresses:
                            addresses[key].add(value[key])
                        times[label].append(value['thread_cycles'] / value['result']['instructions'])
                        per_wall[label].append(value['wall_ns'])
                    wall.append(statistics.mean(per_wall['base']) / statistics.mean(per_wall['new']))
                assert all(len(values) == 1 for values in addresses.values())
                offsets.append(dict(
                    byte_offset=padding, ratio=statistics.median([row['gain'] for row in group]),
                    wall_ratio=statistics.median(wall), cycles=len(group),
                    positive_cycles=sum(row['gain'] > 1 for row in group),
                    aa_median=[statistics.median([abs(row['aa'][index] - 1) for row in group])
                               for index in range(2)],
                    cycles_per_instruction={key: statistics.median(value) for key, value in times.items()},
                    addresses={key: next(iter(value)) for key, value in addresses.items()}))
            cells.append(dict(panel=item['panel'], case=item['case'], mode=item['mode'],
                              consumer=consumer, offsets=offsets,
                              geomean=geomean([offset['ratio'] for offset in offsets])))
    aggregates = []
    for panel in sorted({cell['panel'] for cell in cells}):
        for consumer in sorted({cell['consumer'] for cell in cells}):
            for family in ['x86', 'other']:
                for mode in [0, 1, 2]:
                    selected = [cell for cell in cells if cell['panel'] == panel and
                                cell['consumer'] == consumer and cell['mode'] == mode and
                                (cell['case'].startswith(('putty', 'scalar', 'simd'))) == (family == 'x86')]
                    if selected:
                        aggregates.append(dict(panel=panel, consumer=consumer, family=family, mode=mode,
                                               cells=len(selected), geomean=geomean([cell['geomean'] for cell in selected])))
    cleanup = json.loads((artifact / 'cleanup.json').read_text())
    assert cleanup['removed']
    analyses.append(dict(artifact=artifact.name, cpu=json.loads((artifact / 'processor.json').read_text()),
                         frames=json.loads((artifact / 'frames.json').read_text()),
                         public_records=sum(row['outputs'][0]['records'] for row in snapshots),
                         cells=cells, aggregate=aggregates, cleanup=cleanup))
(ROOT / 'analysis.json').write_text(json.dumps(analyses, indent=2) + '\n')
for analysis in analyses:
    print(analysis['artifact'], analysis['cpu'], analysis['frames'])
    for group in analysis['aggregate']:
        print(group['panel'], group['consumer'], group['family'], group['mode'], round(group['geomean'], 5))
