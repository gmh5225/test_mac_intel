from pathlib import Path
import json
import random
import statistics as st

r = Path(__file__).resolve().parent
read = lambda p: json.loads(p.read_text())
run = read(r / 'native-run.json')
assert run['conclusion'] == 'success' and run['head_sha'] == (r / 'native-revision.txt').read_text().strip()
directories = list((r / 'native').iterdir())
assert len(directories) == 1
d = directories[0]
assert read(d / 'download.json')['digest'].startswith('sha256:')
assert read(d / 'cleanup.json')['removed']
assert read(d / 'complete.json')['complete']
assert read(d / 'complete.json')['source'] == read(r / 'candidates.json')
assert read(d / 'consumer.json')['source_sha256'] == read(r / 'consumer-change.json')['modified_sha256']
assert read(d / 'consumer.json')['shared_by_all_variants']
controls = read(d / 'launch-controls.json')
assert controls['original_sha256']['base'] == controls['original_sha256']['aa']
assert set(read(d / 'scan-objects.json')['changed']) <= {
    'arch/X86/X86OutputIterator.c.o', 'arch/X86/X86MemoryOutput.c.o', 'arch/X86/X86ImmediateOutput.c.o'}

def estimate(values, seed):
    randomizer = random.Random(seed)
    samples = sorted(st.median(randomizer.choices(values, k=len(values))) for _ in range(2000))
    return dict(ratio=st.median(values), ci95=[samples[49], samples[1949]])

timings = read(d / 'timings.json')
assert len(timings) == 16
rows = []
for item in timings:
    assert len(item['pairs']) == 21
    key = '/'.join(map(str, (item['case'], item['mode'], item['launch'], item['observer'])))
    estimates = {v: estimate([x['ratios'][v] for x in item['pairs']], key + '/' + v)
                 for v in ('aa', 'scan')}
    assert all(estimates[v]['ratio'] == item['median'][v] for v in estimates)
    rows.append(dict(case=item['case'], mode=item['mode'], launch=item['launch'],
                     observer=item['observer'], repeats=item['repeats'], estimates=estimates))
interactions = []
for case, mode, launch in sorted({(x['case'], x['mode'], x['launch']) for x in timings}):
    pair = {x['observer']: x for x in timings if (x['case'], x['mode'], x['launch']) == (case, mode, launch)}
    assert pair.keys() == {0, 1}
    assert [x['cycle'] for x in pair[0]['pairs']] == [x['cycle'] for x in pair[1]['pairs']] == list(range(21))
    values = [a['ratios']['scan'] / b['ratios']['scan'] for a, b in zip(pair[0]['pairs'], pair[1]['pairs'])]
    interactions.append(dict(case=case, mode=mode, launch=launch,
        field_observation_gain_over_string_observation_gain=estimate(values, case + '/' + launch)))

pmu = read(d / 'pmu.json')
assert pmu['restore_returncode'] == 0 and pmu['restored_setting'] == pmu['original_setting']
hardware = []
if pmu['supported']:
    records = read(d / 'hardware.json')
    assert len(records) == 960
    assert all(all(v == 100 for v in x['counters']['running_percent'].values()) for x in records)
    assert all(all(v > 0 for v in x['counters']['counts'].values()) for x in records)
    for case, mode, observer in sorted({(x['case'], x['mode'], x['observer']) for x in records}):
        relevant = [x for x in records if (x['case'], x['mode'], x['observer']) == (case, mode, observer)]
        for event in ('cycles:u', 'instructions:u', 'r21:u', 'r22:u'):
            ratios = {'aa': [], 'scan': []}
            for cycle in range(20):
                current = [x for x in relevant if x['cycle'] == cycle]
                counts = {v: [x['counters']['counts'][event] for x in current if x['variant'] == v]
                          for v in ('base', 'aa', 'scan')}
                assert all(len(x) == 2 for x in counts.values())
                for v in ratios:
                    ratios[v].append(sum(counts[v]) / sum(counts['base']))
            hardware.append(dict(case=case, mode=mode, observer=observer, event=event,
                estimates={v: estimate(x, f'{case}/{mode}/{observer}/{event}/{v}') for v,x in ratios.items()}))
    assert len(hardware) == 32
report = dict(complete=True, run=run, source=read(r / 'candidates.json')['scan'], rows=rows,
              interactions=interactions, hardware=hardware, pmu=pmu,
              aa_flags=[x for x in rows if abs(x['estimates']['aa']['ratio'] - 1) > .01],
              observation_contract=read(d / 'observation-contract.json'),
              cleanup=read(d / 'cleanup.json'), publication_qualified=False,
              overall_goal_complete=False,
              scope='Diagnostic factorial comparison only; paired-cycle unadjusted bootstrap intervals. Runtime observer changes neither library text/detail options nor candidate sources. It changes the consumer code relative to frozen qualification. Hardware ratios are candidate/base whole-process counts, native gains are base/candidate measured-loop CPU time. Different calibrated work between observers and process startup limit direct counter comparisons across observers.')
(r / 'native-review.json').write_text(json.dumps(report, indent=2) + '\n')
print('observer panels', len(rows), 'interactions', len(interactions), 'A/A flags', len(report['aa_flags']))
