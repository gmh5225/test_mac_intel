from pathlib import Path
import json
import statistics as st
from cost_parser import trace, instructions, interval

r = Path(__file__).resolve().parent
read = lambda p: json.loads(p.read_text())
protocol, run = read(r / 'protocol.json'), read(r / 'run.json')
assert run['conclusion'] == 'success' and run['head_sha'] == (r / 'revision.txt').read_text().strip()
profiles, rows, costs = [], [], []
for d in sorted((r / 'results').iterdir()):
    assert read(d / 'download.json')['digest'].startswith('sha256:')
    done, cleanup, cpu = read(d / 'complete.json'), read(d / 'cleanup.json'), read(d / 'cpu.json')
    assert cleanup['removed'] and done['protocol'] == protocol
    profile = dict(name=d.name, selected=done['selected'], cpu=cpu, cleanup=cleanup)
    profiles.append(profile)
    if not done['selected']:
        assert cpu['model'] != protocol['requested_cpu'] and done['cases'] == 0
        continue
    assert cpu['model'] == protocol['requested_cpu']
    source = protocol['source']['variants']['merge']
    assert read(d / 'merge-tested-source.json') == dict(tree=source['tree'], patch_sha256=source['sha256'])
    assert read(d / 'objects-merge.json')['changed'] == ['arch/X86/X86EvexScan.c.o']
    assert read(d / 'merge-linked-layout.json')['unmodified_text_positions_identical']
    controls = read(d / 'launch-controls.json')
    assert controls['aslr_disable_returncode'] == 0
    assert controls['original_sha256']['base'] == controls['original_sha256']['aa']
    names = {x['alias'] for x in controls['identities'].values()} | {controls['shared_path']}
    assert len(names) == 4 and len({len(n) for n in names}) == 1
    values = read(d / 'timings.json')
    assert len(values) == done['cases'] == 10
    assert {x['launch'] for x in values} == {a + '-' + b for a in protocol['image_controls'] for b in protocol['aslr_controls']}
    for x in values:
        assert (x['case'], x['mode']) == ('arm64-ls', 0)
        assert len(x['pairs']) == protocol['cycles'] == 36
        ratios = {v: [pair[v] for pair in x['pairs']] for v in ('aa', 'merge')}
        assert all(st.median(v) == x['median'][k] for k, v in ratios.items())
        key = d.name + '/' + x['launch']
        rows.append(dict(host=d.name, launch=x['launch'], gain=x['median']['merge'],
                         ci95=interval(ratios['merge'], key), aa=x['median']['aa'],
                         aa_ci95=interval(ratios['aa'], key + '/aa')))
    observed = {x['variant']: x for x in read(d / 'instruction-costs.json')}
    assert set(observed) == {'base', 'merge'}
    assert all(x['collected_traversals'] == 3 for x in observed.values())
    assert observed['base']['result'] == observed['merge']['result']
    parsed = {label: trace(d / ('arm64-ls-0-' + label + '.callgrind.gz'), label) for label in observed}
    assembly = {label: instructions(d / (label + '-linked-disassembly.gz')) for label in observed}
    for label, (functions, pcs) in parsed.items():
        assert pcs and set(pcs) <= set(assembly[label])
        assert [sum(v[i] for v in functions.values()) for i in range(3)] == [observed[label]['events'][k] for k in ('Ir', 'Dr', 'Dw')]
    old_fn, old_pc = parsed['base']; new_fn, new_pc = parsed['merge']
    changed_bytes = [pc for pc in old_pc.keys() & new_pc.keys() if assembly['base'][pc][0] != assembly['merge'][pc][0]]
    costs.append(dict(host=d.name, totals_equal=all(observed['base']['events'][k] == observed['merge']['events'][k] for k in ('Ir', 'Dr', 'Dw')),
                      function_counts_equal=old_fn == new_fn, executable_pc_counts_equal=old_pc == new_pc,
                      changed_executed_bytes=len(changed_bytes), examples=changed_bytes[:12]))
    debug = read(d / 'debug-entries.json')
    assert len(debug) == 15
    profile['entry_diagnostics'] = debug
    profile['debug_complete'] = all(x['returncode'] == 0 and len(x['entries']) == 1 for x in debug)
    for x in debug:
        x['entry_offsets'] = [{k: dict(mod64=int(v,16)%64, mod4096=int(v,16)%4096) for k,v in entry.items()} for entry in x['entries']]
assert len(profiles) == protocol['allocations'] == 4
selected = sum(x['selected'] for x in profiles)
assert len(rows) == selected * 10 and len(costs) == selected
report = dict(complete=True, run=run, protocol=protocol, profiles=profiles, rows=rows, costs=costs,
              selected_profiles=selected, losses=[x for x in rows if x['gain'] < .99],
              aa_outside_one_percent=[x for x in rows if abs(x['aa'] - 1) > .01],
              publication_qualified=False,
              scope='Controlled launch diagnosis with frozen binaries and consumer. Preserve the original timing flag. Nonmatching CPU allocations do not provide performance evidence. GDB observations are outside native timing; instruction and byte equality are not hardware PMU attribution.',
              directory_context=protocol['directory_control'])
(r / 'review.json').write_text(json.dumps(report, indent=2) + '\n')
print('Selected original CPU allocations:', selected, 'rows:', len(rows), 'losses:', len(report['losses']), 'AA flags:', len(report['aa_outside_one_percent']))
for x in rows:
    print(x['host'], x['launch'], round(x['gain'], 5), x['ci95'], 'AA', round(x['aa'], 5))
