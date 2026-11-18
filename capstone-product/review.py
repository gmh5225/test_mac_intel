from pathlib import Path
import hashlib
import json

r = Path(__file__).resolve().parent
read = lambda f: json.loads(f.read_text())
run, inputs = read(r / 'product-run.json'), read(r / 'product-check/inputs.json')
assert run['status'] == 'completed' and run['conclusion'] == 'failure'
assert run['head_sha'] == (r / 'product-check/revision.txt').read_text().strip()
d, = (r / 'product').iterdir()
assert read(d / 'download.json')['digest'].startswith('sha256:')
assert read(d / 'cleanup.json')['removed']
log = (r / 'failed-job.log').read_text()
assert 'assert integration_binaries[before] == integration_binaries[after]' in log
assert not (d / 'complete.json').exists()
labels = ['base', *inputs['variants']]
states, differences, tests, heads, source_trees = {}, {}, {}, {}, {}
reference = read(d / 'base-real-signatures.json')
for label in labels:
    assert '100% tests passed, 0 tests failed out of 34' in (d / ('tests-'+label+'.log')).read_text()
    tests[label] = 34
    states[label] = read(d / (label+'-public-state.json'))
    heads[label] = read(d / (label+'-neverd-head.json'))
    assert heads[label] == inputs['current_neverd' if label.startswith('current-') else 'neverd']
    source_trees[label] = read(d / (label+'-source-tree.json'))
    if label != 'base':
        assert source_trees[label]['tree'] == inputs['variants'][label]['tree']
    assert read(d / (label+'-llvm-identity.json')) == inputs['prior_llvm_identity']
    assert read(d / (label+'-managed-source-identity.json')) == inputs['prior_managed_source_identity']
    assert read(d / (label+'-real-signatures.json')) == reference
for f in d.glob('record-difference-*.json'):
    record = read(f)
    assert record['states'] == 40068 and record['changed'] == 0 and record['classes'] == []
    differences[f.stem] = record
assert len(differences) == 4 and len(set(states.values())) == 1
binaries = read(d / 'integration-binaries.json')
pairs = [('base', 'current-base'), ('small-alias-output', 'current-alias-output')]
identity = []
for before, after in pairs:
    assert read(d / (before+'-objects.json')) == read(d / (after+'-objects.json'))
    names = sorted(binaries[before])
    assert len(names) == 4 and all(binaries[before][name] != binaries[after][name] for name in names)
    symbol_files_identical = all((d/(stem+'-'+before+'.log')).read_bytes() == (d/(stem+'-'+after+'.log')).read_bytes()
                                 for stem in ('timed-symbols', 'symbols', 'linked-light'))
    identity.append(dict(before=before, after=after, all_four_executables_differ=True,
        capstone_object_bytes_identical=True, captured_symbols_and_decodeOneLight_disassembly_identical=symbol_files_identical))
report = dict(complete=True, run=run, failed_gate='Exact complete linked executable identity across different NeverD heads',
    semantic_checks_passed=True, tests=tests, states=states, complete_state_differences=differences,
    heads=heads, capstone_source_trees=source_trees, llvm_source_identity=inputs['prior_llvm_identity'],
    prebuilt=False, real_input_checks_per_variant=len(reference), real_cases=len({x['case'] for x in reference}),
    binary_identity=identity, integration_binaries=binaries, cleanup=read(d / 'cleanup.json'),
    failed_log_sha256=hashlib.sha256((r / 'failed-job.log').read_bytes()).hexdigest(),
    source_transfer_qualified=False, timing_repeated=False, publication_qualified=False,
    scope='Preserve the failed exact-binary transfer. All four builds passed 34 tests, 40068 complete states and 56 real-input/mode signatures. Capstone object bytes and the captured symbols/entry disassembly are identical across the head pairs, but that does not prove equality of all executable bytes or allow moving old timings to the newer head. The later 30335927/e02db43d integration was separately reviewed at the source contract; this run does not build those later heads.')
(r / 'failed-identity-review.json').write_text(json.dumps(report, indent=2)+'\n')
print('Preserved failed full-image identity; 136 tests, complete states and 56 signatures per variant passed.')
