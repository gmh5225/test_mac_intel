from pathlib import Path
import json

r = Path(__file__).resolve().parent
read = lambda p: json.loads(p.read_text())
run, inputs = read(r / 'run.json'), read(r / 'inputs.json')
assert run['conclusion'] == 'success' and run['head_sha'] == (r / 'revision.txt').read_text().strip()
d, = (r / 'results').iterdir()
assert read(d / 'download.json')['digest'].startswith('sha256:')
done = read(d / 'complete.json')
assert done['integration_only'] and not done['native_timing'] and done['cases'] == 56
assert done['neverd'] == inputs['neverd'] and read(d / 'inputs.json') == inputs
assert read(d / 'cleanup.json')['removed'] and not any(read(d / 'residual.json').values())
checks = read(d / 'integration-case-equivalence.json')
assert checks['unchanged'] and len(checks['checks']) == 56
assert read(d / 'original-probe-equivalence.json')['unchanged']
assert read(d / 'batch-probe-equivalence.json')['unchanged']
llvm, managed = read(d / 'llvm-baseline-identity.json'), read(d / 'base-managed-source-identity.json')
assert not read(d / 'llvm_source_build.json')['prebuilt']
tests, states = {}, {}
for label in ('base', *inputs['variants']):
    assert read(d / (label + '-llvm-identity.json')) == llvm
    assert read(d / (label + '-managed-source-identity.json')) == managed
    log = (d / ('tests-' + label + '.log')).read_text()
    assert '100% tests passed' in log
    tests[label] = [line for line in log.splitlines() if 'tests passed' in line]
    states[label] = read(d / (label + '-public-state.json'))
    if label != 'base':
        diff = read(d / ('record-difference-' + label + '.json'))
        assert diff['changed'] == 0 and diff['states'] > 0
        assert read(d / (label + '-source-tree.json'))['tree'] == inputs['variants'][label]['tree']
result = dict(complete=True, run=run, inputs=inputs, tests=tests, states=states,
              case_equivalence=checks, llvm_identity=llvm, managed_source_identity=managed,
              cleanup=read(d / 'cleanup.json'), raw=str(d.relative_to(r)), native_timing=False,
              scope='Fresh current-dev build and semantic integration checks. Performance results remain attributed to the separately tested NeverD revision.')
(r / 'review.json').write_text(json.dumps(result, indent=2) + '\n')
print('Updated dev integration passed:', inputs['neverd'], '56 real-case signatures and full product states.')
