"""Audit the failed terminal assertion without changing the original artifacts."""
from pathlib import Path
import ast
import copy
import hashlib
import json
import subprocess as sp

r = Path(__file__).resolve().parent
read = lambda p: json.loads(p.read_text())
sha = lambda b: hashlib.sha256(b).hexdigest()
run = read(r / 'native-run.json')
assert run['status'] == 'completed' and run['conclusion'] == 'failure'
assert run['head_sha'] == (r / 'native-revision.txt').read_text().strip()
repo = r.parent / 'round349-intel-actions/repo'
original = sp.check_output(['git', '-C', repo, 'show', run['head_sha'] + ':capstone-vectors/measure.py']).decode()
fixed = (r / 'timing-driver.py').read_text()
old = '    assert len(costs)==6\n'
new = "    expected_costs={(mode,label) for mode in (0,1,2) for label in ('integer','signature','classbit')}\n    assert len(costs)==len(expected_costs) and {(row['mode'],row['variant']) for row in costs}==expected_costs\n"
assert original.count(old) == 1 and fixed == original.replace(old, new)
(r / 'failed-timing-driver.py').write_text(original)
ast.parse(fixed)

def terminal(code, marker, costs, records, launches):
    segment = code[code.index(marker):code.index('\nw=Path(tempfile.mkdtemp')]
    segment = '\n'.join(line[4:] for line in segment.splitlines())
    saved = {}
    scope = dict(costs=costs, reported=records, launches=launches,
                 save=lambda name, value: saved.update({name: value}))
    exec(compile(segment, '<exact-terminal-postconditions>', 'exec'), scope)
    return saved

profiles = {}
for d in sorted((r / 'native').iterdir()):
    version = '14' if '22.04' in d.name else '18'
    log = (r / ('native-clang' + version + '-job.log')).read_text()
    assert log.count('Traceback (most recent call last):') == 1
    assert 'assert len(costs)==6' in log and 'AssertionError' in log
    assert not (d / 'complete.json').exists()
    costs = read(d / 'instruction-costs.json')
    records = read(d / 'measurements.json')
    launches = read(d / 'launch-controls.json')['launches']
    assert len(records) == 42 and launches == ['images', 'same-file-fixed']
    assert all(len(row['cycles']) == 32 for row in records)
    assert read(d / 'cleanup.json')['removed']
    try:
        terminal(original, old, costs, records, launches)
    except AssertionError:
        pass
    else:
        raise AssertionError('The original final assertion must reproduce its failure')
    saved = terminal(fixed, new.splitlines()[0] + '\n', costs, records, launches)
    assert saved['complete.json']['cases'] == 42
    invalid = [costs[:-1], costs[:-1] + [costs[0]], copy.deepcopy(costs)]
    invalid[-1][0]['mode'] = 3
    for rows in invalid:
        try:
            terminal(fixed, new.splitlines()[0] + '\n', rows, records, launches)
        except AssertionError:
            pass
        else:
            raise AssertionError('Incomplete, duplicate, or unexpected cost coverage was accepted')
    profiles[d.name] = dict(artifact=read(d / 'download.json'),
        observed_cost_records=len(costs), original_failure_reproduced=True,
        repaired_postcondition_passed=True, malformed_matrices_rejected=len(invalid),
        derived_complete=saved['complete.json'],
        measurements_sha256=sha((d / 'measurements.json').read_bytes()),
        costs_sha256=sha((d / 'instruction-costs.json').read_bytes()),
        job_log_sha256=sha(log.encode()))
assert len(profiles) == 2
audit = dict(complete=True, source_run=run, original_driver_sha256=sha(original.encode()),
    corrected_driver_sha256=sha(fixed.encode()), profiles=profiles,
    scope='Local replay of the exact terminal postconditions over complete immutable native artifacts. The original Actions run remains failed. No timing is rerun or discarded, and no complete.json is added to the original artifacts.',
    publication_qualified=False)
(r / 'completion-audit.json').write_text(json.dumps(audit, indent=2) + '\n')
print('Both original terminal failures reproduced; both repaired matrices passed; six malformed matrices rejected.')
