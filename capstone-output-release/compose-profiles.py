from pathlib import Path
import ast
import gzip
import json
import re
import subprocess as sp

r = Path(__file__).resolve().parent
repair = r.parent/'round1478-sanitizer-location-control'
read = lambda p: json.loads(p.read_text())
def log_text(p):
    return p.read_text(errors='replace') if p.exists() else gzip.decompress(p.with_suffix(p.suffix+'.gz').read_bytes()).decode(errors='replace')

source = read(r/'tree.json')
original = read(r/'profiles-run.json')
fixed = read(repair/'profiles-run.json')
assert original['status'] == fixed['status'] == 'completed'
assert original['conclusion'] == 'failure' and fixed['conclusion'] == 'success'
assert original['head_sha'] == (r/'profiles-revision.txt').read_text().strip()
assert fixed['head_sha'] == (repair/'profiles-revision.txt').read_text().strip()
assert source['tree'] == read(repair/'tree.json')['tree']
assert source['sha256'] == read(repair/'tree.json')['sha256']
repo = r.parent/'round349-intel-actions/repo'
for run in (original, fixed):
    meta = json.loads(sp.check_output(['git','-C',repo,'show',run['head_sha']+':capstone-output-release/candidate.json'], text=True))
    assert (meta['tree'], meta['sha256']) == (source['tree'], source['sha256'])

def audit(d, item):
    assert read(d/'download.json')['digest'].startswith('sha256:')
    assert read(d/'cleanup.json')['removed']
    units = scheduled = 0
    skipped = {}
    for phase in item['phases']:
        text = log_text(d/(phase+'-tests.log'))
        assert 'runtime error:' not in text and 'ERROR: AddressSanitizer' not in text
        count = re.search(r'100% tests passed(?:, 0 tests failed)? out of (\d+)', text)
        assert count
        skipped[phase] = re.findall(r'^\s*\d+ - (\S+) \(Skipped\)', text, re.M)
        assert set(skipped[phase]) <= {'unit_x86_x87_environment_hardware'}
        scheduled += int(count[1])
        units += int(count[1]) - len(skipped[phase])
    fixtures = {}
    for f in sorted({x.with_suffix('') if x.suffix == '.gz' else x for x in d.glob('*-fixtures.log*')}):
        text = log_text(f)
        assert 'runtime error:' not in text and 'ERROR: AddressSanitizer' not in text
        counts = re.findall(r'Decoded instructions:\s+(\d+)', text)
        assert len(counts) == 1 and int(counts[0]) > 0
        fixtures[f.stem] = int(counts[0])
    for arch in ('arm','aarch64','mips','riscv'):
        assert len({n for key,n in fixtures.items() if key.endswith('-'+arch+'-fixtures')}) <= 1
    return dict(host=d.name, result=item, units=units, scheduled_units=scheduled,
                skipped=skipped, fixtures=fixtures, cleanup=read(d/'cleanup.json'))

rows = []
failed = []
for d in sorted((r/'profiles').iterdir()):
    if not (d/'complete.json').exists():
        failed.append(d)
        continue
    item = read(d/'complete.json')
    assert item['tested_tree'] == source['tree']
    if item['arm_policy_active']:
        assert item['observer_executed']
    if (d/'runtime-objects.json').exists():
        proof = read(d/'runtime-objects.json')
        assert set(proof['changed']) <= set(proof['allowed'])
        if item['archs'] == 'x86':
            assert not proof['changed']
    else:
        assert item['compiler'] in ('MT','MD')
    row = audit(d,item)
    row['run_id'] = original['id']
    rows.append(row)
assert len(rows) == 16 and len(failed) == 1 and '-sanitize-' in failed[0].name

fixed_report = read(repair/'profiles-review.json')
assert fixed_report['complete'] and len(fixed_report['rows']) == 1
fixed_row = fixed_report['rows'][0]
d = repair/'profiles'/fixed_row['host']
proof = read(d/'source-location-object-proof.json')
assert proof['all_nonowner_objects_identical'] and proof['location_control_changed'] == ['cs.c.o']
failure_log = (r/'sanitizer-job.log').read_text()
assertion, = re.findall(r'AssertionError: (\[[^\n]+\])', failure_log)
assert set(ast.literal_eval(assertion)) == set(proof['raw_changed'])
failed_semantics = audit(failed[0], fixed_row['result'])
assert failed_semantics['units'] == fixed_row['units'] == 289
assert failed_semantics['fixtures'] == fixed_row['fixtures']
row = audit(d, fixed_row['result'])
row['run_id'] = fixed['id']
rows.append(row)
assert len(rows) == len(read(r/'profiles-matrix.json')) == 17
report = dict(complete=True, publication_qualified=False, source=source,
              original_run=original, repair_run=fixed, rows=rows,
              unit_executions=sum(x['units'] for x in rows),
              scheduled_unit_executions=sum(x['scheduled_units'] for x in rows),
              fixture_executions=sum(sum(x['fixtures'].values()) for x in rows),
              original_failed_job_semantic_tests=failed_semantics,
              source_location_proof=proof,
              scope='Sixteen successful original profiles plus one exact-source sanitizer rerun. The original failed run and its test evidence remain unchanged. All semantic tests use the unmodified candidate; the diagnostic #line adjustment is used only to attribute object metadata differences. Native performance and current NeverD integration remain separate requirements.')
(r/'profiles-composition-review.json').write_text(json.dumps(report,indent=2)+'\n')
print('profiles',len(rows),'unit executions',report['unit_executions'],'fixture executions',report['fixture_executions'])
