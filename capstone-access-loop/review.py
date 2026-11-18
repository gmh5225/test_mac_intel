from pathlib import Path
import json
import xml.etree.ElementTree as ET

r = Path(__file__).resolve().parent
read = lambda p: json.loads(p.read_text())
meta = read(r / 'tree.json')
run = read(r / 'profiles-run.json')
assert run['conclusion'] == 'success' and run['head_sha'] == (r / 'profiles-revision.txt').read_text().strip()
profiles = []
for d in sorted((r / 'profiles').iterdir()):
    assert read(d / 'download.json')['digest'].startswith('sha256:')
    complete, cleanup = read(d / 'complete.json'), read(d / 'cleanup.json')
    assert complete['success'] and cleanup['removed'] and complete['source'] == meta
    cases = ET.parse(d / 'tests.xml').getroot().findall('testcase')
    assert len(cases) == len(complete['units'])
    assert not any(c.find('failure') is not None or c.find('skipped') is not None for c in cases)
    assert 'runtime error:' not in (d / 'tests.log').read_text()
    if complete['profile'] == 'adapter':
        assert complete['adapter_priority_cases'] == 168
        assert (d / 'adapter-precedence.log').read_text().strip().endswith('168 cases passed')
    profiles.append(dict(name=d.name, complete=complete, cleanup=cleanup))
expected = {('clang','sanitize'),('gcc','sanitize'),('clang','diet'),('gcc','diet'),
            ('clang','reduced'),('gcc','reduced'),('clang','adapter'),('clang','no-x86'),('clang','x86-only'),('gcc','x86-only')}
assert {(x['complete']['compiler'], x['complete']['profile']) for x in profiles} == expected
report = dict(complete=True, source=meta, run=run, profiles=profiles,
              unit_checks=sum(len(x['complete']['units']) for x in profiles),
              adapter_priority_cases=sum(x['complete']['adapter_priority_cases'] for x in profiles),
              cleaned_bytes=sum(x['cleanup']['bytes'] for x in profiles),
              publication_qualified=False)
(r / 'profiles-review.json').write_text(json.dumps(report, indent=2) + '\n')
print('Ten profiles:', report['unit_checks'], 'unit checks; adapter priority cases:', report['adapter_priority_cases'])
