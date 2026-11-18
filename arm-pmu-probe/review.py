from pathlib import Path
import json

r = Path(__file__).resolve().parent
read = lambda file: json.loads(file.read_text())
run = read(r / 'native-run.json')
assert run['status'] == 'completed' and run['conclusion'] == 'success'
assert run['head_sha'] == (r / 'native-revision.txt').read_text().strip()
d, = (r / 'native').iterdir()
assert read(d / 'download.json')['digest'].startswith('sha256:')
assert read(d / 'complete.json')['complete'] and read(d / 'permissions.json')['restored']
report = dict(complete=True, run=run, host=read(d / 'environment.json'),
              permissions=read(d / 'permissions.json'), capability=read(d / 'capability.json'),
              publication_qualified=False, production_modified=False,
              scope='Only hardware-event availability. No candidate code or native speed was measured.')
(r / 'native-review.json').write_text(json.dumps(report, indent=2) + '\n')
print('ARM PMU available:', report['capability']['available'])
for item in report['capability']['records']:
    print(item['group'], item['available'], item['counts'], item['stderr'].strip())
