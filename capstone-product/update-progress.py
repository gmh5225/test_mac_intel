from pathlib import Path
import json

r = Path(__file__).resolve().parent
read = lambda p: json.loads(p.read_text())
reports = {}
paths = {
    'native_original': '../round1367-evex-transfer-comparison/native-review.json',
    'mixed_original': '../round1367-evex-transfer-comparison/mixed-review.json',
    'native_controls': '../round1370-evex-transfer-launch-controls/native-review.json',
    'mixed_controls': '../round1370-evex-transfer-launch-controls/mixed-review.json',
    'image_identity': '../round1374-evex-transfer-image-identity/review.json',
    'original_context': '../round1376-evex-transfer-original-context/review.json',
    'original_context_final': '../round1377-evex-transfer-original-context-final/review.json',
    'profiles': 'profiles-review.json', 'portable': 'build-review.json',
    'product': 'product-review.json',
    'current_dev': '../round1378-transfer-current-dev-integration/review.json',
}
for name, file in paths.items():
    path = r / file
    if not path.exists():
        reports[name] = dict(status='pending', file=file)
        continue
    data = read(path)
    item = dict(status='reviewed', file=file, run=data.get('run'))
    for key in ('complete', 'unit_checks', 'checks', 'adapter_priority_cases', 'selected_profiles'):
        if key in data:
            item[key] = data[key]
    for key in ('rows', 'costs', 'aa_outside_one_percent'):
        if key in data:
            item[key] = len(data[key])
    if 'losses' in data:
        v = data['losses']
        item['losses'] = {k: len(a) for k, a in v.items()} if isinstance(v, dict) else len(v)
    reports[name] = item
publication = read(r / 'publication.json') if (r / 'publication.json').exists() else None
published = publication and all(publication[k]['published'] for k in ('capstone', 'neverd'))
report = dict(status='Published to Capstone next and NeverD dev' if published else 'Qualification in progress',
              source=read(r / 'tree.json'), prepared_commit=read(r / 'prepared-commit.json'),
              preceding_publication=read(r.parent / 'round1364-evex-canonical-scan-plan/publication.json'),
              reports=reports, original_negative_evidence_preserved=True, publication=publication,
              production_modified=bool(published), overall_goal_complete=False,
              formatting_prototype='../round1375-evex-output-existing-miss',
              held_scan_construction_prototypes=['../round1371-evex-result-call-boundary', '../round1373-deferred-scan-initialization'])
(r / 'progress.json').write_text(json.dumps(report, indent=2) + '\n')
print({key: value['status'] for key, value in reports.items()})
