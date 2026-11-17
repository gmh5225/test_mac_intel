from pathlib import Path
import json

r = Path(__file__).resolve().parent
read = lambda name: json.loads((r / name).read_text())
sources = read('tree.json')
reports = {}
for mode in ('native', 'native-timing', 'mixed-timing', 'profiles', 'focused', 'focused-9v45', 'build', 'product'):
    path = r / (mode + '-review.json')
    if not path.exists():
        run = r / (mode + '-run.json')
        reports[mode] = dict(status='pending', run=read(run.name) if run.exists() else None)
        continue
    report = read(path.name)
    brief = dict(status='reviewed', run=report.get('run'), report=path.name)
    for key in ('complete', 'selected_profiles', 'timing_obtained', 'outcome', 'unit_checks'):
        if key in report:
            brief[key] = report[key]
    for key in ('rows', 'costs', 'aa_outside_one_percent'):
        if key in report:
            brief[key] = len(report[key])
    if 'losses' in report:
        brief['losses'] = ({label: len(values) for label, values in report['losses'].items()}
                           if isinstance(report['losses'], dict) else len(report['losses']))
    reports[mode] = brief
publication = read('publication.json') if (r / 'publication.json').exists() else None
qualified = (r / 'qualification.json').exists() and read('qualification.json')['qualified_for_publication']
published = publication and all(publication[k]['published'] for k in ('capstone', 'neverd'))
report = dict(status='Published to Capstone next and NeverD dev' if published else 'Validation in progress',
              source=sources, reports=reports,
              preceding_publication=read('../round1363-evex-isolated-elf-x64/publication.json'),
              original_native_flags_preserved=True, publication_qualified=qualified,
              publication=publication, candidate_production_modified=bool(published), overall_goal_complete=False,
              remaining_work=['Continue the separately predeclared EVEX transfer comparison and investigate formatted/detail construction costs'] if published else ['Complete outstanding validation and publication'])
(r / 'progress.json').write_text(json.dumps(report, indent=2) + '\n')
print({key: value['status'] for key, value in reports.items()})
