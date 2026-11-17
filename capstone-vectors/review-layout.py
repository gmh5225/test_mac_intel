from pathlib import Path
import importlib.util
import json

r = Path(__file__).resolve().parent
read = lambda p: json.loads(p.read_text())
review = read(r / 'profile-review.json')
assert review['complete']
path = r.parent / 'round1379-evex-output-native-controls/layout.py'
spec = importlib.util.spec_from_file_location('layout', path)
layout = importlib.util.module_from_spec(spec)
spec.loader.exec_module(layout)
profiles = []
for directory in sorted((r / 'profile').iterdir()):
    data = layout.linked_layout(directory / 'integer-symbols.txt', directory / 'mode32-symbols.txt', 'output')
    (directory / 'mode32-linked-layout.json').write_text(json.dumps(data, indent=2) + '\n')
    profiles.append(dict(profile=directory.name, categories={key: {field: len(data[key][field])
        for field in ('changed', 'added', 'removed')} for key in ('text', 'readonly', 'writable')}))
assert len(profiles) == 4

report = dict(complete=True, source=review['source'], run=review['run'], profiles=profiles,
    scope='Every vector-core object has identical disassembly after normalizing its private entry name. Linked positions and all data movements are reported separately. The old entry name now denotes the new dispatcher; the original entry is renamed Base. This is not native performance qualification.',
    publication_qualified=False, next_experiment='round1393-vex32-plan-dispatch')
(r / 'layout-review.json').write_text(json.dumps(report, indent=2) + '\n')
print('Captured all four text/data layouts; wrapper overhead is retained separately.')
