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
    data = layout.linked_layout(directory / 'integer-symbols.txt', directory / 'isolate-symbols.txt', 'output')
    (directory / 'isolate-linked-layout.json').write_text(json.dumps(data, indent=2) + '\n')
    profiles.append(dict(profile=directory.name, categories={key: {field: len(data[key][field])
        for field in ('changed', 'added', 'removed')} for key in ('text', 'readonly', 'writable')}))
assert len(profiles) == 4
assert all(p['categories']['text']['changed'] == 0 for p in profiles if '-clang-' in p['profile'])
report = dict(complete=True, source=review['source'], run=review['run'], profiles=profiles,
    scope='The two Clang builds retain every common text symbol position and size. GCC11 still moves downstream text and GCC13 moves three existing vector functions. The renamed broadcast is reported as a removal/addition. Readonly/writable movement remains explicit; this is not native performance qualification.',
    publication_qualified=False, next_experiment='round1392-evex-prechecked-dispatch-native')
(r / 'layout-review.json').write_text(json.dumps(report, indent=2) + '\n')
print('Captured all four text/data layouts; common Clang text positions are preserved.')
