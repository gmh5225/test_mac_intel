from pathlib import Path
import hashlib
import json
import sys

r = Path(__file__).resolve().parent
sys.path.insert(0, str(r.parent / 'round1379-evex-output-native-controls'))
from layout import linked_layout, symbols

read = lambda p: json.loads(p.read_text())
review = read(r / 'profile-review.json')
assert review['complete']
profiles = []
for d in sorted((r / 'profile').iterdir()):
    before, after = d / 'integer-symbols.txt', d / 'existingmiss-symbols.txt'
    layout = linked_layout(before, after, 'output')
    broadcast = {name: symbols(path, 'tTwW').get('writeEvexBroadcast')
                 for name, path in [('before', before), ('after', after)]}
    item = dict(profile=d.name, layout=layout, broadcast=broadcast,
        source_files_sha256={path.name: hashlib.sha256(path.read_bytes()).hexdigest() for path in (before, after)})
    profiles.append(item)
    print(d.name, 'broadcast', broadcast,
          'changed symbols', {k: len(layout[k]['changed']) for k in ('text', 'readonly', 'writable')})
assert len(profiles) == 4
result = dict(source=review['source'], run=review['run'], profiles=profiles,
    native_timing=False, publication_qualified=False,
    scope='Exact same frozen profile consumer, compiler settings and prepared parent as R1375. Packed admission preserves the canonical accepted set, but emitted size and downstream position changes are reported without treating them as throughput gains.')
(r / 'layout-review.json').write_text(json.dumps(result, indent=2) + '\n')
