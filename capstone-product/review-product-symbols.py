from pathlib import Path
import hashlib
import json
import sys

r = Path(__file__).resolve().parent
sys.path.insert(0, str(r.parent / 'round1370-evex-transfer-launch-controls'))
from layout import linked_layout

report = json.loads((r / 'product-review.json').read_text())
assert report['complete'] and report['run']['conclusion'] == 'success'
d = r / report['raw']
label, = report['inputs']['variants']
left, right = (d / ('timed-symbols-' + name + '.log') for name in ('base', label))
proof = linked_layout(left, right, 'merge')
proof.update(symbol_files_sha256={f.name: hashlib.sha256(f.read_bytes()).hexdigest() for f in (left, right)},
             run=report['run'], source=report['inputs']['variants'][label],
             scope='The same predeclared R1367/R1370 layout criterion: unchanged text positions, preserved data symbol names and sizes, with every moved data address recorded. Data-address equality is not asserted.')
(r / 'product-symbol-review.json').write_text(json.dumps(proof, indent=2) + '\n')
print('Unmodified text positions preserved:', proof['text_symbols'],
      'read-only moves:', len(proof['readonly']['moves']),
      'writable moves:', len(proof['writable']['moves']))
