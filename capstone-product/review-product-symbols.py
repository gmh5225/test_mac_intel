from pathlib import Path
import hashlib
import json

r = Path(__file__).resolve().parent
report = json.loads((r / 'product-review.json').read_text())
assert report['complete'] and report['run']['conclusion'] == 'success'
d = r / report['raw']
source = (r / 'layout.py').read_text()
scope = {'Path': Path}
exec(source[source.index('def symbols'):], scope)
label, = report['inputs']['variants']
left, right = (d / ('timed-symbols-' + name + '.log') for name in ('base', label))
proof = scope['linked_proof'](left, right)
symbols = scope['symbols']
before, after = symbols(left, 'bBdDgGsSvV'), symbols(right, 'bBdDgGsSvV')
assert before == after, dict(missing=sorted(set(before) - set(after))[:10], added=sorted(set(after) - set(before))[:10])
proof.update(original_writable_positions_identical=True, writable_symbols=len(before),
             symbol_files_sha256={f.name: hashlib.sha256(f.read_bytes()).hexdigest() for f in (left, right)},
             run=report['run'], source=report['inputs']['variants'][label])
(r / 'product-symbol-review.json').write_text(json.dumps(proof, indent=2) + '\n')
print('All original text, read-only and writable symbol positions preserved:',
      proof['text_symbols'], proof['readonly_symbols'], proof['writable_symbols'])
