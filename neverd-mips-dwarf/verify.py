"""Check recovered type identities and member ranges on every compiler object."""
from pathlib import Path
import hashlib
import json
import subprocess
import sys

reader, inputs, output = map(Path, sys.argv[1:])
manifest = json.loads((inputs / 'manifest.json').read_text())
assert len(manifest) == len({r['name'] for r in manifest}) == 24
results = []
for row in manifest:
    path = inputs / row['name']
    assert hashlib.sha256(path.read_bytes()).hexdigest() == row['sha256']
    result = subprocess.check_output([reader.resolve(), path], text=True).splitlines()
    records = [line for line in result if line.startswith(('union ', 'struct '))]
    assert records == ['struct Packet 8', 'union Header 4', 'struct HeaderBits 4',
                       'union PackedHeader 6', 'struct PackedBits 6'], (path, result)
    fields = {name: (int(offset), int(width)) for name, offset, width in
              (line.split() for line in result if line not in records)}
    offsets = {'Packet.tag': 0, 'Packet.header': 32, 'Header.fields': 0, 'Header.word': 0,
               'HeaderBits.version': 0, 'HeaderBits.kind': 3, 'HeaderBits.length': 10,
               'PackedHeader.fields': 0, 'PackedHeader.bytes': 0, 'PackedBits.prefix': 0,
               'PackedBits.value': 27, 'PackedBits.trailer': 40}
    assert {f: pos for f, (pos, width) in fields.items()} == offsets, (path, fields)
    assert [fields['HeaderBits.' + f][1] for f in ('version','kind','length')] == [3,7,22]
    assert [fields['PackedBits.' + f][1] for f in ('prefix','value')] == [27,12]
    results.append(dict(**row, records=records, fields=fields))
output.write_text(json.dumps(results, indent=2) + '\n')
