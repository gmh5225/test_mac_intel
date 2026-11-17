from pathlib import Path
from collections import defaultdict
import hashlib
import re
import subprocess as sp

def symbols(path, kinds):
    result = defaultdict(list)
    for line in Path(path).read_text().splitlines():
        match = re.match(r'([0-9a-fA-F]+) ([0-9a-fA-F]+) (\S) (.+)$', line)
        if match and match[3] in kinds:
            result[match[4]].append((match[3], int(match[1], 16), int(match[2], 16)))
    return dict(result)

def linked_layout(before, after, label):
    assert label == 'output'
    result = dict(captured=True, criterion='Record every symbol relocation and size change. Object isolation is mandatory; actual native timing and A/A controls determine performance acceptance.')
    for category, kinds in (('text', 'tTwW'), ('readonly', 'rR'), ('writable', 'bBdDgGsSvV')):
        left, right = symbols(before, kinds), symbols(after, kinds)
        common = left.keys() & right.keys()
        result[category] = dict(original_symbols=len(left), unchanged=sum(left[k] == right[k] for k in common),
            changed=[dict(symbol=k, before=left[k], after=right[k]) for k in sorted(common) if left[k] != right[k]],
            removed=[dict(symbol=k, positions=left[k]) for k in sorted(left.keys() - right.keys())],
            added=[dict(symbol=k, positions=right[k]) for k in sorted(right.keys() - left.keys())])
    return result

def object_proof(label, before, after):
    assert label == 'output'
    result = {}
    for key, path in (('before', before), ('after', after)):
        data = Path(path).read_bytes()
        result[key] = dict(sha256=hashlib.sha256(data).hexdigest(), size=len(data),
            sections=sp.check_output(['objdump', '-h', path], text=True))
    return result
