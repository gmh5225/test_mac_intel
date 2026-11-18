from pathlib import Path

def linked_layout(before, after, label):
    from collections import defaultdict
    import re
    assert label == 'output'
    def symbols(path, kinds):
        result = defaultdict(list)
        for line in Path(path).read_text().splitlines():
            match = re.match(r'([0-9a-fA-F]+) ([0-9a-fA-F]+) (\S) (.+)$', line)
            if match and match[3] in kinds:
                result[match[4]].append((match[3], int(match[1],16), int(match[2],16)))
        return dict(result)
    result = dict(captured=True, criterion='Exact ordinary iterator text; report all linked symbol positions independently of the object proof.')
    for category, kinds in (('text','tTwW'),('readonly','rR'),('writable','bBdDgGsSvV')):
        left, right = symbols(before,kinds), symbols(after,kinds)
        common = left.keys() & right.keys()
        result[category] = dict(original_symbols=len(left), unchanged=sum(left[k]==right[k] for k in common),
            changed=[dict(symbol=k,before=left[k],after=right[k]) for k in sorted(common) if left[k]!=right[k]],
            added=[dict(symbol=k,positions=right[k]) for k in sorted(right.keys()-left.keys())],
            removed=[dict(symbol=k,positions=left[k]) for k in sorted(left.keys()-right.keys())])
    return result
