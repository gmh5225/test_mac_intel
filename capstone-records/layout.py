from pathlib import Path
from collections import defaultdict
import hashlib
import re

from elftools.elf.elffile import ELFFile


def ordinary_text_proof(before, after, active):
    def load(path):
        with Path(path).open('rb') as stream:
            elf = ELFFile(stream)
            table = elf.get_section_by_name('.symtab')
            index = elf.get_section_index('.text')
            functions = {s.name: (s['st_value'], s['st_size']) for s in table.iter_symbols()
                         if s['st_info']['type'] == 'STT_FUNC' and s['st_shndx'] == index}
            data = {s.name: s.data() for s in elf.iter_sections()
                    if s['sh_type'] == 'SHT_PROGBITS' and
                    (s.name.startswith('.rodata') or s.name == '.data.rel.ro')}
            return elf.get_section_by_name('.text').data(), functions, data
    left, fa, da = load(before)
    right, fb, db = load(after)
    data = {name: dict(before_sha256=hashlib.sha256(raw).hexdigest(),
                       original_bytes_preserved=db.get(name,b'')[:len(raw)] == raw)
            for name,raw in da.items()}
    result = dict(active=active, before_size=len(left), after_size=len(right),
        ordinary_text_identical=left==right, original_functions=fa, candidate_functions=fb,
        changed_positions=[dict(function=k,before=fa[k],after=fb.get(k)) for k in fa if fa[k]!=fb.get(k)],
        original_data=data,
        scope='This experiment moves the call before the common fallback and can split merged scan-entry blocks. Whole ordinary text identity is not its gate. Preserve all original constant bytes and both canonical fallback owners, and report every compiler and linked layout change before timing.')
    result['passed'] = (Path(before).read_bytes()==Path(after).read_bytes()) if not active else (
        all(v['original_bytes_preserved'] for v in data.values()) and
        all(name in fb for name in ('decodeScanResultFallback','decodeScanResultGeneric')))
    return result

def symbols(path, kinds):
    result = defaultdict(list)
    for line in Path(path).read_text().splitlines():
        match = re.match(r'([0-9a-fA-F]+) ([0-9a-fA-F]+) (\S) (.+)$', line)
        if match and match[3] in kinds:
            result[match[4]].append((match[3], int(match[1], 16), int(match[2], 16)))
    return dict(result)


def linked_layout(before, after, label):
    assert label == 'output'
    result = dict(captured=True, criterion='Preserve original constant bytes and canonical fallback owners; retain all scan-entry lowering and linked symbol movements for actual throughput qualification.')
    for category, kinds in (('text', 'tTwW'), ('readonly', 'rR'), ('writable', 'bBdDgGsSvV')):
        left, right = symbols(before, kinds), symbols(after, kinds)
        common = left.keys() & right.keys()
        result[category] = dict(original_symbols=len(left), unchanged=sum(left[k] == right[k] for k in common),
            changed=[dict(symbol=k, before=left[k], after=right[k]) for k in sorted(common) if left[k] != right[k]],
            removed=[dict(symbol=k, positions=left[k]) for k in sorted(left.keys() - right.keys())],
            added=[dict(symbol=k, positions=right[k]) for k in sorted(right.keys() - left.keys())])
    return result


def object_proof(label,before,after):
    assert label=='output'
    result=ordinary_text_proof(before,after,True)
    assert result['passed'],result
    return result
