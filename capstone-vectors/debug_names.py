from bisect import bisect_right
from collections import defaultdict
from functools import lru_cache
from pathlib import Path
from elftools.elf.elffile import ELFFile

@lru_cache(maxsize=None)
def symbols_for(path):
    with Path(path).open('rb') as f:
        elf=ELFFile(f)
        note=elf.get_section_by_name('.note.gnu.build-id')
        build_id=next(n['n_desc'] for n in note.iter_notes() if n['n_type']=='NT_GNU_BUILD_ID')
    target=Path('/usr/lib/debug/.build-id')/build_id[:2]/(build_id[2:]+'.debug')
    with target.open('rb') as f:
        elf=ELFFile(f);same=elf.get_section_by_name('.note.gnu.build-id')
        assert any(n['n_desc']==build_id for n in same.iter_notes() if n['n_type']=='NT_GNU_BUILD_ID')
        by_address=defaultdict(dict)
        for s in elf.get_section_by_name('.symtab').iter_symbols():
            if s['st_info']['type'] in ('STT_FUNC','STT_GNU_IFUNC','STT_LOOS') and s['st_size']>0:
                by_address[s['st_value']][s.name]=s['st_size']
    addresses=sorted(by_address);assert len(addresses)>100
    return build_id,addresses,by_address

@lru_cache(maxsize=None)
def resolve(path,offset):
    build,addresses,known=symbols_for(path)
    i=bisect_right(addresses,offset)-1
    if i>=0:
        at=addresses[i]
        names=sorted(name for name,size in known[at].items() if offset<at+size)
        if names:return '|'.join(names),build
    return '[unresolved]',build
