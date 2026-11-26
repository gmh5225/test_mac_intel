from bisect import bisect_left
from collections import defaultdict
from pathlib import Path
import hashlib,json,os,platform,shutil,subprocess as sp,tempfile
from elftools.elf.elffile import ELFFile
from elftools.elf.relocation import RelocationSection
r=Path(__file__).resolve().parent;root=r.parent;source=root/'source';e=root/'evidence';e.mkdir(exist_ok=True)
rd=lambda f:json.loads(f.read_text());q=rd(r/'table-study.json')
def save(name,v):(e/(name+'.json')).write_text(json.dumps(v,indent=2)+'\n')
def sha(data):return hashlib.sha256(data).hexdigest()
def objects(path):
    rows=[]
    with path.open('rb') as f:
        elf=ELFFile(f);sections=list(elf.iter_sections());syms=elf.get_section_by_name('.symtab')
        assert syms is not None,path
        reloc=defaultdict(list);raw={}
        for section in sections:
            if isinstance(section,RelocationSection):
                reloc[section['sh_info']].extend(row['r_offset'] for row in section.iter_relocations())
        for offsets in reloc.values():offsets.sort()
        for sym in syms.iter_symbols():
            idx=sym['st_shndx'];n=sym['st_size'];addr=sym['st_value']
            if sym['st_info']['type']!='STT_OBJECT' or not isinstance(idx,int) or n<256:continue
            sec=sections[idx];flags=sec['sh_flags']
            if sec['sh_type']!='SHT_PROGBITS' or not flags&2 or flags&5:continue
            def has_ref(vals):
                i=bisect_left(vals,addr);return i<len(vals) and vals[i]<addr+n
            if has_ref(reloc[idx]) or (elf['e_type']!='ET_REL' and has_ref(reloc[0])):continue
            if idx not in raw:raw[idx]=sec.data()
            offset=addr-sec['sh_addr'];buf=raw[idx][offset:offset+n]
            assert len(buf)==n
            if any(buf):rows.append((n,sha(buf),sym.name,addr))
    return rows
w=Path(tempfile.mkdtemp());b=w/'build'
try:
    assert sp.check_output(['git','-C',source,'rev-parse','HEAD'],text=True).strip()==q['commit']
    sp.run(['cmake','-S',source,'-B',b,'-G','Ninja','-DCMAKE_BUILD_TYPE=Release','-DCMAKE_C_COMPILER=clang',
            '-DCAPSTONE_ARCHITECTURE_DEFAULT=ON','-DCAPSTONE_BUILD_STATIC_LIBS=ON','-DCAPSTONE_BUILD_SHARED_LIBS=ON',
            '-DCAPSTONE_BUILD_CSTEST=OFF','-DCAPSTONE_BUILD_CSTOOL=OFF','-DCAPSTONE_BUILD_LEGACY_TESTS=OFF','-DCMAKE_EXPORT_COMPILE_COMMANDS=ON'],check=True)
    sp.run(['cmake','--build',b,'--parallel','4','--target','capstone_static','capstone_shared'],check=True)
    import shlex
    occurrences=defaultdict(set);architectures=set();scanned=0
    for cmd in rd(b/'compile_commands.json'):
        src=Path(cmd['file']).resolve().relative_to(source.resolve())
        if src.parts[0]!='arch':continue
        argv=shlex.split(cmd['command']);obj=Path(cmd['directory'])/argv[argv.index('-o')+1]
        if not obj.is_file():continue
        architectures.add(src.parts[1]);scanned+=1
        for n,digest,name,_ in objects(obj):occurrences[n,digest].add((str(src),name))
    assert len(architectures)>=20 and scanned>=100
    shared=(b/'libcapstone.so').resolve();linked=defaultdict(set)
    for n,digest,name,address in objects(shared):linked[n,digest].add((name,address))
    groups=[]
    for (n,digest),entries in occurrences.items():
        owners={k for k,v in entries}
        if len(owners)<2:continue
        names={v for k,v in entries}
        matches=sorted((name,addr) for name,addr in linked[n,digest] if name in names)
        locs={addr for _,addr in matches}
        groups.append(dict(bytes_per_copy=n,sha256=digest,architectures=sorted({Path(src).parts[1] for src in owners}),
                           source_symbols=sorted(entries),linked_matches=matches,linked_copies=len(locs)))
    groups.sort(key=lambda v: (-max(0,v['linked_copies']-1)*v['bytes_per_copy'],-v['bytes_per_copy'],v['sha256']))
    save('tables',dict(complete=True,source=q,machine=platform.machine(),compiler=sp.check_output(['clang','--version'],text=True).splitlines()[0],
        architecture_count=len(architectures),architectures=sorted(architectures),object_count=scanned,shared_bytes=shared.stat().st_size,groups=groups))
finally:
    n=sum(f.stat().st_size for f in w.rglob('*') if f.is_file() and not f.is_symlink());shutil.rmtree(w);save('cleanup',dict(removed=not w.exists(),bytes=n))
