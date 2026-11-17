from pathlib import Path
from collections import Counter
import hashlib
import gzip
import os
import json
import shutil
import subprocess as sp
import tempfile
from code_shape import elf, symbols

r = Path(__file__).resolve().parent
cc = os.environ['MEASURE_CC']
s, e = r.parent/'source', r.parent/'evidence'
e.mkdir()
meta = json.loads((r/'candidate.json').read_text())
sha = lambda path: hashlib.sha256(path.read_bytes()).hexdigest()
def write(name, value):
    (e/(name+'.json')).write_text(json.dumps(value,indent=2)+'\n')
def run(args, label, cwd=None):
    print(label,flush=True)
    with (e/(label+'.log')).open('wb') as out:
        sp.run(list(map(str,args)),cwd=cwd,stdout=out,stderr=sp.STDOUT,check=True)

with tempfile.TemporaryDirectory(prefix='vex32-mode-table-audit-') as tmp:
    w=Path(tmp); b=w/'build'
    try:
        assert sp.check_output(['git','rev-parse','HEAD'],cwd=s,text=True).strip()==meta['parent']
        assert sha(r/'scan.patch')==meta['sha256']
        write('compiler',dict(version=sp.check_output([cc,'--version'],text=True)))
        write('cpu',dict(model=next(x.split(':',1)[1].strip() for x in Path('/proc/cpuinfo').read_text().splitlines() if x.startswith('model name'))))
        run(['clang++','-O3','-DNDEBUG','-std=c++17','-I',s,'-I',s/'include','-c',r/'single.cpp','-o',w/'consumer.o'],'consumer')
        run(['cmake','-S',s,'-B',b,'-G','Ninja','-DCMAKE_BUILD_TYPE=Release','-DCMAKE_C_COMPILER='+cc,'-DCMAKE_C_FLAGS='+('-Wno-error=discarded-qualifiers' if cc=='gcc' else '-Wno-error=incompatible-pointer-types-discards-qualifiers'),'-DCAPSTONE_ARCHITECTURE_DEFAULT=OFF',*['-DCAPSTONE_'+a+'_SUPPORT=ON' for a in ['X86','ARM','AARCH64','MIPS']],'-DCAPSTONE_BUILD_SHARED_LIBS=ON','-DCAPSTONE_BUILD_CSTEST=ON','-DCAPSTONE_BUILD_MACOS_THIN=ON','-DCAPSTONE_BUILD_LEGACY_TESTS=OFF','-DCAPSTONE_BUILD_CSTOOL=OFF'],'configure')
        objects, syms, shapes, allocated, old_backend = {}, {}, {}, {}, set()
        for label in ('base','scan'):
            if label=='scan':
                run(['git','apply','--index',r/'scan.patch'],'apply',s)
                assert sp.check_output(['git','write-tree'],cwd=s,text=True).strip()==meta['tree']
            run(['cmake','--build',b,'--target','capstone_static','-j4'],'build-'+label)
            root=b/'CMakeFiles/capstone.dir'
            objects[label]={str(p.relative_to(root)):sha(p) for p in root.rglob('*.o')}
            binary=w/label
            run(['clang++',w/'consumer.o',b/'libcapstone.a','-lm','-o',binary],'link-'+label)
            syms[label]=symbols(binary)
            (e/(label+'-symbols.txt')).write_bytes(sp.check_output(['nm','-n','-S','--defined-only',binary]))
            (e/(label+'-sections.txt')).write_bytes(sp.check_output(['readelf','-WS',binary]))
            shapes[label]={};allocated[label]={}
            for name in ('X86DisassemblerDecoder','X86VectorOutput'):
                path=root/('arch/X86/'+name+'.c.o')
                data,_,sections,names=elf(path)
                shapes[label][name]={n:dict(size=v[5],alignment=v[8]) for n,v in zip(names,sections) if v[2]&2}
                allocated[label][name]={n:hashlib.sha256(data[v[4]:v[4]+v[5]]).hexdigest() for n,v in zip(names,sections) if v[2]&2 and v[1]!=8}
                (e/(label+'-'+name+'-assembly.txt.gz')).write_bytes(gzip.compress(sp.check_output(['objdump','-dr',path])))
            if label=='base':
                for arch in ('ARM','AArch64','Mips'):
                    for path in (root/'arch'/arch).glob('*.o'):old_backend.update(symbols(path))
            else:
                for name in ('X86VexScan',):
                    (e/(name+'-assembly.txt')).write_bytes(sp.check_output(['objdump','-dr',root/('arch/X86/'+name+'.c.o')]))
        changed=[n for n,h in objects['base'].items() if objects['scan'].get(n)!=h]
        added=set(objects['scan'])-set(objects['base'])
        assert changed==['arch/X86/X86DisassemblerDecoder.c.o'],changed
        assert added=={'arch/X86/X86VexScan.c.o'}
        movements={}
        for kind in ('t','r'):
            entries={name:syms['scan'][name][0][0]-syms['base'][name][0][0] for name in old_backend
                     if len(syms['base'].get(name,[]))==len(syms['scan'].get(name,[]))==1 and syms['base'][name][0][2].lower()==kind}
            movements[kind]=dict(symbols=len(entries),deltas=dict(Counter(entries.values())))
        write('complete',dict(source=meta,changed=changed,added=sorted(added),vector_object_identical=True,
                              shapes=shapes,allocated_section_hashes=allocated,backend_movements=movements,
                              consumer_sha256=sha(w/'consumer.o'),native_timing=False,qualified=False))
    finally:
        size=sum(p.stat().st_size for p in w.rglob('*') if p.is_file())
        shutil.rmtree(w)
        write('cleanup',dict(bytes=size,removed=not w.exists()))
