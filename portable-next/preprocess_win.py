"""Compare the code fed to native MSVC for every Capstone object in each build."""
import concurrent.futures,difflib,hashlib,json,os,shutil,subprocess as sp,tempfile
from pathlib import Path
def verify(r):
    root=r.parent;src=root/'source';e=root/'evidence';e.mkdir(exist_ok=True);q=json.loads((r/'source.json').read_text());w=Path(tempfile.mkdtemp()).resolve()
    def git(*args):return sp.check_output(['git','-C',src,*args],text=True).strip()
    def save(n,z):(e/(n+'.json')).write_text(json.dumps(z,indent=2)+'\n')
    try:
        b=w/'build';assert git('rev-parse','HEAD')==q['base']['commit']
        flags=['-DCMAKE_BUILD_TYPE=Release','-DCMAKE_EXPORT_COMPILE_COMMANDS=ON','-DCAPSTONE_ARCHITECTURE_DEFAULT=OFF','-DCAPSTONE_X86_SUPPORT=ON','-DCAPSTONE_BUILD_CSTEST=OFF','-DCAPSTONE_BUILD_CSTOOL=OFF','-DCAPSTONE_BUILD_SHARED_LIBS=ON','-DCAPSTONE_BUILD_STATIC_LIBS=ON']
        states={};raw_hashes={};object_hashes={}
        for tag in ('base','candidate'):
            if tag=='candidate':
                patch=sp.check_output(['git','-C',root,'cat-file','blob','HEAD:portable-next/candidate.patch']);assert hashlib.sha256(patch).hexdigest()==q[tag]['sha256']
                f=w/'delta.patch';f.write_bytes(patch);git('apply','--index',f)
            assert git('write-tree')==q[tag]['tree']
            sp.run(['cmake','-G','Ninja','-S',src,'-B',b,*flags],check=True)
            jobs=[j for j in json.loads((b/'compile_commands.json').read_text())if Path(j['file']).suffix=='.c']
            def digest(j):
                command=j['command'];assert 'cl.exe' in command.lower() and 'CAPSTONE_HAS_X86' in command
                raw=sp.check_output(command+' /EP',cwd=j['directory'])
                assert len(raw)>5000,(j['file'],len(raw))
                key=j['output'];lines=[v for v in raw.splitlines()if v.strip()]
                if tag=='candidate':
                    import re
                    normalized=[]
                    for line in lines:
                        if re.fullmatch(rb'\s*enum\s*\{\s*X86_SIMPLE_OPERAND_CAPACITY\s*=\s*12\s*\}\s*;\s*',line):continue
                        if all(spelling in line for spelling in (b'.flags = ',b'.reads = ',b'.writes = ',b'.groups = ',b'.read_count = ')):
                            line=re.sub(rb'\.(?:flags|reads|writes|groups|read_count) = ',b'',line)
                        normalized.append(line)
                    lines=normalized
                cleaned=b'\n'.join(lines);saved=w/(hashlib.sha256(key.encode()).hexdigest()+'.pp')
                if tag=='base':saved.write_bytes(cleaned)
                else:
                    original=saved.read_bytes()
                    if original!=cleaned:
                        delta=list(difflib.unified_diff(original.decode(errors='replace').splitlines(),cleaned.decode(errors='replace').splitlines(),n=1))
                        (e/(Path(key).stem+'-difference.txt')).write_text('\n'.join(delta[:32]),encoding='utf-8')
                        print(key,delta[:8],flush=True)
                return key,hashlib.sha256(raw).hexdigest(),hashlib.sha256(cleaned).hexdigest()
            with concurrent.futures.ThreadPoolExecutor(max_workers=2)as pool:rows=list(pool.map(digest,jobs))
            raw_hashes[tag]={key:raw for key,raw,norm in rows};states[tag]={key:norm for key,raw,norm in rows}
            save('raw-preprocessor',raw_hashes);save('preprocessed',states)
            # Independently compare actual compiled instructions, unwind information,
            # data and linker directives for the three fixed/public iterator units.
            import struct
            wanted=['X86ImmediateOutput.c', 'X86MemoryFallback32.c', 'X86MemoryOutput.c', 'X86OutputIterator.c', 'X86RegisterFallback32.c', 'X86Sse64Output.c', 'X86VectorFallback64.c', 'X86Vex32Output.c']
            wanted=set(wanted)
            objects={}
            for j in jobs:
                name=Path(j['file']).name
                if name not in wanted:continue
                out=w/(name+'.obj')
                command=j['command']+' /Brepro /Fo"'+str(out)+'"'
                sp.run(command,cwd=j['directory'],check=True,stdout=sp.DEVNULL)
                data=out.read_bytes()
                machine,nsec=struct.unpack_from('<HH',data);assert machine in (0x14c,0x8664)
                opt,=struct.unpack_from('<H',data,16);off=20+opt
                pieces=[]
                for index in range(nsec):
                    at=off+40*index;sec=data[at:at+8].rstrip(b'\x00')
                    length,raw,rel=struct.unpack_from('<III',data,at+16);count,=struct.unpack_from('<H',data,at+32)
                    if sec.startswith((b'.debug',b'.chks64')):continue
                    payload=data[raw:raw+length] if raw else b''
                    # Resolve relocations through their target names, independent of debug symbols.
                    symtab,symbols=struct.unpack_from('<II',data,8);strings=symtab+18*symbols
                    relocs=[]
                    for jx in range(count):
                        pos,sym,kind=struct.unpack_from('<IIH',data,rel+jx*10)
                        hdr=data[symtab+sym*18:symtab+sym*18+8]
                        if hdr[:4]==bytes(4):
                            start=strings+int.from_bytes(hdr[4:],'little');symbol=data[start:data.index(b'\x00',start)]
                        else:symbol=hdr.rstrip(b'\x00')
                        relocs.append([pos,kind,symbol.decode('ascii',errors='replace')])
                    pieces.append([sec.decode('ascii',errors='replace'),length,hashlib.sha256(payload).hexdigest(),relocs])
                assert any(sec.startswith('.text') and length>0 for sec,length,_,_ in pieces)
                objects[name]=hashlib.sha256(json.dumps(pieces,sort_keys=True).encode()).hexdigest()
            assert set(objects)==wanted;object_hashes[tag]=objects;save('compiled-sections',object_hashes)
        assert object_hashes['base']==object_hashes['candidate'],object_hashes
        assert len(states['base'])>20 and states['base']==states['candidate'],[k for k,v in states['base'].items()if v!=states['candidate'].get(k)]
        save('complete',dict(complete=True,source=q,host='Windows',proof='preprocessed and compiled sections',expected='base',objects=len(states['base']),toolchain=os.environ.get('VSCMD_ARG_TGT_ARCH')))
    finally:
        size=sum(f.stat().st_size for f in w.rglob('*')if f.is_file()and not f.is_symlink());shutil.rmtree(w);save('cleanup',dict(removed=not w.exists(),bytes=size))
