import hashlib, io, json, subprocess as sp, tarfile
from bisect import bisect_right
from pathlib import Path
from elftools.elf.elffile import ELFFile

packages = {
    'code': ('https://deb.debian.org/debian/pool/main/c/coreutils/coreutils_9.7-3_armel.deb','7cf6eb05e7f5e0ea8fe9ca1dbb43a58c9c6953c89dd1f02995fc9b4cb53f7ac1'),
    'debug': ('https://deb.debian.org/debian-debug/pool/main/c/coreutils/coreutils-dbgsym_9.7-3_armel.deb',None),
}
def sha(data): return hashlib.sha256(data).hexdigest()
def package(w,key,expected):
    url,_ = packages[key]; path=w/(key+'.deb')
    sp.run(['curl','-fsSL','--max-time','120','--retry','3',url,'-o',path],check=True)
    digest=sha(path.read_bytes())
    if expected:assert digest==expected,(key,digest,expected)
    members=sp.check_output(['ar','t',path],text=True).splitlines()
    member,=[i for i in members if i.startswith('data.tar')]
    return digest,tarfile.open(fileobj=io.BytesIO(sp.check_output(['ar','p',path,member])),mode='r:*')
def member(archive,path):
    match,=[m for m in archive.getmembers() if m.name.lstrip('./')==path];assert match.isfile()
    return archive.extractfile(match).read()
def build_id(elf):
    section=elf.get_section_by_name('.note.gnu.build-id')
    note,=[n for n in section.iter_notes() if n['n_name']=='GNU' and n['n_type']=='NT_GNU_BUILD_ID']
    return note['n_desc']
def prepare(w,expected=None):
    result={}; digests={}
    key='code';digests[key],code=package(w,key,packages[key][1])
    key='debug';digests[key],debug=package(w,key,expected['packages'][key] if expected else None)
    with code,debug:
        for cmd in ['cat','ls','cp','sort']:
            raw=member(code,'usr/bin/'+cmd);elf=ELFFile(io.BytesIO(raw));ident=build_id(elf)
            dbg=ELFFile(io.BytesIO(member(debug,'usr/lib/debug/.build-id/'+ident[:2]+'/'+ident[2:]+'.debug')))
            assert ident==build_id(dbg) and elf['e_machine']==dbg['e_machine']=='EM_ARM' and elf.little_endian and elf.elfclass==32
            text=elf.get_section_by_name('.text');va=text['sh_addr'];size=text['sh_size']
            idx=dbg.get_section_index('.text');ref=dbg.get_section(idx)
            assert ref['sh_addr']==va and ref['sh_size']==size and text['sh_flags']&4
            functions=set();mapping={}
            for sym in dbg.get_section_by_name('.symtab').iter_symbols():
                if sym['st_shndx']!=idx:continue
                value=sym['st_value'];size0=sym['st_size'];kind=sym.name.split('.')[0]
                if kind in ('$a','$t','$d'):
                    assert mapping.setdefault(value,kind)==kind
                elif sym['st_info']['type']=='STT_FUNC' and size0:
                    addr=value&~1;assert va<=addr<addr+size0<=va+size
                    functions.add((addr,addr+size0))
            assert len(mapping)>10 and len(functions)>50
            coords=sorted(mapping);spans=set()
            for a,b in functions:
                i=bisect_right(coords,a)-1
                if i<0:continue
                while i<len(coords) and coords[i]<b:
                    start=max(coords[i],a);end=min(coords[i+1] if i+1<len(coords) else va+size,b)
                    if mapping[coords[i]]=='$a':
                        assert start<end and (end-start)%4==0 and start%4==0
                        spans.add((start-va,end-start,start))
                    i+=1
            # Debug aliases and nested symbol extents can cover the same instructions.
            # Preserve all function and mapping boundaries, visiting each byte once.
            changes={}
            for off,n,_ in spans:
                changes[off]=changes.get(off,0)+1;changes[off+n]=changes.get(off+n,0)-1
            level=0;rows=[];last=0
            for point,count in sorted(changes.items()):
                if level:rows.append((last,point-last,va+last))
                level+=count;last=point
            assert level==0 and rows, (cmd,len(spans),len(functions),len(mapping),list(mapping.items())[:8])
            assert all(n>0 and not n%4 for _,n,_ in rows)
            name='arm-'+cmd
            ranges=''.join('%d %d %d\n'%row for row in rows).encode()
            data=text.data();(w/(name+'.text')).write_bytes(data);(w/(name+'.ranges')).write_bytes(ranges)
            result[name]=dict(arch='arm',name=name,build_id=ident,binary_sha256=sha(raw),text_sha256=sha(data),extent_sha256=sha(ranges),functions=len(functions),extents=len(rows),code_bytes=sum(n for _,n,_ in rows))
    manifest=dict(packages=digests,fixtures=result)
    if expected:assert manifest==expected
    return manifest
if __name__=='__main__':
    import tempfile,shutil
    r=Path(__file__).resolve().parent;w=Path(tempfile.mkdtemp(dir=r))
    try:
        manifest=prepare(w);(r/'arm-samples.json').write_text(json.dumps(manifest,indent=2)+'\n')
    finally:
        n=sum(f.stat().st_size for f in w.rglob('*') if f.is_file());shutil.rmtree(w);(r/'corpus-cleanup.json').write_text(json.dumps(dict(bytes=n,removed=not w.exists()))+'\n')
