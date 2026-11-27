from pathlib import Path
import hashlib,json,math,random,statistics,subprocess as sp
from elftools.elf.elffile import ELFFile
def inputs(w):
    def get(*a,**kw):return sp.check_output(a,text=True,**kw).strip()
    def sha(v):return hashlib.sha256(v).hexdigest()
    rev='b52ca86e094d19b58e2304417787e96b940e39c6'
    src=w/'seabios';src.mkdir()
    get('git','-C',src,'init','-q')
    get('git','-C',src,'fetch','--quiet','--depth','1','https://github.com/coreboot/seabios.git','refs/tags/rel-1.17.0')
    get('git','-C',src,'checkout','--detach','-q','FETCH_HEAD')
    assert get('git','-C',src,'rev-parse','HEAD')==rev
    sp.run(['make','-j2','PYTHON=python3','CC=gcc','HOSTCC=gcc','EXTRAVERSION=-capstone-bench','out/bios.bin'],cwd=src,check=True)
    image=src/'out/bios.bin';rom=image.read_bytes();load=0x100000-len(rom)
    count=0;rows={};rejected=[]
    with (src/'out/rom16.o').open('rb') as f:
        elf=ELFFile(f)
        assert elf['e_machine']=='EM_386'
        symtab=elf.get_section_by_name('.symtab')
        for s in symtab.iter_symbols():
            n=s['st_size'];addr=s['st_value'];idx=s['st_shndx']
            if s['st_info']['type']!='STT_FUNC' or not n or not isinstance(idx,int):continue
            sec=elf.get_section(idx)
            if not sec['sh_flags']&4:continue
            count+=1
            offset=0xf0000+addr-load
            inside=addr-sec['sh_addr']
            assert inside>=0 and inside+n<=sec['sh_size'] and offset>=0 and offset+n<=len(rom)
            assert rom[offset:offset+n]==sec.data()[inside:inside+n],(s.name,n,addr)
            rows.setdefault((offset,n,addr),[]).append(s.name)
    spans=sorted(rows);assert len(spans)>=20
    path=w/'seabios16-functions.tsv'
    def emit(v):path.write_text(''.join('%d %d %d\n'%z for z in v))
    emit(spans)
    return image,path,dict(source=rev,extents=len(spans),code_bytes=sum(n for _,n,a in spans),extent_sha256=sha(path.read_bytes()),code_sha256=sha(b''.join(rom[k:k+n] for k,n,a in spans)))
