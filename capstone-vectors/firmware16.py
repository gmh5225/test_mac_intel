from pathlib import Path
import hashlib,json,math,random,statistics,subprocess as sp
from elftools.elf.elffile import ELFFile
def verify(w,images,invoke,select):
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
    emit(spans);traces={}
    for tag in images:
        select(tag)
        data=[list(map(int,s.split()))for s in get(*invoke,'audit','1','1',image,path,'16').splitlines()]
        assert len(data)==len(spans) and [tuple(r[:3]) for r in data]==spans
        traces[tag]=data
    chosen=[]
    for i,z in enumerate(spans):
        if all(rr[i][3]==rr[i][4] and rr[i][5]==z[1] for rr in traces.values()):chosen.append(z)
        else:rejected.append(dict(symbols=rows[z],extent=z,results={k:v[i][3:] for k,v in traces.items()}))
    assert len(chosen)>=20;emit(chosen)
    def take(k,mode,reps):
        select('base' if k in ('iced','fast')else k)
        return list(map(int,get(*invoke,k if k in ('iced','fast')else 'private',str(mode),str(reps),image,path,'16').split()))
    result={}
    for mode in range(3):
        reps=max(1,math.ceil(30e6/take('base',mode,1)[0]))
        keys=[*images,'iced']+(['fast']if mode else[])
        expected={k:take(k,mode,reps)[2:] for k in keys}
        assert len({tuple(expected[k]) for k in images})==1 and len({tuple(row[:3])for row in expected.values()})==1,expected
        rng=random.Random(9917+mode);pairs=[]
        for _ in range(17):
            rng.shuffle(keys);v={k:[]for k in keys}
            for k in keys+keys[::-1]:
                x=take(k,mode,reps);assert x[2:]==expected[k];v[k].append(x[:2])
            pairs.append({k:[sum(t[i]for t in vv)for i in (0,1)]for k,vv in v.items()})
        result[str(mode)]=dict(reps=reps,expected=expected,pairs=pairs)
    return dict(source=rev,target='SeaBIOS 1.17.0 16-bit executable STT_FUNC symbols verified byte-for-byte in out/bios.bin',rom_sha256=sha(rom),elf_sha256=sha((src/'out/rom16.o').read_bytes()),symbol_count=count,unique_extents=len(rows),common_extents=len(chosen),code_bytes=sum(n for _,n,_ in chosen),code_sha256=sha(b''.join(rom[off:off+n]for off,n,a in chosen)),extent_sha256=sha(path.read_bytes()),excluded=rejected,results=result)
