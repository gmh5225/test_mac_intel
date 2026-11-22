from pathlib import Path
from elftools.elf.elffile import ELFFile
import hashlib,json,os,random,shlex,shutil,subprocess as sp,tempfile
d=Path(__file__).resolve().parent;s=d.parent/'source';out=d.parent/'evidence';out.mkdir(exist_ok=True)
rd=lambda p:json.loads(p.read_text());sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
def save(n,v):(out/(n+'.json')).write_text(json.dumps(v,indent=2)+'\n')
def cmd(n,a,cwd=None):
    with (out/(n+'.log')).open('w')as f:z=sp.run(a,cwd=cwd,stdout=f,stderr=sp.STDOUT)
    if z.returncode:print((out/(n+'.log')).read_text(errors='replace')[-3000:],flush=True);z.check_returncode()
def g(*a):return sp.check_output(['git','-C',s,*a],text=True).strip()
def symbols(lib):
    result={}
    with lib.open('rb')as f:
        elf=ELFFile(f)
        for sym in elf.get_section_by_name('.symtab').iter_symbols():
            n=sym.name
            if n.startswith(('RISCV','getInstruction16','DecodeInstruction','decodeInstruction','x86_implicit_effects','x86_opcode_effects','x86_mapping_counts','DecodeTable','DecoderTable')) or n in ('cs_disasm_iter','X86_get_insn_id','cs_decode_full_insn','apply_variable_effects','insns'):
                idx=sym['st_shndx'];size=sym['st_size']
                if not isinstance(idx,int)or not size:continue
                sec=elf.get_section(idx);start=sym['st_value']-sec['sh_addr'];f.seek(sec['sh_offset']+start)
                result.setdefault(n,[]).append(dict(address=sym['st_value'],bytes=size,hash=hashlib.sha256(f.read(size)).hexdigest(),section=sec.name))
        sections={v.name:[v['sh_addr'],v['sh_size']]for v in elf.iter_sections()if v.name in ('.text','.rodata','.got','.data.rel.ro')}
    return dict(symbols=result,sections=sections)
m=rd(d/'tree.json');assert g('rev-parse','HEAD')==m['parent'] and sha(d/'projected.patch')==m['sha256']
t=Path(tempfile.mkdtemp());b=t/'b'
try:
    cmd('configure',['cmake','-S',s,'-B',b,'-G','Ninja','-DCMAKE_BUILD_TYPE=Release','-DCMAKE_C_COMPILER=clang','-DCAPSTONE_ARCHITECTURE_DEFAULT=OFF','-DCAPSTONE_BUILD_SHARED_LIBS=ON','-DCAPSTONE_BUILD_STATIC_LIBS=ON','-DCAPSTONE_BUILD_LEGACY_TESTS=OFF','-DCAPSTONE_BUILD_CSTOOL=OFF','-DCAPSTONE_BUILD_CSTEST=ON','-DCMAKE_C_FLAGS=-Wno-error=incompatible-pointer-types-discards-qualifiers',*['-DCAPSTONE_'+a+'_SUPPORT=ON' for a in ('X86','ARM','AARCH64','MIPS','RISCV','PPC')]])
    images={};objects={};layout={}
    for stage in ('base','fix'):
        if stage=='fix':g('apply','--index',str(d/'projected.patch'));assert g('write-tree')==m['tree']
        cmd('build-'+stage,['cmake','--build',b,'--parallel','4','--target','capstone_shared'])
        so,=[x for x in b.glob('libcapstone.so.*')if not x.is_symlink()]
        relink=sp.check_output(['ninja','-C',b,'-t','commands','capstone_shared'],text=True)
        link,=[shlex.split(part.strip()) for line in relink.splitlines() for part in line.split('&&') if ' -shared ' in part and 'X86Mapping.c.o' in part and ' -o ' in part]
        members=[x for x in link if x.endswith('.o')]
        objects[stage]={x:sha(b/x)for x in members}
        mapper,=[x for x in members if x.endswith('/X86Mapping.c.o')]
        for variant in ('stock','last'):
            args=link[:];dest=t/(stage+'-'+variant+'.so');args[args.index('-o')+1]=str(dest)
            if variant=='last':
                args.remove(mapper);insert=max(args.index(x)for x in members if x!=mapper)+1;args.insert(insert,mapper)
            cmd('link-'+stage+'-'+variant,args,b)
            if variant=='stock':assert sha(dest)==sha(so)
            k=stage+'-'+variant;images[k]=dest.read_bytes();layout[k]=symbols(dest)
    assert objects['base'].keys()==objects['fix'].keys()
    changed=[n for n in objects['base'] if objects['base'][n]!=objects['fix'][n]]
    assert all('/RISCV/' not in n for n in changed) and any(x.endswith('/X86Mapping.c.o') for x in changed)
    save('layout',dict(objects=objects,changed=changed,images={k:hashlib.sha256(v).hexdigest()for k,v in images.items()},layout=layout))
    slot=t/'slot';slot.mkdir();target=slot/'libcapstone.so.6';target.write_bytes(images['base-stock']);(slot/'libcapstone.so').symlink_to(target.name)
    cmd('compile',['c++','-std=c++17','-O3','-I',s/'include',d/'time.cpp','-L',slot,'-Wl,-rpath,'+str(slot),'-lcapstone','-o',t/'time'])
    import corpus
    cases=corpus.prepare(d,t,out,lambda args,n:cmd(n,args))
    chosen={'riscv64-sort':105,'riscv64-ls':105,'riscv64-cp':105,'arm64-ls':102,'mips64el-ls':103}
    panels=[(q['name'],chosen[q['name']],0,Path(q['path']),0x100000)for q in cases if q['name']in chosen]
    assert any(z[0]=='riscv64-sort'for z in panels)
    shutil.copy2(d/'fetch.py',t/'fetch.py');cmd('pe',['python3','-B',t/'fetch.py'])
    panels.extend([('putty32',32,2,t/'putty-0.85-32.text',0x401000),('putty64',64,2,t/'putty-0.85-64.text',0x140001000)])
    os.sched_setaffinity(0,{min(os.sched_getaffinity(0))});rng=random.Random(1807)
    save('host',dict(cpu=sp.check_output(['lscpu'],text=True),os=Path('/etc/os-release').read_text(),cc=sp.check_output(['clang','--version'],text=True)))
    images['copy']=images['base-stock'];size=max(map(len,images.values()));images={k:v+bytes(size-len(v)) for k,v in images.items()}
    def invoke(k,n):
        target.write_bytes(images[k]);return list(map(int,sp.check_output(['setarch','x86_64','-R',t/'time',str(arch),str(mode),path,str(ip),str(n)],text=True).split()))
    rows=[]
    for name,arch,mode,path,ip in panels:
        warm=invoke('base-stock',1);n=max(1,round(90e6/warm[0]));expected=invoke('base-stock',n)[2];cycles=[]
        for rep in range(19):
            order=list(images);rng.shuffle(order);cyc={k:[]for k in order}
            for k in order+order[::-1]:
                v=invoke(k,n);assert v[2]==expected,(name,k,expected,v)
                cyc[k].append(v[0])
            cycles.append(cyc)
        rows.append(dict(name=name,mode=mode,sha=sha(path),reps=n,expected=expected,cycles=cycles));save('timings',rows)
    save('complete',dict(done=True,m=m,panels=len(rows)))
finally:
    size=sum(x.stat().st_size for x in t.rglob('*')if x.is_file() and not x.is_symlink());shutil.rmtree(t);save('cleanup',dict(bytes=size,removed=not t.exists()))
