"""Measure the linked Capstone effect of profiling and splitting three x86 translation units."""
from pathlib import Path
import hashlib, io, json, math, os, random, shlex, shutil, subprocess as sp
from elftools.elf.elffile import ELFFile

UNITS = {'X86DisassemblerDecoder.c', 'X86Disassembler.c', 'X86IntelInstPrinter.c'}
def digest(data):
    return hashlib.sha256(data).hexdigest()

def output(*args, **kw):
    return sp.check_output(args, **kw)

def run(*args, **kw):
    sp.run(args, check=True, **kw)

def layout(file):
    with file.open('rb') as stream:
        elf = ELFFile(stream)
        sections = {s.name: s['sh_size'] for s in elf.iter_sections() if s['sh_flags'] & 4}
        syms = elf.get_section_by_name('.symtab')
        targets = {s.name: s['st_size'] for s in syms.iter_symbols() if s.name in
                   ('X86_getInstruction','decodeInstructionFull','readOperands','printInstruction','X86_Intel_printInst','cs_decode_full_insn') or '.cold' in s.name}
    return dict(exec_bytes=sum(sections.values()),cold_bytes=sum(n for s,n in sections.items() if '.unlikely' in s or '.split.' in s),sections=sections,symbols=targets)

def prepare(r,w,build,base,stock,ice,flags,save):
    db=json.loads((build/'compile_commands.json').read_bytes())
    commands={}
    for entry in db:
        name=Path(entry['file']).name
        if name not in UNITS:continue
        args=shlex.split(entry['command'])
        obj=Path(entry['directory'])/args[args.index('-o')+1]
        if obj.is_file():
            assert name not in commands,entry
            commands[name]=(entry['directory'],args,obj)
    assert set(commands)==UNITS,commands.keys()
    members=output('ar','t',stock,text=True).splitlines()
    assert len(members)>=60 and len(members)==len(set(members))
    def contents(lib):
        return {m:digest(output('ar','p',lib,m)) for m in members}
    baseline=contents(stock); reports={};images={};profiles={}
    reference=w/'keep.c'
    reference.write_text('#include "arch/X86/X86ScanAdapter.h"\n__attribute__((used)) static __typeof__(&X86_disasmIterText) const keep = X86_disasmIterText;\n')
    run('clang','-O2','-I',base,'-I',base/'include','-c',reference,'-o',w/'keep.o')
    run('clang++','-O3','-std=c++17','-I',base/'include','-c',r/'foreign.cpp','-o',w/'foreign.o')
    def link_normal(tag,lib):
        run('clang++',w/'driver.o',lib,ice,*flags,'-o',w/('x86-'+tag))
        run('clang++',w/'foreign.o',w/'keep.o',lib,*flags,'-o',w/('foreign-'+tag))
        run('clang','-fPIC','-shared','-I',base/'include',r/'export.c','-Wl,--whole-archive',lib,'-Wl,--no-whole-archive','-o',w/(tag+'.so'))
        images[tag]={n:digest((w/(n+'-'+tag)).read_bytes()) for n in ('x86','foreign')}
        assert '__llvm_profile_write_file' not in output('nm', w/('x86-'+tag), text=True)
    def compile_units(tag,opts):
        directory=w/tag;directory.mkdir()
        objects=[];codes={};messages={}
        for name,(cwd,original,obj) in sorted(commands.items()):
            target=directory/obj.name;args=original.copy();args[args.index('-o')+1]=str(target)
            proc=sp.run([*args,*opts],cwd=cwd,stdout=sp.PIPE,stderr=sp.STDOUT,text=True)
            if proc.returncode:raise RuntimeError(proc.stdout)
            messages[name]=[line for line in proc.stdout.splitlines() if 'warning:' in line]
            objects.append(target);codes[name]=layout(target)
            if tag=='stock':assert digest(target.read_bytes())==baseline[obj.name],name
        lib=directory/stock.name;shutil.copyfile(stock,lib);run('ar','r',lib,*objects)
        assert output('ar','t',lib,text=True).splitlines()==members
        after=contents(lib);modified=sorted(m for m in members if baseline[m]!=after[m])
        assert set(modified)<=set(o.name for o in objects)
        if tag=='stock':assert not modified
        reports[tag]=dict(options=opts,changed=modified,objects=after,layout=codes,warnings=messages,archive=digest(lib.read_bytes()))
        return lib
    compile_units('stock',[]);link_normal('stock',stock)
    assert digest((w/'runner').read_bytes())==images['stock']['x86']
    trace=compile_units('instrumented',['-fprofile-generate'])
    tx=w/'training-x86';run('clang++',w/'driver.o',trace,ice,*flags,'-fprofile-generate','-o',tx)
    zstd=json.loads((r/'zstd.json').read_bytes())
    measured={p['text_sha256'] for p in json.loads((r/'experiment.json').read_bytes())['provenance'].values()}
    training=[]
    for arch,meta in zstd.items():
        package=w/(arch+'.deb');run('curl','-fsSL','--retry','3','--max-time','100','-o',package,meta['url'])
        assert digest(package.read_bytes())==meta['package']
        member=next(x for x in output('ar','t',package,text=True).splitlines() if x.startswith('data.tar'))
        tar=w/'zstd.tar';tar.write_bytes(output('ar','p',package,member))
        data=output('tar','-xOf',tar,meta['member']);assert digest(data)==meta['binary']
        elf=ELFFile(io.BytesIO(data));sec=elf.get_section_by_name('.text');text=sec.data()
        assert digest(text)==meta['text'] and meta['text'] not in measured and len(text)==meta['size'] and sec['sh_addr']==meta['address']
        code=w/(arch+'.text');extent=w/'zstd.tsv';code.write_bytes(text);extent.write_text(f"0 {len(text)} {meta['address']}\n")
        for route in ('capstone','private'):
            for mode in (0,1,2):
                key=f'{arch}-{route}-{mode}'
                args=[route,str(mode),'1',code,extent,'32' if arch=='i386' else '64']
                ref=list(map(int,output(w/'runner',*args).split()))
                pat=str(w/(key+'-%m.profraw'))
                obs=list(map(int,output(tx,*args,env=dict(os.environ,LLVM_PROFILE_FILE=pat)).split()))
                raw,=w.glob(key+'-*.profraw')
                assert obs[2:]==ref[2:] and obs[2]>50000 and raw.stat().st_size>0
                profiles[key]=raw;training.append(dict(name=key,accepted=obs[2],rejected=obs[3],sha=digest(raw.read_bytes())))
        for f in (package,tar,code,extent):f.unlink()
    clang=Path(shutil.which('clang')).resolve()
    prof=clang.parent/'llvm-profdata'
    if not prof.exists():prof=shutil.which('llvm-profdata-'+clang.name.split('-')[-1]) or shutil.which('llvm-profdata')
    data=w/'decoder.profdata';run(prof,'merge','-o',data,*profiles.values())
    desc=output(prof,'show',data,text=True)
    assert 'IR' in desc and 'Total functions' in desc
    use=['-fprofile-use='+str(data),'-Werror=profile-instr-out-of-date']
    for tag,opt in [('trained',['-fno-split-machine-functions']),('split',['-fsplit-machine-functions'])]:
        lib=compile_units(tag,[*use,*opt]);link_normal(tag,lib)
    info=dict(training=training,inputs=zstd,profile_summary=desc,profile_bytes=data.stat().st_size,profile_sha=digest(data.read_bytes()),stock_archive=digest(stock.read_bytes()),reports=reports,images=images,tools=dict(clang=str(clang),profdata=str(prof)))
    save('code-layout',info)
    for f in [*profiles.values(),tx,data]:f.unlink()
    for route in ('public','fixed'):
        run('clang++','-O2','-std=c++17','-I',base/'include',r/('records-'+route+'.cpp'),'-ldl','-o',w/('records-'+route))
    from training import fetch
    foreign=fetch(r,w);assert len(foreign)==5
    save('foreign-corpus',foreign)
    return foreign

def measure(w,cases,foreign,save):
    recorded={};timed={}
    for name,(mode,code,extent,bits) in cases.items():
        if mode:continue
        proof={}
        for route in ('public','fixed'):
            for tag in ('trained','split'):
                out=output(w/('records-'+route),w/'stock.so',w/(tag+'.so'),code,extent,bits,text=True)
                counts=[list(map(int,l.split())) for l in out.splitlines()]
                assert len(counts)==4 and all(x==counts[0] and x[1]>0 for x in counts)
                proof[route+'/'+tag]=counts
        recorded[name]=proof
    save('records',recorded)
    def clock(key,cmd,rival=None):
        names=['stock','stock+copy','trained','trained+copy','split','split+copy']+([rival] if rival else [])
        def take(t,n):
            return list(map(int,output('setarch',os.uname().machine,'-R',*cmd(t.partition('+')[0],n)).split()))
        warm={t:take(t,1) for t in names}
        assert all(v[2:5]==warm['stock'][2:5] for v in warm.values())
        n=max(1,math.ceil(12e6/min(v[0] for v in warm.values())))
        checks={t:take(t,n)[2:] for t in names}
        assert all(z==checks['stock'] for t,z in checks.items() if t!=rival)
        order=names[:];rng=random.Random('three-units/'+key);series=[]
        for _ in range(17):
            rng.shuffle(order);pair={}
            for t in order+order[::-1]:
                v=take(t,n);assert v[2:]==checks[t];both=pair.setdefault(t,[0,0]);both[0]+=v[0];both[1]+=v[1]
            series.append(pair)
        timed[key]=dict(n=n,checks=checks,blocks=series);save('timings',timed)
    for name,(mode,code,extent,bits) in cases.items():
        rival='fast' if mode else 'iced'
        for route in ('capstone','private'):
            clock(route+'/'+name,lambda t,n:[w/('x86-'+('stock' if t==rival else t)),t if t==rival else route,str(mode),str(n),code,extent,bits],rival)
    for z in foreign:
        for mode in range(3):
            clock('foreign/'+z['name']+'/'+str(mode),lambda t,n:[w/('foreign-'+t),z['arch'],w/(z['name']+'.text'),str(mode),str(n)])
    assert len(recorded)==6 and len(timed)==51
