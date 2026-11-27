from pathlib import Path
from elftools.elf.elffile import ELFFile
from overlay import write_control
import hashlib,itertools,json,math,os,random,shutil,subprocess as sp,sys,tempfile
r=Path(__file__).resolve().parent
e=r.parent/'evidence';e.mkdir(exist_ok=True);src=r.parent/'source';ice=r.parent/'iced-source'
read=lambda f:json.loads(f.read_bytes())
sha=lambda f:hashlib.sha256(f.read_bytes()).hexdigest()
def run(*argv,**kw):sp.run(argv,check=True,**kw)
def get(*argv,**kw):return sp.check_output(argv,text=True,**kw).strip()
def save(n,v):(e/(n+'.json')).write_text(json.dumps(v,indent=2)+'\n')
def layout(binary):
    with binary.open('rb')as f:
        elf=ELFFile(f);sec={x.name:[x['sh_addr'],x['sh_size']]for x in elf.iter_sections()if x['sh_flags']&2}
        syms={}
        for s in elf.get_section_by_name('.symtab').iter_symbols():
            index=s['st_shndx'];name=s.name
            if not isinstance(index,int) or s['st_info']['type']!='STT_FUNC' or not s['st_size']:continue
            if not any(v in name for v in ('cs_disasm_iter','cs_decode_full','X86_ATT_printInst','X86_Intel_printInst','X86_getInstruction','decodeInstruction','writeVexBaseMemory','writeVexSibTransfer','X86_decodeOutputMiss64','X86_decodeVector','VexReader')):continue
            segment=elf.get_section(index);off=s['st_value']-segment['sh_addr'];f.seek(segment['sh_offset']+off)
            syms[name]=[s['st_value'],s['st_size'],hashlib.sha256(f.read(s['st_size'])).hexdigest()]
        assert {'cs_disasm_iter','cs_decode_full_insn','X86_ATT_printInst'}<=syms.keys()
        return dict(sections=sec,symbols=syms,sha=sha(binary))
q=read(r/'source.json');m=read(r/'experiment.json');wanted=set(read(r/'focus.json'));w=Path(tempfile.mkdtemp());b=w/'build';ad=w/'adapter';ad.mkdir()
try:
    assert get('git','-C',src,'rev-parse','HEAD')==q['base']['commit'] and get('git','-C',ice,'rev-parse','HEAD')==m['iced_revision']
    assert all(sha(r/k)==v for k,v in m['drivers'].items()) and sha(r/'candidate.patch')==q['candidate']['sha256']
    flags=['-DCAPSTONE_X86_SUPPORT=ON','-DCAPSTONE_ARCHITECTURE_DEFAULT=OFF','-DCAPSTONE_BUILD_CSTEST=OFF','-DCAPSTONE_BUILD_CSTOOL=OFF','-DCAPSTONE_BUILD_STATIC_LIBS=ON','-DCAPSTONE_BUILD_SHARED_LIBS=ON','-DCMAKE_BUILD_TYPE=Release','-DCMAKE_EXPORT_COMPILE_COMMANDS=ON']
    args=['clang++','-O3','-std=c++17','-I',src,'-I',src/'include'];tail=['-ldl','-lpthread','-lm','-no-pie']
    for name in ('Cargo.lock','iced.rs'):shutil.copyfile(r/name,ad/name)
    (ad/'Cargo.toml').write_text((r/'Cargo.toml').read_text().replace('ICED_ROOT',str(ice)))
    run('cargo','build','--release','--locked',cwd=ad);iced=ad/'target/release/libiced_compare.a'
    run('cmake','-G','Ninja','-S',src,'-B',b,*flags)
    so=b/'libcapstone.so';ar=b/'libcapstone.a'
    def build():
        run('cmake','--build',b,'--target','capstone_shared','capstone_static','--parallel','4')
        run(*args,r/'driver.cpp',iced,ar,*tail,'-o',w/'static')
        assert 'libcapstone' not in get('ldd',w/'static')
    layouts={};binaries={'shared':{},'static':{}}
    for stage in ('base','candidate','switch'):
        if stage=='candidate':
            run('git','-C',src,'apply','--index',r/'candidate.patch')
            assert get('git','-C',src,'write-tree')==q['candidate']['tree']
        if stage=='switch':write_control(src,False)
        build();layouts[stage]={k:layout(f)for k,f in [('shared',so),('static',w/'static')]}
        binaries['shared'][stage]=so.read_bytes()
        binaries['static'][stage]=(w/'static').read_bytes()
    save('layout',layouts)
    run(*args,r/'driver.cpp',iced,so,'-Wl,-rpath,'+str(b),*tail,'-o',w/'shared')
    run(*args,r/'vectors.cpp',so,'-Wl,-rpath,'+str(b),*tail,'-o',w/'vectors')
    assert str(b/'libcapstone.so') in get('ldd',w/'shared')
    for name in ('frozen_deb.py','jpeg_archive.py','pe_panels.py','pdata.py','pe-images.json','inputs.json','libmvec.py','libmvec.json'):shutil.copyfile(r/name,w/name)
    inp=read(w/'inputs.json');(w/'inputs.json').write_text(json.dumps({k:v for k,v in inp.items() if k in m['samples']}))
    sys.path.insert(0,str(w));import pe_panels,frozen_deb
    run(sys.executable,'-B',w/'libmvec.py');libmvec=read(w/'libmvec.json')
    fixtures=list(itertools.chain([('libmvec-amd64',64,w/'libmvec.text',[(0,libmvec['bytes'],libmvec['address'])],libmvec)],pe_panels.prepare(w),frozen_deb.prepare(w)))
    cases={}
    for name,bits,f,extents,_ in fixtures:
        prov=m['provenance'][name];assert sha(f)==prov['text_sha256']
        ext=[x for x in extents if tuple(x) not in {tuple(j[:3])for j in prov['excluded_incompatible_extents']}]
        path=w/(name+'.tsv')
        def emit():path.write_text(''.join('%d %d %d\n'%tuple(x) for x in ext))
        emit()
        if m['samples'][name]=='simd-functions':
            events=[list(map(int,line.split()))for line in get(w/'vectors',str(bits),f,path).splitlines()]
            assert len(events)==len(ext)
            ext=[x for x,row in zip(ext,events)if row[1]>=8 and row[1]>=0.15*row[0]];emit()
        assert sha(path)==prov['extent_sha256']
        for k in sorted(wanted):
            link,prog,mode=k.split('/')
            if prog==name:
                cases[k]=(w/('static' if link.startswith('static') else 'shared'),'public-att' if 'att'in link else 'capstone',mode,f,path,str(bits))
    assert set(cases)==wanted
    os.sched_setaffinity(0,{min(os.sched_getaffinity(0))});invoke=['setarch',os.uname().machine,'-R']
    from fixed_image import FixedImage
    images={k:FixedImage(so.resolve() if k=='shared' else w/'static',v,executable=k=='static')for k,v in binaries.items()}
    # Rows are randomized over all four treatments in one and the same job.
    # Both old/new choose functions in one identical ELF file.
    def call(case,tag,reps,count=False):
        app,engine,mode,f,tsv,bits=case
        image=images['static' if app.name=='static' else 'shared']
        image.select('base' if tag.startswith('baseline') else 'candidate' if tag.startswith('production') else 'switch')
        env=dict(os.environ,BENCH_VEX_READER='1' if tag.startswith('new') else '0')
        v=sp.run([*invoke,app,engine,mode,str(reps),f,tsv,bits],env=env,capture_output=True,text=True,check=True)
        row=list(map(int,v.stdout.split()))
        assert len(row)>=6
        if count:
            line,=[s for s in v.stderr.splitlines() if s.startswith('reader ')];bit,entries,records,transfers=map(int,line.split()[1:])
            assert bit==int(env['BENCH_VEX_READER']) and 0<=transfers<=records<=entries
            return row[2:],[entries,records,transfers]
        return row
    timing={};consumed={};tags=['old','old-copy','new','new-copy','baseline','baseline-copy','production','production-copy']
    for key,case in cases.items():
        n=max(1,math.ceil(25e6/call(case,'old',1)[0]));expect=call(case,'old',n)[2:];blocks=[];rng=random.Random('unchanged-elf/'+key)
        for _ in range(35):
            order=tags.copy();rng.shuffle(order);trial={k:[] for k in tags}
            for tag in order+order[::-1]:
                row=call(case,tag,n);assert row[2:]==expect;trial[tag].append(row[:2])
            blocks.append({k:[a+b for a,b in zip(*v)]for k,v in trial.items()})
        timing[key]=dict(reps=n,records=expect,cycles=blocks);save('timing',timing)
    for image in images.values():
        assert {'base','candidate','switch'}==set(image.verified)
    save('complete',dict(complete=True,source=q,isa=os.uname().machine,workloads=len(cases),hardware=get('lscpu'),compiler=get('clang','--version').splitlines()[0],images={k:v.receipt()for k,v in images.items()}))
finally:
    size=sum(f.stat().st_size for f in w.rglob('*') if f.is_file() and not f.is_symlink());shutil.rmtree(w);save('cleanup',dict(bytes=size,removed=not w.exists()))
