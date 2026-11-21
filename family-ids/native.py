from pathlib import Path
import hashlib,json,os,platform,random,shutil,subprocess as sp,tempfile
import corpus
d=Path(__file__).resolve().parent;s=d.parent/'source';out=d.parent/'evidence';out.mkdir(exist_ok=True)
def put(n,v):(out/(n+'.json')).write_text(json.dumps(v,indent=2)+'\n')
def run(args,n):
    with (out/(n+'.log')).open('wb')as f:proc=sp.run(args,stdout=f,stderr=sp.STDOUT)
    if proc.returncode:print((out/(n+'.log')).read_text(errors='replace')[-1900:],flush=True);proc.check_returncode()
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def g(*a):return sp.check_output(['git','-C',s,*a],text=True).strip()
m=json.loads((d/'tree.json').read_text());assert g('rev-parse','HEAD')=='958b98cbbeb217ab3e8babe1de7175546ec82748' and sha(d/'candidate.patch')==m['sha256']
trees=json.loads((d/'trees.json').read_text());assert g('write-tree')==trees['base']
cc=os.environ['CC'];cfg=os.environ['FLAVOR'];tmp=Path(tempfile.mkdtemp());units=['sstream','utils','mcinst','instruction_bytes','feature_mode','mapping']
try:
    flavors=['dedicated','multiarch'] if cfg=='full' else [cfg]
    libraries={x:{} for x in flavors}
    for label in ('base','alias','dispatch','candidate'):
        if label!='base':
            g('restore','--source',trees['base'],'--staged','--worktree','--','arch/Mips/MipsDisassembler.c','arch/Mips/MipsInstPrinter.c')
            g('apply','--index',str(d/(label+'.patch')))
        assert g('write-tree')==trees[label]
        for f in flavors:
            b=tmp/f
            arches=['MIPS']if f in ('dedicated','diet')else ['X86','MIPS','ARM','AARCH64','PPC','RISCV']
            opts=['-DCAPSTONE_ARCHITECTURE_DEFAULT=OFF','-DCMAKE_C_COMPILER='+cc,'-DCMAKE_BUILD_TYPE=Release','-DCAPSTONE_BUILD_SHARED_LIBS=ON','-DCAPSTONE_BUILD_STATIC_LIBS=OFF','-DCAPSTONE_BUILD_LEGACY_TESTS=OFF','-DCAPSTONE_BUILD_CSTOOL=OFF','-DCAPSTONE_BUILD_CSTEST=ON',*['-DCAPSTONE_'+a+'_SUPPORT=ON'for a in arches],'-DCMAKE_C_FLAGS='+('-Wno-error=discarded-qualifiers'if cc=='gcc'else '-Wno-error=incompatible-pointer-types-discards-qualifiers')]
            if f=='diet':opts.append('-DCAPSTONE_BUILD_DIET=ON')
            if f=='intel':opts.append('-DCAPSTONE_X86_ATT_DISABLE=ON')
            if f=='reduce':opts.append('-DCAPSTONE_X86_REDUCE=ON')
            if label=='base':run(['cmake','-S',s,'-B',b,'-G','Ninja',*opts],'configure-'+f)
            run(['cmake','--build',b,'--parallel','3','--target','capstone_shared',*units],'build-'+f+'-'+label)
            run(['ctest','--test-dir',b,'--output-on-failure','--no-tests=error','-R','^unit_('+'|'.join(units)+')$'],'units-'+f+'-'+label)
            path,=[q for q in b.glob('libcapstone.so.*')if not q.is_symlink()]
            dest=tmp/(f+'-'+label+'.so');shutil.copyfile(path,dest);libraries[f][label]=dest
    run(['python3','-B',s/'suite/synctools/fixed_len_decoder.py','--check'],'generation')
    identities={f:{k:sha(v)for k,v in libs.items()}for f,libs in libraries.items()}
    for f,ids in identities.items():assert len(set(ids.values()))==(4 if f=='dedicated' else 1),(f,ids)
    put('identities',identities)
    active='dedicated'if cfg=='full'else cfg
    if active=='dedicated':
        libs=libraries[active];run(['c++','-O2','-std=c++17','-I',s/'include',d/'mips-states.cpp','-ldl','-o',tmp/'records'],'build-records')
        for label in ('dispatch','candidate'):run([tmp/'records',libs['base'],libs[label]],'records-'+label)
        text=(out/'records-candidate.log').read_text().splitlines()[-1];assert '40894464 raw records' in text
        cases=[z for z in corpus.prepare(d,tmp,out,run) if z['name'].startswith('mips64el-')];assert len(cases)==3
        run(['c++','-O2','-std=c++17','-I',s/'include',d/'real.cpp','-ldl','-o',tmp/'real'],'compile-real')
        counts={}
        for z in cases:
            counts[z['name']]=[list(map(int,sp.check_output([tmp/'real',libs['base'],libs['candidate'],z['path'],str(custom)],text=True).split()))for custom in (0,1)]
        put('callback-checks',counts)
        slot=tmp/'slot';slot.mkdir();target=slot/'libcapstone.so.6';shutil.copyfile(libs['base'],target);(slot/'libcapstone.so').symlink_to(target.name)
        run(['c++','-std=c++17','-O3','-I',s/'include',d/'time.cpp','-L',slot,'-Wl,-rpath,'+str(slot),'-lcapstone','-o',tmp/'time'],'compile-time')
        os.sched_setaffinity(0,{min(os.sched_getaffinity(0))});bind=['setarch',platform.machine(),'-R']
        image={k:v.read_bytes()for k,v in libs.items()};image['copy']=image['base'];size=max(map(len,image.values()));image={k:v+bytes(size-len(v))for k,v in image.items()}
        def once(label,path,mode,n):
            target.write_bytes(image[label])
            return list(map(int,sp.check_output([*bind,tmp/'time','103',str(mode),path,'1048576',str(n)],text=True).split()))
        timings=[]
        for z in cases:
            for mode in ((0,)if active=='diet'else (0,1,2)):
                first=once('base',z['path'],mode,1);n=max(1,round(95e6/first[0]));assert first[2]>0
                cycles=[];rng=random.Random(z['name']+str(mode))
                for i in range(15):
                    keys=list(image);rng.shuffle(keys);v={k:[] for k in keys}
                    for k in keys+keys[::-1]:
                        r=once(k,z['path'],mode,n);assert r[2]==first[2];v[k].append(r[:2])
                    cycles.append(v)
                timings.append(dict(sample=z['name'],mode=mode,reps=n,signature=first[2],text_sha256=z['text_sha256'],cycles=cycles))
        put('timings',timings)
    put('complete',dict(source=m,compiler=sp.check_output([cc,'--version'],text=True).splitlines()[0],machine=platform.machine(),flavor=cfg,tests=units))
finally:
    size=sum(p.stat().st_size for p in tmp.rglob('*')if p.is_file()and not p.is_symlink());shutil.rmtree(tmp);put('cleanup',dict(bytes=size,removed=not tmp.exists()))
