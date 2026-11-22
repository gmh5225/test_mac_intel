from pathlib import Path
import hashlib,json,os,platform,random,shutil,subprocess as sp,tempfile
import corpus
r=Path(__file__).resolve().parent
s=r.parent/'source';out=r.parent/'evidence';out.mkdir(exist_ok=True)
def save(n,v):(out/(n+'.json')).write_text(json.dumps(v,indent=2)+'\n')
def run(args,n):
    f=out/(n+'.log')
    with f.open('w') as o:p=sp.run(args,stdout=o,stderr=sp.STDOUT)
    if p.returncode:print(f.read_text(errors='replace')[-2600:],flush=True);p.check_returncode()
def g(*a):return sp.check_output(['git','-C',s,*a],text=True).strip()
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
q=json.loads((r/'tree.json').read_text());cc=os.environ['CC']
assert g('rev-parse','HEAD')==q['parent'] and sha(r/'candidate.patch')==q['sha256']
tests=['riscv_writeback_postprocess','riscv_op_count_iter','riscv_instruction_groups','riscv_mapping_index','riscv_reg_access','riscv_sysreg','riscv_insn_name_segv']
t=Path(tempfile.mkdtemp());libs={};objects={};raw={};tim=[]
try:
    flavors=['dedicated','mixed','diet']
    prev=json.loads((r/'prototype.json').read_text())
    assert prev['parent']==q['parent'] and sha(r/'prototype.patch')==prev['sha256']
    for label in ('base','candidate','prototype'):
        if label=='prototype':
            g('read-tree','--reset','-u','HEAD')
            g('apply','--index',str(r/'prototype.patch'));assert g('write-tree')==prev['tree']
        if label=='candidate':
            g('apply','--index',str(r/'candidate.patch'));assert g('write-tree')==q['tree']
            run(['python3','-B',s/'suite/synctools/operand_writeback.py','--check'],'generate')
        for f in flavors:
            b=t/f;arches=('RISCV','ARM','AARCH64','MIPS','PPC','X86') if f=='mixed' else ('RISCV',)
            opts=['-DCMAKE_BUILD_TYPE=Release','-DCMAKE_C_COMPILER='+cc,'-DCAPSTONE_ARCHITECTURE_DEFAULT=OFF','-DCAPSTONE_BUILD_SHARED_LIBS=ON','-DCAPSTONE_BUILD_STATIC_LIBS=ON','-DCAPSTONE_BUILD_CSTEST=ON','-DCAPSTONE_BUILD_CSTOOL=OFF','-DCAPSTONE_BUILD_LEGACY_TESTS=OFF','-DCMAKE_C_FLAGS='+('-Wno-error=discarded-qualifiers' if cc=='gcc' else '-Wno-error=incompatible-pointer-types-discards-qualifiers'),*['-DCAPSTONE_'+a+'_SUPPORT=ON'for a in arches]]
            if f=='diet':opts.append('-DCAPSTONE_BUILD_DIET=ON')
            if label=='base':run(['cmake','-S',s,'-B',b,'-G','Ninja',*opts],'configure-'+f)
            chosen=tests if f!='diet' else ['riscv_writeback_postprocess']
            run(['cmake','--build',b,'--target','capstone_shared',*chosen,'--parallel','4'],'build-'+f+'-'+label)
            run(['ctest','--test-dir',b,'--no-tests=error','--output-on-failure','--parallel','3','-R','^unit_('+'|'.join(chosen)+')$'],'tests-'+f+'-'+label)
            so,=[p for p in b.glob('libcapstone.so.*')if not p.is_symlink()]
            path=t/(f+'-'+label+'.so');shutil.copyfile(so,path);libs.setdefault(f,{})[label]=path
            objects.setdefault(f,{})[label]={p.name:sha(p) for p in (b/'CMakeFiles/capstone.dir').rglob('*.o')}
    for f,sets in objects.items():
        active=f=='diet' or (f=='dedicated' and cc=='clang')
        base,selected,prototype=(sets[k] for k in ('base','candidate','prototype'))
        assert base.keys()==selected.keys()==prototype.keys()
        diff=[k for k in base if base[k]!=selected[k]]
        assert diff==(['RISCVDisassembler.c.o'] if active else []),(f,diff)
        reference='prototype' if active else 'base'
        assert selected==sets[reference] and sha(libs[f]['candidate'])==sha(libs[f][reference]),f
    save('objects',objects);save('images',{f:{k:sha(p)for k,p in v.items()}for f,v in libs.items()})
    cases=[z for z in corpus.prepare(r,t,out,run) if z['name']in ('riscv64-cp','riscv64-ls','riscv64-sort')];assert len(cases)==3
    run(['c++','-std=c++17','-O2','-I',s/'include',r/'riscv-states.cpp','-ldl','-o',t/'state'],'compile-states')
    for k,opt in [('ordinary',[]),('callbacks',['custom'])]:
        run([t/'state',libs['dedicated']['base'],libs['dedicated']['candidate'],t/'corpus',*opt],'states-'+k)
        raw[k]=json.loads((out/('states-'+k+'.log')).read_text().splitlines()[-1]);assert raw[k]['comparisons']>36000000
    slot=t/'slot';slot.mkdir();so=slot/'libcapstone.so.6';shutil.copyfile(libs['dedicated']['base'],so);(slot/'libcapstone.so').symlink_to(so.name)
    ld=['-L',slot,'-Wl,-rpath,'+str(slot),'-lcapstone']
    run(['c++','-std=c++17','-O3','-I',s/'include',r/'time.cpp',*ld,'-o',t/'time'],'compile-time')
    run([cc,'-O2','-I',s/'include',r/'diet-records.c',*ld,'-o',t/'diet-records'],'compile-diet-states')
    bind=['setarch',platform.machine(),'-R'];os.sched_setaffinity(0,{min(os.sched_getaffinity(0))})
    for f in ('dedicated','diet'):
        if f=='dedicated' and cc=='gcc':continue
        images={k:p.read_bytes()for k,p in libs[f].items()if k!='prototype'};images['copy']=images['base'];size=max(map(len,images.values()));images={k:v+bytes(size-len(v))for k,v in images.items()}
        def once(k,path,mode,n):
            so.write_bytes(images[k]);return list(map(int,sp.check_output([*bind,t/'time','105',str(mode),path,'1048576',str(n)],text=True).split()))
        if f=='diet':
            for k in ('base','candidate'):
                so.write_bytes(images[k])
                with sp.Popen([t/'diet-records'],stdout=sp.PIPE,stderr=sp.PIPE) as proc:
                    digest=hashlib.sha256()
                    while block:=proc.stdout.read(1<<20):digest.update(block)
                    cnt=proc.stderr.read().decode().strip();assert proc.wait()==0 and cnt.startswith('262144 states, ')
                    raw['diet-'+k]=[digest.hexdigest(),cnt]
            assert raw['diet-base']==raw['diet-candidate']
        for z in cases:
            for mode in ((0,) if f=='diet' else (0,1,2)):
                first=once('base',z['path'],mode,1);n=max(1,round(80e6/first[0]));assert first[2]>0
                cycles=[];rng=random.Random(f+z['name']+str(mode))
                for i in range(21):
                    order=list(images);rng.shuffle(order);v={k:[]for k in order}
                    for k in order+order[::-1]:
                        x=once(k,z['path'],mode,n);assert x[2]==first[2];v[k].append(x[:2])
                    cycles.append(v)
                tim.append(dict(profile=f,sample=z['name'],sha=z['text_sha256'],mode=mode,reps=n,signature=first[2],cycles=cycles));save('timings',tim)
    save('raw',raw)
    if cc=='clang' and platform.machine()=='x86_64':run(['python3','-B',r/'identity.py'],'shipping-identity')
    save('complete',dict(source=q,tests=tests,panels=len(tim),compiler=sp.check_output([cc,'--version'],text=True).splitlines()[0],machine=platform.machine()))
finally:
    size=sum(p.stat().st_size for p in t.rglob('*')if p.is_file()and not p.is_symlink());shutil.rmtree(t);save('cleanup',dict(removed=not t.exists(),bytes=size))
