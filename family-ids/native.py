from pathlib import Path
import hashlib,json,os,platform,random,shutil,subprocess as sp,tempfile
import corpus
d=Path(__file__).resolve().parent;s=d.parent/'source';out=d.parent/'evidence';out.mkdir(exist_ok=True)
rd=lambda f:json.loads(f.read_text());q=rd(d/'tree.json');cc=os.environ['CC'];t=Path(tempfile.mkdtemp())
def g(*args):return sp.check_output(['git','-C',s,*args],text=True).strip()
def save(name,obj):(out/(name+'.json')).write_text(json.dumps(obj,indent=2)+'\n')
def sha(f):return hashlib.sha256(f.read_bytes()).hexdigest()
def cmd(name,args):
    with (out/(name+'.log')).open('w')as f:z=sp.run(args,stdout=f,stderr=sp.STDOUT)
    if z.returncode:print((out/(name+'.log')).read_text()[-2100:]);z.check_returncode()
assert platform.machine()=='aarch64' and g('rev-parse','HEAD')==q['parent']
try:
    manifest=rd(d/'manifest.json')['inputs'];profiles={};samples={};rows=[];raw={}
    for profile,arches in [('mixed',['ARM','AARCH64','MIPS','X86']),('paired',['SYSTEMZ','RISCV']),('diet',['SYSTEMZ']),('SYSTEMZ',['SYSTEMZ']),('RISCV',['RISCV'])]:
        b=t/profile;states={};images={};active=profile in ('SYSTEMZ','RISCV')
        for k in ('base','candidate'):
            g('restore','--source','HEAD','--staged','--worktree','.');tag=profile+'-'+k
            if k=='candidate':
                delta=d/'candidate.patch';assert sha(delta)==q['sha256'];g('apply','--index',str(delta));assert g('write-tree')==q['tree']
            opts=['-DCAPSTONE_'+v+'_SUPPORT=ON'for v in arches]
            if profile=='diet':opts.append('-DCAPSTONE_BUILD_DIET=ON')
            cmd('cfg-'+tag,['cmake','-S',s,'-B',b,'-G','Ninja','-DCMAKE_BUILD_TYPE=Release','-DCMAKE_C_COMPILER='+cc,'-DCAPSTONE_ARCHITECTURE_DEFAULT=OFF','-DCAPSTONE_BUILD_SHARED_LIBS=ON','-DCAPSTONE_BUILD_STATIC_LIBS=ON','-DCAPSTONE_BUILD_CSTEST=ON','-DCAPSTONE_BUILD_LEGACY_TESTS=OFF','-DCAPSTONE_BUILD_CSTOOL=OFF','-DCMAKE_C_FLAGS='+('-Wno-error=discarded-qualifiers'if cc=='gcc'else'-Wno-error=incompatible-pointer-types-discards-qualifiers'),*opts])
            units=['register_descriptors','mcinst']if active else []
            cmd('build-'+tag,['cmake','--build',b,'--parallel','4','--target','capstone_shared','capstone_static',*units])
            if units:cmd('test-'+tag,['ctest','--test-dir',b,'--no-tests=error','--output-on-failure','-R','^unit_(register_descriptors|mcinst)$'])
            so,=[f for f in b.glob('libcapstone.so.*')if not f.is_symlink()]
            lib=b/'libcapstone.a'
            states[k]=dict(archive=sha(lib),shared=sha(so),objects={f.name:sha(f)for f in b.rglob('*.c.o')if '/tests/'not in str(f)})
            if active:
                cmd('shim-'+tag,[cc,'-shared','-Wl,-Bsymbolic','-fPIC','-O2','-DCAPSTONE_HAS_'+profile,'-DCAPSTONE_USE_SYS_DYN_MEM','-I',s,'-I',s/'include',d/'shim.c',lib,'-lm','-o',t/(tag+'.so')])
                images[k]=so.read_bytes()
        a,z=states['base'],states['candidate'];assert a['objects'].keys()==z['objects'].keys()
        changes=[n for n,v in a['objects'].items()if z['objects'][n]!=v]
        assert changes==(['SStream.c.o']if active else []) and (a['shared']==z['shared'])!=active and (a['archive']==z['archive'])!=active
        profiles[profile]=dict(states=states,changed=changes);save('profiles',profiles)
        if not active:shutil.rmtree(b);continue
        cmd('compile-state-'+profile,[cc,'-O2','-I',s,'-I',s/'include',d/'hex-state.c','-ldl','-o',t/'guard'])
        cmd('hex-states-'+profile,[t/'guard',t/(profile+'-base.so'),t/(profile+'-candidate.so')])
        assert (out/('hex-states-'+profile+'.log')).read_text().split()[0]=='24824832'
        selector,prefix=('107','s390x')if profile=='SYSTEMZ'else('105','riscv64')
        ref,=[v for v in manifest if v['name']==prefix+'-ls']
        pkg=t/(prefix+'.deb');cmd('fetch-'+prefix,['curl','--retry','3','-fsSL',ref['url'],'-o',pkg]);assert sha(pkg)==ref['package_sha256']
        sz=max(map(len,images.values()));images={k:v+bytes(sz-len(v))for k,v in images.items()};images['copy']=images['base']
        slot=t/(prefix+'-fixed');slot.mkdir();target=slot/'libcapstone.so.6';target.write_bytes(images['base']);(slot/'libcapstone.so').symlink_to(target.name)
        for name in ('time','raw'):cmd('link-'+prefix+name,['c++','-O3','-std=c++17','-I',s/'include',d/(name+'.cpp'),'-L',slot,'-Wl,-rpath,'+str(slot),'-lcapstone','-o',t/name])
        rng=random.Random(2162);os.sched_setaffinity(0,{min(os.sched_getaffinity(0))})
        for member in ('ls','cat','sort','cp'):
            data=corpus.deb_binary(pkg,member);path=t/(prefix+'-'+member+'.text');path.write_bytes(corpus.elf_text(data));case=prefix+'-'+member
            digest=sha(path);assert member!='ls'or digest==ref['text_sha256'];samples[case]=dict(text=digest,elf=hashlib.sha256(data).hexdigest(),package=sha(pkg))
            for opt in range(5):
                obs=[]
                for k in ('base','candidate'):
                    target.write_bytes(images[k]);obs.append(list(map(int,sp.check_output([t/'raw',selector,path,str(opt)]).split())))
                assert obs[0]==obs[1] and obs[0][0]>0;raw[case+'/'+str(opt)]=obs[0]
            def timed(k,mode,rep):
                target.write_bytes(images[k]);return list(map(int,sp.check_output(['setarch',platform.machine(),'-R',t/'time',selector,str(mode),path,'1048576',str(rep)]).split()))
            for mode in (0,1,2):
                one=timed('base',mode,1);reps=max(1,round(65e6/one[0]));cycles=[]
                for _ in range(21):
                    keys=list(images);rng.shuffle(keys);v={k:[]for k in keys}
                    for k in keys+keys[::-1]:
                        z=timed(k,mode,reps);assert z[2]==one[2];v[k].append(z[0])
                    cycles.append(v)
                rows.append(dict(name=case,mode=mode,cycles=cycles,sha=digest,reps=reps));save('timings',rows)
        shutil.rmtree(b)
    save('samples',samples);save('raw',raw);save('complete',dict(done=True,source=q,host=platform.machine(),cc=cc,records=len(raw),panels=len(rows)))
finally:
    n=sum(p.stat().st_size for p in t.rglob('*')if p.is_file()and not p.is_symlink());shutil.rmtree(t);save('cleanup',dict(removed=not t.exists(),bytes=n))
