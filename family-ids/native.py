from pathlib import Path
import json,hashlib,os,platform,shutil,struct,subprocess as sp,tempfile
import corpus
r=Path(__file__).resolve().parent;s=r.parent/'source';out=r.parent/'evidence';out.mkdir(exist_ok=True);rd=lambda f:json.loads(f.read_text());q=rd(r/'stages.json');m=rd(r/'metadata.json');darwin=platform.system()=='Darwin';t=Path(tempfile.mkdtemp())
def put(n,v):(out/(n+'.json')).write_text(json.dumps(v,indent=2)+'\n')
def sha(f):return hashlib.sha256(f.read_bytes()).hexdigest()
def get(*a):return sp.check_output(a,text=True).strip()
def run(label,*a):
    with (out/(label+'.log')).open('w')as f:z=sp.run(a,stdout=f,stderr=sp.STDOUT)
    if z.returncode:print((out/(label+'.log')).read_text(errors='replace')[-1200:]);z.check_returncode()
def apply(k):
    get('git','-C',s,'restore','--source','HEAD','--staged','--worktree','--','.')
    if k!='base':
        assert sha(r/(k+'.patch'))==q[k]['sha256'];get('git','-C',s,'apply','--index',r/(k+'.patch'));assert get('git','-C',s,'write-tree')==q[k]['tree']
try:
    assert get('git','-C',s,'rev-parse','HEAD')==m['checkout'] and all(v['parent']==m['checkout']for v in q.values())
    arch=['MIPS']
    flags=['-DCMAKE_BUILD_TYPE=Release','-DCMAKE_C_COMPILER=clang','-DCMAKE_C_FLAGS=-Wno-error=incompatible-pointer-types-discards-qualifiers','-DCAPSTONE_BUILD_MACOS_THIN=ON','-DCAPSTONE_ARCHITECTURE_DEFAULT=OFF','-DCAPSTONE_BUILD_CSTEST=ON','-DCAPSTONE_BUILD_CSTOOL=OFF','-DCAPSTONE_BUILD_LEGACY_TESTS=OFF','-DCAPSTONE_BUILD_STATIC_LIBS=OFF','-DCAPSTONE_BUILD_SHARED_LIBS=ON',*['-DCAPSTONE_'+a+'_SUPPORT=ON'for a in arch]]
    libs={};images={}
    for k in ('base',*q):
        apply(k);b=t/'build'
        run('cmake-'+k,'cmake','-G','Ninja','-S',s,'-B',b,*flags)
        units=['mips_scan','mips_register_names','mips16_memory_calls','mips16_frames','mips16_word_order','mips16_shifts_hilo','mips16_immediates','mips_msa_control','mips_reglist_offset','mips16e2']
        run('build-'+k,'cmake','--build',b,'--parallel','4','--target','capstone_shared',*units)
        run('unit-'+k,'ctest','--test-dir',b,'--no-tests=error','--output-on-failure','-R','^unit_('+'|'.join(units)+')$')
        lib=next(f for f in b.glob('libcapstone*')if f.is_file()and not f.is_symlink()and ('.dylib' in f.name or '.so.'in f.name))
        path=t/(k+lib.suffix);shutil.copy2(lib,path);libs[k]=path
        images[k]=dict(shared=sha(path),static=(b/'libcapstone.a').is_file(),bytes=path.stat().st_size,
                       object={a:sha(next(b.rglob(a)))for a in('cs.c.o','MipsInstPrinter.c.o','MipsDisassembler.c.o','MipsMapping.c.o')})
    for k in q:
        changes={n for n,v in images['base']['object'].items()if images[k]['object'][n]!=v}
        assert not images[k]['static'] and not images['base']['static']
        expected={'cold':{'cs.c.o'},'mips':{'MipsInstPrinter.c.o','MipsMapping.c.o'},'combined':{'MipsInstPrinter.c.o','cs.c.o'}}[k]
        assert changes==expected,(k,changes,expected)
    assert all(images[k]['shared']!=images['base']['shared']for k in q);put('images',images)
    shutil.rmtree(b);driver=t/'measure';run('driver','clang++','-O3','-std=c++17','-I',s/'include',r/'compare.cpp','-ldl','-o',driver)
    cases={}
    manifest=rd(r/'corpus-manifest.json')
    for n,arch in [(arch+'-'+cmd,arch)for arch in ('mips64el',)for cmd in ('ls','cp','sort')]:
        v,=[e for e in manifest['inputs']if e['name']==n];deb=t/(n+'.deb');run('download-'+n,'curl','-fsSL','--retry','3','--max-time','100',v['url'],'-o',deb);assert sha(deb)==v['package_sha256']
        raw=corpus.deb_binary(deb,v['command'],v.get('member'));body=corpus.elf_text(raw);f=t/(n+'.text');f.write_bytes(body);assert sha(f)==v['text_sha256'];deb.unlink()
        hdr=struct.unpack_from('<16sHHIQQQIHHHHHH',raw);secs=[struct.unpack_from('<IIQQQQIIQQ',raw,hdr[6]+i*hdr[11])for i in range(hdr[12])];sect,=[v for v in secs if v[5]==len(body)and raw[v[4]:v[4]+v[5]]==body]
        cases[n]=(f,arch,sect[3])
    put('inputs',{n:dict(hash=sha(f),arch=arch,ip=ip,bytes=f.stat().st_size)for n,(f,arch,ip) in cases.items()})
    verify={}
    for k in q:
        args=[driver,libs['base'],libs[k]];snapshot=verify[k]={}
        for n,(f,arch,ip) in cases.items():snapshot[n]=json.loads(get(*args,'verify',f,arch,str(ip)))
        put('verified',verify)
    assert darwin
    copy=t/'independent.dylib';shutil.copy2(libs['base'],copy);assert sha(copy)==sha(libs['base'])
    timings={}
    for name,(f,arch,ip) in cases.items():
        panels={}
        for seed in range(24):
            raw=[list(map(int,line.split()))for line in get(driver,libs['base'],copy,libs['mips'],'paired',f,str(ip),str(seed+612)).splitlines()]
            assert len(raw)==18
            for mode in (0,1,2):
                for api in (0,1):
                    rows=[v for v in raw if v[:2]==[mode,api]]
                    assert {x[2]for x in rows}=={0,1,2} and len({tuple(x[5:])for x in rows})==1
                    panels.setdefault(name+'/'+('iter' if api else 'time')+'/'+str(mode),[]).append({('base','copy','mips')[x[2]]:x[3:]for x in rows})
        timings.update(panels);put('timings',timings)
    put('hardware',dict(cpu=get('sysctl','-n','machdep.cpu.brand_string') if darwin else get('lscpu'),compiler=get('clang','--version'))) 
    put('complete',dict(source=q,panels=len(timings),compiler=get('clang','--version'),cpu=get('sysctl','-n','machdep.cpu.brand_string')if darwin else get('lscpu')))
finally:
    size=sum(f.stat().st_size for f in t.rglob('*')if f.is_file()and not f.is_symlink());shutil.rmtree(t);put('cleanup',dict(removed=not t.exists(),bytes=size))
