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
    arch=['X86','ARM','AARCH64','MIPS']
    flags=['-DCMAKE_BUILD_TYPE=Release','-DCMAKE_C_COMPILER=gcc','-DCMAKE_CXX_COMPILER=g++','-DCAPSTONE_BUILD_MACOS_THIN=ON','-DCAPSTONE_ARCHITECTURE_DEFAULT=OFF','-DCAPSTONE_BUILD_CSTEST=ON','-DCAPSTONE_BUILD_CSTOOL=OFF','-DCAPSTONE_BUILD_LEGACY_TESTS=OFF','-DCAPSTONE_BUILD_STATIC_LIBS=ON','-DCAPSTONE_BUILD_SHARED_LIBS=ON',*['-DCAPSTONE_'+a+'_SUPPORT=ON'for a in arch]]
    libs={};images={}
    for k in ('base',*q):
        apply(k);b=t/'build'
        run('cmake-'+k,'cmake','-G','Ninja','-S',s,'-B',b,*flags)
        units=['x86_simple_output','x86_reg_access','x86_buffer_bounds','x86_x87_environment','x86_scan_batch','sstream','instruction_bytes','mcinst','arm_private_stream','text_option']
        run('build-'+k,'cmake','--build',b,'--parallel','4','--target','capstone_static','capstone_shared',*units)
        run('unit-'+k,'ctest','--test-dir',b,'--no-tests=error','--output-on-failure','-R','^unit_('+'|'.join(units)+')$')
        lib=next(f for f in b.glob('libcapstone*')if f.is_file()and not f.is_symlink()and ('.dylib' in f.name or '.so.'in f.name))
        path=t/(k+lib.suffix);shutil.copy2(lib,path);libs[k]=path
        images[k]=dict(shared=sha(path),static=sha(b/'libcapstone.a'),bytes=path.stat().st_size,
                       object={a:sha(next(b.rglob(a)))for a in('X86EvexScan.c.o','cs.c.o','X86OutputIterator.c.o','X86BatchScan.c.o','X86DisassemblerDecoder.c.o','MipsDisassembler.c.o','AArch64Disassembler.c.o')})
    assert len({v['shared']for v in images.values()})==len(q)+1;put('images',images)
    assert len({v['object']['X86BatchScan.c.o']for v in images.values()})==1
    changed=[n for n in images['base']['object']if images['moves']['object'][n]!=images['base']['object'][n]]
    assert changed==['X86EvexScan.c.o'],changed
    run('guard-moves','clang++','-O2','-std=c++17','-I',s/'include',r/'guard-packed.cpp','-ldl','-o',t/'moves')
    run('compile-oracle','g++','-O2','-std=c++17','-I',s/'include',r/'oracle.cpp','-ldl','-o',t/'oracle')
    run('guard-driver','clang++','-O2','-std=c++17','-I',s/'include',r/'guard.cpp','-ldl','-o',t/'guard')
    shutil.rmtree(b);driver=t/'measure';run('driver','clang++','-O3','-std=c++17','-I',s/'include',r/'compare.cpp','-ldl','-o',driver)
    for f in ('fetch.py','libmvec.py','libmvec.json'):shutil.copy2(r/f,t/f)
    for f in ('fetch.py','libmvec.py'):run(f,'python3','-B',t/f)
    cases={}
    for n,v in m['inputs'].items():
        f=t/('libmvec.text'if n.startswith('libmvec')else'putty-0.85-'+str(v['bits'])+'.text');assert sha(f)==v['sha256']
        cases[n]=(f,str(v['bits']),v['address'])
    manifest=rd(r/'corpus-manifest.json')
    for n,arch in [('mips64el-ls','mips64el'),('arm64-ls','arm64')]:
        v,=[e for e in manifest['inputs']if e['name']==n];deb=t/(n+'.deb');run('download-'+n,'curl','-fsSL','--retry','3','--max-time','100',v['url'],'-o',deb);assert sha(deb)==v['package_sha256']
        raw=corpus.deb_binary(deb,v['command'],v.get('member'));body=corpus.elf_text(raw);f=t/(n+'.text');f.write_bytes(body);assert sha(f)==v['text_sha256'];deb.unlink()
        hdr=struct.unpack_from('<16sHHIQQQIHHHHHH',raw);secs=[struct.unpack_from('<IIQQQQIIQQ',raw,hdr[6]+i*hdr[11])for i in range(hdr[12])];sect,=[v for v in secs if v[5]==len(body)and raw[v[4]:v[4]+v[5]]==body]
        cases[n]=(f,arch,sect[3])
    put('inputs',{n:dict(hash=sha(f),arch=arch,ip=ip,bytes=f.stat().st_size)for n,(f,arch,ip) in cases.items()})
    verify={}
    for k in q:
        args=[driver,libs['base'],libs[k]];snapshot=verify[k]={}
        snapshot['options']=json.loads(get(*args,'options'))
        trials,valid=map(int,get(t/'guard',libs['base'],libs[k]).split())
        assert (trials,valid)==(2293830,1239462)
        snapshot['guard']={'trials':trials,'valid':valid}
        count,hits=map(int,get(t/'moves',libs['base'],libs[k]).split());assert count==5308416 and 0<hits<count
        snapshot['packed_moves']=dict(trials=count,accepted=hits)
        res=sp.run([t/'oracle',libs['base'],libs[k]],capture_output=True,text=True);(out/'oracle.log').write_text(res.stderr+res.stdout);res.check_returncode()
        cases_oracle,valid,before,after,new,fixed=map(int,res.stdout.split())
        assert cases_oracle==4*4*(4*256*256+256*256+7*256*16)
        snapshot['full_oracle']=dict(cases=cases_oracle,accepted=valid,baseline_mismatches=before,candidate_mismatches=after,new_mismatches=new,resolved=fixed)
        for n,(f,arch,ip) in cases.items():snapshot[n]=json.loads(get(*args,'verify',f,arch,str(ip)))
        put('verified',verify)
    if not darwin:os.sched_setaffinity(0,{min(os.sched_getaffinity(0))})
    launch=[]if darwin else['setarch',platform.machine(),'-R'];timings={}
    import random,math
    image=t/('timed.dylib' if darwin else 'timed.so')
    images={k:f.read_bytes()for k,f in libs.items()};maxlen=max(map(len,images.values()))
    if not darwin:
        # Every process maps the same pathname, inode, length and load base.
        loads={};spans={}
        for k,v in images.items():
            assert v[:6]==bytes((127,69,76,70,2,1))
            phoff=struct.unpack_from('<Q',v,32)[0];ent,num=struct.unpack_from('<HH',v,54)
            last=max((struct.unpack_from('<IIQQQQQQ',v,pos)[3],pos)for pos in range(phoff,phoff+ent*num,ent)if struct.unpack_from('<I',v,pos)[0]==1)[1]
            pva,psize=struct.unpack_from('<Q',v,last+16)[0],struct.unpack_from('<Q',v,last+40)[0]
            loads[k]=(last,pva,psize);spans[k]=(pva+psize+4095)//4096
        data={};pad={}
        for k,v in images.items():
            buf=bytearray(v+bytes(maxlen-len(v)));off,va,sz=loads[k]
            extra=(max(spans.values())-spans[k])*4096
            if extra:struct.pack_into('<Q',buf,off+40,sz+extra)
            data[k]=buf;pad[k]=extra
        put('load-spans',dict(pages=spans,extra_zero_fill=pad))
        image.write_bytes(data['base']);image.chmod(0o755)
    curr=None;addresses={};offsets={}
    def take(stage,args,reps):
        global curr
        src='base'if stage=='copy'else stage
        if src!=curr:
            if darwin:
                if image.is_symlink():image.unlink()
                image.symlink_to(libs[src])
            else:
                with image.open('r+b')as out_file:assert out_file.write(data[src])==maxlen
            curr=src
        vals=list(map(int,get(*launch,driver,image,'single',*args,str(reps)).split()))
        assert len(vals)==6 and min(vals[0:3])>0
        addresses.setdefault(src,set()).add(vals[4]);assert offsets.setdefault(src,vals[5])==vals[5]
        if not darwin:assert len(set.union(*addresses.values()))==1,addresses
        return vals[:4]
    for n,(f,arch,ip) in cases.items():
        for mode in (0,1,2):
            for api in ('time','iter'):
                key='/'.join((n,api,str(mode)));args=[f,arch,str(ip),api,str(mode)]
                t0=take('base',args,1);reps=max(1,math.ceil(35e6/t0[0]));cycles=[];keys=['base','copy',*q];rng=random.Random(key)
                for _ in range(17):
                    rng.shuffle(keys);obs=[(k,take(k,args,reps))for k in keys+keys[::-1]]
                    assert all(v[2:]==t0[2:]for k,v in obs)
                    cycles.append({k:[sum(o[i]for l,o in obs if k==l)for i in (0,1)]for k in keys})
                timings[key]=dict(cycles=cycles,reps=reps,records=t0[2],value=t0[3]);put('timings',timings)
        put('mappings',dict(sets={k:sorted(v)for k,v in addresses.items()},offsets=offsets,fixed=not darwin,inode=image.stat().st_ino if not darwin else None))
    put('complete',dict(source=q,panels=len(timings),compiler=get('gcc','--version'),cpu=get('sysctl','-n','machdep.cpu.brand_string')if darwin else get('lscpu')))
finally:
    size=sum(f.stat().st_size for f in t.rglob('*')if f.is_file()and not f.is_symlink());shutil.rmtree(t);put('cleanup',dict(removed=not t.exists(),bytes=size))
