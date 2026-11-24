from pathlib import Path
import hashlib,itertools,json,math,os,platform,random,shutil,statistics,subprocess as sp,sys,tempfile
r=Path(__file__).resolve().parent;p=r.parent
e=p/'evidence';e.mkdir(exist_ok=True);rd=lambda f:json.loads(f.read_text())
q=rd(r/'tree.json');m=rd(r/'experiment.json');dev=m['neverd'];base=p/'source';root=p/'neverd-config';ice=p/'iced-source'
def save(name,value):
    f=e/(name+'.json');temp=f.with_suffix('.tmp');temp.write_text(json.dumps(value,indent=2)+'\n');temp.replace(f)
def get(*args,**kwargs):return sp.check_output(args,text=True,**kwargs)
def run(*args,**kwargs):sp.run(args,check=True,**kwargs)
def sha(f):return hashlib.sha256(f.read_bytes()).hexdigest()
def interval(values):
    x=sorted(values);n=len(x)
    def rank(q):
        return next(k for k in range(1,n+1) if 40*sum(math.comb(n,i)*k**i*(n-k)**(n-i) for i in range(n//2+1,n+1))>=q*n**n)-1
    return [statistics.median(x),x[rank(1)],x[rank(39)]]
w=Path(tempfile.mkdtemp());project=w/'project';build=w/'build';ad=w/'adapter'
try:
    assert get('git','-C',base,'rev-parse','HEAD').strip()==q['parent'] and get('git','-C',base,'write-tree').strip()==m['checkout_tree']
    assert get('git','-C',root,'rev-parse','HEAD').strip()==dev
    assert get('git','-C',ice,'rev-parse','HEAD').strip()==m['iced_revision']
    assert all(sha(r/f)==v for f,v in m['drivers'].items())
    (project/'third_party').mkdir(parents=True);(project/'third_party/capstone').symlink_to(base)
    (project/'cmake').mkdir();cm='cmake/NeverDCapstoneCompilerOptions.inc'
    (project/cm).write_bytes(sp.check_output(['git','-C',root,'show',dev+':'+cm]))
    v=get('git','-C',root,'show',dev+':CMakeLists.txt')
    (project/'CMakeLists.txt').write_text('cmake_minimum_required(VERSION 3.22)\nproject(Layers LANGUAGES C CXX)\n'+v[v.index('# --- Capstone (our fork'):v.index('# --- NeverD CMake helpers')])
    run('cmake','-G','Ninja','-S',project,'-B',build,'-DCMAKE_BUILD_TYPE=Release','-DCAPSTONE_BUILD_MACOS_THIN=ON','-DCMAKE_EXPORT_COMPILE_COMMANDS=ON')
    run('cmake','--build',build,'--target','capstone_static','--parallel','4');lib,=build.rglob('libcapstone.a')
    files={Path(c['file']).name for c in rd(build/'compile_commands.json')};assert {'MipsMapping.c','AArch64Mapping.c','ARMMapping.c','X86Sse64Output.c','PPCMapping.c','RISCVMapping.c'}<=files and 'X86PublicOutput.c' not in files
    ad.mkdir()
    for f in ('Cargo.lock','iced.rs'):shutil.copyfile(r/f,ad/f)
    (ad/'Cargo.toml').write_text((r/'Cargo.toml').read_text().replace('ICED_ROOT',str(ice)))
    run('cargo','build','--release','--locked',cwd=ad)
    ice_lib=ad/'target/release/libiced_compare.a'
    shutil.copyfile(r/'driver.cpp',w/'driver.cpp')
    flags=['-lpthread','-lm']+(['-framework','Security','-framework','CoreFoundation','-liconv']if sys.platform=='darwin'else['-ldl','-no-pie'])
    run('clang++','-O3','-DNDEBUG','-std=c++17','-I',base,'-I',base/'include','-c',w/'driver.cpp','-o',w/'driver.o')
    assert sys.platform=='darwin'
    sources=rd(r/'input-sources.json')
    import struct,urllib.request,time
    from elftools.elf.elffile import ELFFile
    assert sha(r/'scalar.c')==sources['c_sha']
    run('clang',*sources['compile'],r/'scalar.c','-o',w/'scalar.o')
    with (w/'scalar.o').open('rb') as obj:
        elf=ELFFile(obj);assert elf['e_machine']=='EM_386';(w/'scalar16').write_bytes(elf.get_section_by_name('.text').data())
    sqlite=Path('/usr/bin/sqlite3')
    arches=get('lipo','-archs',sqlite).strip().split()
    if len(arches)>1:run('lipo',sqlite,'-thin','x86_64','-output',w/'sqlite.x64')
    else:assert arches==['x86_64'];shutil.copy2(sqlite,w/'sqlite.x64')
    mach=(w/'sqlite.x64').read_bytes();magic,cpu,_,filetype,ncmds,_,_,_=struct.unpack_from('<8I',mach)
    assert magic==0xfeedfacf and cpu==0x1000007 and filetype==2
    cursor=32;sections=[]
    for _ in range(ncmds):
        cmd,extent=struct.unpack_from('<II',mach,cursor)
        if cmd==0x19 and mach[cursor+8:cursor+24].rstrip(b'\x00')==b'__TEXT':
            for i in range(struct.unpack_from('<I',mach,cursor+64)[0]):
                offset=cursor+72+80*i
                if mach[offset:offset+16].rstrip(b'\x00')!=b'__text':continue
                addr,n,foff=struct.unpack_from('<QQI',mach,offset+32);assert foff+n<=len(mach);sections.append(mach[foff:foff+n])
        cursor+=extent
    assert len(sections)==1 and len(sections[0])>50000
    (w/'sqlite64').write_bytes(sections[0])
    put=sources['putty'];url=put['source']
    for i in range(3):
        try:
            with urllib.request.urlopen(url,timeout=60) as res:exe=res.read()
            break
        except OSError:
            if i==2:raise
            time.sleep(2**i)
    assert hashlib.sha256(exe).hexdigest()==put['executable_sha256']
    n=put['bytes'];foff=put['section_file_offset'];(w/'putty32').write_bytes(exe[foff:foff+n]);assert sha(w/'putty32')==put['sha256']
    images={}
    for label,tree in [('base',None),('candidate',q)]:
        if tree:
            assert sha(r/'candidate.patch')==q['sha256']
            run('git','-C',base,'apply','--index',r/'candidate.patch')
            assert get('git','-C',base,'write-tree').strip()==tree['tree']
        run('cmake','--build',build,'--target','capstone_static','--parallel','4')
        run('clang++',w/'driver.o',lib,ice_lib,*flags,'-o',w/label)
        images[label]=dict(archive=sha(lib),exe=sha(w/label))
    shutil.copy2(w/'base',w/'duplicate');assert sha(w/'duplicate')==images['base']['exe']!=images['candidate']['exe']
    audit={};results={}
    for name,bits in [('scalar16',16),('sqlite64',64),('putty32',32)]:
        f=w/name;size=f.stat().st_size;spans=w/(name+'.tsv');spans.write_text(f'0 {size} 1048576\n')
        def take(exe,n):return list(map(int,get(w/exe,'capstone','0',str(n),f,spans,str(bits)).split()))
        n=1
        while True:
            probe=take('base',n)
            if probe[0]>=4e6:break
            n*=max(2,min(50,math.ceil(4e6/max(probe[0],1))))
        n=max(1,math.ceil(55e6*n/probe[0]));expected=take('base',n)[2:];assert expected[0]>0
        lanes=['base','duplicate','candidate'];cycles=[];rng=random.Random('two-mac-scans/'+name)
        for _ in range(35):
            rng.shuffle(lanes);times={k:[0,0]for k in lanes}
            for k in lanes+lanes[::-1]:
                row=take(k,n);assert row[2:]==expected;times[k][0]+=row[0];times[k][1]+=row[1]
            cycles.append(times)
        audit[name]=dict(bytes=size,sha256=sha(f),source=sha(sqlite) if name=='sqlite64' else sources['c_sha'] if bits==16 else put['executable_sha256'],repeats=n,checks=expected)
        results[name]=cycles;save('observations',results);save('inputs',audit)
    save('complete',dict(complete=True,source=q,neverd=dev,arch=platform.machine(),images=images,inputs=audit,pairs=35))
finally:
    n=sum(f.stat().st_size for f in w.rglob('*') if f.is_file() and not f.is_symlink());shutil.rmtree(w);save('cleanup',dict(removed=not w.exists(),bytes=n))
