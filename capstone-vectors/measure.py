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
    from training import fetch,holdouts
    heldout=fetch(r,w);save('foreign-corpus',heldout)
    images={};objects={}
    run('clang++','-std=c++17','-O3','-I',base/'include','-c',r/'foreign.cpp','-o',w/'foreign.o')

    for label in ('base','candidate'):
        if label=='candidate':
            assert sha(r/'candidate.patch')==q['sha256']
            run('git','-C',base,'apply','--index',r/'candidate.patch');assert get('git','-C',base,'write-tree').strip()==q['tree']
        run('cmake','--build',build,'--target','capstone_static','--parallel','4')
        objects[label]={f.name:sha(f)for f in build.rglob('*.c.o')}
        run('clang++','-no-pie',w/'foreign.o',lib,'-o',w/label)
        images[label]=dict(archive=sha(lib),exe=sha(w/label))
        run('clang','-shared','-Wl,--whole-archive',lib,'-Wl,--no-whole-archive','-lm','-o',w/(label+'.library'))
        if label=='candidate':
            affected=sorted(k for k,h in objects[label].items() if h!=objects['base'].get(k))
            assert affected==['MCInstStorage.c.o','cs.c.o'] and set(objects['base'])<=set(objects[label]),affected
            save('affected',dict(count=len(objects[label]),changed=affected))
    run('clang++','-std=c++17','-O2','-I',base/'include',r/'states.cpp',*(['-ldl']if sys.platform!='darwin' else []),'-o',w/'states')
    v=sp.run([w/'states',w/'base.library',w/'candidate.library','2048'],capture_output=True,text=True)
    if v.returncode:print(v.stderr[-3000:],flush=True)
    v.check_returncode();save('states',dict(stdout=v.stdout,iterations=2048,settings=v.stderr.count('case arch=')))

    assert images['base']['exe']!=images['candidate']['exe']
    shutil.copy2(w/'base',w/'duplicate');assert sha(w/'duplicate')==images['base']['exe']
    cpu=(get('sysctl','-n','machdep.cpu.brand_string').strip() if sys.platform=='darwin' else get('lscpu'))
    from elftools.elf.elffile import ELFFile
    sections={}
    for name in ('base','candidate'):
        with (w/name).open('rb')as stream:
            elf=ELFFile(stream)
            sections[name]={s.name:dict(address=s['sh_addr'],size=s['sh_size'],sha256=hashlib.sha256(s.data()).hexdigest()) for s in elf.iter_sections() if s['sh_flags'] & 4 and s['sh_size']}
    save('code-sections',sections)
    launch=w/'timed';shutil.copyfile(w/'base',launch);launch.chmod(0o755)
    contents={k:(w/k).read_bytes()for k in ('base','candidate')}
    page=4096;current='base';inode=launch.stat().st_ino
    changed=[start for start in range(0,max(map(len,contents.values())),page) if contents['base'][start:start+page]!=contents['candidate'][start:start+page]]
    def select_image(label):
        global current
        next_image='candidate' if label=='candidate'else'base'
        if current!=next_image:
            payload=contents[next_image]
            with launch.open('r+b')as f:
                for start in changed:
                    if start<len(payload):
                        f.seek(start);f.write(payload[start:start+page])
                f.truncate(len(payload))
            current=next_image
        return launch
    for label in ('candidate','base','duplicate'):
        image=select_image(label)
        assert image.stat().st_ino==inode and sha(image)==images['candidate'if label=='candidate'else'base']['exe']
    save('fixed-image',dict(inode=inode,changed_blocks=len(changed),page=page,images=images))
    host=dict(cpu=cpu,neverd=dev,compiler=get('clang','--version').splitlines()[0],os=platform.platform())
    rows={}
    for row in heldout:
        for mode in range(3):
            def take(label,n):
                return list(map(int,get(select_image(label),row['arch'],w/(row['name']+'.text'),str(mode),str(n)).split()))
            labels=['base','candidate','duplicate']
            n=max(1,math.ceil(30e6/max(take('base',1)[0],1)))
            expected=take('base',n)[2:];assert expected[0]>0
            rng=random.Random(row['name']+'/mixed-fixed/'+str(mode));cycles=[]
            for _ in range(35):
                rng.shuffle(labels);pair={k:[] for k in labels}
                for k in labels+labels[::-1]:
                    got=take(k,n);assert got[2:]==expected
                    pair[k].append(got[:2])
                cycles.append({k:[sum(t[j]for t in ts)for j in (0,1)]for k,ts in pair.items()})
            rows[row['name']+'/'+str(mode)]=dict(checks=expected,repeats=n,cycles=cycles)
            save('foreign-observations',rows)
    assert len(rows)==15
    save('complete',dict(complete=True,source=q,host=host,images=images,pairs=35))
finally:
    n=sum(f.stat().st_size for f in w.rglob('*') if f.is_file() and not f.is_symlink());shutil.rmtree(w);save('cleanup',dict(removed=not w.exists(),bytes=n))
