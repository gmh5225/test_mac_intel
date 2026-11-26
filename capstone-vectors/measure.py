from pathlib import Path
import shlex
import hashlib,itertools,json,math,os,random,shutil,subprocess as sp,sys,tempfile
r=Path(__file__).resolve().parent
p=r.parent;e=p/'evidence';e.mkdir(exist_ok=True)
src=p/'source';ice=p/'iced-source'
read=lambda f:json.loads(f.read_text())
def sha(f):return hashlib.sha256(f.read_bytes()).hexdigest()
def run(*a,**kw):sp.run(a,check=True,**kw)
def get(*a,**kw):return sp.check_output(a,text=True,**kw)
def save(name,data):
    f=e/(name+'.json');t=f.with_suffix('.tmp');t.write_text(json.dumps(data,indent=2)+'\n');t.replace(f)
def once(s,a,b):
    assert s.count(a)==1
    return s.replace(a,b)
m=read(r/'experiment.json');q=read(r/'source.json')
assert get('git','-C',src,'rev-parse','HEAD').strip()==q['base']['commit']
assert get('git','-C',ice,'rev-parse','HEAD').strip()==m['iced_revision']
assert sha(r/'candidate.patch')==q['candidate']['sha256']
assert all(sha(r/f)==h for f,h in m['drivers'].items())
w=Path(tempfile.mkdtemp());build=w/'build';ad=w/'adapter';selected=w/'lib';selected.mkdir();ad.mkdir()
try:
    flags=['-DCAPSTONE_'+arch+'_SUPPORT=ON' for arch in ('ARM','AARCH64','MIPS','PPC','X86','RISCV')]
    flags+=['-DCAPSTONE_ARCHITECTURE_DEFAULT=OFF','-DCAPSTONE_BUILD_CSTEST=OFF','-DCAPSTONE_BUILD_CSTOOL=OFF','-DCAPSTONE_BUILD_STATIC_LIBS=OFF','-DCAPSTONE_BUILD_SHARED_LIBS=ON','-DCMAKE_BUILD_TYPE=Release','-DCMAKE_EXPORT_COMPILE_COMMANDS=ON']
    images={};sources={};copies={};sizes={};symbols={};objects={}
    project=w/'static-project';static_build=w/'static-build';(project/'third_party').mkdir(parents=True)
    (project/'third_party/capstone').symlink_to(src);(project/'cmake').mkdir()
    nd=p/'neverd-config';assert get('git','-C',nd,'rev-parse','HEAD').strip()==m['neverd']
    cm='cmake/NeverDCapstoneCompilerOptions.inc';(project/cm).write_bytes(sp.check_output(['git','-C',nd,'show',m['neverd']+':'+cm]))
    top=get('git','-C',nd,'show',m['neverd']+':CMakeLists.txt')
    (project/'CMakeLists.txt').write_text('cmake_minimum_required(VERSION 3.22)\nproject(StaticDecode LANGUAGES C CXX)\n'+top[top.index('# --- Capstone (our fork'):top.index('# --- NeverD CMake helpers')])
    static_images={}
    for stage in ('base','candidate'):
        if stage=='candidate':run('git','-C',src,'apply','--index',r/'candidate.patch')
        assert get('git','-C',src,'write-tree').strip()==q[stage]['tree']
        run('cmake','-G','Ninja','-S',src,'-B',build,*flags)
        run('cmake','--build',build,'--target','capstone_shared','--parallel','4')
        so=(build/'libcapstone.so').resolve()
        assert any('CAPSTONE_SHARED_X86_READERS' in x['command']for x in read(build/'compile_commands.json'))==(stage=='candidate')
        dll=w/(stage+'.so');shutil.copyfile(so,dll);images[stage]=dll.read_bytes();sources[stage]=sha(dll);sizes[stage]=len(images[stage])
        syms=get('nm','-D','--defined-only','--format=posix',dll).splitlines()
        symbols[stage]=sorted(row.split()[0] for row in syms)
        objects[stage]={str(f.relative_to(build)):sha(f) for f in build.rglob('*.c.o')}
        public,=build.rglob('X86DisassemblerDecoder.c.o')
        if stage=='base':
            original_public=public.read_bytes()
        else:
            full_public=public.read_bytes()
            assert full_public!=original_public
            changed=[k for k,v in objects['base'].items()if objects['candidate'][k]!=v]
            assert changed==[str(public.relative_to(build))],changed
            from elftools.elf.elffile import ELFFile
            import io
            def section_digests(image):
                return {sec.name:hashlib.sha256(sec.data()).hexdigest() for sec in ELFFile(io.BytesIO(image)).iter_sections() if sec['sh_flags']&4}
            base_text=section_digests(original_public);candidate_text=section_digests(full_public)
            save('public-text',dict(original=base_text,candidate=candidate_text,same=base_text==candidate_text,original_object=hashlib.sha256(original_public).hexdigest(),candidate_object=sha(public)))
            commands=get('ninja','-C',build,'-t','commands',so.name).splitlines()
            links=[shlex.split(part.strip()) for line in commands for part in line.split('&&') if ' -shared ' in part]
            assert len(links)==1,links
            args=links[0];assert (build/args[args.index('-o')+1]).resolve()==so and str(public.relative_to(build)) in args
            save('link-arguments',dict(cwd=str(build),command=args))
            for which,blob in [('linked',original_public),('restore',full_public)]:
                public.write_bytes(blob);so.unlink()
                run(*args,cwd=build)
                assert public.read_bytes()==blob
                if which=='restore':assert so.read_bytes()==images['candidate']
                else:
                    link_image=w/'linked.so';shutil.copyfile(so,link_image)
                    images['linked']=link_image.read_bytes();sources['linked']=sha(link_image);sizes['linked']=len(images['linked'])
                    syms=get('nm','-D','--defined-only','--format=posix',link_image).splitlines()
                    assert sorted(row.split()[0]for row in syms)==symbols['base']
        if stage=='candidate':
            orig=m['framed_control'];unit=src/orig['unit'];new_unit=unit.read_bytes()
            assert sha(r/'framed.c')==orig['sha256']
            for label,raw in [('framed',(r/'framed.c').read_bytes()),('restore',new_unit)]:
                unit.write_bytes(raw);run('git','-C',src,'add','--',orig['unit'])
                want=orig['tree'] if label=='framed' else q['candidate']['tree']
                assert get('git','-C',src,'write-tree').strip()==want
                run('cmake','--build',build,'--target','capstone_shared','--parallel','4')
                if label=='restore':
                    assert so.read_bytes()==images['candidate']
                else:
                    clone=w/'framed.so';shutil.copyfile(so,clone)
                    images['framed']=clone.read_bytes();sources['framed']=sha(clone);sizes['framed']=len(images['framed'])
                    syms=get('nm','-D','--defined-only','--format=posix',clone).splitlines()
                    assert sorted(row.split()[0] for row in syms)==symbols['base']
        run('cmake','-G','Ninja','-S',project,'-B',static_build,'-DCMAKE_BUILD_TYPE=Release','-DCMAKE_EXPORT_COMPILE_COMMANDS=ON')
        run('cmake','--build',static_build,'--target','capstone_static','--parallel','4')
        static_lib,=static_build.rglob('libcapstone.a')
        static_images[stage]=dict(archive=sha(static_lib),objects={str(f.relative_to(static_build)):sha(f)for f in static_build.rglob('*.c.o')})
        assert len(static_images[stage]['objects'])>=60
        save('static-product',static_images)
    assert static_images['base']==static_images['candidate']
    delta=dict(added=sorted(set(symbols['candidate'])-set(symbols['base'])),removed=sorted(set(symbols['base'])-set(symbols['candidate'])))
    save('identities',dict(source=q,images=sources,sizes=sizes,symbols=delta,objects=objects))
    assert not delta['added'] and not delta['removed'] and sources['base']!=sources['candidate']
    # Generic full decoding and every non-x86 backend must have the original object code.
    same={k:(objects['base'][k]==objects['candidate'][k]) for k in objects['base'] if k.endswith('cs.c.o') or ('/arch/' in k and '/X86/' not in k)}
    assert any(k.endswith('/cs.c.o')for k in same) and len(same)>=20 and all(same.values()),same
    save('generic-objects',same)
    from elftools.elf.elffile import ELFFile
    with (w/'base.so').open('rb')as f:
        elf=ELFFile(f);soname=next(tag.soname for tag in elf.get_section_by_name('.dynamic').iter_tags() if tag.entry.d_tag=='DT_SONAME')
    maximum=max(sizes.values());images={k:v.ljust(maximum,b'\x00')for k,v in images.items()}
    images['copy']=images['base'];image=selected/soname;image.write_bytes(images['base']);inode=image.stat().st_ino
    spans=[]
    for i in range(0,maximum,4096):
        if len({img[i:i+4096]for img in images.values()})>1:
            if spans and spans[-1][1]==i:spans[-1][1]=min(i+4096,maximum)
            else:spans.append([i,min(i+4096,maximum)])
    previous=None;verified={}
    def select(stage):
        global previous
        if previous!=stage:
            with image.open('r+b',buffering=0)as f:
                for a,b in spans:
                    f.seek(a);assert f.write(memoryview(images[stage])[a:b])==b-a
            previous=stage
        assert image.stat().st_ino==inode
        if stage not in verified:
            verified[stage]=sha(image);assert verified[stage]==hashlib.sha256(images[stage]).hexdigest()
    select('base')
    inc=['-I',src,'-I',src/'include']
    for f in ('Cargo.lock','iced.rs'):shutil.copyfile(r/f,ad/f)
    (ad/'Cargo.toml').write_text((r/'Cargo.toml').read_text().replace('ICED_ROOT',str(ice)))
    run('cargo','build','--release','--locked',cwd=ad)
    ice_lib=ad/'target/release/libiced_compare.a'
    links=[w/'base.so','-Wl,-rpath,'+str(selected),'-ldl','-lpthread','-lm','-no-pie']
    run('clang++','-O3','-std=c++17',*inc,r/'driver.cpp',ice_lib,*links,'-o',w/'driver')
    run('clang++','-O3','-std=c++17',*inc,r/'foreign.cpp',*links,'-o',w/'foreign')
    run('clang++','-O2','-std=c++17',*inc,r/'vectors.cpp',*links,'-o',w/'vectors')
    for name in ('trial-compare','trial-real','public-guard','foreign-verify','trial-vector-guard','trial-states','trial-guard','cmov-guard'):
        run('clang++','-O2','-std=c++17',*inc,r/(name+'.cpp'),'-ldl','-o',w/name)
    for exe in ('driver','foreign','vectors'):
        assert str(image) in get('ldd',w/exe)
    os.sched_setaffinity(0,{min(os.sched_getaffinity(0))})
    invoke=['setarch',os.uname().machine,'-R']
    opts=json.loads(get(w/'trial-compare',w/'base.so',w/'candidate.so','options'))
    domain=list(map(int,get(w/'public-guard',w/'base.so',w/'candidate.so').split()))
    assert domain==[5105184,2971712]
    libs=(w/'base.so',w/'candidate.so')
    states=sp.run([w/'trial-states',*libs,'2048'],text=True,capture_output=True)
    states.check_returncode()
    assert states.stderr.count('case arch=')==464
    scan=list(map(int,get(w/'trial-guard',*libs).split()));assert scan==[2162688,999139]
    vector=json.loads(get(w/'trial-vector-guard',*libs))
    cmov=list(map(int,get(w/'cmov-guard',*libs).split()));assert cmov[0]>1000000 and 0<cmov[1]<cmov[0]
    save('options',dict(domain=domain,options=opts,scan=scan,vector=vector,cmov=cmov,random_state_configurations=464,random_per_state=2048))
    for f in ('frozen_deb.py','jpeg_archive.py','pe_panels.py','pdata.py','pe-images.json','inputs.json','libmvec.py','libmvec.json'):shutil.copyfile(r/f,w/f)
    inputs=read(w/'inputs.json');(w/'inputs.json').write_text(json.dumps({n:v for n,v in inputs.items()if n in m['samples']}))
    sys.path.insert(0,str(w));import pe_panels,frozen_deb
    run(sys.executable,'-B',w/'libmvec.py');raw=read(w/'libmvec.json')
    fixtures=list(itertools.chain([('libmvec-amd64',64,w/'libmvec.text',[(0,raw['bytes'],raw['address'])],raw)],pe_panels.prepare(w),frozen_deb.prepare(w)))
    assert {row[0]for row in fixtures}==set(m['samples'])
    host=dict(cpu=get('lscpu'),compiler=get('clang','--version').splitlines()[0],source=q,iced=m['iced_revision'],prebuilt=False)
    save('host',host);records={};timings={}
    def measure(key,engines,take):
        n=max(1,math.ceil(25e6/take('base',1)[0]));expected={k:take(k,n)[2:]for k in engines}
        assert expected['base']==expected['copy']==expected['candidate']==expected['linked']==expected['framed']
        if 'iced' in expected:assert all(v[:3]==expected['base'][:3]for v in expected.values())
        rng=random.Random('shared-library/'+key);blocks=[];order=list(engines)
        for _ in range(17):
            rng.shuffle(order);trial={k:[] for k in order}
            for k in order+order[::-1]:
                row=take(k,n);assert row[2:]==expected[k];trial[k].append(row[:2])
            blocks.append({k:[sum(t[i]for t in v)for i in (0,1)]for k,v in trial.items()})
        timings[key]=dict(reps=n,checks=expected,cycles=blocks)
        save('timings',timings)
    for name,bits,f,extents,_ in fixtures:
        spec=m['provenance'][name];assert sha(f)==spec['text_sha256']
        intervals=[x for x in extents if tuple(x)not in {tuple(j[:3])for j in spec['excluded_incompatible_extents']}]
        intervals_file=w/(name+'.tsv')
        def emit():intervals_file.write_text(''.join('%d %d %d\n'%tuple(x) for x in intervals))
        emit();select('base')
        if m['samples'][name]=='simd-functions':
            view=[list(map(int,line.split()))for line in get(w/'vectors',str(bits),f,intervals_file).splitlines()]
            assert len(view)==len(intervals);intervals=[x for x,j in zip(intervals,view)if j[1]>=8 and j[1]>=.15*j[0]];emit()
        assert sha(intervals_file)==spec['extent_sha256']
        audits=[]
        for stage in ('base','candidate'):
            select(stage)
            audit=[list(map(int,x.split()))for x in get(*invoke,w/'driver','audit','0','1',f,intervals_file,str(bits)).splitlines()]
            assert len(audit)==len(intervals) and all(x[3]==x[4] and x[1]==x[5]for x in audit)
            audits.append(audit)
        assert audits[0]==audits[1]
        records[name]=[list(map(int,get(w/'trial-real',w/'base.so',w/'candidate.so',f,intervals_file,str(bits),str(mode)).split()))for mode in (4,5,6,7)]
        linked_records=[list(map(int,get(w/'trial-real',w/'base.so',w/'linked.so',f,intervals_file,str(bits),str(mode)).split()))for mode in (4,5,6,7)]
        framed_records=[list(map(int,get(w/'trial-real',w/'base.so',w/'framed.so',f,intervals_file,str(bits),str(mode)).split()))for mode in (4,5,6,7)]
        assert framed_records==linked_records==records[name]
        save('records',records)
        for mode in (0,1,2):
            def take(k,n):
                other=k in ('iced','fast');select('base' if other else k)
                return list(map(int,get(*invoke,w/'driver',k if other else 'capstone',str(mode),str(n),f,intervals_file,str(bits)).split()))
            measure('intel/'+name+'/'+str(mode),['base','copy','linked','framed','candidate','iced']+(['fast']if mode else []),take)
        for mode in (1,2):
            def take(k,n):
                select(k);return list(map(int,get(*invoke,w/'driver','public-att',str(mode),str(n),f,intervals_file,str(bits)).split()))
            measure('att/'+name+'/'+str(mode),images,take)
    from training import fetch
    training_rows=fetch(r,w);save('foreign-corpus',training_rows)
    foreign_records={}
    for row in training_rows:
        if row['arch'] in ('i386','amd64'):continue
        for mode in (0,1,2):
            key=f"foreign/{row['name']}/{mode}"
            counts=list(map(int,get(w/'foreign-verify',w/'base.so',w/'candidate.so',row['arch'],w/(row['name']+'.text'),str(mode)).split()))
            assert len(counts)==2 and counts[0]>0
            foreign_records[key]=counts;save('foreign-records',foreign_records)
            def take(k,n):
                select(k);return list(map(int,get(*invoke,w/'foreign',row['arch'],w/(row['name']+'.text'),str(mode),str(n)).split()))
            measure('foreign/'+row['name']+'/'+str(mode),images,take)
    save('complete',dict(complete=True,source=q,host=host,workloads=len(timings),verified=verified,inode=inode,soname=soname,spans=spans,bytes=maximum))
finally:
    n=sum(f.stat().st_size for f in w.rglob('*') if f.is_file() and not f.is_symlink());shutil.rmtree(w);save('cleanup',dict(removed=not w.exists(),bytes=n))
