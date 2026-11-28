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
    assert get('git','-C',base,'rev-parse','HEAD').strip()==m['checkout_commit'] and get('git','-C',base,'write-tree').strip()==m['checkout_tree']
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
    files={Path(c['file']).name for c in rd(build/'compile_commands.json')};assert {'MipsMapping.c','AArch64Mapping.c','ARMMapping.c','X86Sse64Output.c'}<=files and 'X86PublicOutput.c' not in files
    ad.mkdir()
    for f in ('Cargo.lock','iced.rs'):shutil.copyfile(r/f,ad/f)
    (ad/'Cargo.toml').write_text((r/'Cargo.toml').read_text().replace('ICED_ROOT',str(ice)))
    run('cargo','build','--release','--locked',cwd=ad)
    ice_lib=ad/'target/release/libiced_compare.a'
    shutil.copyfile(r/'driver.cpp',w/'driver.cpp')
    flags=['-lpthread','-lm']+(['-framework','Security','-framework','CoreFoundation','-liconv']if sys.platform=='darwin'else['-ldl','-no-pie'])
    run('clang++','-O3','-DNDEBUG','-std=c++17','-I',base,'-I',base/'include','-c',w/'driver.cpp','-o',w/'driver.o')
    for f in ('frozen_deb.py','jpeg_archive.py','pe_panels.py','pdata.py','pe-images.json','inputs.json','vectors.cpp','libmvec.py','libmvec.json'):shutil.copyfile(r/f,w/f)
    from training import fetch
    foreign=fetch(r,w);assert len(foreign)==5;save('foreign-corpus',foreign)
    run('clang++','-O3','-std=c++17','-I',base/'include','-c',r/'foreign.cpp','-o',w/'foreign.o')
    ref=w/'native.c';ref.write_text('#include "arch/X86/X86ScanAdapter.h"\n__attribute__((used)) static __typeof__(&X86_disasmIterText) const keep = X86_disasmIterText;\n')
    run('clang','-O2','-I',base,'-I',base/'include','-c',ref,'-o',w/'ref.o')
    fix=rd(r/'fix.json');assert fix['parent']==q['commit'] and sha(r/'fix.patch')==fix['sha256']
    from elftools.elf.elffile import ELFFile
    images={};string_outputs=[];unit_results={}
    script=w/'access.ld'
    script.write_text('SECTIONS { .cs_bench_access ALIGN(64) : { KEEP(*(.bench_access_body)) . = 2048; } } INSERT AFTER .text;'+chr(10))
    link_option='-Wl,-T,'+str(script);controls={}
    def observe(path):
        with path.open('rb') as inp:
            elf=ELFFile(inp);tab=elf.get_section_by_name('.symtab')
            syms=sorted([x.name,x['st_value'],x['st_size']] for x in tab.iter_symbols() if x['st_info']['type']=='STT_FUNC' and x['st_size'])
            func,=[v for v in syms if v[0]=='X86_reg_access']
            peer=[v for v in syms if v!=func]
            sections={sec.name:[sec['sh_addr'],sec['sh_size'],hashlib.sha256(sec.data()).hexdigest()] for sec in elf.iter_sections() if sec['sh_flags']&2 and sec['sh_type']!='SHT_NOBITS'}
            assert func[1]==sections['.cs_bench_access'][0] and 0<func[2]<2048 and sections['.cs_bench_access'][1]==2048
            return dict(access=func,peer_count=len(peer),peers_sha256=hashlib.sha256(json.dumps(peer).encode()).hexdigest(),sections=sections)
    for tag in ('base','fixed'):
        if tag=='fixed':
            run('git','-C',base,'apply','--index',r/'fix.patch');assert get('git','-C',base,'write-tree').strip()==fix['tree']
            run(sys.executable,'-B',base/'suite/synctools/x86_mapping_counts.py','--check');run('cmake','--build',build,'--target','capstone_static','--parallel','4')
        run('clang','-O2','-I',base/'include',r/'access.c',lib,'-o',w/'string-insns')
        rows=sp.check_output([w/'string-insns'],input=(r/'cases.tsv').read_bytes()).splitlines()
        string_outputs.append([list(map(int,z.split())) for z in rows])
        run('clang','-O2','-I',base/'include',r/'reg-access-unit.c',lib,'-o',w/'new-unit')
        check=sp.run([w/'new-unit'],text=True,capture_output=True)
        assert (check.returncode==0)==(tag=='fixed') and (tag=='fixed' or 'MOVSB segment' in check.stderr),(tag,check)
        unit_results[tag]=dict(status=check.returncode,stderr=check.stderr)
        run('clang++',w/'driver.o',lib,ice_lib,*flags,'-o',w/('x86-'+tag))
        run('clang++',w/'foreign.o',w/'ref.o',lib,*flags,'-o',w/('foreign-'+tag))
        run('clang','-fPIC','-shared','-I',base/'include',r/'export.c','-Wl,--whole-archive',lib,'-Wl,--no-whole-archive','-o',w/(tag+'.so'))
        objs={str(p.relative_to(build)):sha(p)for p in build.rglob('*.c.o')};assert len(objs)>=60
        images[tag]=dict(x86=sha(w/('x86-'+tag)),foreign=sha(w/('foreign-'+tag)),archive=sha(lib),objects=objs)
        path=base/'arch/X86/X86Mapping.c';old_source=path.read_text()
        marker='void X86_reg_access(const cs_insn *insn';assert old_source.count(marker)==1
        path.write_text(old_source.replace(marker,'__attribute__((section(".bench_access_body")))'+chr(10)+marker))
        run('cmake','--build',build,'--target','capstone_static','--parallel','4')
        run('clang++',w/'driver.o',lib,ice_lib,*flags,link_option,'-o',w/('controlled-x86-'+tag))
        run('clang++',w/'foreign.o',w/'ref.o',lib,*flags,link_option,'-o',w/('controlled-foreign-'+tag))
        controls[tag]={kind:observe(w/('controlled-'+kind+'-'+tag)) for kind in ('x86','foreign')}
        save('controlled-layout',controls)
        for kind,z in controls[tag].items():
            before=controls['base'][kind];assert z['peers_sha256']==before['peers_sha256'] and z['access'][1]==before['access'][1]
            for n,section in z['sections'].items():
                if n.startswith(('.text','.cs_x86_','.cs_alias_')) or n in ('.init','.fini','.plt','.rodata'):
                    assert section==before['sections'][n],(kind,n)
            if tag=='fixed':assert z['sections']['.cs_bench_access'][2]!=before['sections']['.cs_bench_access'][2]
        rel=path.relative_to(base).as_posix()
        run('git','-C',base,'restore','--worktree','--',rel)
        assert get('git','-C',base,'hash-object',rel).strip()==get('git','-C',base,'rev-parse',':'+rel).strip()
        run('git','-C',base,'update-index','--refresh','--',rel)
        assert get('git','-C',base,'write-tree').strip()==(q if tag=='base' else fix)['tree']
        run('cmake','--build',build,'--target','capstone_static','--parallel','4')
        assert sha(lib)==images[tag]['archive']

    changed=[Path(k).name for k,v in images['base']['objects'].items()if images['fixed']['objects'][k]!=v]
    assert changed==['X86Mapping.c.o'],changed
    base_cases,fix_cases=string_outputs
    assert len(base_cases)==len(fix_cases)==14336
    assert all(a[:-1]==b[:-1] and b[-1]==0 for a,b in zip(base_cases,fix_cases))
    repeats=sum(row[-1] for row in base_cases);affected=sum(row[-1]!=0 for row in base_cases)
    assert repeats>=affected>0
    save('encodings',dict(encodings=3584,observations=len(base_cases),old_with_duplicates=affected,removed_duplicates=repeats,remaining_duplicates=0,unit=unit_results))
    save('linked',dict(images=images,changed=changed,source=fix,dev=dev,iced=m['iced_revision']))
    os.link(w/'x86-base',w/'runner')
    for route in ('public','fixed'):run('clang++','-O2','-std=c++17','-I',base/'include',r/('records-'+route+'.cpp'),'-ldl','-o',w/('records-'+route))
    run('clang++','-O2','-I',base/'include',w/'vectors.cpp',lib,'-o',w/'vectors')
    os.sched_setaffinity(0,{min(os.sched_getaffinity(0))})
    cases={}
    inputs=rd(w/'inputs.json');(w/'inputs.json').write_text(json.dumps({n:v for n,v in inputs.items()if n in m['samples']}))
    sys.path.insert(0,str(w));import pe_panels,frozen_deb
    run(sys.executable,'-B',w/'libmvec.py');raw=rd(w/'libmvec.json')
    fixtures=list(itertools.chain([('libmvec-amd64',64,w/'libmvec.text',[(0,raw['bytes'],raw['address'])],raw)],pe_panels.prepare(w),frozen_deb.prepare(w)))
    assert {row[0]for row in fixtures}==set(m["samples"])
    for name,bits,f,spans,_ in fixtures:
        spec=m['provenance'][name]
        assert sha(f)==spec['text_sha256']
        selected=[s for s in spans if tuple(s) not in {tuple(a[:3]) for a in spec['excluded_incompatible_extents']}]
        path=w/(name+'.tsv')
        def emit(v):path.write_text(''.join('%d %d %d\n'%tuple(a) for a in v))
        emit(selected)
        if m['samples'][name]=='simd-functions':
            view=[list(map(int,z.split())) for z in get(w/'vectors',str(bits),f,path).splitlines()]
            assert len(view)==len(selected)
            selected=[s for s,x in zip(selected,view)if x[1]>=8 and x[1]>=.15*x[0]];emit(selected)
        assert sha(path)==spec['extent_sha256']
        checks=[list(map(int,row.split()))for row in get(w/'runner','audit','0','1',f,path,str(bits)).splitlines()]
        assert len(checks)==len(selected) and all(z[3]==z[4] and z[1]==z[5] for z in checks)
        for mode in (0,1,2):
            cases[name+'/'+str(mode)]=(mode,f,path,str(bits))
    assert len(cases)==18
    from compare import run_programs
    run_programs(r,w,cases,foreign,save)
    save('complete',dict(complete=True,source=fix,neverd=dev,iced=m['iced_revision'],cpu=get('lscpu'),cases=list(cases)))
finally:
    n=sum(f.stat().st_size for f in w.rglob('*') if f.is_file() and not f.is_symlink());shutil.rmtree(w);save('cleanup',dict(removed=not w.exists(),bytes=n))
