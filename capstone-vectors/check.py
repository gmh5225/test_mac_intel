"""Compare actual x86-64 public-client link selection and every observable result with two ELF linkers."""
from pathlib import Path
import hashlib,json,os,shutil,subprocess as sp,tempfile
from fixtures import fixtures
r=Path(__file__).resolve().parent;root=r.parent;s=root/'source';nd=root/'neverd-config';e=root/'evidence';e.mkdir(exist_ok=True)
def rd(p):return json.loads(p.read_bytes())
def save(k,v):(e/(k+'.json')).write_text(json.dumps(v,indent=2)+'\n')
def run(*a):sp.run(a,check=True)
def get(*a):return sp.check_output(a,text=True).strip()
digest=lambda x:hashlib.sha256(x).hexdigest()
m=rd(r/'experiment.json');q=rd(r/'source.json');linker='bfd' if os.environ['LD_REPLICA']=='1' else 'lld'
w=Path(tempfile.mkdtemp());proj=w/'project';build=w/'build';elf={};records={}
try:
    assert get('git','-C',nd,'rev-parse','HEAD')==m['neverd'] and get('git','-C',s,'rev-parse','HEAD')==q['base']['commit']
    samples=list(fixtures(r,w,m));assert len(samples)==6
    (proj/'third_party').mkdir(parents=True);(proj/'third_party/capstone').symlink_to(s);(proj/'cmake').mkdir()
    cm='cmake/NeverDCapstoneCompilerOptions.inc';shutil.copyfile(nd/cm,proj/cm)
    project=(nd/'CMakeLists.txt').read_text()
    (proj/'CMakeLists.txt').write_text('cmake_minimum_required(VERSION 3.22)\nproject(RecordBindings LANGUAGES C CXX)\n'+project[project.index('# --- Capstone (our fork'):project.index('# --- NeverD CMake helpers')])
    run('cmake','-S',proj,'-B',build,'-G','Ninja','-DCMAKE_BUILD_TYPE=Release','-DCMAKE_C_COMPILER=clang','-DCMAKE_CXX_COMPILER=clang++','-DCMAKE_EXPORT_COMPILE_COMMANDS=ON')
    for kind in ('guard','compare','real'):
        run('clang++','-std=c++17','-O2','-include','cinttypes','-I',s/'include',r/(kind+'.cpp'),'-ldl','-o',w/kind)
    for tag,key in [('base','base'),('candidate','prefix'),('outlined','outlined')]:
        run('git','-C',s,'restore','--source=HEAD','--staged','--worktree','--','.')
        if tag!='base':
            patch=r/(tag+'.patch');assert digest(patch.read_bytes())==q[key]['sha256']
            run('git','-C',s,'apply','--index',patch)
        assert get('git','-C',s,'write-tree')==q[key]['tree']
        run('cmake','--build',build,'--target','capstone_static','--parallel','4')
        lib,=build.rglob('libcapstone.a')
        for route in ('ordinary','linked','core_first'):
            extra=['-DREQUEST_NATIVE']if route=='linked' else []
            objs=[]
            if route=='core_first':
                core=w/'core.o';core.write_bytes(sp.check_output(['ar','p',lib,'cs.c.o']));objs=[core]
            kinds={}
            for kind in ('so','exe'):
                binary=w/(tag+'-'+route+'.'+kind);opts=['-fPIC','-shared'] if kind=='so' else ['-DTEST_MAIN','-no-pie']
                mapping=w/'link.map'
                run('clang','-O2','-I',s,'-I',s/'include',*opts,*extra,'-fuse-ld='+linker,r/'adapter.c',*objs,lib,'-Wl,-Map='+str(mapping),'-o',binary)
                if kind=='exe':run(binary)
                syms={}
                for line in get('readelf','-sW',binary).splitlines():
                    v=line.split()
                    if len(v)==8 and v[3]=='FUNC' and v[6]!='UND' and v[7] in ('cs_decode_full_insn','X86_decodePublicRecord','X86_disasmIterText','cs_disasm_iter'):syms[v[7]]=[int(v[1],16),v[4],v[5]]
                assert 'cs_disasm_iter' in syms and 'cs_decode_full_insn' in syms
                native='X86_disasmIterText' in syms
                if route=='linked':assert native
                if tag=='base':assert 'X86_decodePublicRecord' not in syms
                else:assert (syms['cs_decode_full_insn'][0]!=syms['X86_decodePublicRecord'][0])==native
                kinds[kind]=dict(native=native,symbols=syms,sha256=digest(binary.read_bytes()))
            elf[tag+'/'+route]=kinds;save('binding',elf)
            if tag=='base':continue
            baseline=w/('base-'+route+'.so');current=w/(tag+'-'+route+'.so')
            guard=list(map(int,get(w/'guard',baseline,current).split()))
            assert guard==[5105184,2971712],guard
            opts=json.loads(get(w/'compare',baseline,current,'options'))
            real={name:[list(map(int,get(w/'real',baseline,current,f,spans,str(bits),str(slot)).split()))for slot in range(4,8)]for name,bits,f,spans in samples}
            for name,z in real.items():assert all(x[:4]==z[0][:4] for x in z) and z[0][0]>0
            records[tag+'/'+route]=dict(guard=guard,options=opts,programs=real);save('records',records)
    assert len(records)==6 and len({json.dumps(v,sort_keys=True) for v in records.values()})==1
    save('complete',dict(complete=True,source=q,linker=linker,compiler=get('clang','--version').splitlines()[0],link_version=get('clang','-fuse-ld='+linker,'-Wl,--version','-x','c','/dev/null','-o',w/'link-version').splitlines()[0]))
finally:
    used=sum(x.stat().st_size for x in w.rglob('*')if x.is_file() and not x.is_symlink());shutil.rmtree(w);save('cleanup',dict(removed=not w.exists(),bytes=used))
