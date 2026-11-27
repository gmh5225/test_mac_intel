from pathlib import Path
import hashlib,json,os,platform,shlex,shutil,subprocess as sp,tempfile
from fixtures import fixtures,sha
r=Path(__file__).resolve().parent;root=r.parent;src=root/'source';e=root/'evidence';e.mkdir(exist_ok=True)
rd=lambda f:json.loads(f.read_text());q=rd(r/'source.json');m=rd(r/'experiment.json');profile=os.environ['SCAN_PROFILE']
if os.name=='nt':
    from preprocess_win import verify
    verify(r)
    raise SystemExit(0)
if profile=='gcc':os.environ.update(CC='gcc',CXX='g++')
if profile in ('clang','clang14'):os.environ.update(CC='clang',CXX='clang++')
os.environ['ZERO_AR_DATE']='1'
def save(name,z):(e/(name+'.json')).write_text(json.dumps(z,indent=2)+'\n')
def get(*a):return sp.check_output(a,text=True).strip()
def run(*a):sp.run(a,check=True)
def git(*a):return get('git','-C',src,*a)
system=platform.system()
w=Path(tempfile.mkdtemp()).resolve()
profiles={};checks={};measured=system=='Linux' and profile=='clang'
try:
    assert git('rev-parse','HEAD')==q['base']['commit']
    inputs=list(fixtures(r,w,m));assert len(inputs)==6
    for config in (['product','standalone','shared-mixed']if measured else ['product','standalone']):
        project=w/config;project.mkdir();build=project/'build';multi=config!='standalone';expect='active' if measured and platform.machine()=='x86_64' and config=='product' else 'base'
        normal=(r/'CMakeLists.txt').read_text()
        prefix=normal[:normal.index('add_subdirectory')]
        targets=normal[normal.index('foreach(linkage static shared)'):].replace('    add_executable','    if(NOT TARGET capstone_\u0024{linkage})\n        continue()\n    endif()\n    add_executable',1)
        if config=='product':
            fragment=(r/'product.cmake').read_text();assert fragment.count('add_subdirectory(third_party/capstone)')==1
            fragment=fragment.replace('add_subdirectory(third_party/capstone)','add_subdirectory("\u0024{CAPSTONE_SOURCE}" capstone)')
            (project/'cmake').mkdir();shutil.copyfile(r/'compiler-options.inc',project/'cmake/NeverDCapstoneCompilerOptions.inc')
        else:fragment='add_subdirectory("\u0024{CAPSTONE_SOURCE}" capstone)\n'
        (project/'CMakeLists.txt').write_text(prefix+fragment+targets)
        shutil.copyfile(r/'probe.cpp',project/'probe.cpp');ident={};cc={};flagsets={};record={};exported={}
        flags=['-G','Ninja','-S',project,'-B',build,'-DCAPSTONE_SOURCE='+str(src),'-DCMAKE_BUILD_TYPE=Release','-DCMAKE_EXPORT_COMPILE_COMMANDS=ON','-DCAPSTONE_BUILD_MACOS_THIN=ON','-DCAPSTONE_ARCHITECTURE_DEFAULT=OFF','-DCAPSTONE_X86_SUPPORT=ON','-DCAPSTONE_BUILD_CSTEST=OFF','-DCAPSTONE_BUILD_CSTOOL=OFF','-DCAPSTONE_BUILD_STATIC_LIBS=ON','-DCAPSTONE_BUILD_SHARED_LIBS=ON']
        if multi:flags+=['-DCAPSTONE_'+isa+'_SUPPORT=ON' for isa in ('ARM','AARCH64','MIPS','PPC','RISCV')]
        for tag in ('base','candidate'):
            git('restore','--source=HEAD','--staged','--worktree','--','.')
            if tag!='base':
                buf=sp.check_output(['git','-C',root,'cat-file','blob','HEAD:portable-next/'+tag+'.patch']);assert sha(buf)==q[tag]['sha256']
                patch=w/'candidate.patch';patch.write_bytes(buf);git('apply','--index',patch)
            assert git('write-tree')==q[tag]['tree']
            run('cmake',*flags)
            names=['static']if config=='product'else['static','shared']
            run('cmake','--build',build,'--parallel','4','--target',*['probe_'+kind for kind in names])
            objs={str(f.relative_to(build)):sha(f.read_bytes()) for f in (build/'capstone').rglob('*.c.o')}
            built={str((build/path).resolve()):path for path in objs}
            rows={}
            for z in rd(build/'compile_commands.json'):
                if Path(z['file']).suffix!='.c':continue
                tokens=shlex.split(z['command'])
                output=z.get('output')or tokens[tokens.index('-o')+1]
                path=str((Path(z['directory'])/output).resolve())
                if path in built:rows[built[path]]=z['command']
            assert set(rows)==set(objs) and len(objs)>20 and any('RISCVMapping.c' in k for k in objs)==multi,(config,len(rows),len(objs),set(objs)-set(rows))
            selected={'cs.c.o','X86DisassemblerDecoder.c.o','X86RegisterFallback32.c.o'}
            flags_per={key:'X86_OPTIONAL_PUBLIC_RECORD' in cmd for key,cmd in rows.items()}
            assert all(v==(tag=='candidate' and expect=='active' and Path(k).name in selected)for k,v in flags_per.items()),(tag,config,flags_per)
            cc[tag]=len(objs);flagsets[tag]=sorted(k for k,v in flags_per.items()if v)
            dest=project/tag;dest.mkdir()
            for kind in names:shutil.copy2(build/('probe_'+kind),dest)
            for f in (build/'capstone').rglob('libcapstone*'):
                if f.is_file() and (f.name.startswith('libcapstone.so') or f.suffix in ('.dylib','.a')):shutil.copy2(f,dest/f.name)
            images={f.name:sha(f.read_bytes())for f in dest.iterdir()};assert 'libcapstone.a' in images
            if 'shared' in names:
                assert Path(get(dest/'probe_shared','--library')).resolve().parent==dest
            assert Path(get(dest/'probe_static','--library')).resolve()==dest/'probe_static'
            ident[tag]=dict(objects=objs,images=images);rec={}
            for stem,bits,file,spans in inputs:
                for syntax,mode in [('intel',0),('intel',1),('intel',2),('att',1),('att',2)]:
                    for kind in names:
                        key='/'.join((kind,syntax,stem,str(mode)))
                        rec[key]=list(map(int,get(dest/('probe_'+kind),'public-att' if syntax=='att' else 'capstone',str(mode),'1',file,spans,str(bits)).split()))[2:]
            record[tag]=rec
            save(config+'-identities',ident)
        old,new=ident['base'],ident['candidate']
        assert old['objects'].keys()==new['objects'].keys()
        changed=sorted(Path(k).name for k,v in old['objects'].items() if new['objects'][k]!=v)
        change_set=set(changed)
        assert change_set==(selected if expect=='active' else set()),(expect,config,change_set)
        assert old['images'].keys()==new['images'].keys()
        if not change_set:
            assert old['images']==new['images'],config
        else:
            assert old['images']['libcapstone.a']!=new['images']['libcapstone.a']
            normalized={}
            for tag in ('base','candidate'):
                exe=project/tag/'probe_static'
                assert 'X86_disasmIterText' not in get('nm',exe)
                out=project/(tag+'.stripped')
                run('objcopy','--strip-all','--remove-section=.note.gnu.build-id',exe,out)
                normalized[tag]=sha(out.read_bytes())
            save('ordinary-executable',normalized)
            assert normalized['base']==normalized['candidate'],normalized
        assert all(rec==record['base']for rec in record.values())
        profiles[config]=dict(expected=expect,object_counts=cc,flags=flagsets,records=len(record['candidate']),identities=ident)
        checks[config]=record['base'];save('checks',checks);save('profiles',profiles)
        shutil.rmtree(project)
    save('complete',dict(complete=True,source=q,profile=profile,host=system,machine=platform.machine(),measured=measured,configs=list(profiles),checks={k:len(v)for k,v in checks.items()}))
finally:
    size=sum(f.stat().st_size for f in w.rglob('*')if f.is_file()and not f.is_symlink());shutil.rmtree(w);save('cleanup',dict(removed=not w.exists(),bytes=size))
