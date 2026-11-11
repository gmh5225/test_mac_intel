from pathlib import Path
import difflib,hashlib,json,os,platform,shutil,subprocess as sp,sys,tempfile
d=Path(__file__).resolve().parent;e=Path('capstone-evidence').resolve();e.mkdir(exist_ok=True)
def run(args,cwd,env=None):
    sp.run([str(a) for a in args],cwd=cwd,env=env,check=True)
def write(name,data):
    (e/(name+'.json')).write_text(json.dumps(data,indent=2,sort_keys=True)+'\n')
def sha(b):return hashlib.sha256(b).hexdigest()
def short_diff(f1,f2,tool):
    def dump(a):
        out=sp.check_output([tool,'-dr',a],stderr=sp.DEVNULL).decode('utf-8','replace').splitlines()
        return out[2:]
    a,b=dump(f1),dump(f2);return '\n'.join(line for i,line in zip(range(500),difflib.unified_diff(a,b,n=2)))
def main(tmp,flavor):
    win=os.name=='nt';src=tmp/'capstone';build=tmp/'build';base='f2f50b8fab856b374daf0e76dc3054f25de65ac9'
    src.mkdir();run(['git','init','-q'],src);run(['git','config','core.autocrlf','false'],src);run(['git','remote','add','origin','https://github.com/NeverSight/capstone.git'],src);run(['git','fetch','-q','--depth=1','origin',base],src);run(['git','checkout','-q','--detach','FETCH_HEAD'],src)
    args=['cmake','-S',src,'-B',build,'-DCMAKE_BUILD_TYPE=Release','-DCAPSTONE_BUILD_CSTOOL=OFF','-DCAPSTONE_BUILD_LEGACY_TESTS=OFF']
    env=dict(os.environ);env.pop('CFLAGS',None)
    if win:
        env['CL']='/Brepro';args+=['-G','Visual Studio 17 2022','-A','x64','-T','host=x64','-DCAPSTONE_BUILD_STATIC_MSVC_RUNTIME='+('ON' if flavor=='MT' else 'OFF')]
    else:
        env['CC']=flavor;env['CXX']='g++' if flavor=='gcc' else 'clang++'
        args+=['-G','Ninja','-DCAPSTONE_BUILD_MACOS_THIN=ON']
    plan=sys.argv[2]
    if plan!='all':
        archs=['X86','ARM','AARCH64','MIPS'] if plan=='four' else ['X86']
        args+=['-DCAPSTONE_ARCHITECTURE_DEFAULT=OFF',*['-DCAPSTONE_'+k+'_SUPPORT=ON' for k in archs]]
    if plan=='disabled':args+=['-DCAPSTONE_MSVC_NATIVE_DECODER=OFF']
    if plan=='diet':args+=['-DCAPSTONE_BUILD_DIET=ON']
    if plan=='reduced':args+=['-DCAPSTONE_X86_REDUCE=ON']
    hashes={};ref=tmp/'reference';ref.mkdir()
    for kind in ('reference','candidate'):
        name=('explicit.patch' if plan=='active' else None) if kind=='reference' else 'scoped.patch'
        if name:
            patch=d/name
            assert sha(patch.read_bytes())==(d/(name+'.sha256')).read_text().strip()
            run(['git','apply','--check',patch],src);run(['git','apply','--whitespace=nowarn',patch],src)
        applied=args+(['-DCAPSTONE_MSVC_NATIVE_DECODER=ON'] if kind=='reference' and plan=='active' else [])
        run(applied,tmp,env);run(['cmake','--build',build,'--config','Release','--target','capstone_static','--parallel',('2' if win else '4')],tmp,env)
        objdir=build/('capstone.dir/Release' if win else 'CMakeFiles/capstone.dir')
        objs={str(f.relative_to(objdir)):f for f in objdir.rglob('*.obj' if win else '*.o')}
        assert len(objs)>(80 if plan=='all' else 12), (len(objs),objdir)
        hashes[kind]={key:sha(a.read_bytes()) for key,a in objs.items()}
        if kind=='reference':
            for key,a in objs.items():
                dst=ref/key;dst.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(a,dst)
            run(['git','reset','--hard','-q',base],src);run(['git','clean','-fdq'],src);shutil.rmtree(build)
    write('objects',hashes);assert hashes['reference'].keys()==hashes['candidate'].keys()
    differing=[k for k,v in hashes['candidate'].items() if v!=hashes['reference'][k]]
    write('comparison',dict(plan=plan,flavor=flavor,objects=len(objs),changed=differing,reference=base,host=platform.platform()))
    tool=(shutil.which('llvm-objdump') or shutil.which('objdump') or (str(Path(os.environ['ProgramFiles'])/'LLVM/bin/llvm-objdump.exe') if win else None))
    for i,k in enumerate(differing[:12]):
        if tool:
            try:(e/('difference-'+str(i)+'.txt')).write_text(k+'\n'+short_diff(ref/k,objs[k],tool))
            except (OSError,sp.CalledProcessError):pass
    print('Objects',len(objs),'differing',differing,flush=True)
    return not differing
with tempfile.TemporaryDirectory(dir=os.environ.get('RUNNER_TEMP')) as tmp:
    root=Path(tmp)
    try:ok=main(root,sys.argv[1])
    finally:size=sum(f.stat().st_size for f in root.rglob('*') if f.is_file())
write('cleanup',dict(removed=not root.exists(),bytes=size))
sys.exit(0 if ok else 1)
