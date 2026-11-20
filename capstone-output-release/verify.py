from pathlib import Path
import hashlib, json, os, shutil, subprocess as sp, tempfile
r=Path(__file__).resolve().parent;out=r.parent/'evidence';out.mkdir()
meta=json.loads((r/'lineage.json').read_text());cc=os.environ['TOOLCHAIN'];profile=os.environ['PROFILE'];arch=os.environ['BUILD_ARCHS']
def save(name,d):(out/(name+'.json')).write_text(json.dumps(d,indent=2)+'\n')
def run(args,name,cwd=None):
    with (out/(name+'.log')).open('wb') as f:
        rc=sp.run(list(map(str,args)),cwd=cwd,stdout=f,stderr=sp.STDOUT).returncode
    if rc:raise RuntimeError((name,(out/(name+'.log')).read_text(errors='replace')[-2400:]))
def git(d,*args):return sp.check_output(['git','-C',d,*args],text=True).strip()
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def remove_readonly(fn,path,exc):os.chmod(path,0o700);fn(path)
w=Path(tempfile.mkdtemp(prefix='capstone-public-profiles-'));s=w/'source';b=w/'build'
try:
    run(['git','clone','--quiet','--shared','--no-checkout','--config','core.autocrlf=false',r.parent/'source',s],'clone')
    git(s,'checkout','--quiet','--detach',meta['bounds']['parent'])
    opts=['-DCMAKE_BUILD_TYPE=Release','-DCAPSTONE_BUILD_MACOS_THIN=ON','-DCAPSTONE_BUILD_CSTEST=ON','-DCAPSTONE_BUILD_CSTOOL=OFF','-DCAPSTONE_BUILD_LEGACY_TESTS=OFF']
    if arch!='all':
        opts+=['-DCAPSTONE_ARCHITECTURE_DEFAULT=OFF']+['-DCAPSTONE_'+a+'_SUPPORT=ON' for a in {'four':('X86','ARM','AARCH64','MIPS'),'x86':('X86',),'arm':('ARM',)}[arch]]
    if os.name=='nt':opts+=['-G','Ninja','-DCMAKE_C_COMPILER=cl','-DCMAKE_CXX_COMPILER=cl','-DCAPSTONE_BUILD_STATIC_MSVC_RUNTIME='+('ON' if cc=='MT' else 'OFF')]
    else:
        opts+=['-G','Ninja','-DCMAKE_C_COMPILER='+cc]
        if cc=='gcc':opts+=['-DCMAKE_C_FLAGS=-Wno-error=discarded-qualifiers']
    if profile=='sanitize':
        opts+=['-DENABLE_ASAN=ON','-DCMAKE_C_FLAGS=-fsanitize=undefined','-DCMAKE_EXE_LINKER_FLAGS=-fsanitize=undefined']
        os.environ['UBSAN_OPTIONS']='halt_on_error=1:print_stacktrace=1'
    if profile=='reduce':opts+=['-DCAPSTONE_X86_REDUCE=ON']
    if profile=='diet':opts+=['-DCAPSTONE_BUILD_DIET=ON']
    run(['cmake','-S',s,'-B',b,*opts],'configure')
    checks={}
    for phase in ['bounds','iterator']:
        patch=w/(phase+'.patch');patch.write_bytes(sp.check_output(['git','-C',r.parent,'show','HEAD:capstone-output-release/'+patch.name]));assert sha(patch)==meta[phase]['sha256']
        git(s,'apply','--index',str(patch)); assert git(s,'write-tree')==meta[phase]['tree']
        registry=json.loads(sp.check_output(['ctest','--test-dir',b,'-C','Release','--show-only=json-v1'],text=True))
        registered={t['name'] for t in registry['tests']}
        wanted=['mcinst','api','mapping','instruction_bytes','text_option','detail_option','x86_buffer_bounds','x86_x87_environment_hardware','arm_private_stream','arm_post_index']
        if profile not in ('diet','reduce'):wanted+=['x86_simple_output','x86_printer_prechecked']
        targets=[name for name in wanted if 'unit_'+name in registered]
        assert 'mcinst' in targets
        run(['cmake','--build',b,'--config','Release','--target','capstone_static',*targets,'--parallel','1'],phase+'-build')
        run(['ctest','--test-dir',b,'-C','Release','--no-tests=error','--output-on-failure','-R','^unit_('+'|'.join(targets)+')$','-j3'],phase+'-tests')
        checks[phase]=targets
    if 'x86_simple_output' in checks['iterator']:
        unit=s/'tests/unit/x86_simple_output.c';old=unit.read_text()
        choose='(side ? cs_disasm_iter : X86_disasmIter)';assert old.count(choose)==1
        libs=[p for p in b.rglob('*') if p.name in ('libcapstone.a','capstone.lib') and p.is_file()]
        assert len(libs)==1,libs
        before=sha(libs[0]);unit.write_text(old.replace(choose,'cs_disasm_iter'))
        run(['cmake','--build',b,'--config','Release','--target','x86_simple_output','--parallel','1'],'public-only-build')
        assert before==sha(libs[0]);run(['ctest','--test-dir',b,'-C','Release','--no-tests=error','--output-on-failure','-R','^unit_x86_simple_output$'],'public-only-tests')
        checks['public_only_against_custom_mnemonic_fallback']=before
    save('complete',dict(toolchain=cc,profile=profile,architectures=arch,checks=checks,source=meta,configure=opts))
finally:
    n=sum(p.stat().st_size for p in w.rglob('*') if p.is_file());shutil.rmtree(w,onerror=remove_readonly);save('cleanup',dict(bytes=n,removed=not w.exists()))
