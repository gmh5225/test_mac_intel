from pathlib import Path
import hashlib,json,os,shutil,subprocess as sp,tempfile,time
r=Path(__file__).resolve().parent
out=r.parent/'evidence';out.mkdir()
meta=json.loads((r/'msvc-variants.json').read_text());label=os.environ['VARIANT']
w=Path(tempfile.mkdtemp(prefix='capstone-msvc-legacy-'));s=w/'src';b=w/'b'
def save(n,value):(out/(n+'.json')).write_text(json.dumps(value,indent=2)+'\n')
def run(args,n,required=True):
    start=time.monotonic()
    with (out/(n+'.log')).open('wb') as stream:
        rc=sp.run(list(map(str,args)),stdout=stream,stderr=sp.STDOUT).returncode
    timings[n]={'rc':rc,'seconds':time.monotonic()-start}
    if required and rc:raise RuntimeError((n,(out/(n+'.log')).read_text(errors='replace')[-2000:]))
    return rc
def git(*args):return sp.check_output(['git','-C',s,*args],text=True).strip()
def sha(path):
    with path.open('rb') as f:return hashlib.file_digest(f,'sha256').hexdigest()
def remove_readonly(fn,p,exc):os.chmod(p,0o700);fn(p)
timings={}
try:
    mem=sp.check_output(['powershell','-NoProfile','-Command','Get-CimInstance Win32_OperatingSystem | Select TotalVisibleMemorySize,FreePhysicalMemory,TotalVirtualMemorySize,FreeVirtualMemory | ConvertTo-Json'],text=True)
    save('memory-before',json.loads(mem))
    rcl=sp.run(['cl'],capture_output=True,text=True);(out/'compiler.txt').write_text(rcl.stderr+rcl.stdout)
    run(['git','clone','--quiet','--shared','--no-checkout','--config','core.autocrlf=false',r.parent/'source',s],'clone')
    git('checkout','-q','--detach',meta['bounds']['parent'])
    if label!='original':
        for name in ('bounds',label):
            patch=w/(name+'.patch');patch.write_bytes(sp.check_output(['git','-C',r.parent,'show','HEAD:capstone-output-release/'+name+'.patch']))
            assert sha(patch)==meta[name]['sha256'];git('apply','--index',str(patch));assert git('write-tree')==meta[name]['tree']
        run(['python','-B',s/'suite/synctools/x86_operand_specializations.py','--check'],'generator')
    save('source',dict(label=label,parent=git('rev-parse','HEAD'),tree=git('write-tree'),configuration='MSVC x64 native Ninja Release dynamic CRT, COMPILE_DEFINITIONS plus /O2 /Ob2, single compiler'))
    run(['cmake','-G','Ninja','-S',s,'-B',b,'-DCMAKE_BUILD_TYPE=Release','-DCMAKE_C_COMPILER=cl','-DCMAKE_CXX_COMPILER=cl','-DCAPSTONE_BUILD_STATIC_MSVC_RUNTIME=OFF','-DCAPSTONE_BUILD_CSTEST=ON','-DCAPSTONE_BUILD_CSTOOL=OFF','-DCAPSTONE_BUILD_LEGACY_TESTS=OFF','-DCAPSTONE_ARCHITECTURE_DEFAULT=OFF',*['-DCAPSTONE_'+a+'_SUPPORT=ON' for a in ('ARM','AARCH64','MIPS','X86')]],'configure')
    obj='CMakeFiles/capstone.dir/arch/X86/X86DisassemblerDecoder.c.obj'
    rc=run(['cmake','--build',b,'--target',obj,'--parallel','1'],'decoder-object',False)
    log=(out/'decoder-object.log').read_text(errors='replace')
    if rc:
        assert 'fatal error C1002' in log,log[-1600:]
    else:
        save('object',dict(size=(b/obj).stat().st_size,sha256=sha(b/obj)))
        targets=['mcinst','x86_scan_batch','x86_simple_output','x86_printer_prechecked','x86_x87_environment_hardware','text_option','instruction_bytes','x86_buffer_bounds']
        run(['cmake','--build',b,'--target',*targets,'--parallel','2'],'units-build')
        run(['ctest','--test-dir',b,'--no-tests=error','--output-on-failure','-R','^unit_('+'|'.join(targets)+')$'],'units')
    save('observation',dict(label=label,compiled=not rc,c1002='fatal error C1002' in log,tree=git('write-tree'),timings=timings))
finally:
    n=sum(p.stat().st_size for p in w.rglob('*') if p.is_file());shutil.rmtree(w,onerror=remove_readonly);save('cleanup',dict(bytes=n,removed=not w.exists()))
