from pathlib import Path
import json, os, shutil, subprocess, tempfile
root=Path(__file__).resolve().parent
source=root.parent/'source'
evidence=root.parent/'evidence'
evidence.mkdir()
def run(args, label):
    print(label, flush=True)
    path=evidence/(label+'.log')
    with path.open('wb') as log:
        proc=subprocess.run(list(map(str,args)),cwd=source,stdout=log,stderr=subprocess.STDOUT)
    if proc.returncode:
        raise RuntimeError((label,path.read_text(errors='replace')[-4500:]))
def save(label,data):
    (evidence/(label+'.json')).write_text(json.dumps(data,indent=2)+'\n')
def clean_error(fn,path,exc):
    os.chmod(path,0o700)
    fn(path)
profile=os.environ['PROFILE']
compiler=os.environ['TOOLCHAIN']
forms=os.environ['FORMS']
root_build=Path(tempfile.mkdtemp(prefix='capstone-verified-config-'))
b=root_build/'build'
try:
    assert subprocess.check_output(['git','rev-parse','HEAD'],cwd=source,text=True).strip()=='15ce0f6bd4b2497685ad5cca9a66aa721f462d53'
    run(['git','-c','core.autocrlf=false','apply',root/(forms+'.patch')],'apply')
    run(['python','suite/synctools/x86_mapping_counts.py','--check'],'mapping-counts')
    if profile=='adapter': run(['python3','suite/synctools/x86_operand_specializations.py','--check'],'regenerate')
    opts=['-DCAPSTONE_ARCHITECTURE_DEFAULT=OFF','-DCAPSTONE_X86_SUPPORT=ON','-DCMAKE_BUILD_TYPE=Release','-DCAPSTONE_BUILD_CSTEST=ON','-DCAPSTONE_BUILD_CSTOOL=OFF','-DCAPSTONE_BUILD_LEGACY_TESTS=OFF']
    if os.name=='nt':
        opts+=['-G','Visual Studio 17 2022','-A','x64','-DCMAKE_C_FLAGS=/MP4','-DCAPSTONE_BUILD_STATIC_MSVC_RUNTIME='+('ON' if compiler=='MT' else 'OFF')]
    else:
        opts+=['-G','Ninja','-DCMAKE_C_COMPILER='+compiler]
    profile_options={'dedicated':[],'four':['-DCAPSTONE_ARM_SUPPORT=ON','-DCAPSTONE_AARCH64_SUPPORT=ON','-DCAPSTONE_MIPS_SUPPORT=ON'],'diet':['-DCAPSTONE_BUILD_DIET=ON'],'reduced':['-DCAPSTONE_X86_REDUCE=ON'],'adapter':['-DCAPSTONE_X86_SCAN_ADAPTER=ON'],'intel':['-DCAPSTONE_X86_ATT_DISABLE=ON'],'sanitize':['-DENABLE_ASAN=ON']}
    run(['cmake','-S',source,'-B',b,*opts,*profile_options[profile],*(['-DCMAKE_C_FLAGS=-fsanitize=undefined','-DCMAKE_EXE_LINKER_FLAGS=-fsanitize=undefined'] if profile=='sanitize' else [])],'configure')
    units=['api','x86_scan_batch']
    if profile in ('diet','reduced'):
        units+=['x86_encoding_accuracy']
    else:
        units+=['x86_simple_output','x86_reg_access','x86_relative_jump','x86_encoding_accuracy','x86_evex_reserved_fields','detail_option']
    run(['cmake','--build',b,'--config','Release','--target','capstone_static',*units,'--parallel','4'],'build')
    run(['ctest','--test-dir',b,'-C','Release','--no-tests=error','--output-on-failure','-R','^unit_('+'|'.join(units)+')$'],'tests')
    save('complete',dict(forms=forms,profile=profile,compiler=compiler,units=units))
finally:
    n=sum(f.stat().st_size for f in root_build.rglob('*') if f.is_file())
    shutil.rmtree(root_build,onerror=clean_error)
    save('cleanup',dict(bytes=n,removed=not root_build.exists()))
