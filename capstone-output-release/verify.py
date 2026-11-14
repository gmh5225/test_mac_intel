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
    assert subprocess.check_output(['git','rev-parse','HEAD'],cwd=source,text=True).strip()=='75da2329204825bb0bd15e574ab58c45b5019dcc'
    run(['git','-c','core.autocrlf=false','apply',root/(forms+'.patch')],'apply')
    run(['python','suite/synctools/x86_mapping_counts.py','--check'],'mapping-counts')
    if profile=='adapter': run(['python3','suite/synctools/x86_operand_specializations.py','--check'],'regenerate')
    opts=['-DCAPSTONE_ARCHITECTURE_DEFAULT=OFF','-DCAPSTONE_X86_SUPPORT=ON','-DCAPSTONE_MIPS_SUPPORT=ON','-DCAPSTONE_ARM_SUPPORT=ON','-DCAPSTONE_AARCH64_SUPPORT=ON','-DCMAKE_BUILD_TYPE=Release','-DCAPSTONE_BUILD_CSTEST=ON','-DCAPSTONE_BUILD_CSTOOL=OFF','-DCAPSTONE_BUILD_LEGACY_TESTS=OFF']
    if os.name=='nt':
        opts+=['-G','Visual Studio 17 2022','-A','x64','-DCMAKE_C_FLAGS=/MP4','-DCAPSTONE_BUILD_STATIC_MSVC_RUNTIME='+('ON' if compiler=='MT' else 'OFF')]
    else:
        opts+=['-G','Ninja','-DCMAKE_C_COMPILER='+compiler]+(['-DCMAKE_C_FLAGS=-Wno-error=discarded-qualifiers'] if compiler=='gcc' else [])
    profile_options={'dedicated':['-DCAPSTONE_ARM_SUPPORT=OFF','-DCAPSTONE_AARCH64_SUPPORT=OFF','-DCAPSTONE_MIPS_SUPPORT=OFF'],'four':['-DCAPSTONE_ARM_SUPPORT=ON','-DCAPSTONE_AARCH64_SUPPORT=ON','-DCAPSTONE_MIPS_SUPPORT=ON'],'diet':['-DCAPSTONE_BUILD_DIET=ON'],'reduced':['-DCAPSTONE_X86_REDUCE=ON'],'adapter':['-DCAPSTONE_X86_SCAN_ADAPTER=ON'],'intel':['-DCAPSTONE_X86_ATT_DISABLE=ON'],'sanitize':['-DENABLE_ASAN=ON']}
    run(['cmake','-S',source,'-B',b,*opts,*profile_options[profile],*(['-DCMAKE_C_FLAGS=-fsanitize=undefined','-DCMAKE_EXE_LINKER_FLAGS=-fsanitize=undefined'] if profile=='sanitize' else [])],'configure')
    units=['api','x86_scan_batch','x86_relative_jump']
    if profile not in ('diet','reduced'):
        units+=['x86_packed_move_access','x86_buffer_bounds','x86_simple_output','x86_encoding_accuracy','x86_reg_access','x86_evex_reserved_fields','x86_memory_scale','mips_scan','detail_option']
    if profile=='adapter':units+=['x86_scan_adapter']
    if profile not in ('diet','reduced'):
        known={q.stem for q in (source/'tests/unit').glob('aarch64_*.c')}
        units+=sorted(q for q in known if q in ('aarch64_memory_access','aarch64_post_index','aarch64_addressing'))
    if profile not in ('diet','reduced'):units+=['arm_post_index','aarch64_scan','aarch64_postprocess']
    if profile!='diet':units+=['mips_register_names','mips_scan','mips_reglist_offset','mips16_immediates','mips16_memory_calls']
    if profile=='dedicated':units=[name for name in units if not name.startswith(('arm_','aarch64_','mips_'))]
    run(['cmake','--build',b,'--config','Release','--target','capstone_static',*units,'--parallel','4'],'build')
    run(['ctest','--test-dir',b,'-C','Release','--no-tests=error','--output-on-failure','-R','^unit_('+'|'.join(units+['mips_register_names_generator','arm_register_names_generator','aarch64_register_names_generator','fixed_len_decoder'])+')$'],'tests')
    if profile=='adapter':
        generator=root_build/'simple-output-generator'
        run(['clang++','-std=c++17','-O2','-Iinclude','suite/synctools/x86_simple_output.cpp',b/'libcapstone.a','-o',generator],'compile-output-generator')
        result=subprocess.check_output([generator],cwd=source)
        assert result==(source/'arch/X86/X86GenSimpleOutput.inc').read_bytes()
    if profile=='adapter':
        generator=root_build/'vector-output-generator'
        run(['clang++','-std=c++17','-O2','-Iinclude','suite/synctools/x86_vector_output.cpp',b/'libcapstone.a','-o',generator],'compile-vector-generator')
        result=subprocess.check_output([generator],cwd=source)
        assert result==(source/'arch/X86/X86GenVectorOutput.inc').read_bytes()
    save('complete',dict(forms=forms,profile=profile,compiler=compiler,units=units))
finally:
    n=sum(f.stat().st_size for f in root_build.rglob('*') if f.is_file())
    shutil.rmtree(root_build,onerror=clean_error)
    save('cleanup',dict(bytes=n,removed=not root_build.exists()))
