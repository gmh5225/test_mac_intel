from pathlib import Path
import json, os, platform, shutil, subprocess, tempfile
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
    assert subprocess.check_output(['git','rev-parse','HEAD'],cwd=source,text=True).strip()==json.loads((root/'candidate.json').read_text())['parent']
    run(['python','suite/synctools/x86_mapping_counts.py','--check'],'mapping-counts')
    if profile=='adapter': run(['python3','suite/synctools/x86_operand_specializations.py','--check'],'regenerate')
    opts=['-DCAPSTONE_ARCHITECTURE_DEFAULT=OFF','-DCAPSTONE_X86_SUPPORT=ON','-DCAPSTONE_MIPS_SUPPORT=ON','-DCAPSTONE_ARM_SUPPORT=ON','-DCAPSTONE_AARCH64_SUPPORT=ON','-DCMAKE_BUILD_TYPE=Release','-DCAPSTONE_BUILD_CSTEST=ON','-DCAPSTONE_BUILD_CSTOOL=OFF','-DCAPSTONE_BUILD_LEGACY_TESTS=OFF']
    if os.name=='nt':
        opts+=['-G','Visual Studio 17 2022','-A','x64','-DCMAKE_C_FLAGS=/MP4','-DCAPSTONE_BUILD_STATIC_MSVC_RUNTIME='+('ON' if compiler=='MT' else 'OFF')]
    else:
        opts+=['-G','Ninja','-DCMAKE_C_COMPILER='+compiler]+(['-DCMAKE_C_FLAGS=-Wno-error=discarded-qualifiers'] if compiler=='gcc' else [])
    profile_options={'all':['-DCAPSTONE_ARCHITECTURE_DEFAULT=ON'],'alias-only':['-DCAPSTONE_X86_SUPPORT=OFF','-DCAPSTONE_ARM_SUPPORT=OFF'],'dedicated':['-DCAPSTONE_ARM_SUPPORT=OFF','-DCAPSTONE_AARCH64_SUPPORT=OFF','-DCAPSTONE_MIPS_SUPPORT=OFF'],'four':['-DCAPSTONE_ARM_SUPPORT=ON','-DCAPSTONE_AARCH64_SUPPORT=ON','-DCAPSTONE_MIPS_SUPPORT=ON'],'diet':['-DCAPSTONE_BUILD_DIET=ON'],'reduced':['-DCAPSTONE_X86_REDUCE=ON'],'adapter':['-DCAPSTONE_X86_SCAN_ADAPTER=ON'],'intel':['-DCAPSTONE_X86_ATT_DISABLE=ON'],'sanitize':['-DENABLE_ASAN=ON']}
    run(['cmake','-S',source,'-B',b,*opts,*profile_options[profile],*(['-DCMAKE_C_FLAGS=-fsanitize=undefined','-DCMAKE_EXE_LINKER_FLAGS=-fsanitize=undefined'] if profile=='sanitize' else [])],'configure')
    units=['mapping','api','x86_scan_batch','x86_relative_jump','x86_reg_access','detail_option']
    if profile not in ('diet','reduced'):
        units+=['x86_packed_move_access','x86_buffer_bounds','x86_simple_output','x86_encoding_accuracy','x86_evex_reserved_fields','x86_memory_scale','mips_scan']
    if profile=='adapter':units+=['x86_scan_adapter']
    if profile not in ('diet','reduced'):
        known={q.stem for q in (source/'tests/unit').glob('aarch64_*.c')}
        units+=sorted(q for q in known if q in ('aarch64_memory_access','aarch64_post_index','aarch64_addressing'))
    if profile not in ('diet','reduced'):units+=['arm_post_index','aarch64_scan','aarch64_postprocess']
    if profile=='dedicated':units=[name for name in units if not name.startswith(('arm_','aarch64_','mips_'))]
    if profile=='alias-only':units=['mapping','api','mips_scan','aarch64_scan','aarch64_postprocess']
    run(['cmake','--build',b,'--config','Release','--target','capstone_static','--parallel','4'],'build-base')
    import hashlib
    def objects():
        roots=[b/'CMakeFiles/capstone.dir',b/'capstone.dir']
        result={}
        for objroot in roots:
            for file in objroot.rglob('*'):
                if file.is_file() and file.suffix in ('.o','.obj'):
                    result[str(file.relative_to(b))]=hashlib.sha256(file.read_bytes()).hexdigest()
        assert len(result)>5, result
        return result
    before=objects()
    run(['git','-c','core.autocrlf=false','apply',root/(forms+'.patch')],'apply')
    run(['git','add','-A'],'stage-tested-source')
    tested_tree=subprocess.check_output(['git','write-tree'],cwd=source,text=True).strip()
    assert tested_tree==json.loads((root/'candidate.json').read_text())['tree'],tested_tree
    run(['cmake','--build',b,'--config','Release','--target','capstone_static',*units,'--parallel','4'],'build')
    after=objects()
    assert before.keys()==after.keys()
    changed=[name for name in before if before[name]!=after[name]]
    save('object-identity',dict(total=len(before),changed=changed,identical=not changed))
    active=(platform.system()=='Linux' and platform.machine()=='aarch64'
            and compiler=='gcc' and profile=='four')
    if active:
        assert set(changed)=={'CMakeFiles/capstone.dir/arch/X86/X86OutputIterator.c.o',
                              'CMakeFiles/capstone.dir/arch/X86/X86VectorOutput.c.o'},changed
    else:
        assert not changed,changed
    save('profile-activation',dict(active=active,host=platform.platform(),
                                  inactive_objects_identical=not active and not changed))

    run(['ctest','--test-dir',b,'-C','Release','--no-tests=error','--output-on-failure','-R','^unit_('+'|'.join(units+['arm_register_names_generator','aarch64_register_names_generator','fixed_len_decoder'])+')$'],'tests')
    assert 'runtime error:' not in (evidence/'tests.log').read_text()
    if profile=='all':
        run(['cmake','--build',b,'--config','Release','--parallel','4'],'build-all-units')
        run(['ctest','--test-dir',b,'-C','Release','--no-tests=error','--output-on-failure','-R','^unit_'],'all-unit-tests')
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
    if profile=='adapter':
        make_build=root_build/'make-build'
        run(['make','-j4','CAPSTONE_ARCHS=x86','CAPSTONE_BUILD_CORE_ONLY=yes','CC='+compiler,'BUILDDIR='+str(make_build),str(make_build/'libcapstone.a')],'make-static')
        smoke=root_build/'make-simple-output'
        run([compiler,'-O2','-DCAPSTONE_HAS_X86','-DCAPSTONE_USE_SYS_DYN_MEM','-Iinclude','tests/unit/x86_simple_output.c',make_build/'libcapstone.a','-lm','-o',smoke],'make-output-link')
        run([smoke],'make-output-records')
        save('make-output-validation',dict(build='Makefile x86-only static library',entrypoint='X86_disasmIter',full_output_records=True))
    if active:
        reference=json.loads((root/'candidate.json').read_text())['parent']
        run(['git','reset','--hard',reference],'restore-for-timed-reference')
        run(['git','apply',root/'timed-reference.patch'],'apply-timed-reference')
        run(['git','add','-u'],'stage-timed-reference')
        reference_tree=subprocess.check_output(['git','write-tree'],cwd=source,text=True).strip()
        expected_reference=json.loads((root/'timed-reference.json').read_text())
        assert reference_tree==expected_reference['tree'],reference_tree
        run(['cmake','--build',b,'--config','Release','--target','capstone_static','--parallel','4'],'build-timed-reference')
        timed=objects()
        assert timed==after,sorted(name for name in after if timed.get(name)!=after[name])
        save('timed-reference-identity',dict(tree=reference_tree,objects=len(timed),identical=True,
                                           qualified_source=expected_reference))
    save('complete',dict(forms=forms,profile=profile,compiler=compiler,units=units,tested_tree=tested_tree))
finally:
    n=sum(f.stat().st_size for f in root_build.rglob('*') if f.is_file())
    shutil.rmtree(root_build,onerror=clean_error)
    save('cleanup',dict(bytes=n,removed=not root_build.exists()))
