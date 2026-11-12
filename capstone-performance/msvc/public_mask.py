from pathlib import Path
import hashlib,json,os,shutil,struct,subprocess as sp,sys
import run as perf

src=perf.source;w=perf.work;mode=sys.argv[2];manifest=perf.manifest

def aggregate_unit_targets(tree, tests):
    # Each test still runs in its own process. One image avoids repeating the
    # same Capstone LTCG compilation for every unit executable.
    driver = tree / 'repair_units.c'
    declarations = ['int repair_unit_' + name + '(void);' for name in tests]
    entries = ['    {"' + name + '", repair_unit_' + name + '},' for name in tests]
    driver.write_text('#include <stdio.h>\n#include <string.h>\n' +
        '\n'.join(declarations) + '\n' +
        'static const struct { const char *name; int (*run)(void); } tests[] = {\n' +
        '\n'.join(entries) + '\n};\n' +
        'int main(int argc, char **argv) {\n' +
        '    if (argc != 2) return 2;\n' +
        '    for (size_t i = 0; i < sizeof(tests) / sizeof(tests[0]); ++i)\n' +
        '        if (strcmp(argv[1], tests[i].name) == 0) return tests[i].run();\n' +
        '    return 2;\n}\n')
    with (tree / 'CMakeLists.txt').open('a') as cmake:
        cmake.write('\nadd_executable(repair_units repair_units.c)\n')
        cmake.write('target_link_libraries(repair_units PRIVATE capstone)\n')
        for name in tests:
            target = 'repair_object_' + name
            cmake.write('add_library(' + target + ' OBJECT tests/unit/' + name + '.c)\n')
            cmake.write('target_compile_definitions(' + target + ' PRIVATE main=repair_unit_' + name + ')\n')
            cmake.write('target_include_directories(' + target + ' PRIVATE tests/unit/include)\n')
            cmake.write('target_link_libraries(' + target + ' PRIVATE capstone)\n')
            cmake.write('target_sources(repair_units PRIVATE $<TARGET_OBJECTS:' + target + '>)\n')
            cmake.write('add_test(NAME repair_unit_' + name + ' COMMAND repair_units ' + name + ')\n')
        cmake.write('set_tests_properties(repair_unit_x86_x87_environment PROPERTIES SKIP_RETURN_CODE 77)\n')
        if 'x86_printer_prechecked' in tests:
            cmake.write('set_tests_properties(repair_unit_x86_printer_prechecked PROPERTIES SKIP_RETURN_CODE 77)\n')

def main():
    root=perf.fetch('base','capstone',manifest['capstone_revision'])
    cand=w/'candidate'
    perf.run(['git','worktree','add','--detach',cand,'HEAD'],'checkout-candidate',root)
    patch=src/'profiles.patch';assert perf.digest(patch.read_bytes())==manifest['source_lineage'][patch.name]['sha256']
    perf.run(['git','apply','--check',patch],'check',cand);perf.run(['git','apply',patch],'apply',cand)
    cases=[c for c in perf.get_cases() if c['name'].startswith(('putty','scalar','simd'))];assert len(cases)==5
    cp=(src/'windows-public.cpp').read_text()
    i=cp.index('const Config configs[]');j=cp.index('uint64_t rng',i)
    configs=[]
    for c in cases:
        for syntax in ('DEFAULT','ATT','MASM'):
            f=Path(c['path']).name
            configs.append('  {CS_ARCH_X86,CS_MODE_'+str(c['bits'])+',CS_OPT_SYNTAX_'+syntax+',"'+f+'-'+syntax+'","'+f+'"},')
    cp=cp[:i]+'const Config configs[] = {\n'+'\n'.join(configs)+'\n};\n'+cp[j:]
    cp=cp.replace('config.arch == CS_ARCH_ARM','config.arch == CS_ARCH_X86').replace('ARM_INS_ADD, ARM_INS_MOV, ARM_INS_HINT, ARM_INS_POP, ARM_INS_BL','X86_INS_ADD, X86_INS_MOV, X86_INS_VADDPS, X86_INS_PUSH, X86_INS_JMP')
    (w/'compare.cpp').write_text(cp)
    dlls=[];records=[]
    options={'full':[],'diet':['-DCAPSTONE_BUILD_DIET=ON'],'reduced':['-DCAPSTONE_X86_REDUCE=ON'],'no-att':['-DCAPSTONE_X86_ATT_DISABLE=ON']}[mode]
    tests=['x86_encoding_accuracy','x86_x87_environment','x86_scan_batch','x86_call_target','x86_relative_jump','x86_vfpclass_memory_mask_detail','x86_vfpclass_scalar_llig']
    if mode=='full':tests+=['x86_evex_detail','x86_evex_mask_conversion_access','x86_evex_vpcmp_id','x86_evex_vpcmp_mask_size','x86_kmask_access','x86_kmask_width','x86_gfni_broadcast_detail','x86_evex_scalar_broadcast_mask_size','x86_apx_evex_shift_rotate','x86_apx_rex2_alu','x86_buffer_bounds','x86_exchange_access','x86_printer_prechecked','arm_post_index','aarch64_postprocess','mips_reglist_offset','mips_msa_control']
    for label,tree in [('base',root),('new',cand)]:
        with (tree/'CMakeLists.txt').open('a') as out:
            out.write('\nadd_executable(maskstate "'+(src/'msvc/mask.c').as_posix()+'")\ntarget_include_directories(maskstate PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}" "${CMAKE_CURRENT_SOURCE_DIR}/include")\ntarget_link_libraries(maskstate PRIVATE capstone_static)\n')
            if label=='new':
                out.write('add_executable(verify "'+(w/'compare.cpp').as_posix()+'")\ntarget_include_directories(verify PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}/include")\ntarget_compile_features(verify PRIVATE cxx_std_17)\n')
        if label == 'new':
            aggregate_unit_targets(tree, tests)
        b=w/(label+'-build')
        perf.run(['cmake','-S',tree,'-B',b,'-A','x64','-DCMAKE_C_FLAGS=/MP4','-DCMAKE_INTERPROCEDURAL_OPTIMIZATION_RELEASE=ON','-DCAPSTONE_BUILD_SHARED_LIBS=ON','-DCAPSTONE_BUILD_STATIC_LIBS=ON','-DCAPSTONE_BUILD_STATIC_MSVC_RUNTIME=OFF','-DCAPSTONE_ARCHITECTURE_DEFAULT=OFF','-DCAPSTONE_X86_SUPPORT=ON','-DCAPSTONE_ARM_SUPPORT=ON','-DCAPSTONE_AARCH64_SUPPORT=ON','-DCAPSTONE_MIPS_SUPPORT=ON','-DCAPSTONE_BUILD_CSTOOL=OFF','-DCAPSTONE_BUILD_LEGACY_TESTS=OFF','-DCAPSTONE_BUILD_CSTEST=ON',*options],label+'-configure')
        perf.run(['cmake','--build',b,'--target','maskstate','capstone_shared',*(['verify','repair_units']if label=='new'else[]),'--config','Release','--parallel','4'],label+'-build')
        flags=[p.read_text(encoding='utf-16',errors='ignore').upper() for p in b.rglob('CL.command.1.tlog')]
        assert any('/MD ' in text and 'X86DISASSEMBLER.C' in text for text in flags)
        if label=='new':
            perf.run(['ctest','--test-dir',b,'-C','Release','--no-tests=error','--output-on-failure','-R','^repair_unit_('+'|'.join(tests)+')$'],'unit-tests')
        out=w/('capstone-'+label+'.dll');shutil.copyfile(next(b.rglob('capstone.dll')),out);dlls.append(out)
        raw=sp.check_output([next(b.rglob('maskstate.exe'))]);assert len(raw)==12*1572864
        masks=sum(bool(flags&32)for flags,_,_ in struct.iter_unpack('<III',raw))
        records.append(dict(count=len(raw)//12,masks=masks,sha256=perf.digest(raw)))
    assert records[0]==records[1];perf.write('private-flags.json',records[0])
    if mode=='full':assert records[0]['masks']>80000
    results=[]
    for custom in (False,True):
        label='custom' if custom else 'default'
        if custom:os.environ['CUSTOM_NAMES']='1'
        perf.run([next(b.rglob('verify.exe')),*dlls,'32768',w],label)
        rows=[json.loads(v) for v in (perf.evidence/(label+'.log')).read_text().splitlines() if v.startswith('{')]
        assert rows and rows[-1]['compared_total']>1000000
        results.append(dict(configuration=label,compared=rows[-1]['compared_total'],cells=len(rows)))
    perf.write('public-states.json',results)
try:main()
finally:
    n=sum(t.stat().st_size for t in w.rglob('*') if t.is_file())
    def writable(func,path,err):os.chmod(path,0o700);func(path)
    shutil.rmtree(w,onerror=writable);perf.write('cleanup.json',dict(bytes=n,removed=not w.exists()))
